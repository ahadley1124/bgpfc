//! Graceful Restart in the daemon: what the threads share about a restart,
//! and how the configuration, the FSM's session and the FIB's startup scan
//! become the RIB's settings.
//!
//! Implements: RFC 4724 §3 (the Restart State bit of the OPEN is set while
//! we are restarting; the Forwarding State bit of a family only if the
//! forwarding state of its routes is in the kernel), §4.1 (a Restarting
//! Speaker defers route selection until the End-of-RIB of every neighbor
//! with the capability, or a timer), §4.2 (what the RIB keeps of a session
//! that ended and for how long); RFC 8538 §2 (the Graceful Notification
//! bit).

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use bgpfc_fsm::{RestartAdvert, Retain, Session};
use bgpfc_rib::{Deferral, PeerRestart, Restart, Retention};
use bgpfc_wire::types::{AddressFamily, Afi};

/// IPv4 unicast has forwarding state in the kernel.
const IPV4: u8 = 1;
/// IPv6 unicast has forwarding state in the kernel.
const IPV6: u8 = 2;

/// What the FIB thread, the RIB thread and the peer threads share about a
/// restart. Each field is advisory and read only to fill in an OPEN, so
/// relaxed atomics are enough: a bit that is a moment out of date is
/// still a bit the speaker could truthfully have sent a moment ago.
#[derive(Debug, Default)]
pub(crate) struct RestartState {
    /// The daemon has restarted with forwarding state kept and has not
    /// yet finished route selection for every family it deferred it for
    /// (RFC 4724 §4.1): the Restart State bit.
    restarting: AtomicBool,
    /// The families with routes installed in the kernel, as bits
    /// ([`IPV4`], [`IPV6`]): the Forwarding State bits.
    forwarding: AtomicU8,
}

impl RestartState {
    /// We are restarting, or no longer are.
    pub(crate) fn set_restarting(&self, restarting: bool) {
        self.restarting.store(restarting, Ordering::Relaxed);
    }

    /// Whether we are restarting.
    pub(crate) fn restarting(&self) -> bool {
        self.restarting.load(Ordering::Relaxed)
    }

    /// The FIB thread's word on which families have forwarding state: it
    /// has routes of the family installed, and the FIB is in install mode.
    /// In dry-run mode nothing is installed, and what the kernel holds
    /// is not ours to claim (RFC 4724 §4.1: the bit "can be set only if
    /// the forwarding state has indeed been preserved").
    pub(crate) fn set_forwarding(&self, ipv4: bool, ipv6: bool) {
        let bits = if ipv4 { IPV4 } else { 0 } | if ipv6 { IPV6 } else { 0 };
        self.forwarding.store(bits, Ordering::Relaxed);
    }

    /// What the next OPEN says: the Restart State bit, and the families
    /// that have the Forwarding State bit.
    pub(crate) fn advert(&self) -> RestartAdvert {
        let bits = self.forwarding.load(Ordering::Relaxed);
        let mut forwarding = Vec::new();
        if bits & IPV4 != 0 {
            forwarding.push(AddressFamily::IPV4_UNICAST);
        }
        if bits & IPV6 != 0 {
            forwarding.push(AddressFamily::IPV6_UNICAST);
        }
        RestartAdvert {
            restarting: self.restarting(),
            forwarding,
        }
    }
}

/// The families, among those routes are installed for, whose kept routes
/// the daemon may wait to learn again: those of a neighbor with
/// `graceful-restart yes`. Routes of any other family cannot be learned
/// again from a neighbor that does not take part, so the startup flush
/// removes them as it always did.
pub(crate) fn keepable(config: &bgpfc_config::Config) -> Vec<Afi> {
    let mut afis = Vec::new();
    for n in config
        .neighbors
        .iter()
        .filter(|n| n.graceful_restart.is_some())
    {
        for f in &n.families {
            if !afis.contains(&f.afi) {
                afis.push(f.afi);
            }
        }
    }
    afis
}

/// What a Restarting Speaker waits for (RFC 4724 §4.1) when the families
/// `kept` have routes in the kernel from before the restart: the
/// End-of-RIB of every neighbor with `graceful-restart yes` for each
/// family it has, for as long as the longest `restart-time` among them
/// from `now`. `None` when there is nothing to wait for.
pub(crate) fn deferral(
    config: &bgpfc_config::Config,
    kept: &[AddressFamily],
    now: Instant,
) -> Option<Deferral> {
    let mut waiting: Vec<(IpAddr, Vec<AddressFamily>)> = Vec::new();
    let mut longest = Duration::ZERO;
    for n in &config.neighbors {
        let Some(gr) = &n.graceful_restart else {
            continue;
        };
        let families: Vec<AddressFamily> = n
            .families
            .iter()
            .copied()
            .filter(|f| kept.contains(f))
            .collect();
        if families.is_empty() {
            continue;
        }
        longest = longest.max(Duration::from_secs(u64::from(gr.restart_time.secs())));
        waiting.push((n.addr, families));
    }
    (!waiting.is_empty()).then(|| Deferral {
        waiting,
        until: now + longest,
    })
}

/// What the RIB needs of a session's Graceful Restart: our capability was
/// advertised (the End-of-RIB marker follows each family's table), what
/// the peer's said, and the stale timer of the neighbor (RFC 4724 §4,
/// §4.2, RFC 8538 §4.1). `None` for a session without it.
pub(crate) fn rib_restart(session: &Session, stale_time: Option<Duration>) -> Option<Restart> {
    let r = session.restart.as_deref()?;
    Some(Restart {
        peer: r.peer.as_ref().map(|p| PeerRestart {
            restarting: p.restarting,
            families: p.families.clone(),
        }),
        stale_time: stale_time.unwrap_or_else(|| {
            Duration::from_secs(u64::from(bgpfc_config::ast::DEFAULT_STALE_TIME))
        }),
    })
}

/// The routes a session that ended leaves as stale ones (RFC 4724 §4.2).
pub(crate) fn retention(r: &Retain) -> Retention {
    Retention {
        families: r.families.clone(),
        restart_time: Duration::from_secs(u64::from(r.restart_time.secs())),
        notification: r.notification,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
    const V6: AddressFamily = AddressFamily::IPV6_UNICAST;

    fn config(neighbors: &str) -> bgpfc_config::Config {
        bgpfc_config::parse_str(
            "t",
            &format!(
                "router-id 192.0.2.1; local-as 65000;
                 policy A {{ term t {{ action accept; }} }}
                 {neighbors}"
            ),
        )
        .unwrap()
    }

    #[test]
    fn the_advert_follows_what_the_threads_publish() {
        let state = RestartState::default();
        // Nothing published: not restarting, no forwarding state.
        assert_eq!(state.advert(), RestartAdvert::default());
        state.set_restarting(true);
        state.set_forwarding(true, false);
        assert_eq!(
            state.advert(),
            RestartAdvert {
                restarting: true,
                forwarding: vec![V4]
            }
        );
        state.set_restarting(false);
        state.set_forwarding(false, true);
        assert_eq!(
            state.advert(),
            RestartAdvert {
                restarting: false,
                forwarding: vec![V6]
            }
        );
        state.set_forwarding(true, true);
        assert_eq!(state.advert().forwarding, vec![V4, V6]);
        assert!(!state.restarting());
    }

    #[test]
    fn only_the_families_of_neighbors_with_graceful_restart_can_be_kept() {
        let c = config(
            "neighbor 192.0.2.2 { remote-as 65001; import A; export A; families ipv4-unicast; }
             neighbor 2001:db8::3 { remote-as 65001; import A; export A;
                 families ipv6-unicast; graceful-restart yes; }",
        );
        assert_eq!(keepable(&c), vec![Afi::Ipv6]);
        let none = config("neighbor 192.0.2.2 { remote-as 65001; import A; export A; }");
        assert_eq!(keepable(&none), Vec::<Afi>::new());
    }

    #[test]
    fn a_restarting_speaker_waits_for_each_graceful_neighbor_of_a_kept_family() {
        let c = config(
            "neighbor 192.0.2.2 { remote-as 65001; import A; export A;
                 families ipv4-unicast ipv6-unicast;
                 graceful-restart yes; restart-time 60; }
             neighbor 192.0.2.3 { remote-as 65001; import A; export A;
                 graceful-restart yes; restart-time 90; }
             neighbor 192.0.2.4 { remote-as 65001; import A; export A; }
             neighbor 2001:db8::5 { remote-as 65001; import A; export A;
                 families ipv6-unicast; graceful-restart yes; restart-time 200; }",
        );
        let now = Instant::now();
        let d = deferral(&c, &[V4], now).unwrap();
        // RFC 4724 §4.1: the peers with the capability, for the families
        // that kept routes; the neighbor without it is not waited for,
        // nor is the one that has no family kept.
        assert_eq!(
            d.waiting,
            vec![
                ("192.0.2.2".parse().unwrap(), vec![V4]),
                ("192.0.2.3".parse().unwrap(), vec![V4]),
            ]
        );
        // The longest restart time among those waited for.
        assert_eq!(d.until, now + Duration::from_secs(90));
        let d = deferral(&c, &[V4, V6], now).unwrap();
        assert_eq!(d.waiting.len(), 3);
        assert_eq!(d.until, now + Duration::from_secs(200));
        assert!(deferral(&c, &[], now).is_none());
    }

    #[test]
    fn a_retention_carries_the_peers_restart_time_in_seconds() {
        let r = Retain {
            families: vec![V4],
            restart_time: bgpfc_wire::types::RestartTime::new(120).unwrap(),
            notification: true,
        };
        assert_eq!(
            retention(&r),
            Retention {
                families: vec![V4],
                restart_time: Duration::from_secs(120),
                notification: true,
            }
        );
    }
}
