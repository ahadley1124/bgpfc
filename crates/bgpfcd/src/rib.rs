//! The RIB thread: the only owner of RIB state (AGENTS.md §3). It turns
//! peer messages into `bgpfc_rib::Rib` calls and delivers what comes out:
//! UPDATEs to peer threads, route changes to the FIB thread. Between
//! messages it sleeps until the next RFC 4271 §9.2.1.1 deadline and then
//! releases the advertisements that were held back; the pacing itself is
//! `bgpfc_rib`'s.

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_fsm::Session;
use bgpfc_rib::{Output, PeerInfo, Rib};
use bgpfc_wire::update::PeerKind;

use crate::coordinator::PeerTable;
use crate::messages::{FibMsg, Intervals, PeerInput, RibMsg, RibQuery, RibReply, RouteReport};

/// Start the RIB thread on `rib`, with the configured advertisement
/// intervals.
pub(crate) fn spawn(
    rib: Rib,
    intervals: Intervals,
    rx: Receiver<RibMsg>,
    peers: PeerTable,
    fib: SyncSender<FibMsg>,
) {
    thread::Builder::new()
        .name("rib".to_owned())
        .spawn(move || run(rib, intervals, &rx, &peers, &fib))
        .expect("spawning the rib thread");
}

fn run(
    mut rib: Rib,
    mut intervals: Intervals,
    rx: &Receiver<RibMsg>,
    peers: &PeerTable,
    fib: &SyncSender<FibMsg>,
) {
    loop {
        let Ok(msg) = next(rx, rib.next_deadline()) else {
            return;
        };
        let now = Instant::now();
        let mut outputs = match msg {
            Some(m) => handle(&mut rib, &mut intervals, m, now),
            None => Vec::new(),
        };
        // RFC 4271 §9.2.1.1: release what is due. After a message too, so
        // that a busy channel cannot starve the deadlines.
        outputs.extend(rib.flush(now));
        deliver(outputs, peers, fib);
    }
}

/// Every sender to the RIB thread is gone.
#[derive(Debug)]
struct Closed;

/// Wait for the next message (`Some`), or until `deadline`, when there is
/// one, passes first (`None`).
fn next(rx: &Receiver<RibMsg>, deadline: Option<Instant>) -> Result<Option<RibMsg>, Closed> {
    let Some(deadline) = deadline else {
        return rx.recv().map(Some).map_err(|_| Closed);
    };
    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(m) => Ok(Some(m)),
        Err(RecvTimeoutError::Timeout) => Ok(None),
        Err(RecvTimeoutError::Disconnected) => Err(Closed),
    }
}

/// Apply one message to the RIB.
fn handle(rib: &mut Rib, intervals: &mut Intervals, msg: RibMsg, now: Instant) -> Vec<Output> {
    match msg {
        RibMsg::PeerUp {
            peer,
            local_addr,
            session,
        } => {
            let interval = advertisement_interval(configured(intervals, peer), session.peer);
            bgpfc_log::info!(
                "rib: peer up",
                peer = peer,
                local = local_addr,
                families = session
                    .families
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                advertisement_interval = interval.as_secs()
            );
            rib.peer_up(peer_info(peer, local_addr, &session, interval), now)
        }
        RibMsg::Update { peer, update } => {
            log_update(peer, &update);
            rib.update(peer, &update, now)
        }
        RibMsg::FamilyDisabled { peer, family } => {
            bgpfc_log::warn!("rib: family disabled", peer = peer, family = family);
            rib.family_disabled(peer, family, now)
        }
        RibMsg::RouteRefresh { peer, family } => {
            bgpfc_log::info!("rib: route refresh", peer = peer, family = family);
            rib.refresh(peer, family, now)
        }
        RibMsg::PeerDown { peer } => {
            let stats = rib.peer_stats(peer).unwrap_or_default();
            bgpfc_log::info!(
                "rib: peer down",
                peer = peer,
                routes_deleted = stats.received.iter().map(|(_, n)| n).sum::<usize>()
            );
            rib.peer_down(peer, now)
        }
        RibMsg::Query(q, reply) => {
            let _ = reply.send(answer(rib, &q));
            Vec::new()
        }
        RibMsg::SetPolicies { policies, reexport } => {
            rib.set_policies(policies.0);
            let mut out = Vec::new();
            for peer in reexport {
                let families: Vec<_> = rib
                    .peer(peer)
                    .map(|p| p.families.clone())
                    .unwrap_or_default();
                for family in families {
                    bgpfc_log::info!("rib: re-export", peer = peer, family = family);
                    out.extend(rib.reexport(peer, family, now));
                }
            }
            out
        }
        RibMsg::SetIntervals(new) => {
            *intervals = new;
            let up: Vec<(IpAddr, PeerKind, Duration)> = rib
                .peers()
                .map(|p| (p.addr, p.kind, p.advertisement_interval))
                .collect();
            let mut out = Vec::new();
            for (peer, kind, old) in up {
                let interval = advertisement_interval(configured(intervals, peer), kind);
                if interval != old {
                    bgpfc_log::info!(
                        "rib: advertisement interval",
                        peer = peer,
                        seconds = interval.as_secs()
                    );
                    out.extend(rib.set_advertisement_interval(peer, interval, now));
                }
            }
            out
        }
        RibMsg::Resend { peer } => {
            let families: Vec<_> = rib
                .peer(peer)
                .map(|p| p.families.clone())
                .unwrap_or_default();
            let mut out = Vec::new();
            for family in families {
                bgpfc_log::info!("rib: resend", peer = peer, family = family);
                out.extend(rib.refresh(peer, family, now));
            }
            out
        }
    }
}

/// The `advertisement-interval` configured for `peer`, if any.
fn configured(intervals: &Intervals, peer: IpAddr) -> Option<Duration> {
    intervals.get(&peer).copied().flatten()
}

/// The interval a session runs with: the configured one, else the
/// RFC 4271 §10 default for its type (30 s external, 5 s internal).
fn advertisement_interval(configured: Option<Duration>, kind: PeerKind) -> Duration {
    configured.unwrap_or_else(|| bgpfc_rib::pacing::default_interval(kind))
}

fn peer_info(peer: IpAddr, local_addr: IpAddr, s: &Session, interval: Duration) -> PeerInfo {
    PeerInfo {
        addr: peer,
        local_addr,
        remote_as: s.peer_as,
        router_id: s.peer_router_id,
        kind: s.peer,
        families: s.families.clone(),
        four_octet_as: s.four_octet_as,
        extended_messages: s.extended_messages,
        advertisement_interval: interval,
    }
}

fn deliver(outputs: Vec<Output>, peers: &PeerTable, fib: &SyncSender<FibMsg>) {
    for o in outputs {
        match o {
            Output::Fib(c) => {
                // A bounded channel: a slow kernel slows the RIB rather
                // than growing memory (AGENTS.md §3 backpressure).
                if fib.send(FibMsg::Change(c)).is_err() {
                    bgpfc_log::error!("fib thread gone");
                }
            }
            Output::Send { peer, messages } => {
                let handle = peers.read().ok().and_then(|t| t.get(&peer).cloned());
                let Some(handle) = handle else {
                    continue;
                };
                bgpfc_log::debug!("rib: send", peer = peer, messages = messages.len());
                match handle.tx.try_send(PeerInput::Send(messages)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        // AGENTS.md §3: never drop updates silently; the
                        // peer thread resets the session.
                        bgpfc_log::warn!("rib: peer queue full", peer = peer);
                        handle.overrun.store(true, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        bgpfc_log::warn!("rib: peer thread gone", peer = peer);
                    }
                }
            }
            Output::EncodeFailed { peer, error } => {
                bgpfc_log::error!("rib: cannot encode update", peer = peer, error = error);
            }
        }
    }
}

fn log_update(peer: IpAddr, update: &bgpfc_wire::update::DecodedUpdate) {
    let announced = update.announcements().count();
    let withdrawn = update.withdrawals().count();
    bgpfc_log::debug!(
        "rib: update",
        peer = peer,
        announced = announced,
        withdrawn = withdrawn
    );
    if bgpfc_log::enabled(bgpfc_log::Level::Trace) {
        for (family, prefix) in update.announcements() {
            bgpfc_log::trace!(
                "rib: announce",
                peer = peer,
                family = family,
                prefix = prefix
            );
        }
        for (family, prefix) in update.withdrawals() {
            bgpfc_log::trace!(
                "rib: withdraw",
                peer = peer,
                family = family,
                prefix = prefix
            );
        }
    }
}

fn answer(rib: &Rib, q: &RibQuery) -> RibReply {
    match q {
        RibQuery::Peers => RibReply::Peers(
            rib.peers()
                .map(|p| (p.clone(), rib.peer_stats(p.addr).unwrap_or_default()))
                .collect(),
        ),
        RibQuery::Routes { family, prefix } => match prefix {
            Some(prefix) => {
                let best = rib
                    .loc_rib(*family)
                    .find(|(p, _)| p == prefix)
                    .map(|(_, b)| b.peer);
                RibReply::Routes(
                    rib.candidates(*family, *prefix)
                        .iter()
                        .map(|c| RouteReport {
                            prefix: *prefix,
                            peer: c.peer,
                            attrs: std::sync::Arc::clone(&c.attrs),
                            best: best == Some(c.peer),
                        })
                        .collect(),
                )
            }
            None => RibReply::Routes(
                rib.loc_rib(*family)
                    .map(|(prefix, b)| RouteReport {
                        prefix,
                        peer: b.peer,
                        attrs: std::sync::Arc::clone(&b.attrs),
                        best: true,
                    })
                    .collect(),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn session(peer_as: u32, kind: PeerKind) -> Session {
        Session {
            peer_as: Asn(peer_as),
            peer_router_id: RouterId::new(1).unwrap(),
            peer: kind,
            hold_time: HoldTime::new(90).unwrap(),
            keepalive_time: Duration::from_secs(30),
            four_octet_as: true,
            extended_messages: false,
            route_refresh: true,
            families: vec![AddressFamily::IPV4_UNICAST],
            extended_next_hop: Vec::new(),
            peer_capabilities: Vec::new(),
        }
    }

    fn up(peer: &str, peer_as: u32, kind: PeerKind) -> RibMsg {
        RibMsg::PeerUp {
            peer: ip(peer),
            local_addr: ip("192.0.2.254"),
            session: session(peer_as, kind),
        }
    }

    #[test]
    fn intervals_default_by_session_type() {
        // RFC 4271 §10: 30 s on EBGP, 5 s on IBGP, unless configured.
        let ext = advertisement_interval(None, PeerKind::External);
        assert_eq!(ext, Duration::from_secs(30));
        let int = advertisement_interval(None, PeerKind::Internal);
        assert_eq!(int, Duration::from_secs(5));
        let off = advertisement_interval(Some(Duration::ZERO), PeerKind::External);
        assert_eq!(off, Duration::ZERO);
        let mut i = Intervals::new();
        assert_eq!(configured(&i, ip("192.0.2.1")), None);
        i.insert(ip("192.0.2.1"), Some(Duration::from_secs(9)));
        assert_eq!(
            configured(&i, ip("192.0.2.1")),
            Some(Duration::from_secs(9))
        );
    }

    #[test]
    fn sessions_start_and_follow_the_configured_intervals() {
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut intervals = Intervals::new();
        intervals.insert(ip("192.0.2.3"), Some(Duration::from_secs(2)));
        handle(
            &mut rib,
            &mut intervals,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        handle(
            &mut rib,
            &mut intervals,
            up("192.0.2.2", 65_000, PeerKind::Internal),
            now,
        );
        handle(
            &mut rib,
            &mut intervals,
            up("192.0.2.3", 65_003, PeerKind::External),
            now,
        );
        let interval = |rib: &Rib, a: &str| rib.peer(ip(a)).unwrap().advertisement_interval;
        assert_eq!(interval(&rib, "192.0.2.1"), Duration::from_secs(30));
        assert_eq!(interval(&rib, "192.0.2.2"), Duration::from_secs(5));
        assert_eq!(interval(&rib, "192.0.2.3"), Duration::from_secs(2));
        // A reload: running sessions follow, no reset.
        let mut new = Intervals::new();
        new.insert(ip("192.0.2.1"), Some(Duration::ZERO));
        handle(&mut rib, &mut intervals, RibMsg::SetIntervals(new), now);
        assert_eq!(interval(&rib, "192.0.2.1"), Duration::ZERO);
        assert_eq!(interval(&rib, "192.0.2.2"), Duration::from_secs(5));
        assert_eq!(interval(&rib, "192.0.2.3"), Duration::from_secs(30));
        assert_eq!(rib.peers().count(), 3);
    }

    #[test]
    fn waits_for_a_message_or_the_deadline() {
        let (tx, rx) = sync_channel(4);
        let down = || RibMsg::PeerDown {
            peer: ip("192.0.2.1"),
        };
        tx.send(down()).unwrap();
        assert!(matches!(next(&rx, None), Ok(Some(RibMsg::PeerDown { .. }))));
        // A deadline already passed: no wait.
        assert!(matches!(next(&rx, Some(Instant::now())), Ok(None)));
        // A deadline ahead: the thread sleeps until it.
        let start = Instant::now();
        let deadline = start + Duration::from_millis(50);
        assert!(matches!(next(&rx, Some(deadline)), Ok(None)));
        assert!(Instant::now() >= deadline);
        // A message wakes it before a later deadline.
        tx.send(down()).unwrap();
        let later = Some(Instant::now() + Duration::from_secs(60));
        assert!(matches!(next(&rx, later), Ok(Some(_))));
        drop(tx);
        assert!(matches!(next(&rx, None), Err(Closed)));
        assert!(matches!(next(&rx, later), Err(Closed)));
    }
}
