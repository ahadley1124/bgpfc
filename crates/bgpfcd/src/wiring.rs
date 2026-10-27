//! From the validated configuration to what the threads need.

use std::num::NonZeroU8;
use std::time::{Duration, Instant};

use bgpfc_config::ast::{self, Neighbor};
use bgpfc_fsm::{Config, Damping, SendHoldTime};
use bgpfc_rib::{Output, Policies, Rib};
use bgpfc_wire::capability::{Capability, NextHopEncoding};
use bgpfc_wire::types::{Afi, Asn, RouterId};

use crate::messages::{Intervals, PrefixLimits, RibSettings};
use crate::peer::PeerConfig;
use crate::rpki;

/// The per-peer configuration for `n`.
pub(crate) fn peer_config(local_as: Asn, router_id: RouterId, n: &Neighbor) -> PeerConfig {
    let mut fsm = Config::new(local_as, router_id, n.remote_as);
    fsm.hold_time = n.hold_time;
    fsm.keepalive_time = n.keepalive_time;
    fsm.connect_retry_time = n.connect_retry_time;
    fsm.passive = n.passive;
    fsm.collision_detect_established = n.collision_detect_established;
    // RFC 4486 §4: the bound on consecutive automatic restarts, with the
    // RFC 4271 §8.1.1 damping it applies to.
    fsm.damping = Some(Damping {
        restart_limit: n.restart_limit,
        ..Damping::default()
    });
    fsm.send_hold_time = match n.send_hold_time {
        ast::SendHoldTime::Default => SendHoldTime::Default,
        ast::SendHoldTime::Off => SendHoldTime::Disabled,
        ast::SendHoldTime::Seconds(s) => SendHoldTime::Fixed(Duration::from_secs(u64::from(s))),
    };
    // RFC 4760 §8: one Multiprotocol capability per configured family;
    // RFC 2918 §4 and RFC 8654 §4: always offered.
    fsm.capabilities = n
        .families
        .iter()
        .map(|f| Capability::Multiprotocol(*f))
        .chain([Capability::RouteRefresh, Capability::ExtendedMessage])
        .collect();
    // RFC 8950 §4: one triple per `extended-next-hop` family, each with an
    // IPv6 next hop, in one capability.
    if !n.extended_next_hop.is_empty() {
        fsm.capabilities.push(Capability::ExtendedNextHop(
            n.extended_next_hop
                .iter()
                .map(|f| NextHopEncoding {
                    nlri_afi: f.afi,
                    nlri_safi: u16::from(f.safi.to_u8()),
                    next_hop_afi: Afi::Ipv6,
                })
                .collect(),
        ));
    }
    // RFC 4271 §10: jitter from something that differs per process.
    fsm.jitter_seed = jitter_seed(&n.addr);
    let (ttl, single_hop) = ttl(local_as, n);
    PeerConfig {
        addr: n.addr,
        port: n.port,
        fsm,
        allow_as_set: n.allow_as_set,
        ttl,
        local: n.local_address,
        single_hop,
    }
}

/// The TTL `n` is sent with, and whether it is an external neighbor held
/// to one hop. As FRR and BIRD do: an external neighbor is taken to be
/// directly connected, TTL 1, unless `multihop` says otherwise; an
/// internal one keeps the system's TTL (`None`) unless `multihop` sets
/// one (`docs/config.md`, "Neighbors").
fn ttl(local_as: Asn, n: &Neighbor) -> (Option<NonZeroU8>, bool) {
    let external = n.remote_as != local_as;
    match n.multihop {
        Some(ttl) => (Some(ttl), false),
        None if external => (Some(NonZeroU8::MIN), true),
        None => (None, false),
    }
}

/// Every neighbor's `advertisement-interval`, for the RIB thread.
pub(crate) fn advertisement_intervals(config: &bgpfc_config::Config) -> Intervals {
    config
        .neighbors
        .iter()
        .map(|n| (n.addr, n.advertisement_interval))
        .collect()
}

/// Every neighbor's `maximum-prefix` limits (RFC 4271 §6.7), for the RIB
/// thread.
pub(crate) fn prefix_limits(config: &bgpfc_config::Config) -> PrefixLimits {
    config
        .neighbors
        .iter()
        .map(|n| (n.addr, n.maximum_prefix.clone()))
        .collect()
}

/// What the RIB thread needs to know about every neighbor.
pub(crate) fn rib_settings(config: &bgpfc_config::Config) -> RibSettings {
    RibSettings {
        intervals: advertisement_intervals(config),
        prefix_limits: prefix_limits(config),
    }
}

/// The RIB the RIB thread starts with: `policies`, a jitter seed for the
/// advertisement intervals (RFC 4271 §10: they are jittered too), and the
/// `rpki` block's `enforcement` and `startup`. RFC 6811 §2: a route leaves
/// the decision process for its validation state only when "explicitly
/// configured to do so", and §5 names "rejecting all "invalid" routes"
/// among the policies; both are set before any route arrives, so that
/// every route is judged under them from the first. The startup setting
/// is the one in effect ([`rpki::startup`]): the block's with a mode that
/// validates, whose client starts before any neighbor, `accept` with
/// `mode disabled`. `Rib` itself starts with `off` and `accept`, and acts
/// on nothing until told.
pub(crate) fn rib(config: &bgpfc_config::Config, policies: Box<dyn Policies>) -> Rib {
    let mut rib = Rib::with_policies(config.local_as, policies);
    rib.set_jitter_seed(jitter_seed(&"rib"));
    // With no route held, nothing is judged again: the report that says
    // so is dropped, as the start line already names the mode.
    let mut report = Vec::new();
    rib.set_enforcement(config.rpki.enforcement, Instant::now(), &mut report);
    rib.set_startup(rpki::startup(&config.rpki), Instant::now(), &mut report);
    debug_assert!(
        report.iter().all(|o| match o {
            Output::Enforcement(r) => r.routes == 0,
            Output::Startup(r) => r.routes == 0,
            _ => false,
        }),
        "{report:?}"
    );
    rib
}

/// A jitter seed that differs per process and per `salt` (a peer's
/// address, or the RIB), from the clock and the hasher's random keys; std
/// has no RNG.
pub(crate) fn jitter_seed(salt: &impl std::hash::Hash) -> u64 {
    use std::hash::{BuildHasher, Hash, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    salt.hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos()
        .hash(&mut h);
    h.finish() | 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgpfc_wire::types::AddressFamily;
    use std::net::IpAddr;

    #[test]
    fn neighbor_becomes_peer_config() {
        let cfg = bgpfc_config::parse_str(
            "t",
            "router-id 192.0.2.1; local-as 65000;
             policy A { term t { action accept; } }
             neighbor 192.0.2.2 {
                 remote-as 65001; port 1179; hold-time 30; keepalive-time 5;
                 connect-retry-time 7; send-hold-time 120; families ipv6-unicast;
                 import A; export A; passive yes; allow-as-set yes;
                 collision-detect-established yes; restart-limit 3;
             }
             neighbor 192.0.2.3 { remote-as 65001; import A; export A; send-hold-time off; }",
        )
        .unwrap();
        let p = peer_config(cfg.local_as, cfg.router_id, &cfg.neighbors[0]);
        assert_eq!(p.addr, "192.0.2.2".parse::<IpAddr>().unwrap());
        assert_eq!(p.port, 1179);
        assert!(p.allow_as_set);
        assert_eq!(p.fsm.local_as, Asn(65_000));
        assert_eq!(p.fsm.remote_as, Asn(65_001));
        assert_eq!(p.fsm.hold_time.secs(), 30);
        assert_eq!(p.fsm.keepalive_time, Some(Duration::from_secs(5)));
        assert_eq!(p.fsm.connect_retry_time, Duration::from_secs(7));
        assert_eq!(
            p.fsm.send_hold_time,
            SendHoldTime::Fixed(Duration::from_secs(120))
        );
        assert!(p.fsm.passive);
        assert!(p.fsm.collision_detect_established);
        assert_eq!(p.fsm.damping.and_then(|d| d.restart_limit), Some(3));
        assert_eq!(
            p.fsm.capabilities,
            vec![
                Capability::Multiprotocol(AddressFamily::IPV6_UNICAST),
                Capability::RouteRefresh,
                Capability::ExtendedMessage,
            ]
        );
        assert_ne!(p.fsm.jitter_seed, 0);
        let q = peer_config(cfg.local_as, cfg.router_id, &cfg.neighbors[1]);
        assert_eq!(q.fsm.send_hold_time, SendHoldTime::Disabled);
        // The config crate's default is the FSM's.
        assert_eq!(
            bgpfc_config::ast::DEFAULT_RESTART_LIMIT,
            bgpfc_fsm::DEFAULT_RESTART_LIMIT
        );
        assert_eq!(q.fsm.damping, Some(Damping::default()));
        assert_eq!(q.fsm.hold_time.secs(), 90);
        assert_eq!(q.fsm.capabilities.len(), 4);
    }

    /// docs/config.md, "Neighbors": TTL 1 to an external neighbor unless
    /// `multihop`, the system's to an internal one unless `multihop`.
    #[test]
    fn external_neighbors_send_with_ttl_one_unless_multihop() {
        let cfg = bgpfc_config::parse_str(
            "t",
            "router-id 192.0.2.1; local-as 65000;
             policy A { term t { action accept; } }
             neighbor 192.0.2.2 { remote-as 65001; import A; export A; }
             neighbor 192.0.2.3 { remote-as 65001; import A; export A; multihop; }
             neighbor 192.0.2.4 { remote-as 65001; import A; export A; multihop 2; }
             neighbor 192.0.2.5 { remote-as 65000; import A; export A; }
             neighbor 192.0.2.6 { remote-as 65000; import A; export A; multihop; }
             neighbor 192.0.2.7 { remote-as 65000; import A; export A; multihop 3; }
             neighbor 192.0.2.8 {
                 remote-as 65001; import A; export A; local-address 192.0.2.1;
             }",
        )
        .unwrap();
        let sent: Vec<(Option<u8>, bool, Option<IpAddr>)> = cfg
            .neighbors
            .iter()
            .map(|n| {
                let p = peer_config(cfg.local_as, cfg.router_id, n);
                (p.ttl.map(NonZeroU8::get), p.single_hop, p.local)
            })
            .collect();
        let local: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(
            sent,
            [
                (Some(1), true, None),
                (Some(255), false, None),
                (Some(2), false, None),
                (None, false, None),
                (Some(255), false, None),
                (Some(3), false, None),
                (Some(1), true, Some(local)),
            ]
        );
    }

    #[test]
    fn extended_next_hop_is_advertised_only_when_configured() {
        let cfg = bgpfc_config::parse_str(
            "t",
            "router-id 192.0.2.1; local-as 65000;
             policy A { term t { action accept; } }
             neighbor 2001:db8::2 { remote-as 65001; import A; export A; extended-next-hop yes; }
             neighbor 2001:db8::3 { remote-as 65001; import A; export A; }",
        )
        .unwrap();
        // RFC 8950 §4 / §6.1: <1, 1, 2> after the other capabilities.
        let p = peer_config(cfg.local_as, cfg.router_id, &cfg.neighbors[0]);
        assert_eq!(
            p.fsm.capabilities.last(),
            Some(&Capability::ExtendedNextHop(vec![
                NextHopEncoding::IPV4_UNICAST_VIA_IPV6
            ]))
        );
        let q = peer_config(cfg.local_as, cfg.router_id, &cfg.neighbors[1]);
        assert!(
            !q.fsm
                .capabilities
                .iter()
                .any(|c| matches!(c, Capability::ExtendedNextHop(_)))
        );
    }

    #[test]
    fn advertisement_intervals_reach_the_rib_per_neighbor() {
        let cfg = bgpfc_config::parse_str(
            "t",
            "router-id 192.0.2.1; local-as 65000;
             policy A { term t { action accept; } }
             neighbor 192.0.2.2 { remote-as 65001; import A; export A; advertisement-interval 0; }
             neighbor 192.0.2.3 { remote-as 65000; import A; export A; }",
        )
        .unwrap();
        let i = advertisement_intervals(&cfg);
        assert_eq!(i.len(), 2);
        assert_eq!(
            i.get(&"192.0.2.2".parse::<IpAddr>().unwrap()),
            Some(&Some(Duration::ZERO))
        );
        // Not configured: the RIB thread picks the RFC 4271 §10 default.
        assert_eq!(i.get(&"192.0.2.3".parse::<IpAddr>().unwrap()), Some(&None));
        assert_ne!(jitter_seed(&"rib"), 0);
    }

    #[test]
    fn the_rib_starts_with_the_rpki_blocks_enforcement() {
        use bgpfc_rib::{AcceptAll, Enforcement};
        let with = |block: &str| {
            bgpfc_config::parse_str(
                "t",
                &format!("router-id 192.0.2.1; local-as 65000; {block}"),
            )
            .unwrap()
        };
        // Written or not, with validation on or off: the configured mode,
        // drop-invalid unless another is written (issue #61).
        for (block, mode) in [
            ("", Enforcement::DropInvalid),
            ("rpki { mode disabled; }", Enforcement::DropInvalid),
            (
                "rpki { mode external; cache 192.0.2.10; }",
                Enforcement::DropInvalid,
            ),
            (
                "rpki { mode external; enforcement prefer-valid; cache 192.0.2.10; }",
                Enforcement::PreferValid,
            ),
            (
                "rpki { mode external; enforcement off; cache 192.0.2.10; }",
                Enforcement::Off,
            ),
        ] {
            let cfg = with(block);
            let rib = rib(&cfg, Box::new(AcceptAll));
            assert_eq!(rib.enforcement(), mode, "{block}");
            assert_eq!(rib.local_as(), Asn(65_000));
            assert_eq!(rib.peers().count(), 0);
        }
    }

    #[test]
    fn the_rib_starts_with_the_rpki_blocks_startup_while_it_validates() {
        use bgpfc_rib::{AcceptAll, Startup};
        let with = |block: &str| {
            bgpfc_config::parse_str(
                "t",
                &format!("router-id 192.0.2.1; local-as 65000; {block}"),
            )
            .unwrap()
        };
        // RFC 6811 §2: held only where the file says so, and only in a
        // mode that will bring the data that releases the routes.
        for (block, startup) in [
            ("", Startup::Accept),
            ("rpki { mode disabled; startup hold; }", Startup::Accept),
            ("rpki { mode external; cache 192.0.2.10; }", Startup::Accept),
            (
                "rpki { mode external; startup hold; cache 192.0.2.10; }",
                Startup::Hold,
            ),
            ("rpki { mode sidecar; startup hold; }", Startup::Hold),
            ("rpki { mode sidecar; startup accept; }", Startup::Accept),
        ] {
            let cfg = with(block);
            let rib = rib(&cfg, Box::new(AcceptAll));
            assert_eq!(rib.startup(), startup, "{block}");
        }
    }

    #[test]
    fn prefix_limits_reach_the_rib_per_neighbor() {
        let cfg = bgpfc_config::parse_str(
            "t",
            "router-id 192.0.2.1; local-as 65000;
             policy A { term t { action accept; } }
             neighbor 192.0.2.2 {
                 remote-as 65001; import A; export A;
                 maximum-prefix ipv6-unicast 20; maximum-prefix ipv4-unicast 10;
             }
             neighbor 192.0.2.3 { remote-as 65000; import A; export A; }",
        )
        .unwrap();
        let s = rib_settings(&cfg);
        assert_eq!(s.intervals.len(), 2);
        assert_eq!(
            s.prefix_limits.get(&"192.0.2.2".parse::<IpAddr>().unwrap()),
            Some(&vec![
                (AddressFamily::IPV6_UNICAST, 20),
                (AddressFamily::IPV4_UNICAST, 10)
            ])
        );
        assert_eq!(
            s.prefix_limits.get(&"192.0.2.3".parse::<IpAddr>().unwrap()),
            Some(&Vec::new())
        );
    }
}
