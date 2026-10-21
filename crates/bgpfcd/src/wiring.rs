//! From the validated configuration to what the threads need.

use std::time::Duration;

use bgpfc_config::ast::{self, Neighbor};
use bgpfc_fsm::{Config, SendHoldTime};
use bgpfc_wire::capability::{Capability, NextHopEncoding};
use bgpfc_wire::types::{Afi, Asn, RouterId};

use crate::messages::Intervals;
use crate::peer::PeerConfig;

/// The per-peer configuration for `n`.
pub(crate) fn peer_config(local_as: Asn, router_id: RouterId, n: &Neighbor) -> PeerConfig {
    let mut fsm = Config::new(local_as, router_id, n.remote_as);
    fsm.hold_time = n.hold_time;
    fsm.keepalive_time = n.keepalive_time;
    fsm.connect_retry_time = n.connect_retry_time;
    fsm.passive = n.passive;
    fsm.collision_detect_established = n.collision_detect_established;
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
    PeerConfig {
        addr: n.addr,
        port: n.port,
        fsm,
        allow_as_set: n.allow_as_set,
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
                 collision-detect-established yes;
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
        assert_eq!(q.fsm.hold_time.secs(), 90);
        assert_eq!(q.fsm.capabilities.len(), 4);
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
}
