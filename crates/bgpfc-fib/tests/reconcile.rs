//! Properties (AGENTS.md §5, `bgpfc-fib` row): applying the plan to the
//! installed table yields the desired table, for any pair of tables; and a
//! route message we send decodes back to the same route, with an IPv4 or
//! an IPv6 gateway (`RTA_GATEWAY` or `RTA_VIA`).
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgpfc_fib::netlink::HEADER_LEN;
use bgpfc_fib::reconcile::{Table, apply, plan};
use bgpfc_fib::route::{RT_TABLE_MAIN, RTPROT_BGP, RouteMsg};
use bgpfc_wire::prefix::Prefix;
use proptest::prelude::*;

/// A gateway for an IPv4 route: IPv4, or IPv6 under RFC 8950 §3, so that a
/// route also moves between the two.
fn gateway() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        (1u8..4).prop_map(|g| IpAddr::V4(Ipv4Addr::new(192, 0, 2, g))),
        (1u16..4).prop_map(|g| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, g))),
    ]
}

fn table() -> impl Strategy<Value = Table> {
    proptest::collection::btree_map(
        (0u8..8, 0u8..3).prop_map(|(i, len)| {
            Prefix::new(IpAddr::V4(Ipv4Addr::new(10, i, 0, 0)), 16 + len).unwrap()
        }),
        gateway(),
        0..10,
    )
}

proptest! {
    #[test]
    fn plan_then_apply_reaches_desired(desired in table(), installed in table()) {
        let ops = plan(&desired, &installed);
        let mut now = installed.clone();
        for op in &ops {
            apply(&mut now, op);
        }
        prop_assert_eq!(&now, &desired);
        // Minimal: nothing is touched that already matches.
        let untouched = desired.iter().filter(|(p, g)| installed.get(*p) == Some(*g)).count();
        let extra = installed.keys().filter(|p| !desired.contains_key(*p)).count();
        prop_assert_eq!(ops.len(), desired.len() - untouched + extra);
        prop_assert_eq!(plan(&desired, &now), vec![]);
    }

    #[test]
    fn route_messages_round_trip(
        addr in any::<u32>(),
        len in 0u8..=32,
        gw in prop_oneof![
            any::<u32>().prop_map(|a| IpAddr::V4(Ipv4Addr::from(a))),
            any::<u128>().prop_map(|a| IpAddr::V6(Ipv6Addr::from(a))),
        ],
        table in prop_oneof![Just(RT_TABLE_MAIN), 1u32..=u32::MAX],
    ) {
        let dst = Prefix::new(IpAddr::V4(Ipv4Addr::from(addr)), len).unwrap();
        let r = RouteMsg::unicast(dst, gw, table, RTPROT_BGP);
        let m = r.encode_set(7);
        prop_assert_eq!(RouteMsg::decode(&m[HEADER_LEN..]).unwrap(), Some(r));
    }
}
