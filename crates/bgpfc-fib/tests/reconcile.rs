//! Properties (AGENTS.md §5, `bgpfc-fib` row): applying the plan to the
//! installed table yields the desired table, for any pair of tables, and
//! the merge the FIB runs against the RIB's routes plans the same; and a
//! route message we send decodes back to the same route, with an IPv4 or
//! an IPv6 gateway (`RTA_GATEWAY` or `RTA_VIA`).
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgpfc_fib::netlink::HEADER_LEN;
use bgpfc_fib::reconcile::{Merge, Op, Routes, Table, apply, plan};
use bgpfc_fib::route::{RT_TABLE_MAIN, RTPROT_BGP, RouteMsg};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Afi;
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
    // Both families: IPv4 and IPv6 routes are kept apart and must come out
    // in one prefix order.
    proptest::collection::btree_map(
        (0u8..8, 0u8..3, any::<bool>()).prop_map(|(i, len, v6)| {
            if v6 {
                let addr = Ipv6Addr::new(0x2001, 0xdb8, u16::from(i), 0, 0, 0, 0, 0);
                Prefix::new(IpAddr::V6(addr), 48 + len).unwrap()
            } else {
                Prefix::new(IpAddr::V4(Ipv4Addr::new(10, i, 0, 0)), 16 + len).unwrap()
            }
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

    /// Merging the desired table, cut in any places, against what is
    /// installed gives the operations `plan` gives (in prefix order rather
    /// than sets first), reaches the desired table, and gives back every
    /// gateway once nothing uses it.
    #[test]
    fn merge_plans_like_the_tables(
        desired in table(),
        installed in table(),
        mut cuts in proptest::collection::vec(0usize..12, 0..4),
    ) {
        let mut r = Routes::new();
        r.set_installed(&installed);
        prop_assert_eq!(r.installed_table(), installed.clone());
        let want: Vec<(Prefix, IpAddr)> = desired.iter().map(|(p, g)| (*p, *g)).collect();
        cuts.sort_unstable();
        let mut merge = Merge::default();
        let mut ops = Vec::new();
        let mut at = 0;
        for cut in cuts {
            let cut = cut.clamp(at, want.len());
            r.merge(&mut merge, &want[at..cut], &mut ops);
            at = cut;
        }
        r.merge(&mut merge, &want[at..], &mut ops);
        r.merge_end(merge, &mut ops);
        let mut expected = plan(&desired, &installed);
        expected.sort_by_key(prefix);
        prop_assert!(ops.is_sorted_by_key(prefix));
        prop_assert_eq!(&ops, &expected);
        for op in &ops {
            r.apply(op);
        }
        prop_assert_eq!(r.installed_table(), desired);
        for op in r.delete_all() {
            r.apply(&op);
        }
        prop_assert_eq!(r.gateways(), 0);
        prop_assert!(r.is_empty());
    }
}

proptest! {
    /// A reconcile of one family, cut in any places, plans what `plan`
    /// plans for that family's routes alone and leaves the other family
    /// as it is (RFC 4724 §4.1 ends the wait family by family); the two
    /// families together give the operations of the whole table.
    #[test]
    fn a_family_merge_touches_only_its_family(
        desired in table(),
        installed in table(),
        v6 in any::<bool>(),
        cut in 0usize..12,
    ) {
        let afi = if v6 { Afi::Ipv6 } else { Afi::Ipv4 };
        let of = |t: &Table, afi: Afi| -> Table {
            t.iter().filter(|(p, _)| p.afi() == afi).map(|(p, g)| (*p, *g)).collect()
        };
        let mut r = Routes::new();
        r.set_installed(&installed);
        prop_assert_eq!(r.count(Afi::Ipv4), of(&installed, Afi::Ipv4).len());
        prop_assert_eq!(r.count(Afi::Ipv6), of(&installed, Afi::Ipv6).len());
        let want: Vec<(Prefix, IpAddr)> =
            of(&desired, afi).into_iter().collect();
        let cut = cut.min(want.len());
        let mut merge = Merge::of(afi);
        let mut ops = Vec::new();
        r.merge(&mut merge, &want[..cut], &mut ops);
        r.merge(&mut merge, &want[cut..], &mut ops);
        r.merge_end(merge, &mut ops);
        let mut expected = plan(&of(&desired, afi), &of(&installed, afi));
        expected.sort_by_key(prefix);
        prop_assert_eq!(&ops, &expected);
        for op in &ops {
            r.apply(op);
        }
        prop_assert_eq!(of(&r.installed_table(), afi), of(&desired, afi));
        let other = if v6 { Afi::Ipv4 } else { Afi::Ipv6 };
        prop_assert_eq!(of(&r.installed_table(), other), of(&installed, other));
    }

    /// Removing every family but the ones kept leaves exactly those.
    #[test]
    fn deleting_all_but_the_kept_families_keeps_them(
        installed in table(),
        keep4 in any::<bool>(),
        keep6 in any::<bool>(),
    ) {
        let keep: Vec<Afi> = [(keep4, Afi::Ipv4), (keep6, Afi::Ipv6)]
            .into_iter()
            .filter_map(|(k, a)| k.then_some(a))
            .collect();
        let mut r = Routes::new();
        r.set_installed(&installed);
        let ops = r.delete_except(&keep);
        prop_assert!(ops.is_sorted_by_key(prefix));
        for op in &ops {
            prop_assert!(!keep.contains(&prefix(op).afi()));
            r.apply(op);
        }
        let left: Table = installed
            .iter()
            .filter(|(p, _)| keep.contains(&p.afi()))
            .map(|(p, g)| (*p, *g))
            .collect();
        prop_assert_eq!(r.installed_table(), left);
    }
}

fn prefix(op: &Op) -> Prefix {
    match op {
        Op::Set { prefix, .. } | Op::Delete { prefix, .. } => *prefix,
    }
}
