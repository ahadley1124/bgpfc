//! Property: applying the plan to the installed table yields the desired
//! table, for any pair of tables (AGENTS.md §5, `bgpfc-fib` row).
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr};

use bgpfc_fib::reconcile::{Routes, Table, apply, plan};
use bgpfc_wire::prefix::Prefix;
use proptest::prelude::*;

fn table() -> impl Strategy<Value = Table> {
    proptest::collection::btree_map(
        (0u8..8, 0u8..3).prop_map(|(i, len)| {
            Prefix::new(IpAddr::V4(Ipv4Addr::new(10, i, 0, 0)), 16 + len).unwrap()
        }),
        (1u8..4).prop_map(|g| IpAddr::V4(Ipv4Addr::new(192, 0, 2, g))),
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

    /// The one-map store plans exactly what the two tables do, ends at the
    /// same place, and gives back no gateway once nothing uses it.
    #[test]
    fn routes_plan_like_the_tables(desired in table(), installed in table(), later in table()) {
        let mut r = Routes::new();
        r.set_installed(&installed);
        for (p, g) in &desired {
            r.set_desired(*p, Some(*g));
        }
        prop_assert_eq!(r.desired_table(), desired.clone());
        prop_assert_eq!(r.installed_table(), installed.clone());
        let ops = r.plan();
        prop_assert_eq!(&ops, &plan(&desired, &installed));
        for op in &ops {
            r.apply(op);
        }
        prop_assert_eq!(r.installed_table(), desired.clone());
        // Move to another desired table, then to none.
        for p in desired.keys() {
            if !later.contains_key(p) {
                r.set_desired(*p, None);
            }
        }
        for (p, g) in &later {
            r.set_desired(*p, Some(*g));
        }
        prop_assert_eq!(&r.plan(), &plan(&later, &desired));
        r.clear_desired();
        for op in r.plan() {
            r.apply(&op);
        }
        prop_assert_eq!(r.gateways(), 0);
        prop_assert!(r.installed_table().is_empty());
    }
}
