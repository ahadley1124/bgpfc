//! Property: applying the plan to the installed table yields the desired
//! table, for any pair of tables (AGENTS.md §5, `bgpfc-fib` row).
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr};

use bgpfc_fib::reconcile::{Table, apply, plan};
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
}
