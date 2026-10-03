//! Desired versus installed: the operations that turn one into the other
//! (AGENTS.md §3, "FIB thread"). Pure, so it can be property-tested.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bgpfc_wire::prefix::Prefix;

/// A route: one prefix, one gateway (single best path only).
pub type Table = BTreeMap<Prefix, IpAddr>;

/// One kernel operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Install or replace the route to `prefix` via `gateway`.
    Set {
        /// Destination.
        prefix: Prefix,
        /// Gateway.
        gateway: IpAddr,
    },
    /// Remove the route to `prefix`.
    Delete {
        /// Destination.
        prefix: Prefix,
        /// The gateway it had (the kernel matches on it).
        gateway: IpAddr,
    },
}

/// The operations, in prefix order, that make `installed` equal
/// `desired`: a `Set` for every prefix missing or with another gateway,
/// a `Delete` for every prefix only `installed` has.
#[must_use]
pub fn plan(desired: &Table, installed: &Table) -> Vec<Op> {
    let mut ops = Vec::new();
    for (prefix, gateway) in desired {
        if installed.get(prefix) != Some(gateway) {
            ops.push(Op::Set {
                prefix: *prefix,
                gateway: *gateway,
            });
        }
    }
    for (prefix, gateway) in installed {
        if !desired.contains_key(prefix) {
            ops.push(Op::Delete {
                prefix: *prefix,
                gateway: *gateway,
            });
        }
    }
    ops
}

/// Record a successful `op` in `installed`.
pub fn apply(installed: &mut Table, op: &Op) {
    match op {
        Op::Set { prefix, gateway } => {
            installed.insert(*prefix, *gateway);
        }
        Op::Delete { prefix, .. } => {
            installed.remove(prefix);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn plan_sets_changed_and_deletes_extra() {
        let desired: Table = [
            (p("10.0.0.0/8"), ip("1.1.1.1")),
            (p("10.1.0.0/16"), ip("2.2.2.2")),
        ]
        .into_iter()
        .collect();
        let installed: Table = [
            (p("10.0.0.0/8"), ip("1.1.1.1")),
            (p("10.1.0.0/16"), ip("9.9.9.9")),
            (p("10.2.0.0/16"), ip("3.3.3.3")),
        ]
        .into_iter()
        .collect();
        let ops = plan(&desired, &installed);
        assert_eq!(
            ops,
            vec![
                Op::Set {
                    prefix: p("10.1.0.0/16"),
                    gateway: ip("2.2.2.2")
                },
                Op::Delete {
                    prefix: p("10.2.0.0/16"),
                    gateway: ip("3.3.3.3")
                },
            ]
        );
        let mut now = installed;
        for op in &ops {
            apply(&mut now, op);
        }
        assert_eq!(now, desired);
        assert_eq!(plan(&desired, &desired), vec![]);
    }
}
