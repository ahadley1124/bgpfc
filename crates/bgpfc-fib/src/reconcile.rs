//! Desired versus installed: the operations that turn one into the other
//! (AGENTS.md §3, "FIB thread"). Pure, so it can be property-tested.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::ops::Bound::{Excluded, Unbounded};

use bgpfc_wire::prefix::{Ipv4Key, Prefix};

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

/// A gateway's index in [`Gateways`], plus one, so that an absent
/// gateway costs nothing extra.
type GwId = NonZeroU32;

/// The distinct gateways routes use, each stored once with the number of
/// uses. A full table names a handful of gateways, so a route holds a
/// 4-octet index instead of a 17-octet address.
#[derive(Debug, Default)]
struct Gateways {
    addrs: Vec<IpAddr>,
    uses: Vec<u32>,
    index: HashMap<IpAddr, GwId>,
    free: Vec<GwId>,
    /// The gateway used last: the prefixes of one UPDATE share theirs,
    /// so most lookups end here without hashing.
    last: Option<GwId>,
}

impl Gateways {
    fn slot(id: GwId) -> usize {
        // invariant: ids are made from Vec indices plus one.
        usize::try_from(id.get() - 1).unwrap()
    }

    fn addr(&self, id: GwId) -> IpAddr {
        self.addrs[Gateways::slot(id)]
    }

    /// One more use of `addr`.
    fn hold(&mut self, addr: IpAddr) -> GwId {
        let known = match self.last {
            Some(id)
                if self.uses[Gateways::slot(id)] > 0 && self.addrs[Gateways::slot(id)] == addr =>
            {
                Some(id)
            }
            _ => self.index.get(&addr).copied(),
        };
        if let Some(id) = known {
            self.uses[Gateways::slot(id)] += 1;
            self.last = Some(id);
            return id;
        }
        let id = if let Some(id) = self.free.pop() {
            self.addrs[Gateways::slot(id)] = addr;
            self.uses[Gateways::slot(id)] = 1;
            id
        } else {
            self.addrs.push(addr);
            self.uses.push(1);
            // invariant: fewer than 2^32 gateways, and the length is at
            // least one after the push.
            NonZeroU32::new(u32::try_from(self.addrs.len()).unwrap()).unwrap()
        };
        self.index.insert(addr, id);
        self.last = Some(id);
        id
    }

    /// One use of `id` fewer; the slot is reused once none is left.
    fn release(&mut self, id: GwId) {
        let uses = &mut self.uses[Gateways::slot(id)];
        *uses -= 1;
        if *uses == 0 {
            self.index.remove(&self.addrs[Gateways::slot(id)]);
            self.free.push(id);
        }
    }

    fn len(&self) -> usize {
        self.index.len()
    }
}

/// Octets one IPv4 route takes in a [`Routes`] table node: the key and the
/// gateway index (for `bgpfcd --print-sizes`).
pub const ROUTE_SIZE: usize = size_of::<Ipv4Key>() + size_of::<GwId>();

/// The routes the kernel has with our protocol number, as far as we know,
/// each gateway stored once. What the RIB wants is not kept here: a change
/// comes with the next hop it replaces, which is all dry-run needs to
/// report, and a full reconcile walks the RIB's routes in prefix order
/// against these ([`Routes::merge`]), as [`plan`] does with two tables.
#[derive(Debug, Default)]
pub struct Routes {
    /// IPv4 routes, keyed in 5 octets rather than a `Prefix`'s 18: a full
    /// table is mostly B-tree nodes, eleven keys each.
    v4: BTreeMap<Ipv4Key, GwId>,
    v6: BTreeMap<Prefix, GwId>,
    gateways: Gateways,
}

/// How far a reconcile ([`Routes::merge`]) has come: every installed route
/// up to `done`, inclusive, has been dealt with.
#[derive(Clone, Copy, Debug, Default)]
pub struct Merge {
    done: Option<Prefix>,
}

impl Routes {
    /// No routes.
    #[must_use]
    pub fn new() -> Routes {
        Routes::default()
    }

    /// The gateway the kernel has for `prefix`, as far as we know.
    #[must_use]
    pub fn installed(&self, prefix: &Prefix) -> Option<IpAddr> {
        let id = match Ipv4Key::new(*prefix) {
            Some(k) => self.v4.get(&k),
            None => self.v6.get(prefix),
        }?;
        Some(self.gateways.addr(*id))
    }

    /// Routes installed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Whether no route is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Record that the kernel carried out `op`.
    pub fn apply(&mut self, op: &Op) {
        match op {
            Op::Set { prefix, gateway } => self.install(*prefix, Some(*gateway)),
            Op::Delete { prefix, .. } => self.install(*prefix, None),
        }
    }

    /// Replace what is believed installed with `kernel` (the startup dump).
    pub fn set_installed(&mut self, kernel: &Table) {
        *self = Routes::new();
        for (prefix, gateway) in kernel {
            self.install(*prefix, Some(*gateway));
        }
    }

    /// The operations that remove every installed route, in prefix order.
    #[must_use]
    pub fn delete_all(&self) -> Vec<Op> {
        self.after(None)
            .map(|(prefix, id)| Op::Delete {
                prefix,
                gateway: self.gateways.addr(id),
            })
            .collect()
    }

    /// Reconcile part of a desired table: `desired` continues, in prefix
    /// order, the routes `merge` has seen. Adds to `ops` a `Set` for each
    /// route missing or with another gateway, and a `Delete` for each
    /// installed route that the desired table skips; [`Routes::merge_end`]
    /// deletes those past its end. Together they give what [`plan`] gives
    /// for the whole desired table, in prefix order. The operations are
    /// worked out from what is installed before any of them is carried
    /// out, so each prefix must come once.
    pub fn merge(&self, merge: &mut Merge, desired: &[(Prefix, IpAddr)], ops: &mut Vec<Op>) {
        for &(prefix, gateway) in desired {
            debug_assert!(merge.done.is_none_or(|d| d < prefix), "out of order");
            for (stale, id) in self.after(merge.done).take_while(|(p, _)| *p < prefix) {
                ops.push(Op::Delete {
                    prefix: stale,
                    gateway: self.gateways.addr(id),
                });
            }
            if self.installed(&prefix) != Some(gateway) {
                ops.push(Op::Set { prefix, gateway });
            }
            merge.done = Some(prefix);
        }
    }

    /// End a reconcile: delete what is installed past the last desired
    /// route.
    pub fn merge_end(&self, merge: Merge, ops: &mut Vec<Op>) {
        for (stale, id) in self.after(merge.done) {
            ops.push(Op::Delete {
                prefix: stale,
                gateway: self.gateways.addr(id),
            });
        }
    }

    /// The installed routes as a table (for reports).
    #[must_use]
    pub fn installed_table(&self) -> Table {
        self.after(None)
            .map(|(p, id)| (p, self.gateways.addr(id)))
            .collect()
    }

    /// Distinct gateways in use.
    #[must_use]
    pub fn gateways(&self) -> usize {
        self.gateways.len()
    }

    /// The installed routes after `from` (all of them for `None`), in
    /// prefix order: a long listing taken a part at a time.
    pub fn installed_after(&self, from: Option<Prefix>) -> impl Iterator<Item = (Prefix, IpAddr)> {
        self.after(from).map(|(p, id)| (p, self.gateways.addr(id)))
    }

    /// The installed routes after `from` (all of them for `None`), in
    /// prefix order: IPv4 sorts first.
    fn after(&self, from: Option<Prefix>) -> impl Iterator<Item = (Prefix, GwId)> + '_ {
        let (v4, v6) = match from {
            None => (Some(self.v4.range(..)), self.v6.range(..)),
            Some(p) => match Ipv4Key::new(p) {
                Some(k) => (
                    Some(self.v4.range((Excluded(k), Unbounded))),
                    self.v6.range(..),
                ),
                None => (None, self.v6.range((Excluded(p), Unbounded))),
            },
        };
        v4.into_iter()
            .flatten()
            .map(|(k, id)| (k.prefix(), *id))
            .chain(v6.map(|(p, id)| (*p, *id)))
    }

    fn install(&mut self, prefix: Prefix, gateway: Option<IpAddr>) {
        let new = gateway.map(|g| self.gateways.hold(g));
        let old = match (Ipv4Key::new(prefix), new) {
            (Some(k), Some(id)) => self.v4.insert(k, id),
            (Some(k), None) => self.v4.remove(&k),
            (None, Some(id)) => self.v6.insert(prefix, id),
            (None, None) => self.v6.remove(&prefix),
        };
        if let Some(id) = old {
            self.gateways.release(id);
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

    #[test]
    fn routes_store_each_gateway_once() {
        assert_eq!(ROUTE_SIZE, 9);
        let mut r = Routes::new();
        let set = |prefix, gateway| Op::Set {
            prefix: p(prefix),
            gateway: ip(gateway),
        };
        r.apply(&set("10.0.0.0/8", "1.1.1.1"));
        r.apply(&set("10.1.0.0/16", "1.1.1.1"));
        assert_eq!(r.gateways(), 1);
        assert_eq!(r.installed(&p("10.1.0.0/16")), Some(ip("1.1.1.1")));
        // A new gateway for one prefix; the old one is still used.
        r.apply(&set("10.1.0.0/16", "2.2.2.2"));
        assert_eq!(r.gateways(), 2);
        assert_eq!(r.len(), 2);
        // Removing everything empties the gateways too.
        for op in r.delete_all() {
            r.apply(&op);
        }
        assert_eq!(r.gateways(), 0);
        assert!(r.is_empty());
        // A freed gateway slot is reused.
        r.apply(&set("10.0.0.0/8", "3.3.3.3"));
        assert_eq!(r.gateways.addrs.len(), 2);
    }

    #[test]
    fn merge_walks_both_families_in_order() {
        let installed: Table = [
            (p("10.0.0.0/8"), ip("1.1.1.1")),
            (p("10.2.0.0/16"), ip("3.3.3.3")),
            (p("2001:db8::/32"), ip("1.1.1.1")),
            (p("2001:db8:1::/48"), ip("1.1.1.1")),
        ]
        .into_iter()
        .collect();
        let mut r = Routes::new();
        r.set_installed(&installed);
        let mut merge = Merge::default();
        let mut ops = Vec::new();
        r.merge(&mut merge, &[(p("10.1.0.0/16"), ip("2.2.2.2"))], &mut ops);
        r.merge(&mut merge, &[(p("2001:db8::/32"), ip("1.1.1.1"))], &mut ops);
        r.merge_end(merge, &mut ops);
        let delete = |prefix, gateway| Op::Delete {
            prefix: p(prefix),
            gateway: ip(gateway),
        };
        assert_eq!(
            ops,
            vec![
                delete("10.0.0.0/8", "1.1.1.1"),
                Op::Set {
                    prefix: p("10.1.0.0/16"),
                    gateway: ip("2.2.2.2")
                },
                delete("10.2.0.0/16", "3.3.3.3"),
                delete("2001:db8:1::/48", "1.1.1.1"),
            ]
        );
    }

    #[test]
    fn set_installed_replaces_what_was_believed() {
        let mut r = Routes::new();
        r.apply(&Op::Set {
            prefix: p("10.0.0.0/8"),
            gateway: ip("1.1.1.1"),
        });
        let kernel: Table = [(p("10.2.0.0/16"), ip("3.3.3.3"))].into_iter().collect();
        r.set_installed(&kernel);
        assert_eq!(r.installed_table(), kernel);
        assert_eq!(r.gateways(), 1);
    }
}
