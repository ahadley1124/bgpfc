//! Desired versus installed: the operations that turn one into the other
//! (AGENTS.md §3, "FIB thread"). Pure, so it can be property-tested.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::ops::Bound::{Excluded, Unbounded};

use bgpfc_wire::prefix::{Ipv4Key, Prefix};

/// What a route goes through: the immediate next hop, and the interface
/// it is reached on when known. A BGP next hop on a connected network is
/// its own gateway; one further away goes through the gateway of the
/// kernel route that resolves it (RFC 4271 §9.1.2.1, BIRD's `gateway
/// recursive`). Two routes through one gateway on different interfaces
/// are different routes: IPv4 removes the routes through an interface
/// that goes down without a word, and a next hop that comes back through
/// another interface must be installed again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hop {
    /// The gateway (`RTA_GATEWAY`, or `RTA_VIA` for an IPv6 gateway of an
    /// IPv4 route).
    pub gateway: IpAddr,
    /// The interface index (`RTA_OIF`); `None` leaves it to the kernel.
    pub oif: Option<u32>,
}

impl fmt::Display for Hop {
    /// `GATEWAY`, or `GATEWAY dev OIF`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.oif {
            Some(oif) => write!(f, "{} dev {oif}", self.gateway),
            None => write!(f, "{}", self.gateway),
        }
    }
}

/// A route: one prefix, one hop (single best path only).
pub type Table = BTreeMap<Prefix, Hop>;

/// One kernel operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Install or replace the route to `prefix` through `hop`.
    Set {
        /// Destination.
        prefix: Prefix,
        /// What it goes through.
        hop: Hop,
    },
    /// Remove the route to `prefix`.
    Delete {
        /// Destination.
        prefix: Prefix,
        /// The hop it had (the kernel matches on it).
        hop: Hop,
    },
}

impl Op {
    /// The destination.
    #[must_use]
    pub fn prefix(&self) -> Prefix {
        match self {
            Op::Set { prefix, .. } | Op::Delete { prefix, .. } => *prefix,
        }
    }

    /// The hop.
    #[must_use]
    pub fn hop(&self) -> Hop {
        match self {
            Op::Set { hop, .. } | Op::Delete { hop, .. } => *hop,
        }
    }
}

/// The operations, in prefix order, that make `installed` equal
/// `desired`: a `Set` for every prefix missing or with another hop, a
/// `Delete` for every prefix only `installed` has.
#[must_use]
pub fn plan(desired: &Table, installed: &Table) -> Vec<Op> {
    let mut ops = Vec::new();
    for (prefix, hop) in desired {
        if installed.get(prefix) != Some(hop) {
            ops.push(Op::Set {
                prefix: *prefix,
                hop: *hop,
            });
        }
    }
    for (prefix, hop) in installed {
        if !desired.contains_key(prefix) {
            ops.push(Op::Delete {
                prefix: *prefix,
                hop: *hop,
            });
        }
    }
    ops
}

/// Record a successful `op` in `installed`.
pub fn apply(installed: &mut Table, op: &Op) {
    match op {
        Op::Set { prefix, hop } => {
            installed.insert(*prefix, *hop);
        }
        Op::Delete { prefix, .. } => {
            installed.remove(prefix);
        }
    }
}

/// A hop's index in [`Hops`], plus one, so that an absent hop costs
/// nothing extra.
type GwId = NonZeroU32;

/// The distinct hops routes use, each stored once with the number of
/// uses. A full table names a handful of hops, so a route holds a 4-octet
/// index instead of an address and an interface.
#[derive(Debug, Default)]
struct Hops {
    list: Vec<Hop>,
    uses: Vec<u32>,
    index: HashMap<Hop, GwId>,
    free: Vec<GwId>,
    /// The hop used last: the prefixes of one UPDATE share theirs, so
    /// most lookups end here without hashing.
    last: Option<GwId>,
}

impl Hops {
    fn slot(id: GwId) -> usize {
        // invariant: ids are made from Vec indices plus one.
        usize::try_from(id.get() - 1).unwrap()
    }

    fn hop(&self, id: GwId) -> Hop {
        self.list[Hops::slot(id)]
    }

    /// One more use of `hop`.
    fn hold(&mut self, hop: Hop) -> GwId {
        let known = match self.last {
            Some(id) if self.uses[Hops::slot(id)] > 0 && self.list[Hops::slot(id)] == hop => {
                Some(id)
            }
            _ => self.index.get(&hop).copied(),
        };
        if let Some(id) = known {
            self.uses[Hops::slot(id)] += 1;
            self.last = Some(id);
            return id;
        }
        let id = if let Some(id) = self.free.pop() {
            self.list[Hops::slot(id)] = hop;
            self.uses[Hops::slot(id)] = 1;
            id
        } else {
            self.list.push(hop);
            self.uses.push(1);
            // invariant: fewer than 2^32 hops, and the length is at least
            // one after the push.
            NonZeroU32::new(u32::try_from(self.list.len()).unwrap()).unwrap()
        };
        self.index.insert(hop, id);
        self.last = Some(id);
        id
    }

    /// One use of `id` fewer; the slot is reused once none is left.
    fn release(&mut self, id: GwId) {
        let uses = &mut self.uses[Hops::slot(id)];
        *uses -= 1;
        if *uses == 0 {
            self.index.remove(&self.list[Hops::slot(id)]);
            self.free.push(id);
        }
    }

    fn len(&self) -> usize {
        self.index.len()
    }
}

/// Octets one IPv4 route takes in a [`Routes`] table node: the key and the
/// hop index (for `bgpfcd --print-sizes`).
pub const ROUTE_SIZE: usize = size_of::<Ipv4Key>() + size_of::<GwId>();

/// The routes the kernel has with our protocol number, as far as we know,
/// each hop stored once. What the RIB wants is not kept here: a change
/// comes with the hop it replaces, which is all dry-run needs to report,
/// and a full reconcile walks the RIB's routes in prefix order against
/// these ([`Routes::merge`]), as [`plan`] does with two tables.
#[derive(Debug, Default)]
pub struct Routes {
    /// IPv4 routes, keyed in 5 octets rather than a `Prefix`'s 18: a full
    /// table is mostly B-tree nodes, eleven keys each.
    v4: BTreeMap<Ipv4Key, GwId>,
    v6: BTreeMap<Prefix, GwId>,
    hops: Hops,
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

    /// The hop the kernel has for `prefix`, as far as we know.
    #[must_use]
    pub fn installed(&self, prefix: &Prefix) -> Option<Hop> {
        let id = match Ipv4Key::new(*prefix) {
            Some(k) => self.v4.get(&k),
            None => self.v6.get(prefix),
        }?;
        Some(self.hops.hop(*id))
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
            Op::Set { prefix, hop } => self.install(*prefix, Some(*hop)),
            Op::Delete { prefix, .. } => self.install(*prefix, None),
        }
    }

    /// Replace what is believed installed with `kernel` (the startup dump).
    pub fn set_installed(&mut self, kernel: &Table) {
        *self = Routes::new();
        for (prefix, hop) in kernel {
            self.install(*prefix, Some(*hop));
        }
    }

    /// The operations that remove every installed route, in prefix order.
    #[must_use]
    pub fn delete_all(&self) -> Vec<Op> {
        self.after(None)
            .map(|(prefix, id)| Op::Delete {
                prefix,
                hop: self.hops.hop(id),
            })
            .collect()
    }

    /// Reconcile part of a desired table: `desired` continues, in prefix
    /// order, the routes `merge` has seen. Adds to `ops` a `Set` for each
    /// route missing or with another hop, and a `Delete` for each
    /// installed route that the desired table skips; [`Routes::merge_end`]
    /// deletes those past its end. Together they give what [`plan`] gives
    /// for the whole desired table, in prefix order. The operations are
    /// worked out from what is installed before any of them is carried
    /// out, so each prefix must come once.
    pub fn merge(&self, merge: &mut Merge, desired: &[(Prefix, Hop)], ops: &mut Vec<Op>) {
        for &(prefix, hop) in desired {
            debug_assert!(merge.done.is_none_or(|d| d < prefix), "out of order");
            for (stale, id) in self.after(merge.done).take_while(|(p, _)| *p < prefix) {
                ops.push(Op::Delete {
                    prefix: stale,
                    hop: self.hops.hop(id),
                });
            }
            if self.installed(&prefix) != Some(hop) {
                ops.push(Op::Set { prefix, hop });
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
                hop: self.hops.hop(id),
            });
        }
    }

    /// The installed routes as a table (for reports).
    #[must_use]
    pub fn installed_table(&self) -> Table {
        self.after(None)
            .map(|(p, id)| (p, self.hops.hop(id)))
            .collect()
    }

    /// Distinct hops in use.
    #[must_use]
    pub fn hops(&self) -> usize {
        self.hops.len()
    }

    /// The installed routes after `from` (all of them for `None`), in
    /// prefix order: a long listing taken a part at a time.
    pub fn installed_after(&self, from: Option<Prefix>) -> impl Iterator<Item = (Prefix, Hop)> {
        self.after(from).map(|(p, id)| (p, self.hops.hop(id)))
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

    fn install(&mut self, prefix: Prefix, hop: Option<Hop>) {
        let new = hop.map(|h| self.hops.hold(h));
        let old = match (Ipv4Key::new(prefix), new) {
            (Some(k), Some(id)) => self.v4.insert(k, id),
            (Some(k), None) => self.v4.remove(&k),
            (None, Some(id)) => self.v6.insert(prefix, id),
            (None, None) => self.v6.remove(&prefix),
        };
        if let Some(id) = old {
            self.hops.release(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    /// A hop through `gateway`, with no interface.
    fn h(gateway: &str) -> Hop {
        Hop {
            gateway: gateway.parse().unwrap(),
            oif: None,
        }
    }

    #[test]
    fn plan_sets_changed_and_deletes_extra() {
        let desired: Table = [
            (p("10.0.0.0/8"), h("1.1.1.1")),
            (p("10.1.0.0/16"), h("2.2.2.2")),
        ]
        .into_iter()
        .collect();
        let installed: Table = [
            (p("10.0.0.0/8"), h("1.1.1.1")),
            (p("10.1.0.0/16"), h("9.9.9.9")),
            (p("10.2.0.0/16"), h("3.3.3.3")),
        ]
        .into_iter()
        .collect();
        let ops = plan(&desired, &installed);
        assert_eq!(
            ops,
            vec![
                Op::Set {
                    prefix: p("10.1.0.0/16"),
                    hop: h("2.2.2.2")
                },
                Op::Delete {
                    prefix: p("10.2.0.0/16"),
                    hop: h("3.3.3.3")
                },
            ]
        );
        assert_eq!(ops[1].prefix(), p("10.2.0.0/16"));
        assert_eq!(ops[1].hop(), h("3.3.3.3"));
        let mut now = installed;
        for op in &ops {
            apply(&mut now, op);
        }
        assert_eq!(now, desired);
        assert_eq!(plan(&desired, &desired), vec![]);
    }

    /// One gateway on two interfaces is two hops: a route that moves from
    /// one to the other is installed again.
    #[test]
    fn one_gateway_on_two_interfaces_is_two_routes() {
        let on = |oif| Hop {
            oif: Some(oif),
            ..h("192.0.2.1")
        };
        let installed: Table = [(p("10.0.0.0/8"), on(2))].into_iter().collect();
        let desired: Table = [(p("10.0.0.0/8"), on(3))].into_iter().collect();
        assert_eq!(
            plan(&desired, &installed),
            vec![Op::Set {
                prefix: p("10.0.0.0/8"),
                hop: on(3)
            }]
        );
        let mut r = Routes::new();
        r.apply(&Op::Set {
            prefix: p("10.0.0.0/8"),
            hop: on(2),
        });
        r.apply(&Op::Set {
            prefix: p("10.1.0.0/16"),
            hop: on(3),
        });
        r.apply(&Op::Set {
            prefix: p("10.2.0.0/16"),
            hop: h("192.0.2.1"),
        });
        assert_eq!(r.hops(), 3);
        assert_eq!(r.installed(&p("10.1.0.0/16")), Some(on(3)));
        assert_eq!(on(3).to_string(), "192.0.2.1 dev 3");
        assert_eq!(h("192.0.2.1").to_string(), "192.0.2.1");
    }

    #[test]
    fn routes_store_each_hop_once() {
        assert_eq!(ROUTE_SIZE, 9);
        let mut r = Routes::new();
        let set = |prefix, gateway| Op::Set {
            prefix: p(prefix),
            hop: h(gateway),
        };
        r.apply(&set("10.0.0.0/8", "1.1.1.1"));
        r.apply(&set("10.1.0.0/16", "1.1.1.1"));
        assert_eq!(r.hops(), 1);
        assert_eq!(r.installed(&p("10.1.0.0/16")), Some(h("1.1.1.1")));
        // A new hop for one prefix; the old one is still used.
        r.apply(&set("10.1.0.0/16", "2.2.2.2"));
        assert_eq!(r.hops(), 2);
        assert_eq!(r.len(), 2);
        // Removing everything empties the hops too.
        for op in r.delete_all() {
            r.apply(&op);
        }
        assert_eq!(r.hops(), 0);
        assert!(r.is_empty());
        // A freed slot is reused.
        r.apply(&set("10.0.0.0/8", "3.3.3.3"));
        assert_eq!(r.hops.list.len(), 2);
    }

    #[test]
    fn merge_walks_both_families_in_order() {
        let installed: Table = [
            (p("10.0.0.0/8"), h("1.1.1.1")),
            (p("10.2.0.0/16"), h("3.3.3.3")),
            (p("2001:db8::/32"), h("1.1.1.1")),
            (p("2001:db8:1::/48"), h("1.1.1.1")),
        ]
        .into_iter()
        .collect();
        let mut r = Routes::new();
        r.set_installed(&installed);
        let mut merge = Merge::default();
        let mut ops = Vec::new();
        r.merge(&mut merge, &[(p("10.1.0.0/16"), h("2.2.2.2"))], &mut ops);
        r.merge(&mut merge, &[(p("2001:db8::/32"), h("1.1.1.1"))], &mut ops);
        r.merge_end(merge, &mut ops);
        let delete = |prefix, gateway| Op::Delete {
            prefix: p(prefix),
            hop: h(gateway),
        };
        assert_eq!(
            ops,
            vec![
                delete("10.0.0.0/8", "1.1.1.1"),
                Op::Set {
                    prefix: p("10.1.0.0/16"),
                    hop: h("2.2.2.2")
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
            hop: h("1.1.1.1"),
        });
        let kernel: Table = [(p("10.2.0.0/16"), h("3.3.3.3"))].into_iter().collect();
        r.set_installed(&kernel);
        assert_eq!(r.installed_table(), kernel);
        assert_eq!(r.hops(), 1);
    }
}
