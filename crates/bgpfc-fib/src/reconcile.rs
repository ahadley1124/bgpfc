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
    /// Whether the gateway is on the interface's link though no route
    /// covers it (`RTNH_F_ONLINK`), as the kernel route that resolves the
    /// next hop says, such as an IGP's route over an unnumbered link: the
    /// kernel refuses such a gateway without it.
    pub onlink: bool,
}

impl fmt::Display for Hop {
    /// `GATEWAY`, or `GATEWAY dev OIF`, then ` onlink` if so.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.oif {
            Some(oif) => write!(f, "{} dev {oif}", self.gateway)?,
            None => write!(f, "{}", self.gateway)?,
        }
        if self.onlink {
            f.write_str(" onlink")?;
        }
        Ok(())
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

    /// Start a check of what is believed installed against what the
    /// kernel has with our protocol number ([`Check`]).
    #[must_use]
    pub fn check(&self) -> Check<'_> {
        Check {
            routes: self,
            present_v4: Vec::new(),
            present_v6: Vec::new(),
            wrong: Vec::new(),
            unknown: Vec::new(),
        }
    }

    /// The operations that make the kernel hold what is believed installed
    /// again, after a [`Check`]: a route the kernel lost is forgotten and
    /// set, so that it goes in again where no route of another program
    /// has its place; one the kernel has through another hop is set again;
    /// one of ours the kernel has and that is not believed installed is
    /// removed.
    pub fn repair(&mut self, found: Found) -> Vec<Op> {
        let mut ops = Vec::new();
        for (prefix, hop) in found.missing {
            self.install(prefix, None);
            ops.push(Op::Set { prefix, hop });
        }
        for (prefix, hop) in found.wrong {
            ops.push(Op::Set { prefix, hop });
        }
        for (prefix, hop) in found.unknown {
            ops.push(Op::Delete { prefix, hop });
        }
        ops
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

/// A check of the routes believed installed against those the kernel has
/// with our protocol number, which it is told one by one, in any order,
/// as a dump lists them ([`Check::kernel_has`]). IPv4 removes the routes
/// through an interface that goes down, or loses its address, without a
/// notification each, and the interface may be back before anything
/// reads the table: only such a check shows the loss. It keeps the
/// prefixes the kernel has, a 5-octet key for an IPv4 one, to find at the
/// end the routes believed installed that it lacks.
#[derive(Debug)]
pub struct Check<'a> {
    routes: &'a Routes,
    /// Every prefix of ours the kernel has.
    present_v4: Vec<Ipv4Key>,
    present_v6: Vec<Prefix>,
    /// Routes the kernel has through another hop, with the hop believed.
    wrong: Vec<(Prefix, Hop)>,
    /// Routes of ours the kernel has that are not believed installed.
    unknown: Vec<(Prefix, Hop)>,
}

/// What a [`Check`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Routes believed installed that the kernel lacks, with their hop.
    pub missing: Vec<(Prefix, Hop)>,
    /// Routes the kernel has through another hop, with the hop believed.
    pub wrong: Vec<(Prefix, Hop)>,
    /// Routes of ours the kernel has that are not believed installed, with
    /// the kernel's hop.
    pub unknown: Vec<(Prefix, Hop)>,
}

impl Found {
    /// Whether the kernel holds what is believed installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.wrong.is_empty() && self.unknown.is_empty()
    }
}

impl Check<'_> {
    /// The kernel has a route of ours to `prefix` through `hop`. A hop
    /// believed without an interface matches the kernel's on any.
    pub fn kernel_has(&mut self, prefix: Prefix, hop: Hop) {
        match Ipv4Key::new(prefix) {
            Some(k) => self.present_v4.push(k),
            None => self.present_v6.push(prefix),
        }
        match self.routes.installed(&prefix) {
            Some(ours)
                if ours.gateway == hop.gateway
                    && ours.onlink == hop.onlink
                    && ours.oif.is_none_or(|oif| Some(oif) == hop.oif) => {}
            Some(ours) => self.wrong.push((prefix, ours)),
            None => self.unknown.push((prefix, hop)),
        }
    }

    /// What the check found, with the routes believed installed that the
    /// kernel lacks, in prefix order.
    #[must_use]
    pub fn finish(mut self) -> Found {
        let mut missing = Vec::new();
        self.present_v4.sort_unstable();
        self.present_v6.sort_unstable();
        for (prefix, id) in self.routes.after(None) {
            let present = match Ipv4Key::new(prefix) {
                Some(k) => self.present_v4.binary_search(&k).is_ok(),
                None => self.present_v6.binary_search(&prefix).is_ok(),
            };
            if !present {
                missing.push((prefix, self.routes.hops.hop(id)));
            }
        }
        Found {
            missing,
            wrong: self.wrong,
            unknown: self.unknown,
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
            onlink: false,
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

    /// The kernel lost two routes, has one through another hop and one
    /// of ours that is not believed installed: the check finds each, and
    /// the repair sets the lost ones again as new (forgotten first, so
    /// that they go in only where no other route has their place), the
    /// wrong one again, and removes the unknown one. A kernel that holds
    /// what is believed asks for nothing.
    #[test]
    fn a_check_finds_what_the_kernel_lost() {
        let mut r = Routes::new();
        let on = |gateway: &str, oif| Hop {
            oif: Some(oif),
            ..h(gateway)
        };
        for (prefix, hop) in [
            ("10.0.0.0/8", on("192.0.2.1", 2)),
            ("10.1.0.0/16", on("192.0.2.1", 2)),
            ("10.2.0.0/16", h("192.0.2.1")),
            ("2001:db8::/32", on("fe80::1", 3)),
            ("2001:db8:1::/48", on("fe80::1", 3)),
        ] {
            r.apply(&Op::Set {
                prefix: p(prefix),
                hop,
            });
        }
        let mut check = r.check();
        // Through another gateway; a hop believed with no interface
        // matches the kernel's on any; one not believed at all.
        check.kernel_has(p("10.1.0.0/16"), on("192.0.2.9", 2));
        check.kernel_has(p("10.2.0.0/16"), on("192.0.2.1", 7));
        check.kernel_has(p("2001:db8:1::/48"), on("fe80::1", 3));
        check.kernel_has(p("172.16.0.0/12"), on("192.0.2.1", 2));
        let found = check.finish();
        assert_eq!(
            found,
            Found {
                missing: vec![
                    (p("10.0.0.0/8"), on("192.0.2.1", 2)),
                    (p("2001:db8::/32"), on("fe80::1", 3)),
                ],
                wrong: vec![(p("10.1.0.0/16"), on("192.0.2.1", 2))],
                unknown: vec![(p("172.16.0.0/12"), on("192.0.2.1", 2))],
            }
        );
        let ops = r.repair(found);
        assert_eq!(ops.len(), 4);
        assert!(matches!(ops[0], Op::Set { .. }) && matches!(ops[3], Op::Delete { .. }));
        // The lost ones are no longer believed installed: they go in anew.
        assert_eq!(r.installed(&p("10.0.0.0/8")), None);
        assert_eq!(r.installed(&p("10.1.0.0/16")), Some(on("192.0.2.1", 2)));
        assert_eq!(r.len(), 3);
        // All there, and an onlink one that is so in the kernel too.
        let mut whole = Routes::new();
        let onlink = Hop {
            onlink: true,
            ..on("192.168.77.1", 3)
        };
        whole.apply(&Op::Set {
            prefix: p("203.0.113.0/24"),
            hop: onlink,
        });
        let mut check = whole.check();
        check.kernel_has(p("203.0.113.0/24"), onlink);
        let found = check.finish();
        assert!(found.is_empty(), "{found:?}");
        assert_eq!(whole.repair(found), []);
        // The same gateway without onlink is another hop.
        let mut check = whole.check();
        check.kernel_has(p("203.0.113.0/24"), on("192.168.77.1", 3));
        assert_eq!(check.finish().wrong.len(), 1);
    }
}
