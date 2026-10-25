//! Desired versus installed: the operations that turn one into the other
//! (AGENTS.md §3, "FIB thread"). Pure, so it can be property-tested.

use std::collections::btree_map::Entry as Slot;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::num::NonZeroU32;

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

/// The gateway the RIB wants for a prefix and the one the kernel has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Entry {
    desired: Option<GwId>,
    installed: Option<GwId>,
}

/// Octets one IPv4 route takes in a [`Routes`] table node: the key and the
/// two gateway indices (for `bgpfcd --print-sizes`).
pub const ROUTE_SIZE: usize = size_of::<Ipv4Key>() + size_of::<Entry>();

/// The desired and the installed routes in one map, so that the routes
/// the kernel already has the way the RIB wants them are stored once.
/// [`Routes::plan`] gives the same operations as [`plan`] on the two
/// tables apart.
#[derive(Debug, Default)]
pub struct Routes {
    /// IPv4 routes, keyed in 5 octets rather than a `Prefix`'s 18: a full
    /// table is mostly B-tree nodes, eleven keys each.
    v4: BTreeMap<Ipv4Key, Entry>,
    v6: BTreeMap<Prefix, Entry>,
    gateways: Gateways,
}

impl Routes {
    /// No routes.
    #[must_use]
    pub fn new() -> Routes {
        Routes::default()
    }

    /// The gateway the RIB wants for `prefix`.
    #[must_use]
    pub fn desired(&self, prefix: &Prefix) -> Option<IpAddr> {
        let id = self.get(*prefix)?.desired?;
        Some(self.gateways.addr(id))
    }

    /// The gateway the kernel has for `prefix`, as far as we know.
    #[must_use]
    pub fn installed(&self, prefix: &Prefix) -> Option<IpAddr> {
        let id = self.get(*prefix)?.installed?;
        Some(self.gateways.addr(id))
    }

    /// Set what the RIB wants for `prefix` (`None`: no route) and return
    /// what it wanted before.
    pub fn set_desired(&mut self, prefix: Prefix, gateway: Option<IpAddr>) -> Option<IpAddr> {
        let new = gateway.map(|g| self.gateways.hold(g));
        let old = self.change(prefix, |e| std::mem::replace(&mut e.desired, new));
        old.map(|id| {
            let addr = self.gateways.addr(id);
            self.gateways.release(id);
            addr
        })
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
        let prefixes: Vec<Prefix> = self
            .iter()
            .filter(|(_, e)| e.installed.is_some())
            .map(|(p, _)| p)
            .collect();
        for prefix in prefixes {
            self.install(prefix, None);
        }
        for (prefix, gateway) in kernel {
            self.install(*prefix, Some(*gateway));
        }
    }

    /// Want no route at all (shutdown).
    pub fn clear_desired(&mut self) {
        let prefixes: Vec<Prefix> = self
            .iter()
            .filter(|(_, e)| e.desired.is_some())
            .map(|(p, _)| p)
            .collect();
        for prefix in prefixes {
            self.set_desired(prefix, None);
        }
    }

    /// The operations, in the order [`plan`] gives them, that make the
    /// installed routes the desired ones.
    #[must_use]
    pub fn plan(&self) -> Vec<Op> {
        let mut ops = Vec::new();
        for (prefix, e) in self.iter() {
            if let Some(d) = e.desired
                && e.installed != Some(d)
            {
                ops.push(Op::Set {
                    prefix,
                    gateway: self.gateways.addr(d),
                });
            }
        }
        for (prefix, e) in self.iter() {
            if let (None, Some(i)) = (e.desired, e.installed) {
                ops.push(Op::Delete {
                    prefix,
                    gateway: self.gateways.addr(i),
                });
            }
        }
        ops
    }

    /// The desired routes as a table (for reports).
    #[must_use]
    pub fn desired_table(&self) -> Table {
        self.table(|e| e.desired)
    }

    /// The installed routes as a table (for reports).
    #[must_use]
    pub fn installed_table(&self) -> Table {
        self.table(|e| e.installed)
    }

    /// Distinct gateways in use.
    #[must_use]
    pub fn gateways(&self) -> usize {
        self.gateways.len()
    }

    fn table(&self, which: impl Fn(&Entry) -> Option<GwId>) -> Table {
        self.iter()
            .filter_map(|(p, e)| which(e).map(|id| (p, self.gateways.addr(id))))
            .collect()
    }

    fn install(&mut self, prefix: Prefix, gateway: Option<IpAddr>) {
        let new = gateway.map(|g| self.gateways.hold(g));
        let old = self.change(prefix, |e| std::mem::replace(&mut e.installed, new));
        if let Some(id) = old {
            self.gateways.release(id);
        }
    }

    fn get(&self, prefix: Prefix) -> Option<&Entry> {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.get(&k),
            None => self.v6.get(&prefix),
        }
    }

    /// Every entry in prefix order (IPv4 sorts first).
    fn iter(&self) -> impl Iterator<Item = (Prefix, &Entry)> {
        self.v4
            .iter()
            .map(|(k, e)| (k.prefix(), e))
            .chain(self.v6.iter().map(|(p, e)| (*p, e)))
    }

    /// Change `prefix`'s entry, dropping it when it holds nothing after;
    /// one lookup either way.
    fn change<T>(&mut self, prefix: Prefix, f: impl FnOnce(&mut Entry) -> T) -> T {
        match Ipv4Key::new(prefix) {
            Some(k) => change_in(&mut self.v4, k, f),
            None => change_in(&mut self.v6, prefix, f),
        }
    }
}

fn change_in<K: Ord, T>(
    map: &mut BTreeMap<K, Entry>,
    key: K,
    f: impl FnOnce(&mut Entry) -> T,
) -> T {
    {
        match map.entry(key) {
            Slot::Occupied(mut o) => {
                let out = f(o.get_mut());
                if *o.get() == Entry::default() {
                    o.remove();
                }
                out
            }
            Slot::Vacant(v) => {
                let mut e = Entry::default();
                let out = f(&mut e);
                if e != Entry::default() {
                    v.insert(e);
                }
                out
            }
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
        assert_eq!(size_of::<Entry>(), 8);
        assert_eq!(ROUTE_SIZE, 13);
        let mut r = Routes::new();
        assert_eq!(r.set_desired(p("10.0.0.0/8"), Some(ip("1.1.1.1"))), None);
        assert_eq!(r.set_desired(p("10.1.0.0/16"), Some(ip("1.1.1.1"))), None);
        assert_eq!(r.gateways(), 1);
        assert_eq!(r.desired(&p("10.1.0.0/16")), Some(ip("1.1.1.1")));
        assert_eq!(r.installed(&p("10.1.0.0/16")), None);
        for op in r.plan() {
            r.apply(&op);
        }
        assert_eq!(r.installed_table(), r.desired_table());
        assert_eq!(r.plan(), vec![]);
        // A new gateway for one prefix; the old one is still used.
        assert_eq!(
            r.set_desired(p("10.1.0.0/16"), Some(ip("2.2.2.2"))),
            Some(ip("1.1.1.1"))
        );
        assert_eq!(r.gateways(), 2);
        assert_eq!(
            r.plan(),
            vec![Op::Set {
                prefix: p("10.1.0.0/16"),
                gateway: ip("2.2.2.2")
            }]
        );
        // Wanting nothing: deletes with the installed gateways, then the
        // map and the gateways empty out.
        r.clear_desired();
        let ops = r.plan();
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|o| matches!(o, Op::Delete { .. })));
        for op in &ops {
            r.apply(op);
        }
        assert_eq!(r.gateways(), 0);
        assert!(r.v4.is_empty() && r.v6.is_empty());
        // A freed gateway slot is reused.
        r.set_desired(p("10.0.0.0/8"), Some(ip("3.3.3.3")));
        assert_eq!(r.gateways.addrs.len(), 2);
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
