//! How the RIB holds routes. A full table has a million destinations or
//! more, so what one costs is what the RIB costs: a destination is 24
//! octets in its table, with its first route inline and no allocation of
//! its own until a second peer sends a route to it.

use std::collections::{BTreeMap, btree_map};
use std::mem;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;

use bgpfc_wire::prefix::{Ipv4Key, Prefix};
use bgpfc_wire::types::AddressFamily;

use crate::attrs::PathAttrs;

/// A peer's slot in the RIB's peer table. A route names its peer by slot;
/// a slot is reused only after every route naming it has been removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerId(pub(crate) u32);

impl PeerId {
    pub(crate) fn index(self) -> usize {
        // invariant: slots are created by pushing onto a Vec, so the index
        // fits in usize.
        usize::try_from(self.0).unwrap()
    }
}

/// One route in an Adj-RIB-In.
#[derive(Clone, Debug)]
pub(crate) struct Route {
    /// Its attributes, shared with every route that has the same ones.
    pub(crate) attrs: Arc<PathAttrs>,
    /// The peer it came from.
    pub(crate) peer: PeerId,
}

impl Route {
    /// Whether `other` is the same route: same peer, same attribute set.
    pub(crate) fn same(&self, other: &Route) -> bool {
        self.peer == other.peer && Arc::ptr_eq(&self.attrs, &other.attrs)
    }
}

/// Every route to one destination, the best first (Phase 2 moves it
/// there). One route is held inline; more go in a `Vec` sized exactly.
#[derive(Debug)]
pub(crate) enum Destination {
    /// One route, the common case.
    One(Route),
    /// Two or more, or none while the destination is being removed.
    Many(Vec<Route>),
}

impl Destination {
    pub(crate) fn routes(&self) -> &[Route] {
        match self {
            Destination::One(r) => std::slice::from_ref(r),
            Destination::Many(v) => v,
        }
    }

    pub(crate) fn routes_mut(&mut self) -> &mut [Route] {
        match self {
            Destination::One(r) => std::slice::from_mut(r),
            Destination::Many(v) => v,
        }
    }

    /// The best route, if any.
    pub(crate) fn best(&self) -> Option<&Route> {
        self.routes().first()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.routes().is_empty()
    }

    /// The index of `peer`'s route.
    pub(crate) fn position(&self, peer: PeerId) -> Option<usize> {
        self.routes().iter().position(|r| r.peer == peer)
    }

    /// Add a route from a peer that has none here yet, at the end.
    pub(crate) fn push(&mut self, route: Route) {
        match self {
            Destination::Many(v) if v.is_empty() => *self = Destination::One(route),
            Destination::Many(v) => {
                // Grow by one: a destination keeps one route per peer, and
                // a Vec's doubling would leave room nothing fills.
                v.reserve_exact(1);
                v.push(route);
            }
            Destination::One(_) => {
                let Destination::One(first) = mem::replace(self, Destination::Many(Vec::new()))
                else {
                    unreachable!()
                };
                *self = Destination::Many(vec![first, route]);
            }
        }
    }

    /// Remove the route at `i`; the order of the others is not kept.
    pub(crate) fn remove(&mut self, i: usize) -> Route {
        match self {
            Destination::One(_) => {
                let Destination::One(r) = mem::replace(self, Destination::Many(Vec::new())) else {
                    unreachable!()
                };
                r
            }
            Destination::Many(v) => {
                let r = v.swap_remove(i);
                if v.len() == 1 {
                    // invariant: len is 1.
                    *self = Destination::One(v.pop().unwrap());
                } else if v.capacity() >= 2 * v.len() {
                    v.shrink_to_fit();
                }
                r
            }
        }
    }

    /// Put the route at `i` first, as the best.
    pub(crate) fn promote(&mut self, i: usize) {
        self.routes_mut().swap(0, i);
    }

    /// Heap octets owned beyond the destination itself.
    #[cfg(feature = "profiling")]
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Destination::One(_) => 0,
            Destination::Many(v) => v.capacity() * size_of::<Route>(),
        }
    }
}

impl Default for Destination {
    fn default() -> Self {
        Destination::Many(Vec::new())
    }
}

/// One family's values by prefix, in prefix order. IPv4 prefixes are
/// keyed by a 5-octet [`Ipv4Key`] rather than an 18-octet [`Prefix`]: a
/// full table is mostly B-tree nodes, eleven keys each. A family has one
/// kind of prefix, so one of the two maps stays empty, which costs
/// nothing.
#[derive(Debug)]
pub(crate) struct PrefixMap<V> {
    pub(crate) v4: BTreeMap<Ipv4Key, V>,
    pub(crate) v6: BTreeMap<Prefix, V>,
}

/// One family's destinations.
pub(crate) type Table = PrefixMap<Destination>;

/// What [`PrefixMap::update`] did.
pub(crate) enum Updated<V> {
    /// The prefix mapped to the same value already; nothing changed.
    Same,
    /// The new value is in; this is what it replaced, if anything.
    Changed(Option<V>),
}

/// One family's Adj-RIB-Out for one peer: what it was last sent. A
/// B-tree rather than a hash table: 13 octets an IPv4 entry plus node
/// slack, against 32 and a bucket array that doubles (and is held twice
/// while it does) for a full table.
pub(crate) type AdjOut = PrefixMap<Arc<PathAttrs>>;

impl<V> Default for PrefixMap<V> {
    fn default() -> Self {
        PrefixMap {
            v4: BTreeMap::new(),
            v6: BTreeMap::new(),
        }
    }
}

impl<V> PrefixMap<V> {
    pub(crate) fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub(crate) fn get(&self, prefix: Prefix) -> Option<&V> {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.get(&k),
            None => self.v6.get(&prefix),
        }
    }

    pub(crate) fn insert(&mut self, prefix: Prefix, value: V) -> Option<V> {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.insert(k, value),
            None => self.v6.insert(prefix, value),
        }
    }

    /// Map `prefix` to `value` unless `same` says it already maps to the
    /// same thing. One descent of the tree, where a lookup and an insert
    /// make two.
    pub(crate) fn update(
        &mut self,
        prefix: Prefix,
        value: V,
        same: impl FnOnce(&V, &V) -> bool,
    ) -> Updated<V> {
        fn update_in<K: Ord, V>(
            map: &mut BTreeMap<K, V>,
            key: K,
            value: V,
            same: impl FnOnce(&V, &V) -> bool,
        ) -> Updated<V> {
            match map.entry(key) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(value);
                    Updated::Changed(None)
                }
                btree_map::Entry::Occupied(mut e) => {
                    if same(e.get(), &value) {
                        Updated::Same
                    } else {
                        Updated::Changed(Some(e.insert(value)))
                    }
                }
            }
        }
        match Ipv4Key::new(prefix) {
            Some(k) => update_in(&mut self.v4, k, value, same),
            None => update_in(&mut self.v6, prefix, value, same),
        }
    }

    pub(crate) fn remove(&mut self, prefix: Prefix) -> Option<V> {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.remove(&k),
            None => self.v6.remove(&prefix),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.v4.clear();
        self.v6.clear();
    }

    /// Every entry, in prefix order (IPv4 sorts first).
    pub(crate) fn iter(&self) -> impl Iterator<Item = (Prefix, &V)> {
        self.after(None)
    }

    /// The entries after `from` (all of them for `None`), in prefix order.
    pub(crate) fn after(&self, from: Option<Prefix>) -> impl Iterator<Item = (Prefix, &V)> {
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
            .map(|(k, v)| (k.prefix(), v))
            .chain(v6.map(|(p, v)| (*p, v)))
    }

    #[cfg(feature = "profiling")]
    pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
        self.v4.values().chain(self.v6.values())
    }

    /// Heap octets, estimated: B-tree leaves of eleven keys and values
    /// behind a 12-octet header, two thirds full (inserting in random
    /// order averages about that); inner nodes add a few percent.
    #[cfg(feature = "profiling")]
    pub(crate) fn approx_bytes(&self) -> usize {
        fn leaves<K, V>(n: usize) -> usize {
            n * (12 + 11 * (size_of::<K>() + size_of::<V>())) * 3 / 22
        }
        leaves::<Ipv4Key, V>(self.v4.len()) + leaves::<Prefix, V>(self.v6.len())
    }

    pub(crate) fn into_values(self) -> impl Iterator<Item = V> {
        self.v4.into_values().chain(self.v6.into_values())
    }

    /// Keep the entries `keep` says to, in prefix order.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(Prefix, &mut V) -> bool) {
        self.v4.retain(|k, v| keep(k.prefix(), v));
        self.v6.retain(|p, v| keep(*p, v));
    }
}

/// Values per address family. A session has one or two families, so a
/// short list searched in order costs less on every route than hashing.
#[derive(Debug)]
pub(crate) struct FamilyMap<T>(Vec<(AddressFamily, T)>);

impl<T> Default for FamilyMap<T> {
    fn default() -> Self {
        FamilyMap(Vec::new())
    }
}

impl<T> FamilyMap<T> {
    pub(crate) fn get(&self, family: AddressFamily) -> Option<&T> {
        self.0.iter().find(|(f, _)| *f == family).map(|(_, v)| v)
    }

    pub(crate) fn get_mut(&mut self, family: AddressFamily) -> Option<&mut T> {
        self.0
            .iter_mut()
            .find(|(f, _)| *f == family)
            .map(|(_, v)| v)
    }

    pub(crate) fn insert(&mut self, family: AddressFamily, value: T) {
        match self.get_mut(family) {
            Some(v) => *v = value,
            None => self.0.push((family, value)),
        }
    }

    pub(crate) fn remove(&mut self, family: AddressFamily) -> Option<T> {
        let i = self.0.iter().position(|(f, _)| *f == family)?;
        Some(self.0.swap_remove(i).1)
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (AddressFamily, &T)> {
        self.0.iter().map(|(f, v)| (*f, v))
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (AddressFamily, &mut T)> {
        self.0.iter_mut().map(|(f, v)| (*f, v))
    }

    #[cfg(any(test, feature = "profiling"))]
    pub(crate) fn values(&self) -> impl Iterator<Item = &T> {
        self.0.iter().map(|(_, v)| v)
    }
}

impl<T> FamilyMap<T> {
    pub(crate) fn into_values(self) -> impl Iterator<Item = T> {
        self.0.into_iter().map(|(_, v)| v)
    }
}

impl<T: Default> FamilyMap<T> {
    pub(crate) fn or_default(&mut self, family: AddressFamily) -> &mut T {
        let i = if let Some(i) = self.0.iter().position(|(f, _)| *f == family) {
            i
        } else {
            self.0.push((family, T::default()));
            self.0.len() - 1
        };
        &mut self.0[i].1
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bgpfc_wire::as_path::AsPath;
    use bgpfc_wire::attribute::Origin;
    use bgpfc_wire::mp::NextHop;

    use super::*;

    fn route(peer: u32) -> Route {
        Route {
            attrs: Arc::new(PathAttrs {
                origin: Origin::Igp,
                as_path: AsPath::empty(),
                next_hop: NextHop::Ipv4(Ipv4Addr::LOCALHOST),
                med: None,
                local_pref: None,
                atomic_aggregate: false,
                aggregator: None,
                communities: Box::default(),
                ext_communities: Box::default(),
                large_communities: Box::default(),
                unknown: Box::default(),
            }),
            peer: PeerId(peer),
        }
    }

    fn peers(d: &Destination) -> Vec<u32> {
        d.routes().iter().map(|r| r.peer.0).collect()
    }

    #[test]
    fn layout_stays_small() {
        // A full table holds one of these per destination and per route.
        assert_eq!(size_of::<Route>(), 16);
        assert_eq!(size_of::<Destination>(), 24);
    }

    #[test]
    fn one_route_inline_more_in_an_exact_vec() {
        let mut d = Destination::default();
        assert!(d.is_empty());
        assert!(d.best().is_none());
        d.push(route(1));
        assert!(matches!(d, Destination::One(_)));
        d.push(route(2));
        d.push(route(3));
        assert_eq!(peers(&d), vec![1, 2, 3]);
        match &d {
            Destination::Many(v) => assert_eq!(v.capacity(), 3),
            Destination::One(_) => panic!("three routes inline"),
        }
        assert_eq!(d.position(PeerId(3)), Some(2));
        assert_eq!(d.position(PeerId(9)), None);
        d.promote(2);
        assert_eq!(d.best().unwrap().peer, PeerId(3));
        assert_eq!(d.remove(0).peer, PeerId(3));
        assert_eq!(d.routes().len(), 2);
        d.remove(0);
        assert!(matches!(d, Destination::One(_)), "back inline");
        d.remove(0);
        assert!(d.is_empty());
        d.push(route(4));
        assert!(matches!(d, Destination::One(_)));
    }

    #[test]
    fn same_route_means_same_peer_and_attribute_set() {
        let a = route(1);
        let b = Route {
            attrs: Arc::clone(&a.attrs),
            peer: PeerId(2),
        };
        assert!(a.same(&a.clone()));
        assert!(!a.same(&b));
        // Equal attributes in another allocation are a different set.
        assert!(!a.same(&route(1)));
    }

    #[test]
    fn prefix_map_holds_both_kinds_in_prefix_order() {
        let p = |s: &str| s.parse::<Prefix>().unwrap();
        let mut m: PrefixMap<u32> = PrefixMap::default();
        assert!(m.is_empty());
        assert!(matches!(
            m.update(p("2001:db8::/32"), 1, |a, b| a == b),
            Updated::Changed(None)
        ));
        assert!(matches!(
            m.update(p("192.0.2.0/24"), 2, |a, b| a == b),
            Updated::Changed(None)
        ));
        assert!(matches!(
            m.update(p("10.0.0.0/8"), 3, |a, b| a == b),
            Updated::Changed(None)
        ));
        assert!(matches!(
            m.update(p("10.0.0.0/8"), 3, |a, b| a == b),
            Updated::Same
        ));
        assert!(matches!(
            m.update(p("10.0.0.0/8"), 4, |a, b| a == b),
            Updated::Changed(Some(3))
        ));
        assert_eq!(m.insert(p("10.0.0.0/16"), 5), None);
        assert_eq!(m.len(), 4);
        assert_eq!(m.get(p("192.0.2.0/24")), Some(&2));
        assert_eq!(m.get(p("192.0.2.0/25")), None);
        let order: Vec<String> = m.iter().map(|(p, _)| p.to_string()).collect();
        assert_eq!(
            order,
            ["10.0.0.0/8", "10.0.0.0/16", "192.0.2.0/24", "2001:db8::/32"]
        );
        let after = |from: &str| -> Vec<String> {
            m.after(Some(p(from))).map(|(p, _)| p.to_string()).collect()
        };
        assert_eq!(
            after("10.0.0.0/8"),
            ["10.0.0.0/16", "192.0.2.0/24", "2001:db8::/32"]
        );
        assert_eq!(after("192.0.2.0/24"), ["2001:db8::/32"]);
        assert_eq!(after("::/0"), ["2001:db8::/32"]);
        assert_eq!(after("2001:db8::/32"), Vec::<String>::new());
        assert_eq!(m.remove(p("2001:db8::/32")), Some(1));
        m.retain(|p, v| {
            *v += 1;
            p.prefix_len() <= 16
        });
        assert_eq!(m.into_values().collect::<Vec<_>>(), vec![5, 6]);
    }

    #[test]
    fn family_map() {
        let v4 = AddressFamily::IPV4_UNICAST;
        let v6 = AddressFamily::IPV6_UNICAST;
        let mut m: FamilyMap<usize> = FamilyMap::default();
        assert!(m.get(v4).is_none());
        *m.or_default(v6) += 2;
        *m.or_default(v6) += 1;
        m.insert(v4, 7);
        assert_eq!(m.get(v6), Some(&3));
        assert_eq!(m.get(v4), Some(&7));
        m.insert(v4, 8);
        assert_eq!(m.values().sum::<usize>(), 11);
        for (_, v) in m.iter_mut() {
            *v += 1;
        }
        assert_eq!(m.iter().collect::<Vec<_>>(), vec![(v6, &4), (v4, &9)]);
        assert_eq!(m.remove(v6), Some(4));
        assert_eq!(m.remove(v6), None);
        assert_eq!(m.get_mut(v4).copied(), Some(9));
    }
}
