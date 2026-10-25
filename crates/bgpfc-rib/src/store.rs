//! How the RIB holds routes. A full table has a million destinations or
//! more, so what one costs is what the RIB costs: a destination is 24
//! octets in its table, with its first route inline and no allocation of
//! its own until a second peer sends a route to it.

use std::collections::BTreeMap;
use std::mem;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;

use bgpfc_rpki::{AspaState, RovState};
use bgpfc_wire::prefix::{Ipv4Key, Prefix};
use bgpfc_wire::types::AddressFamily;

use crate::attrs::PathAttrs;

/// A peer's slot in the RIB's peer table. A route names its peer by slot;
/// a slot is reused only after every route naming it has been removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PeerId(pub(crate) u32);

impl PeerId {
    pub(crate) fn index(self) -> usize {
        // invariant: slots are created by pushing onto a Vec, so the index
        // fits in usize.
        usize::try_from(self.0).unwrap()
    }
}

/// One route in an Adj-RIB-In: as its peer sent it, and as import policy
/// made it (RFC 4271 §3.2, §9.1.1), with its RFC 6811 validation state.
#[derive(Clone, Debug)]
pub(crate) struct Route {
    /// Its attributes as import policy gave them, shared with every route
    /// that has the same ones; as received for a held route.
    pub(crate) attrs: Arc<PathAttrs>,
    /// Its attributes as its peer sent them, when import policy changed
    /// them: import policy runs on these again when the route's
    /// validation state changes. `None` when they are `attrs`.
    pub(crate) received: Option<Arc<PathAttrs>>,
    /// The peer it came from.
    pub(crate) peer: PeerId,
    /// Its RFC 6811 §2 validation state, judged on the route as received.
    /// Phase 2 does not use it; policy does.
    pub(crate) rov: RovState,
    /// Its ASPA verdict (a placeholder until ASPA lands).
    pub(crate) aspa: AspaState,
    /// Import policy rejected the route for its validation state alone:
    /// the Adj-RIB-In holds it (RFC 6811 §2), but it is no candidate. A
    /// destination keeps these after its candidates.
    pub(crate) held: bool,
}

impl Route {
    /// Whether `other` is the same route: same peer, same attribute set.
    pub(crate) fn same(&self, other: &Route) -> bool {
        self.peer == other.peer && Arc::ptr_eq(&self.attrs, &other.attrs)
    }

    /// Whether `other` has the same validation verdicts, which export
    /// policy may look at.
    pub(crate) fn same_state(&self, other: &Route) -> bool {
        self.rov == other.rov && self.aspa == other.aspa
    }

    /// The attributes as the peer sent them.
    pub(crate) fn received(&self) -> &Arc<PathAttrs> {
        self.received.as_ref().unwrap_or(&self.attrs)
    }
}

/// A route and the Path Identifier its peer sent it with (RFC 7911 §3).
/// Only a destination with a route from a peer that sends identifiers
/// holds these; every other route is held as a plain [`Route`], which has
/// no room for one.
#[derive(Clone, Debug)]
pub(crate) struct PathRoute {
    pub(crate) route: Route,
    /// The identifier, zero for a route whose peer sent none.
    pub(crate) id: u32,
}

/// What a destination holds a route as: a [`Route`], where the identifier
/// is zero, or a [`PathRoute`].
pub(crate) trait Member {
    fn route(&self) -> &Route;
    fn route_mut(&mut self) -> &mut Route;
    /// The Path Identifier, zero for a route sent without one.
    fn id(&self) -> u32;
}

impl Member for Route {
    fn route(&self) -> &Route {
        self
    }
    fn route_mut(&mut self) -> &mut Route {
        self
    }
    fn id(&self) -> u32 {
        0
    }
}

impl Member for PathRoute {
    fn route(&self) -> &Route {
        &self.route
    }
    fn route_mut(&mut self) -> &mut Route {
        &mut self.route
    }
    fn id(&self) -> u32 {
        self.id
    }
}

/// Run `$body` with `$s` bound to the slots of `$dest`, whichever variant.
macro_rules! slots {
    ($dest:expr, $s:ident => $body:expr) => {
        match $dest {
            Destination::One(r) => {
                let $s = std::slice::from_ref(r);
                $body
            }
            Destination::Many(v) => {
                let $s = &v[..];
                $body
            }
            Destination::Paths(v) => {
                let $s = &v[..];
                $body
            }
        }
    };
}

/// As [`slots!`], mutably.
macro_rules! slots_mut {
    ($dest:expr, $s:ident => $body:expr) => {
        match $dest {
            Destination::One(r) => {
                let $s = std::slice::from_mut(r);
                $body
            }
            Destination::Many(v) => {
                let $s = &mut v[..];
                $body
            }
            Destination::Paths(v) => {
                let $s = &mut v[..];
                $body
            }
        }
    };
}

/// Every route to one destination: the candidates first, the best of them
/// first of all (Phase 2 moves it there), then the routes held for their
/// validation state alone. One route is held inline; more go in a boxed
/// slice sized exactly, which keeps a destination at 24 octets beside a
/// 24-octet route.
///
/// A route is told apart by its peer and its Path Identifier (RFC 7911
/// §2: "the combination of the address prefix and the Path Identifier").
/// A peer without ADD-PATH has one route per destination, with identifier
/// zero, and its destinations are `One` or `Many` as before. Only when a
/// peer sends a route with an identifier other than zero does the
/// destination become `Paths`, which holds each route beside its
/// identifier; it goes back to the plain form once every identifier is
/// zero again.
#[derive(Debug)]
pub(crate) enum Destination {
    /// One route, the common case.
    One(Route),
    /// Two or more, or none while the destination is being removed.
    Many(Box<[Route]>),
    /// Routes with Path Identifiers, at least one of them not zero.
    Paths(Box<[PathRoute]>),
}

impl Destination {
    /// A destination of one route, which `id` is the Path Identifier of.
    pub(crate) fn single(route: Route, id: u32) -> Destination {
        if id == 0 {
            Destination::One(route)
        } else {
            Destination::Paths(Box::new([PathRoute { route, id }]))
        }
    }

    /// How many routes the destination holds.
    pub(crate) fn len(&self) -> usize {
        match self {
            Destination::One(_) => 1,
            Destination::Many(v) => v.len(),
            Destination::Paths(v) => v.len(),
        }
    }

    /// The `i`th route; the candidates come first.
    pub(crate) fn route(&self, i: usize) -> &Route {
        slots!(self, s => s[i].route())
    }

    /// The `i`th route, mutably.
    pub(crate) fn route_mut(&mut self, i: usize) -> &mut Route {
        slots_mut!(self, s => s[i].route_mut())
    }

    /// The Path Identifier of the `i`th route; zero if its peer sent none.
    pub(crate) fn id(&self, i: usize) -> u32 {
        slots!(self, s => s[i].id())
    }

    /// Every route with its Path Identifier, candidates first.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Route, u32)> {
        let (one, many, paths): (Option<&Route>, &[Route], &[PathRoute]) = match self {
            Destination::One(r) => (Some(r), &[], &[]),
            Destination::Many(v) => (None, v, &[]),
            Destination::Paths(v) => (None, &[], v),
        };
        one.into_iter()
            .map(|r| (r, 0))
            .chain(many.iter().map(|r| (r, 0)))
            .chain(paths.iter().map(|p| (&p.route, p.id)))
    }

    /// The best route, if any: the first, unless that is held, which only
    /// happens when every route is.
    pub(crate) fn best(&self) -> Option<&Route> {
        // One match, as `routes().first()` was before identifiers: this is
        // called for every route that comes and goes.
        let first = match self {
            Destination::One(r) => Some(r),
            Destination::Many(v) => v.first(),
            Destination::Paths(v) => v.first().map(|p| &p.route),
        };
        first.filter(|r| !r.held)
    }

    /// How many of the routes are candidates; they come first.
    pub(crate) fn candidates(&self) -> usize {
        slots!(self, s => s.partition_point(|r| !r.route().held))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The index of the route `peer` sent with Path Identifier `id` (zero
    /// for a peer that sends none).
    pub(crate) fn position(&self, peer: PeerId, id: u32) -> Option<usize> {
        slots!(self, s => s.iter().position(|r| r.route().peer == peer && r.id() == id))
    }

    /// The index of a route `peer` sent, whichever its identifier.
    pub(crate) fn position_of_peer(&self, peer: PeerId) -> Option<usize> {
        slots!(self, s => s.iter().position(|r| r.route().peer == peer))
    }

    /// The routes as slots with identifiers, whatever form they are in.
    fn into_paths(self) -> Vec<PathRoute> {
        match self {
            Destination::One(route) => vec![PathRoute { route, id: 0 }],
            Destination::Many(v) => v
                .into_vec()
                .into_iter()
                .map(|route| PathRoute { route, id: 0 })
                .collect(),
            Destination::Paths(v) => v.into_vec(),
        }
    }

    /// A destination of `v`, in the plain form when no route has an
    /// identifier.
    fn of_paths(v: Vec<PathRoute>) -> Destination {
        if v.iter().any(|p| p.id != 0) {
            return Destination::Paths(v.into_boxed_slice());
        }
        let mut routes: Vec<Route> = v.into_iter().map(|p| p.route).collect();
        match routes.len() {
            1 => Destination::One(routes.remove(0)),
            _ => Destination::Many(routes.into_boxed_slice()),
        }
    }

    /// Add a route from a peer that has none here yet with this
    /// identifier: a candidate after the other candidates, a held route at
    /// the end.
    pub(crate) fn push(&mut self, route: Route, id: u32) {
        let at = if route.held {
            self.len()
        } else {
            self.candidates()
        };
        match mem::take(self) {
            Destination::Many(v) if v.is_empty() => {
                *self = if id == 0 {
                    Destination::One(route)
                } else {
                    Destination::Paths(Box::new([PathRoute { route, id }]))
                };
            }
            Destination::Many(v) if id == 0 => {
                // Grow by one: a destination keeps one route per peer, and
                // a Vec's doubling would leave room nothing fills.
                let mut v = v.into_vec();
                v.reserve_exact(1);
                v.insert(at, route);
                *self = Destination::Many(v.into_boxed_slice());
            }
            Destination::One(first) if id == 0 => {
                *self = Destination::Many(if at == 0 {
                    Box::new([route, first])
                } else {
                    Box::new([first, route])
                });
            }
            // A Path Identifier other than zero, or a destination that
            // has some already.
            other => {
                let mut v = other.into_paths();
                v.reserve_exact(1);
                v.insert(at, PathRoute { route, id });
                *self = Destination::Paths(v.into_boxed_slice());
            }
        }
    }

    /// Remove the route at `i`, keeping the order of the others.
    pub(crate) fn remove(&mut self, i: usize) -> Route {
        match mem::take(self) {
            Destination::One(r) => r,
            Destination::Many(v) => {
                let mut v = v.into_vec();
                let r = v.remove(i);
                *self = if v.len() == 1 {
                    // invariant: len is 1.
                    Destination::One(v.pop().unwrap())
                } else {
                    Destination::Many(v.into_boxed_slice())
                };
                r
            }
            Destination::Paths(v) => {
                let mut v = v.into_vec();
                let p = v.remove(i);
                *self = Destination::of_paths(v);
                p.route
            }
        }
    }

    /// Replace the route at `i` with `route` of the same peer and
    /// identifier, moving it between the candidates and the held routes
    /// when it changes kind. The route it replaces.
    pub(crate) fn replace(&mut self, i: usize, route: Route) -> Route {
        if self.route(i).held == route.held {
            return mem::replace(self.route_mut(i), route);
        }
        let id = self.id(i);
        let old = self.remove(i);
        self.push(route, id);
        old
    }

    /// Put the candidate at `i` first, as the best.
    pub(crate) fn promote(&mut self, i: usize) {
        slots_mut!(self, s => s.swap(0, i));
    }

    /// Put the candidates before the held routes, keeping the order within
    /// each.
    pub(crate) fn sort_candidates_first(&mut self) {
        slots_mut!(self, s => s.sort_by_key(|r| r.route().held));
    }

    /// Heap octets owned beyond the destination itself.
    #[cfg(feature = "profiling")]
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Destination::One(_) => 0,
            Destination::Many(v) => v.len() * size_of::<Route>(),
            Destination::Paths(v) => v.len() * size_of::<PathRoute>(),
        }
    }
}

impl Default for Destination {
    fn default() -> Self {
        Destination::Many(Box::default())
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

impl<V> Default for PrefixMap<V> {
    fn default() -> Self {
        PrefixMap {
            v4: BTreeMap::new(),
            v6: BTreeMap::new(),
        }
    }
}

impl<V> PrefixMap<V> {
    #[cfg(any(test, feature = "profiling"))]
    pub(crate) fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub(crate) fn get(&self, prefix: Prefix) -> Option<&V> {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.get(&k),
            None => self.v6.get(&prefix),
        }
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

    #[cfg(test)]
    pub(crate) fn into_values(self) -> impl Iterator<Item = V> {
        self.v4.into_values().chain(self.v6.into_values())
    }

    /// Every entry, taken out, in prefix order.
    pub(crate) fn into_entries(self) -> impl Iterator<Item = (Prefix, V)> {
        self.v4
            .into_iter()
            .map(|(k, v)| (k.prefix(), v))
            .chain(self.v6)
    }

    pub(crate) fn insert(&mut self, prefix: Prefix, value: V) -> Option<V> {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.insert(k, value),
            None => self.v6.insert(prefix, value),
        }
    }

    pub(crate) fn remove(&mut self, prefix: Prefix) -> Option<V> {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.remove(&k),
            None => self.v6.remove(&prefix),
        }
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

    #[cfg(test)]
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
            received: None,
            peer: PeerId(peer),
            rov: RovState::Disabled,
            aspa: AspaState::Disabled,
            held: false,
        }
    }

    fn held(peer: u32) -> Route {
        Route {
            held: true,
            ..route(peer)
        }
    }

    fn peers(d: &Destination) -> Vec<u32> {
        d.iter().map(|(r, _)| r.peer.0).collect()
    }

    fn ids(d: &Destination) -> Vec<(u32, u32)> {
        d.iter().map(|(r, id)| (r.peer.0, id)).collect()
    }

    #[test]
    fn layout_stays_small() {
        // A full table holds one of these per destination and per route:
        // a route's validation state and the attributes it was received
        // with fit beside the inline one, as the slice of several routes
        // leaves room for the variant. Path Identifiers cost the routes of
        // peers that send none nothing.
        assert_eq!(size_of::<Route>(), 24);
        assert_eq!(size_of::<Destination>(), 24);
    }

    #[test]
    fn one_route_inline_more_in_an_exact_slice() {
        let mut d = Destination::default();
        assert!(d.is_empty());
        assert!(d.best().is_none());
        d.push(route(1), 0);
        assert!(matches!(d, Destination::One(_)));
        d.push(route(2), 0);
        d.push(route(3), 0);
        assert_eq!(peers(&d), vec![1, 2, 3]);
        match &d {
            Destination::Many(v) => assert_eq!(v.len(), 3),
            _ => panic!("three routes inline"),
        }
        assert_eq!(d.position(PeerId(3), 0), Some(2));
        assert_eq!(d.position(PeerId(9), 0), None);
        d.promote(2);
        assert_eq!(d.best().unwrap().peer, PeerId(3));
        assert_eq!(d.remove(0).peer, PeerId(3));
        assert_eq!(d.len(), 2);
        d.remove(0);
        assert!(matches!(d, Destination::One(_)), "back inline");
        d.remove(0);
        assert!(d.is_empty());
        d.push(route(4), 0);
        assert!(matches!(d, Destination::One(_)));
    }

    #[test]
    fn same_route_means_same_peer_and_attribute_set() {
        let a = route(1);
        let b = Route {
            attrs: Arc::clone(&a.attrs),
            peer: PeerId(2),
            ..a.clone()
        };
        assert!(a.same(&a.clone()));
        assert!(!a.same(&b));
        // Equal attributes in another allocation are a different set.
        assert!(!a.same(&route(1)));
        let valid = Route {
            rov: RovState::Valid,
            ..a.clone()
        };
        assert!(a.same(&valid) && !a.same_state(&valid));
        assert!(Arc::ptr_eq(a.received(), &a.attrs));
    }

    #[test]
    fn held_routes_follow_the_candidates() {
        let mut d = Destination::default();
        d.push(held(1), 0);
        // Only a held route: no best.
        assert!(d.best().is_none());
        assert_eq!(d.candidates(), 0);
        d.push(route(2), 0);
        d.push(held(3), 0);
        d.push(route(4), 0);
        assert_eq!(peers(&d), vec![2, 4, 1, 3]);
        assert_eq!(d.candidates(), 2);
        assert_eq!(d.best().unwrap().peer, PeerId(2));
        // A candidate that becomes held moves behind the candidates, and
        // back.
        let old = d.replace(0, held(2));
        assert!(!old.held);
        assert_eq!(peers(&d), vec![4, 1, 3, 2]);
        d.replace(3, route(2));
        assert_eq!(peers(&d), vec![4, 2, 1, 3]);
        assert_eq!(d.remove(1).peer, PeerId(2));
        assert_eq!(peers(&d), vec![4, 1, 3]);
    }

    #[test]
    fn a_path_identifier_other_than_zero_makes_a_destination_of_paths() {
        // RFC 7911 §2: a path is told apart by its prefix and identifier,
        // so a peer may have several routes here.
        let mut d = Destination::default();
        d.push(route(1), 0);
        assert!(matches!(d, Destination::One(_)));
        d.push(route(2), 0);
        assert!(matches!(d, Destination::Many(_)));
        // Peer 2 sends a second path, with identifier 7.
        assert_eq!(d.position(PeerId(2), 7), None);
        d.push(route(2), 7);
        assert!(matches!(d, Destination::Paths(_)));
        assert_eq!(ids(&d), vec![(1, 0), (2, 0), (2, 7)]);
        assert_eq!(d.position(PeerId(2), 0), Some(1));
        assert_eq!(d.position(PeerId(2), 7), Some(2));
        assert_eq!(d.position(PeerId(2), 8), None);
        assert_eq!(d.position_of_peer(PeerId(2)), Some(1));
        // Held routes go last, whatever their identifier.
        d.push(held(3), 4);
        d.push(route(3), 5);
        assert_eq!(ids(&d), vec![(1, 0), (2, 0), (2, 7), (3, 5), (3, 4)]);
        assert_eq!(d.candidates(), 4);
        // Promotion moves a route with its identifier.
        d.promote(2);
        assert_eq!(ids(&d), vec![(2, 7), (2, 0), (1, 0), (3, 5), (3, 4)]);
        assert_eq!(d.best().unwrap().peer, PeerId(2));
        assert_eq!(d.id(0), 7);
        // A replacement keeps the identifier, also across held and not.
        let old = d.replace(1, held(2));
        assert!(!old.held);
        assert_eq!(ids(&d), vec![(2, 7), (1, 0), (3, 5), (3, 4), (2, 0)]);
        d.replace(3, route(3));
        assert_eq!(ids(&d), vec![(2, 7), (1, 0), (3, 5), (3, 4), (2, 0)]);
        d.sort_candidates_first();
        assert_eq!(d.candidates(), 4);
        // Removing the routes with identifiers takes the destination back
        // to its plain form, with whatever is left.
        assert_eq!(d.remove(0).peer, PeerId(2));
        assert_eq!(d.remove(1).peer, PeerId(3));
        assert!(matches!(d, Destination::Paths(_)), "(3, 4) is still here");
        assert_eq!(d.remove(1).peer, PeerId(3));
        assert_eq!(ids(&d), vec![(1, 0), (2, 0)]);
        assert!(matches!(d, Destination::Many(_)));
        d.remove(0);
        assert!(matches!(d, Destination::One(_)));
    }

    #[test]
    fn a_first_route_with_an_identifier_is_a_destination_of_paths() {
        let mut d = Destination::default();
        d.push(route(1), 3);
        assert!(matches!(&d, Destination::Paths(v) if v.len() == 1));
        assert_eq!(d.position(PeerId(1), 3), Some(0));
        assert_eq!(d.position(PeerId(1), 0), None);
        assert_eq!(d.remove(0).peer, PeerId(1));
        assert!(d.is_empty());
        // Identifier zero from an ADD-PATH peer is a plain route.
        d.push(route(1), 0);
        assert!(matches!(d, Destination::One(_)));
        assert_eq!(d.position(PeerId(1), 0), Some(0));
    }

    #[test]
    fn prefix_map_holds_both_kinds_in_prefix_order() {
        let p = |s: &str| s.parse::<Prefix>().unwrap();
        let mut m: PrefixMap<u32> = PrefixMap::default();
        assert!(m.is_empty());
        assert_eq!(m.insert(p("2001:db8::/32"), 1), None);
        assert_eq!(m.insert(p("192.0.2.0/24"), 2), None);
        assert_eq!(m.insert(p("10.0.0.0/8"), 3), None);
        assert_eq!(m.insert(p("10.0.0.0/8"), 4), Some(3));
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
