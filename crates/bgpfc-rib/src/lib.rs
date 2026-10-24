//! Adj-RIB-In, Loc-RIB, Adj-RIB-Out and the decision process
//! (AGENTS.md §3, "RIB thread": the only owner of all RIB state, driven
//! by messages, no I/O).
//!
//! Implements: RFC 4271 §3.2 (the three RIBs), §9.1 (the decision
//! process: Phase 1 degree of preference, Phase 2 route selection,
//! Phase 3 route dissemination), §9.1.2 (AS loop exclusion), §9.1.4
//! (overlapping routes are independent destinations), §9.2 (update
//! generation), §9.3 (Loc-RIB changes are reported for the FIB), §6.3
//! and RFC 7606 §7.2 (leftmost AS of an external route is the peer's);
//! RFC 4760 §5, §7 (per-family RIBs, family disable); RFC 2918 §4
//! (route refresh re-sends the Adj-RIB-Out).
//!
//! With the `profiling` feature, the work per route is timed into
//! `bgpfc-prof` histograms and the `profiling` module reports the RIB's
//! size and how much its attributes repeat (`docs/PROFILING.md`).
#![forbid(unsafe_code)]

pub mod attrs;
pub mod decision;
pub mod export;
pub mod peer;
#[cfg(feature = "profiling")]
pub mod profiling;
mod store;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn};
use bgpfc_wire::update::{DecodedUpdate, PeerKind};

pub use attrs::{Interner, PathAttrs};
pub use decision::{Candidate, Neighbor};
pub use export::{Batch, Source};
pub use peer::PeerInfo;
use store::{Destination, FamilyMap, PeerId, Route};

/// What a policy decided about a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Keep the route with its attributes as they are.
    Accept,
    /// Keep the route with these attributes instead.
    Modified(PathAttrs),
    /// Drop the route.
    Reject,
}

/// Import and export policy as the RIB sees it (RFC 4271 §9.1.1 local
/// policy, §9.1.3 export policy). `peer` is the peer the route came from
/// on import and the peer it is going to on export.
pub trait Policies: Send {
    /// Decide whether and how a received route enters the Adj-RIB-In.
    fn import(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        attrs: &PathAttrs,
    ) -> Verdict;

    /// Decide whether and how a Loc-RIB route is advertised to `peer`,
    /// before the RFC 4271 §5.1 rewriting for the session.
    fn export(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        attrs: &PathAttrs,
    ) -> Verdict;
}

/// The policy that accepts every route unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcceptAll;

impl Policies for AcceptAll {
    fn import(&self, _: &PeerInfo, _: AddressFamily, _: Prefix, _: &PathAttrs) -> Verdict {
        Verdict::Accept
    }

    fn export(&self, _: &PeerInfo, _: AddressFamily, _: Prefix, _: &PathAttrs) -> Verdict {
        Verdict::Accept
    }
}

/// A Loc-RIB change the FIB must follow (RFC 4271 §9.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FibChange {
    /// The family.
    pub family: AddressFamily,
    /// The destination.
    pub prefix: Prefix,
    /// The new next hop, or `None` when the destination is gone.
    pub next_hop: Option<IpAddr>,
}

/// What the RIB asks its owner to do after an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Install, replace or delete a kernel route.
    Fib(FibChange),
    /// Write framed UPDATE messages to a peer, in order.
    Send {
        /// The peer.
        peer: IpAddr,
        /// Framed messages.
        messages: Vec<Vec<u8>>,
    },
    /// Something could not be encoded for a peer; the caller logs it.
    EncodeFailed {
        /// The peer.
        peer: IpAddr,
        /// Why.
        error: bgpfc_wire::error::EncodeError,
    },
}

/// Where the RIB puts what an input produces, in order. A `Vec` collects
/// it; the daemon hands each output on as it comes, so that a peer with a
/// full table going down does not first build a list of a million FIB
/// changes.
pub trait Sink {
    /// Take the next output.
    fn put(&mut self, output: Output);
}

impl Sink for Vec<Output> {
    fn put(&mut self, output: Output) {
        self.push(output);
    }
}

/// A route the RIB holds: the peer it came from and its attributes.
#[derive(Clone, Copy, Debug)]
pub struct RouteRef<'a> {
    /// The peer it came from.
    pub peer: IpAddr,
    /// Its attributes.
    pub attrs: &'a Arc<PathAttrs>,
}

struct PeerState {
    info: PeerInfo,
    /// What Phase 2 compares about the peer, for every route it sent.
    neighbor: Neighbor,
    /// Families disabled after a malformed multiprotocol attribute
    /// (RFC 4760 §7); no more routes are accepted for them.
    disabled: Vec<AddressFamily>,
    /// Adj-RIB-Out: what the peer was last told, per family.
    adj_out: FamilyMap<HashMap<Prefix, Arc<PathAttrs>>>,
    /// Routes held in the Adj-RIB-In per family (for statistics).
    adj_in_count: FamilyMap<usize>,
}

/// Counters about one peer, for the control plane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Routes accepted from the peer, per family.
    pub received: Vec<(AddressFamily, usize)>,
    /// Routes advertised to the peer, per family.
    pub advertised: Vec<(AddressFamily, usize)>,
}

/// All RIB state.
pub struct Rib {
    /// Adj-RIBs-In and Loc-RIB together: every route per destination,
    /// the best first.
    tables: FamilyMap<BTreeMap<Prefix, Destination>>,
    /// Everything else. Kept apart from the tables so that a table can be
    /// walked while Phase 3 updates the peers' Adj-RIBs-Out.
    s: Sessions,
}

struct Sessions {
    cx: Context,
    /// Peers that are up, by slot; `None` is a free slot.
    peers: Vec<Option<PeerState>>,
    /// The slot of each peer that is up.
    by_addr: HashMap<IpAddr, PeerId>,
}

/// What import and export apply to a route.
struct Context {
    local_as: Asn,
    policies: Box<dyn Policies>,
    interner: Interner,
}

/// UPDATEs being built during one input, per peer and family.
type Batches = HashMap<(IpAddr, AddressFamily), Batch>;

/// A destination whose routes an UPDATE changed, and its best route
/// before the first change (Phase 3 runs when the best route differs).
struct Dirty {
    family: AddressFamily,
    prefix: Prefix,
    old: Option<Route>,
}

impl Rib {
    /// An empty RIB for a speaker in `local_as` that accepts every route.
    #[must_use]
    pub fn new(local_as: Asn) -> Rib {
        Rib::with_policies(local_as, Box::new(AcceptAll))
    }

    /// An empty RIB for a speaker in `local_as` with the given policies.
    #[must_use]
    pub fn with_policies(local_as: Asn, policies: Box<dyn Policies>) -> Rib {
        Rib {
            tables: FamilyMap::default(),
            s: Sessions {
                cx: Context {
                    local_as,
                    policies,
                    interner: Interner::default(),
                },
                peers: Vec::new(),
                by_addr: HashMap::new(),
            },
        }
    }

    /// Replace the policies. The caller re-evaluates routes afterwards
    /// (route refresh for imports, [`Rib::refresh`] for exports).
    pub fn set_policies(&mut self, policies: Box<dyn Policies>) {
        self.s.cx.policies = policies;
    }

    /// Our AS.
    #[must_use]
    pub fn local_as(&self) -> Asn {
        self.s.cx.local_as
    }

    /// A session reached Established: remember the peer and send it the
    /// Loc-RIB for every negotiated family (RFC 4271 §9.2: the initial
    /// Adj-RIB-Out).
    pub fn peer_up(&mut self, info: PeerInfo, out: &mut impl Sink) {
        let addr = info.addr;
        let families = info.families.clone();
        self.s.add(PeerState {
            neighbor: Neighbor::of(&info),
            info,
            disabled: Vec::new(),
            adj_out: FamilyMap::default(),
            adj_in_count: FamilyMap::default(),
        });
        for family in families {
            self.refresh(addr, family, out);
        }
    }

    /// The session left Established: forget the peer and its routes.
    pub fn peer_down(&mut self, addr: IpAddr, out: &mut impl Sink) {
        #[cfg(feature = "profiling")]
        let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_PEER_DOWN);
        let Some(id) = self.s.remove(addr) else {
            return;
        };
        let mut batches = Batches::new();
        // Every table, not only the negotiated families: the slot is free
        // for another peer once this returns, so no route may still name it.
        for (family, table) in self.tables.iter_mut() {
            table.retain(|prefix, dest| {
                self.s
                    .remove_route(family, *prefix, dest, id, &mut batches, out)
            });
        }
        self.s.emit(&batches, out);
    }

    /// Stop accepting `family` from `addr` and drop what it sent
    /// (RFC 4760 §7).
    pub fn family_disabled(&mut self, addr: IpAddr, family: AddressFamily, out: &mut impl Sink) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        let state = self.s.peer_mut(id);
        if !state.disabled.contains(&family) {
            state.disabled.push(family);
        }
        state.adj_in_count.insert(family, 0);
        let mut batches = Batches::new();
        if let Some(table) = self.tables.get_mut(family) {
            table.retain(|prefix, dest| {
                self.s
                    .remove_route(family, *prefix, dest, id, &mut batches, out)
            });
        }
        self.s.emit(&batches, out);
    }

    /// The peer asked for `family` again (RFC 2918 §4): resend the
    /// Adj-RIB-Out in full. Also used to build the initial one.
    pub fn refresh(&mut self, addr: IpAddr, family: AddressFamily, out: &mut impl Sink) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        if !self.s.peer(id).info.speaks(family) {
            return;
        }
        let mut batch = Batch::default();
        // Refill the map in place: its capacity is the table's already.
        let mut adj_out = self
            .s
            .peer_mut(id)
            .adj_out
            .remove(family)
            .unwrap_or_default();
        adj_out.clear();
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table {
                if let Some(a) = self.s.exported(family, *prefix, dest.best(), id) {
                    batch.announce(&a, *prefix);
                    adj_out.insert(*prefix, a);
                }
            }
        }
        let state = self.s.peer_mut(id);
        state.adj_out.insert(family, adj_out);
        Sessions::encode(&state.info, family, &batch, out);
    }

    /// Re-run export for `addr` and `family` after a policy change: only
    /// what differs from the Adj-RIB-Out is sent (announcements for new
    /// or changed routes, withdrawals for routes no longer exported).
    pub fn reexport(&mut self, addr: IpAddr, family: AddressFamily, out: &mut impl Sink) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        if !self.s.peer(id).info.speaks(family) {
            return;
        }
        let mut batch = Batch::default();
        let mut adj_out = self
            .s
            .peer_mut(id)
            .adj_out
            .remove(family)
            .unwrap_or_default();
        // Phase 3 keeps every Adj-RIB-Out entry on a destination that has
        // a best route, so one pass over the table visits all of them.
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table {
                match self.s.exported(family, *prefix, dest.best(), id) {
                    Some(a) => match adj_out.insert(*prefix, Arc::clone(&a)) {
                        Some(old) if Arc::ptr_eq(&old, &a) => {}
                        old => {
                            if let Some(old) = old {
                                self.s.cx.interner.release(old);
                            }
                            batch.announce(&a, *prefix);
                        }
                    },
                    None => {
                        if let Some(old) = adj_out.remove(prefix) {
                            self.s.cx.interner.release(old);
                            batch.withdraw.push(*prefix);
                        }
                    }
                }
            }
        }
        let state = self.s.peer_mut(id);
        state.adj_out.insert(family, adj_out);
        Sessions::encode(&state.info, family, &batch, out);
    }

    /// What the RIB knows about peer `addr`, if it is up.
    #[must_use]
    pub fn peer(&self, addr: IpAddr) -> Option<&PeerInfo> {
        self.s.id(addr).map(|id| &self.s.peer(id).info)
    }

    /// An UPDATE from `addr`: apply its withdrawals and announcements to
    /// the Adj-RIB-In, rerun the decision process for the destinations
    /// touched, and produce the FIB changes and UPDATEs that follow.
    pub fn update(&mut self, addr: IpAddr, update: &DecodedUpdate, out: &mut impl Sink) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        let Sessions { cx, peers, .. } = &mut self.s;
        let Some(state) = peers[id.index()].as_ref() else {
            return;
        };
        let info = &state.info;
        let mut dirty = Vec::new();
        // Attribute sets of the routes removed or replaced, released from
        // the interner once nothing else of this UPDATE holds them.
        let mut released = Vec::new();
        let mut delta: FamilyMap<isize> = FamilyMap::default();
        for (family, prefix) in update.withdrawals() {
            #[cfg(feature = "profiling")]
            let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_REMOVE);
            if state.disabled.contains(&family) {
                continue;
            }
            if let Some(dest) = self.tables.get_mut(family).and_then(|t| t.get_mut(&prefix))
                && let Some(i) = dest.position(id)
            {
                dirty.push(Dirty {
                    family,
                    prefix,
                    old: dest.best().cloned(),
                });
                released.push(dest.remove(i).attrs);
                *delta.or_default(family) -= 1;
            }
        }
        let mut attrs_for: FamilyMap<Option<Arc<PathAttrs>>> = FamilyMap::default();
        for (family, prefix) in update.announcements() {
            #[cfg(feature = "profiling")]
            let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_INSERT);
            if state.disabled.contains(&family) {
                continue;
            }
            let attrs = if let Some(a) = attrs_for.get(family) {
                a.clone()
            } else {
                let a =
                    PathAttrs::from_update(&update.message, family).map(|a| cx.interner.intern(a));
                attrs_for.insert(family, a.clone());
                a
            };
            let Some(attrs) = attrs else {
                continue;
            };
            // RFC 4271 §9.1.2: a route whose AS_PATH contains our AS is an
            // AS loop and is excluded from Phase 2. RFC 4271 §6.3 and
            // RFC 7606 §7.2: on an external session the leftmost AS must
            // be the peer's, else the route is treated as withdrawn.
            // Neither kind is stored.
            let leftmost_ok = info.kind == PeerKind::Internal
                || attrs.as_path.first_asn() == Some(info.remote_as);
            // RFC 4271 §9.1.1: import policy decides what enters, and may
            // change attributes (the degree of preference among them).
            let accepted = if attrs.as_path.contains(cx.local_as) || !leftmost_ok {
                None
            } else {
                match cx.policies.import(info, family, prefix, &attrs) {
                    Verdict::Accept => Some(attrs),
                    Verdict::Modified(a) => Some(cx.interner.intern(a)),
                    Verdict::Reject => None,
                }
            };
            let Some(attrs) = accepted else {
                if let Some(dest) = self.tables.get_mut(family).and_then(|t| t.get_mut(&prefix))
                    && let Some(i) = dest.position(id)
                {
                    dirty.push(Dirty {
                        family,
                        prefix,
                        old: dest.best().cloned(),
                    });
                    released.push(dest.remove(i).attrs);
                    *delta.or_default(family) -= 1;
                }
                continue;
            };
            let dest = self.tables.or_default(family).entry(prefix).or_default();
            let old = dest.best().cloned();
            let route = Route { attrs, peer: id };
            if let Some(i) = dest.position(id) {
                if Arc::ptr_eq(&dest.routes()[i].attrs, &route.attrs) {
                    // An implicit re-announcement of the same route.
                    continue;
                }
                released.push(std::mem::replace(&mut dest.routes_mut()[i], route).attrs);
            } else {
                dest.push(route);
                *delta.or_default(family) += 1;
            }
            dirty.push(Dirty {
                family,
                prefix,
                old,
            });
        }
        let state = self.s.peer_mut(id);
        for (family, d) in delta.iter() {
            let n = state.adj_in_count.or_default(family);
            *n = n.saturating_add_signed(*d);
        }
        self.reconsider(&dirty, out);
        drop((dirty, attrs_for));
        for a in released {
            self.s.cx.interner.release(a);
        }
    }

    /// The Loc-RIB of `family`, best routes in prefix order.
    pub fn loc_rib(&self, family: AddressFamily) -> impl Iterator<Item = (Prefix, RouteRef<'_>)> {
        self.tables
            .get(family)
            .into_iter()
            .flat_map(|t| t.iter())
            .filter_map(|(p, d)| d.best().map(|r| (*p, self.s.route_ref(r))))
    }

    /// Every route to `prefix` in the Adj-RIBs-In, the best first.
    pub fn candidates(
        &self,
        family: AddressFamily,
        prefix: Prefix,
    ) -> impl Iterator<Item = RouteRef<'_>> {
        self.tables
            .get(family)
            .and_then(|t| t.get(&prefix))
            .map_or(&[][..], Destination::routes)
            .iter()
            .map(|r| self.s.route_ref(r))
    }

    /// The Adj-RIB-Out for `addr` and `family`.
    pub fn adj_rib_out(
        &self,
        addr: IpAddr,
        family: AddressFamily,
    ) -> impl Iterator<Item = (Prefix, &Arc<PathAttrs>)> {
        self.s
            .id(addr)
            .and_then(|id| self.s.peer(id).adj_out.get(family))
            .into_iter()
            .flat_map(|m| m.iter().map(|(p, a)| (*p, a)))
    }

    /// Route counts for `addr`.
    #[must_use]
    pub fn peer_stats(&self, addr: IpAddr) -> Option<PeerStats> {
        let p = self.s.peer(self.s.id(addr)?);
        let mut stats = PeerStats::default();
        for family in &p.info.families {
            stats
                .received
                .push((*family, p.adj_in_count.get(*family).copied().unwrap_or(0)));
            stats
                .advertised
                .push((*family, p.adj_out.get(*family).map_or(0, HashMap::len)));
        }
        Some(stats)
    }

    /// Peers currently up.
    pub fn peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.s.peers.iter().flatten().map(|p| &p.info)
    }

    /// Distinct attribute sets held.
    #[must_use]
    pub fn attribute_sets(&self) -> usize {
        self.s.cx.interner.len()
    }

    /// Rerun Phase 2 for each dirty destination and Phase 3 for every
    /// destination whose best route changed.
    fn reconsider(&mut self, dirty: &[Dirty], out: &mut impl Sink) {
        let mut batches = Batches::new();
        let mut seen = HashSet::new();
        for d in dirty {
            // The first entry for a destination has its best route from
            // before the UPDATE.
            if !seen.insert((d.family, d.prefix)) {
                continue;
            }
            let Some(table) = self.tables.get_mut(d.family) else {
                continue;
            };
            let Some(dest) = table.get_mut(&d.prefix) else {
                continue;
            };
            if !self
                .s
                .settle(d.family, d.prefix, dest, d.old.as_ref(), &mut batches, out)
            {
                table.remove(&d.prefix);
            }
        }
        self.s.emit(&batches, out);
    }
}

impl Sessions {
    fn id(&self, addr: IpAddr) -> Option<PeerId> {
        self.by_addr.get(&addr).copied()
    }

    fn peer(&self, id: PeerId) -> &PeerState {
        // invariant: ids are only handed out for occupied slots, and a
        // slot is freed only after every route naming it is gone.
        self.peers[id.index()].as_ref().unwrap()
    }

    fn peer_mut(&mut self, id: PeerId) -> &mut PeerState {
        // invariant: as in `peer`.
        self.peers[id.index()].as_mut().unwrap()
    }

    /// Put `state` in the slot its address has, or in a free one.
    fn add(&mut self, state: PeerState) {
        let id = if let Some(id) = self.by_addr.get(&state.info.addr) {
            *id
        } else {
            let i = if let Some(i) = self.peers.iter().position(Option::is_none) {
                i
            } else {
                self.peers.push(None);
                self.peers.len() - 1
            };
            // invariant: fewer than 2^32 peers.
            let id = PeerId(u32::try_from(i).unwrap());
            self.by_addr.insert(state.info.addr, id);
            id
        };
        self.peers[id.index()] = Some(state);
    }

    /// Forget `addr`; its slot is free once its routes are removed.
    fn remove(&mut self, addr: IpAddr) -> Option<PeerId> {
        let id = self.by_addr.remove(&addr)?;
        if let Some(state) = self.peers[id.index()].take() {
            for a in state.adj_out.into_values().flat_map(HashMap::into_values) {
                self.cx.interner.release(a);
            }
        }
        Some(id)
    }

    fn route_ref<'a>(&self, r: &'a Route) -> RouteRef<'a> {
        RouteRef {
            peer: self.peer(r.peer).neighbor.addr,
            attrs: &r.attrs,
        }
    }

    /// Phase 2: put the best of `dest`'s routes first.
    fn decide(&self, dest: &mut Destination) {
        let routes = dest.routes();
        let best = decision::best(routes.len(), |i| Candidate {
            from: self.peer(routes[i].peer).neighbor,
            attrs: &routes[i].attrs,
        });
        if let Some(i) = best {
            dest.promote(i);
        }
    }

    /// Remove `id`'s route from `dest`, if it has one, and settle the
    /// destination. Whether it still has routes.
    fn remove_route(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        dest: &mut Destination,
        id: PeerId,
        batches: &mut Batches,
        out: &mut impl Sink,
    ) -> bool {
        let Some(i) = dest.position(id) else {
            return true;
        };
        let old = dest.best().cloned();
        let removed = dest.remove(i);
        let keep = self.settle(family, prefix, dest, old.as_ref(), batches, out);
        drop(old);
        self.cx.interner.release(removed.attrs);
        keep
    }

    /// Phase 2 for a destination whose routes changed, then Phase 3 if
    /// its best route is not `old`. Whether it still has routes.
    fn settle(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        dest: &mut Destination,
        old: Option<&Route>,
        batches: &mut Batches,
        out: &mut impl Sink,
    ) -> bool {
        self.decide(dest);
        let new = dest.best();
        let changed = match (old, new) {
            (None, None) => false,
            (Some(a), Some(b)) => !a.same(b),
            _ => true,
        };
        if changed {
            out.put(Output::Fib(FibChange {
                family,
                prefix,
                next_hop: new.map(|r| r.attrs.next_hop_addr()),
            }));
            self.disseminate(family, prefix, new, batches);
        }
        !dest.is_empty()
    }

    /// Phase 3: every peer's Adj-RIB-Out follows the new best route.
    fn disseminate(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        best: Option<&Route>,
        batches: &mut Batches,
    ) {
        for i in 0..self.peers.len() {
            let Some(to) = &self.peers[i] else {
                continue;
            };
            if !to.info.speaks(family) {
                continue;
            }
            let to_addr = to.info.addr;
            // invariant: fewer than 2^32 peers.
            let exported = self.exported(family, prefix, best, PeerId(u32::try_from(i).unwrap()));
            // invariant: the slot was occupied above.
            let to = self.peers[i].as_mut().unwrap();
            let adj_out = to.adj_out.or_default(family);
            match exported {
                Some(a) => {
                    let same = adj_out.get(&prefix).is_some_and(|old| Arc::ptr_eq(old, &a));
                    if !same {
                        if let Some(old) = adj_out.insert(prefix, Arc::clone(&a)) {
                            self.cx.interner.release(old);
                        }
                        batches
                            .entry((to_addr, family))
                            .or_default()
                            .announce(&a, prefix);
                    }
                }
                None => {
                    if let Some(old) = adj_out.remove(&prefix) {
                        self.cx.interner.release(old);
                        batches
                            .entry((to_addr, family))
                            .or_default()
                            .withdraw
                            .push(prefix);
                    }
                }
            }
        }
    }

    /// The interned attributes `best` is advertised with to peer `to`, if
    /// any: export policy first (RFC 4271 §9.1.3), then the session
    /// rewriting of §5.1.
    fn exported(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        best: Option<&Route>,
        to: PeerId,
    ) -> Option<Arc<PathAttrs>> {
        let best = best?;
        let from = self.peer(best.peer).neighbor;
        let source = Source {
            peer: from.addr,
            kind: from.kind,
        };
        let to = &self.peers[to.index()].as_ref()?.info;
        let cx = &mut self.cx;
        // The route is not offered to the policy at all when §9.2 rules
        // it out, so a policy cannot override those.
        if !export::eligible(family, source, to) {
            return None;
        }
        let modified;
        let attrs: &PathAttrs = match cx.policies.export(to, family, prefix, &best.attrs) {
            Verdict::Reject => return None,
            Verdict::Accept => &best.attrs,
            Verdict::Modified(a) => {
                modified = a;
                &modified
            }
        };
        export::export(cx.local_as, family, source, attrs, to).map(|a| cx.interner.intern(a))
    }

    /// Encode the batches, in peer and family order.
    fn emit(&self, batches: &Batches, out: &mut impl Sink) {
        let mut keys: Vec<_> = batches.keys().copied().collect();
        keys.sort();
        for key in keys {
            if let Some(id) = self.id(key.0) {
                Sessions::encode(&self.peer(id).info, key.1, &batches[&key], out);
            }
        }
    }

    fn encode(to: &PeerInfo, family: AddressFamily, batch: &Batch, out: &mut impl Sink) {
        if batch.is_empty() {
            return;
        }
        out.put(match batch.encode(family, to) {
            Ok(messages) => Output::Send {
                peer: to.addr,
                messages,
            },
            Err(error) => Output::EncodeFailed {
                peer: to.addr,
                error,
            },
        });
    }
}
