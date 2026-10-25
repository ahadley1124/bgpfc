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

use std::collections::btree_map::Entry as Slot;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use bgpfc_wire::prefix::{Ipv4Key, Prefix};
use bgpfc_wire::types::{AddressFamily, Asn};
use bgpfc_wire::update::{DecodedUpdate, PeerKind};

pub use attrs::{Interner, PathAttrs};
pub use decision::{Candidate, Neighbor};
pub use export::{Batch, Source};
pub use peer::PeerInfo;
use store::{Destination, FamilyMap, PeerId, Route, Table};

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
    /// The next hop it replaces, or `None` when the destination is new.
    pub previous: Option<IpAddr>,
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
    /// Routes in the Adj-RIB-Out per family. The Adj-RIB-Out itself is
    /// not stored (RFC 4271 §3.2 asks for the information, not a table):
    /// what the peer was last told about a destination is what export
    /// makes of its best route, since every change of that best route is
    /// sent as it happens and a policy change is compared under both
    /// policies ([`Rib::set_policies`]). A copy per peer would cost tens of
    /// megabytes for each full table sent.
    advertised: FamilyMap<usize>,
    /// Routes held in the Adj-RIB-In per family (for statistics).
    adj_in_count: FamilyMap<usize>,
    /// The session is going down: its routes are being removed, and it is
    /// sent nothing more.
    leaving: bool,
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
    tables: FamilyMap<Table>,
    /// Everything else. Kept apart from the tables so that a table can be
    /// walked while Phase 3 updates the peers' Adj-RIBs-Out.
    s: Sessions,
    /// Buffers each UPDATE reuses.
    scratch: Scratch,
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

/// UPDATEs being built during one input, per peer and family. A short
/// list: an input reaches a handful of peers.
#[derive(Default)]
struct Batches(Vec<(PeerId, AddressFamily, Batch)>);

impl Batches {
    fn get(&mut self, peer: PeerId, family: AddressFamily) -> &mut Batch {
        let i = if let Some(i) = self
            .0
            .iter()
            .position(|(p, f, _)| *p == peer && *f == family)
        {
            i
        } else {
            self.0.push((peer, family, Batch::default()));
            self.0.len() - 1
        };
        &mut self.0[i].2
    }
}

/// A destination an UPDATE changed: its best route before the first
/// change and after the last. Phase 3 runs when they differ.
struct Dirty {
    family: AddressFamily,
    prefix: Prefix,
    old: Option<Route>,
    new: Option<Route>,
    /// A later entry for a destination listed earlier, merged into it.
    merged: bool,
}

/// Buffers an UPDATE reuses, so that one costs no allocation of its own.
#[derive(Default)]
struct Scratch {
    dirty: Vec<Dirty>,
    /// How many of `dirty` the UPDATE's withdrawals made; the rest come
    /// from its announcements.
    withdrawn: usize,
    /// Indices of the entries the withdrawals made, sorted by destination.
    order: Vec<u32>,
    /// Attribute sets of the routes removed or replaced, released from
    /// the interner once nothing else of the UPDATE holds them.
    released: Vec<Arc<PathAttrs>>,
    /// Routes added minus routes removed, per family.
    delta: FamilyMap<isize>,
    batches: Batches,
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
            scratch: Scratch::default(),
        }
    }

    /// Replace the policies, and send the peers in `reexport` (those
    /// whose export policy changed) what that changes: announcements for
    /// routes new or changed, withdrawals for routes no longer exported,
    /// found by exporting every best route under the old policies and the
    /// new. Import changes are the caller's to re-evaluate (route refresh).
    pub fn set_policies(
        &mut self,
        policies: Box<dyn Policies>,
        reexport: &[IpAddr],
        out: &mut impl Sink,
    ) {
        let old = std::mem::replace(&mut self.s.cx.policies, policies);
        for addr in reexport {
            let Some(id) = self.s.id(*addr) else {
                continue;
            };
            let families = self.s.peer(id).info.families.clone();
            for family in families {
                self.reexport(&*old, id, family, out);
            }
        }
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
            advertised: FamilyMap::default(),
            adj_in_count: FamilyMap::default(),
            leaving: false,
        });
        for family in families {
            self.refresh(addr, family, out);
        }
    }

    /// The session left Established: forget the peer and its routes.
    pub fn peer_down(&mut self, addr: IpAddr, out: &mut impl Sink) {
        #[cfg(feature = "profiling")]
        let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_PEER_DOWN);
        let Some(id) = self.s.id(addr) else {
            return;
        };
        // Kept while its routes go, which export needs to tell apart.
        self.s.peer_mut(id).leaving = true;
        let mut batches = Batches::default();
        // Every table, not only the negotiated families: the slot is free
        // for another peer once this returns, so no route may still name it.
        for (family, table) in self.tables.iter_mut() {
            table.retain(|prefix, dest| {
                self.s
                    .remove_route(family, prefix, dest, id, &mut batches, out)
            });
        }
        self.s.emit(&mut batches, out);
        self.s.remove(addr);
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
        let mut batches = Batches::default();
        if let Some(table) = self.tables.get_mut(family) {
            table.retain(|prefix, dest| {
                self.s
                    .remove_route(family, prefix, dest, id, &mut batches, out)
            });
        }
        self.s.emit(&mut batches, out);
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
        let mut n = 0;
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table.iter() {
                let a = self.s.exported(None, family, prefix, dest.best(), id);
                n += usize::from(a.is_some());
                self.s.compare(id, family, prefix, None, a, &mut batch);
            }
        }
        self.s.peer_mut(id).advertised.insert(family, n);
        self.s.send(id, family, batch, out);
    }

    /// After a change of export policy from `old`: what differs for `id`
    /// in `family` between exporting every best route under `old` and
    /// under the current policies.
    fn reexport(
        &mut self,
        old: &dyn Policies,
        id: PeerId,
        family: AddressFamily,
        out: &mut impl Sink,
    ) {
        if !self.s.peer(id).info.speaks(family) {
            return;
        }
        let mut batch = Batch::default();
        let mut n = 0;
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table.iter() {
                let before = self.s.exported(Some(old), family, prefix, dest.best(), id);
                let after = self.s.exported(None, family, prefix, dest.best(), id);
                n += usize::from(after.is_some());
                self.s
                    .compare(id, family, prefix, before, after, &mut batch);
            }
        }
        self.s.peer_mut(id).advertised.insert(family, n);
        self.s.send(id, family, batch, out);
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
        let mut scratch = std::mem::take(&mut self.scratch);
        self.apply(id, update, &mut scratch);
        self.finish(&mut scratch, out);
        self.scratch = scratch;
    }

    /// Apply an UPDATE's withdrawals, then its announcements, to the
    /// Adj-RIB-In, and run Phase 2 for each destination as it changes.
    fn apply(&mut self, id: PeerId, update: &DecodedUpdate, scratch: &mut Scratch) {
        let Sessions { cx, peers, .. } = &mut self.s;
        let Some(state) = peers[id.index()].as_ref() else {
            return;
        };
        let info = &state.info;
        for (family, prefix) in update.withdrawals() {
            #[cfg(feature = "profiling")]
            let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_REMOVE);
            if state.disabled.contains(&family) {
                continue;
            }
            if let Some(table) = self.tables.get_mut(family) {
                withdraw(peers, table, family, prefix, id, scratch);
            }
        }
        scratch.withdrawn = scratch.dirty.len();
        // The attribute set of the family being announced: an UPDATE has
        // one per family, and lists each family's prefixes together.
        let mut current: Option<(AddressFamily, Option<Arc<PathAttrs>>)> = None;
        for (family, prefix) in update.announcements() {
            #[cfg(feature = "profiling")]
            let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_INSERT);
            if state.disabled.contains(&family) {
                continue;
            }
            let attrs = match &current {
                Some((f, a)) if *f == family => a.clone(),
                _ => {
                    let a = PathAttrs::from_update(&update.message, family)
                        .map(|a| cx.interner.intern(a));
                    current = Some((family, a.clone()));
                    a
                }
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
            match accepted {
                Some(attrs) => {
                    let table = self.tables.or_default(family);
                    announce(
                        peers,
                        table,
                        family,
                        prefix,
                        Route { attrs, peer: id },
                        scratch,
                    );
                }
                None => {
                    if let Some(table) = self.tables.get_mut(family) {
                        withdraw(peers, table, family, prefix, id, scratch);
                    }
                }
            }
        }
        let state = self.s.peer_mut(id);
        for (family, d) in scratch.delta.iter_mut() {
            let n = state.adj_in_count.or_default(family);
            *n = n.saturating_add_signed(*d);
            *d = 0;
        }
    }

    /// Phase 3 for every destination whose best route an UPDATE changed,
    /// then the UPDATEs that follow; release what the UPDATE let go of.
    fn finish(&mut self, scratch: &mut Scratch, out: &mut impl Sink) {
        merge_repeats(&mut scratch.dirty, scratch.withdrawn, &mut scratch.order);
        for d in &scratch.dirty {
            if !d.merged {
                self.s.changed(
                    d.family,
                    d.prefix,
                    d.old.as_ref(),
                    d.new.as_ref(),
                    &mut scratch.batches,
                    out,
                );
            }
        }
        self.s.emit(&mut scratch.batches, out);
        scratch.dirty.clear();
        for a in scratch.released.drain(..) {
            self.s.cx.interner.release(a);
        }
    }

    /// The Loc-RIB of `family`, best routes in prefix order.
    pub fn loc_rib(&self, family: AddressFamily) -> impl Iterator<Item = (Prefix, RouteRef<'_>)> {
        self.loc_rib_after(family, None)
    }

    /// The Loc-RIB of `family` after `from`, in prefix order: a long
    /// listing taken a part at a time.
    pub fn loc_rib_after(
        &self,
        family: AddressFamily,
        from: Option<Prefix>,
    ) -> impl Iterator<Item = (Prefix, RouteRef<'_>)> {
        self.tables
            .get(family)
            .into_iter()
            .flat_map(move |t| t.after(from))
            .filter_map(|(p, d)| d.best().map(|r| (p, self.s.route_ref(r))))
    }

    /// Every route to `prefix` in the Adj-RIBs-In, the best first.
    pub fn candidates(
        &self,
        family: AddressFamily,
        prefix: Prefix,
    ) -> impl Iterator<Item = RouteRef<'_>> {
        self.tables
            .get(family)
            .and_then(|t| t.get(prefix))
            .map_or(&[][..], Destination::routes)
            .iter()
            .map(|r| self.s.route_ref(r))
    }

    /// Every destination's next hop, as the FIB wants it: IPv4 unicast,
    /// then IPv6 unicast, each in prefix order, so in one prefix order
    /// throughout (what `bgpfc_fib::Routes::merge` takes).
    pub fn fib_routes(&self) -> impl Iterator<Item = (Prefix, IpAddr)> {
        self.fib_routes_after(None)
    }

    /// [`Rib::fib_routes`] after `from`.
    pub fn fib_routes_after(&self, from: Option<Prefix>) -> impl Iterator<Item = (Prefix, IpAddr)> {
        [AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST]
            .into_iter()
            .filter_map(|f| self.tables.get(f))
            .flat_map(move |t| t.after(from))
            .filter_map(|(p, d)| d.best().map(|r| (p, r.attrs.next_hop_addr())))
    }

    /// The Adj-RIB-Out for `addr` and `family`, in prefix order: each
    /// route as the export policy leaves it, before the session rewrite
    /// (RFC 4271 §5.1) that encoding applies. Worked out from the Loc-RIB,
    /// which is how the RIB keeps it.
    #[must_use]
    pub fn adj_rib_out(
        &self,
        addr: IpAddr,
        family: AddressFamily,
    ) -> Vec<(Prefix, Arc<PathAttrs>)> {
        let Some(id) = self.s.id(addr) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table.iter() {
                match self.s.exported(None, family, prefix, dest.best(), id) {
                    Some(Exported::Own(a)) => out.push((prefix, a)),
                    Some(Exported::Changed(a)) => out.push((prefix, Arc::new(a))),
                    None => {}
                }
            }
        }
        out
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
                .push((*family, p.advertised.get(*family).copied().unwrap_or(0)));
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

    /// Forget `addr`, whose routes are gone; its slot is free.
    fn remove(&mut self, addr: IpAddr) {
        if let Some(id) = self.by_addr.remove(&addr) {
            self.peers[id.index()] = None;
        }
    }

    fn route_ref<'a>(&self, r: &'a Route) -> RouteRef<'a> {
        RouteRef {
            peer: self.peer(r.peer).neighbor.addr,
            attrs: &r.attrs,
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
        decide(&self.peers, dest);
        self.changed(family, prefix, old, dest.best(), batches, out);
        !dest.is_empty()
    }

    /// Phase 3 and the FIB change when the best route went from `old` to
    /// `new`; nothing when it is the same route.
    fn changed(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        old: Option<&Route>,
        new: Option<&Route>,
        batches: &mut Batches,
        out: &mut impl Sink,
    ) {
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
                previous: old.map(|r| r.attrs.next_hop_addr()),
            }));
            self.disseminate(family, prefix, old, new, batches);
        }
    }

    /// Phase 3: every peer is told about the best route going from `old`
    /// to `new`, as far as export makes a difference to it.
    fn disseminate(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        old: Option<&Route>,
        new: Option<&Route>,
        batches: &mut Batches,
    ) {
        for i in 0..self.peers.len() {
            let Some(to) = &self.peers[i] else {
                continue;
            };
            if to.leaving || !to.info.speaks(family) {
                continue;
            }
            // invariant: fewer than 2^32 peers.
            let id = PeerId(u32::try_from(i).unwrap());
            // A peer is never sent its own routes (export::eligible): from
            // it before and after, there is nothing to do. With one peer
            // up, that is every route.
            if old.is_none_or(|r| r.peer == id) && new.is_none_or(|r| r.peer == id) {
                continue;
            }
            let before = self.exported(None, family, prefix, old, id);
            let after = self.exported(None, family, prefix, new, id);
            let counted = (before.is_some(), after.is_some());
            self.compare(id, family, prefix, before, after, batches);
            let n = self.peer_mut(id).advertised.or_default(family);
            match counted {
                (false, true) => *n += 1,
                (true, false) => *n = n.saturating_sub(1),
                _ => {}
            }
        }
    }

    /// What export makes of `best` for peer `to`, under `policies` when
    /// given (the ones replaced, in a re-export), else the current ones:
    /// the route's own set when the policy accepts it unchanged (RFC 4271
    /// §9.1.3), else the policy's. `None` when it is not advertised to
    /// `to`. The session rewrite of §5.1 is the encoder's
    /// (`Batch::encode`).
    fn exported(
        &self,
        policies: Option<&dyn Policies>,
        family: AddressFamily,
        prefix: Prefix,
        best: Option<&Route>,
        to: PeerId,
    ) -> Option<Exported> {
        let best = best?;
        let from = self.peer(best.peer).neighbor;
        let source = Source {
            peer: from.addr,
            kind: from.kind,
        };
        let to = &self.peer(to).info;
        // The route is not offered to the policy at all when §9.2 rules
        // it out, so a policy cannot override those.
        if !export::eligible(family, source, to) {
            return None;
        }
        let policies = policies.unwrap_or(&*self.cx.policies);
        match policies.export(to, family, prefix, &best.attrs) {
            Verdict::Reject => None,
            Verdict::Accept => {
                export::permitted(&best.attrs, to).then(|| Exported::Own(Arc::clone(&best.attrs)))
            }
            Verdict::Modified(a) => export::permitted(&a, to).then_some(Exported::Changed(a)),
        }
    }

    /// Put in peer `id`'s batch what it must be sent about `prefix` when
    /// what export makes of its best route goes from `before` to `after`:
    /// an announcement, a withdrawal, or nothing when they are the same
    /// set or the session rewrite (RFC 4271 §5.1) makes them the same,
    /// which the peer cannot tell apart.
    fn compare(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        prefix: Prefix,
        before: Option<Exported>,
        after: Option<Exported>,
        batches: &mut impl BatchFor,
    ) {
        match (before, after) {
            (None, None) => {}
            (Some(_), None) => batches.batch(id, family).withdraw.push(prefix),
            (Some(b), Some(a))
                if b.is(&a)
                    || export::same_rewrite(family, b.attrs(), a.attrs(), &self.peer(id).info) => {}
            (_, Some(a)) => {
                let a = match a {
                    Exported::Own(a) => a,
                    Exported::Changed(a) => self.cx.interner.intern(a),
                };
                batches.batch(id, family).announce(&a, prefix);
            }
        }
    }

    /// Encode and hand over one peer's batch for `family`.
    fn send(&mut self, id: PeerId, family: AddressFamily, mut batch: Batch, out: &mut impl Sink) {
        Sessions::encode(self.cx.local_as, &self.peer(id).info, family, &batch, out);
        for a in batch.take_sets() {
            self.cx.interner.release(a);
        }
    }

    /// Encode the batches, in peer address and family order, and empty
    /// them.
    fn emit(&mut self, batches: &mut Batches, out: &mut impl Sink) {
        batches
            .0
            .sort_by_key(|(id, family, _)| (self.peer(*id).info.addr, *family));
        for (id, family, batch) in &mut batches.0 {
            Sessions::encode(self.cx.local_as, &self.peer(*id).info, *family, batch, out);
            // The sets a policy changed are held by nothing else.
            for a in batch.take_sets() {
                self.cx.interner.release(a);
            }
        }
        batches.0.clear();
    }

    fn encode(
        local_as: Asn,
        to: &PeerInfo,
        family: AddressFamily,
        batch: &Batch,
        out: &mut impl Sink,
    ) {
        if batch.is_empty() {
            return;
        }
        out.put(match batch.encode(local_as, family, to) {
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

/// What export makes of a route for one peer, before the session rewrite.
enum Exported {
    /// The route's own set: the policy accepted it unchanged.
    Own(Arc<PathAttrs>),
    /// The set the policy changed it to, not interned until it is sent.
    Changed(PathAttrs),
}

impl Exported {
    fn attrs(&self) -> &PathAttrs {
        match self {
            Exported::Own(a) => a,
            Exported::Changed(a) => a,
        }
    }

    /// Whether both are the same route's own set.
    fn is(&self, other: &Exported) -> bool {
        matches!((self, other), (Exported::Own(a), Exported::Own(b)) if Arc::ptr_eq(a, b))
    }
}

/// Where Phase 3 puts what a peer is to be sent: the input's batches, or
/// the one batch of a re-export.
trait BatchFor {
    fn batch(&mut self, id: PeerId, family: AddressFamily) -> &mut Batch;
}

impl BatchFor for Batches {
    fn batch(&mut self, id: PeerId, family: AddressFamily) -> &mut Batch {
        self.get(id, family)
    }
}

impl BatchFor for Batch {
    fn batch(&mut self, _: PeerId, _: AddressFamily) -> &mut Batch {
        self
    }
}

/// Phase 2: put the best of `dest`'s routes first.
fn decide(peers: &[Option<PeerState>], dest: &mut Destination) {
    let routes = dest.routes();
    let best = decision::best(routes.len(), |i| Candidate {
        // invariant: a route's peer slot is occupied (Sessions::peer).
        from: peers[routes[i].peer.index()].as_ref().unwrap().neighbor,
        attrs: &routes[i].attrs,
    });
    if let Some(i) = best {
        dest.promote(i);
    }
}

/// Remove peer `id`'s route to `prefix`, if there is one, and note the
/// destination's best route before and after.
fn withdraw(
    peers: &[Option<PeerState>],
    table: &mut Table,
    family: AddressFamily,
    prefix: Prefix,
    id: PeerId,
    scratch: &mut Scratch,
) {
    match Ipv4Key::new(prefix) {
        Some(k) => withdraw_in(peers, &mut table.v4, k, family, prefix, id, scratch),
        None => withdraw_in(peers, &mut table.v6, prefix, family, prefix, id, scratch),
    }
}

fn withdraw_in<K: Ord>(
    peers: &[Option<PeerState>],
    map: &mut BTreeMap<K, Destination>,
    key: K,
    family: AddressFamily,
    prefix: Prefix,
    id: PeerId,
    scratch: &mut Scratch,
) {
    let Slot::Occupied(mut slot) = map.entry(key) else {
        return;
    };
    let dest = slot.get_mut();
    let Some(i) = dest.position(id) else {
        return;
    };
    let old = dest.best().cloned();
    scratch.released.push(dest.remove(i).attrs);
    decide(peers, dest);
    let new = dest.best().cloned();
    if dest.is_empty() {
        slot.remove();
    }
    *scratch.delta.or_default(family) -= 1;
    scratch.dirty.push(Dirty {
        family,
        prefix,
        old,
        new,
        merged: false,
    });
}

/// Add or replace `route`'s peer's route to `prefix` and note the
/// destination's best route before and after.
fn announce(
    peers: &[Option<PeerState>],
    table: &mut Table,
    family: AddressFamily,
    prefix: Prefix,
    route: Route,
    scratch: &mut Scratch,
) {
    match Ipv4Key::new(prefix) {
        Some(k) => announce_in(peers, &mut table.v4, k, family, prefix, route, scratch),
        None => announce_in(peers, &mut table.v6, prefix, family, prefix, route, scratch),
    }
}

fn announce_in<K: Ord>(
    peers: &[Option<PeerState>],
    map: &mut BTreeMap<K, Destination>,
    key: K,
    family: AddressFamily,
    prefix: Prefix,
    route: Route,
    scratch: &mut Scratch,
) {
    let (old, new) = match map.entry(key) {
        Slot::Vacant(slot) => {
            // A new destination: its one route is the best.
            let new = route.clone();
            slot.insert(Destination::One(route));
            *scratch.delta.or_default(family) += 1;
            (None, new)
        }
        Slot::Occupied(mut slot) => {
            let dest = slot.get_mut();
            let old = dest.best().cloned();
            if let Some(i) = dest.position(route.peer) {
                if Arc::ptr_eq(&dest.routes()[i].attrs, &route.attrs) {
                    // An implicit re-announcement of the same route.
                    return;
                }
                let replaced = std::mem::replace(&mut dest.routes_mut()[i], route);
                scratch.released.push(replaced.attrs);
            } else {
                dest.push(route);
                *scratch.delta.or_default(family) += 1;
            }
            decide(peers, dest);
            // invariant: the destination has the route just added.
            (old, dest.best().unwrap().clone())
        }
    };
    scratch.dirty.push(Dirty {
        family,
        prefix,
        old,
        new: Some(new),
        merged: false,
    });
}

/// Merge the entries for a destination an UPDATE touched twice into the
/// first: the best route before the first change and after the last.
/// Only a withdrawal and then an announcement of the same prefix touch a
/// destination twice (a prefix in both the withdrawn routes and the NLRI,
/// say): withdrawing again finds no route, and announcing again the same
/// interned route changes nothing. So the entries of the first
/// `withdrawn` are sorted and each later one looked up among them, which
/// costs nothing for an UPDATE that only announces or only withdraws.
fn merge_repeats(dirty: &mut [Dirty], withdrawn: usize, order: &mut Vec<u32>) {
    if withdrawn == 0 || withdrawn == dirty.len() {
        return;
    }
    let key = |d: &Dirty| (d.family, d.prefix);
    order.clear();
    // invariant: one UPDATE has fewer than 2^32 prefixes.
    order.extend(0..u32::try_from(withdrawn).unwrap());
    order.sort_unstable_by_key(|&i| key(&dirty[i as usize]));
    for j in withdrawn..dirty.len() {
        let found = order.binary_search_by_key(&key(&dirty[j]), |&i| key(&dirty[i as usize]));
        if let Ok(k) = found {
            let first = order[k] as usize;
            dirty[first].new = dirty[j].new.take();
            dirty[j].merged = true;
        }
    }
}
