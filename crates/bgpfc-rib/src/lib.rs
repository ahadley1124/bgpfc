//! Adj-RIB-In, Loc-RIB, Adj-RIB-Out and the decision process
//! (AGENTS.md §3, "RIB thread": the only owner of all RIB state, driven
//! by messages, no I/O).
//!
//! Implements: RFC 4271 §3.2 (the three RIBs; the Adj-RIBs-In hold the
//! routes import policy accepts, as received, and those it rejects for
//! their validation state alone), §9.1 (the decision
//! process: Phase 1 degree of preference, Phase 2 route selection,
//! Phase 3 route dissemination), §9.1.2 (AS loop exclusion), §9.1.4
//! (overlapping routes are independent destinations), §9.2 (update
//! generation), §9.2.1.1 (`MinRouteAdvertisementIntervalTimer`, see
//! [`pacing`]), §9.3 (Loc-RIB changes are reported for the FIB), §6.3
//! and RFC 7606 §7.2 (leftmost AS of an external route is the peer's),
//! §6.3 a) (a route whose next hop is our own address is ignored, see
//! [`Output::InvalidNextHop`]);
//! RFC 4760 §3, §5, §7, §8 (each NLRI field with its own next hop,
//! per-family RIBs, family disable, routes taken of the families we
//! advertised and sent of the negotiated ones); RFC 2918 §4 (route refresh
//! re-sends the Adj-RIB-Out); RFC 8950 §3–§5 (IPv4 routes with an IPv6
//! next hop, see [`export`]); RFC 4271 §6.7 (a per-family prefix limit
//! that ends the session, see [`Output::PrefixLimitExceeded`]);
//! RFC 7911 §2, §3, §5 (the Adj-RIB-In keeps each path a peer sends under
//! its Path Identifier and every one takes part in the decision process;
//! a peer that takes several paths is sent the `n` best or all of them,
//! each with an identifier of ours, see the private `addpath` module);
//! RFC 6811 §2 (every route received gets its validation state from a
//! lookup, kept as a property of the route; the state never keeps a
//! route out of the Adj-RIB-In: one import policy rejects for its state
//! alone is kept), §3 (policy sees the validation state and may set it,
//! see [`Policies`] and [`Verdict`]), §4 (the affected routes are
//! validated again when the validation source changes, see
//! [`Rib::validation_changed`]);
//! RFC 9234 §5 (the Only to Customer procedures of a session with a BGP
//! Role: a route leak is not kept, see [`Output::RouteLeak`], and the
//! attribute is added and checked on the way out, see [`otc`] and
//! [`export`]).
//!
//! Time is injected: every call that can send takes `now`, and
//! [`Rib::next_deadline`] and [`Rib::flush`] let the owner release held
//! advertisements when their interval ends.
//!
//! With the `profiling` feature, the work per route is timed into
//! `bgpfc-prof` histograms and the `profiling` module reports the RIB's
//! size and how much its attributes repeat (`docs/PROFILING.md`).
#![forbid(unsafe_code)]

mod addpath;
pub mod attrs;
pub mod decision;
pub mod export;
pub mod otc;
pub mod pacing;
pub mod peer;
#[cfg(feature = "profiling")]
pub mod profiling;
mod store;
#[cfg(test)]
mod tests;
mod validation;

use std::cmp::Reverse;
use std::collections::btree_map::Entry as Slot;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_rpki::{InvalidAction, NullSource, ValidationSource};
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::{Ipv4Key, Prefix};
use bgpfc_wire::types::{AddressFamily, Asn, PathId};
use bgpfc_wire::update::{DecodedUpdate, PeerKind};

pub use attrs::{Interner, PathAttrs};
pub use bgpfc_rpki::{AspaState, RouteOrigin, RovState};
pub use decision::{Candidate, Neighbor};
pub use export::{Batch, Source};
pub use peer::{PathLimit, PeerInfo};
pub use validation::{Enforcement, Revalidation};

use addpath::{Sent, Sync};
use pacing::{Clock, Held, Jitter, Now, Offer, Pace, Pacing, Tick};
use store::{Destination, FamilyMap, Member, PeerId, Route, Table};

/// What a policy decided about a route.
///
/// RFC 6811 §3 asks that policy can "match and set the validation state of
/// routes". Matching needs only the state a policy is told; setting is
/// what [`Verdict::Restated`] and [`Verdict::ModifiedRestated`] carry back
/// to the RIB, which then holds the route with that state, as its
/// validation state, in place of the one the lookup gave. A state is
/// local to the speaker (RFC 6811 §2: "a local property or attribute of
/// the Route"), so it only means something on import; export policy may
/// set it for the terms that follow in its own run, and the RIB ignores
/// what an export verdict restates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Keep the route with its attributes as they are.
    Accept,
    /// Keep the route with these attributes instead.
    Modified(PathAttrs),
    /// Keep the route with its attributes as they are, and this
    /// validation state in place of the one it was given (RFC 6811 §3).
    Restated(RovState),
    /// Keep the route with these attributes and this validation state.
    ModifiedRestated(PathAttrs, RovState),
    /// Drop the route.
    Reject,
}

impl Verdict {
    /// The validation state this verdict gives the route, if it sets one.
    #[must_use]
    pub fn rov(&self) -> Option<RovState> {
        match self {
            Verdict::Restated(rov) | Verdict::ModifiedRestated(_, rov) => Some(*rov),
            Verdict::Accept | Verdict::Modified(_) | Verdict::Reject => None,
        }
    }
}

/// Import and export policy as the RIB sees it (RFC 4271 §9.1.1 local
/// policy, §9.1.3 export policy). `peer` is the peer the route came from
/// on import and the peer it is going to on export. `rov` is the route's
/// validation state: on import the one the lookup gave it, on export the
/// one it holds, which import policy may have set. Policy must be able to
/// match and set it (RFC 6811 §3, see [`Verdict`]).
pub trait Policies: Send {
    /// Decide whether and how a route held in the Adj-RIB-In becomes a
    /// candidate for the decision process.
    fn import(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        attrs: &PathAttrs,
        rov: RovState,
    ) -> Verdict;

    /// Decide whether and how a Loc-RIB route is advertised to `peer`,
    /// before the RFC 4271 §5.1 rewriting for the session.
    fn export(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        attrs: &PathAttrs,
        rov: RovState,
    ) -> Verdict;
}

/// The policy that accepts every route unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcceptAll;

impl Policies for AcceptAll {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        Verdict::Accept
    }

    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
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
    /// The peer has more routes of `family` than its prefix limit allows
    /// (RFC 4271 §6.7). The RIB has already dropped every route the peer
    /// sent and forgotten the peer, so nothing it sends from now on is
    /// used; the caller ends the session with a Cease / Maximum Number of
    /// Prefixes Reached carrying `family` and `limit` (RFC 4486 §4).
    PrefixLimitExceeded {
        /// The peer.
        peer: IpAddr,
        /// The family over its limit.
        family: AddressFamily,
        /// The limit.
        limit: u32,
    },
    /// Routes ignored because their next hop is semantically incorrect
    /// (RFC 4271 §6.3): our own address on the session. The caller logs
    /// them; no NOTIFICATION is sent and the session stays up.
    InvalidNextHop {
        /// The peer that sent them.
        peer: IpAddr,
        /// Their family.
        family: AddressFamily,
        /// The next hop they came with.
        next_hop: NextHop,
        /// The routes.
        prefixes: Vec<Prefix>,
    },
    /// Routes ignored because they are route leaks by RFC 9234 §5: they
    /// came with the Only to Customer attribute from a customer or an
    /// RS-Client, or from a peer with another AS in it. Such a route "MUST
    /// be considered ineligible", so it is not kept and one the peer sent
    /// before for the prefix is withdrawn. The caller logs it; no
    /// NOTIFICATION is sent and the session stays up.
    RouteLeak {
        /// The peer that sent them.
        peer: IpAddr,
        /// Their family.
        family: AddressFamily,
        /// The AS in the attribute.
        otc: Asn,
        /// How many routes of the UPDATE were leaks.
        routes: usize,
        /// The first of them.
        first: Prefix,
    },
    /// Routes in the Adj-RIBs-In changed RFC 6811 validation state with
    /// the validation source (see [`Rib::validation_changed`]): one report
    /// per change of the source, counted rather than listed, however many
    /// routes it moved. The caller logs it. The state a route gets on
    /// arrival is its first, not a change, and is not reported.
    Revalidated(Revalidation),
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

/// A route the RIB holds: the peer it came from, its attributes as import
/// policy gave them, and its validation verdicts.
#[derive(Clone, Copy, Debug)]
pub struct RouteRef<'a> {
    /// The peer it came from.
    pub peer: IpAddr,
    /// Its attributes.
    pub attrs: &'a Arc<PathAttrs>,
    /// Its RFC 6811 §2 validation state: the lookup's, unless import
    /// policy set another (RFC 6811 §3).
    pub rov: RovState,
    /// Its ASPA verdict (a placeholder until ASPA lands).
    pub aspa: AspaState,
    /// The Path Identifier its peer sent it with (RFC 7911 §3): `Some` for
    /// a route of a family the peer sends with them, zero included.
    pub path_id: Option<PathId>,
}

struct PeerState {
    info: PeerInfo,
    /// What Phase 2 compares about the peer, for every route it sent.
    neighbor: Neighbor,
    /// Families disabled after an incorrect multiprotocol attribute
    /// (RFC 4760 §7); no more routes are accepted for them this session.
    disabled: Vec<AddressFamily>,
    /// Routes in the Adj-RIB-Out per family. The Adj-RIB-Out itself is
    /// not stored (RFC 4271 §3.2 asks for the information, not a table):
    /// what the peer was last told about a destination is what export
    /// makes of its best route, since every change of that best route is
    /// sent as it happens, a policy change is compared under both
    /// policies ([`Rib::set_policies`]), and pacing keeps what the peer
    /// has for the destinations it holds back ([`pacing`]). A copy per
    /// peer would cost tens of megabytes for each full table sent.
    advertised: FamilyMap<usize>,
    /// Routes of each family in the Adj-RIB-In: what
    /// [`PeerStats::received`] reports and the RFC 4271 §6.7 limit counts.
    adj_in_count: FamilyMap<usize>,
    /// The RFC 4271 §9.2.1.1 pacing state per family.
    pacing: FamilyMap<Pacing>,
    /// What the peer has been sent of each prefix, for the families it is
    /// sent several paths of (RFC 7911 §5); empty for any other.
    sent: FamilyMap<Sent>,
    /// The session is going down: its routes are being removed, and it is
    /// sent nothing more.
    leaving: bool,
}

impl PeerState {
    /// Routes of `family` in the Adj-RIB-In.
    fn received(&self, family: AddressFamily) -> usize {
        self.adj_in_count.get(family).copied().unwrap_or(0)
    }

    /// [`received`](Self::received) with the routes added minus those
    /// removed by an UPDATE being applied, `delta`, not yet counted.
    fn received_with(&self, family: AddressFamily, delta: &FamilyMap<isize>) -> usize {
        self.received(family)
            .saturating_add_signed(delta.get(family).copied().unwrap_or(0))
    }
}

/// Counters about one peer, for the control plane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Routes accepted from the peer, per family it may send, with those
    /// import policy rejects for their validation state alone, which the
    /// Adj-RIB-In holds too (RFC 6811 §2): what the RFC 4271 §6.7 limit
    /// counts.
    pub received: Vec<(AddressFamily, usize)>,
    /// Routes advertised to the peer, per negotiated family.
    pub advertised: Vec<(AddressFamily, usize)>,
}

/// A wake-up for one destination of one peer (RFC 4271 §9.2.1.1): a held
/// advertisement may go out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Deadline {
    at: Tick,
    peer: PeerId,
    family: AddressFamily,
    prefix: Prefix,
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
    /// How many peers that are up are sent several paths of some family
    /// (RFC 7911 §5), so that a change to a destination looks for them
    /// only if there are any.
    path_senders: usize,
    /// Pending wake-ups, earliest first. Each `Pacing` knows the one live
    /// entry per destination; an entry an earlier one replaced stays
    /// until due and is then ignored, and those of a peer that went down
    /// are removed with it.
    deadlines: BinaryHeap<Reverse<Deadline>>,
    /// Pending sweeps of a peer's pacing for a family, earliest first,
    /// one live entry each likewise.
    sweeps: BinaryHeap<Reverse<(Tick, PeerId, AddressFamily)>>,
    /// Pacing time, counted from the first instant the RIB was given.
    clock: Option<Clock>,
    /// The time of the input being handled ([`Sessions::tick`]).
    at: Now,
    /// RFC 4271 §10 jitter for the pacing intervals.
    jitter: Jitter,
}

/// What import and export apply to a route.
struct Context {
    local_as: Asn,
    policies: Box<dyn Policies>,
    interner: Interner,
    /// Where validation states come from (issue #56): [`NullSource`],
    /// every route `Disabled`, until [`Rib::validation_changed`] says
    /// otherwise.
    validation: Arc<dyn ValidationSource>,
    /// What the RIB does with Invalid routes by itself, apart from policy
    /// ([`Rib::set_invalid_action`]).
    invalid: InvalidAction,
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

/// A destination an input changed: its best route before the first
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
    /// The parts of the UPDATE ignored for their next hop (RFC 4271
    /// §6.3) or as route leaks (RFC 9234 §5), reported before what the
    /// UPDATE changed.
    ignored: Vec<Output>,
    batches: Batches,
}

impl Scratch {
    /// Entries a buffer keeps room for between inputs: more than the
    /// largest UPDATE needs (a 65535-octet message holds about 16 000
    /// IPv4 prefixes), far fewer than an input that touches a whole
    /// table, such as a change of validation source, whose room would
    /// otherwise stay allocated (about 80 octets a destination).
    const KEEP: usize = 1 << 14;

    /// Give back the room an unusually large input left.
    fn trim(&mut self) {
        fn trim<T>(v: &mut Vec<T>) {
            if v.capacity() > Scratch::KEEP {
                v.shrink_to(Scratch::KEEP);
            }
        }
        trim(&mut self.dirty);
        trim(&mut self.order);
        trim(&mut self.released);
    }
}

impl Rib {
    /// An empty RIB for a speaker in `local_as` that accepts every route.
    #[must_use]
    pub fn new(local_as: Asn) -> Rib {
        Rib::with_policies(local_as, Box::new(AcceptAll))
    }

    /// An empty RIB for a speaker in `local_as` with the given policies.
    /// Validation is off ([`NullSource`]: every route `Disabled`) until
    /// [`Rib::validation_changed`] gives it a source.
    #[must_use]
    pub fn with_policies(local_as: Asn, policies: Box<dyn Policies>) -> Rib {
        Rib {
            tables: FamilyMap::default(),
            s: Sessions {
                cx: Context {
                    local_as,
                    policies,
                    interner: Interner::default(),
                    validation: Arc::new(NullSource),
                    invalid: InvalidAction::Policy,
                },
                peers: Vec::new(),
                by_addr: HashMap::new(),
                path_senders: 0,
                deadlines: BinaryHeap::new(),
                sweeps: BinaryHeap::new(),
                clock: None,
                at: Now::default(),
                jitter: Jitter::new(0),
            },
            scratch: Scratch::default(),
        }
    }

    /// Seed the RFC 4271 §10 jitter of the advertisement intervals; zero,
    /// the default, applies none.
    pub fn set_jitter_seed(&mut self, seed: u64) {
        self.s.jitter = Jitter::new(seed);
    }

    /// Replace the policies, and send the peers in `reexport` (those
    /// whose export policy changed) what that changes: announcements for
    /// routes new or changed, withdrawals for routes no longer exported,
    /// found by exporting every best route under the old policies and the
    /// new, paced like any other change (RFC 4271 §9.2.1.1). Import
    /// changes are the caller's to re-evaluate (route refresh).
    pub fn set_policies(
        &mut self,
        policies: Box<dyn Policies>,
        reexport: &[IpAddr],
        now: Instant,
        out: &mut impl Sink,
    ) {
        let old = std::mem::replace(&mut self.s.cx.policies, policies);
        for addr in reexport {
            let Some(id) = self.s.id(*addr) else {
                continue;
            };
            let families = self.s.peer(id).info.families.clone();
            for family in families {
                self.reexport(&*old, id, family, now, out);
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
    /// Adj-RIB-Out). These first advertisements are not held back.
    pub fn peer_up(&mut self, info: PeerInfo, now: Instant, out: &mut impl Sink) {
        let addr = info.addr;
        let families = info.families.clone();
        self.s.add(PeerState {
            neighbor: Neighbor::of(&info),
            info,
            disabled: Vec::new(),
            advertised: FamilyMap::default(),
            adj_in_count: FamilyMap::default(),
            pacing: FamilyMap::default(),
            sent: FamilyMap::default(),
            leaving: false,
        });
        for family in families {
            self.refresh(addr, family, now, out);
        }
    }

    /// The session left Established: forget the peer and its routes.
    /// Every family's table is searched, not only the negotiated ones: the
    /// peer may have sent routes of any family we advertised (RFC 4760
    /// §8), and none may outlive the session.
    pub fn peer_down(&mut self, addr: IpAddr, now: Instant, out: &mut impl Sink) {
        #[cfg(feature = "profiling")]
        let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_PEER_DOWN);
        let Some(id) = self.s.id(addr) else {
            return;
        };
        self.s.tick(now);
        // Kept while its routes go, which export needs to tell apart.
        self.s.peer_mut(id).leaving = true;
        let mut batches = Batches::default();
        // Every table: the slot is free for another peer once this
        // returns, so no route may still name it.
        for (family, table) in self.tables.iter_mut() {
            table.retain(|prefix, dest| {
                self.s
                    .remove_route(family, prefix, dest, id, &mut batches, out)
            });
        }
        self.s.emit(&mut batches, out);
        self.s.remove(addr);
    }

    /// Change the prefix limits of peer `addr` (RFC 4271 §6.7), as a reload
    /// does. A family already over its new limit is handled as if the
    /// limit had just been exceeded.
    pub fn set_prefix_limits(
        &mut self,
        addr: IpAddr,
        limits: Vec<(AddressFamily, u32)>,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        let state = self.s.peer_mut(id);
        state.info.prefix_limits = limits;
        let over = state
            .info
            .prefix_limits
            .iter()
            .copied()
            .find(|(f, l)| state.received(*f) > *l as usize);
        if let Some((family, limit)) = over {
            let mut scratch = std::mem::take(&mut self.scratch);
            self.prefix_limit_exceeded(id, family, limit, &mut scratch, now, out);
            self.scratch = scratch;
        }
    }

    /// RFC 4271 §6.7 (b): the speaker "terminates the BGP connection with
    /// the neighbor". The routes the peer sent go at once, those of the
    /// UPDATE that crossed the limit included (in `scratch`), so none of
    /// them is passed on; the caller sends the Cease (RFC 4486 §4).
    fn prefix_limit_exceeded(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        limit: u32,
        scratch: &mut Scratch,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let addr = self.s.peer(id).info.addr;
        self.s.peer_mut(id).leaving = true;
        for (f, table) in self.tables.iter_mut() {
            drop_routes(self.s.phase2(), table, f, id, scratch);
        }
        // The peer goes with its counts: what the removals added up to
        // must not carry over to the next UPDATE's peer.
        for (_, d) in scratch.delta.iter_mut() {
            *d = 0;
        }
        out.put(Output::PrefixLimitExceeded {
            peer: addr,
            family,
            limit,
        });
        merge_all(&mut scratch.dirty, &mut scratch.order);
        self.finish(scratch, now, out);
        self.s.remove(addr);
        for o in scratch.ignored.drain(..) {
            out.put(o);
        }
    }

    /// The peer asked for `family` again (RFC 2918 §4): resend the
    /// Adj-RIB-Out in full, held destinations as they are now. Also used
    /// to build the initial one. Every destination's interval restarts.
    pub fn refresh(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        if !self.s.peer(id).info.speaks(family) {
            return;
        }
        let now = self.s.tick(now);
        let mut batch = Batch::default();
        if self.s.peer(id).info.path_limit(family).is_some() {
            // RFC 7911 §5 with RFC 2918 §4: every path again, under the
            // identifiers it has, and those it should not have withdrawn.
            let held = self
                .s
                .peer_mut(id)
                .pacing
                .or_default(family)
                .readvertise(now);
            debug_assert!(held.iter().all(|(_, h)| h.has.is_none()));
            if let Some(table) = self.tables.get(family) {
                for (prefix, dest) in table.iter() {
                    self.s
                        .sync_paths(id, family, prefix, Some(dest), Sync::Full, &mut batch);
                }
            }
            self.s.send(id, family, batch, out);
            return;
        }
        let held = self
            .s
            .peer_mut(id)
            .pacing
            .or_default(family)
            .readvertise(now);
        let table = self.tables.get(family);
        // What the peer has of a destination held back and no longer
        // exported goes: the refresh carries the routes there are now.
        for (prefix, h) in held {
            if let Some(has) = h.has {
                let best = table
                    .and_then(|t| t.get(prefix))
                    .and_then(Destination::best);
                if self.s.exported(None, family, prefix, best, id).is_none() {
                    batch.withdraw.push(prefix);
                }
                self.s.cx.interner.release(has);
            }
        }
        let mut n = 0;
        if let Some(table) = table {
            for (prefix, dest) in table.iter() {
                let a = self.s.exported(None, family, prefix, dest.best(), id);
                n += usize::from(a.is_some());
                self.s.compare(id, family, prefix, None, a, &mut batch);
            }
        }
        let state = self.s.peer_mut(id);
        state.advertised.insert(family, n);
        state.pacing.or_default(family).note_routes(n);
        self.s.send(id, family, batch, out);
    }

    /// After a change of export policy from `old`: what differs for `id`
    /// in `family` between exporting every best route under `old` and
    /// under the current policies, paced like any other change.
    fn reexport(
        &mut self,
        old: &dyn Policies,
        id: PeerId,
        family: AddressFamily,
        now: Instant,
        out: &mut impl Sink,
    ) {
        if !self.s.peer(id).info.speaks(family) {
            return;
        }
        self.s.tick(now);
        let mut batch = Batch::default();
        if self.s.peer(id).info.path_limit(family).is_some() {
            // What the peer has been sent is kept, so the new policies are
            // compared with that, not with the old policies.
            self.resync_paths(id, family, out);
            return;
        }
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table.iter() {
                let before = self.s.exported(Some(old), family, prefix, dest.best(), id);
                let after = self.s.exported(None, family, prefix, dest.best(), id);
                self.s.offer(id, family, prefix, before, after, &mut batch);
            }
        }
        self.s.send(id, family, batch, out);
    }

    /// Bring the paths peer `id` has of `family` up to date with the
    /// Loc-RIB, every destination, paced like any other change (RFC 7911
    /// §5, RFC 4271 §9.2.1.1).
    fn resync_paths(&mut self, id: PeerId, family: AddressFamily, out: &mut impl Sink) {
        let mut batch = Batch::default();
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table.iter() {
                self.s
                    .sync_paths(id, family, prefix, Some(dest), Sync::Change, &mut batch);
            }
        }
        self.s.send(id, family, batch, out);
    }

    /// Change how many paths of a prefix peer `addr` is sent, per family
    /// (RFC 7911 §5), as a reload does: what the change adds is announced
    /// and what it takes away withdrawn. Only the number can change on a
    /// running session; the families were negotiated in the OPEN, so a
    /// family not sent paths of already is left alone.
    pub fn set_add_path_limits(
        &mut self,
        addr: IpAddr,
        limits: &[(AddressFamily, PathLimit)],
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        let mut changed = Vec::new();
        for (family, current) in &mut self.s.peer_mut(id).info.add_path_send {
            if let Some((_, new)) = limits.iter().find(|(f, _)| f == family)
                && new != current
            {
                *current = *new;
                changed.push(*family);
            }
        }
        self.s.tick(now);
        for family in changed {
            self.resync_paths(id, family, out);
        }
    }

    /// Change the `MinRouteAdvertisementIntervalTimer` of peer `addr`
    /// (RFC 4271 §9.2.1.1). Held destinations move to the new end of
    /// their interval, and go out now if that has passed.
    pub fn set_advertisement_interval(
        &mut self,
        addr: IpAddr,
        interval: Duration,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        let pace_now = self.s.tick(now);
        let Sessions {
            peers,
            deadlines,
            jitter,
            ..
        } = &mut self.s;
        let Some(state) = peers[id.index()].as_mut() else {
            return;
        };
        if state.info.advertisement_interval == interval {
            return;
        }
        state.info.advertisement_interval = interval;
        let mut pace = Pace {
            interval,
            now: pace_now,
            jitter,
        };
        for (family, pacing) in state.pacing.iter_mut() {
            for (prefix, at) in pacing.reschedule(&mut pace) {
                if pacing.queue(prefix, at) {
                    deadlines.push(Reverse(Deadline {
                        at,
                        peer: id,
                        family,
                        prefix,
                    }));
                }
            }
        }
        self.flush(now, out);
    }

    /// When [`Rib::flush`] next has something to do, if ever: the owner
    /// calls it then. Stale wake-ups make this early at worst, never late.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        let clock = self.s.clock?;
        let release = self.s.deadlines.peek().map(|Reverse(d)| d.at);
        let sweep = self.s.sweeps.peek().map(|Reverse((at, ..))| *at);
        clock.instant(release.into_iter().chain(sweep).min()?)
    }

    /// Send what the interval held back and may go out by `now`: for each
    /// such destination, the route it has now, if that differs from what
    /// the peer has (RFC 4271 §9.2.1.1). Every Loc-RIB change, whatever
    /// caused it, is offered to each peer's pacing; what it holds back
    /// comes out here.
    pub fn flush(&mut self, now: Instant, out: &mut impl Sink) {
        if self.s.clock.is_none() {
            return;
        }
        let now = self.s.tick(now);
        self.release_due(now, out);
        // After the releases, so that a second they open and close is
        // sorted at once.
        self.s.sweep(now);
    }

    /// Send what the interval held back and may go out by `now`.
    fn release_due(&mut self, now: Now, out: &mut impl Sink) {
        let mut due = Vec::new();
        while let Some(Reverse(d)) = self.s.deadlines.peek()
            && d.at <= now.floor
        {
            due.push(*d);
            self.s.deadlines.pop();
        }
        if due.is_empty() {
            return;
        }
        shrink_heap(&mut self.s.deadlines);
        // One batch per peer and family, so that what is released together
        // is packed together (RFC 4271 §9.2).
        due.sort_unstable_by_key(|d| (d.peer.0, d.family, d.prefix, d.at));
        for group in due.chunk_by(|a, b| a.peer == b.peer && a.family == b.family) {
            let (id, family) = (group[0].peer, group[0].family);
            if self.s.peers.get(id.index()).is_none_or(Option::is_none) {
                continue;
            }
            let mut batch = Batch::default();
            let paths = self.s.peer(id).info.path_limit(family).is_some();
            for d in group {
                let Some(held) = self.s.wake(id, family, d.prefix, d.at) else {
                    continue;
                };
                if paths {
                    // RFC 7911 §5: the paths the destination has now.
                    let dest = self.tables.get(family).and_then(|t| t.get(d.prefix));
                    self.s
                        .sync_paths(id, family, d.prefix, dest, Sync::Release, &mut batch);
                    continue;
                }
                let best = self
                    .tables
                    .get(family)
                    .and_then(|t| t.get(d.prefix))
                    .and_then(Destination::best);
                let after = self.s.exported(None, family, d.prefix, best, id);
                self.s
                    .release(id, family, d.prefix, held, after, &mut batch);
            }
            if let Some(pacing) = self.s.peer_mut(id).pacing.get_mut(family) {
                pacing.compact();
            }
            self.s.send(id, family, batch, out);
        }
    }

    /// What the RIB knows about peer `addr`, if it is up.
    #[must_use]
    pub fn peer(&self, addr: IpAddr) -> Option<&PeerInfo> {
        self.s.id(addr).map(|id| &self.s.peer(id).info)
    }

    /// An UPDATE from `addr`: disable the families its incorrect MP
    /// attributes named (RFC 4760 §7), apply its withdrawals and
    /// announcements to the Adj-RIB-In, rerun the decision process for the
    /// destinations touched, and produce the FIB changes and UPDATEs that
    /// follow, after an [`Output::InvalidNextHop`] for each part of the
    /// UPDATE whose routes were ignored. Routes of a family we did not
    /// advertise to the peer are ignored (RFC 4760 §8).
    pub fn update(
        &mut self,
        addr: IpAddr,
        update: &DecodedUpdate,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(id) = self.s.id(addr) else {
            return;
        };
        let mut scratch = std::mem::take(&mut self.scratch);
        if let Some((family, limit)) = self.apply(id, update, &mut scratch) {
            self.prefix_limit_exceeded(id, family, limit, &mut scratch, now, out);
        } else {
            for o in scratch.ignored.drain(..) {
                out.put(o);
            }
            if update.message.path_ids.is_some() {
                // RFC 7911 §3: several paths of one prefix may be in one
                // UPDATE, and so a destination may change more than twice.
                merge_all(&mut scratch.dirty, &mut scratch.order);
            } else {
                merge_repeats(&mut scratch.dirty, scratch.withdrawn, &mut scratch.order);
            }
            self.finish(&mut scratch, now, out);
        }
        self.scratch = scratch;
    }

    /// Apply an UPDATE's family disables, withdrawals, then
    /// announcements, to the Adj-RIB-In, and run Phase 2 for each
    /// destination as it changes. The family and limit of an RFC 4271
    /// §6.7 prefix limit the UPDATE took the peer past, if it did: the rest
    /// of it is not applied.
    fn apply(
        &mut self,
        id: PeerId,
        update: &DecodedUpdate,
        scratch: &mut Scratch,
    ) -> Option<(AddressFamily, u32)> {
        // RFC 4760 §7, before anything else in the UPDATE, so that none of
        // the disabled family's routes in it counts either (RFC 7606 §3 h:
        // the strongest approach wins).
        for d in &update.disabled {
            self.disable_family(id, d.family, scratch);
        }
        let Sessions { cx, peers, .. } = &mut self.s;
        let p2 = Phase2::new(peers, cx.invalid);
        // invariant: ids are only handed out for occupied slots.
        let state = peers[id.index()].as_ref().unwrap();
        let info = &state.info;
        // RFC 4760 §8 needs both sides to advertise a family only for a
        // bi-directional exchange: our capability is what lets the peer
        // send routes of one (RFC 5492 §3), so those of every family we
        // advertised are taken, negotiated or not. Routes of a family we
        // did not advertise are ignored, as are those of a family disabled
        // by RFC 4760 §7.
        let unused =
            |family: AddressFamily| state.disabled.contains(&family) || !info.receives(family);
        // RFC 7911 §5: a withdrawal names a path by its prefix and
        // identifier (zero where the family has none); "If a BGP speaker
        // receives a message to withdraw a prefix with a Path Identifier
        // not seen before, it SHOULD silently ignore it", which finding no
        // such route does.
        for (family, prefix, path) in update.withdrawn_paths() {
            #[cfg(feature = "profiling")]
            let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_REMOVE);
            if unused(family) {
                continue;
            }
            if let Some(table) = self.tables.get_mut(family) {
                withdraw(p2, table, family, prefix, (id, path.0), scratch);
            }
        }
        scratch.withdrawn = scratch.dirty.len();
        let mut exceeded = None;
        'parts: for (family, next_hop, prefixes, path_ids) in attrs::announced(update) {
            if unused(family) {
                continue;
            }
            // RFC 4271 §6.3 a): a next hop that is the receiving speaker's
            // own address is semantically incorrect, and RFC 4760 §3 holds
            // MP_REACH_NLRI next hops to the same rule. "The error SHOULD
            // be logged, and the route SHOULD be ignored", with no
            // NOTIFICATION: the caller logs the output. Ignored, so not
            // kept in the Adj-RIB-In, and one the peer sent before for the
            // prefix goes too; the new announcement replaced it, and
            // keeping it would keep what the peer no longer advertises
            // (RFC 7606 §6 on discarding UPDATEs).
            if info.is_own_address(&next_hop) {
                if let Some(table) = self.tables.get_mut(family) {
                    withdraw_all(p2, table, family, (prefixes, path_ids), id, scratch);
                }
                scratch.ignored.push(Output::InvalidNextHop {
                    peer: info.addr,
                    family,
                    next_hop,
                    prefixes: prefixes.to_vec(),
                });
                continue;
            }
            let mut built = PathAttrs::from_update(&update.message, next_hop);
            // RFC 9234 §5 ingress, once for this part of the UPDATE. A
            // leak is not kept, as for the checks below: no import policy
            // may make it eligible ("The operator MUST NOT have the
            // ability to modify the procedures").
            if let Err(otc) = otc::receive(info, &mut built) {
                if let Some(table) = self.tables.get_mut(family) {
                    withdraw_all(p2, table, family, (prefixes, path_ids), id, scratch);
                }
                report_leak(scratch, info, family, otc, prefixes);
                continue;
            }
            let attrs = cx.interner.intern(built);
            // RFC 4271 §9.1.2: a route whose AS_PATH contains our AS is an
            // AS loop and is excluded from Phase 2. RFC 4271 §6.3 and RFC
            // 7606 §7.2: on an external session the leftmost AS must be the
            // peer's, else the route is treated as withdrawn. Neither kind
            // is kept in the Adj-RIB-In: no import policy can make it
            // usable, and our AS is fixed for the life of the RIB.
            let leftmost_ok = info.kind == PeerKind::Internal
                || attrs.as_path.first_asn() == Some(info.remote_as);
            if attrs.as_path.contains(cx.local_as) || !leftmost_ok {
                if let Some(table) = self.tables.get_mut(family) {
                    withdraw_all(p2, table, family, (prefixes, path_ids), id, scratch);
                }
                scratch.released.push(attrs);
                continue;
            }
            // RFC 6811 §2: "When a BGP speaker receives an UPDATE from a
            // neighbor, it SHOULD perform a lookup as described above for
            // each of the Routes in the UPDATE message", and "The
            // validation state of the Route MUST be set to reflect the
            // result of the lookup." The origin is that of the AS_PATH as
            // received, which the decoder has already merged with AS4_PATH
            // (RFC 6793 §4.2.3), so that a two-octet peer's route does not
            // seem to come from AS_TRANS. Every route of this part of the
            // UPDATE has the same path, and so the same origin.
            let origin = RouteOrigin::from_as_path(&attrs.as_path, cx.local_as);
            let aspa = cx.validation.aspa(&attrs.as_path);
            let limit = info.prefix_limit(family);
            let drop_invalid = cx.invalid.drops();
            for (k, &prefix) in prefixes.iter().enumerate() {
                #[cfg(feature = "profiling")]
                let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_INSERT);
                // RFC 7911 §5: the route is the prefix with its Path
                // Identifier; a newer one for both replaces the older.
                let path = path_at(path_ids, k);
                let lookup = cx.validation.rov(prefix, origin);
                let judged = judge(
                    &*cx.policies,
                    &mut cx.interner,
                    info,
                    (family, prefix),
                    &attrs,
                    (lookup, drop_invalid),
                );
                match judged.into_route(&attrs, id, lookup, aspa) {
                    Some(route) => {
                        let table = self.tables.or_default(family);
                        announce(p2, table, family, prefix, route, path, scratch);
                    }
                    // Not kept, and one the peer sent before for the prefix
                    // goes too: the new announcement replaced it.
                    None => {
                        if let Some(table) = self.tables.get_mut(family) {
                            withdraw(p2, table, family, prefix, (id, path), scratch);
                        }
                    }
                }
                // RFC 4271 §6.7: "the number of address prefixes received
                // from the neighbor exceeds the locally-configured, upper
                // bound". Counted are the routes the Adj-RIB-In holds after
                // the loop checks and import policy, the ones "the speaker
                // is willing to accept" (§6.7): a route import policy
                // rejects is not kept, so counting it would take the
                // memory the limit is there to bound. One rejected for its
                // validation state alone is kept (RFC 6811 §2, see
                // `judge`) and counted; whether a route is kept does not
                // depend on its state, so a change of validation state
                // never moves the count.
                // NOTE(interop): FRR's `maximum-prefix` without `force`
                // and BIRD's `import limit` count accepted routes too.
                if let Some(limit) = limit
                    && state.received_with(family, &scratch.delta) > limit as usize
                {
                    exceeded = Some((family, limit));
                    scratch.released.push(attrs);
                    break 'parts;
                }
            }
            scratch.released.push(attrs);
        }
        let state = self.s.peer_mut(id);
        for (family, d) in scratch.delta.iter_mut() {
            let n = state.adj_in_count.or_default(family);
            *n = n.saturating_add_signed(*d);
            *d = 0;
        }
        exceeded
    }

    /// RFC 4760 §7: an incorrect MP attribute from `id` for `family`.
    /// The speaker "MUST delete all the BGP routes received from that
    /// neighbor whose AFI/SAFI is the same", and "SHOULD ignore all the
    /// subsequent routes with that AFI/SAFI received over that session":
    /// the family stays disabled until the peer goes down.
    fn disable_family(&mut self, id: PeerId, family: AddressFamily, scratch: &mut Scratch) {
        let state = self.s.peer_mut(id);
        if state.disabled.contains(&family) {
            // Already disabled: nothing of it is held.
            return;
        }
        state.disabled.push(family);
        state.adj_in_count.insert(family, 0);
        if let Some(table) = self.tables.get_mut(family) {
            drop_routes(self.s.phase2(), table, family, id, scratch);
        }
        // The count is zero now, whatever the removals added up to.
        scratch.delta.insert(family, 0);
    }

    /// Phase 3 for every destination whose best route an input changed,
    /// then the UPDATEs that follow; release what the input let go of.
    fn finish(&mut self, scratch: &mut Scratch, now: Instant, out: &mut impl Sink) {
        self.s.tick(now);
        for d in &scratch.dirty {
            if !d.merged {
                // The destination as it is now, for the peers sent several
                // paths of it; nothing to look up if there are none.
                let dest = if self.s.path_senders > 0 {
                    self.tables.get(d.family).and_then(|t| t.get(d.prefix))
                } else {
                    None
                };
                self.s.changed(
                    d.family,
                    d.prefix,
                    (d.old.as_ref(), d.new.as_ref()),
                    dest,
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
        scratch.trim();
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
            .filter_map(move |(p, d)| d.best().map(|r| (p, self.s.route_ref(family, r, d.id(0)))))
    }

    /// The candidate routes to `prefix`, the best first: those import
    /// policy accepted, with the attributes it gave them. The routes the
    /// Adj-RIB-In holds for their validation state alone are not among
    /// them.
    #[must_use]
    pub fn candidates(&self, family: AddressFamily, prefix: Prefix) -> Vec<RouteRef<'_>> {
        let Some(dest) = self.tables.get(family).and_then(|t| t.get(prefix)) else {
            return Vec::new();
        };
        dest.iter()
            .take(dest.candidates())
            .map(|(r, id)| self.s.route_ref(family, r, id))
            .collect()
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
    /// (RFC 4271 §5.1) that encoding applies, or for a destination pacing
    /// holds back, what the peer was last sent. Worked out from the
    /// Loc-RIB, which is how the RIB keeps it.
    #[must_use]
    pub fn adj_rib_out(
        &self,
        addr: IpAddr,
        family: AddressFamily,
    ) -> std::vec::IntoIter<(Prefix, Arc<PathAttrs>)> {
        let Some(id) = self.s.id(addr) else {
            return Vec::new().into_iter();
        };
        if self.s.peer(id).info.path_limit(family).is_some() {
            // RFC 7911 §5: every path it has been sent, a prefix more than
            // once if it has several.
            let paths = self.sent_paths(addr, family);
            return paths
                .into_iter()
                .map(|(prefix, _, attrs)| (prefix, attrs))
                .collect::<Vec<_>>()
                .into_iter();
        }
        let pacing = self.s.peer(id).pacing.get(family);
        let mut out = Vec::new();
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table.iter() {
                if pacing.and_then(|p| p.held(prefix)).is_some() {
                    continue;
                }
                match self.s.exported(None, family, prefix, dest.best(), id) {
                    Some(Exported::Own(a)) => out.push((prefix, a)),
                    Some(Exported::Changed(a)) => out.push((prefix, Arc::new(a))),
                    None => {}
                }
            }
        }
        if let Some(pacing) = pacing {
            for (prefix, h) in pacing.all_held() {
                if let Some(a) = &h.has {
                    out.push((prefix, Arc::clone(a)));
                }
            }
            out.sort_by_key(|(p, _)| *p);
        }
        out.into_iter()
    }

    /// The paths peer `addr` has been sent of `family`, in prefix order,
    /// each with the Path Identifier it was sent with (RFC 7911 §5) and
    /// the attributes as the export policy left them, before the session
    /// rewrite (RFC 4271 §5.1). Empty unless the peer is sent several
    /// paths of the family: what any other peer has is [`Rib::adj_rib_out`].
    #[must_use]
    pub fn sent_paths(
        &self,
        addr: IpAddr,
        family: AddressFamily,
    ) -> Vec<(Prefix, PathId, Arc<PathAttrs>)> {
        let Some(id) = self.s.id(addr) else {
            return Vec::new();
        };
        let Some(sent) = self.s.peer(id).sent.get(family) else {
            return Vec::new();
        };
        let mut out: Vec<_> = sent
            .iter()
            .flat_map(|(prefix, paths)| {
                paths
                    .iter()
                    .map(move |p| (prefix, PathId(p.tx), Arc::clone(&p.attrs)))
            })
            .collect();
        out.sort_by_key(|(prefix, id, _)| (*prefix, *id));
        out
    }

    /// Route counts for `addr`.
    #[must_use]
    pub fn peer_stats(&self, addr: IpAddr) -> Option<PeerStats> {
        let p = self.s.peer(self.s.id(addr)?);
        let mut stats = PeerStats::default();
        let mut taken: Vec<AddressFamily> = p
            .info
            .receive_families
            .iter()
            .chain(&p.info.families)
            .copied()
            .collect();
        taken.sort();
        taken.dedup();
        for family in taken {
            stats.received.push((family, p.received(family)));
        }
        for family in &p.info.families {
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
    /// What Phase 2 reads, as the RIB is set up now.
    fn phase2(&self) -> Phase2<'_> {
        Phase2::new(&self.peers, self.cx.invalid)
    }

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

    /// Take `now` as the time of the input being handled, in pacing
    /// time; the first instant ever given is tick 0.
    fn tick(&mut self, now: Instant) -> Now {
        self.at = self.clock.get_or_insert(Clock::new(now)).now(now);
        self.at
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
        self.path_senders += usize::from(!state.info.add_path_send.is_empty());
        self.peers[id.index()] = Some(state);
    }

    /// Forget `addr`, whose routes are gone; its slot is free, and its
    /// wake-ups have nothing left to wake.
    fn remove(&mut self, addr: IpAddr) {
        let Some(id) = self.by_addr.remove(&addr) else {
            return;
        };
        if let Some(state) = self.peers[id.index()].take() {
            self.path_senders -= usize::from(!state.info.add_path_send.is_empty());
            // The attribute sets of the paths it was sent.
            for sent in state.sent.into_values() {
                for (_, paths) in sent.into_entries() {
                    for p in paths.into_vec() {
                        self.cx.interner.release(p.attrs);
                    }
                }
            }
            for pacing in state.pacing.into_values() {
                for h in pacing.into_held() {
                    if let Some(has) = h.has {
                        self.cx.interner.release(has);
                    }
                }
            }
        }
        self.deadlines.retain(|Reverse(d)| d.peer != id);
        shrink_heap(&mut self.deadlines);
        self.sweeps.retain(|Reverse((_, peer, _))| *peer != id);
        shrink_heap(&mut self.sweeps);
    }

    /// Sweep the pacing whose sweeps are due by `now`.
    fn sweep(&mut self, now: Now) {
        while let Some(&Reverse((at, id, family))) = self.sweeps.peek()
            && at <= now.floor
        {
            self.sweeps.pop();
            let next = self.peers[id.index()]
                .as_mut()
                .and_then(|p| p.pacing.get_mut(family))
                .and_then(|p| p.swept(at, now));
            if let Some(next) = next {
                self.sweeps.push(Reverse((next, id, family)));
            }
        }
        shrink_heap(&mut self.sweeps);
    }

    /// Queue a sweep of `id`'s pacing for `family`, if it remembers
    /// something and has none queued.
    fn queue_sweep(&mut self, id: PeerId, family: AddressFamily) {
        let at = self
            .peer_mut(id)
            .pacing
            .get_mut(family)
            .and_then(Pacing::queue_sweep);
        if let Some(at) = at {
            self.sweeps.push(Reverse((at, id, family)));
        }
    }

    /// A route of `family` as the control plane sees it, which has the Path
    /// Identifier `id` it came with if its peer sends them (RFC 7911 §3).
    fn route_ref<'a>(&self, family: AddressFamily, r: &'a Route, id: u32) -> RouteRef<'a> {
        let peer = self.peer(r.peer);
        RouteRef {
            peer: peer.neighbor.addr,
            attrs: &r.attrs,
            rov: r.rov,
            aspa: r.aspa,
            path_id: peer.info.receives_paths(family).then_some(PathId(id)),
        }
    }

    /// Remove `id`'s routes from `dest`, if it has any, and settle the
    /// destination. Whether it still has routes. A peer sent with ADD-PATH
    /// has a route for each path (RFC 7911 §5).
    fn remove_route(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        dest: &mut Destination,
        id: PeerId,
        batches: &mut Batches,
        out: &mut impl Sink,
    ) -> bool {
        let Some(i) = dest.position_of_peer(id) else {
            return true;
        };
        let old = dest.best().cloned();
        let removed = dest.remove(i);
        // More only for a peer sent with ADD-PATH, so nothing is allocated
        // for any other.
        let mut more: Vec<Route> = Vec::new();
        while !dest.is_empty()
            && let Some(next) = dest.position_of_peer(id)
        {
            more.push(dest.remove(next));
        }
        decide(self.phase2(), dest);
        self.changed(
            family,
            prefix,
            (old.as_ref(), dest.best()),
            Some(dest),
            batches,
            out,
        );
        drop(old);
        self.release_route(removed);
        for r in more {
            self.release_route(r);
        }
        !dest.is_empty()
    }

    /// Give the attribute sets of a route no longer held back to the
    /// interner.
    fn release_route(&mut self, route: Route) {
        self.cx.interner.release(route.attrs);
        if let Some(r) = route.received {
            self.cx.interner.release(r);
        }
    }

    /// Phase 3 and the FIB change when the best route went from `old` to
    /// `new`: the FIB when another route is chosen; Phase 3 then, and also
    /// when the chosen one has another validation state, which export
    /// policy may look at; nothing when it is the same route as it was.
    fn changed(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        (old, new): (Option<&Route>, Option<&Route>),
        dest: Option<&Destination>,
        batches: &mut Batches,
        out: &mut impl Sink,
    ) {
        let (route_changed, state_changed) = match (old, new) {
            (None, None) => (false, false),
            (Some(a), Some(b)) => (!a.same(b), !a.same_state(b)),
            _ => (true, true),
        };
        // RFC 4271 §9.3: the FIB follows the chosen route; its validation
        // state alone changes nothing there.
        if route_changed {
            out.put(Output::Fib(FibChange {
                family,
                prefix,
                next_hop: new.map(|r| r.attrs.next_hop_addr()),
                previous: old.map(|r| r.attrs.next_hop_addr()),
            }));
        }
        if route_changed || state_changed {
            self.disseminate(family, prefix, old, new, batches);
        }
        // RFC 7911 §5: a peer sent several paths hears of a change to any
        // of them, not only to the best.
        if self.path_senders > 0 {
            self.sync_senders(family, prefix, dest, batches);
        }
    }

    /// Phase 3: every peer is told about the best route going from `old`
    /// to `new`, as far as export makes a difference to it, through its
    /// pacing (RFC 4271 §9.2.1.1), so every Loc-RIB change, whatever
    /// caused it, is rate-limited the same way.
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
            // A peer sent several paths is brought up to date with the
            // destination as a whole (`sync_senders`).
            if to.leaving || !to.info.speaks(family) || to.info.path_limit(family).is_some() {
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
            let batch = batches.get(id, family);
            self.offer(id, family, prefix, before, after, batch);
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
        match policies.export(to, family, prefix, &best.attrs, best.rov) {
            Verdict::Reject => None,
            // RFC 6811 §2: the state is local to the speaker and does not
            // go to the peer, so a state export policy set is no change.
            Verdict::Accept | Verdict::Restated(_) => export::permitted(family, &best.attrs, to)
                .then(|| Exported::Own(Arc::clone(&best.attrs))),
            Verdict::Modified(mut a) | Verdict::ModifiedRestated(mut a, _) => {
                // RFC 9234 §5: "The operator MUST NOT have the ability to
                // modify the procedures", and a set attribute "MUST be
                // preserved unchanged": whatever a policy made of the
                // route, the attribute is the route's own.
                a.otc = best.attrs.otc;
                export::permitted(family, &a, to).then_some(Exported::Changed(a))
            }
        }
    }

    /// What export makes of `prefix`'s best route for peer `id` going
    /// from `before` to `after`: tell the peer, at once or when its
    /// interval ends (RFC 4271 §9.2.1.1), and count what it has.
    fn offer(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        prefix: Prefix,
        before: Option<Exported>,
        after: Option<Exported>,
        batch: &mut Batch,
    ) {
        let interval = self.peer(id).info.advertisement_interval;
        let mut pace = Pace {
            interval,
            now: self.at,
            jitter: &mut self.jitter,
        };
        // invariant: ids are only handed out for occupied slots.
        let state = self.peers[id.index()].as_mut().unwrap();
        let held = state
            .pacing
            .get(family)
            .and_then(|p| p.held(prefix))
            .map(|h| h.has.is_some());
        if let Some(has) = held {
            // Held back: the peer has what it was last sent, whatever the
            // route was in between, and the release compares with that.
            // Only a withdrawal goes at once.
            if after.is_none() && has {
                batch.withdraw.push(prefix);
                count(state, family, -1);
                // invariant: a held destination's pacing exists.
                let pacing = state.pacing.get_mut(family).unwrap();
                if let Some(has) = pacing.withdrew_held(prefix, &pace) {
                    self.cx.interner.release(has);
                }
            }
            return;
        }
        match (before, after) {
            (None, None) => {}
            (Some(_), None) => {
                batch.withdraw.push(prefix);
                count(state, family, -1);
                state.pacing.or_default(family).withdrew(prefix, &pace);
            }
            (Some(b), Some(a))
                if b.is(&a)
                    || export::same_rewrite(
                        self.cx.local_as,
                        family,
                        b.attrs(),
                        a.attrs(),
                        &state.info,
                    ) => {}
            (before, Some(a)) => {
                let had = before.is_some();
                let pacing = state.pacing.or_default(family);
                match pacing.offer(prefix, had, &mut pace) {
                    Offer::Now => {
                        pacing.advertised(prefix, &pace);
                        if !had {
                            count(state, family, 1);
                        }
                        let a = a.intern(&mut self.cx.interner);
                        batch.announce(&a, prefix);
                    }
                    Offer::Hold(due) => {
                        let has = before.map(|b| b.intern(&mut self.cx.interner));
                        pacing.hold(prefix, due, has);
                        if pacing.queue(prefix, due) {
                            self.deadlines.push(Reverse(Deadline {
                                at: due,
                                peer: id,
                                family,
                                prefix,
                            }));
                        }
                    }
                }
            }
        }
    }

    /// A wake-up for `prefix` of peer `id` at `at` came due by `now`:
    /// what was held, if its interval ended.
    fn wake(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        prefix: Prefix,
        at: Tick,
    ) -> Option<Held> {
        let now = self.at;
        let pacing = self.peer_mut(id).pacing.get_mut(family)?;
        // One that an earlier wake-up replaced: nothing to do.
        if !pacing.fired(prefix, at) {
            return None;
        }
        let wake = pacing.wake(prefix, now);
        if let Some(again) = wake.again
            && pacing.queue(prefix, again)
        {
            self.deadlines.push(Reverse(Deadline {
                at: again,
                peer: id,
                family,
                prefix,
            }));
        }
        wake.released
    }

    /// The interval of a destination held for peer `id` ended (RFC 4271
    /// §9.2.1.1: "the last route selected SHALL be advertised at the end
    /// of `MinRouteAdvertisementIntervalTimer`"): send `after`, what export
    /// makes of its route now, unless the peer already has it.
    fn release(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        prefix: Prefix,
        held: Held,
        after: Option<Exported>,
        batch: &mut Batch,
    ) {
        let interval = self.peer(id).info.advertisement_interval;
        let pace = Pace {
            interval,
            now: self.at,
            jitter: &mut self.jitter,
        };
        // invariant: ids are only handed out for occupied slots.
        let state = self.peers[id.index()].as_mut().unwrap();
        let had = held.has.is_some();
        match (
            held.has.as_ref().map(|a| Exported::Own(Arc::clone(a))),
            after,
        ) {
            (None, None) => {}
            (Some(_), None) => {
                batch.withdraw.push(prefix);
                count(state, family, -1);
                state.pacing.or_default(family).withdrew(prefix, &pace);
            }
            (Some(b), Some(a))
                if b.is(&a)
                    || export::same_rewrite(
                        self.cx.local_as,
                        family,
                        b.attrs(),
                        a.attrs(),
                        &state.info,
                    ) => {}
            (_, Some(a)) => {
                state.pacing.or_default(family).advertised(prefix, &pace);
                if !had {
                    count(state, family, 1);
                }
                let a = a.intern(&mut self.cx.interner);
                batch.announce(&a, prefix);
            }
        }
        if let Some(has) = held.has {
            self.cx.interner.release(has);
        }
    }

    /// Put in peer `id`'s batch what it must be sent about `prefix` when
    /// what export makes of its best route goes from `before` to `after`,
    /// with no pacing: an announcement, a withdrawal, or nothing when they
    /// are the same set or the session rewrite (RFC 4271 §5.1) makes them
    /// the same, which the peer cannot tell apart.
    fn compare(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        prefix: Prefix,
        before: Option<Exported>,
        after: Option<Exported>,
        batch: &mut Batch,
    ) {
        match (before, after) {
            (None, None) => {}
            (Some(_), None) => batch.withdraw.push(prefix),
            (Some(b), Some(a))
                if b.is(&a)
                    || export::same_rewrite(
                        self.cx.local_as,
                        family,
                        b.attrs(),
                        a.attrs(),
                        &self.peer(id).info,
                    ) => {}
            (_, Some(a)) => {
                let a = a.intern(&mut self.cx.interner);
                batch.announce(&a, prefix);
            }
        }
    }

    /// Encode and hand over one peer's batch for `family`.
    fn send(&mut self, id: PeerId, family: AddressFamily, mut batch: Batch, out: &mut impl Sink) {
        if !batch.is_empty() {
            self.queue_sweep(id, family);
        }
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
            if !batch.is_empty() {
                self.queue_sweep(*id, *family);
            }
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

/// Add `delta` to the routes `state`'s Adj-RIB-Out has of `family`, and
/// let its pacing know how many that is.
fn count(state: &mut PeerState, family: AddressFamily, delta: isize) {
    let n = state.advertised.or_default(family);
    *n = n.saturating_add_signed(delta);
    let n = *n;
    state.pacing.or_default(family).note_routes(n);
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

    /// As an interned set.
    fn intern(self, interner: &mut Interner) -> Arc<PathAttrs> {
        match self {
            Exported::Own(a) => a,
            Exported::Changed(a) => interner.intern(a),
        }
    }
}

/// `heap` with its capacity cut down once it is less than a quarter used,
/// so that a burst of churn does not keep its memory.
fn shrink_heap<T: Ord>(heap: &mut BinaryHeap<T>) {
    if heap.capacity() > 64 && heap.len() < heap.capacity() / 4 {
        heap.shrink_to(heap.len() * 2);
    }
}

/// What Phase 2 reads besides the routes of a destination.
#[derive(Clone, Copy)]
struct Phase2<'a> {
    peers: &'a [Option<PeerState>],
    /// Invalid routes lose to the others ([`InvalidAction::PreferValid`]).
    demote_invalid: bool,
}

impl<'a> Phase2<'a> {
    /// Phase 2 over `peers`, with the RIB's `invalid` action in force.
    fn new(peers: &'a [Option<PeerState>], invalid: InvalidAction) -> Self {
        Phase2 {
            peers,
            demote_invalid: invalid.demotes(),
        }
    }

    /// Whether Phase 2 puts `route` below the routes that are not Invalid
    /// (RFC 6811 §5).
    fn demotes(self, route: &Route) -> bool {
        self.demote_invalid && route.rov == RovState::Invalid
    }
}

/// Phase 2: put the best of `dest`'s candidates first.
fn decide(p2: Phase2<'_>, dest: &mut Destination) {
    let n = dest.candidates();
    let best = match &*dest {
        Destination::One(r) => pick(p2, std::slice::from_ref(r), n),
        Destination::Many(v) => pick(p2, v, n),
        Destination::Paths(v) => pick(p2, v, n),
    };
    if let Some(i) = best {
        dest.promote(i);
    }
}

/// The best of the first `n` of `routes`.
fn pick<T: Member>(p2: Phase2<'_>, routes: &[T], n: usize) -> Option<usize> {
    decision::best(n, |i| Candidate {
        // invariant: a route's peer slot is occupied (Sessions::peer).
        from: p2.peers[routes[i].route().peer.index()]
            .as_ref()
            .unwrap()
            .neighbor,
        attrs: &routes[i].route().attrs,
        path_id: routes[i].id(),
        demoted: p2.demotes(routes[i].route()),
    })
}

/// Remove every route `id` sent from `table`, a table of `family`, noting
/// each destination's best route before and after.
fn drop_routes(
    p2: Phase2<'_>,
    table: &mut Table,
    family: AddressFamily,
    id: PeerId,
    scratch: &mut Scratch,
) {
    table.retain(|prefix, dest| {
        if let Some(mut i) = dest.position_of_peer(id) {
            let old = dest.best().cloned();
            // A peer sent with ADD-PATH has a route for each path.
            loop {
                let removed = dest.remove(i);
                scratch.released.push(removed.attrs);
                scratch.released.extend(removed.received);
                *scratch.delta.or_default(family) -= 1;
                if dest.is_empty() {
                    break;
                }
                match dest.position_of_peer(id) {
                    Some(next) => i = next,
                    None => break,
                }
            }
            decide(p2, dest);
            scratch.dirty.push(Dirty {
                family,
                prefix,
                old,
                new: dest.best().cloned(),
                merged: false,
            });
        }
        !dest.is_empty()
    });
}

/// The Path Identifier of the `k`th prefix of a part of an UPDATE, whose
/// `ids` are as many as its prefixes or none (RFC 7911 §3).
fn path_at(ids: &[PathId], k: usize) -> u32 {
    ids.get(k).map_or(0, |i| i.0)
}

/// Remove what peer `id` sent for each of the `prefixes` of one part of an
/// UPDATE, with the Path Identifiers `ids` that go with them: the routes of
/// an announcement that is not kept replace the peer's earlier ones for
/// them (RFC 7911 §5: the same prefix and identifier).
fn withdraw_all(
    p2: Phase2<'_>,
    table: &mut Table,
    family: AddressFamily,
    (prefixes, ids): (&[Prefix], &[PathId]),
    id: PeerId,
    scratch: &mut Scratch,
) {
    for (k, &prefix) in prefixes.iter().enumerate() {
        withdraw(p2, table, family, prefix, (id, path_at(ids, k)), scratch);
    }
}

/// Report `prefixes` of `family` from the peer `from` as route leaks with
/// `otc` (RFC 9234 §5), if there is any prefix to report.
fn report_leak(
    scratch: &mut Scratch,
    from: &PeerInfo,
    family: AddressFamily,
    otc: Asn,
    prefixes: &[Prefix],
) {
    if let Some(&first) = prefixes.first() {
        scratch.ignored.push(Output::RouteLeak {
            peer: from.addr,
            family,
            otc,
            routes: prefixes.len(),
            first,
        });
    }
}

/// Remove the route peer `id` sent for `prefix` with Path Identifier
/// `path` (zero where it sends none), if there is one, and note the
/// destination's best route before and after.
fn withdraw(
    p2: Phase2<'_>,
    table: &mut Table,
    family: AddressFamily,
    prefix: Prefix,
    from: (PeerId, u32),
    scratch: &mut Scratch,
) {
    match Ipv4Key::new(prefix) {
        Some(k) => withdraw_in(p2, &mut table.v4, k, family, prefix, from, scratch),
        None => withdraw_in(p2, &mut table.v6, prefix, family, prefix, from, scratch),
    }
}

fn withdraw_in<K: Ord>(
    p2: Phase2<'_>,
    map: &mut BTreeMap<K, Destination>,
    key: K,
    family: AddressFamily,
    prefix: Prefix,
    (id, path): (PeerId, u32),
    scratch: &mut Scratch,
) {
    let Slot::Occupied(mut slot) = map.entry(key) else {
        return;
    };
    let dest = slot.get_mut();
    let Some(i) = dest.position(id, path) else {
        return;
    };
    let old = dest.best().cloned();
    let removed = dest.remove(i);
    scratch.released.push(removed.attrs);
    scratch.released.extend(removed.received);
    decide(p2, dest);
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

/// Add or replace the route `route`'s peer sent for `prefix` with Path
/// Identifier `path` (zero where it sends none), and note the destination's
/// best route before and after.
fn announce(
    p2: Phase2<'_>,
    table: &mut Table,
    family: AddressFamily,
    prefix: Prefix,
    route: Route,
    path: u32,
    scratch: &mut Scratch,
) {
    match Ipv4Key::new(prefix) {
        Some(k) => announce_in(p2, &mut table.v4, k, family, prefix, (route, path), scratch),
        None => announce_in(
            p2,
            &mut table.v6,
            prefix,
            family,
            prefix,
            (route, path),
            scratch,
        ),
    }
}

fn announce_in<K: Ord>(
    p2: Phase2<'_>,
    map: &mut BTreeMap<K, Destination>,
    key: K,
    family: AddressFamily,
    prefix: Prefix,
    (route, path): (Route, u32),
    scratch: &mut Scratch,
) {
    let (old, new) = match map.entry(key) {
        Slot::Vacant(slot) => {
            // A new destination: its one route is the best, unless it is
            // held.
            let new = (!route.held).then(|| route.clone());
            slot.insert(Destination::single(route, path));
            *scratch.delta.or_default(family) += 1;
            (None, new)
        }
        Slot::Occupied(mut slot) => {
            let dest = slot.get_mut();
            let old = dest.best().cloned();
            if let Some(i) = dest.position(route.peer, path) {
                let r = dest.route(i);
                if Arc::ptr_eq(&r.attrs, &route.attrs)
                    && r.received.as_ref().map(Arc::as_ptr)
                        == route.received.as_ref().map(Arc::as_ptr)
                    && r.same_state(&route)
                    && r.held == route.held
                {
                    // An implicit re-announcement of the same route.
                    return;
                }
                let replaced = dest.replace(i, route);
                scratch.released.push(replaced.attrs);
                scratch.released.extend(replaced.received);
            } else {
                dest.push(route, path);
                *scratch.delta.or_default(family) += 1;
            }
            decide(p2, dest);
            (old, dest.best().cloned())
        }
    };
    scratch.dirty.push(Dirty {
        family,
        prefix,
        old,
        new,
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

/// Merge every set of entries for one destination into its first, as
/// [`merge_repeats`] does for those of one UPDATE: after the routes of a
/// peer over its prefix limit are dropped, a destination its UPDATE
/// changed is changed again.
fn merge_all(dirty: &mut [Dirty], order: &mut Vec<u32>) {
    let key = |d: &Dirty| (d.family, d.prefix);
    order.clear();
    // invariant: fewer than 2^32 destinations.
    order.extend(0..u32::try_from(dirty.len()).unwrap());
    // Stable: the first of each destination stays first.
    order.sort_by_key(|&i| key(&dirty[i as usize]));
    let mut i = 0;
    while i < order.len() {
        let k = key(&dirty[order[i] as usize]);
        let mut j = i + 1;
        while j < order.len() && key(&dirty[order[j] as usize]) == k {
            j += 1;
        }
        if j - i > 1 {
            let (first, last) = (order[i] as usize, order[j - 1] as usize);
            dirty[first].new = dirty[last].new.take();
            for &m in &order[i + 1..j] {
                dirty[m as usize].merged = true;
            }
        }
        i = j;
    }
}

/// What import policy makes of a route (see [`judge`]).
enum Judged {
    /// A candidate for Phase 2, with these attributes and this validation
    /// state, which is the lookup's unless policy set another (RFC 6811
    /// §3).
    Accepted(Arc<PathAttrs>, RovState),
    /// Not a candidate, but one the Adj-RIB-In holds (RFC 6811 §2): import
    /// policy rejects the route with its validation state and accepts it
    /// with another, or accepts it and the RIB itself refuses it for being
    /// Invalid ([`InvalidAction::Drop`]). The state is the one the route
    /// holds meanwhile: the lookup's, or the one policy set that the RIB
    /// refused.
    Held(RovState),
    /// Rejected whatever the route's validation state: not kept.
    Dropped,
}

impl Judged {
    /// The route `peer` sent with `received`, as import policy judged it,
    /// with the verdicts of the lookup, `lookup` and `aspa`; `None` when
    /// it is not kept. A route held for its validation state keeps the
    /// state of the lookup: it was never given another.
    fn into_route(
        self,
        received: &Arc<PathAttrs>,
        peer: PeerId,
        lookup: RovState,
        aspa: AspaState,
    ) -> Option<Route> {
        let (attrs, rov, held) = match self {
            Judged::Accepted(a, rov) => (a, rov, false),
            Judged::Held(rov) => (Arc::clone(received), rov, true),
            Judged::Dropped => return None,
        };
        let received = (!Arc::ptr_eq(&attrs, received)).then(|| Arc::clone(received));
        Some(Route {
            attrs,
            received,
            peer,
            rov,
            lookup,
            aspa,
            held,
        })
    }
}

/// RFC 4271 §9.1.1: import policy decides whether a route `info`'s peer
/// sent for `prefix` of `family`, with `attrs` as received and the
/// validation state `rov` the lookup gave it, is a candidate for Phase 2,
/// and with which attributes and validation state (RFC 6811 §3: policy
/// may set the state). With `drop_invalid` ([`InvalidAction::Drop`]) a
/// route that policy accepts with the state Invalid is not a candidate
/// either (RFC 6811 §5: "rejecting all 'invalid' routes").
///
/// RFC 6811 §2: "An implementation MUST NOT exclude a route from the
/// Adj-RIB-In ... as a side effect of its validation state, unless
/// explicitly configured to do so", and §4 runs the decision process
/// again when the state changes. So a route policy rejects is put to it
/// again with each other state, and is held when one of them would make
/// policy accept it: once its state changes it is taken without a
/// ROUTE-REFRESH. A route policy rejects whatever its state is dropped,
/// as rejected routes were before validation existed: no change of state
/// can bring it back, and holding it would let a filtered peer fill
/// memory, past any `maximum-prefix`, with routes nothing uses.
///
/// What the RIB refuses by itself is held the same way, since a change of
/// state or of the action admits it, and it is what makes `drop_invalid`
/// leave what is kept alone: whether a route is in the Adj-RIB-In depends
/// on policy and never on the action, so the action can change, and a
/// reload that changes it needs no ROUTE-REFRESH to bring routes back.
///
/// Every route reaches the candidates through here, whatever made it
/// worth deciding again.
fn judge(
    policies: &dyn Policies,
    interner: &mut Interner,
    info: &PeerInfo,
    (family, prefix): (AddressFamily, Prefix),
    attrs: &Arc<PathAttrs>,
    (rov, drop_invalid): (RovState, bool),
) -> Judged {
    let verdict = policies.import(info, family, prefix, attrs, rov);
    // The state the route would hold, if accepted.
    let state = verdict.rov().unwrap_or(rov);
    if drop_invalid && state == RovState::Invalid && !matches!(verdict, Verdict::Reject) {
        return Judged::Held(state);
    }
    match verdict {
        Verdict::Accept => Judged::Accepted(Arc::clone(attrs), rov),
        Verdict::Restated(state) => Judged::Accepted(Arc::clone(attrs), state),
        Verdict::Modified(a) => Judged::Accepted(modified(interner, attrs, a), rov),
        Verdict::ModifiedRestated(a, state) => {
            Judged::Accepted(modified(interner, attrs, a), state)
        }
        Verdict::Reject => {
            let admitted = RovState::ALL.into_iter().filter(|s| *s != rov).any(|s| {
                !matches!(
                    policies.import(info, family, prefix, attrs, s),
                    Verdict::Reject
                )
            });
            if admitted {
                Judged::Held(rov)
            } else {
                Judged::Dropped
            }
        }
    }
}

/// The interned attributes import policy made of a route that arrived with
/// `received`.
fn modified(interner: &mut Interner, received: &PathAttrs, mut made: PathAttrs) -> Arc<PathAttrs> {
    // RFC 9234 §5: the ingress procedure has run, and no policy may undo it
    // or change the attribute (see `Sessions::exported`).
    made.otc = received.otc;
    interner.intern(made)
}
