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
//! RFC 6811 §2 (every route received gets its validation state from a
//! lookup, kept as a property of the route; the state never keeps a
//! route out of the Adj-RIB-In: one import policy rejects for its state
//! alone is kept, and one the operator's enforcement rules out is kept
//! and is no candidate, see [`Held`]), §3 (policy sees
//! the validation state and may set the one a route is used with, see
//! [`Policies`] and [`Imported`]), §4 (the affected routes are
//! validated again when the validation source changes, see
//! [`Rib::validation_changed`]), §5 (enforcement: Invalid routes left out
//! of the decision process, or Valid ones preferred before anything else,
//! see [`Rib::set_enforcement`] and [`decision::Step::Validation`]).
//!
//! Time is injected: every call that can send takes `now`, and
//! [`Rib::next_deadline`] and [`Rib::flush`] let the owner release held
//! advertisements when their interval ends.
//!
//! With the `profiling` feature, the work per route is timed into
//! `bgpfc-prof` histograms and the `profiling` module reports the RIB's
//! size and how much its attributes repeat (`docs/PROFILING.md`).
#![forbid(unsafe_code)]

pub mod attrs;
pub mod decision;
pub mod export;
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

use bgpfc_rpki::{NullSource, ValidationSource};
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::{Ipv4Key, Prefix};
use bgpfc_wire::types::{AddressFamily, Asn};
use bgpfc_wire::update::{DecodedUpdate, PeerKind};

pub use attrs::{Interner, PathAttrs};
pub use bgpfc_rpki::{AspaState, Enforcement, RouteOrigin, RovState};
pub use decision::{Candidate, Neighbor};
pub use export::{Batch, Source};
pub use peer::PeerInfo;
pub use validation::{Rejudged, Revalidation};

use pacing::{Clock, Jitter, Now, Offer, Pace, Pacing, Tick};
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

/// What import policy made of a route (RFC 4271 §9.1.1, RFC 6811 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    /// Whether the route is a candidate, and with which attributes.
    pub verdict: Verdict,
    /// The validation state policy set, if it set one (RFC 6811 §3: "the
    /// ability to match and set the validation state of routes"): the
    /// route is then used with it in place of the one the lookup gave it,
    /// which it keeps as its own (RFC 6811 §2: "The validation state of
    /// the Route MUST be set to reflect the result of the lookup").
    pub rov: Option<RovState>,
}

/// Why the Adj-RIB-In holds a route that is no candidate for the decision
/// process. RFC 6811 §2: "An implementation MUST NOT exclude a route from
/// the Adj-RIB-In or from consideration in the decision process as a side
/// effect of its validation state, unless explicitly configured to do
/// so": the route stays in the Adj-RIB-In, counted as received, and is
/// used again, with no UPDATE, once its state allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// Import policy rejected it with its validation state and accepts it
    /// with another.
    Policy,
    /// Import policy accepted it, but the operator's [`Enforcement`] rules
    /// out the state it is used with (Invalid under `drop-invalid`, RFC
    /// 6811 §5: "rejecting all "invalid" routes").
    Enforcement,
}

impl Held {
    /// The name used in logs and control output: `policy` or
    /// `enforcement`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Held::Policy => "policy",
            Held::Enforcement => "enforcement",
        }
    }
}

impl std::fmt::Display for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Verdict> for Imported {
    /// A verdict that sets no validation state.
    fn from(verdict: Verdict) -> Imported {
        Imported { verdict, rov: None }
    }
}

/// Import and export policy as the RIB sees it (RFC 4271 §9.1.1 local
/// policy, §9.1.3 export policy). `peer` is the peer the route came from
/// on import and the peer it is going to on export. `rov` is the route's
/// validation state, which policy must be able to match and set (RFC 6811
/// §3).
pub trait Policies: Send {
    /// Decide whether and how a route held in the Adj-RIB-In becomes a
    /// candidate for the decision process, and with which validation
    /// state it is used. `rov` is the state the lookup gave the route
    /// (RFC 6811 §2).
    fn import(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        attrs: &PathAttrs,
        rov: RovState,
    ) -> Imported;

    /// Decide whether and how a Loc-RIB route is advertised to `peer`,
    /// before the RFC 4271 §5.1 rewriting for the session. `rov` is the
    /// state the route is used with: the one import policy set, else the
    /// one the lookup gave it.
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
    ) -> Imported {
        Verdict::Accept.into()
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
    /// Routes in the Adj-RIBs-In changed RFC 6811 validation state with
    /// the validation source (see [`Rib::validation_changed`]): one report
    /// per change of the source, counted rather than listed, however many
    /// routes it moved. The caller logs it. The state a route gets on
    /// arrival is its first, not a change, and is not reported.
    Revalidated(Revalidation),
    /// The operator's enforcement mode changed (see
    /// [`Rib::set_enforcement`]), and every route was judged again under
    /// it: one report, counted, followed by the FIB changes and UPDATEs
    /// that follow. The caller logs it.
    Enforcement(Rejudged),
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
    /// Its RFC 6811 §2 validation state: what the lookup gave it.
    pub rov: RovState,
    /// The validation state import policy set, if it set one (RFC 6811
    /// §3), which the route is used with in place of `rov`.
    pub rov_set: Option<RovState>,
    /// Its ASPA verdict (a placeholder until ASPA lands).
    pub aspa: AspaState,
    /// Why the Adj-RIB-In holds it while it is no candidate, if it is not
    /// one.
    pub held: Option<Held>,
}

impl RouteRef<'_> {
    /// The validation state the route is used with: the one import policy
    /// set, else the one the lookup gave it. Export policy sees this one.
    #[must_use]
    pub fn effective_rov(&self) -> RovState {
        self.rov_set.unwrap_or(self.rov)
    }
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
    /// How many of those are held and no candidate ([`Held`]): what
    /// [`PeerStats::held`] reports. Kept as routes come, go and change
    /// places, so that the control plane never walks the table for it.
    adj_in_held: FamilyMap<usize>,
    /// The RFC 4271 §9.2.1.1 pacing state per family.
    pacing: FamilyMap<Pacing>,
    /// The session is going down: its routes are being removed, and it is
    /// sent nothing more.
    leaving: bool,
}

impl PeerState {
    /// Routes of `family` in the Adj-RIB-In.
    fn received(&self, family: AddressFamily) -> usize {
        self.adj_in_count.get(family).copied().unwrap_or(0)
    }

    /// Routes of `family` held in the Adj-RIB-In and no candidates.
    fn held(&self, family: AddressFamily) -> usize {
        self.adj_in_held.get(family).copied().unwrap_or(0)
    }
}

/// Counters about one peer, for the control plane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Routes accepted from the peer, per family it may send, with those
    /// held for their validation state ([`Held`]), which the Adj-RIB-In
    /// holds too (RFC 6811 §2): what the RFC 4271 §6.7 limit counts.
    pub received: Vec<(AddressFamily, usize)>,
    /// How many of `received` are held and no candidate ([`Held`]), in
    /// the same families and order.
    pub held: Vec<(AddressFamily, usize)>,
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
    /// What the validation state does to a route's use beyond policy:
    /// [`Enforcement::Off`] until [`Rib::set_enforcement`] says otherwise.
    enforcement: Enforcement,
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
    /// Held routes added minus held routes removed, per family.
    held_delta: FamilyMap<isize>,
    /// The parts of the UPDATE ignored for their next hop (RFC 4271
    /// §6.3), reported before what the UPDATE changed.
    ignored: Vec<Output>,
    batches: Batches,
}

impl Scratch {
    /// Count `route`, added to the Adj-RIB-In of `family`.
    fn note_added(&mut self, family: AddressFamily, route: &Route) {
        *self.delta.or_default(family) += 1;
        if route.held.is_some() {
            *self.held_delta.or_default(family) += 1;
        }
    }

    /// Count `route`, removed from the Adj-RIB-In of `family`.
    fn note_removed(&mut self, family: AddressFamily, route: &Route) {
        *self.delta.or_default(family) -= 1;
        if route.held.is_some() {
            *self.held_delta.or_default(family) -= 1;
        }
    }

    /// Add what the routes added and removed came to to `state`'s
    /// counts, and start again from zero.
    fn count_into(&mut self, state: &mut PeerState) {
        for (family, d) in self.delta.iter_mut() {
            let n = state.adj_in_count.or_default(family);
            *n = n.saturating_add_signed(*d);
            *d = 0;
        }
        for (family, d) in self.held_delta.iter_mut() {
            let n = state.adj_in_held.or_default(family);
            *n = n.saturating_add_signed(*d);
            *d = 0;
        }
    }

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
    /// [`Rib::validation_changed`] gives it a source, and nothing acts on
    /// the state beyond policy ([`Enforcement::Off`]) until
    /// [`Rib::set_enforcement`] says otherwise.
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
                    // RFC 8481 §5: "Absent specific operator
                    // configuration, policy MUST NOT be applied"; the
                    // daemon sets the configured mode.
                    enforcement: Enforcement::Off,
                },
                peers: Vec::new(),
                by_addr: HashMap::new(),
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
            adj_in_held: FamilyMap::default(),
            pacing: FamilyMap::default(),
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
            drop_routes(self.s.decide(), table, f, id, scratch);
        }
        // The peer goes with its counts: what the removals added up to
        // must not carry over to the next UPDATE's peer.
        for (_, d) in scratch
            .delta
            .iter_mut()
            .chain(scratch.held_delta.iter_mut())
        {
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
        if let Some(table) = self.tables.get(family) {
            for (prefix, dest) in table.iter() {
                let before = self.s.exported(Some(old), family, prefix, dest.best(), id);
                let after = self.s.exported(None, family, prefix, dest.best(), id);
                self.s.offer(id, family, prefix, before, after, &mut batch);
            }
        }
        self.s.send(id, family, batch, out);
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
            for d in group {
                let Some(held) = self.s.wake(id, family, d.prefix, d.at) else {
                    continue;
                };
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
            merge_repeats(&mut scratch.dirty, scratch.withdrawn, &mut scratch.order);
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
        let decide = Decide {
            peers,
            enforcement: cx.enforcement,
        };
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
        for (family, prefix) in update.withdrawals() {
            #[cfg(feature = "profiling")]
            let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_REMOVE);
            if unused(family) {
                continue;
            }
            if let Some(table) = self.tables.get_mut(family) {
                withdraw(decide, table, family, prefix, id, scratch);
            }
        }
        scratch.withdrawn = scratch.dirty.len();
        let mut exceeded = None;
        'parts: for (family, next_hop, prefixes) in attrs::announced(update) {
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
                    for &prefix in prefixes {
                        withdraw(decide, table, family, prefix, id, scratch);
                    }
                }
                scratch.ignored.push(Output::InvalidNextHop {
                    peer: info.addr,
                    family,
                    next_hop,
                    prefixes: prefixes.to_vec(),
                });
                continue;
            }
            let attrs = cx
                .interner
                .intern(PathAttrs::from_update(&update.message, next_hop));
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
                    for &prefix in prefixes {
                        withdraw(decide, table, family, prefix, id, scratch);
                    }
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
            for &prefix in prefixes {
                #[cfg(feature = "profiling")]
                let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::RIB_INSERT);
                let rov = cx.validation.rov(prefix, origin);
                let judged = judge(
                    &*cx.policies,
                    cx.enforcement,
                    &mut cx.interner,
                    info,
                    (family, prefix),
                    &attrs,
                    rov,
                );
                match judged.into_route(&attrs, id, rov, aspa) {
                    Some(route) => {
                        let table = self.tables.or_default(family);
                        announce(decide, table, family, prefix, route, scratch);
                    }
                    // Not kept, and one the peer sent before for the prefix
                    // goes too: the new announcement replaced it.
                    None => {
                        if let Some(table) = self.tables.get_mut(family) {
                            withdraw(decide, table, family, prefix, id, scratch);
                        }
                    }
                }
                // RFC 4271 §6.7: "the number of address prefixes received
                // from the neighbor exceeds the locally-configured, upper
                // bound". Counted are the routes the Adj-RIB-In holds after
                // the loop checks and import policy, the ones "the speaker
                // is willing to accept" (§6.7): a route import policy
                // rejects is not kept, so counting it would take the
                // memory the limit is there to bound. One held for its
                // validation state, by policy or by enforcement, is kept
                // (RFC 6811 §2, see `judge`) and counted; whether a route
                // is kept does not depend on its state or on the
                // enforcement mode, so a change of either never moves the
                // count.
                // NOTE(interop): FRR's `maximum-prefix` without `force`
                // and BIRD's `import limit` count accepted routes too.
                if let Some(limit) = limit {
                    let n = state
                        .received(family)
                        .saturating_add_signed(scratch.delta.get(family).copied().unwrap_or(0));
                    if n > limit as usize {
                        exceeded = Some((family, limit));
                        scratch.released.push(attrs);
                        break 'parts;
                    }
                }
            }
            scratch.released.push(attrs);
        }
        scratch.count_into(self.s.peer_mut(id));
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
        state.adj_in_held.insert(family, 0);
        if let Some(table) = self.tables.get_mut(family) {
            drop_routes(self.s.decide(), table, family, id, scratch);
        }
        // The counts are zero now, whatever the removals added up to.
        scratch.delta.insert(family, 0);
        scratch.held_delta.insert(family, 0);
    }

    /// Phase 3 for every destination whose best route an input changed,
    /// then the UPDATEs that follow; release what the input let go of.
    fn finish(&mut self, scratch: &mut Scratch, now: Instant, out: &mut impl Sink) {
        self.s.tick(now);
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
            .filter_map(|(p, d)| d.best().map(|r| (p, self.s.route_ref(r))))
    }

    /// The candidate routes to `prefix`, the best first: those import
    /// policy accepted, with the attributes it gave them. The routes the
    /// Adj-RIB-In holds for their validation state ([`Held`]) are not
    /// among them.
    #[must_use]
    pub fn candidates(&self, family: AddressFamily, prefix: Prefix) -> Vec<RouteRef<'_>> {
        self.tables
            .get(family)
            .and_then(|t| t.get(prefix))
            .map_or(&[][..], |d| &d.routes()[..d.candidates()])
            .iter()
            .map(|r| self.s.route_ref(r))
            .collect()
    }

    /// Every route the Adj-RIBs-In hold for `prefix`: the candidates, the
    /// best first, then the routes held for their validation state, each
    /// with why ([`RouteRef::held`]).
    #[must_use]
    pub fn routes(&self, family: AddressFamily, prefix: Prefix) -> Vec<RouteRef<'_>> {
        self.tables
            .get(family)
            .and_then(|t| t.get(prefix))
            .map_or(&[][..], Destination::routes)
            .iter()
            .map(|r| self.s.route_ref(r))
            .collect()
    }

    /// Every route of `family` the Adj-RIBs-In hold for its validation
    /// state and that is no candidate, in prefix order.
    pub fn held(&self, family: AddressFamily) -> impl Iterator<Item = (Prefix, RouteRef<'_>)> {
        self.tables
            .get(family)
            .into_iter()
            .flat_map(store::PrefixMap::iter)
            .flat_map(move |(p, d)| {
                d.routes()[d.candidates()..]
                    .iter()
                    .map(move |r| (p, self.s.route_ref(r)))
            })
    }

    /// What the validation state does to a route's use beyond policy.
    #[must_use]
    pub fn enforcement(&self) -> Enforcement {
        self.s.cx.enforcement
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
            stats.held.push((family, p.held(family)));
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
        self.peers[id.index()] = Some(state);
    }

    /// Forget `addr`, whose routes are gone; its slot is free, and its
    /// wake-ups have nothing left to wake.
    fn remove(&mut self, addr: IpAddr) {
        let Some(id) = self.by_addr.remove(&addr) else {
            return;
        };
        if let Some(state) = self.peers[id.index()].take() {
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

    /// What Phase 2 needs of the sessions.
    fn decide(&self) -> Decide<'_> {
        Decide {
            peers: &self.peers,
            enforcement: self.cx.enforcement,
        }
    }

    fn route_ref<'a>(&self, r: &'a Route) -> RouteRef<'a> {
        RouteRef {
            peer: self.peer(r.peer).neighbor.addr,
            attrs: &r.attrs,
            rov: r.rov,
            rov_set: r.rov_set,
            aspa: r.aspa,
            held: r.held,
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
        self.decide().run(dest);
        self.changed(family, prefix, old.as_ref(), dest.best(), batches, out);
        drop(old);
        self.release_route(removed);
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
        old: Option<&Route>,
        new: Option<&Route>,
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
        // RFC 6811 §3: the state policy set is the one the route is used
        // with, here too.
        match policies.export(to, family, prefix, &best.attrs, best.effective_rov()) {
            Verdict::Reject => None,
            Verdict::Accept => export::permitted(family, &best.attrs, to)
                .then(|| Exported::Own(Arc::clone(&best.attrs))),
            Verdict::Modified(a) => {
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
                if b.is(&a) || export::same_rewrite(family, b.attrs(), a.attrs(), &state.info) => {}
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
    ) -> Option<pacing::Held> {
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
        held: pacing::Held,
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
                if b.is(&a) || export::same_rewrite(family, b.attrs(), a.attrs(), &state.info) => {}
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
                    || export::same_rewrite(family, b.attrs(), a.attrs(), &self.peer(id).info) => {}
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

/// What Phase 2 needs of the RIB: the peers the routes name, and the
/// enforcement mode, which may rank the routes by validation state.
#[derive(Clone, Copy)]
struct Decide<'a> {
    peers: &'a [Option<PeerState>],
    enforcement: Enforcement,
}

impl Decide<'_> {
    /// Phase 2: put the best of `dest`'s candidates first.
    fn run(self, dest: &mut Destination) {
        let routes = dest.routes();
        let best = decision::best(
            dest.candidates(),
            |i| Candidate {
                // invariant: a route's peer slot is occupied
                // (Sessions::peer).
                from: self.peers[routes[i].peer.index()]
                    .as_ref()
                    .unwrap()
                    .neighbor,
                attrs: &routes[i].attrs,
                rov: routes[i].effective_rov(),
            },
            self.enforcement,
        );
        if let Some(i) = best {
            dest.promote(i);
        }
    }
}

/// Remove every route `id` sent from `table`, a table of `family`, noting
/// each destination's best route before and after.
fn drop_routes(
    decide: Decide<'_>,
    table: &mut Table,
    family: AddressFamily,
    id: PeerId,
    scratch: &mut Scratch,
) {
    table.retain(|prefix, dest| {
        if let Some(i) = dest.position(id) {
            let old = dest.best().cloned();
            let removed = dest.remove(i);
            scratch.note_removed(family, &removed);
            scratch.released.push(removed.attrs);
            scratch.released.extend(removed.received);
            decide.run(dest);
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

/// Remove peer `id`'s route to `prefix`, if there is one, and note the
/// destination's best route before and after.
fn withdraw(
    decide: Decide<'_>,
    table: &mut Table,
    family: AddressFamily,
    prefix: Prefix,
    id: PeerId,
    scratch: &mut Scratch,
) {
    match Ipv4Key::new(prefix) {
        Some(k) => withdraw_in(decide, &mut table.v4, k, family, prefix, id, scratch),
        None => withdraw_in(decide, &mut table.v6, prefix, family, prefix, id, scratch),
    }
}

fn withdraw_in<K: Ord>(
    decide: Decide<'_>,
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
    let removed = dest.remove(i);
    scratch.note_removed(family, &removed);
    scratch.released.push(removed.attrs);
    scratch.released.extend(removed.received);
    decide.run(dest);
    let new = dest.best().cloned();
    if dest.is_empty() {
        slot.remove();
    }
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
    decide: Decide<'_>,
    table: &mut Table,
    family: AddressFamily,
    prefix: Prefix,
    route: Route,
    scratch: &mut Scratch,
) {
    match Ipv4Key::new(prefix) {
        Some(k) => announce_in(decide, &mut table.v4, k, family, prefix, route, scratch),
        None => announce_in(
            decide,
            &mut table.v6,
            prefix,
            family,
            prefix,
            route,
            scratch,
        ),
    }
}

fn announce_in<K: Ord>(
    decide: Decide<'_>,
    map: &mut BTreeMap<K, Destination>,
    key: K,
    family: AddressFamily,
    prefix: Prefix,
    route: Route,
    scratch: &mut Scratch,
) {
    let (old, new) = match map.entry(key) {
        Slot::Vacant(slot) => {
            // A new destination: its one route is the best, unless it is
            // held.
            let new = route.held.is_none().then(|| route.clone());
            scratch.note_added(family, &route);
            slot.insert(Destination::One(route));
            (None, new)
        }
        Slot::Occupied(mut slot) => {
            let dest = slot.get_mut();
            let old = dest.best().cloned();
            if let Some(i) = dest.position(route.peer) {
                let r = &dest.routes()[i];
                if Arc::ptr_eq(&r.attrs, &route.attrs)
                    && r.received.as_ref().map(Arc::as_ptr)
                        == route.received.as_ref().map(Arc::as_ptr)
                    && r.same_state(&route)
                    && r.held == route.held
                {
                    // An implicit re-announcement of the same route.
                    return;
                }
                scratch.note_added(family, &route);
                let replaced = dest.replace(i, route);
                scratch.note_removed(family, &replaced);
                scratch.released.push(replaced.attrs);
                scratch.released.extend(replaced.received);
            } else {
                scratch.note_added(family, &route);
                dest.push(route);
            }
            decide.run(dest);
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
    /// A candidate for Phase 2, with these attributes, used with the
    /// validation state policy set, if it set one.
    Accepted {
        attrs: Arc<PathAttrs>,
        rov_set: Option<RovState>,
    },
    /// Held in the Adj-RIB-In, and no candidate, for why `by` says;
    /// used with the validation state policy set, if it set one.
    Held { by: Held, rov_set: Option<RovState> },
    /// Rejected whatever the route's validation state: not kept.
    Dropped,
}

impl Judged {
    /// The route `peer` sent with `received`, as import policy judged it,
    /// with validation verdicts `rov` and `aspa`; `None` when it is not
    /// kept.
    fn into_route(
        self,
        received: &Arc<PathAttrs>,
        peer: PeerId,
        rov: RovState,
        aspa: AspaState,
    ) -> Option<Route> {
        let (attrs, rov_set, held) = match self {
            Judged::Accepted { attrs, rov_set } => (attrs, rov_set, None),
            Judged::Held { by, rov_set } => (Arc::clone(received), rov_set, Some(by)),
            Judged::Dropped => return None,
        };
        let received = (!Arc::ptr_eq(&attrs, received)).then(|| Arc::clone(received));
        Some(Route {
            attrs,
            received,
            peer,
            rov,
            rov_set,
            aspa,
            held,
        })
    }
}

/// RFC 4271 §9.1.1: import policy decides whether a route `info`'s peer
/// sent for `prefix` of `family`, with `attrs` as received and validation
/// state `rov`, is a candidate for Phase 2, with which attributes, and,
/// RFC 6811 §3, with which validation state it is used; then
/// `enforcement` decides whether that state may be a candidate.
///
/// RFC 6811 §2: "An implementation MUST NOT exclude a route from the
/// Adj-RIB-In ... as a side effect of its validation state, unless
/// explicitly configured to do so", and §4 runs the decision process
/// again when the state changes. So a route policy rejects is put to it
/// again with each other state, and is held ([`Held::Policy`]) when one of
/// them would make policy accept it: once its state changes it is taken
/// without a ROUTE-REFRESH. A route policy rejects whatever its state is
/// dropped, as rejected routes were before validation existed: no change
/// of state can bring it back, and holding it would let a filtered peer
/// fill memory, past any `maximum-prefix`, with routes nothing uses.
///
/// A route policy accepts but whose state `enforcement` rules out (RFC
/// 6811 §5, "rejecting all "invalid" routes", configured) is held
/// ([`Held::Enforcement`]) whatever the other states would give: a change
/// of state or of the enforcement mode, which a reload makes with no
/// ROUTE-REFRESH, may bring it back, and the Adj-RIB-In keeps it as RFC
/// 6811 §2 asks. Policy alone decides what is kept, so that costs no
/// further question to policy.
///
/// Every route reaches the candidates through here, whatever made it
/// worth deciding again.
fn judge(
    policies: &dyn Policies,
    enforcement: Enforcement,
    interner: &mut Interner,
    info: &PeerInfo,
    (family, prefix): (AddressFamily, Prefix),
    attrs: &Arc<PathAttrs>,
    rov: RovState,
) -> Judged {
    let Imported {
        verdict,
        rov: rov_set,
    } = policies.import(info, family, prefix, attrs, rov);
    let attrs = match verdict {
        Verdict::Accept => Arc::clone(attrs),
        Verdict::Modified(a) => interner.intern(a),
        Verdict::Reject => {
            let admitted = RovState::ALL.into_iter().filter(|s| *s != rov).any(|s| {
                !matches!(
                    policies.import(info, family, prefix, attrs, s).verdict,
                    Verdict::Reject
                )
            });
            return if admitted {
                Judged::Held {
                    by: Held::Policy,
                    rov_set: None,
                }
            } else {
                Judged::Dropped
            };
        }
    };
    if enforcement.admits(rov_set.unwrap_or(rov)) {
        Judged::Accepted { attrs, rov_set }
    } else {
        // Held as received, like any held route: the set policy made of
        // it goes back to the interner.
        interner.release(attrs);
        Judged::Held {
            by: Held::Enforcement,
            rov_set,
        }
    }
}
