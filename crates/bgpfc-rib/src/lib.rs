//! Adj-RIB-In, Loc-RIB, Adj-RIB-Out and the decision process
//! (AGENTS.md §3, "RIB thread": the only owner of all RIB state, driven
//! by messages, no I/O).
//!
//! Implements: RFC 4271 §3.2 (the three RIBs; the Adj-RIBs-In hold routes
//! as received, before import policy), §9.1 (the decision
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
//! route out of the Adj-RIB-In or the decision process), §3 (policy sees
//! the validation state, see [`Policies`]), §4 (the affected routes are
//! validated again when the validation source changes, see
//! [`Rib::validation_changed`]).
//!
//! Time is injected: every call that can send takes `now`, and
//! [`Rib::next_deadline`] and [`Rib::flush`] let the owner release held
//! advertisements when their interval ends.
#![forbid(unsafe_code)]

pub mod attrs;
pub mod decision;
pub mod export;
pub mod pacing;
pub mod peer;
#[cfg(test)]
mod tests;
mod validation;

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_rpki::{NullSource, ValidationSource};
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn};
use bgpfc_wire::update::{DecodedUpdate, PeerKind};

pub use attrs::{Interner, PathAttrs};
pub use bgpfc_rpki::{AspaState, RouteOrigin, RovState};
pub use decision::Candidate;
pub use export::{Batch, Source};
pub use peer::PeerInfo;
pub use validation::Revalidation;

use pacing::{AdjRibOut, Clock, Jitter, Now, Pace, Step, Tick};

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
/// on import and the peer it is going to on export. `rov` is the route's
/// validation state, which policy must be able to match (RFC 6811 §3).
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
}

/// The best route to a destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BestRoute {
    /// The peer it came from.
    pub peer: IpAddr,
    /// Its attributes.
    pub attrs: Arc<PathAttrs>,
    /// Its RFC 6811 §2 validation state.
    pub rov: RovState,
    /// Its ASPA verdict (a placeholder until ASPA lands).
    pub aspa: AspaState,
}

impl BestRoute {
    /// The best route that `c` is.
    fn of(c: &Candidate) -> BestRoute {
        BestRoute {
            peer: c.peer,
            attrs: Arc::clone(&c.attrs),
            rov: c.rov,
            aspa: c.aspa,
        }
    }
}

/// A route in an Adj-RIB-In: what a peer advertised for a destination,
/// before import policy (RFC 4271 §3.2: "unprocessed routing
/// information").
#[derive(Clone, Debug)]
struct Received {
    /// The peer that sent it.
    peer: IpAddr,
    /// Its attributes as received, interned.
    attrs: Arc<PathAttrs>,
    /// Its RFC 6811 §2 validation state under the current validation
    /// source: a property of the route, not of its attributes, which
    /// routes to other prefixes share.
    rov: RovState,
    /// Its ASPA verdict under the current validation source.
    aspa: AspaState,
}

/// One destination: the route each peer sent for it, those import policy
/// accepted, and the chosen one.
#[derive(Debug, Default)]
struct Destination {
    /// The Adj-RIBs-In for this destination: at most one route per peer,
    /// kept whatever import policy makes of it, so that policy can run
    /// again on what the peer sent.
    received: Vec<Received>,
    /// What import policy accepted of `received`, with the attributes it
    /// gave them: the routes Phase 2 chooses from (RFC 4271 §9.1.1).
    candidates: Vec<Candidate>,
    best: Option<BestRoute>,
}

impl Destination {
    /// Nothing is held for the destination and nothing was chosen, so
    /// there is nothing left to decide or to withdraw: it can go.
    fn is_unused(&self) -> bool {
        self.received.is_empty() && self.best.is_none()
    }
}

struct PeerState {
    info: PeerInfo,
    /// Families disabled after an incorrect multiprotocol attribute
    /// (RFC 4760 §7); no more routes are accepted for them this session.
    disabled: HashSet<AddressFamily>,
    /// Adj-RIB-Out: what the peer was last told, per family, with the
    /// RFC 4271 §9.2.1.1 pacing state.
    adj_out: HashMap<AddressFamily, AdjRibOut>,
    /// Routes of each family in the Adj-RIB-In, accepted by import policy
    /// or not: what [`PeerStats::received`] reports and the RFC 4271 §6.7
    /// limit counts.
    adj_in_count: HashMap<AddressFamily, usize>,
}

impl PeerState {
    /// Routes of `family` in the Adj-RIB-In.
    fn received(&self, family: AddressFamily) -> u64 {
        self.adj_in_count
            .get(&family)
            .map_or(0, |n| u64::try_from(*n).unwrap_or(u64::MAX))
    }
}

/// Counters about one peer, for the control plane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Routes the peer sent that the Adj-RIB-In holds, per family it may
    /// send, whether import policy accepted them or not: what the
    /// RFC 4271 §6.7 limit counts.
    pub received: Vec<(AddressFamily, usize)>,
    /// Routes advertised to the peer, per negotiated family.
    pub advertised: Vec<(AddressFamily, usize)>,
}

/// A wake-up for one destination of one peer (RFC 4271 §9.2.1.1): a held
/// advertisement may go out, or a remembered one may be forgotten.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Deadline {
    at: Tick,
    peer: IpAddr,
    family: AddressFamily,
    prefix: Prefix,
}

/// All RIB state.
pub struct Rib {
    local_as: Asn,
    policies: Box<dyn Policies>,
    peers: HashMap<IpAddr, PeerState>,
    /// Adj-RIBs-In and Loc-RIB together, per family and in prefix order:
    /// every route received for a destination, the candidates import
    /// policy made of them, and the best among those.
    tables: HashMap<AddressFamily, BTreeMap<Prefix, Destination>>,
    interner: Interner,
    /// Where validation states come from (issue #56): [`NullSource`],
    /// every route `Disabled`, until [`Rib::validation_changed`] says
    /// otherwise.
    validation: Arc<dyn ValidationSource>,
    /// Pending wake-ups, earliest first. Each `AdjRibOut` knows the one
    /// live entry per destination; an entry an earlier one replaced stays
    /// until due and is then ignored, and those of a peer that went down
    /// are removed with it.
    deadlines: BinaryHeap<Reverse<Deadline>>,
    /// Pacing time, counted from the first instant the RIB was given.
    clock: Option<Clock>,
    /// RFC 4271 §10 jitter for the pacing intervals.
    jitter: Jitter,
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
            local_as,
            policies,
            peers: HashMap::new(),
            tables: HashMap::new(),
            interner: Interner::default(),
            validation: Arc::new(NullSource),
            deadlines: BinaryHeap::new(),
            clock: None,
            jitter: Jitter::new(0),
        }
    }

    /// Seed the RFC 4271 §10 jitter of the advertisement intervals; zero,
    /// the default, applies none.
    pub fn set_jitter_seed(&mut self, seed: u64) {
        self.jitter = Jitter::new(seed);
    }

    /// Replace the policies. The caller re-evaluates routes afterwards
    /// (route refresh for imports, [`Rib::refresh`] for exports).
    pub fn set_policies(&mut self, policies: Box<dyn Policies>) {
        self.policies = policies;
    }

    /// Our AS.
    #[must_use]
    pub fn local_as(&self) -> Asn {
        self.local_as
    }

    /// A session reached Established: remember the peer and send it the
    /// Loc-RIB for every negotiated family (RFC 4271 §9.2: the initial
    /// Adj-RIB-Out). These first advertisements are not held back.
    pub fn peer_up(&mut self, info: PeerInfo, now: Instant) -> Vec<Output> {
        let addr = info.addr;
        let families = info.families.clone();
        self.peers.insert(
            addr,
            PeerState {
                info,
                disabled: HashSet::new(),
                adj_out: HashMap::new(),
                adj_in_count: HashMap::new(),
            },
        );
        let mut out = Vec::new();
        for family in families {
            out.extend(self.refresh(addr, family, now));
        }
        out
    }

    /// The session left Established: forget the peer and its routes.
    pub fn peer_down(&mut self, addr: IpAddr, now: Instant) -> Vec<Output> {
        let dirty = self.forget_peer(addr);
        self.reconsider(&dirty, now)
    }

    /// Remove the peer and every route it sent; the destinations whose
    /// candidates changed. Every family's table is searched, not only the
    /// negotiated ones: the peer may have sent routes of any family we
    /// advertised (RFC 4760 §8), and none may outlive the session.
    fn forget_peer(&mut self, addr: IpAddr) -> Vec<(AddressFamily, Prefix)> {
        if self.peers.remove(&addr).is_none() {
            return Vec::new();
        }
        // Its wake-ups have nothing left to wake.
        self.deadlines.retain(|Reverse(d)| d.peer != addr);
        shrink_heap(&mut self.deadlines);
        let mut dirty: Vec<(AddressFamily, Prefix)> = Vec::new();
        for (family, table) in &mut self.tables {
            drop_peer_routes(*family, table, addr, &mut dirty);
        }
        dirty
    }

    /// Change the prefix limits of peer `addr` (RFC 4271 §6.7), as a reload
    /// does. A family already over its new limit is handled as if the
    /// limit had just been exceeded.
    pub fn set_prefix_limits(
        &mut self,
        addr: IpAddr,
        limits: Vec<(AddressFamily, u32)>,
        now: Instant,
    ) -> Vec<Output> {
        let Some(state) = self.peers.get_mut(&addr) else {
            return Vec::new();
        };
        state.info.prefix_limits = limits;
        let over = state
            .info
            .prefix_limits
            .iter()
            .copied()
            .find(|(f, l)| state.received(*f) > u64::from(*l));
        match over {
            Some((family, limit)) => {
                self.prefix_limit_exceeded(addr, family, limit, Vec::new(), now)
            }
            None => Vec::new(),
        }
    }

    /// RFC 4271 §6.7 (b): the speaker "terminates the BGP connection with
    /// the neighbor". The routes the peer sent go at once, those of the
    /// UPDATE that crossed the limit included, so none of them is passed
    /// on; the caller sends the Cease (RFC 4486 §4).
    fn prefix_limit_exceeded(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        limit: u32,
        mut dirty: Vec<(AddressFamily, Prefix)>,
        now: Instant,
    ) -> Vec<Output> {
        dirty.extend(self.forget_peer(addr));
        let mut out = vec![Output::PrefixLimitExceeded {
            peer: addr,
            family,
            limit,
        }];
        out.extend(self.reconsider(&dirty, now));
        out
    }

    /// RFC 4760 §7: an incorrect MP attribute from `addr` for `family`.
    /// The speaker "MUST delete all the BGP routes received from that
    /// neighbor whose AFI/SAFI is the same", and "SHOULD ignore all the
    /// subsequent routes with that AFI/SAFI received over that session":
    /// the family stays disabled until the peer goes down. `dirty` gets the
    /// destinations that lost a route.
    fn disable_family(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        dirty: &mut Vec<(AddressFamily, Prefix)>,
    ) {
        let Some(state) = self.peers.get_mut(&addr) else {
            return;
        };
        if !state.disabled.insert(family) {
            // Already disabled: nothing of it is held.
            return;
        }
        state.adj_in_count.insert(family, 0);
        if let Some(table) = self.tables.get_mut(&family) {
            drop_peer_routes(family, table, addr, dirty);
        }
    }

    /// The peer asked for `family` again (RFC 2918 §4): resend the
    /// Adj-RIB-Out in full, held destinations as they are now. Also used
    /// to build the initial one. Every destination's interval restarts.
    pub fn refresh(&mut self, addr: IpAddr, family: AddressFamily, now: Instant) -> Vec<Output> {
        let now = self.now(now);
        let Some(state) = self.peers.get(&addr) else {
            return Vec::new();
        };
        if !state.info.speaks(family) {
            return Vec::new();
        }
        let info = state.info.clone();
        let mut batch = Batch::default();
        let mut routes = Vec::new();
        for (prefix, best) in self.bests(family) {
            if let Some(a) = self.exported(family, prefix, &best, &info) {
                batch.announce(&a, prefix);
                routes.push((prefix, a));
            }
        }
        if let Some(state) = self.peers.get_mut(&addr) {
            batch.withdraw = state
                .adj_out
                .entry(family)
                .or_default()
                .readvertise(routes, now);
        }
        Rib::emit(&info, family, &batch)
    }

    /// Re-run export for `addr` and `family` after a policy change: only
    /// what differs from the Adj-RIB-Out is sent (announcements for new
    /// or changed routes, withdrawals for routes no longer exported),
    /// paced like any other change (RFC 4271 §9.2.1.1).
    pub fn reexport(&mut self, addr: IpAddr, family: AddressFamily, now: Instant) -> Vec<Output> {
        let now = self.now(now);
        let Some(state) = self.peers.get(&addr) else {
            return Vec::new();
        };
        if !state.info.speaks(family) {
            return Vec::new();
        }
        let info = state.info.clone();
        let mut batch = Batch::default();
        for (prefix, best) in self.bests(family) {
            let desired = self.exported(family, prefix, &best, &info);
            self.offer(addr, family, prefix, desired, now, &mut batch);
        }
        // Destinations the peer has that no longer have a route at all.
        let table = self.tables.get(&family);
        let gone: Vec<Prefix> = self
            .peers
            .get(&addr)
            .and_then(|s| s.adj_out.get(&family))
            .into_iter()
            .flat_map(AdjRibOut::prefixes)
            .filter(|p| {
                table
                    .and_then(|t| t.get(p))
                    .and_then(|d| d.best.as_ref())
                    .is_none()
            })
            .collect();
        for prefix in gone {
            self.offer(addr, family, prefix, None, now, &mut batch);
        }
        Rib::emit(&info, family, &batch)
    }

    /// Change the `MinRouteAdvertisementIntervalTimer` of peer `addr`
    /// (RFC 4271 §9.2.1.1). Held destinations move to the new end of
    /// their interval, and go out now if that has passed.
    pub fn set_advertisement_interval(
        &mut self,
        addr: IpAddr,
        interval: Duration,
        now: Instant,
    ) -> Vec<Output> {
        let pace_now = self.now(now);
        let Some(state) = self.peers.get_mut(&addr) else {
            return Vec::new();
        };
        if state.info.advertisement_interval == interval {
            return Vec::new();
        }
        state.info.advertisement_interval = interval;
        let mut pace = Pace {
            interval,
            now: pace_now,
            jitter: &mut self.jitter,
        };
        for (family, adj) in &mut state.adj_out {
            for (prefix, at) in adj.reschedule(&mut pace) {
                if adj.queue(prefix, at) {
                    self.deadlines.push(Reverse(Deadline {
                        at,
                        peer: addr,
                        family: *family,
                        prefix,
                    }));
                }
            }
        }
        self.flush(now)
    }

    /// When [`Rib::flush`] next has something to do, if ever: the owner
    /// calls it then. Stale wake-ups make this early at worst, never late.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        let clock = self.clock?;
        let Reverse(d) = self.deadlines.peek()?;
        clock.instant(d.at)
    }

    /// Send what the interval held back and may go out by `now`: for each
    /// such destination, the route it has now, if that differs from what
    /// the peer has (RFC 4271 §9.2.1.1). Every Loc-RIB change, whatever
    /// caused it, is offered to each peer's pacing; what it holds back
    /// comes out here.
    pub fn flush(&mut self, now: Instant) -> Vec<Output> {
        let Some(clock) = self.clock else {
            return Vec::new();
        };
        let now = clock.now(now);
        let mut due = Vec::new();
        while let Some(Reverse(d)) = self.deadlines.peek()
            && d.at <= now.floor
        {
            due.push(*d);
            self.deadlines.pop();
        }
        if due.is_empty() {
            return Vec::new();
        }
        shrink_heap(&mut self.deadlines);
        // One batch per peer and family, so that what is released together
        // is packed together (RFC 4271 §9.2).
        due.sort_unstable_by_key(|d| (d.peer, d.family, d.prefix, d.at));
        let mut out = Vec::new();
        for group in due.chunk_by(|a, b| a.peer == b.peer && a.family == b.family) {
            let (peer, family) = (group[0].peer, group[0].family);
            let Some(info) = self.peers.get(&peer).map(|s| s.info.clone()) else {
                continue;
            };
            let mut batch = Batch::default();
            for d in group {
                let Some(adj) = self
                    .peers
                    .get_mut(&peer)
                    .and_then(|s| s.adj_out.get_mut(&family))
                else {
                    break;
                };
                // One that an earlier wake-up replaced: nothing to do.
                if !adj.fired(d.prefix, d.at) {
                    continue;
                }
                let wake = adj.wake(d.prefix, info.advertisement_interval, now);
                if let Some(at) = wake.again
                    && adj.queue(d.prefix, at)
                {
                    self.deadlines.push(Reverse(Deadline { at, ..*d }));
                }
                if !wake.release {
                    continue;
                }
                let desired = self
                    .best(family, d.prefix)
                    .and_then(|b| self.exported(family, d.prefix, &b, &info));
                let Some(state) = self.peers.get_mut(&peer) else {
                    break;
                };
                let mut pace = Pace {
                    interval: state.info.advertisement_interval,
                    now,
                    jitter: &mut self.jitter,
                };
                let adj = state.adj_out.entry(family).or_default();
                let step = adj.release(d.prefix, desired, &mut pace);
                record(
                    step,
                    adj,
                    (peer, family, d.prefix),
                    &mut batch,
                    &mut self.deadlines,
                );
            }
            if let Some(adj) = self
                .peers
                .get_mut(&peer)
                .and_then(|s| s.adj_out.get_mut(&family))
            {
                adj.compact();
            }
            out.extend(Rib::emit(&info, family, &batch));
        }
        out
    }

    /// What the RIB knows about peer `addr`, if it is up.
    #[must_use]
    pub fn peer(&self, addr: IpAddr) -> Option<&PeerInfo> {
        self.peers.get(&addr).map(|p| &p.info)
    }

    /// An UPDATE from `addr`: disable the families its incorrect MP
    /// attributes named (RFC 4760 §7), apply its withdrawals and
    /// announcements to the Adj-RIB-In, rerun the decision process for the
    /// destinations touched, and produce the FIB changes and UPDATEs that
    /// follow, after an [`Output::InvalidNextHop`] for each part of the
    /// UPDATE whose routes were ignored. Routes of a family we did not
    /// advertise to the peer are ignored (RFC 4760 §8).
    pub fn update(&mut self, addr: IpAddr, update: &DecodedUpdate, now: Instant) -> Vec<Output> {
        let Some(state) = self.peers.get(&addr) else {
            return Vec::new();
        };
        let info = state.info.clone();
        let mut dirty = Vec::new();
        // RFC 4760 §7, before anything else in the UPDATE, so that none of
        // the disabled family's routes in it counts either (RFC 7606 §3 h:
        // the strongest approach wins).
        for d in &update.disabled {
            self.disable_family(addr, d.family, &mut dirty);
        }
        let disabled = self
            .peers
            .get(&addr)
            .map(|s| s.disabled.clone())
            .unwrap_or_default();
        // RFC 4760 §8 needs both sides to advertise a family only for a
        // bi-directional exchange: our capability is what lets the peer
        // send routes of one (RFC 5492 §3), so those of every family we
        // advertised are taken, negotiated or not. Routes of a family we
        // did not advertise are ignored, as are those of a family disabled
        // by RFC 4760 §7.
        let unused = |family: AddressFamily| disabled.contains(&family) || !info.receives(family);
        for (family, prefix) in update.withdrawals() {
            if unused(family) {
                continue;
            }
            self.remove_route(addr, family, prefix, &mut dirty);
        }
        let mut ignored = Vec::new();
        for (family, next_hop, prefixes) in attrs::announced(update) {
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
                for &prefix in prefixes {
                    self.remove_route(addr, family, prefix, &mut dirty);
                }
                ignored.push(Output::InvalidNextHop {
                    peer: addr,
                    family,
                    next_hop,
                    prefixes: prefixes.to_vec(),
                });
                continue;
            }
            let attrs = self
                .interner
                .intern(PathAttrs::from_update(&update.message, next_hop));
            // RFC 4271 §9.1.2: a route whose AS_PATH contains our AS is an
            // AS loop and is excluded from Phase 2. RFC 4271 §6.3 and RFC
            // 7606 §7.2: on an external session the leftmost AS must be the
            // peer's, else the route is treated as withdrawn. Neither kind
            // is kept in the Adj-RIB-In: no import policy can make it
            // usable, and our AS is fixed for the life of the RIB.
            if !self.usable(&info, &attrs) {
                for &prefix in prefixes {
                    self.remove_route(addr, family, prefix, &mut dirty);
                }
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
            let origin = RouteOrigin::from_as_path(&attrs.as_path, self.local_as);
            let aspa = self.validation.aspa(&attrs.as_path);
            let limit = info.prefix_limit(family);
            for &prefix in prefixes {
                let route = Received {
                    peer: addr,
                    attrs: Arc::clone(&attrs),
                    rov: self.validation.rov(prefix, origin),
                    aspa,
                };
                self.announce(&info, family, prefix, route, &mut dirty);
                // RFC 4271 §6.7: "the number of address prefixes received
                // from the neighbor exceeds the locally-configured, upper
                // bound". Counted are the routes the Adj-RIB-In holds,
                // whether import policy accepted them or not: every route
                // the peer advertises and has not withdrawn, less those
                // the loop checks above drop. The Adj-RIB-In keeps what
                // import policy rejects, so that policy can run again when
                // its input changes, and those routes take the memory the
                // limit is there to bound. Counted this way, only the
                // peer's UPDATEs move the count: a change of policy never
                // ends a session.
                // NOTE(interop): BIRD's `receive limit` counts the same
                // routes; BIRD's `import limit` and FRR's `maximum-prefix`
                // without `force` count only those import policy accepts.
                if let Some(limit) = limit
                    && self.received(addr, family) > u64::from(limit)
                {
                    let mut out = self.prefix_limit_exceeded(addr, family, limit, dirty, now);
                    out.append(&mut ignored);
                    return out;
                }
            }
        }
        ignored.extend(self.reconsider(&dirty, now));
        ignored
    }

    /// Drop the route `addr` sent for `prefix` from the Adj-RIB-In, if
    /// there is one; `dirty` gets the destination when that changes its
    /// candidates.
    fn remove_route(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        prefix: Prefix,
        dirty: &mut Vec<(AddressFamily, Prefix)>,
    ) {
        let Some(table) = self.tables.get_mut(&family) else {
            return;
        };
        let Some(dest) = table.get_mut(&prefix) else {
            return;
        };
        let Some(i) = dest.received.iter().position(|r| r.peer == addr) else {
            return;
        };
        dest.received.remove(i);
        if remove_candidate(dest, addr) {
            dirty.push((family, prefix));
        } else if dest.is_unused() {
            table.remove(&prefix);
        }
        self.count(addr, family, -1);
    }

    /// Routes of `family` from `addr` in the Adj-RIB-In.
    fn received(&self, addr: IpAddr, family: AddressFamily) -> u64 {
        self.peers.get(&addr).map_or(0, |s| s.received(family))
    }

    /// Whether routes from `info`'s peer with `attrs` pass the checks no
    /// policy can override: no AS loop (RFC 4271 §9.1.2), and on an
    /// external session the peer's AS leftmost (RFC 4271 §6.3, RFC 7606
    /// §7.2).
    fn usable(&self, info: &PeerInfo, attrs: &PathAttrs) -> bool {
        let leftmost_ok =
            info.kind == PeerKind::Internal || attrs.as_path.first_asn() == Some(info.remote_as);
        leftmost_ok && !attrs.as_path.contains(self.local_as)
    }

    /// `route`, announced by `info`'s peer for `prefix`, into the
    /// Adj-RIB-In in place of any route the peer sent for it before, and
    /// through import policy into the candidates; `dirty` gets the
    /// destination if its candidates changed.
    fn announce(
        &mut self,
        info: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        route: Received,
        dirty: &mut Vec<(AddressFamily, Prefix)>,
    ) {
        let peer = route.peer;
        let dest = self
            .tables
            .entry(family)
            .or_default()
            .entry(prefix)
            .or_default();
        let (held, fresh) = if let Some(i) = dest.received.iter().position(|r| r.peer == peer) {
            dest.received[i] = route;
            (i, false)
        } else {
            push_one(&mut dest.received, route);
            (dest.received.len() - 1, true)
        };
        if import(
            &*self.policies,
            &mut self.interner,
            info,
            (family, prefix),
            &dest.received[held],
            &mut dest.candidates,
        ) {
            dirty.push((family, prefix));
        }
        if fresh {
            self.count(peer, family, 1);
        }
    }

    /// The Loc-RIB of `family`, best routes in prefix order.
    pub fn loc_rib(&self, family: AddressFamily) -> impl Iterator<Item = (Prefix, &BestRoute)> {
        self.tables
            .get(&family)
            .into_iter()
            .flat_map(|t| t.iter())
            .filter_map(|(p, d)| d.best.as_ref().map(|b| (*p, b)))
    }

    /// Every route to `prefix` in the Adj-RIBs-In.
    #[must_use]
    pub fn candidates(&self, family: AddressFamily, prefix: Prefix) -> &[Candidate] {
        self.tables
            .get(&family)
            .and_then(|t| t.get(&prefix))
            .map_or(&[], |d| d.candidates.as_slice())
    }

    /// The Adj-RIB-Out for `addr` and `family`.
    pub fn adj_rib_out(
        &self,
        addr: IpAddr,
        family: AddressFamily,
    ) -> impl Iterator<Item = (Prefix, &Arc<PathAttrs>)> {
        self.peers
            .get(&addr)
            .and_then(|p| p.adj_out.get(&family))
            .into_iter()
            .flat_map(AdjRibOut::iter)
    }

    /// Route counts for `addr`.
    #[must_use]
    pub fn peer_stats(&self, addr: IpAddr) -> Option<PeerStats> {
        let p = self.peers.get(&addr)?;
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
            stats
                .received
                .push((family, p.adj_in_count.get(&family).copied().unwrap_or(0)));
        }
        for family in &p.info.families {
            stats
                .advertised
                .push((*family, p.adj_out.get(family).map_or(0, AdjRibOut::len)));
        }
        Some(stats)
    }

    /// Peers currently up.
    pub fn peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values().map(|p| &p.info)
    }

    /// Distinct attribute sets held.
    #[must_use]
    pub fn attribute_sets(&self) -> usize {
        self.interner.len()
    }

    fn count(&mut self, addr: IpAddr, family: AddressFamily, delta: isize) {
        if let Some(state) = self.peers.get_mut(&addr) {
            let n = state.adj_in_count.entry(family).or_insert(0);
            *n = n.saturating_add_signed(delta);
        }
    }

    /// Rerun Phase 2 for each dirty destination and Phase 3 for every
    /// destination whose best route changed. Phase 3 goes through the
    /// pacing of each peer (RFC 4271 §9.2.1.1), so every Loc-RIB change,
    /// whatever caused it, is rate-limited the same way.
    fn reconsider(&mut self, dirty: &[(AddressFamily, Prefix)], now: Instant) -> Vec<Output> {
        let now = self.now(now);
        let mut out = Vec::new();
        let mut batches: HashMap<(IpAddr, AddressFamily), Batch> = HashMap::new();
        let mut seen = HashSet::new();
        // The peers do not change while the decision runs: taken once,
        // not once per destination.
        let infos: Vec<PeerInfo> = if dirty.is_empty() {
            Vec::new()
        } else {
            self.peers.values().map(|p| p.info.clone()).collect()
        };
        for &(family, prefix) in dirty {
            if !seen.insert((family, prefix)) {
                continue;
            }
            let Some(table) = self.tables.get_mut(&family) else {
                continue;
            };
            let Some(dest) = table.get_mut(&prefix) else {
                continue;
            };
            let new_best =
                decision::best(&dest.candidates).map(|i| BestRoute::of(&dest.candidates[i]));
            // Whether another route is chosen, and whether the chosen one
            // has another validation state.
            let (route_changed, state_changed) = match (&dest.best, &new_best) {
                (None, None) => (false, false),
                (Some(a), Some(b)) => (
                    a.peer != b.peer || !Arc::ptr_eq(&a.attrs, &b.attrs),
                    a.rov != b.rov || a.aspa != b.aspa,
                ),
                _ => (true, true),
            };
            if !route_changed && !state_changed {
                // A destination created and emptied before it was ever
                // decided (a prefix limit drops the UPDATE's own routes).
                if dest.is_unused() {
                    table.remove(&prefix);
                }
                continue;
            }
            dest.best.clone_from(&new_best);
            if dest.is_unused() {
                table.remove(&prefix);
            }
            // RFC 4271 §9.3: the FIB follows the chosen route; its
            // validation state alone changes nothing there.
            if route_changed {
                out.push(Output::Fib(FibChange {
                    family,
                    prefix,
                    next_hop: new_best.as_ref().map(|b| b.attrs.next_hop_addr()),
                }));
            }
            // Phase 3: every peer's Adj-RIB-Out follows. Export policy
            // sees the validation state, so a new state alone runs it
            // again; the pacing sends nothing to a peer whose route
            // stays the same.
            for info in &infos {
                let exported = new_best
                    .as_ref()
                    .and_then(|b| self.exported(family, prefix, b, info));
                let batch = batches.entry((info.addr, family)).or_default();
                self.offer(info.addr, family, prefix, exported, now, batch);
            }
        }
        let mut keys: Vec<_> = batches.keys().copied().collect();
        keys.sort();
        for key in keys {
            let batch = &batches[&key];
            if let Some(state) = self.peers.get(&key.0) {
                let info = state.info.clone();
                out.extend(Rib::emit(&info, key.1, batch));
            }
        }
        out
    }

    /// Offer `desired` for `prefix` to `peer`'s pacing and put what it
    /// says to send now into `batch`.
    fn offer(
        &mut self,
        peer: IpAddr,
        family: AddressFamily,
        prefix: Prefix,
        desired: Option<Arc<PathAttrs>>,
        now: Now,
        batch: &mut Batch,
    ) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        let mut pace = Pace {
            interval: state.info.advertisement_interval,
            now,
            jitter: &mut self.jitter,
        };
        let adj = state.adj_out.entry(family).or_default();
        let step = adj.offer(prefix, desired, &mut pace);
        record(
            step,
            adj,
            (peer, family, prefix),
            batch,
            &mut self.deadlines,
        );
    }

    /// The pacing time of `now`; the first instant ever given is tick 0.
    fn now(&mut self, now: Instant) -> Now {
        self.clock.get_or_insert(Clock::new(now)).now(now)
    }

    /// The best route to every destination of `family`, in prefix order.
    fn bests(&self, family: AddressFamily) -> Vec<(Prefix, BestRoute)> {
        self.tables
            .get(&family)
            .into_iter()
            .flat_map(|t| t.iter())
            .filter_map(|(p, d)| d.best.clone().map(|b| (*p, b)))
            .collect()
    }

    /// The best route to `prefix`.
    fn best(&self, family: AddressFamily, prefix: Prefix) -> Option<BestRoute> {
        self.tables.get(&family)?.get(&prefix)?.best.clone()
    }

    /// The interned attributes `best` is advertised with to `to`, if any:
    /// export policy first (RFC 4271 §9.1.3), then the session rewriting
    /// of §5.1.
    fn exported(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        best: &BestRoute,
        to: &PeerInfo,
    ) -> Option<Arc<PathAttrs>> {
        let kind = self
            .peers
            .get(&best.peer)
            .map_or(PeerKind::External, |p| p.info.kind);
        let source = Source {
            peer: best.peer,
            kind,
        };
        // The route is not offered to the policy at all when §9.2 rules
        // it out, so a policy cannot override those.
        if !export::eligible(family, source, to) {
            return None;
        }
        let modified;
        let verdict = self
            .policies
            .export(to, family, prefix, &best.attrs, best.rov);
        let attrs: &PathAttrs = match verdict {
            Verdict::Reject => return None,
            Verdict::Accept => &best.attrs,
            Verdict::Modified(a) => {
                modified = a;
                &modified
            }
        };
        export::export(self.local_as, family, source, attrs, to).map(|a| self.interner.intern(a))
    }

    fn emit(to: &PeerInfo, family: AddressFamily, batch: &Batch) -> Vec<Output> {
        if batch.is_empty() {
            return Vec::new();
        }
        match batch.encode(family, to) {
            Ok(messages) => vec![Output::Send {
                peer: to.addr,
                messages,
            }],
            Err(error) => vec![Output::EncodeFailed {
                peer: to.addr,
                error,
            }],
        }
    }
}

/// Put a pacing decision for `prefix` of `peer` and `family` into
/// `batch`, and its wake-up, if it needs one that `adj` has not queued
/// yet, into `deadlines`.
fn record(
    step: Step,
    adj: &mut AdjRibOut,
    (peer, family, prefix): (IpAddr, AddressFamily, Prefix),
    batch: &mut Batch,
    deadlines: &mut BinaryHeap<Reverse<Deadline>>,
) {
    let wake = match step {
        Step::Quiet => None,
        Step::Announce(a) => {
            batch.announce(&a, prefix);
            None
        }
        Step::Withdraw { forget } => {
            batch.withdraw.push(prefix);
            forget
        }
        Step::Hold(at) => Some(at),
    };
    if let Some(at) = wake
        && adj.queue(prefix, at)
    {
        deadlines.push(Reverse(Deadline {
            at,
            peer,
            family,
            prefix,
        }));
    }
}

/// `heap` with its capacity cut down once it is less than a quarter used,
/// so that a burst of churn does not keep its memory.
fn shrink_heap<T: Ord>(heap: &mut BinaryHeap<T>) {
    if heap.capacity() > 64 && heap.len() < heap.capacity() / 4 {
        heap.shrink_to(heap.len() * 2);
    }
}

/// Remove `peer`'s candidate; whether there was one.
fn remove_candidate(dest: &mut Destination, peer: IpAddr) -> bool {
    let before = dest.candidates.len();
    dest.candidates.retain(|c| c.peer != peer);
    dest.candidates.len() != before
}

/// Remove every route `peer` sent from `table`, a table of `family`:
/// `dirty` gets the destinations whose candidates changed, and those left
/// with nothing to decide go.
fn drop_peer_routes(
    family: AddressFamily,
    table: &mut BTreeMap<Prefix, Destination>,
    peer: IpAddr,
    dirty: &mut Vec<(AddressFamily, Prefix)>,
) {
    table.retain(|prefix, dest| {
        dest.received.retain(|r| r.peer != peer);
        if remove_candidate(dest, peer) {
            dirty.push((family, *prefix));
        }
        // One with a best route stays for the decision process, which
        // withdraws it and then removes the destination.
        !dest.is_unused()
    });
}

/// Push onto a per-destination list. Most destinations are heard from one
/// peer, so the first entry gets room for itself alone rather than the
/// four a `Vec` would make; a second one grows it as usual.
fn push_one<T>(list: &mut Vec<T>, item: T) {
    if list.capacity() == 0 {
        list.reserve_exact(1);
    }
    list.push(item);
}

/// RFC 4271 §9.1.1: import policy decides whether `route`, as the
/// Adj-RIB-In holds it for `prefix` of `family`, is a candidate for
/// Phase 2, and with which attributes; the candidate carries the route's
/// validation state. `candidates` gets the outcome in place of what it
/// held for the route's peer; whether that changed them.
///
/// Every route reaches the candidates through here, whatever made it
/// worth deciding again.
fn import(
    policies: &dyn Policies,
    interner: &mut Interner,
    info: &PeerInfo,
    (family, prefix): (AddressFamily, Prefix),
    route: &Received,
    candidates: &mut Vec<Candidate>,
) -> bool {
    let accepted = match policies.import(info, family, prefix, &route.attrs, route.rov) {
        Verdict::Accept => Some(Arc::clone(&route.attrs)),
        Verdict::Modified(a) => Some(interner.intern(a)),
        Verdict::Reject => None,
    };
    let held = candidates.iter().position(|c| c.peer == route.peer);
    match (accepted, held) {
        (None, None) => false,
        (None, Some(i)) => {
            candidates.remove(i);
            true
        }
        (Some(attrs), Some(i)) => {
            let c = &mut candidates[i];
            if Arc::ptr_eq(&c.attrs, &attrs) && c.rov == route.rov && c.aspa == route.aspa {
                // An implicit re-announcement of the same route.
                return false;
            }
            c.attrs = attrs;
            c.rov = route.rov;
            c.aspa = route.aspa;
            true
        }
        (Some(attrs), None) => {
            push_one(
                candidates,
                Candidate {
                    peer: route.peer,
                    kind: info.kind,
                    router_id: info.router_id.to_u32(),
                    remote_as: info.remote_as,
                    attrs,
                    rov: route.rov,
                    aspa: route.aspa,
                },
            );
            true
        }
    }
}
