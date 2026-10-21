//! Adj-RIB-In, Loc-RIB, Adj-RIB-Out and the decision process
//! (AGENTS.md §3, "RIB thread": the only owner of all RIB state, driven
//! by messages, no I/O).
//!
//! Implements: RFC 4271 §3.2 (the three RIBs), §9.1 (the decision
//! process: Phase 1 degree of preference, Phase 2 route selection,
//! Phase 3 route dissemination), §9.1.2 (AS loop exclusion), §9.1.4
//! (overlapping routes are independent destinations), §9.2 (update
//! generation), §9.2.1.1 (`MinRouteAdvertisementIntervalTimer`, see
//! [`pacing`]), §9.3 (Loc-RIB changes are reported for the FIB), §6.3
//! and RFC 7606 §7.2 (leftmost AS of an external route is the peer's);
//! RFC 4760 §3, §5, §7 (each NLRI field with its own next hop, per-family
//! RIBs, family disable); RFC 2918 §4 (route refresh re-sends the
//! Adj-RIB-Out); RFC 8950 §3–§5 (IPv4 routes with an IPv6 next hop, see
//! [`export`]).
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

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn};
use bgpfc_wire::update::{DecodedUpdate, PeerKind};

pub use attrs::{Interner, PathAttrs};
pub use decision::Candidate;
pub use export::{Batch, Source};
pub use peer::PeerInfo;

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

/// The best route to a destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BestRoute {
    /// The peer it came from.
    pub peer: IpAddr,
    /// Its attributes.
    pub attrs: Arc<PathAttrs>,
}

/// One destination: every eligible route to it and the chosen one.
#[derive(Debug, Default)]
struct Destination {
    candidates: Vec<Candidate>,
    best: Option<BestRoute>,
}

struct PeerState {
    info: PeerInfo,
    /// Families disabled after a malformed multiprotocol attribute
    /// (RFC 4760 §7); no more routes are accepted for them.
    disabled: HashSet<AddressFamily>,
    /// Adj-RIB-Out: what the peer was last told, per family, with the
    /// RFC 4271 §9.2.1.1 pacing state.
    adj_out: HashMap<AddressFamily, AdjRibOut>,
    /// Routes held in the Adj-RIB-In per family (for statistics).
    adj_in_count: HashMap<AddressFamily, usize>,
}

/// Counters about one peer, for the control plane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Routes accepted from the peer, per family.
    pub received: Vec<(AddressFamily, usize)>,
    /// Routes advertised to the peer, per family.
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
    /// Adj-RIBs-In and Loc-RIB together: every candidate per destination
    /// and the best among them.
    tables: HashMap<AddressFamily, BTreeMap<Prefix, Destination>>,
    interner: Interner,
    /// Pending wake-ups, earliest first. Entries made stale by later
    /// changes stay until due and are then ignored.
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
    #[must_use]
    pub fn with_policies(local_as: Asn, policies: Box<dyn Policies>) -> Rib {
        Rib {
            local_as,
            policies,
            peers: HashMap::new(),
            tables: HashMap::new(),
            interner: Interner::default(),
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
        let Some(state) = self.peers.remove(&addr) else {
            return Vec::new();
        };
        let mut dirty: Vec<(AddressFamily, Prefix)> = Vec::new();
        for family in &state.info.families {
            if let Some(table) = self.tables.get_mut(family) {
                for (prefix, dest) in table.iter_mut() {
                    if remove_candidate(dest, addr) {
                        dirty.push((*family, *prefix));
                    }
                }
            }
        }
        self.reconsider(&dirty, now)
    }

    /// Stop accepting `family` from `addr` and drop what it sent
    /// (RFC 4760 §7).
    pub fn family_disabled(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        now: Instant,
    ) -> Vec<Output> {
        let Some(state) = self.peers.get_mut(&addr) else {
            return Vec::new();
        };
        state.disabled.insert(family);
        state.adj_in_count.insert(family, 0);
        let mut dirty = Vec::new();
        if let Some(table) = self.tables.get_mut(&family) {
            for (prefix, dest) in table.iter_mut() {
                if remove_candidate(dest, addr) {
                    dirty.push((family, *prefix));
                }
            }
        }
        self.reconsider(&dirty, now)
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
                self.deadlines.push(Reverse(Deadline {
                    at,
                    peer: addr,
                    family: *family,
                    prefix,
                }));
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
        // One batch per peer and family, so that what is released together
        // is packed together (RFC 4271 §9.2).
        due.sort_unstable_by_key(|d| (d.peer, d.family, d.prefix));
        due.dedup_by_key(|d| (d.peer, d.family, d.prefix));
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
                let wake = adj.wake(d.prefix, info.advertisement_interval, now);
                if let Some(at) = wake.again {
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
                let step = state
                    .adj_out
                    .entry(family)
                    .or_default()
                    .release(d.prefix, desired, &mut pace);
                record(
                    step,
                    peer,
                    family,
                    d.prefix,
                    &mut batch,
                    &mut self.deadlines,
                );
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

    /// An UPDATE from `addr`: apply its withdrawals and announcements to
    /// the Adj-RIB-In, rerun the decision process for the destinations
    /// touched, and produce the FIB changes and UPDATEs that follow.
    pub fn update(&mut self, addr: IpAddr, update: &DecodedUpdate, now: Instant) -> Vec<Output> {
        let Some(state) = self.peers.get(&addr) else {
            return Vec::new();
        };
        let info = state.info.clone();
        let disabled = state.disabled.clone();
        let mut dirty = Vec::new();
        for (family, prefix) in update.withdrawals() {
            if disabled.contains(&family) {
                continue;
            }
            if let Some(dest) = self
                .tables
                .get_mut(&family)
                .and_then(|t| t.get_mut(&prefix))
                && remove_candidate(dest, addr)
            {
                self.count(addr, family, -1);
                dirty.push((family, prefix));
            }
        }
        for (family, next_hop, prefixes) in attrs::announced(update) {
            if disabled.contains(&family) {
                continue;
            }
            let attrs = self
                .interner
                .intern(PathAttrs::from_update(&update.message, next_hop));
            for &prefix in prefixes {
                self.announce(addr, &info, family, prefix, &attrs, &mut dirty);
            }
        }
        self.reconsider(&dirty, now)
    }

    /// One announced route from `addr` into the Adj-RIB-In, after the loop
    /// checks and import policy; `dirty` gets the destination if anything
    /// changed.
    fn announce(
        &mut self,
        addr: IpAddr,
        info: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        attrs: &Arc<PathAttrs>,
        dirty: &mut Vec<(AddressFamily, Prefix)>,
    ) {
        // RFC 4271 §9.1.2: a route whose AS_PATH contains our AS is an AS
        // loop and is excluded from Phase 2. RFC 4271 §6.3 and RFC 7606
        // §7.2: on an external session the leftmost AS must be the peer's,
        // else the route is treated as withdrawn. Neither kind is stored.
        let leftmost_ok =
            info.kind == PeerKind::Internal || attrs.as_path.first_asn() == Some(info.remote_as);
        // RFC 4271 §9.1.1: import policy decides what enters, and may
        // change attributes (the degree of preference among them).
        let accepted = if attrs.as_path.contains(self.local_as) || !leftmost_ok {
            None
        } else {
            match self.policies.import(info, family, prefix, attrs) {
                Verdict::Accept => Some(Arc::clone(attrs)),
                Verdict::Modified(a) => Some(self.interner.intern(a)),
                Verdict::Reject => None,
            }
        };
        let Some(attrs) = accepted else {
            if let Some(dest) = self
                .tables
                .get_mut(&family)
                .and_then(|t| t.get_mut(&prefix))
                && remove_candidate(dest, addr)
            {
                self.count(addr, family, -1);
                dirty.push((family, prefix));
            }
            return;
        };
        let dest = self
            .tables
            .entry(family)
            .or_default()
            .entry(prefix)
            .or_default();
        let candidate = Candidate {
            peer: addr,
            kind: info.kind,
            router_id: info.router_id.to_u32(),
            remote_as: info.remote_as,
            attrs,
        };
        if let Some(c) = dest.candidates.iter_mut().find(|c| c.peer == addr) {
            if Arc::ptr_eq(&c.attrs, &candidate.attrs) {
                // An implicit re-announcement of the same route.
                return;
            }
            *c = candidate;
        } else {
            dest.candidates.push(candidate);
            self.count(addr, family, 1);
        }
        dirty.push((family, prefix));
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
        for family in &p.info.families {
            stats
                .received
                .push((*family, p.adj_in_count.get(family).copied().unwrap_or(0)));
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
            let new_best = decision::best(&dest.candidates).map(|i| BestRoute {
                peer: dest.candidates[i].peer,
                attrs: Arc::clone(&dest.candidates[i].attrs),
            });
            let changed = match (&dest.best, &new_best) {
                (None, None) => false,
                (Some(a), Some(b)) => a.peer != b.peer || !Arc::ptr_eq(&a.attrs, &b.attrs),
                _ => true,
            };
            if !changed {
                continue;
            }
            dest.best.clone_from(&new_best);
            if dest.candidates.is_empty() {
                table.remove(&prefix);
            }
            out.push(Output::Fib(FibChange {
                family,
                prefix,
                next_hop: new_best.as_ref().map(|b| b.attrs.next_hop_addr()),
            }));
            // Phase 3: every peer's Adj-RIB-Out follows.
            let infos: Vec<PeerInfo> = self.peers.values().map(|p| p.info.clone()).collect();
            for info in infos {
                let exported = new_best
                    .as_ref()
                    .and_then(|b| self.exported(family, prefix, b, &info));
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
        let step = state
            .adj_out
            .entry(family)
            .or_default()
            .offer(prefix, desired, &mut pace);
        record(step, peer, family, prefix, batch, &mut self.deadlines);
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
        let attrs: &PathAttrs = match self.policies.export(to, family, prefix, &best.attrs) {
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

/// Put a pacing decision for `prefix` into `batch`, and its wake-up, if
/// any, into `deadlines`.
fn record(
    step: Step,
    peer: IpAddr,
    family: AddressFamily,
    prefix: Prefix,
    batch: &mut Batch,
    deadlines: &mut BinaryHeap<Reverse<Deadline>>,
) {
    let wake = |at| {
        Reverse(Deadline {
            at,
            peer,
            family,
            prefix,
        })
    };
    match step {
        Step::Quiet => {}
        Step::Announce(a) => batch.announce(&a, prefix),
        Step::Withdraw { forget } => {
            batch.withdraw.push(prefix);
            if let Some(at) = forget {
                deadlines.push(wake(at));
            }
        }
        Step::Hold(at) => deadlines.push(wake(at)),
    }
}

/// Remove `peer`'s candidate; whether there was one.
fn remove_candidate(dest: &mut Destination, peer: IpAddr) -> bool {
    let before = dest.candidates.len();
    dest.candidates.retain(|c| c.peer != peer);
    dest.candidates.len() != before
}
