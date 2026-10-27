//! Validation states that follow the validation source (issue #56).
//!
//! Every route in an Adj-RIB-In carries the validation state the current
//! [`ValidationSource`] gives it. When the source changes, the routes it
//! may judge differently are validated again in place, and those whose
//! state changed go through import policy and the decision process again,
//! the way an UPDATE takes them.
//!
//! The same walk judges every route again when the operator's
//! enforcement mode changes ([`Rib::set_enforcement`]), and every route not
//! validated yet when the startup setting changes ([`Rib::set_startup`]).
//!
//! Implements: RFC 6811 §2 ("The validation state of the Route MUST be
//! set to reflect the result of the lookup"), §4 ("When a mapping is added
//! or deleted, the implementation MUST re-validate any affected prefixes
//! and run the BGP decision process if needed"), for the routes that
//! [`AffectedPrefixes`] names; §5 (a change of what acts on the state
//! runs the decision process again for every route); §2 (routes not
//! validated yet are held only as configured, and judged again when that
//! changes).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Instant;

use bgpfc_rpki::{
    AffectedPrefixes, Enforcement, PrefixSet, RouteOrigin, RovState, Startup, ValidationChange,
    ValidationSource,
};
use bgpfc_wire::prefix::{Ipv4Key, Prefix};
use bgpfc_wire::types::{AddressFamily, Afi, Asn};

use crate::store::{Destination, PeerId, Route, Table};
use crate::{
    Decide, Dirty, Held, Interner, Judged, Output, PeerState, Policies, Rib, Scratch, Sink, judge,
};

/// A table walks its affected destinations in one pass, rather than one
/// range query per range, once it has fewer than this many destinations
/// per range (see [`Rib::validation_changed`]). On a full table a range
/// query costs about 0.6 µs and a pass about 35 ns per destination, so
/// the pass is cheaper from about one range per 17 destinations
/// (`benches/rib.rs`, `revalidate_*`).
const DENSE: usize = 16;

/// What became of a route a change of validation state moved, once the
/// decision process ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteStatus {
    /// The best route to its destination.
    Best,
    /// A candidate, not the best.
    Candidate,
    /// Held in the Adj-RIB-In and no candidate, for this reason.
    Held(Held),
}

/// One route whose RFC 6811 validation state a change of the validation
/// source moved (issue #59: "An operator needs to see that a prefix went
/// Valid → Invalid at a specific time"; the caller adds the time).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    /// The route's family.
    pub family: AddressFamily,
    /// Its destination.
    pub prefix: Prefix,
    /// The peer it came from.
    pub peer: IpAddr,
    /// Its Route Origin ASN (RFC 6811 §2).
    pub origin: RouteOrigin,
    /// The state the lookup gave it before the change: valid, invalid or
    /// not-found.
    pub from: RovState,
    /// The state the lookup gives it now: valid, invalid or not-found.
    pub to: RovState,
    /// What it is after the decision process.
    pub route: RouteStatus,
}

/// What validating routes again after a change of the validation source
/// did (RFC 6811 §4), for the caller to log: counts and a short sample,
/// and the routes that moved among valid, invalid and not-found, at most
/// [`Revalidation::LISTED`] of them, so that a change that moves every
/// route of a full table, as turning validation on or off or the expiry
/// of the VRPs does, costs one bounded report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Revalidation {
    /// Routes held in the Adj-RIBs-In that the change affected, each
    /// validated again.
    pub routes: usize,
    /// How many of them moved from one RFC 6811 state to another:
    /// `(from, to, routes)` for each pair that occurred, in the order of
    /// [`RovState::ALL`] by `from`, then by `to`.
    pub changes: Vec<(RovState, RovState, usize)>,
    /// Destinations with a route whose state changed.
    pub destinations: usize,
    /// The first of those destinations, at most [`Revalidation::SAMPLE`]
    /// of them, IPv4 before IPv6 and each in prefix order.
    pub sample: Vec<Prefix>,
    /// Destinations where the decision process then chose another route,
    /// or none: the FIB changes the report comes with.
    pub best_changed: usize,
    /// Routes the change took out of use: candidates before it, held
    /// after it ([`Held`]).
    pub held: usize,
    /// Routes the change put back into use: held before it, candidates
    /// after it.
    pub released: usize,
    /// The routes whose state moved from one RFC 6811 state to another,
    /// at most [`Revalidation::LISTED`], IPv4 before IPv6 and each in
    /// prefix order, with what became of each. A move to or from
    /// `disabled` is validation being switched on or off: counted in
    /// `changes`, never listed. A route that no state lets import policy
    /// accept any more leaves the Adj-RIB-In and is not listed either.
    pub transitions: Vec<Transition>,
    /// The moves among valid, invalid and not-found that `transitions`
    /// does not list.
    pub unlisted: usize,
}

/// What judging every route again under a new enforcement mode did (see
/// [`Rib::set_enforcement`]), for the caller to log: counts, as for a
/// [`Revalidation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejudged {
    /// The mode before.
    pub from: Enforcement,
    /// The mode now.
    pub to: Enforcement,
    /// Routes held in the Adj-RIBs-In, each judged again.
    pub routes: usize,
    /// Routes the new mode took out of use: candidates before, held after.
    pub held: usize,
    /// Routes the new mode put back into use: held before, candidates
    /// after.
    pub released: usize,
    /// Destinations where the decision process then chose another route,
    /// or none.
    pub best_changed: usize,
}

/// What judging every route not validated yet again under a new startup
/// setting did (see [`Rib::set_startup`]), for the caller to log: counts,
/// as for a [`Rejudged`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupChange {
    /// The setting before.
    pub from: Startup,
    /// The setting now.
    pub to: Startup,
    /// Routes used with state `disabled`, each judged again; the others
    /// are not the setting's business.
    pub routes: usize,
    /// Routes the new setting took out of use: candidates before, held
    /// after.
    pub held: usize,
    /// Routes the new setting put back into use: held before, candidates
    /// after.
    pub released: usize,
    /// Destinations where the decision process then chose another route,
    /// or none.
    pub best_changed: usize,
}

impl Revalidation {
    /// The most destinations [`Revalidation::sample`] names.
    pub const SAMPLE: usize = 8;

    /// The most routes [`Revalidation::transitions`] lists: enough for an
    /// ordinary delta, which moves few routes, and a bound on the report
    /// (about 55 KB, 52 bytes a route on a 64-bit target) when a change
    /// moves a whole table.
    pub const LISTED: usize = 1024;

    /// Routes whose state changed.
    #[must_use]
    pub fn changed(&self) -> usize {
        self.changes.iter().map(|c| c.2).sum()
    }
}

/// The counts of a [`Revalidation`] or a [`Rejudged`] as the pass gathers
/// them.
#[derive(Default)]
struct Tally {
    routes: usize,
    /// Routes per (from, to), indexed by [`slot`].
    moved: [[usize; 4]; 4],
    destinations: usize,
    sample: Vec<Prefix>,
    held: usize,
    released: usize,
    transitions: Vec<Transition>,
    unlisted: usize,
}

impl Tally {
    /// The report, with `best_changed` from the decision process that
    /// followed; `None` when no route changed state.
    fn finish(self, best_changed: usize) -> Option<Revalidation> {
        let mut changes = Vec::new();
        for from in RovState::ALL {
            for to in RovState::ALL {
                let n = self.moved[slot(from)][slot(to)];
                if n > 0 {
                    changes.push((from, to, n));
                }
            }
        }
        if changes.is_empty() {
            return None;
        }
        Some(Revalidation {
            routes: self.routes,
            changes,
            destinations: self.destinations,
            sample: self.sample,
            best_changed,
            held: self.held,
            released: self.released,
            transitions: self.transitions,
            unlisted: self.unlisted,
        })
    }
}

/// The index of `state` in [`RovState::ALL`].
fn slot(state: RovState) -> usize {
    match state {
        RovState::Valid => 0,
        RovState::Invalid => 1,
        RovState::NotFound => 2,
        RovState::Disabled => 3,
    }
}

impl Rib {
    /// The validation source changed (issue #56): use `change.source` from
    /// now on, and validate again every route held in an Adj-RIB-In that
    /// `change.affected` covers (RFC 6811 §4), in place. Each route whose
    /// state changed goes through import policy again, which sees the new
    /// state, and its destination through the decision process; the
    /// Adj-RIB-In keeps it whatever policy now says of it, as it did
    /// before, since policy accepts it with some state (see `judge`). What
    /// follows comes out as it does for an UPDATE, after one
    /// [`Output::Revalidated`] that counts the changes, if any route's
    /// state changed: FIB changes, and UPDATEs sent or held back by the
    /// RFC 4271 §9.2.1.1 pacing. Routes import policy rejected for their
    /// state are validated again too, since the new state may make policy
    /// accept them.
    ///
    /// Changes must be given in the order the producer made them; a run
    /// of them may be given as one, with the last source and every
    /// affected set merged (see [`ValidationChange`]).
    ///
    /// Finding the affected routes: a table is in prefix order, and the
    /// prefixes one changed prefix covers (RFC 6811 §2) are one range of
    /// that order, so the changed prefixes become ranges, sorted, those
    /// inside another dropped. A small delta then costs a range query per
    /// range, a descent of the tree plus the routes in range, and never
    /// visits a destination outside the ranges: 1000 changed VRP prefixes
    /// against a full table are 1000 descents, not a scan. A table with
    /// fewer than 16 destinations per range is walked once instead,
    /// alongside the sorted ranges, as that is then the cheaper of the
    /// two: a step and a comparison or two per destination, against a
    /// descent of the tree per range. [`AffectedPrefixes::All`] is one
    /// pass over every table. Either way the cost of the routes whose
    /// state changes, through import policy and the decision process,
    /// soon outweighs that of finding them.
    pub fn validation_changed(
        &mut self,
        change: ValidationChange,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let ValidationChange { source, affected } = change;
        self.s.cx.validation = source;
        let ranges = match &affected {
            AffectedPrefixes::All => None,
            AffectedPrefixes::CoveredBy(changed) => Some(covered_ranges(changed)),
        };
        let mut scratch = std::mem::take(&mut self.scratch);
        let tally = self.walk(ranges.as_deref(), Rejudge::Restated, &mut scratch);
        if let Some(report) = tally.finish(best_changed(&scratch.dirty)) {
            out.put(Output::Revalidated(report));
        }
        self.finish(&mut scratch, now, out);
        self.scratch = scratch;
    }

    /// Use `enforcement` from now on (RFC 6811 §5: "rejecting all
    /// "invalid" routes", or preferring by state, as the operator
    /// configured): judge every route held in an Adj-RIB-In again under
    /// it, with the validation state it has, and run the decision process
    /// for every destination, since the ranking may have changed too. A
    /// route the new mode rules out is held, and one it admits again is
    /// used again, with no UPDATE and no ROUTE-REFRESH. What follows comes
    /// out after one [`Output::Enforcement`] that counts it: FIB changes,
    /// and UPDATEs sent or held back by the RFC 4271 §9.2.1.1 pacing, as
    /// for an UPDATE. Nothing happens when the mode is the current one.
    ///
    /// It is the walk [`Rib::validation_changed`] makes for
    /// [`AffectedPrefixes::All`], made on a reload that changes the mode.
    pub fn set_enforcement(&mut self, enforcement: Enforcement, now: Instant, out: &mut impl Sink) {
        let from = self.s.cx.enforcement;
        if from == enforcement {
            return;
        }
        self.s.cx.enforcement = enforcement;
        let mut scratch = std::mem::take(&mut self.scratch);
        let tally = self.walk(None, Rejudge::All, &mut scratch);
        out.put(Output::Enforcement(Rejudged {
            from,
            to: enforcement,
            routes: tally.routes,
            held: tally.held,
            released: tally.released,
            best_changed: best_changed(&scratch.dirty),
        }));
        self.finish(&mut scratch, now, out);
        self.scratch = scratch;
    }

    /// Use `startup` from now on for the routes not validated yet, those
    /// used with state `disabled` (RFC 6811 §2: none leaves the decision
    /// process for its state "unless explicitly configured to do so"):
    /// under [`Startup::Hold`] they are held ([`crate::Held::Startup`]),
    /// under [`Startup::Accept`] used. Every such route is judged again,
    /// and its destination decided again; the others, validated or given
    /// a state by import policy, are left as they are. What follows comes
    /// out after one [`Output::Startup`] that counts it, as for
    /// [`Rib::set_enforcement`]. Nothing happens when the setting is the
    /// current one.
    ///
    /// The owner holds routes only while it waits for the first data of
    /// a validation source it expects: a route the [`NullSource`] of
    /// validation turned off judges is `disabled` too, so the owner turns
    /// the hold off before it turns validation off.
    ///
    /// [`NullSource`]: bgpfc_rpki::NullSource
    pub fn set_startup(&mut self, startup: Startup, now: Instant, out: &mut impl Sink) {
        let from = self.s.cx.startup;
        if from == startup {
            return;
        }
        self.s.cx.startup = startup;
        let mut scratch = std::mem::take(&mut self.scratch);
        let tally = self.walk(None, Rejudge::Unvalidated, &mut scratch);
        out.put(Output::Startup(StartupChange {
            from,
            to: startup,
            routes: tally.routes,
            held: tally.held,
            released: tally.released,
            best_changed: best_changed(&scratch.dirty),
        }));
        self.finish(&mut scratch, now, out);
        self.scratch = scratch;
    }

    /// Visit the destinations of every table that `ranges` (from
    /// [`covered_ranges`]) cover, or all of them for `None`, with a
    /// [`Pass`] that judges again the routes `rejudge` names. The scratch
    /// gets the destinations to run Phase 3 for.
    fn walk(
        &mut self,
        ranges: Option<&[RangeInclusive<Prefix>]>,
        rejudge: Rejudge,
        scratch: &mut Scratch,
    ) -> Tally {
        let mut tally = Tally::default();
        // Empty destinations to remove once a table's walk is done.
        let mut empty: Vec<Prefix> = Vec::new();
        let mut moves: Vec<Move> = Vec::new();
        // IPv4 before IPv6, whichever table came first, for the order of
        // the sample and the transitions.
        let mut tables: Vec<(AddressFamily, &mut Table)> = self.tables.iter_mut().collect();
        tables.sort_by_key(|(family, _)| *family);
        for (family, table) in tables {
            let cx = &mut self.s.cx;
            let mut pass = Pass {
                family,
                local_as: cx.local_as,
                source: &*cx.validation,
                peers: &mut self.s.peers,
                policies: &*cx.policies,
                acting: (cx.enforcement, cx.startup),
                rejudge,
                interner: &mut cx.interner,
                tally: &mut tally,
                scratch: &mut *scratch,
                empty: &mut empty,
                moves: &mut moves,
            };
            match ranges {
                None => {
                    for (k, d) in &mut table.v4 {
                        pass.destination(k.prefix(), d);
                    }
                    for (p, d) in &mut table.v6 {
                        pass.destination(*p, d);
                    }
                }
                Some(ranges) => {
                    let ranges = of_family(ranges, family.afi);
                    let dense =
                        ranges.len().saturating_mul(DENSE) >= table.v4.len() + table.v6.len();
                    let v4: Vec<RangeInclusive<Ipv4Key>> = ranges
                        .iter()
                        .filter_map(|r| Some(Ipv4Key::new(*r.start())?..=Ipv4Key::new(*r.end())?))
                        .collect();
                    let visit4 = |k: &Ipv4Key, d: &mut Destination| pass.destination(k.prefix(), d);
                    if dense {
                        walk_alongside(&mut table.v4, &v4, visit4);
                    } else {
                        walk_ranges(&mut table.v4, &v4, visit4);
                    }
                    let visit6 = |p: &Prefix, d: &mut Destination| pass.destination(*p, d);
                    if dense {
                        walk_alongside(&mut table.v6, ranges, visit6);
                    } else {
                        walk_ranges(&mut table.v6, ranges, visit6);
                    }
                }
            }
            for prefix in empty.drain(..) {
                match Ipv4Key::new(prefix) {
                    Some(k) => table.v4.remove(&k),
                    None => table.v6.remove(&prefix),
                };
            }
        }
        tally
    }
}

/// Destinations among `dirty` where the decision process chose another
/// route, or none.
fn best_changed(dirty: &[Dirty]) -> usize {
    dirty
        .iter()
        .filter(|d| !same_best(d.old.as_ref(), d.new.as_ref()))
        .count()
}

/// Whether `a` and `b` are the same best route, or both none.
fn same_best(a: Option<&Route>, b: Option<&Route>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.same(b),
        _ => false,
    }
}

/// Which routes a [`Pass`] judges again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rejudge {
    /// Those whose state the validation source now gives differs: every
    /// route visited is validated again first (RFC 6811 §4).
    Restated,
    /// Every route, with the state it has: the enforcement mode changed.
    All,
    /// Every route used with state `disabled`, with that state: the
    /// startup setting changed, which acts on no other.
    Unvalidated,
}

/// What validating routes again needs of the RIB, borrowed apart from
/// the table being walked.
struct Pass<'a> {
    family: AddressFamily,
    local_as: Asn,
    source: &'a dyn ValidationSource,
    peers: &'a mut Vec<Option<PeerState>>,
    policies: &'a dyn Policies,
    /// What acts on the state beyond policy: the enforcement mode, and
    /// the startup setting.
    acting: (Enforcement, Startup),
    /// Which routes to judge again: those whose state changed, or with
    /// the state they have, every route or those not validated yet.
    rejudge: Rejudge,
    interner: &'a mut Interner,
    tally: &'a mut Tally,
    scratch: &'a mut Scratch,
    /// Destinations left with no route, for the caller to remove.
    empty: &'a mut Vec<Prefix>,
    /// The routes of the destination being validated again whose state
    /// moved among valid, invalid and not-found.
    moves: &'a mut Vec<Move>,
}

/// A route whose state moved among valid, invalid and not-found, until
/// its destination has been decided and its [`Transition`] can say what
/// became of it.
struct Move {
    peer: PeerId,
    addr: IpAddr,
    origin: RouteOrigin,
    from: RovState,
    to: RovState,
}

/// What validating one route again did, for its destination.
#[derive(Clone, Copy, Default)]
struct Redone {
    /// Its RFC 6811 state changed.
    restated: bool,
    /// It is a candidate with a new state or new attributes, or one that
    /// came or went: the decision process must run.
    changed: bool,
    /// It moved between the candidates and the held routes.
    moved: bool,
}

impl Pass<'_> {
    /// Validate again the routes held for `prefix`, in place, and run
    /// import policy and enforcement again on those whose state changed,
    /// or on those `rejudge` names; the scratch gets the destination with
    /// its best route before and after if its candidates, or its best
    /// route, changed.
    fn destination(&mut self, prefix: Prefix, dest: &mut Destination) {
        let old = dest.best().cloned();
        let mut done = Redone::default();
        // The routes no state admits any more.
        let mut dropped: Vec<PeerId> = Vec::new();
        for route in dest.routes_mut() {
            let r = self.route(prefix, route, &mut dropped);
            done.restated |= r.restated;
            done.changed |= r.changed;
            done.moved |= r.moved;
        }
        if done.moved {
            // Candidates first; a stable sort keeps their order.
            dest.routes_mut().sort_by_key(|r| r.held.is_some());
        }
        for peer in dropped {
            if let Some(i) = dest.position(peer) {
                let r = dest.remove(i);
                self.scratch.released.push(r.attrs);
                self.scratch.released.extend(r.received);
            }
        }
        if done.restated {
            self.tally.destinations += 1;
            if self.tally.sample.len() < Revalidation::SAMPLE {
                self.tally.sample.push(prefix);
            }
        }
        if done.changed {
            Decide {
                peers: self.peers,
                enforcement: self.acting.0,
            }
            .run(dest);
            let new = dest.best();
            // A pass that is not a change of the validation source judges
            // routes again whose state did not change, and most come out
            // as they were: only a destination whose best route is
            // another, or is used otherwise, is noted, so that a pass
            // over a full table does not note every destination.
            let same = match (&old, new) {
                (None, None) => true,
                (Some(a), Some(b)) => a.same(b) && a.same_state(b),
                _ => false,
            };
            if self.rejudge == Rejudge::Restated || !same {
                self.scratch.dirty.push(Dirty {
                    family: self.family,
                    prefix,
                    old,
                    new: new.cloned(),
                    merged: false,
                });
            }
        }
        self.list(prefix, dest);
        if dest.is_empty() {
            self.empty.push(prefix);
        }
    }

    /// List the moves among valid, invalid and not-found of `dest`'s
    /// routes (issue #59), with what each route is now that the
    /// destination is decided, up to [`Revalidation::LISTED`] in all, and
    /// count the rest.
    fn list(&mut self, prefix: Prefix, dest: &Destination) {
        for m in self.moves.drain(..) {
            // Not found: no state admits it any more, and it is gone.
            let Some(i) = dest.position(m.peer) else {
                self.tally.unlisted += 1;
                continue;
            };
            let route = match dest.routes()[i].held {
                Some(by) => RouteStatus::Held(by),
                // The candidates come first, the best first of all.
                None if i == 0 => RouteStatus::Best,
                None => RouteStatus::Candidate,
            };
            if self.tally.transitions.len() < Revalidation::LISTED {
                self.tally.transitions.push(Transition {
                    family: self.family,
                    prefix,
                    peer: m.addr,
                    origin: m.origin,
                    from: m.from,
                    to: m.to,
                    route,
                });
            } else {
                self.tally.unlisted += 1;
            }
        }
    }

    /// Validate `route` to `prefix` again and, if its state changed or
    /// the pass judges it again whatever its state, judge it again;
    /// `dropped` gets its peer if no state admits it any more.
    fn route(&mut self, prefix: Prefix, route: &mut Route, dropped: &mut Vec<PeerId>) -> Redone {
        // The startup setting acts on no route that has a state.
        if self.rejudge == Rejudge::Unvalidated && route.effective_rov() != RovState::Disabled {
            return Redone::default();
        }
        self.tally.routes += 1;
        // RFC 6811 §2, on the route as received, as on its arrival. A pass
        // that judges again whatever the state keeps the states: the
        // source is the same.
        let received = Arc::clone(route.received());
        let origin = (self.rejudge == Rejudge::Restated)
            .then(|| RouteOrigin::from_as_path(&received.as_path, self.local_as));
        let (rov, aspa) = match origin {
            Some(origin) => (
                self.source.rov(prefix, origin),
                self.source.aspa(&received.as_path),
            ),
            None => (route.rov, route.aspa),
        };
        if rov == route.rov && aspa == route.aspa && self.rejudge == Rejudge::Restated {
            return Redone::default();
        }
        let (from, restated) = (route.rov, rov != route.rov);
        if restated {
            self.tally.moved[slot(from)][slot(rov)] += 1;
        }
        route.rov = rov;
        route.aspa = aspa;
        // Always found: the Adj-RIBs-In hold routes only of peers that
        // are up, as a peer's routes go with it.
        let Some(peer) = self.peers[route.peer.index()].as_mut() else {
            return Redone {
                restated,
                ..Redone::default()
            };
        };
        // Issue #59: a move among the RFC 6811 states is listed. One to or
        // from `disabled` is validation being switched on or off, which
        // moves every route: counted, not listed.
        if let Some(origin) = origin
            && restated
            && from != RovState::Disabled
            && rov != RovState::Disabled
        {
            self.moves.push(Move {
                peer: route.peer,
                addr: peer.info.addr,
                origin,
                from,
                to: rov,
            });
        }
        let was_held = route.held.is_some();
        let judged = judge(
            self.policies,
            self.acting,
            self.interner,
            &peer.info,
            (self.family, prefix),
            &received,
            rov,
        );
        let (attrs, rov_set, held, gone) = match judged {
            Judged::Accepted { attrs, rov_set } => (attrs, rov_set, None, false),
            Judged::Held { by, rov_set } => (Arc::clone(&received), rov_set, Some(by), false),
            // Policy accepted the route with some state when it was last
            // judged, so only a change of policy since, before the
            // ROUTE-REFRESH that follows one, can leave none. Kept behind
            // the candidates until the destination removes it, and no
            // longer counted.
            Judged::Dropped => {
                let n = peer.adj_in_count.or_default(self.family);
                *n = n.saturating_sub(1);
                if was_held {
                    let n = peer.adj_in_held.or_default(self.family);
                    *n = n.saturating_sub(1);
                }
                dropped.push(route.peer);
                (Arc::clone(&received), None, Some(Held::Policy), true)
            }
        };
        let is_held = held.is_some();
        if !gone && was_held != is_held {
            let n = peer.adj_in_held.or_default(self.family);
            if is_held {
                *n += 1;
                self.tally.held += 1;
            } else {
                *n = n.saturating_sub(1);
                self.tally.released += 1;
            }
        }
        let replaced = std::mem::replace(&mut route.attrs, attrs);
        let unchanged = Arc::ptr_eq(&replaced, &route.attrs);
        self.scratch.released.push(replaced);
        route.received = (!Arc::ptr_eq(&route.attrs, &received)).then(|| Arc::clone(&received));
        route.rov_set = rov_set;
        route.held = held;
        Redone {
            restated,
            changed: !(was_held && is_held && unchanged),
            moved: was_held != is_held,
        }
    }
}

/// The ranges of the prefix order that hold the prefixes some prefix of
/// `changed` covers, in order and disjoint.
///
/// Address blocks nest or are disjoint, and in prefix order a block comes
/// before every block inside it, so a prefix whose range starts inside
/// the range last kept lies wholly within it and adds nothing.
fn covered_ranges(changed: &PrefixSet) -> Vec<RangeInclusive<Prefix>> {
    let mut prefixes: Vec<Prefix> = changed.iter().collect();
    prefixes.sort_unstable();
    let mut ranges: Vec<RangeInclusive<Prefix>> = Vec::new();
    for prefix in prefixes {
        if ranges.last().is_some_and(|last| prefix <= *last.end()) {
            continue;
        }
        ranges.push(covered(prefix));
    }
    ranges
}

/// Every prefix `p` covers (RFC 6811 §2: as long as `p` or longer, and
/// equal to it on its first `p.prefix_len()` bits), as a range of the
/// prefix order, which sorts by family, then address, then length: from
/// `p` itself to the longest prefix at the last address of its block.
/// Nothing else lies between: a prefix at an address inside the block
/// and shorter than `p` would have to be `p`'s own address with a shorter
/// length, which sorts before `p`.
fn covered(p: Prefix) -> RangeInclusive<Prefix> {
    let last = match p {
        Prefix::V4 { addr, len } => Prefix::V4 {
            // A shift by the whole width leaves no host bits (length 32).
            addr: Ipv4Addr::from(
                u32::from(addr) | u32::MAX.checked_shr(u32::from(len)).unwrap_or(0),
            ),
            len: 32,
        },
        Prefix::V6 { addr, len } => Prefix::V6 {
            addr: Ipv6Addr::from(
                u128::from(addr) | u128::MAX.checked_shr(u32::from(len)).unwrap_or(0),
            ),
            len: 128,
        },
    };
    p..=last
}

/// The ranges, from [`covered_ranges`], of prefixes of `afi`. IPv4
/// prefixes sort before IPv6 ones.
fn of_family(ranges: &[RangeInclusive<Prefix>], afi: Afi) -> &[RangeInclusive<Prefix>] {
    let split = ranges.partition_point(|r| matches!(r.start(), Prefix::V4 { .. }));
    match afi {
        Afi::Ipv4 => &ranges[..split],
        Afi::Ipv6 => &ranges[split..],
        Afi::Unknown(_) => &[],
    }
}

/// Visit the destinations of `table` within `ranges` (sorted, disjoint)
/// with a range query per range.
fn walk_ranges<K: Ord + Clone, T>(
    table: &mut BTreeMap<K, T>,
    ranges: &[RangeInclusive<K>],
    mut visit: impl FnMut(&K, &mut T),
) {
    for range in ranges {
        for (prefix, value) in table.range_mut(range.clone()) {
            visit(prefix, value);
        }
    }
}

/// Visit the destinations of `table` within `ranges` (sorted, disjoint)
/// in one pass over the table, moving through the ranges alongside.
fn walk_alongside<K: Ord, T>(
    table: &mut BTreeMap<K, T>,
    ranges: &[RangeInclusive<K>],
    mut visit: impl FnMut(&K, &mut T),
) {
    let mut ranges = ranges.iter().peekable();
    for (prefix, value) in table.iter_mut() {
        while ranges.next_if(|r| r.end() < prefix).is_some() {}
        let Some(range) = ranges.peek() else {
            return;
        };
        if range.start() <= prefix {
            visit(prefix, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use proptest::prelude::*;

    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn a_prefix_covers_one_range_of_the_prefix_order() {
        assert_eq!(
            covered(p("10.0.0.0/8")),
            p("10.0.0.0/8")..=p("10.255.255.255/32")
        );
        assert_eq!(
            covered(p("0.0.0.0/0")),
            p("0.0.0.0/0")..=p("255.255.255.255/32")
        );
        assert_eq!(
            covered(p("192.0.2.1/32")),
            p("192.0.2.1/32")..=p("192.0.2.1/32")
        );
        assert_eq!(
            covered(p("2001:db8::/32")),
            p("2001:db8::/32")..=p("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/128")
        );
        assert_eq!(
            covered(p("::/0")),
            p("::/0")..=p("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")
        );
        assert_eq!(
            covered(p("2001:db8::1/128")),
            p("2001:db8::1/128")..=p("2001:db8::1/128")
        );
        let r = covered(p("10.0.0.0/8"));
        for inside in [
            "10.0.0.0/8",
            "10.0.0.0/9",
            "10.128.0.0/9",
            "10.255.255.255/32",
        ] {
            assert!(r.contains(&p(inside)), "{inside}");
        }
        for outside in [
            "10.0.0.0/7",
            "8.0.0.0/6",
            "11.0.0.0/8",
            "9.255.255.255/32",
            "::/0",
        ] {
            assert!(!r.contains(&p(outside)), "{outside}");
        }
    }

    #[test]
    fn nested_prefixes_give_one_range() {
        let changed: PrefixSet = [
            "10.1.0.0/16",
            "10.0.0.0/8",
            "10.2.3.0/24",
            "192.0.2.0/24",
            "2001:db8::/32",
            "2001:db8:1::/48",
        ]
        .into_iter()
        .map(p)
        .collect();
        let ranges = covered_ranges(&changed);
        assert_eq!(
            ranges,
            vec![
                covered(p("10.0.0.0/8")),
                covered(p("192.0.2.0/24")),
                covered(p("2001:db8::/32")),
            ]
        );
        assert_eq!(of_family(&ranges, Afi::Ipv4), &ranges[..2]);
        assert_eq!(of_family(&ranges, Afi::Ipv6), &ranges[2..]);
        assert_eq!(of_family(&ranges, Afi::Unknown(3)).len(), 0);
        assert_eq!(covered_ranges(&PrefixSet::new()), vec![]);
    }

    /// A prefix of either family from a few bits, so that random ones
    /// nest and collide often.
    fn prefix() -> impl Strategy<Value = Prefix> {
        (any::<bool>(), any::<u8>(), 0u8..=10).prop_map(|(v6, bits, len)| {
            let addr = if v6 {
                IpAddr::V6(Ipv6Addr::from(u128::from(bits) << 120))
            } else {
                IpAddr::V4(Ipv4Addr::from(u32::from(bits) << 24))
            };
            Prefix::new(addr, len).unwrap()
        })
    }

    proptest! {
        /// Both walks visit exactly the destinations some changed prefix
        /// covers, each once and in order.
        #[test]
        fn walks_visit_exactly_the_covered_destinations(
            table in proptest::collection::btree_set(prefix(), 0..40),
            changed in proptest::collection::vec(prefix(), 0..12),
        ) {
            let changed: PrefixSet = changed.into_iter().collect();
            let expected: Vec<Prefix> =
                table.iter().copied().filter(|t| changed.covers(*t)).collect();
            let mut table: BTreeMap<Prefix, u8> = table.into_iter().map(|t| (t, 0)).collect();
            let ranges = covered_ranges(&changed);
            for alongside in [false, true] {
                let mut seen = Vec::new();
                for afi in [Afi::Ipv4, Afi::Ipv6] {
                    let ranges = of_family(&ranges, afi);
                    let visit = |p: &Prefix, _: &mut u8| seen.push(*p);
                    if alongside {
                        walk_alongside(&mut table, ranges, visit);
                    } else {
                        walk_ranges(&mut table, ranges, visit);
                    }
                }
                prop_assert_eq!(&seen, &expected, "alongside: {}", alongside);
            }
        }
    }
}
