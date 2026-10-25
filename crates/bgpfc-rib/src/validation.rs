//! Validation states that follow the validation source (issue #56).
//!
//! Every route in an Adj-RIB-In carries the validation state the current
//! [`ValidationSource`] gives it. When the source changes, the routes it
//! may judge differently are validated again in place, and those whose
//! state changed go through import policy and the decision process again,
//! the way an UPDATE takes them.
//!
//! The same walk judges every route again when the operator's
//! enforcement mode changes ([`Rib::set_enforcement`]).
//!
//! Implements: RFC 6811 §2 ("The validation state of the Route MUST be
//! set to reflect the result of the lookup"), §4 ("When a mapping is added
//! or deleted, the implementation MUST re-validate any affected prefixes
//! and run the BGP decision process if needed"), for the routes that
//! [`AffectedPrefixes`] names; §5 (a change of what acts on the state
//! runs the decision process again for every route).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Instant;

use bgpfc_rpki::{
    AffectedPrefixes, Enforcement, PrefixSet, RouteOrigin, RovState, ValidationChange,
    ValidationSource,
};
use bgpfc_wire::prefix::{Ipv4Key, Prefix};
use bgpfc_wire::types::{AddressFamily, Afi, Asn};

use crate::store::{Destination, PeerId, Route};
use crate::{
    Dirty, Held, Interner, Judged, Output, PeerState, Policies, Rib, Scratch, Sink, decide, judge,
};

/// A table walks its affected destinations in one pass, rather than one
/// range query per range, once it has fewer than this many destinations
/// per range (see [`Rib::validation_changed`]). On a full table a range
/// query costs about 0.6 µs and a pass about 35 ns per destination, so
/// the pass is cheaper from about one range per 17 destinations
/// (`benches/rib.rs`, `revalidate_*`).
const DENSE: usize = 16;

/// What validating routes again after a change of the validation source
/// did (RFC 6811 §4), for the caller to log: counts and a short sample,
/// never an entry per route, so that a change that moves every route of
/// a full table, as turning validation on or off does, costs one small
/// report.
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

impl Revalidation {
    /// The most destinations [`Revalidation::sample`] names.
    pub const SAMPLE: usize = 8;

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
        let tally = self.walk(ranges.as_deref(), false, &mut scratch);
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
        let tally = self.walk(None, true, &mut scratch);
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

    /// Visit the destinations of every table that `ranges` (from
    /// [`covered_ranges`]) cover, or all of them for `None`, with a
    /// [`Pass`]: validate their routes again and, for those whose state
    /// changed, or every route when `force` is set, judge them again. The
    /// scratch gets the destinations to run Phase 3 for.
    fn walk(
        &mut self,
        ranges: Option<&[RangeInclusive<Prefix>]>,
        force: bool,
        scratch: &mut Scratch,
    ) -> Tally {
        let mut tally = Tally::default();
        // Empty destinations to remove once a table's walk is done.
        let mut empty: Vec<Prefix> = Vec::new();
        for (family, table) in self.tables.iter_mut() {
            let cx = &mut self.s.cx;
            let mut pass = Pass {
                family,
                local_as: cx.local_as,
                source: &*cx.validation,
                peers: &mut self.s.peers,
                policies: &*cx.policies,
                enforcement: cx.enforcement,
                force,
                interner: &mut cx.interner,
                tally: &mut tally,
                scratch: &mut *scratch,
                empty: &mut empty,
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

/// What validating routes again needs of the RIB, borrowed apart from
/// the table being walked.
struct Pass<'a> {
    family: AddressFamily,
    local_as: Asn,
    source: &'a dyn ValidationSource,
    peers: &'a mut Vec<Option<PeerState>>,
    policies: &'a dyn Policies,
    enforcement: Enforcement,
    /// Judge every route again, its state changed or not, with the state
    /// it has: the enforcement mode changed.
    force: bool,
    interner: &'a mut Interner,
    tally: &'a mut Tally,
    scratch: &'a mut Scratch,
    /// Destinations left with no route, for the caller to remove.
    empty: &'a mut Vec<Prefix>,
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
    /// or on all of them when forced; the scratch gets the destination
    /// with its best route before and after if its candidates, or its
    /// best route, changed.
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
            decide(self.peers, dest);
            let new = dest.best();
            // A forced pass judges every route again, and most come out
            // as they were: only a destination whose best route is
            // another, or is used otherwise, is noted, so that a pass
            // over a full table does not note every destination.
            let same = match (&old, new) {
                (None, None) => true,
                (Some(a), Some(b)) => a.same(b) && a.same_state(b),
                _ => false,
            };
            if !self.force || !same {
                self.scratch.dirty.push(Dirty {
                    family: self.family,
                    prefix,
                    old,
                    new: new.cloned(),
                    merged: false,
                });
            }
        }
        if dest.is_empty() {
            self.empty.push(prefix);
        }
    }

    /// Validate `route` to `prefix` again and, if its state changed or
    /// the pass is forced, judge it again; `dropped` gets its peer if no
    /// state admits it any more.
    fn route(&mut self, prefix: Prefix, route: &mut Route, dropped: &mut Vec<PeerId>) -> Redone {
        self.tally.routes += 1;
        // RFC 6811 §2, on the route as received, as on its arrival. A
        // forced pass keeps the states: the source is the same.
        let received = Arc::clone(route.received());
        let (rov, aspa) = if self.force {
            (route.rov, route.aspa)
        } else {
            let origin = RouteOrigin::from_as_path(&received.as_path, self.local_as);
            (
                self.source.rov(prefix, origin),
                self.source.aspa(&received.as_path),
            )
        };
        if rov == route.rov && aspa == route.aspa && !self.force {
            return Redone::default();
        }
        let restated = rov != route.rov;
        if restated {
            self.tally.moved[slot(route.rov)][slot(rov)] += 1;
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
        let was_held = route.held.is_some();
        let judged = judge(
            self.policies,
            self.enforcement,
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
