//! Phase 2 of the decision process: choosing the best route to a
//! destination among the eligible ones (RFC 4271 §9.1.2, §9.1.2.2).

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::IpAddr;

use bgpfc_wire::types::Asn;
use bgpfc_wire::update::PeerKind;

use crate::attrs::PathAttrs;
use crate::peer::PeerInfo;

/// What Phase 2 compares about the peer a route was learned from. It is
/// fixed for the life of a session, so the RIB keeps one per peer rather
/// than a copy per route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbor {
    /// The peer's address.
    pub addr: IpAddr,
    /// Internal or external session.
    pub kind: PeerKind,
    /// The peer's BGP Identifier as an integer.
    pub router_id: u32,
    /// The peer's AS.
    pub remote_as: Asn,
}

impl Neighbor {
    /// The decision-process view of a session.
    #[must_use]
    pub fn of(info: &PeerInfo) -> Neighbor {
        Neighbor {
            addr: info.addr,
            kind: info.kind,
            router_id: info.router_id.to_u32(),
            remote_as: info.remote_as,
        }
    }
}

/// One candidate route for a destination, as Phase 2 sees it.
#[derive(Clone, Copy, Debug)]
pub struct Candidate<'a> {
    /// The peer the route came from.
    pub from: Neighbor,
    /// The route's attributes.
    pub attrs: &'a PathAttrs,
}

/// The `LOCAL_PREF` assumed for routes without one (external routes the
/// import policy did not set it on). RFC 4271 §9.1.1 leaves the degree of
/// preference of external routes to local policy; 100 is what BIRD and
/// FRR use.
pub const DEFAULT_LOCAL_PREF: u32 = 100;

impl Candidate<'_> {
    /// Phase 1 degree of preference (RFC 4271 §9.1.1): `LOCAL_PREF` from
    /// internal peers, the policy-set or default value otherwise.
    #[must_use]
    pub fn degree_of_preference(&self) -> u32 {
        self.attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF)
    }

    /// The neighboring AS the route came through, for MED comparison
    /// (RFC 4271 §9.1.2.2 c): the leftmost AS in `AS_PATH`, else the
    /// peer's own AS (a route the peer originated).
    #[must_use]
    pub fn neighbor_as(&self) -> Asn {
        self.attrs
            .as_path
            .first_asn()
            .unwrap_or(self.from.remote_as)
    }
}

/// `AS_PATH` length as RFC 4271 §9.1.2.2 a) counts it: each AS in a
/// sequence is one, a whole `AS_SET` is one, confederation segments
/// are zero.
#[must_use]
pub fn path_length(attrs: &PathAttrs) -> usize {
    attrs.as_path.hop_count()
}

/// The index of the best of `n` candidates, or `None` when there is none.
/// `candidate(i)` is the `i`th, for `i` in `0..n`; the RIB keeps routes
/// apart from the peers they name, so it assembles each on demand.
///
/// Steps, in order (RFC 4271 §9.1.2.2): highest degree of preference;
/// shortest `AS_PATH`; lowest ORIGIN; lowest MED among routes from the
/// same neighboring AS (a missing MED is the lowest value); external over
/// internal; (interior cost: not applicable, no IGP); lowest BGP
/// Identifier; lowest peer address.
#[must_use]
pub fn best<'a>(n: usize, candidate: impl Fn(usize) -> Candidate<'a>) -> Option<usize> {
    #[cfg(feature = "profiling")]
    let _span = {
        bgpfc_prof::metrics::BEST_PATH_RUNS.inc();
        bgpfc_prof::Timer::start(&bgpfc_prof::metrics::BEST_PATH)
    };
    if n == 0 {
        return None;
    }
    // c) MED: only comparable between routes from the same neighboring
    // AS. Routes with a higher MED than another route from their
    // neighboring AS are removed before the remaining steps so that the
    // outcome does not depend on comparison order.
    let mut lowest_med: HashMap<Asn, u32> = HashMap::new();
    for i in 0..n {
        let c = candidate(i);
        let med = c.attrs.med.unwrap_or(0);
        lowest_med
            .entry(c.neighbor_as())
            .and_modify(|m| *m = (*m).min(med))
            .or_insert(med);
    }
    let mut best = 0;
    let mut best_c = candidate(0);
    for i in 1..n {
        let c = candidate(i);
        if compare(&c, &best_c, &lowest_med) == Ordering::Greater {
            best = i;
            best_c = c;
        }
    }
    Some(best)
}

/// `Greater` when `a` is preferred over `b`.
fn compare(a: &Candidate<'_>, b: &Candidate<'_>, lowest_med: &HashMap<Asn, u32>) -> Ordering {
    // §9.1.2.2 (before a): highest degree of preference.
    a.degree_of_preference()
        .cmp(&b.degree_of_preference())
        // a) shortest AS_PATH.
        .then_with(|| path_length(b.attrs).cmp(&path_length(a.attrs)))
        // b) lowest ORIGIN: IGP < EGP < INCOMPLETE.
        .then_with(|| b.attrs.origin.cmp(&a.attrs.origin))
        // c) MED, within the neighboring AS (precomputed minimum).
        .then_with(|| med_rank(b, lowest_med).cmp(&med_rank(a, lowest_med)))
        // d) external over internal.
        .then_with(|| kind_rank(b.from.kind).cmp(&kind_rank(a.from.kind)))
        // e) interior cost to the next hop: no IGP, every next hop is
        // equal. NOTE(interop): BIRD and FRR fall through likewise when
        // no IGP metric is known.
        // f) lowest BGP Identifier.
        .then_with(|| b.from.router_id.cmp(&a.from.router_id))
        // g) lowest peer address.
        .then_with(|| b.from.addr.cmp(&a.from.addr))
}

/// 0 when the route has the lowest MED of its neighboring AS, 1 otherwise.
fn med_rank(c: &Candidate<'_>, lowest_med: &HashMap<Asn, u32>) -> u8 {
    let med = c.attrs.med.unwrap_or(0);
    u8::from(lowest_med.get(&c.neighbor_as()).is_some_and(|m| med > *m))
}

const fn kind_rank(kind: PeerKind) -> u8 {
    match kind {
        PeerKind::External => 0,
        PeerKind::Internal => 1,
    }
}
