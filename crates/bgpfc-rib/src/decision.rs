//! Phase 2 of the decision process: choosing the best route to a
//! destination among the eligible ones (RFC 4271 §9.1.2, §9.1.2.2).
//!
//! Route selection is an explicit list of steps, [`ORDER`] (issue #47),
//! applied as RFC 4271 §9.1.2.2 describes it: "The tie-breaking algorithm
//! begins by considering all equally preferable routes to the same
//! destination, and then selects routes to be removed from
//! consideration. The algorithm terminates as soon as only one route
//! remains in consideration. The criteria MUST be applied in the order
//! specified." Each step keeps, of the routes still under consideration,
//! those it prefers:
//!
//! 1. [`Step::DegreeOfPreference`]: the highest degree of preference
//!    (§9.1.1, §9.1.2), `LOCAL_PREF` or 100. Phase 2 breaks ties among
//!    the routes that share it, so it comes first.
//! 2. [`Step::AsPathLength`]: §9.1.2.2 a), the shortest `AS_PATH`.
//! 3. [`Step::Origin`]: §9.1.2.2 b), the lowest ORIGIN.
//! 4. [`Step::Med`]: §9.1.2.2 c), the lowest `MULTI_EXIT_DISC` of each
//!    neighboring AS, among the routes still under consideration only: a
//!    route an earlier step removed no longer counts, however low its MED.
//! 5. [`Step::External`]: §9.1.2.2 d), routes received via EBGP over those
//!    received via IBGP.
//! 6. [`Step::InteriorCost`]: §9.1.2.2 e), skipped: there is no IGP to give
//!    a cost.
//! 7. [`Step::RouterId`]: §9.1.2.2 f), the lowest BGP Identifier.
//! 8. [`Step::PeerAddress`]: §9.1.2.2 g), the lowest peer address.
//!
//! The order is the RFC's own, and every step is the RFC's, applied as
//! written, so that bgpfcd chooses as every BGP speaker of the AS that
//! follows the RFC does (§9.1.2.2: "all the BGP speakers within an
//! autonomous system ... follow the same route selection algorithm").
//!
//! §9.1.2 also excludes a route whose `NEXT_HOP` cannot be resolved. There
//! is no IGP here, so every next hop counts as resolvable (COMPLIANCE.md,
//! RFC 4271 §9.1.2).

use std::cmp::{Ordering, Reverse};
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

/// One step of route selection, in the order [`ORDER`] applies them
/// (issue #47). Each keeps, of the routes still under consideration, those
/// it prefers, and removes the rest from consideration (RFC 4271
/// §9.1.2.2: "selects routes to be removed from consideration").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// RFC 4271 §9.1.1, §9.1.2: the highest degree of preference, which is
    /// `LOCAL_PREF`, or [`DEFAULT_LOCAL_PREF`] when unset. Phase 2 breaks
    /// ties among the routes that have it, so it comes first.
    DegreeOfPreference,
    /// RFC 4271 §9.1.2.2 a): the fewest AS numbers in `AS_PATH`, an
    /// `AS_SET` counting one and confederation segments none (see
    /// [`path_length`]).
    AsPathLength,
    /// RFC 4271 §9.1.2.2 b): the lowest ORIGIN (IGP, then EGP, then
    /// INCOMPLETE).
    Origin,
    /// RFC 4271 §9.1.2.2 c): no route from the same neighboring AS (see
    /// [`Candidate::neighbor_as`]) with a lower `MULTI_EXIT_DISC` among
    /// those still under consideration; a missing one is the lowest, 0.
    Med,
    /// RFC 4271 §9.1.2.2 d): if any route was received via EBGP, those
    /// received via IBGP go.
    External,
    /// RFC 4271 §9.1.2.2 e): the lowest interior cost to `NEXT_HOP`. There
    /// is no IGP, so no cost can be determined and the step is skipped,
    /// which §9.1.2.2 e) equates with "consider all routes to have equal
    /// costs". NOTE(interop): BIRD and FRR fall through likewise when no
    /// IGP metric is known.
    InteriorCost,
    /// RFC 4271 §9.1.2.2 f): the lowest BGP Identifier.
    RouterId,
    /// RFC 4271 §9.1.2.2 g): the lowest peer address.
    PeerAddress,
}

/// The steps of route selection, in the order they apply. RFC 4271
/// §9.1.2.2: "The criteria MUST be applied in the order specified."
pub const ORDER: [Step; 8] = [
    Step::DegreeOfPreference,
    Step::AsPathLength,
    Step::Origin,
    Step::Med,
    Step::External,
    Step::InteriorCost,
    Step::RouterId,
    Step::PeerAddress,
];

impl Step {
    /// How this step judges route `a` against route `b`: `Greater` when it
    /// prefers `a`, `Less` when it prefers `b`, `Equal` when it removes
    /// neither for the other.
    ///
    /// Every step but [`Step::Med`] orders all routes, by a key of each
    /// route. MED orders only the routes of one neighboring AS and finds
    /// routes of two different ones `Equal`, which is not transitive, so
    /// [`best`] applies it as RFC 4271 §9.1.2.2 c) words it: a route goes
    /// when a route still under consideration beats it.
    #[must_use]
    pub fn compare(self, a: &Candidate<'_>, b: &Candidate<'_>) -> Ordering {
        match self {
            // §9.1.2.2 c): "MULTI_EXIT_DISC is only comparable between
            // routes learned from the same neighboring AS".
            Step::Med => match med(b).cmp(&med(a)) {
                Ordering::Equal => Ordering::Equal,
                o if a.neighbor_as() == b.neighbor_as() => o,
                _ => Ordering::Equal,
            },
            _ => self.by_key(Pair(a, b)).unwrap_or(Ordering::Equal),
        }
    }

    /// `with` applied to the key this step orders routes by, the greater
    /// preferred: the one place each step's key is written. `None` for
    /// MED, which does not order routes of different neighboring ASes,
    /// and for the interior cost, which finds every route alike.
    fn by_key<'a, W: WithKey<'a>>(self, with: W) -> Option<W::Out> {
        Some(match self {
            Step::DegreeOfPreference => with.key(Candidate::degree_of_preference),
            Step::AsPathLength => with.key(|c| Reverse(path_length(c.attrs))),
            Step::Origin => with.key(|c| Reverse(c.attrs.origin)),
            Step::External => with.key(|c| c.from.kind == PeerKind::External),
            Step::RouterId => with.key(|c| Reverse(c.from.router_id)),
            Step::PeerAddress => with.key(|c| Reverse(c.from.addr)),
            Step::Med | Step::InteriorCost => return None,
        })
    }
}

/// Something done with the key a step orders routes by ([`Step::by_key`]).
trait WithKey<'a> {
    type Out;
    fn key<K: Ord>(self, key: impl Fn(&Candidate<'a>) -> K) -> Self::Out;
}

/// Two routes, compared by the key.
struct Pair<'x, 'a>(&'x Candidate<'a>, &'x Candidate<'a>);

impl<'a> WithKey<'a> for Pair<'_, 'a> {
    type Out = Ordering;

    fn key<K: Ord>(self, key: impl Fn(&Candidate<'a>) -> K) -> Ordering {
        key(self.0).cmp(&key(self.1))
    }
}

/// The routes still under consideration, cut down to those with the
/// greatest key.
struct KeepMax<'x, 'w, F>(&'x mut Considered<'w>, &'x F);

impl<'a, F: Fn(usize) -> Candidate<'a>> WithKey<'a> for KeepMax<'_, '_, F> {
    type Out = ();

    fn key<K: Ord>(self, key: impl Fn(&Candidate<'a>) -> K) {
        let KeepMax(considered, candidate) = self;
        considered.keep_max(|i| key(&candidate(i)));
    }
}

/// RFC 4271 §9.1.2.2 c): "If route n has no `MULTI_EXIT_DISC` attribute, the
/// function returns the lowest possible `MULTI_EXIT_DISC` value (i.e., 0)."
fn med(c: &Candidate<'_>) -> u32 {
    c.attrs.med.unwrap_or(0)
}

/// The index of the best of `n` candidates, or `None` when there is none.
/// `candidate(i)` is the `i`th, for `i` in `0..n`; the RIB keeps routes
/// apart from the peers they name, so it assembles each on demand.
///
/// Every candidate starts under consideration, and each step of [`ORDER`]
/// removes from consideration those it does not prefer, until one is
/// left (RFC 4271 §9.1.2.2: "The algorithm terminates as soon as only
/// one route remains in consideration"). After g) one is always left, as
/// a destination holds at most one route per peer; should two share a
/// peer, the first is chosen. The outcome does not depend on the order of
/// the candidates.
#[must_use]
pub fn best<'a>(n: usize, candidate: impl Fn(usize) -> Candidate<'a>) -> Option<usize> {
    #[cfg(feature = "profiling")]
    let _span = {
        bgpfc_prof::metrics::BEST_PATH_RUNS.inc();
        bgpfc_prof::Timer::start(&bgpfc_prof::metrics::BEST_PATH)
    };
    match n {
        0 => None,
        // Most destinations have one route: nothing to compare.
        1 => Some(0),
        // Two routes, the next most common case: a step removes one of
        // them or neither, so the first step that prefers one chooses it.
        2 => {
            let (a, b) = (candidate(0), candidate(1));
            let decided = ORDER.iter().map(|s| s.compare(&b, &a)).find(|o| o.is_ne());
            Some(usize::from(decided == Some(Ordering::Greater)))
        }
        _ => Some(eliminate(n, &candidate)),
    }
}

/// [`best`] of `n` candidates, more than one.
fn eliminate<'a>(n: usize, candidate: &impl Fn(usize) -> Candidate<'a>) -> usize {
    // One bit per candidate: a word on the stack for up to 64, the usual
    // case by far (a route per peer), and the heap only beyond.
    let mut inline = [0u64; 1];
    let mut spilled = Vec::new();
    let words: &mut [u64] = if n <= 64 {
        &mut inline
    } else {
        spilled.resize(n.div_ceil(64), 0);
        &mut spilled
    };
    let mut considered = Considered::all(words, n);
    for step in ORDER {
        if considered.one_left() {
            break;
        }
        match step {
            // §9.1.2.2 c), as written: "for m = all routes still under
            // consideration / for n = all routes still under consideration
            // / if (neighborAS(m) == neighborAS(n)) and (MED(n) < MED(m)) /
            // remove route m from consideration". Removing m as soon as it
            // loses gives the same routes as judging every m against the
            // set before the step: whatever removes m, the route with the
            // lowest MED of m's neighboring AS removes it too, and nothing
            // removes that one.
            Step::Med => considered.retain(|m, considered| {
                let m = candidate(m);
                let (m_med, m_as) = (med(&m), m.neighbor_as());
                !considered.iter().any(|n| {
                    let n = candidate(n);
                    med(&n) < m_med && n.neighbor_as() == m_as
                })
            }),
            _ => {
                step.by_key(KeepMax(&mut considered, candidate));
            }
        }
    }
    // invariant: a step never removes every route: what beats a route
    // stays.
    considered.iter().next().unwrap()
}

/// The candidates still under consideration, one bit each.
struct Considered<'w> {
    words: &'w mut [u64],
}

impl<'w> Considered<'w> {
    /// The first `n` candidates, `words` holding at least `n` bits.
    fn all(words: &'w mut [u64], n: usize) -> Considered<'w> {
        for (i, word) in words.iter_mut().enumerate() {
            let bits = n.saturating_sub(i * 64);
            *word = if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
        }
        Considered { words }
    }

    /// Whether only one is still under consideration: one word has one
    /// bit set, and the others none.
    fn one_left(&self) -> bool {
        let mut set = self.words.iter().filter(|w| **w != 0);
        set.next().is_some_and(|w| w & (w - 1) == 0) && set.next().is_none()
    }

    /// Their indices, in order.
    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(w, &word)| {
            let mut bits = word;
            std::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                Some(w * 64 + b)
            })
        })
    }

    /// Remove from consideration each candidate `keep` says no to, asked
    /// in order with the candidates still under consideration then.
    fn retain(&mut self, mut keep: impl FnMut(usize, &Considered<'_>) -> bool) {
        for w in 0..self.words.len() {
            let mut bits = self.words[w];
            while bits != 0 {
                let b = bits.trailing_zeros();
                bits &= bits - 1;
                if !keep(w * 64 + b as usize, self) {
                    self.words[w] &= !(1u64 << b);
                }
            }
        }
    }

    /// Keep those with the greatest `key`, in one pass that asks for the
    /// key of each once: when one beats every candidate kept so far, those
    /// all go.
    fn keep_max<K: Ord>(&mut self, key: impl Fn(usize) -> K) {
        let mut max: Option<K> = None;
        for w in 0..self.words.len() {
            let mut bits = self.words[w];
            while bits != 0 {
                let b = bits.trailing_zeros();
                bits &= bits - 1;
                let k = key(w * 64 + b as usize);
                match max.as_ref().map(|m| k.cmp(m)) {
                    None | Some(Ordering::Greater) => {
                        self.words[..w].fill(0);
                        self.words[w] &= !((1u64 << b) - 1);
                        max = Some(k);
                    }
                    Some(Ordering::Equal) => {}
                    Some(Ordering::Less) => self.words[w] &= !(1u64 << b),
                }
            }
        }
    }
}
