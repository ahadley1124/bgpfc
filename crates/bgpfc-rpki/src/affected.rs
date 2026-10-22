//! Which routes a change of VRPs can affect, so that only those are
//! validated again.
//!
//! Implements: RFC 6811 §4 ("When a mapping is added or deleted, the
//! implementation MUST re-validate any affected prefixes"), using the
//! "Covered" relation of RFC 6811 §2.

use bgpfc_wire::prefix::Prefix;

use crate::index::{Bits, LenIndex};
use crate::set::{VrpSet, changed_prefixes};
use crate::vrp::Vrp;

/// The routes whose validation state may differ after a change of
/// validation source (RFC 6811 §4; issue #59: a VRP change re-evaluates
/// only the routes it affects).
///
/// A route's state depends only on the VRPs that Cover it (RFC 6811 §2).
/// A route that no added or removed VRP covers therefore keeps its state,
/// and validating again the routes that some changed VRP prefix covers is
/// enough. That is wider than the "affected prefix" of RFC 6811 §4 ("any
/// prefix that was matched by a deleted or updated mapping, or could be
/// matched by an added or updated mapping"), and has to be: a new VRP
/// that covers a route it can never match, because the route is longer
/// than the maximum length, still turns `NotFound` into `Invalid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AffectedPrefixes {
    /// Every route: the change is not a VRP delta, for example validation
    /// was turned on or off.
    All,
    /// The routes that one of these changed VRP prefixes covers.
    CoveredBy(PrefixSet),
}

impl AffectedPrefixes {
    /// No route is affected.
    #[must_use]
    pub fn none() -> AffectedPrefixes {
        AffectedPrefixes::CoveredBy(PrefixSet::new())
    }

    /// The routes affected by replacing `old` with `new`: those covered by
    /// the prefix of a VRP that is in one set and not the other.
    ///
    /// One pass over each set, comparing all the VRPs of one prefix at
    /// once. A producer that already knows the delta, such as an RTR
    /// client applying announcements and withdrawals, should use
    /// [`AffectedPrefixes::from_vrps`] instead, which costs only the size
    /// of the delta.
    #[must_use]
    pub fn between(old: &VrpSet, new: &VrpSet) -> AffectedPrefixes {
        let mut prefixes = PrefixSet::new();
        changed_prefixes(old, new, &mut prefixes);
        AffectedPrefixes::CoveredBy(prefixes)
    }

    /// The routes affected by announcing or withdrawing `changes`.
    #[must_use]
    pub fn from_vrps<I: IntoIterator<Item = Vrp>>(changes: I) -> AffectedPrefixes {
        AffectedPrefixes::CoveredBy(changes.into_iter().map(|vrp| vrp.prefix()).collect())
    }

    /// Whether the route for `route` may have changed state and must be
    /// validated again.
    #[must_use]
    pub fn covers(&self, route: Prefix) -> bool {
        match self {
            AffectedPrefixes::All => true,
            AffectedPrefixes::CoveredBy(prefixes) => prefixes.covers(route),
        }
    }

    /// Whether no route at all is affected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            AffectedPrefixes::All => false,
            AffectedPrefixes::CoveredBy(prefixes) => prefixes.is_empty(),
        }
    }

    /// Add the routes `other` affects, as when two changes are applied
    /// one after the other and their routes validated once.
    pub fn merge(&mut self, other: AffectedPrefixes) {
        match other {
            AffectedPrefixes::All => *self = AffectedPrefixes::All,
            AffectedPrefixes::CoveredBy(theirs) => {
                if let AffectedPrefixes::CoveredBy(mine) = self {
                    mine.extend(theirs.iter());
                }
            }
        }
    }
}

/// A set of prefixes, indexed to answer without allocating whether any of
/// them Covers a given prefix (RFC 6811 §2).
#[derive(Clone, Debug, Default)]
pub struct PrefixSet {
    v4: LenIndex<u32, ()>,
    v6: LenIndex<u128, ()>,
    len: usize,
}

impl PrefixSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> PrefixSet {
        PrefixSet::default()
    }

    /// Number of prefixes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether there are no prefixes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Add `prefix`. `false` if it was already present.
    pub fn insert(&mut self, prefix: Prefix) -> bool {
        let added = match prefix {
            Prefix::V4 { addr, len } => insert_in(&mut self.v4, u32::from(addr), len),
            Prefix::V6 { addr, len } => insert_in(&mut self.v6, u128::from(addr), len),
        };
        if added {
            self.len += 1;
        }
        added
    }

    /// Whether `prefix` itself is in the set.
    #[must_use]
    pub fn contains(&self, prefix: Prefix) -> bool {
        match prefix {
            Prefix::V4 { addr, len } => self.v4.get(u32::from(addr), len).is_some(),
            Prefix::V6 { addr, len } => self.v6.get(u128::from(addr), len).is_some(),
        }
    }

    /// Whether some prefix in the set Covers `route`: is `route` itself or
    /// less specific than it (RFC 6811 §2).
    #[must_use]
    pub fn covers(&self, route: Prefix) -> bool {
        match route {
            Prefix::V4 { addr, len } => self.v4.covering(u32::from(addr), len).next().is_some(),
            Prefix::V6 { addr, len } => self.v6.covering(u128::from(addr), len).next().is_some(),
        }
    }

    /// Every prefix, IPv4 first, otherwise in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = Prefix> + '_ {
        let v4 = self.v4.iter().map(|(key, len, ())| key.prefix(len));
        let v6 = self.v6.iter().map(|(key, len, ())| key.prefix(len));
        v4.chain(v6)
    }
}

fn insert_in<K: Bits>(index: &mut LenIndex<K, ()>, key: K, len: u8) -> bool {
    // `get_or_default` fails only for a length past the address size,
    // which `Prefix` rules out.
    index.get(key, len).is_none() && index.get_or_default(key, len).is_some()
}

impl PartialEq for PrefixSet {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.iter().all(|prefix| other.contains(prefix))
    }
}

impl Eq for PrefixSet {}

impl Extend<Prefix> for PrefixSet {
    fn extend<I: IntoIterator<Item = Prefix>>(&mut self, iter: I) {
        for prefix in iter {
            self.insert(prefix);
        }
    }
}

impl FromIterator<Prefix> for PrefixSet {
    fn from_iter<I: IntoIterator<Item = Prefix>>(iter: I) -> Self {
        let mut set = PrefixSet::new();
        set.extend(iter);
        set
    }
}

#[cfg(test)]
mod tests {
    use bgpfc_wire::types::Asn;

    use super::*;
    use crate::{RouteOrigin, RovState};

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(p(prefix), max_len, Asn(asn)).unwrap()
    }

    #[test]
    fn all_and_none() {
        let all = AffectedPrefixes::All;
        let none = AffectedPrefixes::none();
        for route in ["0.0.0.0/0", "192.0.2.1/32", "::/0", "2001:db8::1/128"] {
            assert!(all.covers(p(route)));
            assert!(!none.covers(p(route)));
        }
        assert!(!all.is_empty());
        assert!(none.is_empty());
    }

    #[test]
    fn covered_routes_are_the_prefix_and_its_more_specifics() {
        let affected = AffectedPrefixes::from_vrps([
            vrp("192.0.2.0/24", 24, 64_496),
            vrp("2001:db8::/32", 48, 64_496),
        ]);
        assert!(!affected.is_empty());
        for route in [
            "192.0.2.0/24",
            "192.0.2.128/25",
            "192.0.2.7/32",
            "2001:db8::/32",
            "2001:db8:1::/48",
            "2001:db8::1/128",
        ] {
            assert!(affected.covers(p(route)), "{route}");
        }
        for route in [
            "192.0.0.0/16",
            "0.0.0.0/0",
            "192.0.3.0/24",
            "198.51.100.0/24",
            "2001:db8::/31",
            "2001:db9::/32",
            "::/0",
            // Same leading bits, other family.
            "32.1.13.184/32",
        ] {
            assert!(!affected.covers(p(route)), "{route}");
        }
    }

    #[test]
    fn between_finds_exactly_the_changed_prefixes() {
        let old: VrpSet = [
            vrp("192.0.2.0/24", 24, 64_496),
            vrp("198.51.100.0/24", 24, 64_496),
            vrp("203.0.113.0/24", 24, 64_496),
            vrp("2001:db8::/32", 48, 64_496),
        ]
        .into_iter()
        .collect();
        assert!(AffectedPrefixes::between(&old, &old).is_empty());
        assert!(AffectedPrefixes::between(&VrpSet::new(), &VrpSet::new()).is_empty());

        let mut new = old.clone();
        // A changed maximum length, a removal, an extra AS for a prefix
        // and a new prefix.
        new.remove(vrp("192.0.2.0/24", 24, 64_496));
        new.insert(vrp("192.0.2.0/24", 25, 64_496));
        new.remove(vrp("2001:db8::/32", 48, 64_496));
        new.insert(vrp("198.51.100.0/24", 24, 64_497));
        new.insert(vrp("10.0.0.0/8", 8, 64_496));
        let expected: PrefixSet = [
            "192.0.2.0/24",
            "2001:db8::/32",
            "198.51.100.0/24",
            "10.0.0.0/8",
        ]
        .into_iter()
        .map(p)
        .collect();
        assert_eq!(
            AffectedPrefixes::between(&old, &new),
            AffectedPrefixes::CoveredBy(expected.clone())
        );
        // Direction does not matter.
        assert_eq!(
            AffectedPrefixes::between(&new, &old),
            AffectedPrefixes::CoveredBy(expected)
        );
        assert!(!AffectedPrefixes::between(&old, &new).covers(p("203.0.113.0/24")));
    }

    #[test]
    fn a_vrp_that_can_never_match_still_affects_what_it_covers() {
        // RFC 6811 §4 calls a prefix affected if it "could be matched by an
        // added ... mapping". This route is longer than the maximum length,
        // so it never can be, yet it goes from NotFound to Invalid.
        let old = VrpSet::new();
        let new: VrpSet = [vrp("192.0.2.0/24", 24, 64_496)].into_iter().collect();
        let route = p("192.0.2.0/25");
        let origin = RouteOrigin::As(Asn(64_496));
        assert_eq!(old.validate(route, origin), RovState::NotFound);
        assert_eq!(new.validate(route, origin), RovState::Invalid);
        assert!(AffectedPrefixes::between(&old, &new).covers(route));
    }

    #[test]
    fn merge_unions_and_all_absorbs() {
        let mut a = AffectedPrefixes::from_vrps([vrp("192.0.2.0/24", 24, 64_496)]);
        a.merge(AffectedPrefixes::from_vrps([vrp(
            "2001:db8::/32",
            32,
            64_496,
        )]));
        assert!(a.covers(p("192.0.2.0/25")));
        assert!(a.covers(p("2001:db8::/64")));
        a.merge(AffectedPrefixes::none());
        assert!(a.covers(p("192.0.2.0/25")));
        assert!(!a.covers(p("198.51.100.0/24")));
        a.merge(AffectedPrefixes::All);
        assert_eq!(a, AffectedPrefixes::All);
        a.merge(AffectedPrefixes::from_vrps([vrp("10.0.0.0/8", 8, 64_496)]));
        assert_eq!(a, AffectedPrefixes::All);
        let mut none = AffectedPrefixes::none();
        none.merge(AffectedPrefixes::none());
        assert!(none.is_empty());
    }

    #[test]
    fn prefix_set_basics() {
        let mut set = PrefixSet::new();
        assert!(set.is_empty());
        assert!(set.insert(p("192.0.2.0/24")));
        assert!(!set.insert(p("192.0.2.0/24")));
        assert!(set.insert(p("192.0.2.0/25")));
        assert!(set.insert(p("::/0")));
        assert_eq!(set.len(), 3);
        assert!(set.contains(p("192.0.2.0/25")));
        assert!(!set.contains(p("192.0.2.128/25")));
        assert!(set.covers(p("192.0.2.128/25")));
        assert!(set.covers(p("2001:db8::/32")));
        assert!(!set.covers(p("192.0.0.0/16")));
        let mut listed: Vec<Prefix> = set.iter().collect();
        listed.sort();
        assert_eq!(listed, [p("192.0.2.0/24"), p("192.0.2.0/25"), p("::/0")]);
        let same: PrefixSet = listed.iter().rev().copied().collect();
        assert_eq!(set, same);
        assert_ne!(set, PrefixSet::new());
    }
}
