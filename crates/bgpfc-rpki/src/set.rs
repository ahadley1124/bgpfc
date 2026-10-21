//! A set of VRPs and the route origin validation procedure over it.
//!
//! Implements: RFC 6811 §2 (Covered, Matched; Valid, Invalid, `NotFound`;
//! "NONE" and AS 0 never match), §2.1 (the procedure: any matching VRP
//! decides, the order VRPs are visited in does not matter); RFC 6483 §4
//! (an AS 0 VRP makes what it covers Invalid unless another VRP
//! matches); RFC 7607 §2 (AS 0 is not a valid origin); RFC 9319 §3 (a
//! route longer than the maximum length is not authorised); RFC 8210
//! §5.6 (one VRP per {Prefix, Len, Max-Len, ASN}).

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Asn;

use crate::affected::PrefixSet;
use crate::index::{Bits, LenIndex};
use crate::origin::RouteOrigin;
use crate::state::RovState;
use crate::vrp::Vrp;

/// What one VRP authorises for its prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Auth {
    max_len: u8,
    asn: Asn,
}

/// The VRPs of one address family, grouped by prefix.
type Family<K> = LenIndex<K, Vec<Auth>>;

/// A set of VRPs, indexed for route origin validation.
///
/// Per address family there is one hash map per VRP prefix length, from
/// the network to the (maximum length, ASN) pairs of the VRPs with that
/// prefix, and a bitmask of the prefix lengths in use.
/// [`VrpSet::validate`] probes only those lengths, up to the route's
/// own, and never allocates: a few dozen hash lookups at most for a
/// full-table VRP set.
///
/// A VRP is stored once however often it is inserted: RFC 8210 §5.6
/// wants "one and only one `IPvX` PDU for a unique {Prefix, Len, Max-Len,
/// ASN}", so [`VrpSet::insert`] and [`VrpSet::remove`] report whether
/// they changed anything and let the caller detect duplicate
/// announcements and withdrawals of unknown VRPs.
#[derive(Clone, Debug, Default)]
pub struct VrpSet {
    v4: Family<u32>,
    v6: Family<u128>,
    len: usize,
}

impl VrpSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> VrpSet {
        VrpSet::default()
    }

    /// Number of VRPs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether there are no VRPs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Add `vrp`. `false` if it was already present, and nothing changed.
    pub fn insert(&mut self, vrp: Vrp) -> bool {
        let auth = Auth {
            max_len: vrp.max_len(),
            asn: vrp.asn(),
        };
        let added = match vrp.prefix() {
            Prefix::V4 { addr, len } => insert_in(&mut self.v4, u32::from(addr), len, auth),
            Prefix::V6 { addr, len } => insert_in(&mut self.v6, u128::from(addr), len, auth),
        };
        if added {
            self.len += 1;
        }
        added
    }

    /// Remove `vrp`. `false` if it was not present, and nothing changed.
    pub fn remove(&mut self, vrp: Vrp) -> bool {
        let auth = Auth {
            max_len: vrp.max_len(),
            asn: vrp.asn(),
        };
        let removed = match vrp.prefix() {
            Prefix::V4 { addr, len } => remove_in(&mut self.v4, u32::from(addr), len, auth),
            Prefix::V6 { addr, len } => remove_in(&mut self.v6, u128::from(addr), len, auth),
        };
        if removed {
            self.len -= 1;
        }
        removed
    }

    /// Whether `vrp` is in the set.
    #[must_use]
    pub fn contains(&self, vrp: Vrp) -> bool {
        let auth = Auth {
            max_len: vrp.max_len(),
            asn: vrp.asn(),
        };
        match vrp.prefix() {
            Prefix::V4 { addr, len } => auths(&self.v4, u32::from(addr), len).contains(&auth),
            Prefix::V6 { addr, len } => auths(&self.v6, u128::from(addr), len).contains(&auth),
        }
    }

    /// Every VRP, IPv4 first, otherwise in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = Vrp> + '_ {
        family_vrps(&self.v4).chain(family_vrps(&self.v6))
    }

    /// The validation state of a route for `prefix` whose Route Origin
    /// ASN is `origin` (RFC 6811 §2). Never `Disabled`.
    #[must_use]
    pub fn validate(&self, prefix: Prefix, origin: RouteOrigin) -> RovState {
        match prefix {
            Prefix::V4 { addr, len } => validate_in(&self.v4, u32::from(addr), len, origin),
            Prefix::V6 { addr, len } => validate_in(&self.v6, u128::from(addr), len, origin),
        }
    }
}

fn insert_in<K: Bits>(family: &mut Family<K>, key: K, len: u8, auth: Auth) -> bool {
    // `None` only for a length past the address size, which `Prefix`
    // rules out.
    let Some(auths) = family.get_or_default(key, len) else {
        return false;
    };
    if auths.contains(&auth) {
        return false;
    }
    auths.push(auth);
    true
}

fn remove_in<K: Bits>(family: &mut Family<K>, key: K, len: u8, auth: Auth) -> bool {
    let Some(auths) = family.get_mut(key, len) else {
        return false;
    };
    let Some(i) = auths.iter().position(|a| *a == auth) else {
        return false;
    };
    auths.swap_remove(i);
    if auths.is_empty() {
        // An empty list would make the prefix look like it still Covers.
        family.remove(key, len);
    }
    true
}

fn auths<K: Bits>(family: &Family<K>, key: K, len: u8) -> &[Auth] {
    family.get(key, len).map_or(&[], Vec::as_slice)
}

fn family_vrps<K: Bits>(family: &Family<K>) -> impl Iterator<Item = Vrp> + '_ {
    family.iter().flat_map(|(key, len, auths)| {
        auths
            .iter()
            .map(move |a| Vrp::from_parts(key.prefix(len), a.max_len, a.asn))
    })
}

fn validate_in<K: Bits>(family: &Family<K>, key: K, len: u8, origin: RouteOrigin) -> RovState {
    // RFC 6811 §2: "a Route whose Origin ASN is 'NONE' cannot be Matched
    // by any VRP" and "no Route can be Matched by a VRP whose ASN is
    // zero" (AS 0 VRPs: RFC 6483 §4; AS 0 is never a valid origin: RFC
    // 7607 §2). Matching needs the two ASNs to be equal, so refusing an
    // origin of AS 0 refuses every AS 0 VRP.
    let origin = match origin {
        RouteOrigin::As(asn) if asn != Asn(0) => Some(asn),
        RouteOrigin::As(_) | RouteOrigin::None => None,
    };
    let mut covered = false;
    // RFC 6811 §2: "Covered: ... the VRP prefix length is less than or
    // equal to the Route prefix length, and the VRP prefix address and the
    // Route prefix address are identical for all bits specified by the VRP
    // prefix length"; that is what `covering` yields.
    for auths in family.covering(key, len) {
        covered = true;
        // RFC 6811 §2: "Matched: ... Covered by that VRP, the Route prefix
        // length is less than or equal to the VRP maximum length, and the
        // Route Origin ASN is equal to the VRP ASN." One match is enough:
        // "Valid: At least one VRP Matches the Route Prefix."
        if let Some(origin) = origin
            && auths.iter().any(|a| len <= a.max_len && a.asn == origin)
        {
            return RovState::Valid;
        }
    }
    if covered {
        // RFC 6811 §2: "At least one VRP Covers the Route Prefix, but no
        // VRP Matches it."
        RovState::Invalid
    } else {
        // RFC 6811 §2: "No VRP Covers the Route Prefix."
        RovState::NotFound
    }
}

/// Add to `out` the prefix of every VRP that is in one of `old` and `new`
/// but not in the other. Compares all the VRPs of a prefix at once.
pub(crate) fn changed_prefixes(old: &VrpSet, new: &VrpSet, out: &mut PrefixSet) {
    changed_in(&old.v4, &new.v4, |key, len| {
        out.insert(key.prefix(len));
    });
    changed_in(&old.v6, &new.v6, |key, len| {
        out.insert(key.prefix(len));
    });
}

fn changed_in<K: Bits>(old: &Family<K>, new: &Family<K>, mut changed: impl FnMut(K, u8)) {
    for (key, len, before) in old.iter() {
        let after = auths(new, key, len);
        // Neither list holds an entry twice, so equal lengths and
        // inclusion one way make them equal.
        if before.len() != after.len() || !before.iter().all(|a| after.contains(a)) {
            changed(key, len);
        }
    }
    for (key, len, _) in new.iter() {
        if old.get(key, len).is_none() {
            changed(key, len);
        }
    }
}

impl PartialEq for VrpSet {
    /// Same VRPs, whatever order they were inserted in.
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.iter().all(|vrp| other.contains(vrp))
    }
}

impl Eq for VrpSet {}

impl Extend<Vrp> for VrpSet {
    fn extend<I: IntoIterator<Item = Vrp>>(&mut self, iter: I) {
        for vrp in iter {
            self.insert(vrp);
        }
    }
}

impl FromIterator<Vrp> for VrpSet {
    fn from_iter<I: IntoIterator<Item = Vrp>>(iter: I) -> Self {
        let mut set = VrpSet::new();
        set.extend(iter);
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use RovState::{Invalid, NotFound, Valid};

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(p(prefix), max_len, Asn(asn)).unwrap()
    }

    fn set(vrps: &[Vrp]) -> VrpSet {
        vrps.iter().copied().collect()
    }

    fn by(asn: u32) -> RouteOrigin {
        RouteOrigin::As(Asn(asn))
    }

    #[track_caller]
    fn check(set: &VrpSet, cases: &[(&str, RouteOrigin, RovState)]) {
        for (prefix, origin, want) in cases {
            assert_eq!(
                set.validate(p(prefix), *origin),
                *want,
                "{prefix} from {origin}"
            );
        }
    }

    #[test]
    fn single_roa_outcomes() {
        // RFC 6483 §2, the "Route's Validity State" table for one ROA,
        // row by row, with a matching and a non-matching origin AS.
        let set = set(&[vrp("198.51.100.0/24", 24, 64_496)]);
        check(
            &set,
            &[
                // Non-intersecting: unknown.
                ("203.0.113.0/24", by(64_496), NotFound),
                ("203.0.113.0/24", by(64_511), NotFound),
                // Covering aggregate: unknown.
                ("198.51.0.0/16", by(64_496), NotFound),
                ("198.51.0.0/16", by(64_511), NotFound),
                // Match ROA prefix: valid / invalid.
                ("198.51.100.0/24", by(64_496), Valid),
                ("198.51.100.0/24", by(64_511), Invalid),
                // More specific than ROA: invalid / invalid.
                ("198.51.100.128/25", by(64_496), Invalid),
                ("198.51.100.128/25", by(64_511), Invalid),
            ],
        );
    }

    #[test]
    fn loose_and_minimal_roas() {
        // RFC 9319 §3: the loose ROA (192.168.0.0/16-24, AS 64496)
        // authorises the forged-origin sub-prefix hijack "192.168.0.0/24:
        // AS 64511, AS 64496": the route is Valid.
        let loose = set(&[vrp("192.168.0.0/16", 24, 64_496)]);
        check(
            &loose,
            &[
                ("192.168.0.0/24", by(64_496), Valid),
                ("192.168.225.0/24", by(64_496), Valid),
                ("192.168.0.0/16", by(64_496), Valid),
                ("192.168.0.0/25", by(64_496), Invalid),
            ],
        );
        // The minimal ROA (192.168.0.0/16, 192.168.225.0/24, AS 64496)
        // makes the same announcement Invalid.
        let minimal = set(&[
            vrp("192.168.0.0/16", 16, 64_496),
            vrp("192.168.225.0/24", 24, 64_496),
        ]);
        check(
            &minimal,
            &[
                ("192.168.0.0/24", by(64_496), Invalid),
                ("192.168.225.0/24", by(64_496), Valid),
                ("192.168.0.0/16", by(64_496), Valid),
                ("192.168.225.0/24", by(64_511), Invalid),
            ],
        );
    }

    #[test]
    fn max_len_edges() {
        // RFC 6811 §2: Matched needs "the Route prefix length is less than
        // or equal to the VRP maximum length"; RFC 9319 §3: nothing longer
        // is authorised.
        let set = set(&[
            vrp("2001:db8::/32", 48, 64_496),
            vrp("192.0.2.0/24", 24, 64_496),
            vrp("198.51.100.0/24", 26, 64_496),
        ]);
        check(
            &set,
            &[
                // Exactly max_len.
                ("2001:db8:ffff::/48", by(64_496), Valid),
                ("198.51.100.192/26", by(64_496), Valid),
                // One longer.
                ("2001:db8:ffff::/49", by(64_496), Invalid),
                ("198.51.100.192/27", by(64_496), Invalid),
                // Between prefix length and max_len.
                ("2001:db8:ff00::/40", by(64_496), Valid),
                ("198.51.100.0/25", by(64_496), Valid),
                // max_len == prefix length: only the prefix itself.
                ("192.0.2.0/24", by(64_496), Valid),
                ("192.0.2.0/25", by(64_496), Invalid),
                ("192.0.2.1/32", by(64_496), Invalid),
            ],
        );
    }

    #[test]
    fn as0_never_matches() {
        // RFC 6483 §4: an AS 0 ROA says the prefix "and any more specific
        // prefix, should not be used in a routing context".
        let as0 = set(&[vrp("192.0.2.0/24", 32, 0), vrp("2001:db8::/32", 128, 0)]);
        check(
            &as0,
            &[
                ("192.0.2.0/24", by(64_496), Invalid),
                ("192.0.2.128/28", by(64_496), Invalid),
                ("2001:db8::/48", by(64_496), Invalid),
                // RFC 6811 §2: "no Route can be Matched by a VRP whose ASN
                // is zero", not even a route claiming AS 0 (RFC 7607 §2).
                ("192.0.2.0/24", by(0), Invalid),
                ("2001:db8::/32", by(0), Invalid),
                ("192.0.2.0/24", RouteOrigin::None, Invalid),
                // An AS 0 VRP covers like any other: nothing outside it.
                ("192.0.0.0/16", by(64_496), NotFound),
            ],
        );
        // RFC 6483 §4: other ROAs may still authorise more specifics, and
        // "the presence or lack of presence of the AS 0 ROA does not alter
        // the route's validity state" when they match.
        let mut mixed = as0.clone();
        mixed.insert(vrp("192.0.2.0/26", 26, 64_496));
        check(
            &mixed,
            &[
                ("192.0.2.0/26", by(64_496), Valid),
                ("192.0.2.64/26", by(64_496), Invalid),
                ("192.0.2.0/26", by(64_511), Invalid),
            ],
        );
    }

    #[test]
    fn one_matching_vrp_among_several_suffices() {
        // RFC 6811 §2: "Valid: At least one VRP Matches"; §2.1: the order in
        // which VRPs are visited does not matter.
        let vrps = [
            vrp("10.0.0.0/8", 8, 64_496),
            vrp("10.0.0.0/16", 24, 64_497),
            vrp("10.0.0.0/24", 24, 64_498),
            vrp("10.0.0.0/24", 24, 64_499),
            vrp("10.0.0.0/24", 28, 0),
        ];
        let forward = set(&vrps);
        let mut reversed = vrps;
        reversed.reverse();
        let reversed = set(&reversed);
        assert_eq!(forward, reversed);
        for set in [&forward, &reversed] {
            check(
                set,
                &[
                    ("10.0.0.0/24", by(64_497), Valid),
                    ("10.0.0.0/24", by(64_498), Valid),
                    ("10.0.0.0/24", by(64_499), Valid),
                    ("10.0.0.0/24", by(64_496), Invalid),
                    ("10.0.0.0/8", by(64_496), Valid),
                    ("10.0.0.0/8", by(64_497), Invalid),
                    ("10.0.0.0/20", by(64_497), Valid),
                    ("10.0.0.0/25", by(64_498), Invalid),
                    ("10.1.0.0/16", by(64_497), Invalid),
                    ("11.0.0.0/8", by(64_496), NotFound),
                ],
            );
        }
    }

    #[test]
    fn origin_none_never_matches() {
        // RFC 6811 §2: "a Route whose Origin ASN is 'NONE' cannot be
        // Matched by any VRP".
        let set = set(&[vrp("192.0.2.0/24", 32, 64_496), vrp("::/0", 128, 64_496)]);
        check(
            &set,
            &[
                ("192.0.2.0/24", RouteOrigin::None, Invalid),
                ("2001:db8::/32", RouteOrigin::None, Invalid),
                ("198.51.100.0/24", RouteOrigin::None, NotFound),
            ],
        );
    }

    #[test]
    fn confederation_routes_validate_against_the_local_as() {
        // RFC 6811 §2: the Route Origin ASN of a route whose final segment
        // is a confederation segment, or whose path is empty, is the
        // speaker's own AS.
        use bgpfc_wire::as_path::{AsPath, AsPathSegment, SegmentType};
        let local = Asn(64_500);
        let set = set(&[vrp("192.0.2.0/24", 24, 64_500)]);
        let confed = AsPath {
            segments: vec![AsPathSegment {
                kind: SegmentType::ConfedSequence,
                asns: vec![Asn(65_100)],
            }],
        };
        for path in [AsPath::empty(), confed] {
            let origin = RouteOrigin::from_as_path(&path, local);
            assert_eq!(set.validate(p("192.0.2.0/24"), origin), Valid);
            let elsewhere = RouteOrigin::from_as_path(&path, Asn(64_501));
            assert_eq!(set.validate(p("192.0.2.0/24"), elsewhere), Invalid);
        }
        let aggregate = AsPath {
            segments: vec![AsPathSegment {
                kind: SegmentType::Set,
                asns: vec![Asn(64_500)],
            }],
        };
        let origin = RouteOrigin::from_as_path(&aggregate, local);
        assert_eq!(set.validate(p("192.0.2.0/24"), origin), Invalid);
    }

    #[test]
    fn families_are_separate() {
        let v4 = set(&[vrp("0.0.0.0/0", 32, 64_496)]);
        check(
            &v4,
            &[
                // An IPv4 VRP for 0.0.0.0/0 covers every IPv4 route...
                ("0.0.0.0/0", by(64_496), Valid),
                ("203.0.113.7/32", by(64_496), Valid),
                ("203.0.113.7/32", by(64_497), Invalid),
                // ...and no IPv6 route, not even ::/0 or ::ffff:0:0/96.
                ("::/0", by(64_496), NotFound),
                ("::ffff:0:0/96", by(64_496), NotFound),
            ],
        );
        let v6 = set(&[vrp("2001:db8::/32", 32, 64_497)]);
        check(
            &v6,
            &[
                ("2001:db8::/32", by(64_497), Valid),
                ("2001:db8::1/128", by(64_497), Invalid),
                ("2001:db9::/32", by(64_497), NotFound),
                // 32.1.13.184 has the leading 32 bits of 2001:db8::.
                ("32.1.13.184/32", by(64_497), NotFound),
                ("0.0.0.0/0", by(64_497), NotFound),
            ],
        );
    }

    #[test]
    fn host_routes_and_default_vrps() {
        let set = set(&[
            vrp("192.0.2.1/32", 32, 64_496),
            vrp("2001:db8::1/128", 128, 64_496),
            vrp("::/0", 0, 64_497),
        ]);
        check(
            &set,
            &[
                ("192.0.2.1/32", by(64_496), Valid),
                ("192.0.2.2/32", by(64_496), NotFound),
                ("192.0.2.0/31", by(64_496), NotFound),
                ("2001:db8::1/128", by(64_496), Valid),
                ("2001:db8::2/128", by(64_496), Invalid),
                ("::/0", by(64_497), Valid),
                ("2001:db8::/32", by(64_497), Invalid),
            ],
        );
    }

    #[test]
    fn empty_set_finds_nothing() {
        let set = VrpSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.iter().count(), 0);
        check(
            &set,
            &[
                ("0.0.0.0/0", by(64_496), NotFound),
                ("::/0", RouteOrigin::None, NotFound),
            ],
        );
    }

    #[test]
    fn insert_and_remove_report_changes() {
        // RFC 8210 §5.6: one entry per {Prefix, Len, Max-Len, ASN}; the RTR
        // client needs to know about duplicates and unknown withdrawals.
        let a = vrp("192.0.2.0/24", 24, 64_496);
        let b = vrp("192.0.2.0/24", 25, 64_496);
        let c = vrp("192.0.2.0/24", 24, 64_497);
        let d = vrp("2001:db8::/32", 48, 64_496);
        let mut set = VrpSet::new();
        assert!(set.insert(a));
        assert!(!set.insert(a));
        assert!(set.insert(b));
        assert!(set.insert(c));
        assert!(set.insert(d));
        assert!(!set.insert(d));
        assert_eq!(set.len(), 4);
        assert!(set.contains(a) && set.contains(b) && set.contains(c) && set.contains(d));
        let mut all: Vec<Vrp> = set.iter().collect();
        all.sort();
        // Ordered by prefix, then maximum length, then AS.
        assert_eq!(all, [a, c, b, d]);

        assert!(set.remove(b));
        assert!(!set.remove(b));
        assert!(!set.contains(b));
        assert!(!set.remove(vrp("192.0.2.0/25", 25, 64_496)));
        assert_eq!(set.len(), 3);
        assert_eq!(set.validate(p("192.0.2.0/25"), by(64_496)), Invalid);

        // Removing the last VRP of a prefix uncovers it.
        assert!(set.remove(a));
        assert!(set.remove(c));
        assert_eq!(set.validate(p("192.0.2.0/24"), by(64_496)), NotFound);
        assert!(set.remove(d));
        assert!(set.is_empty());
        assert_eq!(set, VrpSet::new());
        assert_eq!(set.validate(p("2001:db8::/32"), by(64_496)), NotFound);
    }

    #[test]
    fn equality_ignores_insertion_order() {
        let a = vrp("192.0.2.0/24", 24, 64_496);
        let b = vrp("192.0.2.0/24", 24, 64_497);
        let one: VrpSet = [a, b].into_iter().collect();
        let two: VrpSet = [b, a, b].into_iter().collect();
        assert_eq!(one, two);
        assert_eq!(two.len(), 2);
        let three: VrpSet = [a].into_iter().collect();
        assert_ne!(one, three);
        let mut four = three.clone();
        four.extend([vrp("192.0.2.0/24", 24, 64_498)]);
        assert_ne!(one, four);
    }
}
