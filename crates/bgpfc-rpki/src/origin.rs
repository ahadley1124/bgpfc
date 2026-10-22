//! The origin AS that route origin validation checks.
//!
//! Implements: RFC 6811 §2 (Route Origin ASN, including the distinguished
//! value "NONE"); RFC 6483 §2 (an aggregate's origin cannot be
//! determined).

use std::fmt;

use bgpfc_wire::as_path::{AsPath, SegmentType};
use bgpfc_wire::types::Asn;

/// The Route Origin ASN of RFC 6811 §2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteOrigin {
    /// The route was originated by this AS.
    As(Asn),
    /// The distinguished value "NONE": the origin cannot be determined.
    /// No VRP can match it (RFC 6811 §2).
    None,
}

impl RouteOrigin {
    /// Derive the Route Origin ASN from a route's `AS_PATH` and the
    /// speaker's own AS.
    ///
    /// `path` must be the path as the speaker understands it: for a route
    /// from a two-octet peer, the `AS_PATH` merged with `AS4_PATH`
    /// (RFC 6793 §4.2.3), or the origin may be `AS_TRANS`.
    #[must_use]
    pub fn from_as_path(path: &AsPath, local_as: Asn) -> RouteOrigin {
        // RFC 6811 §2: "Route Origin ASN: The origin AS number derived from
        // a Route as follows:
        //   * the rightmost AS in the final segment of the AS_PATH attribute
        //     in the Route if that segment is of type AS_SEQUENCE, or
        //   * the BGP speaker's own AS number if that segment is of type
        //     AS_CONFED_SEQUENCE or AS_CONFED_SET or if the AS_PATH is
        //     empty, or
        //   * the distinguished value "NONE" if the final segment of the
        //     AS_PATH attribute is of any other type."
        let Some(last) = path.segments.last() else {
            return RouteOrigin::As(local_as);
        };
        match last.kind {
            // An AS_SEQUENCE without ASes is malformed (RFC 7606 §7.2) and
            // cannot be decoded; were one built by hand, it has no
            // rightmost AS, so its origin cannot be determined.
            SegmentType::Sequence => last
                .asns
                .last()
                .map_or(RouteOrigin::None, |&asn| RouteOrigin::As(asn)),
            SegmentType::ConfedSequence | SegmentType::ConfedSet => RouteOrigin::As(local_as),
            // RFC 6483 §2: with an AS_SET "the route is an aggregate, then
            // the origin AS cannot be determined".
            SegmentType::Set => RouteOrigin::None,
        }
    }
}

impl fmt::Display for RouteOrigin {
    /// `AS64496`, or `none`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteOrigin::As(asn) => write!(f, "{asn}"),
            RouteOrigin::None => f.write_str("none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use bgpfc_wire::as_path::AsPathSegment;

    use super::*;

    const LOCAL: Asn = Asn(64_500);

    fn seg(kind: SegmentType, asns: &[u32]) -> AsPathSegment {
        AsPathSegment {
            kind,
            asns: asns.iter().map(|&a| Asn(a)).collect(),
        }
    }

    fn origin(segments: Vec<AsPathSegment>) -> RouteOrigin {
        RouteOrigin::from_as_path(&AsPath { segments }, LOCAL)
    }

    #[test]
    fn rightmost_as_of_a_final_sequence() {
        // RFC 6811 §2, first bullet.
        assert_eq!(
            origin(vec![seg(SegmentType::Sequence, &[64_496, 64_497, 64_498])]),
            RouteOrigin::As(Asn(64_498))
        );
        assert_eq!(
            origin(vec![seg(SegmentType::Sequence, &[64_496])]),
            RouteOrigin::As(Asn(64_496))
        );
        // Only the final segment counts.
        assert_eq!(
            origin(vec![
                seg(SegmentType::Sequence, &[64_496]),
                seg(SegmentType::Set, &[64_497, 64_498]),
                seg(SegmentType::Sequence, &[64_499, 64_510]),
            ]),
            RouteOrigin::As(Asn(64_510))
        );
        // A path that crossed a confederation and then left it.
        assert_eq!(
            origin(vec![
                seg(SegmentType::ConfedSequence, &[65_100, 65_101]),
                seg(SegmentType::Sequence, &[64_496, 64_497]),
            ]),
            RouteOrigin::As(Asn(64_497))
        );
        // Four-octet origins are origins like any other (RFC 6811 §3).
        assert_eq!(
            origin(vec![seg(SegmentType::Sequence, &[64_496, 4_200_000_000])]),
            RouteOrigin::As(Asn(4_200_000_000))
        );
    }

    #[test]
    fn local_as_for_an_empty_path_or_a_final_confed_segment() {
        // RFC 6811 §2, second bullet.
        assert_eq!(origin(vec![]), RouteOrigin::As(LOCAL));
        assert_eq!(
            RouteOrigin::from_as_path(&AsPath::empty(), Asn(4_200_000_000)),
            RouteOrigin::As(Asn(4_200_000_000))
        );
        assert_eq!(
            origin(vec![seg(SegmentType::ConfedSequence, &[65_100, 65_101])]),
            RouteOrigin::As(LOCAL)
        );
        assert_eq!(
            origin(vec![seg(SegmentType::ConfedSet, &[65_100, 65_101])]),
            RouteOrigin::As(LOCAL)
        );
        assert_eq!(
            origin(vec![
                seg(SegmentType::Sequence, &[64_496]),
                seg(SegmentType::ConfedSequence, &[65_100]),
            ]),
            RouteOrigin::As(LOCAL)
        );
    }

    #[test]
    fn none_for_any_other_final_segment() {
        // RFC 6811 §2, third bullet; RFC 6483 §2: an aggregate.
        assert_eq!(
            origin(vec![seg(SegmentType::Set, &[64_496, 64_497])]),
            RouteOrigin::None
        );
        assert_eq!(
            origin(vec![
                seg(SegmentType::Sequence, &[64_496, 64_497]),
                seg(SegmentType::Set, &[64_498]),
            ]),
            RouteOrigin::None
        );
        // A set earlier in the path does not hide a final sequence.
        assert_ne!(
            origin(vec![
                seg(SegmentType::Set, &[64_498]),
                seg(SegmentType::Sequence, &[64_496]),
            ]),
            RouteOrigin::None
        );
        // A hand-built empty sequence has no rightmost AS.
        assert_eq!(
            origin(vec![seg(SegmentType::Sequence, &[])]),
            RouteOrigin::None
        );
    }

    #[test]
    fn display() {
        assert_eq!(RouteOrigin::As(Asn(64_496)).to_string(), "AS64496");
        assert_eq!(RouteOrigin::None.to_string(), "none");
    }
}
