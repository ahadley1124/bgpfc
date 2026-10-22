//! The `AS_PATH` attribute and its four-octet companion `AS4_PATH`.
//!
//! Implements: RFC 4271 §4.3 b) (segment encoding), §5.1.2 (semantics),
//! §9.1.2.2 (AS count); RFC 7606 §7.2 (malformation); RFC 6793 §3,
//! §4.2.2 (`AS_TRANS` in two-octet paths), §4.2.3 (merging `AS4_PATH`),
//! §6 (confederation segments never in `AS4_PATH`); RFC 5065 §3 (segment
//! types 3 and 4 exist, so they must be recognised), §5.3 (confederation
//! segments do not count); RFC 9774 §3 (`AS_SET` deprecated); RFC 7607
//! §2 (AS 0 is malformed).

use std::fmt;

use crate::error::EncodeError;
use crate::reader::{Reader, WriteBytes as _};
use crate::types::Asn;

/// Path segment types (RFC 4271 §4.3; RFC 5065 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SegmentType {
    /// Unordered set of ASes (deprecated by RFC 9774 §3; never generated).
    Set = 1,
    /// Ordered sequence of ASes.
    Sequence = 2,
    /// Ordered sequence of member ASes within a confederation.
    ConfedSequence = 3,
    /// Unordered set of member ASes within a confederation (deprecated).
    ConfedSet = 4,
}

impl SegmentType {
    /// From the wire value; `None` is a malformed path (RFC 7606 §7.2).
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(SegmentType::Set),
            2 => Some(SegmentType::Sequence),
            3 => Some(SegmentType::ConfedSequence),
            4 => Some(SegmentType::ConfedSet),
            _ => None,
        }
    }

    /// Whether this is one of the RFC 5065 confederation types.
    #[must_use]
    pub const fn is_confed(self) -> bool {
        matches!(self, SegmentType::ConfedSequence | SegmentType::ConfedSet)
    }

    /// Whether this is a set type (unordered; counts as one AS).
    #[must_use]
    pub const fn is_set(self) -> bool {
        matches!(self, SegmentType::Set | SegmentType::ConfedSet)
    }
}

/// One `<type, length, ASes>` segment. A segment on the wire holds 1..=255
/// ASes; an empty one is malformed (RFC 7606 §7.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AsPathSegment {
    /// Segment type.
    pub kind: SegmentType,
    /// AS numbers in wire order (leftmost first).
    pub asns: Vec<Asn>,
}

/// Largest number of ASes one segment can hold (one-octet count).
pub const MAX_SEGMENT_LEN: usize = 255;

/// An `AS_PATH`: a list of segments, leftmost segment first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AsPath {
    /// Segments in wire order.
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// The empty path an originator sends to internal peers
    /// (RFC 4271 §5.1.2).
    #[must_use]
    pub const fn empty() -> AsPath {
        AsPath {
            segments: Vec::new(),
        }
    }

    /// A single `AS_SEQUENCE` segment. Empty input gives the empty path.
    #[must_use]
    pub fn sequence(asns: &[Asn]) -> AsPath {
        if asns.is_empty() {
            return AsPath::empty();
        }
        AsPath {
            segments: vec![AsPathSegment {
                kind: SegmentType::Sequence,
                asns: asns.to_vec(),
            }],
        }
    }

    /// Decode an `AS_PATH` or `AS4_PATH` value. `four_octet` selects the
    /// ASN width (RFC 6793 §3).
    ///
    /// # Errors
    /// [`AsPathError`] for the RFC 7606 §7.2 malformations: unknown segment
    /// type, zero segment length, a segment running past the attribute, or
    /// a lone trailing octet.
    pub fn decode(bytes: &[u8], four_octet: bool) -> Result<AsPath, AsPathError> {
        let mut r = Reader::new(bytes);
        let mut segments = Vec::new();
        while !r.is_empty() {
            // RFC 7606 §7.2: fewer than two octets cannot hold a segment header.
            if r.remaining() < 2 {
                return Err(AsPathError::Underrun);
            }
            let kind = r.u8().map_err(|_| AsPathError::Underrun)?;
            let kind = SegmentType::from_u8(kind).ok_or(AsPathError::UnknownSegmentType(kind))?;
            let count = r.u8().map_err(|_| AsPathError::Underrun)?;
            if count == 0 {
                return Err(AsPathError::ZeroLengthSegment);
            }
            let mut asns = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                let asn = if four_octet {
                    r.u32().map_err(|_| AsPathError::Overrun)?
                } else {
                    u32::from(r.u16().map_err(|_| AsPathError::Overrun)?)
                };
                asns.push(Asn(asn));
            }
            segments.push(AsPathSegment { kind, asns });
        }
        Ok(AsPath { segments })
    }

    /// Append the wire form. With `four_octet` false, non-mappable ASNs are
    /// written as `AS_TRANS` (RFC 6793 §4.2.2); the caller adds an
    /// `AS4_PATH` when [`AsPath::has_non_mappable`] says so.
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] for a segment with more than 255 ASes, and
    /// [`EncodeError::EmptySegment`] for one with none.
    pub fn encode(&self, four_octet: bool, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        for seg in &self.segments {
            let count = u8::try_from(seg.asns.len()).map_err(|_| EncodeError::TooLong {
                what: "AS_PATH segment",
                len: seg.asns.len(),
                max: MAX_SEGMENT_LEN,
            })?;
            if count == 0 {
                return Err(EncodeError::EmptySegment);
            }
            out.put_u8(seg.kind as u8);
            out.put_u8(count);
            for asn in &seg.asns {
                if four_octet {
                    out.put_u32(asn.0);
                } else {
                    out.put_u16(asn.to_two_octet());
                }
            }
        }
        Ok(())
    }

    /// Number of ASes for path-length comparison: each AS in a sequence
    /// counts one, a set counts one, confederation segments count nothing
    /// (RFC 4271 §9.1.2.2; RFC 5065 §5.3). Also the count RFC 6793 §4.2.3
    /// uses to merge `AS4_PATH`.
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.segments
            .iter()
            .map(|s| match s.kind {
                SegmentType::Sequence => s.asns.len(),
                SegmentType::Set => 1,
                SegmentType::ConfedSequence | SegmentType::ConfedSet => 0,
            })
            .sum()
    }

    /// Every ASN in every segment, leftmost first.
    pub fn asns(&self) -> impl Iterator<Item = Asn> + '_ {
        self.segments.iter().flat_map(|s| s.asns.iter().copied())
    }

    /// The leftmost AS, if any (what RFC 4271 §6.3 compares to the sending
    /// external peer's AS).
    #[must_use]
    pub fn first_asn(&self) -> Option<Asn> {
        self.asns().next()
    }

    /// Whether any ASN needs four octets (RFC 6793 §4.2.2: then an
    /// `AS4_PATH` accompanies a two-octet `AS_PATH`).
    #[must_use]
    pub fn has_non_mappable(&self) -> bool {
        self.asns().any(|a| !a.is_mappable())
    }

    /// Whether any segment is an `AS_SET` or `AS_CONFED_SET` (RFC 9774 §3).
    #[must_use]
    pub fn contains_set(&self) -> bool {
        self.segments.iter().any(|s| s.kind.is_set())
    }

    /// Whether any segment is a confederation segment (RFC 5065 §3).
    #[must_use]
    pub fn contains_confed(&self) -> bool {
        self.segments.iter().any(|s| s.kind.is_confed())
    }

    /// Whether AS 0 appears anywhere (RFC 7607 §2: malformed).
    #[must_use]
    pub fn contains_as0(&self) -> bool {
        self.asns().any(|a| a == Asn(0))
    }

    /// Whether the path contains `asn` (loop detection, RFC 4271 §9.1.2).
    #[must_use]
    pub fn contains(&self, asn: Asn) -> bool {
        self.asns().any(|a| a == asn)
    }

    /// The path with confederation segments removed, as `AS4_PATH` must be
    /// built (RFC 6793 §4.2.2) and as a received `AS4_PATH` is cleaned
    /// (RFC 6793 §6).
    #[must_use]
    pub fn without_confed(&self) -> AsPath {
        AsPath {
            segments: self
                .segments
                .iter()
                .filter(|s| !s.kind.is_confed())
                .cloned()
                .collect(),
        }
    }

    /// Reconstruct the full path from a two-octet `AS_PATH` and the
    /// `AS4_PATH` that travelled with it (RFC 6793 §4.2.3).
    ///
    /// If `AS_PATH` has fewer ASes than `AS4_PATH`, `AS4_PATH` is ignored.
    /// Otherwise as many leading ASes of `AS_PATH` as the difference are
    /// prepended to `AS4_PATH`; a confederation segment is prepended when it
    /// leads or is adjacent to a prepended segment.
    #[must_use]
    pub fn merge_as4(as_path: &AsPath, as4_path: &AsPath) -> AsPath {
        let count = as_path.hop_count();
        let count4 = as4_path.hop_count();
        if count < count4 {
            return as_path.clone();
        }
        let mut need = count - count4;
        let mut segments = Vec::new();
        // The loop runs only while segments are being prepended, so every
        // confederation segment it meets is leading or adjacent to one.
        for seg in &as_path.segments {
            if seg.kind.is_confed() {
                segments.push(seg.clone());
                continue;
            }
            if need == 0 {
                break;
            }
            match seg.kind {
                SegmentType::Sequence if seg.asns.len() <= need => {
                    need -= seg.asns.len();
                    segments.push(seg.clone());
                }
                SegmentType::Sequence => {
                    segments.push(AsPathSegment {
                        kind: SegmentType::Sequence,
                        asns: seg.asns[..need].to_vec(),
                    });
                    need = 0;
                }
                _ => {
                    need -= 1;
                    segments.push(seg.clone());
                }
            }
        }
        segments.extend(as4_path.segments.iter().cloned());
        AsPath { segments }
    }
}

/// Why an `AS_PATH` is malformed (RFC 7606 §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsPathError {
    /// Segment type other than 1..=4.
    UnknownSegmentType(u8),
    /// A segment with a Path Segment Length of zero.
    ZeroLengthSegment,
    /// A segment's ASes run past the attribute.
    Overrun,
    /// A single octet remains after the last segment.
    Underrun,
}

impl fmt::Display for AsPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsPathError::UnknownSegmentType(t) => write!(f, "unknown AS_PATH segment type {t}"),
            AsPathError::ZeroLengthSegment => f.write_str("AS_PATH segment of length zero"),
            AsPathError::Overrun => f.write_str("AS_PATH segment overruns the attribute"),
            AsPathError::Underrun => f.write_str("AS_PATH has a trailing octet"),
        }
    }
}

impl std::error::Error for AsPathError {}

impl fmt::Display for AsPath {
    /// `65001 65002 { 65003 65004 } ( 65005 )` style: sequences as numbers,
    /// sets in braces, confederation segments in parentheses / brackets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for seg in &self.segments {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            let (open, close) = match seg.kind {
                SegmentType::Sequence => ("", ""),
                SegmentType::Set => ("{ ", " }"),
                SegmentType::ConfedSequence => ("( ", " )"),
                SegmentType::ConfedSet => ("[ ", " ]"),
            };
            f.write_str(open)?;
            for (i, asn) in seg.asns.iter().enumerate() {
                if i > 0 {
                    f.write_str(" ")?;
                }
                write!(f, "{}", asn.0)?;
            }
            f.write_str(close)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(asns: &[u32]) -> AsPathSegment {
        AsPathSegment {
            kind: SegmentType::Sequence,
            asns: asns.iter().map(|&a| Asn(a)).collect(),
        }
    }

    fn set(asns: &[u32]) -> AsPathSegment {
        AsPathSegment {
            kind: SegmentType::Set,
            asns: asns.iter().map(|&a| Asn(a)).collect(),
        }
    }

    #[test]
    fn two_and_four_octet_round_trips() {
        let path = AsPath {
            segments: vec![seq(&[65_001, 65_002]), set(&[65_003])],
        };
        let mut two = Vec::new();
        path.encode(false, &mut two).unwrap();
        assert_eq!(two, [2, 2, 0xfd, 0xe9, 0xfd, 0xea, 1, 1, 0xfd, 0xeb]);
        assert_eq!(AsPath::decode(&two, false).unwrap(), path);
        let mut four = Vec::new();
        path.encode(true, &mut four).unwrap();
        assert_eq!(
            four,
            [
                2, 2, 0, 0, 0xfd, 0xe9, 0, 0, 0xfd, 0xea, 1, 1, 0, 0, 0xfd, 0xeb
            ]
        );
        assert_eq!(AsPath::decode(&four, true).unwrap(), path);
        assert_eq!(AsPath::decode(&[], true).unwrap(), AsPath::empty());
        assert_eq!(path.to_string(), "65001 65002 { 65003 }");
    }

    #[test]
    fn as_trans_replaces_non_mappable_asns_in_two_octet_paths() {
        // RFC 6793 §4.2.2.
        let path = AsPath::sequence(&[Asn(4_200_000_000), Asn(65_002)]);
        assert!(path.has_non_mappable());
        let mut two = Vec::new();
        path.encode(false, &mut two).unwrap();
        assert_eq!(two, [2, 2, 0x5b, 0xa0, 0xfd, 0xea]);
        assert_eq!(
            AsPath::decode(&two, false).unwrap(),
            AsPath::sequence(&[Asn::TRANS, Asn(65_002)])
        );
    }

    #[test]
    fn malformations_per_rfc7606() {
        assert_eq!(
            AsPath::decode(&[5, 1, 0, 1], false),
            Err(AsPathError::UnknownSegmentType(5))
        );
        assert_eq!(
            AsPath::decode(&[2, 0], false),
            Err(AsPathError::ZeroLengthSegment)
        );
        assert_eq!(
            AsPath::decode(&[2, 2, 0, 1], false),
            Err(AsPathError::Overrun)
        );
        assert_eq!(
            AsPath::decode(&[2, 1, 0, 0, 0, 1], true)
                .unwrap()
                .hop_count(),
            1
        );
        assert_eq!(
            AsPath::decode(&[2, 1, 0, 1, 2], false),
            Err(AsPathError::Underrun)
        );
        assert_eq!(AsPath::decode(&[2], false), Err(AsPathError::Underrun));
    }

    #[test]
    fn encode_rejects_bad_segments() {
        let big = AsPath {
            segments: vec![seq(&vec![1; 256])],
        };
        assert!(matches!(
            big.encode(true, &mut Vec::new()),
            Err(EncodeError::TooLong {
                what: "AS_PATH segment",
                ..
            })
        ));
        let empty = AsPath {
            segments: vec![seq(&[])],
        };
        assert_eq!(
            empty.encode(true, &mut Vec::new()),
            Err(EncodeError::EmptySegment)
        );
    }

    #[test]
    fn counting_and_predicates() {
        let path = AsPath {
            segments: vec![
                AsPathSegment {
                    kind: SegmentType::ConfedSequence,
                    asns: vec![Asn(65_100), Asn(65_101)],
                },
                seq(&[65_001, 65_002, 65_003]),
                set(&[65_004, 65_005]),
            ],
        };
        // RFC 4271 §9.1.2.2 + RFC 5065 §5.3: 3 + 1 + 0.
        assert_eq!(path.hop_count(), 4);
        assert!(path.contains_set());
        assert!(path.contains_confed());
        assert!(!path.contains_as0());
        assert!(path.contains(Asn(65_005)));
        assert_eq!(path.first_asn(), Some(Asn(65_100)));
        assert_eq!(
            path.without_confed().segments,
            vec![seq(&[65_001, 65_002, 65_003]), set(&[65_004, 65_005])]
        );
        assert!(AsPath::sequence(&[Asn(1), Asn(0)]).contains_as0());
        assert_eq!(AsPath::empty().first_asn(), None);
        assert_eq!(
            path.to_string(),
            "( 65100 65101 ) 65001 65002 65003 { 65004 65005 }"
        );
    }

    #[test]
    fn as4_merge_per_rfc6793() {
        // The route crossed two OLD speakers (65010, 65011) after leaving the
        // last NEW speaker; AS_PATH has them plus AS_TRANS for the 4-octet AS.
        let as_path = AsPath::sequence(&[Asn(65_010), Asn(65_011), Asn::TRANS, Asn(65_002)]);
        let as4_path = AsPath::sequence(&[Asn(4_200_000_000), Asn(65_002)]);
        let merged = AsPath::merge_as4(&as_path, &as4_path);
        assert_eq!(
            merged.segments,
            vec![seq(&[65_010, 65_011]), seq(&[4_200_000_000, 65_002])]
        );
        // Equal counts: AS4_PATH is the whole answer.
        let as_path = AsPath::sequence(&[Asn::TRANS, Asn(65_002)]);
        assert_eq!(AsPath::merge_as4(&as_path, &as4_path), as4_path);
        // AS_PATH shorter than AS4_PATH: AS4_PATH ignored.
        let short = AsPath::sequence(&[Asn::TRANS]);
        assert_eq!(AsPath::merge_as4(&short, &as4_path), short);
        // A leading set counts as one AS and is taken whole.
        let as_path = AsPath {
            segments: vec![set(&[65_010, 65_011]), seq(&[Asn::TRANS.0, 65_002])],
        };
        assert_eq!(
            AsPath::merge_as4(&as_path, &as4_path).segments,
            vec![set(&[65_010, 65_011]), seq(&[4_200_000_000, 65_002])]
        );
        // Leading confederation segment is kept; it counts nothing.
        let as_path = AsPath {
            segments: vec![
                AsPathSegment {
                    kind: SegmentType::ConfedSequence,
                    asns: vec![Asn(65_100)],
                },
                seq(&[65_010, Asn::TRANS.0, 65_002]),
            ],
        };
        assert_eq!(
            AsPath::merge_as4(&as_path, &as4_path).segments,
            vec![
                AsPathSegment {
                    kind: SegmentType::ConfedSequence,
                    asns: vec![Asn(65_100)],
                },
                seq(&[65_010]),
                seq(&[4_200_000_000, 65_002]),
            ]
        );
    }
}
