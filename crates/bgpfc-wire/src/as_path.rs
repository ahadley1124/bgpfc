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

/// One `<type, length, ASes>` segment, owned: what a path is built from.
/// A segment on the wire holds 1..=255 ASes; an empty one is malformed
/// (RFC 7606 §7.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AsPathSegment {
    /// Segment type.
    pub kind: SegmentType,
    /// AS numbers in wire order (leftmost first).
    pub asns: Vec<Asn>,
}

/// Largest number of ASes one segment can hold (one-octet count).
pub const MAX_SEGMENT_LEN: usize = 255;

/// A header word holds the segment type above this many bits and the AS
/// count below them.
const KIND_SHIFT: u32 = 24;

/// An `AS_PATH`: a list of segments, leftmost segment first.
///
/// A full table holds one per attribute set, so it is one allocation of
/// exactly its size: for each segment a header word (type and AS count),
/// then its ASes. [`AsPath::segments`] reads it back.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct AsPath {
    // invariant: a sequence of header words, each followed by as many
    // ASNs as its count, with a valid `SegmentType` in its top octet.
    words: Box<[u32]>,
}

/// A segment of an [`AsPath`], borrowed from it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    /// Segment type.
    pub kind: SegmentType,
    asns: &'a [u32],
}

impl<'a> Segment<'a> {
    /// Number of ASes in the segment.
    #[must_use]
    pub fn len(&self) -> usize {
        self.asns.len()
    }

    /// Whether the segment holds no AS (only a path built by hand can
    /// have one; it does not encode).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.asns.is_empty()
    }

    /// The segment's ASes, leftmost first.
    pub fn asns(self) -> impl DoubleEndedIterator<Item = Asn> + ExactSizeIterator + 'a {
        self.asns.iter().map(|&a| Asn(a))
    }

    /// An owned copy.
    #[must_use]
    pub fn into_owned(self) -> AsPathSegment {
        AsPathSegment {
            kind: self.kind,
            asns: self.asns().collect(),
        }
    }
}

impl fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(match self.kind {
            SegmentType::Set => "Set",
            SegmentType::Sequence => "Sequence",
            SegmentType::ConfedSequence => "ConfedSequence",
            SegmentType::ConfedSet => "ConfedSet",
        })
        .field(&self.asns)
        .finish()
    }
}

/// The segments of an [`AsPath`], leftmost first.
#[derive(Clone, Debug)]
pub struct Segments<'a> {
    rest: &'a [u32],
}

impl<'a> Iterator for Segments<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Segment<'a>> {
        let (&head, rest) = self.rest.split_first()?;
        // invariant: AsPath wrote a valid type and as many ASNs as the count.
        let kind = u8::try_from(head >> KIND_SHIFT)
            .ok()
            .and_then(SegmentType::from_u8)
            .expect("invariant: a header word holds a segment type");
        let (asns, rest) = rest.split_at((head & ((1 << KIND_SHIFT) - 1)) as usize);
        self.rest = rest;
        Some(Segment { kind, asns })
    }
}

/// Appends segments to the words of a path being built.
struct Builder(Vec<u32>);

impl Builder {
    fn with_capacity(words: usize) -> Builder {
        Builder(Vec::with_capacity(words))
    }

    /// Start a segment of `len` ASes; the caller pushes them next.
    fn header(&mut self, kind: SegmentType, len: usize) {
        // invariant: no path holds 2^24 ASes in one segment; the wire
        // allows 255 and prepending opens a new segment past that.
        let len = u32::try_from(len)
            .ok()
            .filter(|&n| n < 1 << KIND_SHIFT)
            .expect("invariant: a segment holds fewer than 2^24 ASes");
        self.0.push(u32::from(kind as u8) << KIND_SHIFT | len);
    }

    fn segment(&mut self, seg: Segment<'_>) {
        self.header(seg.kind, seg.len());
        self.0.extend_from_slice(seg.asns);
    }

    fn build(self) -> AsPath {
        AsPath {
            words: self.0.into_boxed_slice(),
        }
    }
}

impl AsPath {
    /// The empty path an originator sends to internal peers
    /// (RFC 4271 §5.1.2).
    #[must_use]
    pub fn empty() -> AsPath {
        AsPath::default()
    }

    /// A single `AS_SEQUENCE` segment. Empty input gives the empty path.
    #[must_use]
    pub fn sequence(asns: &[Asn]) -> AsPath {
        if asns.is_empty() {
            return AsPath::empty();
        }
        let mut b = Builder::with_capacity(1 + asns.len());
        b.header(SegmentType::Sequence, asns.len());
        b.0.extend(asns.iter().map(|a| a.0));
        b.build()
    }

    /// A path of these segments, in order.
    #[must_use]
    pub fn from_segments(segments: &[AsPathSegment]) -> AsPath {
        let words = segments.iter().map(|s| 1 + s.asns.len()).sum();
        let mut b = Builder::with_capacity(words);
        for s in segments {
            b.header(s.kind, s.asns.len());
            b.0.extend(s.asns.iter().map(|a| a.0));
        }
        b.build()
    }

    /// The segments, leftmost first.
    #[must_use]
    pub fn segments(&self) -> Segments<'_> {
        Segments { rest: &self.words }
    }

    /// Octets the path holds on the heap, for memory accounting.
    #[must_use]
    pub fn heap_size(&self) -> usize {
        size_of_val::<[u32]>(&self.words)
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
        // Exact for one segment, the usual case: its two-octet header
        // and each AS take a word.
        let mut b = Builder::with_capacity(if four_octet {
            (bytes.len() + 2) / 4
        } else {
            bytes.len() / 2
        });
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
            b.header(kind, usize::from(count));
            for _ in 0..count {
                let asn = if four_octet {
                    r.u32().map_err(|_| AsPathError::Overrun)?
                } else {
                    u32::from(r.u16().map_err(|_| AsPathError::Overrun)?)
                };
                b.0.push(asn);
            }
        }
        Ok(b.build())
    }

    /// Append the wire form. With `four_octet` false, non-mappable ASNs are
    /// written as `AS_TRANS` (RFC 6793 §4.2.2); the caller adds an
    /// `AS4_PATH` when [`AsPath::has_non_mappable`] says so.
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] for a segment with more than 255 ASes, and
    /// [`EncodeError::EmptySegment`] for one with none.
    pub fn encode(&self, four_octet: bool, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        for seg in self.segments() {
            let count = u8::try_from(seg.len()).map_err(|_| EncodeError::TooLong {
                what: "AS_PATH segment",
                len: seg.len(),
                max: MAX_SEGMENT_LEN,
            })?;
            if count == 0 {
                return Err(EncodeError::EmptySegment);
            }
            out.put_u8(seg.kind as u8);
            out.put_u8(count);
            for asn in seg.asns() {
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
        self.segments()
            .map(|s| match s.kind {
                SegmentType::Sequence => s.len(),
                SegmentType::Set => 1,
                SegmentType::ConfedSequence | SegmentType::ConfedSet => 0,
            })
            .sum()
    }

    /// Every ASN in every segment, leftmost first.
    pub fn asns(&self) -> impl Iterator<Item = Asn> + '_ {
        self.segments().flat_map(Segment::asns)
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
        self.segments().any(|s| s.kind.is_set())
    }

    /// Whether any segment is a confederation segment (RFC 5065 §3).
    #[must_use]
    pub fn contains_confed(&self) -> bool {
        self.segments().any(|s| s.kind.is_confed())
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

    /// The path with `asn` prepended, as sent to an external peer
    /// (RFC 4271 §5.1.2 b, c): to the leading `AS_SEQUENCE`, or in a new
    /// one when the path is empty, starts with another type, or its first
    /// sequence already holds 255 ASes (§5.1.2 b 1, §4.3).
    #[must_use]
    pub fn prepend(&self, asn: Asn) -> AsPath {
        let mut segments = self.segments();
        let grow = segments
            .clone()
            .next()
            .filter(|s| s.kind == SegmentType::Sequence && s.len() < MAX_SEGMENT_LEN);
        // One word more for an AS added to the first sequence, two for a
        // new segment.
        let mut b = Builder::with_capacity(self.words.len() + if grow.is_some() { 1 } else { 2 });
        if let Some(seg) = grow {
            segments.next();
            b.header(SegmentType::Sequence, seg.len() + 1);
            b.0.push(asn.0);
            b.0.extend_from_slice(seg.asns);
        } else {
            b.header(SegmentType::Sequence, 1);
            b.0.push(asn.0);
        }
        for seg in segments {
            b.segment(seg);
        }
        b.build()
    }

    /// The path with confederation segments removed, as `AS4_PATH` must be
    /// built (RFC 6793 §4.2.2) and as a received `AS4_PATH` is cleaned
    /// (RFC 6793 §6).
    #[must_use]
    pub fn without_confed(&self) -> AsPath {
        let mut b = Builder::with_capacity(self.words.len());
        for seg in self.segments().filter(|s| !s.kind.is_confed()) {
            b.segment(seg);
        }
        b.build()
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
        let mut b = Builder::with_capacity(as_path.words.len() + as4_path.words.len());
        // The loop runs only while segments are being prepended, so every
        // confederation segment it meets is leading or adjacent to one.
        for seg in as_path.segments() {
            if seg.kind.is_confed() {
                b.segment(seg);
                continue;
            }
            if need == 0 {
                break;
            }
            match seg.kind {
                SegmentType::Sequence if seg.len() <= need => {
                    need -= seg.len();
                    b.segment(seg);
                }
                SegmentType::Sequence => {
                    b.segment(Segment {
                        kind: SegmentType::Sequence,
                        asns: &seg.asns[..need],
                    });
                    need = 0;
                }
                _ => {
                    need -= 1;
                    b.segment(seg);
                }
            }
        }
        for seg in as4_path.segments() {
            b.segment(seg);
        }
        b.build()
    }
}

impl fmt::Debug for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.segments()).finish()
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
        for seg in self.segments() {
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
            for (i, asn) in seg.asns().enumerate() {
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

    fn owned(p: &AsPath) -> Vec<AsPathSegment> {
        p.segments().map(Segment::into_owned).collect()
    }

    #[test]
    fn two_and_four_octet_round_trips() {
        let path = AsPath::from_segments(&[seq(&[65_001, 65_002]), set(&[65_003])]);
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
    fn segments_read_back_what_built_the_path() {
        let segments = [
            AsPathSegment {
                kind: SegmentType::ConfedSet,
                asns: vec![Asn(7)],
            },
            seq(&[65_001, 4_200_000_000]),
            set(&[65_003, 65_004]),
        ];
        let path = AsPath::from_segments(&segments);
        assert_eq!(owned(&path), segments);
        assert_eq!(
            format!("{path:?}"),
            "[ConfedSet([7]), Sequence([65001, 4200000000]), Set([65003, 65004])]"
        );
        // One word per segment and per AS, nothing more.
        assert_eq!(path.heap_size(), 8 * 4);
        assert_eq!(AsPath::empty().heap_size(), 0);
        assert_eq!(AsPath::sequence(&[]), AsPath::empty());
        assert_eq!(owned(&AsPath::sequence(&[Asn(1), Asn(2)])), [seq(&[1, 2])]);
    }

    #[test]
    fn decoding_sizes_the_path_exactly() {
        // Two-octet and four-octet, one segment and two.
        for (bytes, four) in [
            (&[2, 2, 0, 1, 0, 2][..], false),
            (&[2, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 2][..], true),
            (&[2, 2, 0, 0, 0, 1, 0, 0, 0, 2][..], true),
        ] {
            let p = AsPath::decode(bytes, four).unwrap();
            assert_eq!(p.heap_size(), (p.segments().count() + p.asns().count()) * 4);
        }
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
        let big = AsPath::from_segments(&[seq(&vec![1; 256])]);
        assert!(matches!(
            big.encode(true, &mut Vec::new()),
            Err(EncodeError::TooLong {
                what: "AS_PATH segment",
                ..
            })
        ));
        let empty = AsPath::from_segments(&[seq(&[])]);
        assert_eq!(
            empty.encode(true, &mut Vec::new()),
            Err(EncodeError::EmptySegment)
        );
    }

    #[test]
    fn counting_and_predicates() {
        let path = AsPath::from_segments(&[
            AsPathSegment {
                kind: SegmentType::ConfedSequence,
                asns: vec![Asn(65_100), Asn(65_101)],
            },
            seq(&[65_001, 65_002, 65_003]),
            set(&[65_004, 65_005]),
        ]);
        // RFC 4271 §9.1.2.2 + RFC 5065 §5.3: 3 + 1 + 0.
        assert_eq!(path.hop_count(), 4);
        assert!(path.contains_set());
        assert!(path.contains_confed());
        assert!(!path.contains_as0());
        assert!(path.contains(Asn(65_005)));
        assert_eq!(path.first_asn(), Some(Asn(65_100)));
        assert_eq!(
            owned(&path.without_confed()),
            [seq(&[65_001, 65_002, 65_003]), set(&[65_004, 65_005])]
        );
        assert!(AsPath::sequence(&[Asn(1), Asn(0)]).contains_as0());
        assert_eq!(AsPath::empty().first_asn(), None);
        assert_eq!(
            path.to_string(),
            "( 65100 65101 ) 65001 65002 65003 { 65004 65005 }"
        );
    }

    #[test]
    fn prepend_respects_segment_limit_and_sets() {
        // RFC 4271 §5.1.2 b, c.
        let p1 = AsPath::empty().prepend(Asn(1));
        assert_eq!(owned(&p1), [seq(&[1])]);
        let p2 = p1.prepend(Asn(2));
        assert_eq!(owned(&p2), [seq(&[2, 1])]);
        // RFC 4271 §4.3: a sequence holds at most 255 ASes.
        let full = AsPath::sequence(&[Asn(9); 255]);
        let p3 = full.prepend(Asn(1));
        assert_eq!(owned(&p3), [seq(&[1]), seq(&[9; 255])]);
        let p4 = AsPath::from_segments(&[set(&[5]), seq(&[6])]).prepend(Asn(1));
        assert_eq!(owned(&p4), [seq(&[1]), set(&[5]), seq(&[6])]);
        let confed = AsPath::from_segments(&[AsPathSegment {
            kind: SegmentType::ConfedSequence,
            asns: vec![Asn(7)],
        }]);
        assert_eq!(owned(&confed.prepend(Asn(1)))[0], seq(&[1]));
        // Sized exactly: exported sets are kept as long as their routes.
        assert_eq!(p2.heap_size(), 3 * 4);
        assert_eq!(p3.heap_size(), (2 + 256) * 4);
    }

    #[test]
    fn as4_merge_per_rfc6793() {
        // The route crossed two OLD speakers (65010, 65011) after leaving the
        // last NEW speaker; AS_PATH has them plus AS_TRANS for the 4-octet AS.
        let as_path = AsPath::sequence(&[Asn(65_010), Asn(65_011), Asn::TRANS, Asn(65_002)]);
        let as4_path = AsPath::sequence(&[Asn(4_200_000_000), Asn(65_002)]);
        let merged = AsPath::merge_as4(&as_path, &as4_path);
        assert_eq!(
            owned(&merged),
            [seq(&[65_010, 65_011]), seq(&[4_200_000_000, 65_002])]
        );
        // Equal counts: AS4_PATH is the whole answer.
        let as_path = AsPath::sequence(&[Asn::TRANS, Asn(65_002)]);
        assert_eq!(AsPath::merge_as4(&as_path, &as4_path), as4_path);
        // AS_PATH shorter than AS4_PATH: AS4_PATH ignored.
        let short = AsPath::sequence(&[Asn::TRANS]);
        assert_eq!(AsPath::merge_as4(&short, &as4_path), short);
        // A leading set counts as one AS and is taken whole.
        let as_path =
            AsPath::from_segments(&[set(&[65_010, 65_011]), seq(&[Asn::TRANS.0, 65_002])]);
        assert_eq!(
            owned(&AsPath::merge_as4(&as_path, &as4_path)),
            [set(&[65_010, 65_011]), seq(&[4_200_000_000, 65_002])]
        );
        // Leading confederation segment is kept; it counts nothing.
        let as_path = AsPath::from_segments(&[
            AsPathSegment {
                kind: SegmentType::ConfedSequence,
                asns: vec![Asn(65_100)],
            },
            seq(&[65_010, Asn::TRANS.0, 65_002]),
        ]);
        assert_eq!(
            owned(&AsPath::merge_as4(&as_path, &as4_path)),
            [
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
