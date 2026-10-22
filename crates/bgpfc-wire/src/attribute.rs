//! Path attributes: the `<flags, type, length, value>` layer and the typed
//! value of every attribute this implementation knows.
//!
//! Implements: RFC 4271 §4.3 (attribute encoding, ORIGIN, `AS_PATH`,
//! `NEXT_HOP`, `MULTI_EXIT_DISC`, `LOCAL_PREF`, `ATOMIC_AGGREGATE`,
//! AGGREGATOR), §5 (categories and flag rules); RFC 7606 §4 (attribute
//! length errors); RFC 6793 §3 (four-octet AGGREGATOR); RFC 1997, RFC 4360,
//! RFC 8092 (community attributes); RFC 4760 §3, §4 (`MP_REACH_NLRI`,
//! `MP_UNREACH_NLRI`).
//!
//! Deciding what a malformed attribute means for the UPDATE as a whole
//! (RFC 7606) is done in [`crate::update`]; this module only parses.

use std::fmt;
use std::net::Ipv4Addr;

use crate::as_path::AsPath;
use crate::community::{
    Community, ExtendedCommunity, LargeCommunity, encode_communities, encode_extended_communities,
    encode_large_communities,
};
use crate::error::EncodeError;
use crate::mp::{MpReach, MpUnreach};
use crate::reader::{Reader, WriteBytes as _};
use crate::types::Asn;

/// Attribute Flags bits (RFC 4271 §4.3).
pub mod flags {
    /// Optional (1) or well-known (0).
    pub const OPTIONAL: u8 = 0x80;
    /// Transitive (1) or non-transitive (0); always 1 for well-known.
    pub const TRANSITIVE: u8 = 0x40;
    /// Partial: an optional transitive attribute passed on by a speaker
    /// that did not recognise it.
    pub const PARTIAL: u8 = 0x20;
    /// Attribute Length is two octets rather than one.
    pub const EXTENDED_LENGTH: u8 = 0x10;
}

/// Attribute Type Codes from the IANA "BGP Path Attributes" registry.
pub mod code {
    /// ORIGIN (RFC 4271).
    pub const ORIGIN: u8 = 1;
    /// `AS_PATH` (RFC 4271).
    pub const AS_PATH: u8 = 2;
    /// `NEXT_HOP` (RFC 4271).
    pub const NEXT_HOP: u8 = 3;
    /// `MULTI_EXIT_DISC` (RFC 4271).
    pub const MULTI_EXIT_DISC: u8 = 4;
    /// `LOCAL_PREF` (RFC 4271).
    pub const LOCAL_PREF: u8 = 5;
    /// `ATOMIC_AGGREGATE` (RFC 4271).
    pub const ATOMIC_AGGREGATE: u8 = 6;
    /// AGGREGATOR (RFC 4271).
    pub const AGGREGATOR: u8 = 7;
    /// COMMUNITIES (RFC 1997).
    pub const COMMUNITIES: u8 = 8;
    /// `MP_REACH_NLRI` (RFC 4760).
    pub const MP_REACH_NLRI: u8 = 14;
    /// `MP_UNREACH_NLRI` (RFC 4760).
    pub const MP_UNREACH_NLRI: u8 = 15;
    /// Extended Communities (RFC 4360).
    pub const EXTENDED_COMMUNITIES: u8 = 16;
    /// `AS4_PATH` (RFC 6793).
    pub const AS4_PATH: u8 = 17;
    /// `AS4_AGGREGATOR` (RFC 6793).
    pub const AS4_AGGREGATOR: u8 = 18;
    /// Large Communities (RFC 8092).
    pub const LARGE_COMMUNITIES: u8 = 32;
}

/// ORIGIN values (RFC 4271 §4.3 a).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Origin {
    /// Interior to the originating AS.
    Igp = 0,
    /// Learned via EGP.
    Egp = 1,
    /// Learned by some other means.
    Incomplete = 2,
}

impl Origin {
    /// From the wire value; `None` is an undefined ORIGIN (RFC 4271 §6.3).
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Origin> {
        match v {
            0 => Some(Origin::Igp),
            1 => Some(Origin::Egp),
            2 => Some(Origin::Incomplete),
            _ => None,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Origin::Igp => "igp",
            Origin::Egp => "egp",
            Origin::Incomplete => "incomplete",
        })
    }
}

/// AGGREGATOR value: the AS and router that formed an aggregate
/// (RFC 4271 §4.3 g, §5.1.7). Held with a four-octet ASN (RFC 6793 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Aggregator {
    /// Aggregating AS.
    pub asn: Asn,
    /// Aggregating speaker, conventionally its BGP Identifier.
    pub address: Ipv4Addr,
}

/// A path attribute with its value decoded.
///
/// `AS4_PATH` and `AS4_AGGREGATOR` do not appear here: the UPDATE decoder
/// merges them into `AsPath` and `Aggregator` (RFC 6793 §4.2.3) and the
/// encoder derives them when a two-octet peer needs them (§4.2.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathAttribute {
    /// ORIGIN, well-known mandatory.
    Origin(Origin),
    /// `AS_PATH`, well-known mandatory.
    AsPath(AsPath),
    /// `NEXT_HOP`, well-known mandatory for IPv4 unicast NLRI.
    NextHop(Ipv4Addr),
    /// `MULTI_EXIT_DISC`, optional non-transitive.
    MultiExitDisc(u32),
    /// `LOCAL_PREF`, well-known, required on internal sessions.
    LocalPref(u32),
    /// `ATOMIC_AGGREGATE`, well-known discretionary, no value.
    AtomicAggregate,
    /// AGGREGATOR, optional transitive.
    Aggregator(Aggregator),
    /// COMMUNITIES, optional transitive (RFC 1997).
    Communities(Vec<Community>),
    /// `MP_REACH_NLRI`, optional non-transitive (RFC 4760 §3).
    MpReach(MpReach),
    /// `MP_UNREACH_NLRI`, optional non-transitive (RFC 4760 §4).
    MpUnreach(MpUnreach),
    /// Extended Communities, optional transitive (RFC 4360 §2).
    ExtendedCommunities(Vec<ExtendedCommunity>),
    /// Large Communities, optional transitive (RFC 8092 §3).
    LargeCommunities(Vec<LargeCommunity>),
    /// An optional transitive attribute this implementation does not know,
    /// carried unchanged with its flags so that it can be passed on with
    /// the Partial bit set (RFC 4271 §5).
    Unknown {
        /// Attribute Flags as received, Extended Length bit cleared.
        flags: u8,
        /// Attribute Type Code.
        code: u8,
        /// Attribute value.
        value: Vec<u8>,
    },
}

impl PathAttribute {
    /// Attribute Type Code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            PathAttribute::Origin(_) => code::ORIGIN,
            PathAttribute::AsPath(_) => code::AS_PATH,
            PathAttribute::NextHop(_) => code::NEXT_HOP,
            PathAttribute::MultiExitDisc(_) => code::MULTI_EXIT_DISC,
            PathAttribute::LocalPref(_) => code::LOCAL_PREF,
            PathAttribute::AtomicAggregate => code::ATOMIC_AGGREGATE,
            PathAttribute::Aggregator(_) => code::AGGREGATOR,
            PathAttribute::Communities(_) => code::COMMUNITIES,
            PathAttribute::MpReach(_) => code::MP_REACH_NLRI,
            PathAttribute::MpUnreach(_) => code::MP_UNREACH_NLRI,
            PathAttribute::ExtendedCommunities(_) => code::EXTENDED_COMMUNITIES,
            PathAttribute::LargeCommunities(_) => code::LARGE_COMMUNITIES,
            PathAttribute::Unknown { code, .. } => *code,
        }
    }

    /// Attribute Flags to send (Extended Length bit excluded; the encoder
    /// sets it from the value length). Known attributes get the flags
    /// RFC 4271 §4.3/§5 require for their category; unknown ones keep what
    /// they came with.
    #[must_use]
    pub fn flags(&self) -> u8 {
        match self {
            PathAttribute::Unknown { flags, .. } => {
                flags & (flags::OPTIONAL | flags::TRANSITIVE | flags::PARTIAL)
            }
            // Only the Optional/Transitive expectation is defined for known
            // codes, and every known code has one.
            _ => expected_flags(self.code()).unwrap_or(flags::TRANSITIVE),
        }
    }

    /// Append the whole attribute: flags, type, length, value.
    ///
    /// `four_octet` selects the ASN width in `AS_PATH` and AGGREGATOR
    /// (RFC 6793 §3). With it false, non-mappable ASNs become `AS_TRANS`
    /// and the UPDATE encoder adds `AS4_PATH` / `AS4_AGGREGATOR`.
    ///
    /// # Errors
    /// [`EncodeError`] if a value exceeds 65535 octets or an `AS_PATH`
    /// segment cannot be encoded.
    pub fn encode(&self, four_octet: bool, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let mut value = Vec::new();
        match self {
            PathAttribute::Origin(o) => value.put_u8(*o as u8),
            PathAttribute::AsPath(p) => p.encode(four_octet, &mut value)?,
            PathAttribute::NextHop(a) => value.put_bytes(&a.octets()),
            PathAttribute::MultiExitDisc(v) | PathAttribute::LocalPref(v) => value.put_u32(*v),
            PathAttribute::AtomicAggregate => {}
            PathAttribute::Aggregator(a) => {
                if four_octet {
                    value.put_u32(a.asn.0);
                } else {
                    value.put_u16(a.asn.to_two_octet());
                }
                value.put_bytes(&a.address.octets());
            }
            PathAttribute::Communities(cs) => encode_communities(cs, &mut value),
            PathAttribute::MpReach(m) => m.encode(&mut value),
            PathAttribute::MpUnreach(m) => m.encode(&mut value),
            PathAttribute::ExtendedCommunities(cs) => encode_extended_communities(cs, &mut value),
            PathAttribute::LargeCommunities(cs) => encode_large_communities(cs, &mut value),
            PathAttribute::Unknown { value: v, .. } => value.put_bytes(v),
        }
        encode_attribute(self.flags(), self.code(), &value, out)
    }
}

/// The Optional and Transitive bits a known attribute type must carry
/// (RFC 4271 §4.3, §5; RFC 1997; RFC 4760 §3, §4; RFC 4360 §2; RFC 6793 §3;
/// RFC 8092 §3). `None` for codes this implementation does not know.
#[must_use]
pub const fn expected_flags(code: u8) -> Option<u8> {
    Some(match code {
        code::ORIGIN
        | code::AS_PATH
        | code::NEXT_HOP
        | code::LOCAL_PREF
        | code::ATOMIC_AGGREGATE => flags::TRANSITIVE,
        code::MULTI_EXIT_DISC | code::MP_REACH_NLRI | code::MP_UNREACH_NLRI => flags::OPTIONAL,
        code::AGGREGATOR
        | code::COMMUNITIES
        | code::EXTENDED_COMMUNITIES
        | code::AS4_PATH
        | code::AS4_AGGREGATOR
        | code::LARGE_COMMUNITIES => flags::OPTIONAL | flags::TRANSITIVE,
        _ => return None,
    })
}

/// Append `<flags, type, length, value>`, using the Extended Length form
/// when the value does not fit one octet (RFC 4271 §4.3).
///
/// # Errors
/// [`EncodeError::TooLong`] for a value over 65535 octets.
pub fn encode_attribute(
    flags: u8,
    code: u8,
    value: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let flags = flags & !flags::EXTENDED_LENGTH;
    if let Ok(len) = u8::try_from(value.len()) {
        out.put_u8(flags);
        out.put_u8(code);
        out.put_u8(len);
    } else {
        let len = u16::try_from(value.len()).map_err(|_| EncodeError::TooLong {
            what: "path attribute",
            len: value.len(),
            max: usize::from(u16::MAX),
        })?;
        out.put_u8(flags | flags::EXTENDED_LENGTH);
        out.put_u8(code);
        out.put_u16(len);
    }
    out.put_bytes(value);
    Ok(())
}

/// One attribute as found on the wire, before its value is interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawAttribute<'a> {
    /// Attribute Flags as received.
    pub flags: u8,
    /// Attribute Type Code.
    pub code: u8,
    /// Attribute value.
    pub value: &'a [u8],
    /// The whole attribute, flags through value: what a NOTIFICATION Data
    /// field carries for attribute errors (RFC 4271 §6.3).
    pub raw: &'a [u8],
}

impl RawAttribute<'_> {
    /// The Optional and Transitive bits as received.
    #[must_use]
    pub const fn category_bits(&self) -> u8 {
        self.flags & (flags::OPTIONAL | flags::TRANSITIVE)
    }
}

/// The attribute header or length is inconsistent with the Total Path
/// Attribute Length (RFC 7606 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawAttributeError {
    /// Fewer octets remain than the smallest attribute header.
    Underrun,
    /// The attribute's length runs past the end of the attributes.
    Overrun,
}

impl fmt::Display for RawAttributeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RawAttributeError::Underrun => f.write_str("truncated path attribute header"),
            RawAttributeError::Overrun => {
                f.write_str("path attribute length exceeds the attributes field")
            }
        }
    }
}

impl std::error::Error for RawAttributeError {}

/// Parse the next attribute's header and delimit its value.
///
/// # Errors
/// [`RawAttributeError`] per RFC 7606 §4.
pub fn parse_raw<'a>(r: &mut Reader<'a>) -> Result<RawAttribute<'a>, RawAttributeError> {
    let start = r.rest_peek();
    let flags = r.u8().map_err(|_| RawAttributeError::Underrun)?;
    let code = r.u8().map_err(|_| RawAttributeError::Underrun)?;
    let (len, header) = if flags & flags::EXTENDED_LENGTH == 0 {
        (
            usize::from(r.u8().map_err(|_| RawAttributeError::Underrun)?),
            3,
        )
    } else {
        (
            usize::from(r.u16().map_err(|_| RawAttributeError::Underrun)?),
            4,
        )
    };
    let value = r.take(len).map_err(|_| RawAttributeError::Overrun)?;
    Ok(RawAttribute {
        flags,
        code,
        value,
        raw: &start[..header + len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_table() {
        for v in 0..=2u8 {
            assert_eq!(Origin::from_u8(v).unwrap() as u8, v);
        }
        assert_eq!(Origin::from_u8(3), None);
        assert_eq!(Origin::Incomplete.to_string(), "incomplete");
    }

    #[test]
    fn well_known_attributes_encode_with_their_flags() {
        let cases: Vec<(PathAttribute, Vec<u8>)> = vec![
            (PathAttribute::Origin(Origin::Igp), vec![0x40, 1, 1, 0]),
            (
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
                vec![0x40, 2, 4, 2, 1, 0xfd, 0xe9],
            ),
            (
                PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
                vec![0x40, 3, 4, 192, 0, 2, 1],
            ),
            (
                PathAttribute::MultiExitDisc(50),
                vec![0x80, 4, 4, 0, 0, 0, 50],
            ),
            (
                PathAttribute::LocalPref(100),
                vec![0x40, 5, 4, 0, 0, 0, 100],
            ),
            (PathAttribute::AtomicAggregate, vec![0x40, 6, 0]),
            (
                PathAttribute::Aggregator(Aggregator {
                    asn: Asn(65_001),
                    address: Ipv4Addr::new(192, 0, 2, 1),
                }),
                vec![0xc0, 7, 6, 0xfd, 0xe9, 192, 0, 2, 1],
            ),
            (
                PathAttribute::Communities(vec![Community::NO_EXPORT]),
                vec![0xc0, 8, 4, 0xff, 0xff, 0xff, 1],
            ),
            (
                PathAttribute::LargeCommunities(vec![LargeCommunity {
                    global: 1,
                    local1: 2,
                    local2: 3,
                }]),
                vec![0xc0, 32, 12, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3],
            ),
            (
                PathAttribute::Unknown {
                    flags: 0xe0,
                    code: 99,
                    value: vec![7],
                },
                vec![0xe0, 99, 1, 7],
            ),
        ];
        for (attr, wire) in cases {
            let mut out = Vec::new();
            attr.encode(false, &mut out).unwrap();
            assert_eq!(out, wire, "{attr:?}");
            let raw = parse_raw(&mut Reader::new(&wire)).unwrap();
            assert_eq!(raw.code, attr.code());
            assert_eq!(raw.raw, &wire[..]);
            assert_eq!(raw.category_bits(), attr.flags() & 0xc0);
        }
    }

    #[test]
    fn four_octet_as_in_as_path_and_aggregator() {
        let agg = PathAttribute::Aggregator(Aggregator {
            asn: Asn(4_200_000_000),
            address: Ipv4Addr::new(192, 0, 2, 1),
        });
        let mut two = Vec::new();
        agg.encode(false, &mut two).unwrap();
        // RFC 6793 §4.2.2: AS_TRANS in the two-octet form.
        assert_eq!(two, [0xc0, 7, 6, 0x5b, 0xa0, 192, 0, 2, 1]);
        let mut four = Vec::new();
        agg.encode(true, &mut four).unwrap();
        assert_eq!(four, [0xc0, 7, 8, 0xfa, 0x56, 0xea, 0x00, 192, 0, 2, 1]);
    }

    #[test]
    fn extended_length_is_used_above_255_octets() {
        let value = vec![0xab; 300];
        let mut out = Vec::new();
        encode_attribute(0xc0, 99, &value, &mut out).unwrap();
        assert_eq!(&out[..4], &[0xd0, 99, 1, 44]);
        assert_eq!(out.len(), 304);
        let raw = parse_raw(&mut Reader::new(&out)).unwrap();
        assert_eq!(raw.value, &value[..]);
        assert_eq!(raw.raw.len(), 304);
        // The caller's Extended Length bit is recomputed, not trusted.
        let mut out = Vec::new();
        encode_attribute(0xd0, 99, &[1], &mut out).unwrap();
        assert_eq!(out, [0xc0, 99, 1, 1]);
        let huge = vec![0; 65_536];
        assert!(matches!(
            encode_attribute(0xc0, 99, &huge, &mut Vec::new()),
            Err(EncodeError::TooLong {
                what: "path attribute",
                ..
            })
        ));
    }

    #[test]
    fn raw_parsing_errors_per_rfc7606() {
        // RFC 7606 §4: fewer than three (four with Extended Length) octets.
        assert_eq!(
            parse_raw(&mut Reader::new(&[0x40, 1])),
            Err(RawAttributeError::Underrun)
        );
        assert_eq!(
            parse_raw(&mut Reader::new(&[0x50, 1, 0])),
            Err(RawAttributeError::Underrun)
        );
        // Length past the end.
        assert_eq!(
            parse_raw(&mut Reader::new(&[0x40, 1, 2, 0])),
            Err(RawAttributeError::Overrun)
        );
        assert_eq!(
            parse_raw(&mut Reader::new(&[0x50, 1, 1, 0, 0])),
            Err(RawAttributeError::Overrun)
        );
        // Extended length with a value that would have fit one octet is fine.
        let raw = parse_raw(&mut Reader::new(&[0x50, 1, 0, 1, 2])).unwrap();
        assert_eq!(raw.value, &[2]);
    }

    #[test]
    fn expected_flags_table() {
        assert_eq!(expected_flags(code::ORIGIN), Some(0x40));
        assert_eq!(expected_flags(code::MULTI_EXIT_DISC), Some(0x80));
        assert_eq!(expected_flags(code::MP_REACH_NLRI), Some(0x80));
        assert_eq!(expected_flags(code::AGGREGATOR), Some(0xc0));
        assert_eq!(expected_flags(code::AS4_PATH), Some(0xc0));
        assert_eq!(expected_flags(code::LARGE_COMMUNITIES), Some(0xc0));
        assert_eq!(expected_flags(99), None);
    }
}
