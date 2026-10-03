//! Community attributes: standard, extended and large.
//!
//! Implements: RFC 1997 (COMMUNITIES, type 8, well-known values);
//! RFC 4360 §2, §3 (Extended Communities, type 16); RFC 8092 §3, §5, §6
//! (Large Communities, type 32); RFC 7606 §7.8, §7.14 (length rules).

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::reader::{Reader, WriteBytes as _};

/// A standard four-octet community (RFC 1997).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Community(pub u32);

impl Community {
    /// `NO_EXPORT`: not advertised outside the confederation (RFC 1997).
    pub const NO_EXPORT: Community = Community(0xffff_ff01);
    /// `NO_ADVERTISE`: not advertised to any peer (RFC 1997).
    pub const NO_ADVERTISE: Community = Community(0xffff_ff02);
    /// `NO_EXPORT_SUBCONFED`: not advertised to external peers (RFC 1997).
    pub const NO_EXPORT_SUBCONFED: Community = Community(0xffff_ff03);

    /// Build from the conventional `asn:value` halves.
    #[must_use]
    pub const fn new(asn: u16, value: u16) -> Community {
        Community(((asn as u32) << 16) | value as u32)
    }

    /// The high half, conventionally an AS number (RFC 1997).
    #[must_use]
    pub const fn asn(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// The low half.
    #[must_use]
    pub const fn value(self) -> u16 {
        (self.0 & 0xffff) as u16
    }
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Community::NO_EXPORT => f.write_str("no-export"),
            Community::NO_ADVERTISE => f.write_str("no-advertise"),
            Community::NO_EXPORT_SUBCONFED => f.write_str("no-export-subconfed"),
            c => write!(f, "{}:{}", c.asn(), c.value()),
        }
    }
}

impl fmt::Debug for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Community {
    type Err = ParseCommunityError;

    /// Parse `asn:value` or one of the well-known names.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "no-export" => return Ok(Community::NO_EXPORT),
            "no-advertise" => return Ok(Community::NO_ADVERTISE),
            "no-export-subconfed" => return Ok(Community::NO_EXPORT_SUBCONFED),
            _ => {}
        }
        let (a, v) = s.split_once(':').ok_or(ParseCommunityError)?;
        let a: u16 = a.parse().map_err(|_| ParseCommunityError)?;
        let v: u16 = v.parse().map_err(|_| ParseCommunityError)?;
        Ok(Community::new(a, v))
    }
}

/// An eight-octet extended community (RFC 4360 §2), kept as raw octets
/// because the type space is open-ended. Two are equal only when all eight
/// octets are equal (RFC 4360 §2).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtendedCommunity(pub [u8; 8]);

impl ExtendedCommunity {
    /// High-order octet of the Type field.
    #[must_use]
    pub const fn type_high(self) -> u8 {
        self.0[0]
    }

    /// Low-order octet of the Type field (the sub-type for extended types).
    #[must_use]
    pub const fn type_low(self) -> u8 {
        self.0[1]
    }

    /// Whether the community is transitive across ASes: the T bit is zero
    /// (RFC 4360 §2).
    #[must_use]
    pub const fn is_transitive(self) -> bool {
        self.0[0] & 0x40 == 0
    }

    /// Two-octet AS specific (RFC 4360 §3.1): `0x00` or `0x40` type high.
    #[must_use]
    pub const fn two_octet_as(sub_type: u8, transitive: bool, asn: u16, local: u32) -> Self {
        let high = if transitive { 0x00 } else { 0x40 };
        let a = asn.to_be_bytes();
        let l = local.to_be_bytes();
        ExtendedCommunity([high, sub_type, a[0], a[1], l[0], l[1], l[2], l[3]])
    }

    /// IPv4 address specific (RFC 4360 §3.2): `0x01` or `0x41` type high.
    #[must_use]
    pub const fn ipv4(sub_type: u8, transitive: bool, addr: Ipv4Addr, local: u16) -> Self {
        let high = if transitive { 0x01 } else { 0x41 };
        let a = addr.octets();
        let l = local.to_be_bytes();
        ExtendedCommunity([high, sub_type, a[0], a[1], a[2], a[3], l[0], l[1]])
    }
}

impl fmt::Display for ExtendedCommunity {
    /// Typed forms for the RFC 4360 templates (`as2:sub:asn:local`,
    /// `ipv4:sub:addr:local`), `as4:sub:asn:local` for RFC 5668, and hex
    /// otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        let sub = b[1];
        match b[0] & 0x3f {
            0x00 => write!(
                f,
                "as2:{sub}:{}:{}",
                u16::from_be_bytes([b[2], b[3]]),
                u32::from_be_bytes([b[4], b[5], b[6], b[7]])
            ),
            0x01 => write!(
                f,
                "ipv4:{sub}:{}:{}",
                Ipv4Addr::new(b[2], b[3], b[4], b[5]),
                u16::from_be_bytes([b[6], b[7]])
            ),
            0x02 => write!(
                f,
                "as4:{sub}:{}:{}",
                u32::from_be_bytes([b[2], b[3], b[4], b[5]]),
                u16::from_be_bytes([b[6], b[7]])
            ),
            _ => {
                f.write_str("0x")?;
                for o in b {
                    write!(f, "{o:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for ExtendedCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A twelve-octet large community (RFC 8092 §3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LargeCommunity {
    /// Global Administrator, conventionally an ASN.
    pub global: u32,
    /// Local Data Part 1.
    pub local1: u32,
    /// Local Data Part 2.
    pub local2: u32,
}

impl fmt::Display for LargeCommunity {
    /// The canonical `global:local1:local2` form (RFC 8092 §5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.global, self.local1, self.local2)
    }
}

impl fmt::Debug for LargeCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for LargeCommunity {
    type Err = ParseCommunityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s
            .split(':')
            .map(|p| p.parse::<u32>().map_err(|_| ParseCommunityError));
        let global = parts.next().ok_or(ParseCommunityError)??;
        let local1 = parts.next().ok_or(ParseCommunityError)??;
        let local2 = parts.next().ok_or(ParseCommunityError)??;
        if parts.next().is_some() {
            return Err(ParseCommunityError);
        }
        Ok(LargeCommunity {
            global,
            local1,
            local2,
        })
    }
}

/// A textual community did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseCommunityError;

impl fmt::Display for ParseCommunityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed community")
    }
}

impl std::error::Error for ParseCommunityError {}

/// An attribute value whose length is not a non-zero multiple of the
/// community size (RFC 7606 §7.8, §7.14; RFC 8092 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadCommunityLength {
    /// Attribute length found.
    pub len: usize,
    /// Size of one community of this kind.
    pub unit: usize,
}

impl fmt::Display for BadCommunityLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "community attribute length {} is not a non-zero multiple of {}",
            self.len, self.unit
        )
    }
}

impl std::error::Error for BadCommunityLength {}

fn check_len(bytes: &[u8], unit: usize) -> Result<(), BadCommunityLength> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(unit) {
        return Err(BadCommunityLength {
            len: bytes.len(),
            unit,
        });
    }
    Ok(())
}

/// Decode a COMMUNITIES value (RFC 1997; RFC 7606 §7.8: non-zero multiple
/// of 4).
///
/// # Errors
/// [`BadCommunityLength`] for any other length.
pub fn decode_communities(bytes: &[u8]) -> Result<Vec<Community>, BadCommunityLength> {
    check_len(bytes, 4)?;
    let mut r = Reader::new(bytes);
    let mut out = Vec::with_capacity(bytes.len() / 4);
    while let Ok(v) = r.u32() {
        out.push(Community(v));
    }
    Ok(out)
}

/// Decode an Extended Communities value (RFC 4360 §2; RFC 7606 §7.14:
/// non-zero multiple of 8). Unknown types are never an error (RFC 7606
/// §7.14).
///
/// # Errors
/// [`BadCommunityLength`] for any other length.
pub fn decode_extended_communities(
    bytes: &[u8],
) -> Result<Vec<ExtendedCommunity>, BadCommunityLength> {
    check_len(bytes, 8)?;
    let mut r = Reader::new(bytes);
    let mut out = Vec::with_capacity(bytes.len() / 8);
    while let Ok(v) = r.array::<8>() {
        out.push(ExtendedCommunity(v));
    }
    Ok(out)
}

/// Decode a Large Communities value (RFC 8092 §3; §6: non-zero multiple of
/// 12). Duplicates are silently removed, keeping first occurrences
/// (RFC 8092 §3), and are not an error (§6).
///
/// # Errors
/// [`BadCommunityLength`] for any other length.
pub fn decode_large_communities(bytes: &[u8]) -> Result<Vec<LargeCommunity>, BadCommunityLength> {
    check_len(bytes, 12)?;
    let mut r = Reader::new(bytes);
    let mut out: Vec<LargeCommunity> = Vec::with_capacity(bytes.len() / 12);
    while let (Ok(global), Ok(local1), Ok(local2)) = (r.u32(), r.u32(), r.u32()) {
        let lc = LargeCommunity {
            global,
            local1,
            local2,
        };
        if !out.contains(&lc) {
            out.push(lc);
        }
    }
    Ok(out)
}

/// Append COMMUNITIES octets.
pub fn encode_communities(cs: &[Community], out: &mut Vec<u8>) {
    for c in cs {
        out.put_u32(c.0);
    }
}

/// Append Extended Communities octets.
pub fn encode_extended_communities(cs: &[ExtendedCommunity], out: &mut Vec<u8>) {
    for c in cs {
        out.put_bytes(&c.0);
    }
}

/// Append Large Communities octets.
pub fn encode_large_communities(cs: &[LargeCommunity], out: &mut Vec<u8>) {
    for c in cs {
        out.put_u32(c.global);
        out.put_u32(c.local1);
        out.put_u32(c.local2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_communities() {
        let c = Community::new(65_000, 100);
        assert_eq!(c.0, 0xfde8_0064);
        assert_eq!(c.to_string(), "65000:100");
        assert_eq!("65000:100".parse::<Community>().unwrap(), c);
        assert_eq!(Community::NO_EXPORT.to_string(), "no-export");
        assert_eq!(
            "no-advertise".parse::<Community>().unwrap(),
            Community::NO_ADVERTISE
        );
        assert_eq!(Community::NO_EXPORT_SUBCONFED.0, 0xffff_ff03);
        assert!("65536:1".parse::<Community>().is_err());
        assert!("1".parse::<Community>().is_err());
        let wire = [0xfd, 0xe8, 0, 100, 0xff, 0xff, 0xff, 0x01];
        let cs = decode_communities(&wire).unwrap();
        assert_eq!(cs, vec![c, Community::NO_EXPORT]);
        let mut out = Vec::new();
        encode_communities(&cs, &mut out);
        assert_eq!(out, wire);
        // RFC 7606 §7.8.
        assert_eq!(
            decode_communities(&[]),
            Err(BadCommunityLength { len: 0, unit: 4 })
        );
        assert_eq!(
            decode_communities(&[1, 2, 3]),
            Err(BadCommunityLength { len: 3, unit: 4 })
        );
    }

    #[test]
    fn extended_communities() {
        // Route Target 65000:100 (RFC 4360 §4: type 0x00, sub-type 0x02).
        let rt = ExtendedCommunity::two_octet_as(0x02, true, 65_000, 100);
        assert_eq!(rt.0, [0, 2, 0xfd, 0xe8, 0, 0, 0, 100]);
        assert_eq!(rt.to_string(), "as2:2:65000:100");
        assert!(rt.is_transitive());
        assert_eq!((rt.type_high(), rt.type_low()), (0, 2));
        let nt = ExtendedCommunity::two_octet_as(0x02, false, 65_000, 100);
        assert!(!nt.is_transitive());
        let ip = ExtendedCommunity::ipv4(0x02, true, Ipv4Addr::new(192, 0, 2, 1), 7);
        assert_eq!(ip.to_string(), "ipv4:2:192.0.2.1:7");
        let as4 = ExtendedCommunity([0x02, 0x02, 0xfa, 0x56, 0xea, 0x00, 0, 9]);
        assert_eq!(as4.to_string(), "as4:2:4200000000:9");
        let opaque = ExtendedCommunity([0x03, 0x0c, 1, 2, 3, 4, 5, 6]);
        assert_eq!(opaque.to_string(), "0x030c010203040506");
        let mut wire = Vec::new();
        encode_extended_communities(&[rt, opaque], &mut wire);
        assert_eq!(
            decode_extended_communities(&wire).unwrap(),
            vec![rt, opaque]
        );
        // RFC 7606 §7.14.
        assert_eq!(
            decode_extended_communities(&wire[..12]),
            Err(BadCommunityLength { len: 12, unit: 8 })
        );
        assert!(decode_extended_communities(&[]).is_err());
    }

    #[test]
    fn large_communities() {
        let a: LargeCommunity = "65000:1:2".parse().unwrap();
        assert_eq!(
            a,
            LargeCommunity {
                global: 65_000,
                local1: 1,
                local2: 2
            }
        );
        assert_eq!(a.to_string(), "65000:1:2");
        assert!("1:2".parse::<LargeCommunity>().is_err());
        assert!("1:2:3:4".parse::<LargeCommunity>().is_err());
        let b: LargeCommunity = "4200000000:0:4294967295".parse().unwrap();
        let mut wire = Vec::new();
        encode_large_communities(&[a, b, a], &mut wire);
        assert_eq!(wire.len(), 36);
        // RFC 8092 §3: duplicates removed on receipt, not an error (§6).
        assert_eq!(decode_large_communities(&wire).unwrap(), vec![a, b]);
        // RFC 8092 §6.
        assert_eq!(
            decode_large_communities(&wire[..13]),
            Err(BadCommunityLength { len: 13, unit: 12 })
        );
        assert!(decode_large_communities(&[]).is_err());
    }
}
