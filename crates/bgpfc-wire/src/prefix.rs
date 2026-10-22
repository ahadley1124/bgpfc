//! IP prefixes and their `<length, prefix>` NLRI encoding.
//!
//! Implements: RFC 4271 §4.3 (Withdrawn Routes and NLRI encoding),
//! RFC 4760 §5 (the same encoding for other address families), RFC 7606
//! §5.3 (syntactic correctness of NLRI fields).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::reader::{Reader, WriteBytes as _};
use crate::types::Afi;

/// An IP prefix in canonical form: host bits are zero.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prefix {
    /// An IPv4 prefix.
    V4 {
        /// Network address with host bits zero.
        addr: Ipv4Addr,
        /// Prefix length, 0..=32.
        len: u8,
    },
    /// An IPv6 prefix.
    V6 {
        /// Network address with host bits zero.
        addr: Ipv6Addr,
        /// Prefix length, 0..=128.
        len: u8,
    },
}

impl Prefix {
    /// Build a prefix, zeroing host bits. `None` if `len` exceeds the
    /// address size.
    #[must_use]
    pub fn new(addr: IpAddr, len: u8) -> Option<Prefix> {
        match addr {
            IpAddr::V4(a) => (len <= 32).then(|| Prefix::V4 {
                addr: Ipv4Addr::from(mask32(u32::from(a), len)),
                len,
            }),
            IpAddr::V6(a) => (len <= 128).then(|| Prefix::V6 {
                addr: Ipv6Addr::from(mask128(u128::from(a), len)),
                len,
            }),
        }
    }

    /// The address family this prefix belongs to.
    #[must_use]
    pub const fn afi(&self) -> Afi {
        match self {
            Prefix::V4 { .. } => Afi::Ipv4,
            Prefix::V6 { .. } => Afi::Ipv6,
        }
    }

    /// Prefix length in bits.
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        match self {
            Prefix::V4 { len, .. } | Prefix::V6 { len, .. } => *len,
        }
    }

    /// Network address.
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        match self {
            Prefix::V4 { addr, .. } => IpAddr::V4(*addr),
            Prefix::V6 { addr, .. } => IpAddr::V6(*addr),
        }
    }

    /// The default route of this prefix's family.
    #[must_use]
    pub const fn default_route(afi: Afi) -> Option<Prefix> {
        match afi {
            Afi::Ipv4 => Some(Prefix::V4 {
                addr: Ipv4Addr::UNSPECIFIED,
                len: 0,
            }),
            Afi::Ipv6 => Some(Prefix::V6 {
                addr: Ipv6Addr::UNSPECIFIED,
                len: 0,
            }),
            Afi::Unknown(_) => None,
        }
    }

    /// Append the `<length, prefix>` tuple: one length octet, then the
    /// minimum number of octets holding `len` bits (RFC 4271 §4.3).
    pub fn encode(&self, out: &mut Vec<u8>) {
        let len = self.prefix_len();
        out.put_u8(len);
        let octets = prefix_octets(len);
        match self {
            Prefix::V4 { addr, .. } => out.put_bytes(&addr.octets()[..octets]),
            Prefix::V6 { addr, .. } => out.put_bytes(&addr.octets()[..octets]),
        }
    }

    /// Decode one `<length, prefix>` tuple of family `afi`. Trailing bits
    /// beyond the prefix length are zeroed (RFC 4271 §4.3: their value is
    /// irrelevant).
    ///
    /// # Errors
    /// [`NlriError`] when the field is syntactically incorrect per RFC 7606
    /// §5.3: a length over the family's address size, or a tuple that runs
    /// past the end of the field. Families other than IPv4 and IPv6 cannot
    /// be decoded.
    pub fn decode(r: &mut Reader<'_>, afi: Afi) -> Result<Prefix, NlriError> {
        let max = match afi {
            Afi::Ipv4 => 32,
            Afi::Ipv6 => 128,
            Afi::Unknown(_) => return Err(NlriError::UnsupportedAfi(afi)),
        };
        let len = r.u8().map_err(|_| NlriError::Truncated)?;
        if len > max {
            return Err(NlriError::LengthTooLong { len, max });
        }
        let bytes = r
            .take(prefix_octets(len))
            .map_err(|_| NlriError::Truncated)?;
        let prefix = if afi == Afi::Ipv4 {
            let mut o = [0u8; 4];
            o[..bytes.len()].copy_from_slice(bytes);
            Prefix::V4 {
                addr: Ipv4Addr::from(mask32(u32::from_be_bytes(o), len)),
                len,
            }
        } else {
            let mut o = [0u8; 16];
            o[..bytes.len()].copy_from_slice(bytes);
            Prefix::V6 {
                addr: Ipv6Addr::from(mask128(u128::from_be_bytes(o), len)),
                len,
            }
        };
        Ok(prefix)
    }
}

/// Octets needed to carry `bits` prefix bits.
const fn prefix_octets(bits: u8) -> usize {
    (bits as usize).div_ceil(8)
}

const fn mask32(v: u32, len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        v & (u32::MAX << (32 - len as u32))
    }
}

const fn mask128(v: u128, len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        v & (u128::MAX << (128 - len as u32))
    }
}

/// Decode a whole Withdrawn Routes or NLRI field of family `afi`.
///
/// # Errors
/// As [`Prefix::decode`]; the field is all-or-nothing (RFC 7606 §5.3).
pub fn decode_prefixes(bytes: &[u8], afi: Afi) -> Result<Vec<Prefix>, NlriError> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(Prefix::decode(&mut r, afi)?);
    }
    Ok(out)
}

/// Encode prefixes back to back.
pub fn encode_prefixes(prefixes: &[Prefix], out: &mut Vec<u8>) {
    for p in prefixes {
        p.encode(out);
    }
}

/// Why an NLRI field is syntactically incorrect (RFC 7606 §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NlriError {
    /// A prefix length larger than the address family allows.
    LengthTooLong {
        /// The length found.
        len: u8,
        /// The family's maximum.
        max: u8,
    },
    /// The last tuple runs past the end of the field.
    Truncated,
    /// NLRI of this family cannot be parsed by this implementation.
    UnsupportedAfi(Afi),
}

impl fmt::Display for NlriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NlriError::LengthTooLong { len, max } => {
                write!(f, "prefix length {len} exceeds {max}")
            }
            NlriError::Truncated => f.write_str("NLRI truncated"),
            NlriError::UnsupportedAfi(afi) => write!(f, "unsupported AFI {}", afi.to_u16()),
        }
    }
}

impl std::error::Error for NlriError {}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), self.prefix_len())
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Why a textual prefix did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsePrefixError;

impl fmt::Display for ParsePrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected address/length")
    }
}

impl std::error::Error for ParsePrefixError {}

impl FromStr for Prefix {
    type Err = ParsePrefixError;

    /// Parse `address/length`. Host bits are zeroed.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').ok_or(ParsePrefixError)?;
        let addr: IpAddr = addr.parse().map_err(|_| ParsePrefixError)?;
        let len: u8 = len.parse().map_err(|_| ParsePrefixError)?;
        Prefix::new(addr, len).ok_or(ParsePrefixError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn canonical_form_zeroes_host_bits() {
        assert_eq!(p("10.1.2.3/8"), p("10.0.0.0/8"));
        assert_eq!(p("10.1.2.3/8").to_string(), "10.0.0.0/8");
        assert_eq!(p("2001:db8:ffff::1/32").to_string(), "2001:db8::/32");
        assert_eq!(p("192.0.2.1/32").to_string(), "192.0.2.1/32");
        assert_eq!(p("0.0.0.0/0"), Prefix::default_route(Afi::Ipv4).unwrap());
        assert_eq!(p("::/0"), Prefix::default_route(Afi::Ipv6).unwrap());
        assert!("10.0.0.0/33".parse::<Prefix>().is_err());
        assert!("::/129".parse::<Prefix>().is_err());
        assert!("10.0.0.0".parse::<Prefix>().is_err());
        assert!("x/8".parse::<Prefix>().is_err());
    }

    #[test]
    fn encoding_uses_the_minimum_octets() {
        // RFC 4271 §4.3.
        let cases: &[(&str, &[u8])] = &[
            ("0.0.0.0/0", &[0]),
            ("10.0.0.0/8", &[8, 10]),
            ("10.1.0.0/9", &[9, 10, 0]),
            ("192.0.2.0/24", &[24, 192, 0, 2]),
            ("192.0.2.1/32", &[32, 192, 0, 2, 1]),
            ("::/0", &[0]),
            ("2001:db8::/32", &[32, 0x20, 0x01, 0x0d, 0xb8]),
            ("2001:db8::/33", &[33, 0x20, 0x01, 0x0d, 0xb8, 0]),
        ];
        for (text, wire) in cases {
            let prefix = p(text);
            let mut out = Vec::new();
            prefix.encode(&mut out);
            assert_eq!(&out, wire, "{text}");
            let mut r = Reader::new(wire);
            assert_eq!(
                Prefix::decode(&mut r, prefix.afi()).unwrap(),
                prefix,
                "{text}"
            );
            assert!(r.is_empty());
        }
    }

    #[test]
    fn trailing_bits_are_ignored_on_decode() {
        // RFC 4271 §4.3: the value of trailing bits is irrelevant.
        let mut r = Reader::new(&[9, 10, 0xff]);
        assert_eq!(
            Prefix::decode(&mut r, Afi::Ipv4).unwrap(),
            p("10.128.0.0/9")
        );
    }

    #[test]
    fn field_decoding_and_syntax_errors() {
        // RFC 7606 §5.3.
        let field = [8, 10, 24, 192, 0, 2, 0];
        assert_eq!(
            decode_prefixes(&field, Afi::Ipv4).unwrap(),
            vec![p("10.0.0.0/8"), p("192.0.2.0/24"), p("0.0.0.0/0")]
        );
        assert_eq!(decode_prefixes(&[], Afi::Ipv6).unwrap(), vec![]);
        assert_eq!(
            decode_prefixes(&[33, 1, 2, 3, 4, 5], Afi::Ipv4),
            Err(NlriError::LengthTooLong { len: 33, max: 32 })
        );
        assert_eq!(
            decode_prefixes(&[129], Afi::Ipv6),
            Err(NlriError::LengthTooLong { len: 129, max: 128 })
        );
        assert_eq!(
            decode_prefixes(&[24, 192, 0], Afi::Ipv4),
            Err(NlriError::Truncated)
        );
        assert_eq!(
            decode_prefixes(&[8, 10], Afi::Unknown(25)),
            Err(NlriError::UnsupportedAfi(Afi::Unknown(25)))
        );
        let mut out = Vec::new();
        encode_prefixes(
            &[p("10.0.0.0/8"), p("192.0.2.0/24"), p("0.0.0.0/0")],
            &mut out,
        );
        assert_eq!(out, field);
    }

    #[test]
    fn ordering_is_total_and_stable() {
        let mut v = vec![p("10.0.0.0/8"), p("::/0"), p("10.0.0.0/9"), p("9.0.0.0/8")];
        v.sort();
        assert_eq!(
            v,
            vec![p("9.0.0.0/8"), p("10.0.0.0/8"), p("10.0.0.0/9"), p("::/0")]
        );
    }
}
