//! `MP_REACH_NLRI` and `MP_UNREACH_NLRI`.
//!
//! Implements: RFC 4760 §3 (`MP_REACH_NLRI`), §4 (`MP_UNREACH_NLRI`), §5
//! (NLRI encoding), §6 (SAFI values); RFC 2545 §3 (IPv6 next hop: global,
//! optionally followed by link-local); RFC 8950 §3 (IPv6 next hop for IPv4
//! NLRI, told apart by its length); RFC 7606 §5.3 (minimum lengths, NLRI
//! syntax), §7.11 (next hop length).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::prefix::{NlriError, Prefix, decode_prefixes, encode_prefixes};
use crate::reader::{Reader, WriteBytes as _};
use crate::types::{AddressFamily, Afi, Safi};

/// Network Address of Next Hop (RFC 4760 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NextHop {
    /// A four-octet IPv4 next hop.
    Ipv4(Ipv4Addr),
    /// A global IPv6 next hop, optionally with the link-local address of the
    /// same router (RFC 2545 §3): 16 or 32 octets on the wire.
    Ipv6 {
        /// Global-scope address.
        global: Ipv6Addr,
        /// Link-local address, present only when the sender shares a subnet
        /// with the next hop and the receiver (RFC 2545 §3).
        link_local: Option<Ipv6Addr>,
    },
}

impl NextHop {
    /// Length of Next Hop Network Address on the wire.
    #[must_use]
    pub const fn wire_len(&self) -> u8 {
        match self {
            NextHop::Ipv4(_) => 4,
            NextHop::Ipv6 {
                link_local: None, ..
            } => 16,
            NextHop::Ipv6 {
                link_local: Some(_),
                ..
            } => 32,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            NextHop::Ipv4(a) => out.put_bytes(&a.octets()),
            NextHop::Ipv6 { global, link_local } => {
                out.put_bytes(&global.octets());
                if let Some(ll) = link_local {
                    out.put_bytes(&ll.octets());
                }
            }
        }
    }

    /// Decode `len` octets of next hop for NLRI of family `afi`
    /// (RFC 4760 §3; RFC 2545 §3; RFC 8950 §3).
    fn decode(r: &mut Reader<'_>, afi: Afi, len: u8) -> Option<NextHop> {
        match (afi, len) {
            (Afi::Ipv4, 4) => Some(NextHop::Ipv4(Ipv4Addr::from(r.array::<4>().ok()?))),
            // RFC 8950 §3 for IPv4 NLRI, RFC 2545 §3 for IPv6 NLRI.
            (Afi::Ipv4 | Afi::Ipv6, 16) => Some(NextHop::Ipv6 {
                global: Ipv6Addr::from(r.array::<16>().ok()?),
                link_local: None,
            }),
            (Afi::Ipv4 | Afi::Ipv6, 32) => Some(NextHop::Ipv6 {
                global: Ipv6Addr::from(r.array::<16>().ok()?),
                link_local: Some(Ipv6Addr::from(r.array::<16>().ok()?)),
            }),
            _ => None,
        }
    }
}

impl fmt::Display for NextHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NextHop::Ipv4(a) => a.fmt(f),
            NextHop::Ipv6 {
                global,
                link_local: None,
            } => global.fmt(f),
            NextHop::Ipv6 {
                global,
                link_local: Some(ll),
            } => write!(f, "{global} ({ll})"),
        }
    }
}

/// `MP_REACH_NLRI` (type 14): feasible routes of one family with their next
/// hop (RFC 4760 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MpReach {
    /// `<AFI, SAFI>` of the NLRI.
    pub family: AddressFamily,
    /// Next hop for every prefix in `nlri`.
    pub next_hop: NextHop,
    /// Advertised prefixes.
    pub nlri: Vec<Prefix>,
}

/// `MP_UNREACH_NLRI` (type 15): withdrawn routes of one family
/// (RFC 4760 §4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MpUnreach {
    /// `<AFI, SAFI>` of the withdrawn routes.
    pub family: AddressFamily,
    /// Withdrawn prefixes.
    pub withdrawn: Vec<Prefix>,
}

/// Minimum `MP_REACH_NLRI` length (RFC 7606 §5.3).
pub const MP_REACH_MIN_LEN: usize = 5;
/// Minimum `MP_UNREACH_NLRI` length (RFC 7606 §5.3).
pub const MP_UNREACH_MIN_LEN: usize = 3;

/// The `<AFI, SAFI>` at the start of either attribute, if at least three
/// octets are present. Used to pick the family to disable when the rest of
/// the attribute is unusable (RFC 4760 §7).
#[must_use]
pub fn family_of(value: &[u8]) -> Option<AddressFamily> {
    let mut r = Reader::new(value);
    let afi = Afi::from_u16(r.u16().ok()?);
    let safi = Safi::from_u8(r.u8().ok()?);
    Some(AddressFamily { afi, safi })
}

fn supported(family: AddressFamily) -> bool {
    matches!(family.afi, Afi::Ipv4 | Afi::Ipv6) && family.safi == Safi::Unicast
}

impl MpReach {
    /// Decode an attribute value.
    ///
    /// # Errors
    /// [`MpError`] when the attribute is incorrect per RFC 7606 §5.3 and
    /// §7.11, or carries a family this implementation cannot parse
    /// (anything but IPv4 and IPv6 unicast).
    pub fn decode(value: &[u8]) -> Result<MpReach, MpError> {
        if value.len() < MP_REACH_MIN_LEN {
            return Err(MpError::TooShort {
                len: value.len(),
                min: MP_REACH_MIN_LEN,
            });
        }
        let mut r = Reader::new(value);
        // Five octets are present, so the fixed fields cannot fail.
        let afi = Afi::from_u16(r.u16().unwrap_or_default());
        let safi = Safi::from_u8(r.u8().unwrap_or_default());
        let family = AddressFamily { afi, safi };
        if !supported(family) {
            return Err(MpError::UnsupportedFamily(family));
        }
        let nh_len = r.u8().unwrap_or_default();
        let next_hop = NextHop::decode(&mut r, afi, nh_len).ok_or(MpError::BadNextHopLength {
            family,
            len: nh_len,
        })?;
        // RFC 4760 §3: Reserved, SHOULD be ignored. Its absence means the
        // next hop overran the attribute.
        let _reserved = r.u8().map_err(|_| MpError::BadNextHopLength {
            family,
            len: nh_len,
        })?;
        let nlri = decode_prefixes(r.rest(), afi).map_err(MpError::Nlri)?;
        Ok(MpReach {
            family,
            next_hop,
            nlri,
        })
    }

    /// Append the attribute value: AFI, SAFI, next hop length, next hop, a
    /// zero reserved octet, NLRI (RFC 4760 §3).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.family.afi.to_u16());
        out.put_u8(self.family.safi.to_u8());
        out.put_u8(self.next_hop.wire_len());
        self.next_hop.encode(out);
        out.put_u8(0);
        encode_prefixes(&self.nlri, out);
    }
}

impl MpUnreach {
    /// Decode an attribute value.
    ///
    /// # Errors
    /// [`MpError`] when shorter than three octets, of an unsupported family,
    /// or with syntactically incorrect NLRI (RFC 7606 §5.3).
    pub fn decode(value: &[u8]) -> Result<MpUnreach, MpError> {
        if value.len() < MP_UNREACH_MIN_LEN {
            return Err(MpError::TooShort {
                len: value.len(),
                min: MP_UNREACH_MIN_LEN,
            });
        }
        let mut r = Reader::new(value);
        let afi = Afi::from_u16(r.u16().unwrap_or_default());
        let safi = Safi::from_u8(r.u8().unwrap_or_default());
        let family = AddressFamily { afi, safi };
        if !supported(family) {
            return Err(MpError::UnsupportedFamily(family));
        }
        let withdrawn = decode_prefixes(r.rest(), afi).map_err(MpError::Nlri)?;
        Ok(MpUnreach { family, withdrawn })
    }

    /// Append the attribute value: AFI, SAFI, withdrawn routes
    /// (RFC 4760 §4).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.family.afi.to_u16());
        out.put_u8(self.family.safi.to_u8());
        encode_prefixes(&self.withdrawn, out);
    }
}

/// Why a multiprotocol attribute is incorrect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpError {
    /// Shorter than the fixed fields (RFC 7606 §5.3).
    TooShort {
        /// Length found.
        len: usize,
        /// Minimum for this attribute.
        min: usize,
    },
    /// A family whose NLRI this implementation cannot parse.
    UnsupportedFamily(AddressFamily),
    /// Length of Next Hop Network Address not valid for the family
    /// (RFC 7606 §7.11).
    BadNextHopLength {
        /// The attribute's family.
        family: AddressFamily,
        /// The length found.
        len: u8,
    },
    /// NLRI syntactically incorrect (RFC 7606 §5.3).
    Nlri(NlriError),
}

impl MpError {
    /// The family the attribute named, when it got that far.
    #[must_use]
    pub const fn family(&self) -> Option<AddressFamily> {
        match self {
            MpError::TooShort { .. } | MpError::Nlri(_) => None,
            MpError::UnsupportedFamily(f) | MpError::BadNextHopLength { family: f, .. } => Some(*f),
        }
    }
}

impl fmt::Display for MpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpError::TooShort { len, min } => {
                write!(f, "attribute is {len} octets, minimum {min}")
            }
            MpError::UnsupportedFamily(fam) => write!(f, "unsupported address family {fam}"),
            MpError::BadNextHopLength { family, len } => {
                write!(f, "next hop length {len} is invalid for {family}")
            }
            MpError::Nlri(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for MpError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn ipv6_unicast_reach_round_trips() {
        // RFC 2545 §3: global next hop then link-local, length 32.
        let m = MpReach {
            family: AddressFamily::IPV6_UNICAST,
            next_hop: NextHop::Ipv6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: Some("fe80::1".parse().unwrap()),
            },
            nlri: vec![p("2001:db8:1::/48"), p("::/0")],
        };
        let mut wire = Vec::new();
        m.encode(&mut wire);
        let mut expect = vec![0, 2, 1, 32];
        expect.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        expect.extend_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        expect.extend_from_slice(&[0, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0]);
        assert_eq!(wire, expect);
        assert_eq!(MpReach::decode(&wire).unwrap(), m);
        assert_eq!(m.next_hop.to_string(), "2001:db8::1 (fe80::1)");
        // Global only, length 16.
        let m16 = MpReach {
            next_hop: NextHop::Ipv6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: None,
            },
            ..m
        };
        let mut wire = Vec::new();
        m16.encode(&mut wire);
        assert_eq!(wire[3], 16);
        assert_eq!(MpReach::decode(&wire).unwrap(), m16);
    }

    #[test]
    fn ipv4_nlri_with_ipv4_or_ipv6_next_hop() {
        let v4 = MpReach {
            family: AddressFamily::IPV4_UNICAST,
            next_hop: NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            nlri: vec![p("10.0.0.0/8")],
        };
        let mut wire = Vec::new();
        v4.encode(&mut wire);
        assert_eq!(wire, [0, 1, 1, 4, 192, 0, 2, 1, 0, 8, 10]);
        assert_eq!(MpReach::decode(&wire).unwrap(), v4);
        // RFC 8950 §3: IPv4 NLRI, 16-octet IPv6 next hop.
        let v6nh = MpReach {
            next_hop: NextHop::Ipv6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: None,
            },
            ..v4
        };
        let mut wire = Vec::new();
        v6nh.encode(&mut wire);
        assert_eq!(&wire[..4], &[0, 1, 1, 16]);
        assert_eq!(MpReach::decode(&wire).unwrap(), v6nh);
        // RFC 4760 §3: reserved octet ignored.
        wire[20] = 0xff;
        assert_eq!(MpReach::decode(&wire).unwrap(), v6nh);
    }

    #[test]
    fn reach_errors() {
        assert_eq!(
            MpReach::decode(&[0, 1, 1, 4]),
            Err(MpError::TooShort { len: 4, min: 5 })
        );
        let vpn = AddressFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unknown(128),
        };
        assert_eq!(
            MpReach::decode(&[0, 1, 128, 4, 1, 2, 3, 4, 0]),
            Err(MpError::UnsupportedFamily(vpn))
        );
        // RFC 7606 §7.11: next hop length inconsistent with the family.
        let e = MpReach::decode(&[0, 1, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0]).unwrap_err();
        assert_eq!(
            e,
            MpError::BadNextHopLength {
                family: AddressFamily::IPV4_UNICAST,
                len: 8
            }
        );
        assert_eq!(e.family(), Some(AddressFamily::IPV4_UNICAST));
        // IPv6 NLRI never has a four-octet next hop.
        assert!(matches!(
            MpReach::decode(&[0, 2, 1, 4, 1, 2, 3, 4, 0]),
            Err(MpError::BadNextHopLength { .. })
        ));
        // Next hop longer than the attribute.
        assert!(matches!(
            MpReach::decode(&[0, 1, 1, 16, 1, 2, 3]),
            Err(MpError::BadNextHopLength { .. })
        ));
        // Reserved octet missing.
        assert!(matches!(
            MpReach::decode(&[0, 1, 1, 4, 1, 2, 3, 4]),
            Err(MpError::BadNextHopLength { .. })
        ));
        // RFC 7606 §5.3: NLRI length over the family's size.
        assert_eq!(
            MpReach::decode(&[0, 1, 1, 4, 1, 2, 3, 4, 0, 33, 1, 2, 3, 4, 5]),
            Err(MpError::Nlri(NlriError::LengthTooLong { len: 33, max: 32 }))
        );
        assert_eq!(family_of(&[0, 2, 1]), Some(AddressFamily::IPV6_UNICAST));
        assert_eq!(family_of(&[0, 2]), None);
    }

    #[test]
    fn unreach_round_trip_and_errors() {
        let m = MpUnreach {
            family: AddressFamily::IPV6_UNICAST,
            withdrawn: vec![p("2001:db8::/32")],
        };
        let mut wire = Vec::new();
        m.encode(&mut wire);
        assert_eq!(wire, [0, 2, 1, 32, 0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(MpUnreach::decode(&wire).unwrap(), m);
        // RFC 7606 §5.2 / RFC 4724: an End-of-RIB marker is an empty one.
        let eor = MpUnreach::decode(&[0, 2, 1]).unwrap();
        assert_eq!(eor.withdrawn, vec![]);
        assert_eq!(
            MpUnreach::decode(&[0, 2]),
            Err(MpError::TooShort { len: 2, min: 3 })
        );
        assert_eq!(
            MpUnreach::decode(&[0, 2, 1, 24, 0x20]),
            Err(MpError::Nlri(NlriError::Truncated))
        );
        assert!(matches!(
            MpUnreach::decode(&[0, 2, 2]),
            Err(MpError::UnsupportedFamily(_))
        ));
    }
}
