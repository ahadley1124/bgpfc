//! `MP_REACH_NLRI` and `MP_UNREACH_NLRI`.
//!
//! Implements: RFC 4760 §3 (`MP_REACH_NLRI`), §4 (`MP_UNREACH_NLRI`), §5
//! (NLRI encoding), §6 (SAFI values); RFC 2545 §3 (IPv6 next hop: global,
//! optionally followed by link-local); RFC 8950 §3 (IPv6 next hop for IPv4
//! NLRI, told apart by its length), §4 (only once negotiated); RFC 7606
//! §5.3 (minimum lengths, NLRI syntax), §7.11 (next hop length); RFC 4271
//! §6.3 (a next hop is a valid IP host address), which RFC 4760 §3 applies
//! to the next hop of `MP_REACH_NLRI` as well.

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

    /// Whether the next hop is a valid IP host address: what RFC 4271 §6.3
    /// calls a syntactically correct `NEXT_HOP`, with RFC 4760 §3 holding
    /// `MP_REACH_NLRI` next hops to the same rules. For IPv6 that is the
    /// global address RFC 2545 §3 puts first; the link-local one after it
    /// is checked on decode.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        match self {
            NextHop::Ipv4(a) => is_host_ipv4(*a),
            NextHop::Ipv6 { global, .. } => is_global_ipv6(*global),
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
    /// (RFC 4760 §3; RFC 2545 §3; RFC 8950 §3). `extended_next_hop`: we
    /// advertised RFC 8950 §4 Extended Next Hop Encoding for IPv4 unicast.
    fn decode(r: &mut Reader<'_>, afi: Afi, len: u8, extended_next_hop: bool) -> Option<NextHop> {
        match (afi, len) {
            (Afi::Ipv4, 4) => Some(NextHop::Ipv4(Ipv4Addr::from(r.array::<4>().ok()?))),
            // RFC 2545 §3 for IPv6 NLRI. RFC 8950 §3 for IPv4 NLRI, but only
            // once we advertised it (§4): RFC 7606 §7.11 judges the length
            // against the AFI/SAFI "potentially modified by any extensions
            // in use", so without RFC 8950 four octets are the only length
            // expected.
            (Afi::Ipv4 | Afi::Ipv6, 16 | 32) if afi == Afi::Ipv6 || extended_next_hop => {
                let global = Ipv6Addr::from(r.array::<16>().ok()?);
                let link_local = if len == 32 {
                    Some(Ipv6Addr::from(r.array::<16>().ok()?))
                } else {
                    None
                };
                // RFC 2545 §3: the second address is "the link-local IPv6
                // address of the next hop". NOTE(interop): the RFC says
                // nothing of one that is not link-local; BIRD and FRR
                // ignore it and keep the route, and so do we.
                let link_local = link_local.filter(Ipv6Addr::is_unicast_link_local);
                Some(NextHop::Ipv6 { global, link_local })
            }
            _ => None,
        }
    }
}

/// Whether `a` is a valid IP host address, which RFC 4271 §6.3 requires of
/// a `NEXT_HOP`. Not host addresses: `0.0.0.0/8`, which RFC 1122 §3.2.1.3
/// (a) and (b) allow only as a source while a host learns its address;
/// `127.0.0.0/8`, which §3.2.1.3 (g) keeps inside a host; `224.0.0.0/4`,
/// which identifies host groups (RFC 1112 §4); and `240.0.0.0/4`, reserved
/// (RFC 1112 §4), which holds the limited broadcast address
/// `255.255.255.255` (RFC 1122 §3.2.1.3 (c)). A directed broadcast address
/// cannot be told apart without the subnet's mask.
#[must_use]
pub const fn is_host_ipv4(a: Ipv4Addr) -> bool {
    let [first, ..] = a.octets();
    !(first == 0 || first == 127 || first >= 224)
}

/// Whether `a` can be the global address RFC 2545 §3 puts first in an IPv6
/// next hop. Not the unspecified address, which "must not be used as the
/// destination address" (RFC 4291 §2.5.2); not the loopback address, which
/// never leaves a node (§2.5.3); not a multicast address (§2.7); and not a
/// link-local one (§2.5.6), whose place is the second address of a 32-octet
/// next hop.
#[must_use]
pub const fn is_global_ipv6(a: Ipv6Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_unicast_link_local())
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
    /// Decode an attribute value. `extended_next_hop`: we advertised
    /// Extended Next Hop Encoding for IPv4 unicast (RFC 8950 §4), so its
    /// next hop may be IPv6 (§3).
    ///
    /// # Errors
    /// [`MpError`] when the attribute is incorrect per RFC 7606 §5.3 and
    /// §7.11, or carries a family this implementation cannot parse
    /// (anything but IPv4 and IPv6 unicast).
    pub fn decode(value: &[u8], extended_next_hop: bool) -> Result<MpReach, MpError> {
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
        let next_hop = NextHop::decode(&mut r, afi, nh_len, extended_next_hop).ok_or(
            MpError::BadNextHopLength {
                family,
                len: nh_len,
            },
        )?;
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
        assert_eq!(MpReach::decode(&wire, false).unwrap(), m);
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
        assert_eq!(MpReach::decode(&wire, false).unwrap(), m16);
    }

    #[test]
    fn host_addresses_per_rfc4271_section_6_3() {
        // RFC 1122 §3.2.1.3 and RFC 1112 §4, at the edges of each range.
        for (a, host) in [
            ("0.0.0.0", false),
            ("0.255.255.255", false),
            ("1.0.0.0", true),
            ("10.0.0.1", true),
            ("126.255.255.255", true),
            ("127.0.0.1", false),
            ("127.255.255.255", false),
            ("128.0.0.0", true),
            ("223.255.255.255", true),
            ("224.0.0.0", false),
            ("239.255.255.255", false),
            ("240.0.0.1", false),
            ("255.255.255.255", false),
        ] {
            let a: Ipv4Addr = a.parse().unwrap();
            assert_eq!(is_host_ipv4(a), host, "{a}");
            assert_eq!(NextHop::Ipv4(a).is_valid(), host, "{a}");
        }
        // RFC 2545 §3 and RFC 4291: the first address is a global one.
        for (a, global) in [
            ("::", false),
            ("::1", false),
            ("ff02::1", false),
            ("ff0e::1", false),
            ("fe80::1", false),
            ("febf::1", false),
            ("fec0::1", true),
            ("fc00::1", true),
            ("2001:db8::1", true),
            ("::ffff:192.0.2.1", true),
        ] {
            let a: Ipv6Addr = a.parse().unwrap();
            assert_eq!(is_global_ipv6(a), global, "{a}");
            let nh = NextHop::Ipv6 {
                global: a,
                link_local: Some("fe80::1".parse().unwrap()),
            };
            assert_eq!(nh.is_valid(), global, "{a}");
        }
    }

    #[test]
    fn a_second_address_that_is_not_link_local_is_ignored() {
        // RFC 2545 §3 wants the link-local address second; BIRD and FRR
        // drop anything else and keep the route.
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let other: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut wire = vec![0, 2, 1, 32];
        wire.extend_from_slice(&global.octets());
        wire.extend_from_slice(&other.octets());
        wire.extend_from_slice(&[0, 32, 0x20, 0x01, 0x0d, 0xb8]);
        let m = MpReach::decode(&wire, false).unwrap();
        assert_eq!(
            m.next_hop,
            NextHop::Ipv6 {
                global,
                link_local: None
            }
        );
        assert_eq!(m.nlri, vec![p("2001:db8::/32")]);
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
        for negotiated in [false, true] {
            assert_eq!(MpReach::decode(&wire, negotiated).unwrap(), v4);
        }
        // RFC 8950 §3: IPv4 NLRI, 16-octet IPv6 next hop.
        let v6nh = MpReach {
            next_hop: NextHop::Ipv6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: None,
            },
            ..v4.clone()
        };
        let mut wire = Vec::new();
        v6nh.encode(&mut wire);
        assert_eq!(&wire[..4], &[0, 1, 1, 16]);
        assert_eq!(MpReach::decode(&wire, true).unwrap(), v6nh);
        // RFC 4760 §3: reserved octet ignored.
        wire[20] = 0xff;
        assert_eq!(MpReach::decode(&wire, true).unwrap(), v6nh);
    }

    #[test]
    fn ipv6_next_hop_for_ipv4_nlri_needs_rfc8950() {
        // RFC 8950 §6.1, laid out by hand: AFI 1, SAFI 1, a 32-octet next
        // hop (global then link-local, RFC 2545 §3), reserved, then
        // 192.0.2.0/24.
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut wire = vec![0, 1, 1, 32];
        wire.extend_from_slice(&global.octets());
        wire.extend_from_slice(&link_local.octets());
        wire.extend_from_slice(&[0, 24, 192, 0, 2]);
        let m = MpReach {
            family: AddressFamily::IPV4_UNICAST,
            next_hop: NextHop::Ipv6 {
                global,
                link_local: Some(link_local),
            },
            nlri: vec![p("192.0.2.0/24")],
        };
        assert_eq!(MpReach::decode(&wire, true).unwrap(), m);
        let mut again = Vec::new();
        m.encode(&mut again);
        assert_eq!(again, wire);
        // RFC 7606 §7.11: without RFC 8950 only four octets are expected
        // for IPv4 NLRI; 16 and 32 are malformed and disable the family.
        assert_eq!(
            MpReach::decode(&wire, false),
            Err(MpError::BadNextHopLength {
                family: AddressFamily::IPV4_UNICAST,
                len: 32
            })
        );
        let mut short = vec![0, 1, 1, 16];
        short.extend_from_slice(&global.octets());
        short.extend_from_slice(&[0, 24, 192, 0, 2]);
        assert_eq!(
            MpReach::decode(&short, false),
            Err(MpError::BadNextHopLength {
                family: AddressFamily::IPV4_UNICAST,
                len: 16
            })
        );
        assert!(MpReach::decode(&short, true).is_ok());
        // Negotiated or not, other lengths stay malformed, and IPv6 NLRI
        // is unaffected (RFC 2545 §3).
        assert!(MpReach::decode(&[0, 1, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0], true).is_err());
        let mut v6 = vec![0, 2, 1, 16];
        v6.extend_from_slice(&global.octets());
        v6.push(0);
        for negotiated in [false, true] {
            assert!(MpReach::decode(&v6, negotiated).is_ok());
        }
    }

    #[test]
    fn reach_errors() {
        assert_eq!(
            MpReach::decode(&[0, 1, 1, 4], false),
            Err(MpError::TooShort { len: 4, min: 5 })
        );
        let vpn = AddressFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unknown(128),
        };
        assert_eq!(
            MpReach::decode(&[0, 1, 128, 4, 1, 2, 3, 4, 0], false),
            Err(MpError::UnsupportedFamily(vpn))
        );
        // RFC 7606 §7.11: next hop length inconsistent with the family.
        let e = MpReach::decode(&[0, 1, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0], false).unwrap_err();
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
            MpReach::decode(&[0, 2, 1, 4, 1, 2, 3, 4, 0], false),
            Err(MpError::BadNextHopLength { .. })
        ));
        // Next hop longer than the attribute.
        assert!(matches!(
            MpReach::decode(&[0, 1, 1, 16, 1, 2, 3], true),
            Err(MpError::BadNextHopLength { .. })
        ));
        // Reserved octet missing.
        assert!(matches!(
            MpReach::decode(&[0, 1, 1, 4, 1, 2, 3, 4], false),
            Err(MpError::BadNextHopLength { .. })
        ));
        // RFC 7606 §5.3: NLRI length over the family's size.
        assert_eq!(
            MpReach::decode(&[0, 1, 1, 4, 1, 2, 3, 4, 0, 33, 1, 2, 3, 4, 5], false),
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
