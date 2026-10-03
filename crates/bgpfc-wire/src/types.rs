//! Typed wire values shared by several messages: AS numbers, BGP
//! identifiers, hold times, address families.
//!
//! Implements: RFC 4271 §4.2 (Hold Time, BGP Identifier), RFC 6793 §3
//! (four-octet AS numbers, `AS_TRANS`), RFC 4760 §3 (AFI/SAFI values),
//! RFC 6286 §2.1 (BGP Identifier is any non-zero 4-octet value).

use std::fmt;
use std::net::Ipv4Addr;

/// An Autonomous System number. Always held as four octets (RFC 6793 §3):
/// a two-octet ASN is the same number with the high two octets zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Asn(pub u32);

impl Asn {
    /// `AS_TRANS`: stands in for a non-mappable four-octet ASN wherever only
    /// two octets fit (RFC 6793 §3; IANA value 23456).
    pub const TRANS: Asn = Asn(23_456);

    /// `AS_TRANS` as it appears in a two-octet field.
    pub const TRANS_TWO_OCTET: u16 = 23_456;

    /// Whether this ASN fits in two octets (RFC 6793 §3, "mappable").
    #[must_use]
    pub const fn is_mappable(self) -> bool {
        self.0 <= u16::MAX as u32
    }

    /// The two-octet representation: the number itself if mappable,
    /// otherwise `AS_TRANS` (RFC 6793 §3).
    #[must_use]
    pub fn to_two_octet(self) -> u16 {
        u16::try_from(self.0).unwrap_or(Asn::TRANS_TWO_OCTET)
    }
}

impl From<u16> for Asn {
    fn from(v: u16) -> Self {
        Asn(u32::from(v))
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

/// BGP Identifier: a four-octet value chosen by the speaker (RFC 4271 §4.2),
/// conventionally one of its IPv4 addresses and printed as such.
///
/// RFC 6286 §2.1 updates RFC 4271: any non-zero value is syntactically
/// valid, so [`RouterId::new`] rejects only zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouterId(u32);

impl RouterId {
    /// Validate a BGP Identifier: must be non-zero (RFC 6286 §2.1).
    #[must_use]
    pub const fn new(v: u32) -> Option<RouterId> {
        if v == 0 { None } else { Some(RouterId(v)) }
    }

    /// Raw value.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

impl From<Ipv4Addr> for RouterId {
    /// Infallible for display purposes; a `0.0.0.0` router ID is still
    /// rejected on the wire by [`RouterId::new`].
    fn from(a: Ipv4Addr) -> Self {
        RouterId(u32::from(a))
    }
}

impl fmt::Display for RouterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ipv4Addr::from(self.0).fmt(f)
    }
}

/// Hold Time in seconds: zero, or at least three (RFC 4271 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HoldTime(u16);

impl HoldTime {
    /// Validate a Hold Time: `0` or `>= 3` (RFC 4271 §4.2; §6.2 requires
    /// rejecting one and two seconds).
    #[must_use]
    pub const fn new(secs: u16) -> Option<HoldTime> {
        if secs == 1 || secs == 2 {
            None
        } else {
            Some(HoldTime(secs))
        }
    }

    /// Seconds.
    #[must_use]
    pub const fn secs(self) -> u16 {
        self.0
    }

    /// Whether this disables the hold timer and keepalives (RFC 4271 §4.4).
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for HoldTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0)
    }
}

/// Address Family Identifier (RFC 4760 §3; IANA "Address Family Numbers").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Afi {
    /// IP version 4.
    Ipv4,
    /// IP version 6.
    Ipv6,
    /// Any other registered or unregistered value.
    Unknown(u16),
}

impl Afi {
    /// Wire value.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Afi::Ipv4 => 1,
            Afi::Ipv6 => 2,
            Afi::Unknown(v) => v,
        }
    }

    /// From the wire value.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            1 => Afi::Ipv4,
            2 => Afi::Ipv6,
            v => Afi::Unknown(v),
        }
    }
}

/// Subsequent Address Family Identifier (RFC 4760 §3, §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Safi {
    /// Unicast forwarding.
    Unicast,
    /// Multicast forwarding.
    Multicast,
    /// Any other registered or unregistered value.
    Unknown(u8),
}

impl Safi {
    /// Wire value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Safi::Unicast => 1,
            Safi::Multicast => 2,
            Safi::Unknown(v) => v,
        }
    }

    /// From the wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Safi::Unicast,
            2 => Safi::Multicast,
            v => Safi::Unknown(v),
        }
    }
}

/// An `<AFI, SAFI>` pair, as negotiated with RFC 4760 §8 and named in
/// ROUTE-REFRESH (RFC 2918 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressFamily {
    /// Address Family Identifier.
    pub afi: Afi,
    /// Subsequent Address Family Identifier.
    pub safi: Safi,
}

impl AddressFamily {
    /// IPv4 unicast.
    pub const IPV4_UNICAST: AddressFamily = AddressFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    };
    /// IPv6 unicast.
    pub const IPV6_UNICAST: AddressFamily = AddressFamily {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
    };
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let afi = match self.afi {
            Afi::Ipv4 => "ipv4".to_owned(),
            Afi::Ipv6 => "ipv6".to_owned(),
            Afi::Unknown(v) => format!("afi{v}"),
        };
        let safi = match self.safi {
            Safi::Unicast => "unicast".to_owned(),
            Safi::Multicast => "multicast".to_owned(),
            Safi::Unknown(v) => format!("safi{v}"),
        };
        write!(f, "{afi}-{safi}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn_mapping_and_as_trans() {
        assert_eq!(Asn::TRANS, Asn(23_456));
        assert!(Asn(65_535).is_mappable());
        assert!(!Asn(65_536).is_mappable());
        assert_eq!(Asn(64_512).to_two_octet(), 64_512);
        assert_eq!(Asn(4_200_000_000).to_two_octet(), 23_456);
        assert_eq!(Asn::from(7u16), Asn(7));
        assert_eq!(Asn(65_000).to_string(), "AS65000");
    }

    #[test]
    fn router_id_rejects_zero_only() {
        assert_eq!(RouterId::new(0), None);
        let id = RouterId::new(0xc000_0201).unwrap();
        assert_eq!(id.to_string(), "192.0.2.1");
        assert_eq!(RouterId::from(Ipv4Addr::new(192, 0, 2, 1)), id);
        // RFC 6286: a value that is not a unicast host address is still valid.
        assert!(RouterId::new(0xffff_ffff).is_some());
    }

    #[test]
    fn hold_time_rejects_one_and_two() {
        assert!(HoldTime::new(0).unwrap().is_zero());
        assert_eq!(HoldTime::new(1), None);
        assert_eq!(HoldTime::new(2), None);
        assert_eq!(HoldTime::new(3).unwrap().secs(), 3);
        assert_eq!(HoldTime::new(90).unwrap().to_string(), "90s");
    }

    #[test]
    fn afi_safi_round_trip() {
        for v in [0u16, 1, 2, 3, 25, 0xffff] {
            assert_eq!(Afi::from_u16(v).to_u16(), v);
        }
        for v in 0..=u8::MAX {
            assert_eq!(Safi::from_u8(v).to_u8(), v);
        }
        assert_eq!(AddressFamily::IPV4_UNICAST.to_string(), "ipv4-unicast");
        let odd = AddressFamily {
            afi: Afi::Unknown(25),
            safi: Safi::Unknown(70),
        };
        assert_eq!(odd.to_string(), "afi25-safi70");
    }
}
