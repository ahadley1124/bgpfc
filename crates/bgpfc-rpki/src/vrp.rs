//! Validated ROA Payloads.
//!
//! Implements: RFC 6811 §2 (a VRP is an IP prefix, a maximum length and
//! an origin AS); RFC 8210 §5.1, §5.6, §5.7 (Max Length is at least the
//! prefix length and at most the address size of the family).

use std::fmt;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Asn;

use crate::RpkiError;

/// A Validated ROA Payload: "(IP address, prefix length, maximum length,
/// origin AS number)" (RFC 6811 §2).
///
/// The fields are private so that every `Vrp` has a maximum length within
/// the bounds [`Vrp::new`] checks. A VRP for AS 0 is legal: it disavows
/// origination of its prefix and everything more specific (RFC 6483 §4),
/// and validation never lets it match (RFC 6811 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Vrp {
    prefix: Prefix,
    max_len: u8,
    asn: Asn,
}

impl Vrp {
    /// Build a VRP.
    ///
    /// # Errors
    /// [`RpkiError::MaxLenBelowPrefixLen`] when `max_len` is shorter than
    /// the prefix, and [`RpkiError::MaxLenTooLong`] when it exceeds 32 for
    /// IPv4 or 128 for IPv6.
    pub fn new(prefix: Prefix, max_len: u8, asn: Asn) -> Result<Vrp, RpkiError> {
        // RFC 8210 §5.1: Max Length "MUST NOT be less than the Prefix
        // Length element".
        if max_len < prefix.prefix_len() {
            return Err(RpkiError::MaxLenBelowPrefixLen { prefix, max_len });
        }
        // RFC 8210 §5.6, §5.7: the field ranges are 0..32 and 0..128.
        if max_len > address_bits(prefix) {
            return Err(RpkiError::MaxLenTooLong { prefix, max_len });
        }
        Ok(Vrp {
            prefix,
            max_len,
            asn,
        })
    }

    /// The VRP Prefix (RFC 6811 §2).
    #[must_use]
    pub const fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// The maximum length: the longest route prefix this VRP authorises.
    #[must_use]
    pub const fn max_len(&self) -> u8 {
        self.max_len
    }

    /// The VRP ASN: the AS authorised to originate (RFC 6811 §2).
    #[must_use]
    pub const fn asn(&self) -> Asn {
        self.asn
    }
}

/// Address size of the prefix's family.
const fn address_bits(prefix: Prefix) -> u8 {
    match prefix {
        Prefix::V4 { .. } => 32,
        Prefix::V6 { .. } => 128,
    }
}

impl fmt::Display for Vrp {
    /// `192.0.2.0/24-24 AS64496`: prefix, maximum length, origin AS, in
    /// the notation of RFC 9319 §3.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{} {}", self.prefix, self.max_len, self.asn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn max_len_bounds() {
        // RFC 8210 §5.1: max length not below the prefix length.
        assert_eq!(
            Vrp::new(p("192.0.2.0/24"), 23, Asn(64_496)),
            Err(RpkiError::MaxLenBelowPrefixLen {
                prefix: p("192.0.2.0/24"),
                max_len: 23
            })
        );
        // RFC 8210 §5.6, §5.7: at most the address size.
        assert_eq!(
            Vrp::new(p("192.0.2.0/24"), 33, Asn(64_496)),
            Err(RpkiError::MaxLenTooLong {
                prefix: p("192.0.2.0/24"),
                max_len: 33
            })
        );
        assert_eq!(
            Vrp::new(p("2001:db8::/32"), 129, Asn(64_496)),
            Err(RpkiError::MaxLenTooLong {
                prefix: p("2001:db8::/32"),
                max_len: 129
            })
        );
        // The edges themselves are fine.
        for (prefix, max_len) in [
            ("192.0.2.0/24", 24),
            ("192.0.2.0/24", 32),
            ("0.0.0.0/0", 0),
            ("192.0.2.1/32", 32),
            ("2001:db8::/32", 32),
            ("2001:db8::/32", 128),
            ("::/0", 0),
            ("2001:db8::1/128", 128),
        ] {
            let vrp = Vrp::new(p(prefix), max_len, Asn(64_496)).unwrap();
            assert_eq!(vrp.prefix(), p(prefix));
            assert_eq!(vrp.max_len(), max_len);
            assert_eq!(vrp.asn(), Asn(64_496));
        }
        // An IPv4 max length that would be fine for IPv6 is not.
        assert!(Vrp::new(p("192.0.2.0/24"), 48, Asn(64_496)).is_err());
    }

    #[test]
    fn as0_vrps_are_legal() {
        // RFC 6483 §4: an AS 0 ROA "should have a maxLength value of 32 for
        // IPv4 addresses and a maxlength value of 128 for IPv6".
        assert!(Vrp::new(p("192.0.2.0/24"), 32, Asn(0)).is_ok());
        assert!(Vrp::new(p("2001:db8::/32"), 128, Asn(0)).is_ok());
    }

    #[test]
    fn display_and_errors() {
        let vrp = Vrp::new(p("192.168.0.0/16"), 24, Asn(64_496)).unwrap();
        assert_eq!(vrp.to_string(), "192.168.0.0/16-24 AS64496");
        let vrp = Vrp::new(p("2001:db8::/32"), 48, Asn(0)).unwrap();
        assert_eq!(vrp.to_string(), "2001:db8::/32-48 AS0");
        assert_eq!(
            Vrp::new(p("192.0.2.0/24"), 8, Asn(1))
                .unwrap_err()
                .to_string(),
            "VRP 192.0.2.0/24: max length 8 is shorter than the prefix"
        );
        assert_eq!(
            Vrp::new(p("192.0.2.0/24"), 40, Asn(1))
                .unwrap_err()
                .to_string(),
            "VRP 192.0.2.0/24: max length 40 exceeds the address size"
        );
    }

    #[test]
    fn ordering_is_total() {
        let a = Vrp::new(p("10.0.0.0/8"), 8, Asn(2)).unwrap();
        let b = Vrp::new(p("10.0.0.0/8"), 9, Asn(1)).unwrap();
        let c = Vrp::new(p("10.0.0.0/8"), 9, Asn(2)).unwrap();
        let mut v = vec![c, b, a];
        v.sort();
        assert_eq!(v, vec![a, b, c]);
    }
}
