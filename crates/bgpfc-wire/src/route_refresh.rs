//! The ROUTE-REFRESH message.
//!
//! Implements: RFC 2918 §3 (format: one `<AFI, Res, SAFI>`). The §4 rules
//! on when to send one and when to ignore one belong to the RIB.

use crate::error::{DecodeError, HeaderSubcode};
use crate::header::HEADER_LEN;
use crate::reader::{Reader, WriteBytes as _};
use crate::types::{AddressFamily, Afi, Safi};

/// Length of the ROUTE-REFRESH body (RFC 2918 §3).
pub const ROUTE_REFRESH_LEN: usize = 4;

/// A ROUTE-REFRESH message body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    /// The `<AFI, SAFI>` whose Adj-RIB-Out the sender wants re-advertised.
    pub family: AddressFamily,
}

impl RouteRefreshMessage {
    /// Encode the body: AFI, a zero reserved octet, SAFI (RFC 2918 §3).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROUTE_REFRESH_LEN);
        out.put_u16(self.family.afi.to_u16());
        out.put_u8(0);
        out.put_u8(self.family.safi.to_u8());
        out
    }

    /// Decode a body. The reserved octet is ignored (RFC 2918 §3).
    ///
    /// # Errors
    /// Bad Message Length (Data: the message's Length field) when the body
    /// is not exactly four octets. RFC 2918 fixes the size and RFC 4271
    /// §4.1 lets a type constrain its Length; RFC 2918 names no error code
    /// of its own.
    // NOTE(interop): RFC 7313 §5 defines ROUTE-REFRESH Message Error /
    // Invalid Message Length for this case; switch to it when RFC 7313 is
    // implemented. BIRD and FRR send Bad Message Length today.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        if body.len() != ROUTE_REFRESH_LEN {
            let total = u16::try_from(body.len() + HEADER_LEN).unwrap_or(u16::MAX);
            return Err(DecodeError::header(
                HeaderSubcode::BadMessageLength,
                total.to_be_bytes().to_vec(),
            ));
        }
        let mut r = Reader::new(body);
        // Exactly four octets are present, so these reads cannot fail.
        let afi = Afi::from_u16(r.u16().unwrap_or_default());
        let _reserved = r.u8();
        let safi = Safi::from_u8(r.u8().unwrap_or_default());
        Ok(RouteRefreshMessage {
            family: AddressFamily { afi, safi },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_refresh_round_trips() {
        let m = RouteRefreshMessage {
            family: AddressFamily::IPV6_UNICAST,
        };
        assert_eq!(m.encode(), [0, 2, 0, 1]);
        assert_eq!(RouteRefreshMessage::decode(&[0, 2, 0, 1]).unwrap(), m);
        // RFC 2918 §3: reserved octet ignored by the receiver.
        assert_eq!(RouteRefreshMessage::decode(&[0, 2, 0xff, 1]).unwrap(), m);
        let odd = RouteRefreshMessage::decode(&[0x40, 0, 0, 0x80]).unwrap();
        assert_eq!(odd.family.afi, Afi::Unknown(0x4000));
        assert_eq!(odd.family.safi, Safi::Unknown(0x80));
    }

    #[test]
    fn wrong_length_is_bad_message_length() {
        for body in [&[][..], &[0, 1, 0][..], &[0, 1, 0, 1, 0][..]] {
            let e = RouteRefreshMessage::decode(body).unwrap_err();
            let total = u16::try_from(body.len() + HEADER_LEN).unwrap();
            assert_eq!(
                e,
                DecodeError::header(
                    HeaderSubcode::BadMessageLength,
                    total.to_be_bytes().to_vec()
                )
            );
        }
    }
}
