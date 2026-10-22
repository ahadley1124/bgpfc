//! Capabilities carried in the OPEN Capabilities Optional Parameter.
//!
//! Implements: RFC 5492 §4 (TLV encoding), §5 (unknown capabilities are
//! ignored, never an error); RFC 4760 §8 (Multiprotocol Extensions, code 1);
//! RFC 2918 §2 (Route Refresh, code 2); RFC 8654 §3 (Extended Message,
//! code 6); RFC 6793 §3 (Four-octet AS, code 65).

use crate::error::{DecodeError, EncodeError, OpenSubcode};
use crate::reader::{Reader, WriteBytes as _};
use crate::types::{AddressFamily, Afi, Asn, Safi};

/// One capability TLV.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Multiprotocol Extensions for one `<AFI, SAFI>` (RFC 4760 §8).
    Multiprotocol(AddressFamily),
    /// Route Refresh (RFC 2918 §2).
    RouteRefresh,
    /// Extended Message, 65535-octet messages (RFC 8654 §3).
    ExtendedMessage,
    /// Four-octet AS number support, carrying the speaker's ASN (RFC 6793 §3).
    FourOctetAs(Asn),
    /// A capability this implementation does not understand. Kept so that
    /// the OPEN round-trips; the FSM ignores it (RFC 5492 §5).
    Unknown {
        /// Capability Code.
        code: u8,
        /// Capability Value, at most 255 octets.
        value: Vec<u8>,
    },
}

impl Capability {
    /// Capability Code assigned by IANA.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Capability::Multiprotocol(_) => 1,
            Capability::RouteRefresh => 2,
            Capability::ExtendedMessage => 6,
            Capability::FourOctetAs(_) => 65,
            Capability::Unknown { code, .. } => *code,
        }
    }

    /// Append this capability as a `<Code, Length, Value>` triple
    /// (RFC 5492 §4).
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if an unknown capability's value exceeds the
    /// one-octet Capability Length field.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.put_u8(self.code());
        match self {
            Capability::Multiprotocol(af) => {
                out.put_u8(4);
                // RFC 4760 §8: AFI (2), Reserved (1, zero), SAFI (1).
                out.put_u16(af.afi.to_u16());
                out.put_u8(0);
                out.put_u8(af.safi.to_u8());
            }
            Capability::RouteRefresh | Capability::ExtendedMessage => out.put_u8(0),
            Capability::FourOctetAs(asn) => {
                out.put_u8(4);
                out.put_u32(asn.0);
            }
            Capability::Unknown { value, .. } => {
                let len = u8::try_from(value.len()).map_err(|_| EncodeError::TooLong {
                    what: "capability value",
                    len: value.len(),
                    max: usize::from(u8::MAX),
                })?;
                out.put_u8(len);
                out.put_bytes(value);
            }
        }
        Ok(())
    }

    /// Decode one triple from `r`.
    ///
    /// # Errors
    /// OPEN Message Error, subcode Unspecific: the Capabilities parameter
    /// is recognised but malformed (RFC 4271 §6.2), because the triple is
    /// truncated or a known code carries the wrong length.
    pub fn decode(r: &mut Reader<'_>) -> Result<Capability, DecodeError> {
        let code = r.u8().map_err(|_| malformed())?;
        let len = r.u8().map_err(|_| malformed())?;
        let mut v = r.sub(usize::from(len)).map_err(|_| malformed())?;
        let cap = match code {
            // RFC 4760 §8: length 4; the reserved octet is ignored on receipt.
            1 if len == 4 => {
                let afi = Afi::from_u16(v.u16().map_err(|_| malformed())?);
                let _reserved = v.u8().map_err(|_| malformed())?;
                let safi = Safi::from_u8(v.u8().map_err(|_| malformed())?);
                Capability::Multiprotocol(AddressFamily { afi, safi })
            }
            // RFC 2918 §2: length 0.
            2 if len == 0 => Capability::RouteRefresh,
            // RFC 8654 §3: length 0.
            6 if len == 0 => Capability::ExtendedMessage,
            // RFC 6793 §3: length 4, the speaker's ASN.
            65 if len == 4 => Capability::FourOctetAs(Asn(v.u32().map_err(|_| malformed())?)),
            1 | 2 | 6 | 65 => return Err(malformed()),
            // RFC 5492 §5: capabilities not understood MUST be ignored.
            _ => Capability::Unknown {
                code,
                value: v.rest().to_vec(),
            },
        };
        Ok(cap)
    }
}

/// RFC 4271 §6.2: a recognised but malformed optional parameter is reported
/// with subcode 0 (Unspecific).
fn malformed() -> DecodeError {
    DecodeError::open(OpenSubcode::Unspecific, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(cap: &Capability, wire: &[u8]) {
        let mut out = Vec::new();
        cap.encode(&mut out).unwrap();
        assert_eq!(out, wire, "encode {cap:?}");
        let mut r = Reader::new(wire);
        assert_eq!(&Capability::decode(&mut r).unwrap(), cap);
        assert!(r.is_empty());
    }

    #[test]
    fn known_capabilities_round_trip() {
        round_trip(
            &Capability::Multiprotocol(AddressFamily::IPV4_UNICAST),
            &[1, 4, 0, 1, 0, 1],
        );
        round_trip(
            &Capability::Multiprotocol(AddressFamily::IPV6_UNICAST),
            &[1, 4, 0, 2, 0, 1],
        );
        round_trip(&Capability::RouteRefresh, &[2, 0]);
        round_trip(&Capability::ExtendedMessage, &[6, 0]);
        round_trip(
            &Capability::FourOctetAs(Asn(65_000)),
            &[65, 4, 0, 0, 0xfd, 0xe8],
        );
        round_trip(
            &Capability::FourOctetAs(Asn(4_200_000_000)),
            &[65, 4, 0xfa, 0x56, 0xea, 0x00],
        );
    }

    #[test]
    fn multiprotocol_ignores_the_reserved_octet() {
        // RFC 4760 §8: Res. SHOULD be zero and is ignored by the receiver.
        let mut r = Reader::new(&[1, 4, 0, 1, 0xff, 1]);
        assert_eq!(
            Capability::decode(&mut r).unwrap(),
            Capability::Multiprotocol(AddressFamily::IPV4_UNICAST)
        );
    }

    #[test]
    fn unknown_capabilities_are_kept_not_rejected() {
        // Graceful Restart (64) with a two-octet value, and an empty one.
        round_trip(
            &Capability::Unknown {
                code: 64,
                value: vec![0x40, 0x78],
            },
            &[64, 2, 0x40, 0x78],
        );
        round_trip(
            &Capability::Unknown {
                code: 200,
                value: vec![],
            },
            &[200, 0],
        );
        let big = Capability::Unknown {
            code: 200,
            value: vec![0; 256],
        };
        assert!(matches!(
            big.encode(&mut Vec::new()),
            Err(EncodeError::TooLong {
                what: "capability value",
                ..
            })
        ));
    }

    #[test]
    fn malformed_known_capabilities_are_unspecific_open_errors() {
        for wire in [
            &[1, 3, 0, 1, 0][..],     // MP with wrong length
            &[2, 1, 0][..],           // route refresh with a value
            &[6, 4, 0, 0, 0, 0][..],  // extended message with a value
            &[65, 2, 0xfd, 0xe8][..], // 4-octet AS with two octets
            &[65, 4, 0, 0][..],       // truncated value
            &[1][..],                 // truncated length
            &[][..],
        ] {
            let e = Capability::decode(&mut Reader::new(wire)).unwrap_err();
            assert_eq!(
                e,
                DecodeError::open(OpenSubcode::Unspecific, vec![]),
                "{wire:?}"
            );
        }
    }
}
