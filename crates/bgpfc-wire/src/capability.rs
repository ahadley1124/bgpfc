//! Capabilities carried in the OPEN Capabilities Optional Parameter.
//!
//! Implements: RFC 5492 §4 (TLV encoding), §5 (unknown capabilities are
//! ignored, never an error); RFC 4760 §8 (Multiprotocol Extensions, code 1);
//! RFC 2918 §2 (Route Refresh, code 2); RFC 8950 §4 (Extended Next Hop
//! Encoding, code 5); RFC 8654 §3 (Extended Message, code 6); RFC 9234
//! §4.1 (BGP Role, code 9); RFC 6793 §3 (Four-octet AS, code 65).

use crate::error::{DecodeError, EncodeError, OpenSubcode};
use crate::reader::{Reader, WriteBytes as _};
use crate::role::Role;
use crate::types::{AddressFamily, Afi, Asn, Safi};

/// One capability TLV.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Multiprotocol Extensions for one `<AFI, SAFI>` (RFC 4760 §8).
    Multiprotocol(AddressFamily),
    /// Route Refresh (RFC 2918 §2).
    RouteRefresh,
    /// Extended Next Hop Encoding (RFC 8950 §4): the NLRI families the
    /// speaker accepts with a next hop of another protocol.
    ExtendedNextHop(Vec<NextHopEncoding>),
    /// Extended Message, 65535-octet messages (RFC 8654 §3).
    ExtendedMessage,
    /// BGP Role: the speaker's relationship to the other end of an eBGP
    /// session (RFC 9234 §4.1).
    Role(Role),
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
            Capability::ExtendedNextHop(_) => 5,
            Capability::ExtendedMessage => 6,
            Capability::Role(_) => 9,
            Capability::FourOctetAs(_) => 65,
            Capability::Unknown { code, .. } => *code,
        }
    }

    /// Append this capability as a `<Code, Length, Value>` triple
    /// (RFC 5492 §4).
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if the value exceeds the one-octet
    /// Capability Length field: an unknown capability's value over 255
    /// octets, or more than 42 Extended Next Hop Encoding triples.
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
            Capability::ExtendedNextHop(triples) => {
                // RFC 8950 §4: six octets per <NLRI AFI, NLRI SAFI,
                // Nexthop AFI> triple, each field two octets.
                let len = triples.len() * NextHopEncoding::WIRE_LEN;
                let len = u8::try_from(len).map_err(|_| EncodeError::TooLong {
                    what: "extended next hop capability",
                    len,
                    max: usize::from(u8::MAX),
                })?;
                out.put_u8(len);
                for t in triples {
                    out.put_u16(t.nlri_afi.to_u16());
                    out.put_u16(t.nlri_safi);
                    out.put_u16(t.next_hop_afi.to_u16());
                }
            }
            Capability::Role(role) => {
                // RFC 9234 §4.1: length 1, the Role Value.
                out.put_u8(1);
                out.put_u8(role.to_u8());
            }
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
            // RFC 8950 §4: whole six-octet triples.
            // NOTE(interop): an empty value (no triples) is accepted and
            // means nothing, as BIRD does; RFC 8950 §4 draws at least one
            // triple but names no error for none.
            5 if usize::from(len) % NextHopEncoding::WIRE_LEN == 0 => {
                let mut triples = Vec::with_capacity(usize::from(len) / NextHopEncoding::WIRE_LEN);
                while !v.is_empty() {
                    triples.push(NextHopEncoding {
                        nlri_afi: Afi::from_u16(v.u16().map_err(|_| malformed())?),
                        nlri_safi: v.u16().map_err(|_| malformed())?,
                        next_hop_afi: Afi::from_u16(v.u16().map_err(|_| malformed())?),
                    });
                }
                Capability::ExtendedNextHop(triples)
            }
            // RFC 8654 §3: length 0.
            6 if len == 0 => Capability::ExtendedMessage,
            // RFC 9234 §4.1: length 1, the Role Value. An unassigned value is
            // kept: RFC 9234 §4.2 has it correspond to no Role, which is a
            // Role Mismatch for the FSM to answer, not a malformed
            // capability.
            9 if len == 1 => Capability::Role(Role::from_u8(v.u8().map_err(|_| malformed())?)),
            // RFC 6793 §3: length 4, the speaker's ASN.
            65 if len == 4 => Capability::FourOctetAs(Asn(v.u32().map_err(|_| malformed())?)),
            1 | 2 | 5 | 6 | 9 | 65 => return Err(malformed()),
            // RFC 5492 §5: capabilities not understood MUST be ignored.
            _ => Capability::Unknown {
                code,
                value: v.rest().to_vec(),
            },
        };
        Ok(cap)
    }
}

/// One `<NLRI AFI, NLRI SAFI, Nexthop AFI>` triple of the Extended Next Hop
/// Encoding capability (RFC 8950 §4): NLRI of that family may be advertised
/// with a next hop of the Nexthop AFI's protocol, the protocol told apart
/// by the next hop's length (RFC 8950 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NextHopEncoding {
    /// NLRI AFI.
    pub nlri_afi: Afi,
    /// NLRI SAFI, two octets here (RFC 8950 §4) though one everywhere else
    /// (RFC 4760 §3). Kept as received so that the capability round-trips;
    /// a value above 255 names no family.
    pub nlri_safi: u16,
    /// Nexthop AFI: the protocol the next hop may belong to.
    pub next_hop_afi: Afi,
}

impl NextHopEncoding {
    /// `<1, 1, 2>`: IPv4 unicast NLRI with an IPv6 next hop (RFC 8950
    /// §6.1), the one triple this implementation advertises.
    pub const IPV4_UNICAST_VIA_IPV6: NextHopEncoding = NextHopEncoding {
        nlri_afi: Afi::Ipv4,
        nlri_safi: 1,
        next_hop_afi: Afi::Ipv6,
    };

    /// Octets per triple on the wire (RFC 8950 §4).
    const WIRE_LEN: usize = 6;

    /// The NLRI `<AFI, SAFI>`, or `None` when the SAFI does not fit the
    /// one-octet SAFI space (RFC 4760 §3).
    #[must_use]
    pub fn family(&self) -> Option<AddressFamily> {
        let safi = u8::try_from(self.nlri_safi).ok()?;
        Some(AddressFamily {
            afi: self.nlri_afi,
            safi: Safi::from_u8(safi),
        })
    }
}

/// Every triple of every Extended Next Hop Encoding capability in `caps`:
/// RFC 5492 §4 lets a speaker send a capability more than once, and the
/// triples of all instances count.
pub fn next_hop_encodings(caps: &[Capability]) -> impl Iterator<Item = NextHopEncoding> + '_ {
    caps.iter()
        .filter_map(|c| match c {
            Capability::ExtendedNextHop(t) => Some(t.iter().copied()),
            _ => None,
        })
        .flatten()
}

/// The Role Value of every BGP Role capability in `caps`, in order: RFC 9234
/// §4.2 lets a speaker receive several, and acts on them together.
pub fn roles(caps: &[Capability]) -> impl Iterator<Item = Role> + '_ {
    caps.iter().filter_map(|c| match c {
        Capability::Role(r) => Some(*r),
        _ => None,
    })
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
    fn role_capability_follows_rfc_9234() {
        // RFC 9234 §4.1: code 9, length 1, then the Role Value of Table 1.
        for (role, value) in [
            (Role::Provider, 0),
            (Role::RouteServer, 1),
            (Role::RouteServerClient, 2),
            (Role::Customer, 3),
            (Role::Peer, 4),
        ] {
            round_trip(&Capability::Role(role), &[9, 1, value]);
        }
        // Values 5 to 255 are unassigned: kept, so that the capability
        // round-trips and the FSM can reject the pairing (§4.2).
        round_trip(&Capability::Role(Role::Unknown(5)), &[9, 1, 5]);
        round_trip(&Capability::Role(Role::Unknown(255)), &[9, 1, 255]);
        assert_eq!(Capability::Role(Role::Peer).code(), 9);
    }

    #[test]
    fn roles_lists_every_role_capability() {
        // RFC 9234 §4.2: several may arrive, each one counts.
        let caps = [
            Capability::RouteRefresh,
            Capability::Role(Role::Customer),
            Capability::ExtendedMessage,
            Capability::Role(Role::Peer),
        ];
        assert_eq!(
            roles(&caps).collect::<Vec<_>>(),
            [Role::Customer, Role::Peer]
        );
        assert_eq!(roles(&caps[..1]).count(), 0);
    }

    #[test]
    fn extended_next_hop_round_trips() {
        // RFC 8950 §6.1: <NLRI AFI=1, NLRI SAFI=1, Nexthop AFI=2>, two
        // octets per field.
        round_trip(
            &Capability::ExtendedNextHop(vec![NextHopEncoding::IPV4_UNICAST_VIA_IPV6]),
            &[5, 6, 0, 1, 0, 1, 0, 2],
        );
        // RFC 8950 §6.2 and §6.3: VPN-IPv4 unicast and multicast as well.
        let vpn = |safi| NextHopEncoding {
            nlri_safi: safi,
            ..NextHopEncoding::IPV4_UNICAST_VIA_IPV6
        };
        round_trip(
            &Capability::ExtendedNextHop(vec![
                NextHopEncoding::IPV4_UNICAST_VIA_IPV6,
                vpn(128),
                vpn(129),
            ]),
            &[
                5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 128, 0, 2, 0, 1, 0, 129, 0, 2,
            ],
        );
        // RFC 8950 §4 specifies no other triples. They are kept, so the
        // capability round-trips, and match nothing.
        let odd = NextHopEncoding {
            nlri_afi: Afi::Unknown(25),
            nlri_safi: 0x1234,
            next_hop_afi: Afi::Ipv4,
        };
        round_trip(
            &Capability::ExtendedNextHop(vec![odd]),
            &[5, 6, 0, 25, 0x12, 0x34, 0, 1],
        );
        assert_eq!(odd.family(), None);
        assert_eq!(
            NextHopEncoding::IPV4_UNICAST_VIA_IPV6.family(),
            Some(AddressFamily::IPV4_UNICAST)
        );
        assert_eq!(vpn(128).family().map(|f| f.safi), Some(Safi::Unknown(128)));
        // An empty value is accepted (NOTE(interop) in `decode`).
        round_trip(&Capability::ExtendedNextHop(vec![]), &[5, 0]);
    }

    #[test]
    fn extended_next_hop_limits_and_merging() {
        // 42 triples fill 252 of the 255 octets a capability may hold.
        let fits = Capability::ExtendedNextHop(vec![NextHopEncoding::IPV4_UNICAST_VIA_IPV6; 42]);
        let mut out = Vec::new();
        fits.encode(&mut out).unwrap();
        assert_eq!(out.len(), 2 + 252);
        let over = Capability::ExtendedNextHop(vec![NextHopEncoding::IPV4_UNICAST_VIA_IPV6; 43]);
        assert_eq!(
            over.encode(&mut Vec::new()),
            Err(EncodeError::TooLong {
                what: "extended next hop capability",
                len: 258,
                max: 255,
            })
        );
        // RFC 5492 §4: several instances; their triples add up.
        let caps = [
            Capability::RouteRefresh,
            Capability::ExtendedNextHop(vec![NextHopEncoding::IPV4_UNICAST_VIA_IPV6]),
            Capability::ExtendedNextHop(vec![NextHopEncoding {
                nlri_safi: 2,
                ..NextHopEncoding::IPV4_UNICAST_VIA_IPV6
            }]),
        ];
        assert_eq!(
            next_hop_encodings(&caps)
                .map(|t| t.nlri_safi)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(next_hop_encodings(&caps[..1]).count(), 0);
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
            &[1, 3, 0, 1, 0][..],             // MP with wrong length
            &[2, 1, 0][..],                   // route refresh with a value
            &[6, 4, 0, 0, 0, 0][..],          // extended message with a value
            &[5, 4, 0, 1, 0, 1][..],          // extended next hop: a partial triple
            &[5, 7, 0, 1, 0, 1, 0, 2, 0][..], // a triple and one octet more
            &[5, 6, 0, 1, 0, 1][..],          // extended next hop: truncated value
            &[9, 0][..],                      // role with no Role Value
            &[9, 2, 0, 3][..],                // role with two octets
            &[9, 1][..],                      // role truncated
            &[65, 2, 0xfd, 0xe8][..],         // 4-octet AS with two octets
            &[65, 4, 0, 0][..],               // truncated value
            &[1][..],                         // truncated length
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
