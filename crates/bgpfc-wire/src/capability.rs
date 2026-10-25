//! Capabilities carried in the OPEN Capabilities Optional Parameter.
//!
//! Implements: RFC 5492 §4 (TLV encoding), §5 (unknown capabilities are
//! ignored, never an error); RFC 4760 §8 (Multiprotocol Extensions, code 1);
//! RFC 2918 §2 (Route Refresh, code 2); RFC 8950 §4 (Extended Next Hop
//! Encoding, code 5); RFC 8654 §3 (Extended Message, code 6); RFC 6793 §3
//! (Four-octet AS, code 65); RFC 7911 §4 (ADD-PATH, code 69).

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
    /// Extended Next Hop Encoding (RFC 8950 §4): the NLRI families the
    /// speaker accepts with a next hop of another protocol.
    ExtendedNextHop(Vec<NextHopEncoding>),
    /// Extended Message, 65535-octet messages (RFC 8654 §3).
    ExtendedMessage,
    /// Four-octet AS number support, carrying the speaker's ASN (RFC 6793 §3).
    FourOctetAs(Asn),
    /// ADD-PATH: per `<AFI, SAFI>`, whether the speaker can receive and/or
    /// send multiple paths (RFC 7911 §4). A speaker lists all its families
    /// in one instance; the tuples of several instances add up.
    AddPath(Vec<AddPathTuple>),
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
            Capability::FourOctetAs(_) => 65,
            Capability::AddPath(_) => 69,
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
            Capability::FourOctetAs(asn) => {
                out.put_u8(4);
                out.put_u32(asn.0);
            }
            Capability::AddPath(tuples) => {
                // RFC 7911 §4: four octets per tuple, AFI (2), SAFI (1),
                // Send/Receive (1).
                let len = tuples.len() * AddPathTuple::WIRE_LEN;
                let len = u8::try_from(len).map_err(|_| EncodeError::TooLong {
                    what: "add-path capability",
                    len,
                    max: usize::from(u8::MAX),
                })?;
                out.put_u8(len);
                for t in tuples {
                    out.put_u16(t.family.afi.to_u16());
                    out.put_u8(t.family.safi.to_u8());
                    out.put_u8(t.mode.to_u8());
                }
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
            // RFC 6793 §3: length 4, the speaker's ASN.
            65 if len == 4 => Capability::FourOctetAs(Asn(v.u32().map_err(|_| malformed())?)),
            // RFC 7911 §4: whole four-octet tuples.
            // NOTE(interop): an empty value (no tuples) is accepted and means
            // nothing, as with RFC 8950 above; RFC 7911 §4 draws one or more
            // tuples but names no error for none.
            69 if usize::from(len) % AddPathTuple::WIRE_LEN == 0 => {
                let raw = v.rest_peek();
                let mut tuples = Vec::with_capacity(usize::from(len) / AddPathTuple::WIRE_LEN);
                let mut understood = true;
                while !v.is_empty() {
                    let afi = Afi::from_u16(v.u16().map_err(|_| malformed())?);
                    let safi = Safi::from_u8(v.u8().map_err(|_| malformed())?);
                    match AddPathMode::from_u8(v.u8().map_err(|_| malformed())?) {
                        Some(mode) => tuples.push(AddPathTuple {
                            family: AddressFamily { afi, safi },
                            mode,
                        }),
                        None => understood = false,
                    }
                }
                if understood {
                    Capability::AddPath(tuples)
                } else {
                    // RFC 7911 §4: "If any other value is received, then the
                    // capability SHOULD be treated as not understood and
                    // ignored": the whole capability, kept as unknown so
                    // that the OPEN round-trips.
                    Capability::Unknown {
                        code,
                        value: raw.to_vec(),
                    }
                }
            }
            1 | 2 | 5 | 6 | 65 | 69 => return Err(malformed()),
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

/// The Send/Receive field of an ADD-PATH tuple (RFC 7911 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddPathMode {
    /// 1: the sender is able to receive multiple paths from its peer.
    Receive,
    /// 2: the sender is able to send multiple paths to its peer.
    Send,
    /// 3: both.
    Both,
}

impl AddPathMode {
    /// From the wire value; `None` for anything but 1, 2 and 3, which
    /// RFC 7911 §4 has the receiver treat as not understood.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<AddPathMode> {
        match v {
            1 => Some(AddPathMode::Receive),
            2 => Some(AddPathMode::Send),
            3 => Some(AddPathMode::Both),
            _ => None,
        }
    }

    /// Wire value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            AddPathMode::Receive => 1,
            AddPathMode::Send => 2,
            AddPathMode::Both => 3,
        }
    }

    /// Whether the speaker can receive multiple paths (value 1 or 3).
    #[must_use]
    pub const fn receives(self) -> bool {
        matches!(self, AddPathMode::Receive | AddPathMode::Both)
    }

    /// Whether the speaker can send multiple paths (value 2 or 3).
    #[must_use]
    pub const fn sends(self) -> bool {
        matches!(self, AddPathMode::Send | AddPathMode::Both)
    }

    /// The mode that can do what `receive` and `send` say; `None` if
    /// neither.
    #[must_use]
    pub const fn of(receive: bool, send: bool) -> Option<AddPathMode> {
        match (receive, send) {
            (true, true) => Some(AddPathMode::Both),
            (true, false) => Some(AddPathMode::Receive),
            (false, true) => Some(AddPathMode::Send),
            (false, false) => None,
        }
    }
}

/// One `<AFI, SAFI, Send/Receive>` tuple of the ADD-PATH capability
/// (RFC 7911 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddPathTuple {
    /// The `<AFI, SAFI>` the tuple is about (as in RFC 4760).
    pub family: AddressFamily,
    /// What the speaker can do for it.
    pub mode: AddPathMode,
}

impl AddPathTuple {
    /// Octets per tuple on the wire (RFC 7911 §4).
    const WIRE_LEN: usize = 4;
}

/// What the ADD-PATH capabilities in `caps` say about `family`: the
/// speaker can receive and/or send multiple paths for it, as
/// `(receive, send)`. RFC 5492 §4 lets a capability be sent more than
/// once and RFC 7911 §4 asks a speaker to use a single instance, so the
/// tuples of all instances count, and a family listed twice has both
/// abilities either entry gives.
#[must_use]
pub fn add_path_abilities(caps: &[Capability], family: AddressFamily) -> (bool, bool) {
    caps.iter()
        .filter_map(|c| match c {
            Capability::AddPath(t) => Some(t),
            _ => None,
        })
        .flatten()
        .filter(|t| t.family == family)
        .fold((false, false), |(r, s), t| {
            (r || t.mode.receives(), s || t.mode.sends())
        })
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
    fn add_path_round_trips() {
        // RFC 7911 §4: AFI (2), SAFI (1), Send/Receive (1), per tuple.
        let tuple = |family, mode| AddPathTuple { family, mode };
        round_trip(
            &Capability::AddPath(vec![tuple(
                AddressFamily::IPV4_UNICAST,
                AddPathMode::Receive,
            )]),
            &[69, 4, 0, 1, 1, 1],
        );
        // One instance for several families (RFC 7911 §4 MUST).
        round_trip(
            &Capability::AddPath(vec![
                tuple(AddressFamily::IPV4_UNICAST, AddPathMode::Send),
                tuple(AddressFamily::IPV6_UNICAST, AddPathMode::Both),
            ]),
            &[69, 8, 0, 1, 1, 2, 0, 2, 1, 3],
        );
        // A family this implementation does not speak is still a tuple.
        round_trip(
            &Capability::AddPath(vec![tuple(
                AddressFamily {
                    afi: Afi::Unknown(25),
                    safi: Safi::Unknown(65),
                },
                AddPathMode::Both,
            )]),
            &[69, 4, 0, 25, 65, 3],
        );
        // An empty value is accepted (NOTE(interop) in `decode`).
        round_trip(&Capability::AddPath(vec![]), &[69, 0]);
        assert_eq!(Capability::AddPath(vec![]).code(), 69);
    }

    #[test]
    fn add_path_with_a_value_other_than_1_to_3_is_not_understood() {
        // RFC 7911 §4: the capability is treated as not understood and
        // ignored; it is kept so that the OPEN round-trips.
        for mode in [0u8, 4, 255] {
            let wire = [69, 8, 0, 1, 1, 3, 0, 2, 1, mode];
            round_trip(
                &Capability::Unknown {
                    code: 69,
                    value: wire[2..].to_vec(),
                },
                &wire,
            );
        }
    }

    #[test]
    fn add_path_length_must_be_whole_tuples() {
        for wire in [
            &[69, 3, 0, 1, 1][..],
            &[69, 5, 0, 1, 1, 1, 0][..],
            &[69, 4, 0, 1, 1][..], // truncated value
            &[69][..],
        ] {
            let e = Capability::decode(&mut Reader::new(wire)).unwrap_err();
            assert_eq!(
                e,
                DecodeError::open(OpenSubcode::Unspecific, vec![]),
                "{wire:?}"
            );
        }
    }

    #[test]
    fn add_path_limits_and_abilities() {
        let v4 = AddressFamily::IPV4_UNICAST;
        let v6 = AddressFamily::IPV6_UNICAST;
        // 63 tuples fill 252 of the 255 octets a capability may hold.
        let tuple = AddPathTuple {
            family: v4,
            mode: AddPathMode::Both,
        };
        let mut out = Vec::new();
        Capability::AddPath(vec![tuple; 63])
            .encode(&mut out)
            .unwrap();
        assert_eq!(out.len(), 2 + 252);
        assert_eq!(
            Capability::AddPath(vec![tuple; 64]).encode(&mut Vec::new()),
            Err(EncodeError::TooLong {
                what: "add-path capability",
                len: 256,
                max: 255,
            })
        );
        // Modes name what the sender can do.
        assert!(AddPathMode::Receive.receives() && !AddPathMode::Receive.sends());
        assert!(!AddPathMode::Send.receives() && AddPathMode::Send.sends());
        assert!(AddPathMode::Both.receives() && AddPathMode::Both.sends());
        assert_eq!(AddPathMode::of(true, true), Some(AddPathMode::Both));
        assert_eq!(AddPathMode::of(true, false), Some(AddPathMode::Receive));
        assert_eq!(AddPathMode::of(false, true), Some(AddPathMode::Send));
        assert_eq!(AddPathMode::of(false, false), None);
        for v in 0..=u8::MAX {
            assert_eq!(
                AddPathMode::from_u8(v).map(AddPathMode::to_u8),
                (1..=3).contains(&v).then_some(v)
            );
        }
        // RFC 5492 §4: several instances add up, and a family listed twice
        // has what either entry gives.
        let caps = [
            Capability::RouteRefresh,
            Capability::AddPath(vec![
                AddPathTuple {
                    family: v4,
                    mode: AddPathMode::Receive,
                },
                AddPathTuple {
                    family: v4,
                    mode: AddPathMode::Send,
                },
            ]),
            Capability::AddPath(vec![AddPathTuple {
                family: v6,
                mode: AddPathMode::Receive,
            }]),
        ];
        assert_eq!(add_path_abilities(&caps, v4), (true, true));
        assert_eq!(add_path_abilities(&caps, v6), (true, false));
        assert_eq!(
            add_path_abilities(&caps[..1], v4),
            (false, false),
            "no capability"
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
            &[1, 3, 0, 1, 0][..],             // MP with wrong length
            &[2, 1, 0][..],                   // route refresh with a value
            &[6, 4, 0, 0, 0, 0][..],          // extended message with a value
            &[5, 4, 0, 1, 0, 1][..],          // extended next hop: a partial triple
            &[5, 7, 0, 1, 0, 1, 0, 2, 0][..], // a triple and one octet more
            &[5, 6, 0, 1, 0, 1][..],          // extended next hop: truncated value
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
