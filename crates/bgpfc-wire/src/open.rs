//! The OPEN message.
//!
//! Implements: RFC 4271 §4.2 (format), §6.2 (error handling); RFC 5492 §4
//! (Capabilities Optional Parameter, type 2, possibly repeated); RFC 9072 §2
//! and §3 (extended optional parameters length); RFC 6793 §3 (`AS_TRANS` in
//! My Autonomous System); RFC 7607 §2 (AS 0 is Bad Peer AS); RFC 6286 §2.1
//! (BGP Identifier validity).

use crate::capability::Capability;
use crate::error::{DecodeError, EncodeError, OpenSubcode};
use crate::reader::{Reader, Truncated, WriteBytes as _};
use crate::types::{Asn, HoldTime, RouterId};

/// The only BGP version this implementation speaks (RFC 4271 §4.2).
pub const BGP_VERSION: u8 = 4;

/// Optional Parameter type of the Capabilities parameter (RFC 5492 §4).
const PARAM_CAPABILITIES: u8 = 2;

/// Optional Parameter type reserved as the extended-length marker
/// (RFC 9072 §2).
const PARAM_EXTENDED_LENGTH: u8 = 255;

/// An OPEN message body (everything after the header).
///
/// The optional parameters are flattened to the list of capabilities they
/// carry. RFC 5492 §4 asks senders to use one Capabilities parameter and
/// receivers to accept several; the set of capabilities is what matters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenMessage {
    /// My Autonomous System field as sent on the wire: the speaker's ASN if
    /// it fits two octets, otherwise `AS_TRANS` (RFC 6793 §3). See
    /// [`OpenMessage::asn`] for the real number.
    pub my_as: u16,
    /// Proposed Hold Time (RFC 4271 §4.2).
    pub hold_time: HoldTime,
    /// BGP Identifier of the sender.
    pub router_id: RouterId,
    /// Capabilities from every Capabilities Optional Parameter, in order.
    pub capabilities: Vec<Capability>,
}

impl OpenMessage {
    /// Build the OPEN a speaker with ASN `asn` sends.
    ///
    /// Sets My Autonomous System per RFC 6793 §3 and prepends the Four-octet
    /// AS capability carrying `asn`, which a NEW speaker always advertises,
    /// unless `capabilities` already has one.
    #[must_use]
    pub fn new(
        asn: Asn,
        hold_time: HoldTime,
        router_id: RouterId,
        mut capabilities: Vec<Capability>,
    ) -> Self {
        if !capabilities
            .iter()
            .any(|c| matches!(c, Capability::FourOctetAs(_)))
        {
            capabilities.insert(0, Capability::FourOctetAs(asn));
        }
        OpenMessage {
            my_as: asn.to_two_octet(),
            hold_time,
            router_id,
            capabilities,
        }
    }

    /// The sender's ASN: from the Four-octet AS capability when present
    /// (RFC 6793 §3), else the two-octet My Autonomous System field.
    #[must_use]
    pub fn asn(&self) -> Asn {
        self.capabilities
            .iter()
            .find_map(|c| match c {
                Capability::FourOctetAs(asn) => Some(*asn),
                _ => None,
            })
            .unwrap_or_else(|| Asn::from(self.my_as))
    }

    /// Whether the peer advertised `cap` (RFC 5492 §4 allows duplicates, so
    /// this is a set query).
    #[must_use]
    pub fn has(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Encode the body, choosing the RFC 4271 parameter encoding unless the
    /// parameters exceed 255 octets, in which case RFC 9072 §2 requires the
    /// extended encoding.
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if a capability cannot be encoded or the
    /// parameters exceed the 16-bit extended length.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        self.encode_with(false)
    }

    /// Encode the body; `force_extended` uses the RFC 9072 encoding even for
    /// short parameter lists (RFC 9072 §2 permits this by configuration).
    ///
    /// # Errors
    /// As [`OpenMessage::encode`].
    pub fn encode_with(&self, force_extended: bool) -> Result<Vec<u8>, EncodeError> {
        let caps = self.encode_capabilities()?;
        let extended = force_extended || caps.len() + 2 > usize::from(u8::MAX);
        let mut out = Vec::with_capacity(10 + 4 + caps.len());
        out.put_u8(BGP_VERSION);
        out.put_u16(self.my_as);
        out.put_u16(self.hold_time.secs());
        out.put_u32(self.router_id.to_u32());
        if caps.is_empty() {
            out.put_u8(0);
        } else if extended {
            // RFC 9072 §2: Non-Ext OP Len. SHOULD be 255, Non-Ext OP Type is
            // 255, then a two-octet length and two-octet parameter lengths.
            let param_len = u16::try_from(caps.len()).map_err(|_| EncodeError::TooLong {
                what: "capabilities",
                len: caps.len(),
                max: usize::from(u16::MAX),
            })?;
            let total = param_len.checked_add(3).ok_or(EncodeError::TooLong {
                what: "optional parameters",
                len: caps.len() + 3,
                max: usize::from(u16::MAX),
            })?;
            out.put_u8(PARAM_EXTENDED_LENGTH);
            out.put_u8(PARAM_EXTENDED_LENGTH);
            out.put_u16(total);
            out.put_u8(PARAM_CAPABILITIES);
            out.put_u16(param_len);
            out.put_bytes(&caps);
        } else {
            // RFC 4271 §4.2 with one Capabilities parameter (RFC 5492 §4).
            // `extended` is false, so caps.len() + 2 <= 255 and both casts fit.
            let param_len = u8::try_from(caps.len()).map_err(|_| unreachable_len())?;
            out.put_u8(param_len + 2);
            out.put_u8(PARAM_CAPABILITIES);
            out.put_u8(param_len);
            out.put_bytes(&caps);
        }
        Ok(out)
    }

    fn encode_capabilities(&self) -> Result<Vec<u8>, EncodeError> {
        let mut caps = Vec::new();
        for c in &self.capabilities {
            c.encode(&mut caps)?;
        }
        Ok(caps)
    }

    /// Decode an OPEN body (the octets after the 19-octet header, whose
    /// length the header decoder has already checked against the minimum).
    ///
    /// # Errors
    /// An OPEN Message Error per RFC 4271 §6.2: Unsupported Version Number
    /// (Data: the two-octet version 4), Bad Peer AS for AS 0 (RFC 7607 §2),
    /// Unacceptable Hold Time for one or two seconds, Bad BGP Identifier
    /// for zero (RFC 6286 §2.1), Unsupported Optional Parameter for an
    /// unknown parameter type, and Unspecific for a parameter that is
    /// recognised but malformed, including a parameter list that does not
    /// fit the body exactly.
    pub fn decode(body: &[u8]) -> Result<OpenMessage, DecodeError> {
        let mut r = Reader::new(body);
        let version = r.u8().map_err(malformed)?;
        if version != BGP_VERSION {
            // RFC 4271 §6.2: Data is the largest supported version below the
            // peer's bid, or the smallest supported version if the bid is
            // lower; with only version 4 supported both are 4.
            return Err(DecodeError::open(
                OpenSubcode::UnsupportedVersionNumber,
                u16::from(BGP_VERSION).to_be_bytes().to_vec(),
            ));
        }
        let my_as = r.u16().map_err(malformed)?;
        if my_as == 0 {
            // RFC 7607 §2: AS 0 in OPEN is Bad Peer AS. Other acceptability
            // checks (is this the configured remote AS?) belong to the FSM.
            return Err(DecodeError::open(OpenSubcode::BadPeerAs, Vec::new()));
        }
        let hold_time = HoldTime::new(r.u16().map_err(malformed)?)
            // RFC 4271 §6.2: one and two seconds MUST be rejected.
            .ok_or_else(|| DecodeError::open(OpenSubcode::UnacceptableHoldTime, Vec::new()))?;
        let router_id = RouterId::new(r.u32().map_err(malformed)?)
            // RFC 4271 §6.2 as updated by RFC 6286 §2.1: zero is invalid.
            .ok_or_else(|| DecodeError::open(OpenSubcode::BadBgpIdentifier, Vec::new()))?;
        let capabilities = decode_parameters(&mut r)?;
        if !r.is_empty() {
            // RFC 4271 §4.1: padding after the message is not allowed.
            return Err(malformed(Truncated));
        }
        Ok(OpenMessage {
            my_as,
            hold_time,
            router_id,
            capabilities,
        })
    }
}

/// Parse the Optional Parameters Length and the parameters it covers, in
/// either the RFC 4271 or the RFC 9072 encoding.
fn decode_parameters(r: &mut Reader<'_>) -> Result<Vec<Capability>, DecodeError> {
    let opt_len = r.u8().map_err(malformed)?;
    if opt_len == 0 {
        // RFC 4271 §4.2: zero means no optional parameters. RFC 9072 §2
        // forbids zero for the extended encoding, so this is final.
        return Ok(Vec::new());
    }
    // RFC 9072 §2: a non-zero one-octet length followed by type 255 selects
    // the extended encoding; the one-octet length is then ignored.
    let peek = Reader::new(r.rest_peek()).u8().map_err(malformed)?;
    let (mut params, extended) = if peek == PARAM_EXTENDED_LENGTH {
        let _non_ext_type = r.u8().map_err(malformed)?;
        let ext_len = r.u16().map_err(malformed)?;
        (r.sub(usize::from(ext_len)).map_err(malformed)?, true)
    } else {
        (r.sub(usize::from(opt_len)).map_err(malformed)?, false)
    };
    let mut caps = Vec::new();
    while !params.is_empty() {
        let kind = params.u8().map_err(malformed)?;
        let len = if extended {
            // RFC 9072 §2: two-octet Parameter Length.
            usize::from(params.u16().map_err(malformed)?)
        } else {
            usize::from(params.u8().map_err(malformed)?)
        };
        let mut value = params.sub(len).map_err(malformed)?;
        match kind {
            PARAM_CAPABILITIES => {
                // RFC 5492 §4: one or more triples; several Capabilities
                // parameters are accepted and merged.
                while !value.is_empty() {
                    caps.push(Capability::decode(&mut value)?);
                }
            }
            // RFC 9072 §3: type 255 anywhere but the Non-Ext OP Type position
            // is an unrecognised parameter, like any other unknown type
            // (RFC 4271 §6.2).
            _ => {
                return Err(DecodeError::open(
                    OpenSubcode::UnsupportedOptionalParameter,
                    Vec::new(),
                ));
            }
        }
    }
    Ok(caps)
}

/// RFC 4271 §6.2: a recognised but malformed parameter, and by extension a
/// body that ends inside a fixed field, is subcode 0 (Unspecific).
fn malformed(_: Truncated) -> DecodeError {
    DecodeError::open(OpenSubcode::Unspecific, Vec::new())
}

/// `encode_with` only takes the one-octet path when the length fits.
fn unreachable_len() -> EncodeError {
    EncodeError::TooLong {
        what: "capabilities",
        len: usize::from(u8::MAX) + 1,
        max: usize::from(u8::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AddressFamily;

    fn rid() -> RouterId {
        RouterId::new(0xc000_0201).unwrap() // 192.0.2.1
    }

    /// A bare OPEN as an old speaker sends it: AS 65000, hold 90, no params.
    const BARE: [u8; 10] = [4, 0xfd, 0xe8, 0, 90, 0xc0, 0, 2, 1, 0];

    #[test]
    fn bare_open_round_trips() {
        let m = OpenMessage::decode(&BARE).unwrap();
        assert_eq!(m.my_as, 65_000);
        assert_eq!(m.hold_time.secs(), 90);
        assert_eq!(m.router_id, rid());
        assert_eq!(m.capabilities, Vec::new());
        assert_eq!(m.asn(), Asn(65_000));
        assert_eq!(m.encode().unwrap(), BARE);
    }

    #[test]
    fn open_with_capabilities_round_trips() {
        // As captured from a modern speaker: MP IPv4+IPv6 unicast, route
        // refresh, extended message, 4-octet AS, all in one parameter.
        let wire = [
            4, 0xfd, 0xe8, 0, 90, 0xc0, 0, 2, 1, // fixed fields
            24, 2, 22, // opt len, type 2, param len
            65, 4, 0, 0, 0xfd, 0xe8, // 4-octet AS
            1, 4, 0, 1, 0, 1, // MP ipv4 unicast
            1, 4, 0, 2, 0, 1, // MP ipv6 unicast
            2, 0, // route refresh
            6, 0, // extended message
        ];
        let m = OpenMessage::new(
            Asn(65_000),
            HoldTime::new(90).unwrap(),
            rid(),
            vec![
                Capability::Multiprotocol(AddressFamily::IPV4_UNICAST),
                Capability::Multiprotocol(AddressFamily::IPV6_UNICAST),
                Capability::RouteRefresh,
                Capability::ExtendedMessage,
            ],
        );
        assert_eq!(m.encode().unwrap(), wire);
        assert_eq!(OpenMessage::decode(&wire).unwrap(), m);
        assert!(m.has(&Capability::RouteRefresh));
        assert!(!m.has(&Capability::Unknown {
            code: 64,
            value: vec![]
        }));
    }

    #[test]
    fn new_uses_as_trans_for_a_four_octet_asn() {
        // RFC 6793 §3.
        let m = OpenMessage::new(
            Asn(4_200_000_000),
            HoldTime::new(180).unwrap(),
            rid(),
            vec![],
        );
        assert_eq!(m.my_as, Asn::TRANS.to_two_octet());
        assert_eq!(
            m.capabilities,
            vec![Capability::FourOctetAs(Asn(4_200_000_000))]
        );
        assert_eq!(m.asn(), Asn(4_200_000_000));
        let wire = m.encode().unwrap();
        assert_eq!(&wire[1..3], &[0x5b, 0xa0]); // 23456
        assert_eq!(
            OpenMessage::decode(&wire).unwrap().asn(),
            Asn(4_200_000_000)
        );
    }

    #[test]
    fn several_capabilities_parameters_are_merged() {
        // RFC 5492 §4: MUST accept one capability per parameter.
        let wire = [
            4, 0xfd, 0xe8, 0, 90, 0xc0, 0, 2, 1, //
            8, 2, 2, 2, 0, 2, 2, 6, 0,
        ];
        let m = OpenMessage::decode(&wire).unwrap();
        assert_eq!(
            m.capabilities,
            vec![Capability::RouteRefresh, Capability::ExtendedMessage]
        );
        // Re-encoding normalises to one parameter (RFC 5492 §4 SHOULD).
        assert_eq!(
            m.encode().unwrap(),
            [4, 0xfd, 0xe8, 0, 90, 0xc0, 0, 2, 1, 6, 2, 4, 2, 0, 6, 0]
        );
    }

    #[test]
    fn extended_parameters_are_chosen_when_needed_and_accepted_always() {
        // RFC 9072 §2: forced extended encoding of a short list.
        let m = OpenMessage {
            my_as: 1,
            hold_time: HoldTime::new(0).unwrap(),
            router_id: rid(),
            capabilities: vec![Capability::RouteRefresh],
        };
        let wire = m.encode_with(true).unwrap();
        assert_eq!(
            wire,
            [4, 0, 1, 0, 0, 0xc0, 0, 2, 1, 255, 255, 0, 5, 2, 0, 2, 2, 0]
        );
        assert_eq!(OpenMessage::decode(&wire).unwrap(), m);
        // RFC 9072 §3: Non-Ext OP Len. other than 255 still selects extended.
        let mut odd = wire.clone();
        odd[9] = 7;
        assert_eq!(OpenMessage::decode(&odd).unwrap(), m);
        // Over 255 octets of capabilities: extended is automatic.
        let caps: Vec<Capability> = (0..60)
            .map(|i| Capability::Unknown {
                code: 128 + i,
                value: vec![i; 3],
            })
            .collect();
        let big = OpenMessage {
            capabilities: caps,
            ..m.clone()
        };
        let wire = big.encode().unwrap();
        assert_eq!(wire[9], 255);
        assert_eq!(wire[10], 255);
        assert_eq!(u16::from_be_bytes([wire[11], wire[12]]), 60 * 5 + 3);
        assert_eq!(OpenMessage::decode(&wire).unwrap(), big);
    }

    fn err(body: &[u8]) -> DecodeError {
        OpenMessage::decode(body).unwrap_err()
    }

    #[test]
    fn fixed_field_errors() {
        let mut b = BARE;
        b[0] = 5;
        assert_eq!(
            err(&b),
            DecodeError::open(OpenSubcode::UnsupportedVersionNumber, vec![0, 4])
        );
        let mut b = BARE;
        b[1] = 0;
        b[2] = 0;
        assert_eq!(err(&b), DecodeError::open(OpenSubcode::BadPeerAs, vec![]));
        for secs in [1u8, 2] {
            let mut b = BARE;
            b[3] = 0;
            b[4] = secs;
            assert_eq!(
                err(&b),
                DecodeError::open(OpenSubcode::UnacceptableHoldTime, vec![])
            );
        }
        let mut b = BARE;
        b[5..9].copy_from_slice(&[0; 4]);
        assert_eq!(
            err(&b),
            DecodeError::open(OpenSubcode::BadBgpIdentifier, vec![])
        );
    }

    #[test]
    fn parameter_errors() {
        let unspecific = DecodeError::open(OpenSubcode::Unspecific, vec![]);
        let unsupported = DecodeError::open(OpenSubcode::UnsupportedOptionalParameter, vec![]);
        let prefix = &BARE[..9];
        let with = |tail: &[u8]| [prefix, tail].concat();
        // Unknown parameter type 1 (Authentication, deprecated).
        assert_eq!(err(&with(&[3, 1, 1, 0])), unsupported);
        // Type 255 where a parameter type belongs (RFC 9072 §3).
        assert_eq!(err(&with(&[4, 2, 0, 255, 0])), unsupported);
        // Parameter list longer than the body.
        assert_eq!(err(&with(&[9, 2, 0])), unspecific);
        // Parameter length longer than the list.
        assert_eq!(err(&with(&[3, 2, 5, 0])), unspecific);
        // Trailing octets after the parameters.
        assert_eq!(err(&with(&[2, 2, 0, 0])), unspecific);
        // Truncated fixed fields.
        assert_eq!(err(&BARE[..5]), unspecific);
        // Extended length pointing past the body.
        assert_eq!(err(&with(&[255, 255, 0, 9, 2, 0, 2, 2, 0])), unspecific);
        // Malformed capability inside a recognised parameter.
        assert_eq!(err(&with(&[4, 2, 2, 65, 1])), unspecific);
    }
}
