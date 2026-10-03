//! The fixed-size message header and message framing.
//!
//! Implements: RFC 4271 §4.1 (header format), §6.1 (header error handling),
//! RFC 2918 §3 (ROUTE-REFRESH type code), RFC 8654 §4 and §6 (65535-octet
//! messages when negotiated, except OPEN and KEEPALIVE).

use crate::error::{DecodeError, EncodeError, HeaderSubcode};
use crate::reader::{Reader, WriteBytes as _};

/// Length of the fixed header: 16 marker octets, 2 length octets, 1 type.
pub const HEADER_LEN: usize = 19;

/// The Marker field: all ones (RFC 4271 §4.1).
pub const MARKER: [u8; 16] = [0xff; 16];

/// Largest message without the Extended Message capability (RFC 4271 §4.1).
pub const MAX_MESSAGE_LEN: u16 = 4096;

/// Largest message with the Extended Message capability (RFC 8654 §2).
pub const MAX_EXTENDED_MESSAGE_LEN: u16 = u16::MAX;

/// Message type codes (RFC 4271 §4.1; RFC 2918 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// OPEN (§4.2).
    Open = 1,
    /// UPDATE (§4.3).
    Update = 2,
    /// NOTIFICATION (§4.5).
    Notification = 3,
    /// KEEPALIVE (§4.4).
    Keepalive = 4,
    /// ROUTE-REFRESH (RFC 2918 §3).
    RouteRefresh = 5,
}

impl MessageType {
    /// From the wire value; `None` for a type this implementation does not
    /// know, which RFC 4271 §6.1 treats as Bad Message Type.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(MessageType::Open),
            2 => Some(MessageType::Update),
            3 => Some(MessageType::Notification),
            4 => Some(MessageType::Keepalive),
            5 => Some(MessageType::RouteRefresh),
            _ => None,
        }
    }

    /// Smallest legal value of the Length field for this type, header
    /// included (RFC 4271 §6.1; RFC 2918 §3 for ROUTE-REFRESH).
    #[must_use]
    pub const fn min_len(self) -> u16 {
        match self {
            MessageType::Open => 29,
            MessageType::Update | MessageType::RouteRefresh => 23,
            MessageType::Notification => 21,
            MessageType::Keepalive => 19,
        }
    }

    /// Largest legal value of the Length field for this type.
    ///
    /// KEEPALIVE is exactly the header (RFC 4271 §6.1). RFC 8654 §4 raises
    /// the limit to 65535 for every type except OPEN and KEEPALIVE, and only
    /// once the local speaker has advertised the Extended Message capability
    /// (`extended`).
    #[must_use]
    pub const fn max_len(self, extended: bool) -> u16 {
        match self {
            MessageType::Keepalive => 19,
            MessageType::Open => MAX_MESSAGE_LEN,
            _ if extended => MAX_EXTENDED_MESSAGE_LEN,
            _ => MAX_MESSAGE_LEN,
        }
    }
}

/// A decoded, validated message header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Message type.
    pub kind: MessageType,
    /// Total message length including this header (RFC 4271 §4.1).
    pub length: u16,
}

impl Header {
    /// Decode and validate the first [`HEADER_LEN`] octets of a message.
    ///
    /// `extended` is whether this speaker advertised the Extended Message
    /// capability to the peer (RFC 8654 §5: the limit is raised only then).
    ///
    /// # Errors
    /// A Message Header Error with the subcode RFC 4271 §6.1 prescribes:
    /// Connection Not Synchronized for a bad marker, Bad Message Length for
    /// a length outside the bounds of the type (Data: the Length field), Bad
    /// Message Type for an unknown type (Data: the Type field). Fewer than
    /// [`HEADER_LEN`] octets is reported as Bad Message Length with the
    /// octet count as Data.
    pub fn decode(bytes: &[u8], extended: bool) -> Result<Header, DecodeError> {
        let mut r = Reader::new(bytes);
        // RFC 4271 §6.1: a marker that is not all ones is a synchronisation
        // error, checked before anything else.
        let marker: [u8; 16] = r.array().map_err(|_| short(bytes.len()))?;
        if marker != MARKER {
            return Err(DecodeError::header(
                HeaderSubcode::ConnectionNotSynchronized,
                Vec::new(),
            ));
        }
        let length = r.u16().map_err(|_| short(bytes.len()))?;
        let kind = r.u8().map_err(|_| short(bytes.len()))?;
        // RFC 4271 §6.1: Length below 19 is Bad Message Length regardless of
        // type; Data carries the erroneous Length field. The 65535 ceiling of
        // RFC 8654 §2 is the field's own range.
        let bad_len = || {
            DecodeError::header(
                HeaderSubcode::BadMessageLength,
                length.to_be_bytes().to_vec(),
            )
        };
        if usize::from(length) < HEADER_LEN {
            return Err(bad_len());
        }
        // RFC 4271 §6.1: unknown type is Bad Message Type; Data carries the
        // erroneous Type field.
        let kind = MessageType::from_u8(kind)
            .ok_or_else(|| DecodeError::header(HeaderSubcode::BadMessageType, vec![kind]))?;
        // RFC 4271 §6.1 per-type minimums; RFC 8654 §4/§6 per-type maximums.
        if length < kind.min_len() || length > kind.max_len(extended) {
            return Err(bad_len());
        }
        Ok(Header { kind, length })
    }

    /// Octets that follow the header.
    #[must_use]
    pub fn body_len(self) -> usize {
        usize::from(self.length) - HEADER_LEN
    }

    /// Serialise a header for a message whose body is `body_len` octets.
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if the total would not fit the 16-bit Length
    /// field. Callers that must respect the peer's 4096-octet limit check
    /// that themselves; this is the hard protocol ceiling.
    pub fn encode(kind: MessageType, body_len: usize) -> Result<[u8; HEADER_LEN], EncodeError> {
        let total = body_len
            .checked_add(HEADER_LEN)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(EncodeError::TooLong {
                what: "message",
                len: body_len.saturating_add(HEADER_LEN),
                max: usize::from(MAX_EXTENDED_MESSAGE_LEN),
            })?;
        let mut out = [0xff; HEADER_LEN];
        out[16..18].copy_from_slice(&total.to_be_bytes());
        out[18] = kind as u8;
        Ok(out)
    }
}

/// Header plus body in one buffer, ready to write to the socket.
///
/// # Errors
/// [`EncodeError::TooLong`] if header plus body exceed 65535 octets.
pub fn frame(kind: MessageType, body: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let header = Header::encode(kind, body.len())?;
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.put_bytes(&header);
    out.put_bytes(body);
    Ok(out)
}

/// Fewer than [`HEADER_LEN`] octets were offered; reported as Bad Message
/// Length with the count as Data, since no Length field was read.
fn short(have: usize) -> DecodeError {
    let have = u16::try_from(have).unwrap_or(u16::MAX);
    DecodeError::header(HeaderSubcode::BadMessageLength, have.to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    fn hdr(len: u16, kind: u8) -> Vec<u8> {
        let mut v = MARKER.to_vec();
        v.put_u16(len);
        v.put_u8(kind);
        v
    }

    #[test]
    fn keepalive_header_decodes() {
        let h = Header::decode(&hdr(19, 4), false).unwrap();
        assert_eq!(
            h,
            Header {
                kind: MessageType::Keepalive,
                length: 19
            }
        );
        assert_eq!(h.body_len(), 0);
    }

    #[test]
    fn bad_marker_is_connection_not_synchronized() {
        let mut b = hdr(19, 4);
        b[3] = 0xfe;
        let e = Header::decode(&b, false).unwrap_err();
        assert_eq!(
            e,
            DecodeError::header(HeaderSubcode::ConnectionNotSynchronized, vec![])
        );
        assert_eq!(e.code, ErrorCode::MessageHeader);
    }

    #[test]
    fn length_bounds_carry_the_length_field_as_data() {
        for (len, kind) in [
            (18, 4),
            (4097, 2),
            (20, 4),
            (28, 1),
            (22, 2),
            (20, 3),
            (22, 5),
        ] {
            let e = Header::decode(&hdr(len, kind), false).unwrap_err();
            assert_eq!(
                e,
                DecodeError::header(HeaderSubcode::BadMessageLength, len.to_be_bytes().to_vec()),
                "len {len} kind {kind}"
            );
        }
        for (len, kind) in [(29, 1), (23, 2), (21, 3), (19, 4), (23, 5), (4096, 2)] {
            assert!(
                Header::decode(&hdr(len, kind), false).is_ok(),
                "len {len} kind {kind}"
            );
        }
    }

    #[test]
    fn extended_messages_only_when_negotiated_and_never_for_open_or_keepalive() {
        // RFC 8654 §4: over 4096 without the capability is Bad Message Length.
        assert!(Header::decode(&hdr(4097, 2), false).is_err());
        assert!(Header::decode(&hdr(65535, 2), true).is_ok());
        assert!(Header::decode(&hdr(65535, 3), true).is_ok());
        assert!(Header::decode(&hdr(65535, 5), true).is_ok());
        // RFC 8654 §4: OPEN and KEEPALIVE keep the RFC 4271 limits.
        assert!(Header::decode(&hdr(4097, 1), true).is_err());
        assert!(Header::decode(&hdr(20, 4), true).is_err());
    }

    #[test]
    fn unknown_type_carries_the_type_as_data() {
        let e = Header::decode(&hdr(19, 6), false).unwrap_err();
        assert_eq!(
            e,
            DecodeError::header(HeaderSubcode::BadMessageType, vec![6])
        );
        // The marker is checked before the type (RFC 4271 §6.1 order).
        let mut b = hdr(19, 6);
        b[0] = 0;
        assert_eq!(Header::decode(&b, false).unwrap_err().subcode, 1);
    }

    #[test]
    fn short_input_is_bad_message_length() {
        let e = Header::decode(&hdr(19, 4)[..10], false).unwrap_err();
        assert_eq!(
            e,
            DecodeError::header(HeaderSubcode::BadMessageLength, vec![0, 10])
        );
    }

    #[test]
    fn encode_and_frame() {
        let h = Header::encode(MessageType::Open, 10).unwrap();
        assert_eq!(&h[..16], &MARKER);
        assert_eq!(&h[16..], &[0, 29, 1]);
        let f = frame(MessageType::Keepalive, &[]).unwrap();
        assert_eq!(f, hdr(19, 4));
        assert_eq!(
            Header::decode(&f, false).unwrap().kind,
            MessageType::Keepalive
        );
        let too_long = vec![0; usize::from(u16::MAX) - HEADER_LEN + 1];
        assert!(matches!(
            frame(MessageType::Update, &too_long),
            Err(EncodeError::TooLong {
                what: "message",
                ..
            })
        ));
        assert!(frame(MessageType::Update, &too_long[1..]).is_ok());
    }

    #[test]
    fn message_type_table() {
        for v in 1..=5u8 {
            assert_eq!(MessageType::from_u8(v).unwrap() as u8, v);
        }
        assert_eq!(MessageType::from_u8(0), None);
        assert_eq!(MessageType::from_u8(6), None);
    }
}
