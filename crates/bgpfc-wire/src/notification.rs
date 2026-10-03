//! The NOTIFICATION message.
//!
//! Implements: RFC 4271 §4.5 (format), §6.4 (errors in a NOTIFICATION are
//! logged, never answered), §6.5 (Hold Timer Expired), §6.7 (Cease);
//! RFC 4486 §4 (Cease subcode usage and the Maximum Prefixes data field);
//! RFC 9003 §2 and §4 (Shutdown Communication); RFC 8654 §5 (4096-octet
//! limit towards peers without Extended Message).

use std::fmt;

use crate::error::{CeaseSubcode, DecodeError, EncodeError, ErrorCode, FsmSubcode, subcode_name};
use crate::header::MAX_MESSAGE_LEN;
use crate::reader::{Reader, Truncated, WriteBytes as _};
use crate::types::{AddressFamily, Afi, Safi};

/// Largest Shutdown Communication (RFC 9003 §2: a one-octet length).
pub const MAX_SHUTDOWN_COMMUNICATION: usize = 255;

/// A NOTIFICATION message body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationMessage {
    /// Error Code.
    pub code: ErrorCode,
    /// Error Subcode. Its meaning depends on `code`; `0` where the code
    /// defines no subcodes (RFC 4271 §4.5).
    pub subcode: u8,
    /// Data field; its layout depends on code and subcode.
    pub data: Vec<u8>,
}

impl NotificationMessage {
    /// A Cease with an empty Data field (RFC 4271 §6.7, RFC 4486 §4).
    #[must_use]
    pub fn cease(subcode: CeaseSubcode) -> Self {
        NotificationMessage {
            code: ErrorCode::Cease,
            subcode: subcode as u8,
            data: Vec::new(),
        }
    }

    /// Cease / Maximum Number of Prefixes Reached with the optional Data
    /// field of RFC 4486 §4 Figure 1: AFI, SAFI and the upper bound.
    #[must_use]
    pub fn max_prefixes_reached(family: AddressFamily, limit: u32) -> Self {
        let mut data = Vec::with_capacity(7);
        data.put_u16(family.afi.to_u16());
        data.put_u8(family.safi.to_u8());
        data.put_u32(limit);
        NotificationMessage {
            code: ErrorCode::Cease,
            subcode: CeaseSubcode::MaxPrefixesReached as u8,
            data,
        }
    }

    /// Cease / Administrative Shutdown or Administrative Reset carrying a
    /// Shutdown Communication (RFC 9003 §2): a length octet and UTF-8.
    ///
    /// An empty `message` sends a zero length, which RFC 9003 §2 defines as
    /// "no Shutdown Communication".
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if `message` exceeds 255 octets, or
    /// [`EncodeError::NotShutdown`] if `subcode` is neither Administrative
    /// Shutdown nor Administrative Reset (RFC 9003 §2 allows only those).
    pub fn shutdown(subcode: CeaseSubcode, message: &str) -> Result<Self, EncodeError> {
        if !matches!(
            subcode,
            CeaseSubcode::AdministrativeShutdown | CeaseSubcode::AdministrativeReset
        ) {
            return Err(EncodeError::NotShutdown);
        }
        let len = u8::try_from(message.len()).map_err(|_| EncodeError::TooLong {
            what: "shutdown communication",
            len: message.len(),
            max: MAX_SHUTDOWN_COMMUNICATION,
        })?;
        let mut data = Vec::with_capacity(1 + message.len());
        data.put_u8(len);
        data.put_bytes(message.as_bytes());
        Ok(NotificationMessage {
            code: ErrorCode::Cease,
            subcode: subcode as u8,
            data,
        })
    }

    /// Hold Timer Expired (RFC 4271 §6.5); it has no subcodes.
    #[must_use]
    pub fn hold_timer_expired() -> Self {
        NotificationMessage {
            code: ErrorCode::HoldTimerExpired,
            subcode: 0,
            data: Vec::new(),
        }
    }

    /// Finite State Machine Error (RFC 4271 §6.6, RFC 6608 §4). For the
    /// "unexpected message" subcodes, `data` is the one-octet type of the
    /// unexpected message.
    #[must_use]
    pub fn fsm(subcode: FsmSubcode, data: Vec<u8>) -> Self {
        NotificationMessage {
            code: ErrorCode::Fsm,
            subcode: subcode as u8,
            data,
        }
    }

    /// The NOTIFICATION that reports a decode error.
    #[must_use]
    pub fn from_decode_error(e: DecodeError) -> Self {
        NotificationMessage {
            code: e.code,
            subcode: e.subcode,
            data: e.data,
        }
    }

    /// Encode the body: code, subcode, data (RFC 4271 §4.5).
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if the message would exceed 4096 octets when
    /// `extended` is false (RFC 8654 §5: a NOTIFICATION to a peer that did
    /// not advertise Extended Message must not exceed 4096), or 65535.
    pub fn encode(&self, extended: bool) -> Result<Vec<u8>, EncodeError> {
        let max = if extended {
            usize::from(u16::MAX)
        } else {
            usize::from(MAX_MESSAGE_LEN)
        };
        let total = self
            .data
            .len()
            .saturating_add(crate::header::HEADER_LEN + 2);
        if total > max {
            return Err(EncodeError::TooLong {
                what: "notification",
                len: total,
                max,
            });
        }
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.put_u8(self.code.to_u8());
        out.put_u8(self.subcode);
        out.put_bytes(&self.data);
        Ok(out)
    }

    /// Decode a body. Unknown codes and subcodes are kept as received:
    /// RFC 4271 §6.4 says an error in a NOTIFICATION cannot be reported back
    /// and is only logged, so nothing here is rejected except a body too
    /// short to hold code and subcode, which the header decoder's 21-octet
    /// minimum already rules out.
    ///
    /// # Errors
    /// [`Truncated`] if the body is shorter than two octets.
    pub fn decode(body: &[u8]) -> Result<Self, Truncated> {
        let mut r = Reader::new(body);
        let code = ErrorCode::from_u8(r.u8()?);
        let subcode = r.u8()?;
        Ok(NotificationMessage {
            code,
            subcode,
            data: r.rest().to_vec(),
        })
    }

    /// Whether the code/subcode pair is one this implementation knows
    /// (RFC 4271 §6.4 asks for unknown ones to be logged).
    #[must_use]
    pub fn is_recognised(&self) -> bool {
        subcode_name(self.code, self.subcode).is_some()
    }

    /// The Shutdown Communication of a Cease / Administrative Shutdown or
    /// Reset (RFC 9003 §2), if any.
    ///
    /// `None` when this is not such a Cease or the length octet is zero.
    /// `Some(Err(_))` when the field is malformed: the length does not match
    /// the data, or the text is not valid UTF-8, which RFC 9003 §2 forbids
    /// interpreting and §4 asks to log.
    #[must_use]
    pub fn shutdown_communication(&self) -> Option<Result<&str, ShutdownCommunicationError>> {
        if self.code != ErrorCode::Cease
            || !matches!(
                self.subcode,
                s if s == CeaseSubcode::AdministrativeShutdown as u8
                    || s == CeaseSubcode::AdministrativeReset as u8
            )
        {
            return None;
        }
        let (&len, text) = self.data.split_first()?;
        if len == 0 {
            return None;
        }
        if usize::from(len) != text.len() {
            return Some(Err(ShutdownCommunicationError::LengthMismatch {
                declared: len,
                actual: text.len(),
            }));
        }
        Some(std::str::from_utf8(text).map_err(|_| ShutdownCommunicationError::InvalidUtf8))
    }

    /// The `<AFI, SAFI>` and prefix limit of a Cease / Maximum Number of
    /// Prefixes Reached whose Data field is present (RFC 4486 §4 Figure 1).
    /// `None` when absent or not exactly seven octets.
    #[must_use]
    pub fn max_prefixes(&self) -> Option<(AddressFamily, u32)> {
        if self.code != ErrorCode::Cease || self.subcode != CeaseSubcode::MaxPrefixesReached as u8 {
            return None;
        }
        let mut r = Reader::new(&self.data);
        let afi = Afi::from_u16(r.u16().ok()?);
        let safi = Safi::from_u8(r.u8().ok()?);
        let limit = r.u32().ok()?;
        r.is_empty().then_some((AddressFamily { afi, safi }, limit))
    }
}

impl fmt::Display for NotificationMessage {
    /// `Cease/Administrative Shutdown` style, with raw numbers for unknown
    /// pairs, for log lines.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self.code {
            ErrorCode::MessageHeader => "Message Header Error",
            ErrorCode::Open => "OPEN Message Error",
            ErrorCode::Update => "UPDATE Message Error",
            ErrorCode::HoldTimerExpired => "Hold Timer Expired",
            ErrorCode::Fsm => "Finite State Machine Error",
            ErrorCode::Cease => "Cease",
            ErrorCode::RouteRefresh => "ROUTE-REFRESH Message Error",
            ErrorCode::Unknown(v) => return write!(f, "code {v}/subcode {}", self.subcode),
        };
        match subcode_name(self.code, self.subcode) {
            Some(name) if self.subcode == 0 && name == code => f.write_str(code),
            Some(name) => write!(f, "{code}/{name}"),
            None => write!(f, "{code}/subcode {}", self.subcode),
        }
    }
}

/// A Shutdown Communication that cannot be shown to the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownCommunicationError {
    /// The length octet disagrees with the octets that follow it.
    LengthMismatch {
        /// Value of the length octet.
        declared: u8,
        /// Octets actually present after it.
        actual: usize,
    },
    /// Not valid UTF-8 (RFC 9003 §2: MUST NOT be interpreted).
    InvalidUtf8,
}

impl fmt::Display for ShutdownCommunicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShutdownCommunicationError::LengthMismatch { declared, actual } => write!(
                f,
                "shutdown communication length {declared} but {actual} octet(s) present"
            ),
            ShutdownCommunicationError::InvalidUtf8 => {
                f.write_str("shutdown communication is not valid UTF-8")
            }
        }
    }
}

impl std::error::Error for ShutdownCommunicationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HeaderSubcode;

    fn round_trip(m: &NotificationMessage, wire: &[u8]) {
        assert_eq!(m.encode(false).unwrap(), wire, "{m}");
        assert_eq!(&NotificationMessage::decode(wire).unwrap(), m);
    }

    #[test]
    fn plain_notifications_round_trip() {
        round_trip(&NotificationMessage::hold_timer_expired(), &[4, 0]);
        round_trip(
            &NotificationMessage::cease(CeaseSubcode::PeerDeconfigured),
            &[6, 3],
        );
        round_trip(
            &NotificationMessage::fsm(FsmSubcode::UnexpectedInOpenSent, vec![2]),
            &[5, 1, 2],
        );
        round_trip(
            &NotificationMessage::from_decode_error(DecodeError::header(
                HeaderSubcode::BadMessageLength,
                vec![0x10, 0x01],
            )),
            &[1, 2, 0x10, 0x01],
        );
    }

    #[test]
    fn unknown_codes_are_kept_and_flagged() {
        // RFC 4271 §6.4: never answered, only logged.
        let m = NotificationMessage::decode(&[9, 4, 1, 2, 3]).unwrap();
        assert_eq!(m.code, ErrorCode::Unknown(9));
        assert!(!m.is_recognised());
        assert_eq!(m.to_string(), "code 9/subcode 4");
        let m = NotificationMessage::decode(&[6, 9]).unwrap();
        assert!(!m.is_recognised());
        assert_eq!(m.to_string(), "Cease/subcode 9");
        assert!(NotificationMessage::cease(CeaseSubcode::AdministrativeReset).is_recognised());
        assert_eq!(NotificationMessage::decode(&[6]), Err(Truncated));
    }

    #[test]
    fn display_names() {
        assert_eq!(
            NotificationMessage::hold_timer_expired().to_string(),
            "Hold Timer Expired"
        );
        assert_eq!(
            NotificationMessage::cease(CeaseSubcode::AdministrativeShutdown).to_string(),
            "Cease/Administrative Shutdown"
        );
        assert_eq!(
            NotificationMessage::fsm(FsmSubcode::Unspecified, vec![]).to_string(),
            "Finite State Machine Error/Unspecified Error"
        );
    }

    #[test]
    fn max_prefixes_data_field() {
        // RFC 4486 §4 Figure 1.
        let m = NotificationMessage::max_prefixes_reached(AddressFamily::IPV4_UNICAST, 10_000);
        round_trip(&m, &[6, 1, 0, 1, 1, 0, 0, 0x27, 0x10]);
        assert_eq!(
            m.max_prefixes(),
            Some((AddressFamily::IPV4_UNICAST, 10_000))
        );
        // Data is optional.
        assert_eq!(
            NotificationMessage::cease(CeaseSubcode::MaxPrefixesReached).max_prefixes(),
            None
        );
        // Wrong size is not interpreted.
        let short = NotificationMessage::decode(&[6, 1, 0, 1, 1]).unwrap();
        assert_eq!(short.max_prefixes(), None);
        assert_eq!(
            NotificationMessage::hold_timer_expired().max_prefixes(),
            None
        );
    }

    #[test]
    fn shutdown_communication_round_trips() {
        // RFC 9003 §2 / §3 example.
        let text = "[TICKET-1-1438367390] software upgrade; back in 2 hours";
        let m = NotificationMessage::shutdown(CeaseSubcode::AdministrativeShutdown, text).unwrap();
        let mut wire = vec![6, 2, u8::try_from(text.len()).unwrap()];
        wire.extend_from_slice(text.as_bytes());
        round_trip(&m, &wire);
        assert_eq!(m.shutdown_communication(), Some(Ok(text)));
        // Multibyte text: length counts octets, not characters.
        let ru = "Плановые работы";
        let m = NotificationMessage::shutdown(CeaseSubcode::AdministrativeReset, ru).unwrap();
        assert_eq!(m.data[0], u8::try_from(ru.len()).unwrap());
        assert_eq!(m.shutdown_communication(), Some(Ok(ru)));
        // Empty: zero length means no communication.
        let m = NotificationMessage::shutdown(CeaseSubcode::AdministrativeShutdown, "").unwrap();
        assert_eq!(m.data, vec![0]);
        assert_eq!(m.shutdown_communication(), None);
        // No data at all.
        assert_eq!(
            NotificationMessage::cease(CeaseSubcode::AdministrativeShutdown)
                .shutdown_communication(),
            None
        );
        // Not a shutdown subcode.
        assert_eq!(
            NotificationMessage::shutdown(CeaseSubcode::PeerDeconfigured, "x"),
            Err(EncodeError::NotShutdown)
        );
        let m = NotificationMessage::decode(&[6, 3, 1, b'x']).unwrap();
        assert_eq!(m.shutdown_communication(), None);
        // Too long.
        let long = "x".repeat(256);
        assert!(matches!(
            NotificationMessage::shutdown(CeaseSubcode::AdministrativeShutdown, &long),
            Err(EncodeError::TooLong {
                what: "shutdown communication",
                ..
            })
        ));
        assert!(
            NotificationMessage::shutdown(CeaseSubcode::AdministrativeShutdown, &long[1..]).is_ok()
        );
    }

    #[test]
    fn malformed_shutdown_communication_is_reported_not_interpreted() {
        // RFC 9003 §2: invalid UTF-8 MUST NOT be interpreted.
        let m = NotificationMessage::decode(&[6, 2, 2, 0xff, 0xfe]).unwrap();
        assert_eq!(
            m.shutdown_communication(),
            Some(Err(ShutdownCommunicationError::InvalidUtf8))
        );
        // Length octet disagrees with the data.
        let m = NotificationMessage::decode(&[6, 4, 5, b'a', b'b']).unwrap();
        assert_eq!(
            m.shutdown_communication(),
            Some(Err(ShutdownCommunicationError::LengthMismatch {
                declared: 5,
                actual: 2
            }))
        );
        let m = NotificationMessage::decode(&[6, 4, 1, b'a', b'b']).unwrap();
        assert!(matches!(m.shutdown_communication(), Some(Err(_))));
    }

    #[test]
    fn notification_size_limit_depends_on_extended_messages() {
        // RFC 8654 §5.
        let big = NotificationMessage {
            code: ErrorCode::Update,
            subcode: 1,
            data: vec![0; 4096 - 21 + 1],
        };
        assert!(matches!(
            big.encode(false),
            Err(EncodeError::TooLong {
                what: "notification",
                ..
            })
        ));
        assert!(big.encode(true).is_ok());
        let fits = NotificationMessage {
            data: vec![0; 4096 - 21],
            ..big.clone()
        };
        assert_eq!(fits.encode(false).unwrap().len(), 4096 - 19);
    }
}
