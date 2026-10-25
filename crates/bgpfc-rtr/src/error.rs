//! Error codes of the Error Report PDU, and the crate's error type.
//!
//! Implements: RFC 8210 §12 (error codes 0–8, which are fatal), §5.11
//! (no Error Report about an Error Report), §7 (unsupported and
//! unexpected versions);
//! RFC 6810 §10 (error codes 0–7).

use std::fmt;

use crate::pdu::{PduType, Version};

/// The Error Code of an Error Report PDU (RFC 8210 §12; RFC 6810 §10
/// defines 0–7 and RFC 8210 adds 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// 0: "The receiver believes the received PDU to be corrupt in a
    /// manner not specified by another error code."
    CorruptData,
    /// 1: "some kind of internal error unrelated to protocol operation".
    InternalError,
    /// 2: the cache "has no useful data available at this time". The only
    /// code that is not fatal.
    NoDataAvailable,
    /// 3: "The cache server believes the client's request to be invalid."
    InvalidRequest,
    /// 4: "The Protocol Version is not known by the receiver of the PDU."
    UnsupportedProtocolVersion,
    /// 5: "The PDU Type is not known by the receiver of the PDU."
    UnsupportedPduType,
    /// 6: a withdrawal (Flag=0) of a record the receiver does not hold.
    WithdrawalOfUnknownRecord,
    /// 7: an announcement (Flag=1) of a record that is already active.
    DuplicateAnnouncementReceived,
    /// 8: a Protocol Version that differs from the negotiated one.
    UnexpectedProtocolVersion,
    /// A code not in the registry. Holds a value no other variant names.
    Unknown(u16),
}

impl ErrorCode {
    /// From the 16-bit Error Code field.
    #[must_use]
    pub const fn from_u16(v: u16) -> ErrorCode {
        match v {
            0 => ErrorCode::CorruptData,
            1 => ErrorCode::InternalError,
            2 => ErrorCode::NoDataAvailable,
            3 => ErrorCode::InvalidRequest,
            4 => ErrorCode::UnsupportedProtocolVersion,
            5 => ErrorCode::UnsupportedPduType,
            6 => ErrorCode::WithdrawalOfUnknownRecord,
            7 => ErrorCode::DuplicateAnnouncementReceived,
            8 => ErrorCode::UnexpectedProtocolVersion,
            other => ErrorCode::Unknown(other),
        }
    }

    /// The value of the Error Code field.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            ErrorCode::CorruptData => 0,
            ErrorCode::InternalError => 1,
            ErrorCode::NoDataAvailable => 2,
            ErrorCode::InvalidRequest => 3,
            ErrorCode::UnsupportedProtocolVersion => 4,
            ErrorCode::UnsupportedPduType => 5,
            ErrorCode::WithdrawalOfUnknownRecord => 6,
            ErrorCode::DuplicateAnnouncementReceived => 7,
            ErrorCode::UnexpectedProtocolVersion => 8,
            ErrorCode::Unknown(v) => v,
        }
    }

    /// Whether the error ends the session. RFC 8210 §12 marks every code
    /// but No Data Available "(fatal)", and "Errors which are considered
    /// fatal MUST cause the session to be dropped." A code outside the
    /// registry counts as fatal: nothing says it is safe to carry on.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        !matches!(self, ErrorCode::NoDataAvailable)
    }

    /// The name RFC 8210 §12 gives the code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ErrorCode::CorruptData => "Corrupt Data",
            ErrorCode::InternalError => "Internal Error",
            ErrorCode::NoDataAvailable => "No Data Available",
            ErrorCode::InvalidRequest => "Invalid Request",
            ErrorCode::UnsupportedProtocolVersion => "Unsupported Protocol Version",
            ErrorCode::UnsupportedPduType => "Unsupported PDU Type",
            ErrorCode::WithdrawalOfUnknownRecord => "Withdrawal of Unknown Record",
            ErrorCode::DuplicateAnnouncementReceived => "Duplicate Announcement Received",
            ErrorCode::UnexpectedProtocolVersion => "Unexpected Protocol Version",
            ErrorCode::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for ErrorCode {
    /// `Corrupt Data (0)`; an unregistered code prints as `Unknown (42)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.to_u16())
    }
}

/// Why a PDU, or a stream of them, could not be accepted.
///
/// Every variant maps to the Error Code to report ([`RtrError::code`]),
/// and [`RtrError::may_report`] says whether an Error Report may be sent
/// at all. All of them are fatal (RFC 8210 §12): the session is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RtrError {
    /// The Protocol Version is neither 0 nor 1, and no version has been
    /// negotiated yet (RFC 8210 §7; code 4).
    UnsupportedVersion {
        /// The Protocol Version field.
        version: u8,
        /// The PDU Type field.
        pdu_type: u8,
    },
    /// The Protocol Version differs from the one negotiated for the
    /// session, whether or not it is a version this implementation knows
    /// (RFC 8210 §7; code 8).
    UnexpectedVersion {
        /// The version negotiated for the session.
        expected: Version,
        /// The Protocol Version field.
        version: u8,
        /// The PDU Type field.
        pdu_type: u8,
    },
    /// The PDU Type is not defined for the PDU's version: 5, 11–254 and
    /// 255 never are, and 9 (Router Key) is reserved in version 0
    /// (RFC 8210 §14; code 5).
    UnsupportedPduType {
        /// The Protocol Version.
        version: Version,
        /// The PDU Type field.
        pdu_type: u8,
    },
    /// The Length field is below the length the PDU type requires, or
    /// below the 8-octet header (RFC 8210 §5.1–§5.11; code 0).
    TooShort {
        /// The PDU Type field.
        pdu_type: u8,
        /// The Length field.
        length: u32,
        /// The smallest Length allowed.
        min: u32,
    },
    /// The Length field exceeds the length the PDU type allows, or
    /// [`MAX_PDU_LEN`](crate::pdu::MAX_PDU_LEN) (RFC 8210 §5.1–§5.11;
    /// code 0).
    TooLong {
        /// The PDU Type field.
        pdu_type: u8,
        /// The Length field.
        length: u32,
        /// The largest Length allowed.
        max: u32,
    },
    /// Fewer octets were given than the header, or than its Length field
    /// says the PDU has (code 0).
    Truncated {
        /// The PDU Type field, if it was present.
        pdu_type: Option<u8>,
        /// Octets needed.
        need: usize,
        /// Octets given.
        have: usize,
    },
    /// More octets were given than the Length field says the PDU has
    /// (code 0).
    TrailingData {
        /// The PDU Type field.
        pdu_type: u8,
        /// The Length field.
        length: u32,
        /// Octets given.
        have: usize,
    },
    /// A Prefix PDU whose Prefix Length or Max Length exceeds the address
    /// size (RFC 8210 §5.6, §5.7: "0..32", "0..128"), or whose Max Length
    /// is less than its Prefix Length (RFC 8210 §5.1). Code 0.
    BadPrefixLength {
        /// The PDU Type field: 4 for IPv4, 6 for IPv6.
        pdu_type: u8,
        /// The Prefix Length field.
        prefix_len: u8,
        /// The Max Length field.
        max_len: u8,
    },
    /// An Error Report whose Length of Encapsulated PDU runs past the
    /// Length of Error Text field (RFC 8210 §5.11; code 0).
    EncapsulatedPduOverrun {
        /// The Length of Encapsulated PDU field.
        length: u32,
        /// Octets left for the encapsulated PDU and the text length field.
        room: usize,
    },
    /// An Error Report whose Length of Error Text does not end exactly at
    /// the end of the PDU (RFC 8210 §5.11; code 0).
    ErrorTextLength {
        /// The Length of Error Text field.
        length: u32,
        /// Octets left after the field.
        room: usize,
    },
    /// An Error Report whose text is not UTF-8 (RFC 8210 §5.11: "it MUST
    /// be a string in UTF-8 encoding"). Code 0.
    ErrorTextNotUtf8,
}

impl RtrError {
    /// The Error Code to put in the Error Report.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            RtrError::UnsupportedVersion { .. } => ErrorCode::UnsupportedProtocolVersion,
            RtrError::UnexpectedVersion { .. } => ErrorCode::UnexpectedProtocolVersion,
            RtrError::UnsupportedPduType { .. } => ErrorCode::UnsupportedPduType,
            // RFC 8210 §12: Corrupt Data is the code for corruption "not
            // specified by another error code"; no other code covers bad
            // lengths or field values.
            RtrError::TooShort { .. }
            | RtrError::TooLong { .. }
            | RtrError::Truncated { .. }
            | RtrError::TrailingData { .. }
            | RtrError::BadPrefixLength { .. }
            | RtrError::EncapsulatedPduOverrun { .. }
            | RtrError::ErrorTextLength { .. }
            | RtrError::ErrorTextNotUtf8 => ErrorCode::CorruptData,
        }
    }

    /// The PDU Type field of the PDU in error, when it was read.
    #[must_use]
    pub const fn pdu_type(&self) -> Option<u8> {
        match self {
            RtrError::UnsupportedVersion { pdu_type, .. }
            | RtrError::UnexpectedVersion { pdu_type, .. }
            | RtrError::UnsupportedPduType { pdu_type, .. }
            | RtrError::TooShort { pdu_type, .. }
            | RtrError::TooLong { pdu_type, .. }
            | RtrError::TrailingData { pdu_type, .. }
            | RtrError::BadPrefixLength { pdu_type, .. } => Some(*pdu_type),
            RtrError::Truncated { pdu_type, .. } => *pdu_type,
            RtrError::EncapsulatedPduOverrun { .. }
            | RtrError::ErrorTextLength { .. }
            | RtrError::ErrorTextNotUtf8 => Some(PduType::ErrorReport.to_u8()),
        }
    }

    /// Whether the error may be answered with an Error Report. It may not
    /// when the PDU in error is itself an Error Report: RFC 8210 §5.11
    /// "An Error Report PDU MUST NOT be sent for an Error Report PDU",
    /// and §7 repeats this for an unknown or unexpected Protocol Version.
    /// The session is dropped either way.
    #[must_use]
    pub fn may_report(&self) -> bool {
        self.pdu_type() != Some(PduType::ErrorReport.to_u8())
    }
}

/// A PDU Type field for messages: the registry name when it has one.
struct TypeName(u8);

impl fmt::Display for TypeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Version 1 knows every type version 0 does, and Router Key too.
        match PduType::from_u8(self.0, Version::V1) {
            Some(t) => write!(f, "{} PDU", t.name()),
            None => write!(f, "PDU type {}", self.0),
        }
    }
}

impl fmt::Display for RtrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtrError::UnsupportedVersion { version, pdu_type } => write!(
                f,
                "{}: unsupported protocol version {version}",
                TypeName(*pdu_type)
            ),
            RtrError::UnexpectedVersion {
                expected,
                version,
                pdu_type,
            } => write!(
                f,
                "{}: protocol version {version} in a version {expected} session",
                TypeName(*pdu_type)
            ),
            RtrError::UnsupportedPduType { version, pdu_type } => write!(
                f,
                "PDU type {pdu_type} is not defined in protocol version {version}"
            ),
            RtrError::TooShort {
                pdu_type,
                length,
                min,
            } => write!(
                f,
                "{}: length {length} is below the minimum of {min}",
                TypeName(*pdu_type)
            ),
            RtrError::TooLong {
                pdu_type,
                length,
                max,
            } => write!(
                f,
                "{}: length {length} exceeds the maximum of {max}",
                TypeName(*pdu_type)
            ),
            RtrError::Truncated {
                pdu_type,
                need,
                have,
            } => match pdu_type {
                Some(t) => write!(f, "{}: truncated, {have} of {need} octets", TypeName(*t)),
                None => write!(f, "PDU truncated, {have} of {need} octets"),
            },
            RtrError::TrailingData {
                pdu_type,
                length,
                have,
            } => write!(
                f,
                "{}: {have} octets given for a length of {length}",
                TypeName(*pdu_type)
            ),
            RtrError::BadPrefixLength {
                pdu_type,
                prefix_len,
                max_len,
            } => {
                let bits = if *pdu_type == PduType::Ipv4Prefix.to_u8() {
                    32
                } else {
                    128
                };
                write!(f, "{}: ", TypeName(*pdu_type))?;
                if *prefix_len > bits {
                    write!(f, "prefix length {prefix_len} exceeds {bits}")
                } else if *max_len > bits {
                    write!(f, "max length {max_len} exceeds {bits}")
                } else {
                    write!(
                        f,
                        "max length {max_len} is less than prefix length {prefix_len}"
                    )
                }
            }
            RtrError::EncapsulatedPduOverrun { length, room } => write!(
                f,
                "Error Report PDU: encapsulated PDU length {length} exceeds the {room} octets left"
            ),
            RtrError::ErrorTextLength { length, room } => write!(
                f,
                "Error Report PDU: error text length {length} does not match the {room} octets left"
            ),
            RtrError::ErrorTextNotUtf8 => f.write_str("Error Report PDU: error text is not UTF-8"),
        }
    }
}

impl std::error::Error for RtrError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_name_the_registry() {
        // RFC 8210 §12: codes 0–8.
        let names = [
            "Corrupt Data",
            "Internal Error",
            "No Data Available",
            "Invalid Request",
            "Unsupported Protocol Version",
            "Unsupported PDU Type",
            "Withdrawal of Unknown Record",
            "Duplicate Announcement Received",
            "Unexpected Protocol Version",
        ];
        for (v, name) in (0u16..).zip(names) {
            let code = ErrorCode::from_u16(v);
            assert_eq!(code.to_u16(), v);
            assert_eq!(code.name(), name);
            assert!(!matches!(code, ErrorCode::Unknown(_)));
        }
        for v in [9, 255, 256, u16::MAX] {
            assert_eq!(ErrorCode::from_u16(v), ErrorCode::Unknown(v));
            assert_eq!(ErrorCode::from_u16(v).to_u16(), v);
        }
        assert_eq!(ErrorCode::CorruptData.to_string(), "Corrupt Data (0)");
        assert_eq!(ErrorCode::Unknown(42).to_string(), "Unknown (42)");
    }

    #[test]
    fn only_no_data_available_is_not_fatal() {
        // RFC 8210 §12: every code but 2 is marked "(fatal)".
        for v in 0..=u16::from(u8::MAX) {
            assert_eq!(ErrorCode::from_u16(v).is_fatal(), v != 2, "code {v}");
        }
    }

    #[test]
    fn errors_map_to_codes() {
        let e = RtrError::UnsupportedVersion {
            version: 2,
            pdu_type: 3,
        };
        assert_eq!(e.code(), ErrorCode::UnsupportedProtocolVersion);
        assert_eq!(
            e.to_string(),
            "Cache Response PDU: unsupported protocol version 2"
        );
        let e = RtrError::UnexpectedVersion {
            expected: Version::V1,
            version: 0,
            pdu_type: 4,
        };
        assert_eq!(e.code(), ErrorCode::UnexpectedProtocolVersion);
        assert_eq!(e.pdu_type(), Some(4));
        assert!(e.may_report());
        assert_eq!(
            e.to_string(),
            "IPv4 Prefix PDU: protocol version 0 in a version 1 session"
        );
        let e = RtrError::UnsupportedPduType {
            version: Version::V0,
            pdu_type: 9,
        };
        assert_eq!(e.code(), ErrorCode::UnsupportedPduType);
        assert_eq!(
            e.to_string(),
            "PDU type 9 is not defined in protocol version 0"
        );
        let e = RtrError::TooLong {
            pdu_type: 200,
            length: 70_000,
            max: 65_536,
        };
        assert_eq!(e.code(), ErrorCode::CorruptData);
        assert_eq!(
            e.to_string(),
            "PDU type 200: length 70000 exceeds the maximum of 65536"
        );
        let e = RtrError::BadPrefixLength {
            pdu_type: 4,
            prefix_len: 24,
            max_len: 16,
        };
        assert_eq!(e.code(), ErrorCode::CorruptData);
        assert_eq!(
            e.to_string(),
            "IPv4 Prefix PDU: max length 16 is less than prefix length 24"
        );
        let e = RtrError::BadPrefixLength {
            pdu_type: 6,
            prefix_len: 129,
            max_len: 129,
        };
        assert_eq!(
            e.to_string(),
            "IPv6 Prefix PDU: prefix length 129 exceeds 128"
        );
        let e = RtrError::Truncated {
            pdu_type: None,
            need: 8,
            have: 1,
        };
        assert_eq!(e.pdu_type(), None);
        assert_eq!(e.to_string(), "PDU truncated, 1 of 8 octets");
    }

    #[test]
    fn no_error_report_about_an_error_report() {
        // RFC 8210 §5.11, §7.
        for e in [
            RtrError::ErrorTextNotUtf8,
            RtrError::ErrorTextLength { length: 3, room: 2 },
            RtrError::EncapsulatedPduOverrun { length: 9, room: 4 },
            RtrError::TooShort {
                pdu_type: 10,
                length: 12,
                min: 16,
            },
            RtrError::UnsupportedVersion {
                version: 7,
                pdu_type: 10,
            },
            RtrError::UnexpectedVersion {
                expected: Version::V1,
                version: 0,
                pdu_type: 10,
            },
        ] {
            assert!(!e.may_report(), "{e}");
            assert_eq!(e.pdu_type(), Some(10));
        }
        for e in [
            RtrError::UnsupportedVersion {
                version: 7,
                pdu_type: 0,
            },
            RtrError::Truncated {
                pdu_type: None,
                need: 8,
                have: 0,
            },
        ] {
            assert!(e.may_report(), "{e}");
        }
    }
}
