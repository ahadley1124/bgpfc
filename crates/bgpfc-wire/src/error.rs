//! Decode errors, carrying exactly what the NOTIFICATION that answers them
//! needs: error code, error subcode and data (RFC 4271 §4.5).
//!
//! Implements: RFC 4271 §4.5 (error codes), §6.1 and §6.2 (subcodes),
//! RFC 5492 §5 (Unsupported Capability).

use std::fmt;

/// NOTIFICATION error code (RFC 4271 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Message Header Error.
    MessageHeader,
    /// OPEN Message Error.
    Open,
    /// UPDATE Message Error.
    Update,
    /// Hold Timer Expired.
    HoldTimerExpired,
    /// Finite State Machine Error.
    Fsm,
    /// Cease.
    Cease,
    /// ROUTE-REFRESH Message Error (RFC 7313 §5).
    RouteRefresh,
    /// A code this implementation does not know.
    Unknown(u8),
}

impl ErrorCode {
    /// Wire value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            ErrorCode::MessageHeader => 1,
            ErrorCode::Open => 2,
            ErrorCode::Update => 3,
            ErrorCode::HoldTimerExpired => 4,
            ErrorCode::Fsm => 5,
            ErrorCode::Cease => 6,
            ErrorCode::RouteRefresh => 7,
            ErrorCode::Unknown(v) => v,
        }
    }

    /// From the wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => ErrorCode::MessageHeader,
            2 => ErrorCode::Open,
            3 => ErrorCode::Update,
            4 => ErrorCode::HoldTimerExpired,
            5 => ErrorCode::Fsm,
            6 => ErrorCode::Cease,
            7 => ErrorCode::RouteRefresh,
            v => ErrorCode::Unknown(v),
        }
    }
}

/// Message Header Error subcodes (RFC 4271 §4.5, §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HeaderSubcode {
    /// The marker was not all ones.
    ConnectionNotSynchronized = 1,
    /// The length field was outside its bounds for the message type.
    BadMessageLength = 2,
    /// The type field was not recognised.
    BadMessageType = 3,
}

/// OPEN Message Error subcodes (RFC 4271 §4.5, §6.2; RFC 5492 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpenSubcode {
    /// A recognised optional parameter was malformed (RFC 4271 §6.2, last
    /// paragraph).
    Unspecific = 0,
    /// Version field not supported.
    UnsupportedVersionNumber = 1,
    /// My Autonomous System field unacceptable.
    BadPeerAs = 2,
    /// BGP Identifier field syntactically incorrect.
    BadBgpIdentifier = 3,
    /// An optional parameter type was not recognised.
    UnsupportedOptionalParameter = 4,
    /// Hold Time of one or two seconds, or otherwise rejected.
    UnacceptableHoldTime = 6,
    /// The peer lacks a capability this speaker requires (RFC 5492 §5).
    UnsupportedCapability = 7,
}

/// Why a message could not be decoded, as the NOTIFICATION to send back.
///
/// `data` is the NOTIFICATION Data field, already laid out as the RFC
/// requires for that subcode (for example the erroneous Length field for
/// Bad Message Length).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    /// Error code.
    pub code: ErrorCode,
    /// Error subcode; its meaning depends on `code`.
    pub subcode: u8,
    /// NOTIFICATION Data field.
    pub data: Vec<u8>,
}

impl DecodeError {
    /// A Message Header Error.
    #[must_use]
    pub fn header(subcode: HeaderSubcode, data: Vec<u8>) -> Self {
        DecodeError {
            code: ErrorCode::MessageHeader,
            subcode: subcode as u8,
            data,
        }
    }

    /// An OPEN Message Error.
    #[must_use]
    pub fn open(subcode: OpenSubcode, data: Vec<u8>) -> Self {
        DecodeError {
            code: ErrorCode::Open,
            subcode: subcode as u8,
            data,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "decode error: code {:?} ({}), subcode {}, {} data octet(s)",
            self.code,
            self.code.to_u8(),
            self.subcode,
            self.data.len()
        )
    }
}

impl std::error::Error for DecodeError {}

/// Why a message could not be encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A field or message does not fit its length field.
    TooLong {
        /// What was too long.
        what: &'static str,
        /// Its length in octets.
        len: usize,
        /// The largest length the format allows.
        max: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::TooLong { what, len, max } => {
                write!(
                    f,
                    "{what} is {len} octets, more than the {max} the format allows"
                )
            }
        }
    }
}

impl std::error::Error for EncodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_round_trip() {
        for v in 0..=u8::MAX {
            assert_eq!(ErrorCode::from_u8(v).to_u8(), v);
        }
        assert_eq!(ErrorCode::from_u8(6), ErrorCode::Cease);
        assert_eq!(ErrorCode::from_u8(9), ErrorCode::Unknown(9));
    }

    #[test]
    fn constructors_set_code_and_subcode() {
        let e = DecodeError::header(HeaderSubcode::BadMessageLength, vec![0, 5]);
        assert_eq!((e.code, e.subcode), (ErrorCode::MessageHeader, 2));
        let e = DecodeError::open(OpenSubcode::UnsupportedCapability, vec![]);
        assert_eq!((e.code, e.subcode), (ErrorCode::Open, 7));
        assert!(e.to_string().contains("subcode 7"));
    }
}
