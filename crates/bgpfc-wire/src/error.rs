//! Decode errors, carrying exactly what the NOTIFICATION that answers them
//! needs: error code, error subcode and data (RFC 4271 §4.5).
//!
//! Implements: RFC 4271 §4.5 (error codes and subcodes), §6.1 and §6.2,
//! RFC 5492 §5 (Unsupported Capability), RFC 6608 §3 (FSM subcodes),
//! RFC 4486 §3 (Cease subcodes).

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

/// UPDATE Message Error subcodes (RFC 4271 §4.5, §6.3). Subcode 7 is
/// deprecated and never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UpdateSubcode {
    /// Malformed Attribute List.
    MalformedAttributeList = 1,
    /// Unrecognized Well-known Attribute.
    UnrecognizedWellKnownAttribute = 2,
    /// Missing Well-known Attribute.
    MissingWellKnownAttribute = 3,
    /// Attribute Flags Error.
    AttributeFlagsError = 4,
    /// Attribute Length Error.
    AttributeLengthError = 5,
    /// Invalid ORIGIN Attribute.
    InvalidOrigin = 6,
    /// Invalid `NEXT_HOP` Attribute.
    InvalidNextHop = 8,
    /// Optional Attribute Error.
    OptionalAttributeError = 9,
    /// Invalid Network Field.
    InvalidNetworkField = 10,
    /// Malformed `AS_PATH`.
    MalformedAsPath = 11,
}

/// Finite State Machine Error subcodes (RFC 6608 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FsmSubcode {
    /// Unspecified Error.
    Unspecified = 0,
    /// Receive Unexpected Message in `OpenSent` State.
    UnexpectedInOpenSent = 1,
    /// Receive Unexpected Message in `OpenConfirm` State.
    UnexpectedInOpenConfirm = 2,
    /// Receive Unexpected Message in Established State.
    UnexpectedInEstablished = 3,
}

/// Cease subcodes (RFC 4486 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CeaseSubcode {
    /// Maximum Number of Prefixes Reached.
    MaxPrefixesReached = 1,
    /// Administrative Shutdown.
    AdministrativeShutdown = 2,
    /// Peer De-configured.
    PeerDeconfigured = 3,
    /// Administrative Reset.
    AdministrativeReset = 4,
    /// Connection Rejected.
    ConnectionRejected = 5,
    /// Other Configuration Change.
    OtherConfigurationChange = 6,
    /// Connection Collision Resolution.
    ConnectionCollisionResolution = 7,
    /// Out of Resources.
    OutOfResources = 8,
}

/// Human-readable name of a `(code, subcode)` pair for logs, from the
/// RFC 4271 §4.5, RFC 5492 §5, RFC 6608 §3 and RFC 4486 §3 tables.
/// `None` when the subcode is not defined for that code.
#[must_use]
pub fn subcode_name(code: ErrorCode, subcode: u8) -> Option<&'static str> {
    Some(match (code, subcode) {
        (ErrorCode::MessageHeader, 1) => "Connection Not Synchronized",
        (ErrorCode::MessageHeader, 2) => "Bad Message Length",
        (ErrorCode::MessageHeader, 3) => "Bad Message Type",
        (ErrorCode::Open, 0) => "Unspecific",
        (ErrorCode::Open, 1) => "Unsupported Version Number",
        (ErrorCode::Open, 2) => "Bad Peer AS",
        (ErrorCode::Open, 3) => "Bad BGP Identifier",
        (ErrorCode::Open, 4) => "Unsupported Optional Parameter",
        (ErrorCode::Open, 6) => "Unacceptable Hold Time",
        (ErrorCode::Open, 7) => "Unsupported Capability",
        (ErrorCode::Update, 1) => "Malformed Attribute List",
        (ErrorCode::Update, 2) => "Unrecognized Well-known Attribute",
        (ErrorCode::Update, 3) => "Missing Well-known Attribute",
        (ErrorCode::Update, 4) => "Attribute Flags Error",
        (ErrorCode::Update, 5) => "Attribute Length Error",
        (ErrorCode::Update, 6) => "Invalid ORIGIN Attribute",
        (ErrorCode::Update, 8) => "Invalid NEXT_HOP Attribute",
        (ErrorCode::Update, 9) => "Optional Attribute Error",
        (ErrorCode::Update, 10) => "Invalid Network Field",
        (ErrorCode::Update, 11) => "Malformed AS_PATH",
        (ErrorCode::HoldTimerExpired, 0) => "Hold Timer Expired",
        (ErrorCode::Fsm, 0) => "Unspecified Error",
        (ErrorCode::Fsm, 1) => "Receive Unexpected Message in OpenSent State",
        (ErrorCode::Fsm, 2) => "Receive Unexpected Message in OpenConfirm State",
        (ErrorCode::Fsm, 3) => "Receive Unexpected Message in Established State",
        (ErrorCode::Cease, 1) => "Maximum Number of Prefixes Reached",
        (ErrorCode::Cease, 2) => "Administrative Shutdown",
        (ErrorCode::Cease, 3) => "Peer De-configured",
        (ErrorCode::Cease, 4) => "Administrative Reset",
        (ErrorCode::Cease, 5) => "Connection Rejected",
        (ErrorCode::Cease, 6) => "Other Configuration Change",
        (ErrorCode::Cease, 7) => "Connection Collision Resolution",
        (ErrorCode::Cease, 8) => "Out of Resources",
        _ => return None,
    })
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

    /// An UPDATE Message Error.
    #[must_use]
    pub fn update(subcode: UpdateSubcode, data: Vec<u8>) -> Self {
        DecodeError {
            code: ErrorCode::Update,
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
    /// A Shutdown Communication was requested on a Cease subcode other than
    /// Administrative Shutdown or Administrative Reset (RFC 9003 §2).
    NotShutdown,
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
            EncodeError::NotShutdown => f.write_str(
                "shutdown communication is only allowed with Administrative Shutdown or Reset",
            ),
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
        let e = DecodeError::update(UpdateSubcode::MalformedAsPath, vec![]);
        assert_eq!((e.code, e.subcode), (ErrorCode::Update, 11));
    }

    #[test]
    fn subcode_names_cover_every_defined_subcode() {
        assert_eq!(
            subcode_name(ErrorCode::Cease, 2),
            Some("Administrative Shutdown")
        );
        assert_eq!(subcode_name(ErrorCode::Update, 7), None, "deprecated");
        assert_eq!(subcode_name(ErrorCode::Unknown(9), 0), None);
        for s in [1u8, 2, 3] {
            assert!(subcode_name(ErrorCode::MessageHeader, s).is_some());
        }
        for s in [0u8, 1, 2, 3, 4, 6, 7] {
            assert!(subcode_name(ErrorCode::Open, s).is_some());
        }
        for s in [1u8, 2, 3, 4, 5, 6, 8, 9, 10, 11] {
            assert!(subcode_name(ErrorCode::Update, s).is_some());
        }
        for s in 0..=3u8 {
            assert!(subcode_name(ErrorCode::Fsm, s).is_some());
        }
        for s in 1..=8u8 {
            assert!(subcode_name(ErrorCode::Cease, s).is_some());
        }
    }
}
