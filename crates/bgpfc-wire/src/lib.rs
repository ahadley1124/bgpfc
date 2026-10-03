//! BGP-4 message codec. Pure functions from bytes to typed messages and
//! back; no I/O, no clock.
//!
//! Decoders take the body of a message (what follows the 19-octet header)
//! and return either the typed message or a [`DecodeError`] that carries the
//! error code, subcode and data of the NOTIFICATION to send in reply.
//! Encoders produce the body; [`header::frame`] prepends the header.
//!
//! Implements: RFC 4271 §4.1–§4.5, §5, §6.1–§6.7; RFC 5492 §4, §5;
//! RFC 4760 §3–§5, §7, §8; RFC 2918 §2, §3; RFC 8654 §3–§6; RFC 6793 §3,
//! §4.2, §6; RFC 9072 §2, §3; RFC 7607 §2; RFC 6286 §2.1; RFC 4486 §3,
//! §4; RFC 6608 §3, §4; RFC 9003 §2, §4; RFC 7606 §3–§5, §7; RFC 2545 §3;
//! RFC 8950 §3; RFC 1997; RFC 4360 §2, §3; RFC 8092 §3, §6; RFC 9774 §3.
#![forbid(unsafe_code)]

pub mod as_path;
pub mod attribute;
pub mod capability;
pub mod community;
pub mod error;
pub mod header;
pub mod keepalive;
pub mod mp;
pub mod notification;
pub mod open;
pub mod prefix;
pub mod reader;
pub mod route_refresh;
pub mod types;

pub use as_path::{AsPath, AsPathSegment, SegmentType};
pub use attribute::{Aggregator, Origin, PathAttribute};
pub use capability::Capability;
pub use community::{Community, ExtendedCommunity, LargeCommunity};
pub use error::{
    CeaseSubcode, DecodeError, EncodeError, ErrorCode, FsmSubcode, HeaderSubcode, OpenSubcode,
    UpdateSubcode, subcode_name,
};
pub use header::{HEADER_LEN, Header, MessageType, frame};
pub use keepalive::KEEPALIVE;
pub use mp::{MpReach, MpUnreach, NextHop};
pub use notification::{NotificationMessage, ShutdownCommunicationError};
pub use open::OpenMessage;
pub use prefix::Prefix;
pub use route_refresh::RouteRefreshMessage;
pub use types::{AddressFamily, Afi, Asn, HoldTime, RouterId, Safi};
