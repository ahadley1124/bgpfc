//! RTR Protocol Data Units: decoding one PDU from its octets, and encoding
//! it back.
//!
//! Every PDU starts with the same 8-octet header: Protocol Version, PDU
//! Type, a 16-bit field whose meaning depends on the type (Session ID,
//! Flags, Error Code or zero), and the Length of the whole PDU. Decoding
//! checks the header first (version, then type, then the length the type
//! requires), then the fields of the body. Reserved fields are ignored on
//! receipt and sent as zero, so every PDU decodes to the same value
//! whatever its reserved bits hold, and encodes canonically.
//!
//! Implements: RFC 8210 §5 (reserved fields), §5.1 (field definitions,
//! Flags, Max Length), §5.2–§5.11 (the PDU layouts), §6 (timing
//! parameters), §7 and §14 (versions and the PDU types of each);
//! RFC 6810 §5 (version 0 PDUs, including the 12-octet End of Data).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgpfc_rpki::Vrp;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::reader::{Reader, WriteBytes as _};
use bgpfc_wire::types::Asn;

use crate::error::{ErrorCode, RtrError};

/// Octets in the header every PDU starts with (RFC 8210 §5.1: the Length
/// counts "the 8 bytes of header").
pub const HEADER_LEN: usize = 8;

/// Longest PDU this implementation accepts, header included.
///
/// RFC 8210 sets no limit beyond the 32-bit Length field. One is needed
/// because a PDU is buffered until all of it has arrived, and a cache
/// announcing a 4 GiB PDU must not make the router buffer 4 GiB. No
/// legitimate PDU comes close to 64 KiB: the fixed-size PDUs are at most
/// 32 octets, a Router Key carrying the ECDSA P-256 key of RFC 8208 is
/// 123 octets, and an Error Report from a cache carries one of the
/// router's queries (at most 12 octets) and some text. 64 KiB leaves room
/// for other key types and long diagnostics, and caps the buffer of a
/// session at a size that does not matter. A longer PDU is Corrupt Data.
///
/// NOTE(interop): BIRD uses the same limit (`RPKI_PDU_MAX_LEN`, 65536).
pub const MAX_PDU_LEN: u32 = 65_536;

/// Octets of an Error Report before its variable parts: the header and
/// the two 4-octet length fields (RFC 8210 §5.11).
const ERROR_REPORT_FIXED_LEN: usize = HEADER_LEN + 4 + 4;

/// [`ERROR_REPORT_FIXED_LEN`] as a Length field.
const ERROR_REPORT_MIN_LEN: u32 = 16;
const _: () = assert!(ERROR_REPORT_MIN_LEN as usize == ERROR_REPORT_FIXED_LEN);

/// Octets of a Router Key before the Subject Public Key Info: the header,
/// the 20-octet SKI and the 4-octet AS Number (RFC 8210 §5.10).
const ROUTER_KEY_FIXED_LEN: usize = HEADER_LEN + RouterKey::SKI_LEN + 4;

/// [`ROUTER_KEY_FIXED_LEN`] as a Length field.
const ROUTER_KEY_MIN_LEN: u32 = 32;
const _: () = assert!(ROUTER_KEY_MIN_LEN as usize == ROUTER_KEY_FIXED_LEN);

/// [`MAX_PDU_LEN`] as a buffer size.
const MAX_PDU_USIZE: usize = MAX_PDU_LEN as usize;

/// The Protocol Version of a PDU (RFC 8210 §5.1, §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    /// Version 0, RFC 6810.
    V0,
    /// Version 1, RFC 8210.
    V1,
}

impl Version {
    /// Every version this implementation speaks, oldest first.
    pub const ALL: [Version; 2] = [Version::V0, Version::V1];

    /// From the Protocol Version field; `None` for any other value, which
    /// RFC 8210 §7 calls "an unrecognized Protocol Version".
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Version> {
        match v {
            0 => Some(Version::V0),
            1 => Some(Version::V1),
            _ => None,
        }
    }

    /// The value of the Protocol Version field.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Version::V0 => 0,
            Version::V1 => 1,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_u8())
    }
}

/// The PDU Type field (RFC 8210 §14, the "rpki-rtr-pdu" registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PduType {
    /// 0: Serial Notify (RFC 8210 §5.2).
    SerialNotify,
    /// 1: Serial Query (RFC 8210 §5.3).
    SerialQuery,
    /// 2: Reset Query (RFC 8210 §5.4).
    ResetQuery,
    /// 3: Cache Response (RFC 8210 §5.5).
    CacheResponse,
    /// 4: IPv4 Prefix (RFC 8210 §5.6).
    Ipv4Prefix,
    /// 6: IPv6 Prefix (RFC 8210 §5.7).
    Ipv6Prefix,
    /// 7: End of Data (RFC 8210 §5.8).
    EndOfData,
    /// 8: Cache Reset (RFC 8210 §5.9).
    CacheReset,
    /// 9: Router Key (RFC 8210 §5.10), version 1 only.
    RouterKey,
    /// 10: Error Report (RFC 8210 §5.11).
    ErrorReport,
}

impl PduType {
    /// The type with wire value `v` in protocol `version`. RFC 8210 §14:
    /// every version 0 type exists in version 1, and 9 is Router Key in
    /// version 1 but reserved in version 0; 5 and 255 are no PDU at all.
    #[must_use]
    pub const fn from_u8(v: u8, version: Version) -> Option<PduType> {
        match v {
            0 => Some(PduType::SerialNotify),
            1 => Some(PduType::SerialQuery),
            2 => Some(PduType::ResetQuery),
            3 => Some(PduType::CacheResponse),
            4 => Some(PduType::Ipv4Prefix),
            6 => Some(PduType::Ipv6Prefix),
            7 => Some(PduType::EndOfData),
            8 => Some(PduType::CacheReset),
            9 if matches!(version, Version::V1) => Some(PduType::RouterKey),
            10 => Some(PduType::ErrorReport),
            _ => None,
        }
    }

    /// The value of the PDU Type field.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            PduType::SerialNotify => 0,
            PduType::SerialQuery => 1,
            PduType::ResetQuery => 2,
            PduType::CacheResponse => 3,
            PduType::Ipv4Prefix => 4,
            PduType::Ipv6Prefix => 6,
            PduType::EndOfData => 7,
            PduType::CacheReset => 8,
            PduType::RouterKey => 9,
            PduType::ErrorReport => 10,
        }
    }

    /// The registry's name for the type, e.g. `Serial Query`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            PduType::SerialNotify => "Serial Notify",
            PduType::SerialQuery => "Serial Query",
            PduType::ResetQuery => "Reset Query",
            PduType::CacheResponse => "Cache Response",
            PduType::Ipv4Prefix => "IPv4 Prefix",
            PduType::Ipv6Prefix => "IPv6 Prefix",
            PduType::EndOfData => "End of Data",
            PduType::CacheReset => "Cache Reset",
            PduType::RouterKey => "Router Key",
            PduType::ErrorReport => "Error Report",
        }
    }

    /// The smallest and largest Length a PDU of this type may have in
    /// `version`, header included.
    const fn length_bounds(self, version: Version) -> (u32, u32) {
        match self {
            // RFC 8210 §5.4, §5.5, §5.9; RFC 6810 §5.4, §5.5, §5.9:
            // "Length=8".
            PduType::ResetQuery | PduType::CacheResponse | PduType::CacheReset => (8, 8),
            // RFC 8210 §5.2, §5.3; RFC 6810 §5.2, §5.3: "Length=12".
            PduType::SerialNotify | PduType::SerialQuery => (12, 12),
            // RFC 8210 §5.6; RFC 6810 §5.6: "Length=20".
            PduType::Ipv4Prefix => (20, 20),
            // RFC 8210 §5.7; RFC 6810 §5.7: "Length=32".
            PduType::Ipv6Prefix => (32, 32),
            // RFC 6810 §5.8: "Length=12"; RFC 8210 §5.8 adds the three
            // intervals: "Length=24".
            PduType::EndOfData => match version {
                Version::V0 => (12, 12),
                Version::V1 => (24, 24),
            },
            // RFC 8210 §5.10: the header, the 20-octet SKI and the AS
            // Number, then the Subject Public Key Info, whose length only
            // the Length field gives.
            PduType::RouterKey => (ROUTER_KEY_MIN_LEN, MAX_PDU_LEN),
            // RFC 8210 §5.11: the header and the two length fields; the
            // encapsulated PDU and the text may both be empty.
            PduType::ErrorReport => (ERROR_REPORT_MIN_LEN, MAX_PDU_LEN),
        }
    }
}

impl fmt::Display for PduType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The timing parameters of a version 1 End of Data PDU, in seconds
/// (RFC 8210 §5.8, §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Intervals {
    /// Refresh Interval: how long to wait before polling the cache again.
    pub refresh: u32,
    /// Retry Interval: how long to wait before retrying a failed poll.
    pub retry: u32,
    /// Expire Interval: how long the data may be used without a
    /// successful poll.
    pub expire: u32,
}

impl Intervals {
    /// The recommended defaults of RFC 8210 §6: refresh after an hour,
    /// retry after ten minutes, expire after two hours.
    pub const DEFAULT: Intervals = Intervals {
        refresh: 3_600,
        retry: 600,
        expire: 7_200,
    };

    /// Whether the cache kept to RFC 8210 §6: Refresh in 1..=86400, Retry
    /// in 1..=7200, Expire in 600..=172800, and "Caches MUST set Expire
    /// Interval to a value larger than either Refresh Interval or Retry
    /// Interval."
    ///
    /// Decoding does not check this. RFC 8210 says what a cache may send,
    /// not what a router does with other values, so that is the caller's
    /// decision.
    #[must_use]
    pub const fn within_limits(&self) -> bool {
        matches!(self.refresh, 1..=86_400)
            && matches!(self.retry, 1..=7_200)
            && matches!(self.expire, 600..=172_800)
            && self.expire > self.refresh
            && self.expire > self.retry
    }
}

impl Default for Intervals {
    fn default() -> Intervals {
        Intervals::DEFAULT
    }
}

/// A Router Key PDU (RFC 8210 §5.10), which exists only in version 1.
///
/// Path validation with router keys (RFC 8205) is out of scope, so the key
/// is carried but not interpreted. The fields are private so that every
/// `RouterKey` fits in [`MAX_PDU_LEN`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouterKey {
    announce: bool,
    ski: [u8; RouterKey::SKI_LEN],
    asn: Asn,
    spki: Vec<u8>,
}

impl RouterKey {
    /// Octets in a Subject Key Identifier (RFC 8210 §5.1: "20-octet").
    pub const SKI_LEN: usize = 20;

    /// A Router Key PDU. `None` if the Subject Public Key Info
    /// (`public_key`) is too long for the PDU to fit in [`MAX_PDU_LEN`].
    #[must_use]
    pub fn new(
        announce: bool,
        ski: [u8; RouterKey::SKI_LEN],
        asn: Asn,
        public_key: Vec<u8>,
    ) -> Option<RouterKey> {
        (public_key.len() <= MAX_PDU_USIZE - ROUTER_KEY_FIXED_LEN).then_some(RouterKey {
            announce,
            ski,
            asn,
            spki: public_key,
        })
    }

    /// Whether the key is announced (Flags bit 0 is 1) rather than
    /// withdrawn (RFC 8210 §5.1).
    #[must_use]
    pub const fn announce(&self) -> bool {
        self.announce
    }

    /// The Subject Key Identifier.
    #[must_use]
    pub const fn ski(&self) -> [u8; RouterKey::SKI_LEN] {
        self.ski
    }

    /// The AS Number the key belongs to.
    #[must_use]
    pub const fn asn(&self) -> Asn {
        self.asn
    }

    /// The DER-encoded Subject Public Key Info, as received.
    #[must_use]
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// The Length field of this PDU.
    fn wire_len(&self) -> u32 {
        wire_len(ROUTER_KEY_FIXED_LEN + self.spki.len())
    }
}

/// An Error Report PDU (RFC 8210 §5.11).
///
/// The fields are private so that every `ErrorReport` fits in
/// [`MAX_PDU_LEN`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ErrorReport {
    version: Version,
    code: ErrorCode,
    pdu: Vec<u8>,
    text: String,
}

impl ErrorReport {
    /// An Error Report about `erroneous_pdu`, with diagnostic `text`.
    ///
    /// For an error not tied to a PDU, pass an empty `erroneous_pdu`
    /// (RFC 8210 §5.11: "the Erroneous PDU field MUST be empty"); an
    /// empty `text` means no diagnostic. If the two do not fit in
    /// [`MAX_PDU_LEN`], the text is cut at a character boundary to fit on
    /// its own, then the PDU to fit beside it: RFC 8210 §5.11 lets the
    /// Erroneous PDU field be truncated when that PDU is of "excessive
    /// length".
    #[must_use]
    pub fn new(version: Version, code: ErrorCode, erroneous_pdu: &[u8], text: &str) -> ErrorReport {
        let room = MAX_PDU_USIZE - ERROR_REPORT_FIXED_LEN;
        let text = utf8_prefix(text, room);
        let pdu = erroneous_pdu
            .get(..room - text.len())
            .unwrap_or(erroneous_pdu);
        ErrorReport {
            version,
            code,
            pdu: pdu.to_vec(),
            text: text.to_owned(),
        }
    }

    /// The Protocol Version of the PDU.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The Error Code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// The Erroneous PDU field: a copy of the PDU in error, possibly
    /// truncated, or empty.
    #[must_use]
    pub fn erroneous_pdu(&self) -> &[u8] {
        &self.pdu
    }

    /// The diagnostic text; empty if there is none.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The Length field of this PDU.
    fn wire_len(&self) -> u32 {
        wire_len(ERROR_REPORT_FIXED_LEN + self.pdu.len() + self.text.len())
    }
}

/// The longest prefix of `s` that is at most `max` octets and ends on a
/// character boundary.
fn utf8_prefix(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default()
}

/// A PDU of either protocol version.
///
/// Every value encodes to a PDU of at most [`MAX_PDU_LEN`] octets that
/// decodes back to the same value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pdu {
    /// The cache has new data (RFC 8210 §5.2).
    SerialNotify {
        /// Protocol Version.
        version: Version,
        /// The cache's Session ID.
        session_id: u16,
        /// The cache's new Serial Number.
        serial: u32,
    },
    /// The router asks for the changes since `serial` (RFC 8210 §5.3).
    SerialQuery {
        /// Protocol Version.
        version: Version,
        /// The Session ID the router expects.
        session_id: u16,
        /// The router's current Serial Number.
        serial: u32,
    },
    /// The router asks for the whole data set (RFC 8210 §5.4).
    ResetQuery {
        /// Protocol Version.
        version: Version,
    },
    /// The cache starts answering a query (RFC 8210 §5.5).
    CacheResponse {
        /// Protocol Version.
        version: Version,
        /// The cache's Session ID.
        session_id: u16,
    },
    /// An IPv4 Prefix or IPv6 Prefix PDU (RFC 8210 §5.6, §5.7), by the
    /// family of the VRP's prefix.
    Prefix {
        /// Protocol Version.
        version: Version,
        /// Flags bit 0: whether the VRP is announced rather than
        /// withdrawn (RFC 8210 §5.1).
        announce: bool,
        /// The prefix, maximum length and ASN. Address bits beyond the
        /// prefix length are zero.
        vrp: Vrp,
    },
    /// The cache has finished answering a query (RFC 8210 §5.8).
    EndOfData {
        /// The cache's Session ID.
        session_id: u16,
        /// The Serial Number the router now holds.
        serial: u32,
        /// The timing parameters: `Some` in version 1 (RFC 8210 §5.8),
        /// whose End of Data carries them, and `None` in version 0
        /// (RFC 6810 §5.8), whose does not. This is also what gives the
        /// PDU's version.
        intervals: Option<Intervals>,
    },
    /// The cache cannot answer a Serial Query incrementally
    /// (RFC 8210 §5.9).
    CacheReset {
        /// Protocol Version.
        version: Version,
    },
    /// A router's public key for path validation (RFC 8210 §5.10);
    /// version 1 only.
    RouterKey(RouterKey),
    /// An error report (RFC 8210 §5.11).
    ErrorReport(ErrorReport),
}

impl Pdu {
    /// The Protocol Version of the PDU.
    #[must_use]
    pub const fn version(&self) -> Version {
        match self {
            Pdu::SerialNotify { version, .. }
            | Pdu::SerialQuery { version, .. }
            | Pdu::ResetQuery { version }
            | Pdu::CacheResponse { version, .. }
            | Pdu::Prefix { version, .. }
            | Pdu::CacheReset { version } => *version,
            Pdu::EndOfData { intervals, .. } => {
                if intervals.is_some() {
                    Version::V1
                } else {
                    Version::V0
                }
            }
            Pdu::RouterKey(_) => Version::V1,
            Pdu::ErrorReport(e) => e.version,
        }
    }

    /// The PDU Type.
    #[must_use]
    pub const fn pdu_type(&self) -> PduType {
        match self {
            Pdu::SerialNotify { .. } => PduType::SerialNotify,
            Pdu::SerialQuery { .. } => PduType::SerialQuery,
            Pdu::ResetQuery { .. } => PduType::ResetQuery,
            Pdu::CacheResponse { .. } => PduType::CacheResponse,
            Pdu::Prefix { vrp, .. } => match vrp.prefix() {
                Prefix::V4 { .. } => PduType::Ipv4Prefix,
                Prefix::V6 { .. } => PduType::Ipv6Prefix,
            },
            Pdu::EndOfData { .. } => PduType::EndOfData,
            Pdu::CacheReset { .. } => PduType::CacheReset,
            Pdu::RouterKey(_) => PduType::RouterKey,
            Pdu::ErrorReport(_) => PduType::ErrorReport,
        }
    }

    /// Decode exactly one PDU of either version, as before the session's
    /// version is negotiated (RFC 8210 §7): `bytes` must hold the whole
    /// PDU and nothing else.
    ///
    /// Reserved fields and the reserved Flags bits are ignored, and
    /// address bits beyond a prefix's length are cleared.
    ///
    /// # Errors
    /// An [`RtrError`] naming the Error Code to report: Unsupported
    /// Protocol Version for a version other than 0 or 1; Unsupported PDU
    /// Type for a type the version does not define; Corrupt Data for a
    /// Length the type does not allow or that does not match `bytes`, a
    /// prefix or maximum length out of bounds, or an Error Report whose
    /// inner lengths do not add up or whose text is not UTF-8.
    pub fn decode(bytes: &[u8]) -> Result<Pdu, RtrError> {
        decode_pdu(bytes, None)
    }

    /// Decode exactly one PDU of a session whose version has been
    /// negotiated, as [`Pdu::decode`] does.
    ///
    /// # Errors
    /// As [`Pdu::decode`], except that a Protocol Version other than
    /// `version` is Unexpected Protocol Version (RFC 8210 §7, §12 code 8)
    /// and is checked first: a version 0 Router Key in a version 1 session
    /// has the wrong version, not an unknown type.
    pub fn decode_negotiated(bytes: &[u8], version: Version) -> Result<Pdu, RtrError> {
        decode_pdu(bytes, Some(version))
    }

    /// Encode the PDU.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Append the encoded PDU to `out`. Reserved fields and reserved
    /// Flags bits are zero (RFC 8210 §5, §5.1).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let version = self.version();
        let pdu_type = self.pdu_type();
        let header = |out: &mut Vec<u8>, field: u16, length: u32| {
            out.put_u8(version.to_u8());
            out.put_u8(pdu_type.to_u8());
            out.put_u16(field);
            out.put_u32(length);
        };
        let (min_len, _) = pdu_type.length_bounds(version);
        match self {
            Pdu::SerialNotify {
                session_id, serial, ..
            }
            | Pdu::SerialQuery {
                session_id, serial, ..
            } => {
                header(out, *session_id, min_len);
                out.put_u32(*serial);
            }
            Pdu::ResetQuery { .. } | Pdu::CacheReset { .. } => header(out, 0, min_len),
            Pdu::CacheResponse { session_id, .. } => header(out, *session_id, min_len),
            Pdu::Prefix { announce, vrp, .. } => {
                header(out, 0, min_len);
                out.put_u8(u8::from(*announce));
                out.put_u8(vrp.prefix().prefix_len());
                out.put_u8(vrp.max_len());
                out.put_u8(0);
                match vrp.prefix().addr() {
                    IpAddr::V4(a) => out.put_bytes(&a.octets()),
                    IpAddr::V6(a) => out.put_bytes(&a.octets()),
                }
                out.put_u32(vrp.asn().0);
            }
            Pdu::EndOfData {
                session_id,
                serial,
                intervals,
            } => {
                header(out, *session_id, min_len);
                out.put_u32(*serial);
                if let Some(i) = intervals {
                    out.put_u32(i.refresh);
                    out.put_u32(i.retry);
                    out.put_u32(i.expire);
                }
            }
            Pdu::RouterKey(k) => {
                // RFC 8210 §5.10: Flags in the high octet of the field,
                // then a zero octet.
                header(
                    out,
                    u16::from_be_bytes([u8::from(k.announce), 0]),
                    k.wire_len(),
                );
                out.put_bytes(&k.ski);
                out.put_u32(k.asn.0);
                out.put_bytes(&k.spki);
            }
            Pdu::ErrorReport(e) => {
                header(out, e.code.to_u16(), e.wire_len());
                out.put_u32(wire_len(e.pdu.len()));
                out.put_bytes(&e.pdu);
                out.put_u32(wire_len(e.text.len()));
                out.put_bytes(e.text.as_bytes());
            }
        }
    }
}

/// Decode one PDU; `expected` is the negotiated version, if there is one.
fn decode_pdu(bytes: &[u8], expected: Option<Version>) -> Result<Pdu, RtrError> {
    let mut r = Reader::new(bytes);
    let header = Header::read(&mut r).ok_or(RtrError::Truncated {
        pdu_type: bytes.get(1).copied(),
        need: HEADER_LEN,
        have: bytes.len(),
    })?;
    let (version, pdu_type) = header.check(expected)?;
    // The Length field is the whole PDU (RFC 8210 §5.1), so it must
    // be exactly what was handed over.
    let length = usize::try_from(header.length).unwrap_or(usize::MAX);
    if bytes.len() < length {
        return Err(RtrError::Truncated {
            pdu_type: Some(header.pdu_type),
            need: length,
            have: bytes.len(),
        });
    }
    if bytes.len() > length {
        return Err(RtrError::TrailingData {
            pdu_type: header.pdu_type,
            length: header.length,
            have: bytes.len(),
        });
    }
    let mut body = Body {
        r,
        short: RtrError::Truncated {
            pdu_type: Some(header.pdu_type),
            need: length,
            have: bytes.len(),
        },
    };
    let field = header.field;
    let pdu = match pdu_type {
        PduType::SerialNotify => Pdu::SerialNotify {
            version,
            session_id: field,
            serial: body.u32()?,
        },
        PduType::SerialQuery => Pdu::SerialQuery {
            version,
            session_id: field,
            serial: body.u32()?,
        },
        // RFC 8210 §5: the "zero" field "MUST be ignored on receipt";
        // RFC 6810 §5.1 likewise. So too below.
        PduType::ResetQuery => Pdu::ResetQuery { version },
        PduType::CacheResponse => Pdu::CacheResponse {
            version,
            session_id: field,
        },
        PduType::Ipv4Prefix | PduType::Ipv6Prefix => decode_prefix(&mut body, version, pdu_type)?,
        PduType::EndOfData => {
            let serial = body.u32()?;
            let intervals = match version {
                Version::V0 => None,
                Version::V1 => Some(Intervals {
                    refresh: body.u32()?,
                    retry: body.u32()?,
                    expire: body.u32()?,
                }),
            };
            Pdu::EndOfData {
                session_id: field,
                serial,
                intervals,
            }
        }
        PduType::CacheReset => Pdu::CacheReset { version },
        PduType::RouterKey => decode_router_key(&mut body, field)?,
        PduType::ErrorReport => decode_error_report(&mut body, version, field)?,
    };
    Ok(pdu)
}

/// A length as a 32-bit field. The constructors keep every PDU within
/// [`MAX_PDU_LEN`], so this never saturates.
fn wire_len(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The header fields as read, before any of them is checked.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Header {
    /// Protocol Version.
    pub(crate) version: u8,
    /// PDU Type.
    pub(crate) pdu_type: u8,
    /// Session ID, Flags, Error Code or zero, by type.
    pub(crate) field: u16,
    /// Length of the whole PDU.
    pub(crate) length: u32,
}

impl Header {
    /// Read the 8 header octets; `None` if there are fewer.
    pub(crate) fn read(r: &mut Reader<'_>) -> Option<Header> {
        let mut h = r.sub(HEADER_LEN).ok()?;
        Some(Header {
            version: h.u8().ok()?,
            pdu_type: h.u8().ok()?,
            field: h.u16().ok()?,
            length: h.u32().ok()?,
        })
    }

    /// Check version, type and length, in that order: the type means
    /// nothing in an unknown version, and the length rule depends on the
    /// type. `expected` is the version negotiated for the session, if
    /// there is one yet.
    pub(crate) fn check(self, expected: Option<Version>) -> Result<(Version, PduType), RtrError> {
        // RFC 8210 §7: once the version is negotiated, "If either party
        // receives a PDU for a different Protocol Version ... [it] SHOULD
        // send an Error Report with an error code of 8".
        if let Some(expected) = expected
            && self.version != expected.to_u8()
        {
            return Err(RtrError::UnexpectedVersion {
                expected,
                version: self.version,
                pdu_type: self.pdu_type,
            });
        }
        // RFC 8210 §7: during negotiation, an unrecognized Protocol
        // Version is reported as Unsupported Protocol Version (§12, code
        // 4).
        let version = Version::from_u8(self.version).ok_or(RtrError::UnsupportedVersion {
            version: self.version,
            pdu_type: self.pdu_type,
        })?;
        // RFC 8210 §12, code 5: "The PDU Type is not known by the receiver
        // of the PDU"; §14 lists the types of each version.
        let pdu_type =
            PduType::from_u8(self.pdu_type, version).ok_or(RtrError::UnsupportedPduType {
                version,
                pdu_type: self.pdu_type,
            })?;
        // RFC 8210 §5.2–§5.11 give each type its Length; anything else is
        // corrupt (§12, code 0).
        let (min, max) = pdu_type.length_bounds(version);
        if self.length < min {
            return Err(RtrError::TooShort {
                pdu_type: self.pdu_type,
                length: self.length,
                min,
            });
        }
        if self.length > max {
            return Err(RtrError::TooLong {
                pdu_type: self.pdu_type,
                length: self.length,
                max,
            });
        }
        Ok((version, pdu_type))
    }
}

/// A cursor over a PDU body whose length has already been checked
/// against the PDU type and the Length field, so its reads cannot run
/// short. If one did, it would be reported as truncation, not a panic.
struct Body<'a> {
    r: Reader<'a>,
    /// The error for a read that runs short.
    short: RtrError,
}

impl<'a> Body<'a> {
    fn u8(&mut self) -> Result<u8, RtrError> {
        self.r.u8().map_err(|_| self.short.clone())
    }

    fn u32(&mut self) -> Result<u32, RtrError> {
        self.r.u32().map_err(|_| self.short.clone())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RtrError> {
        self.r.array().map_err(|_| self.short.clone())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], RtrError> {
        self.r.take(n).map_err(|_| self.short.clone())
    }
}

/// The body of an IPv4 or IPv6 Prefix PDU (RFC 8210 §5.6, §5.7).
fn decode_prefix(
    body: &mut Body<'_>,
    version: Version,
    pdu_type: PduType,
) -> Result<Pdu, RtrError> {
    let flags = body.u8()?;
    let prefix_len = body.u8()?;
    let max_len = body.u8()?;
    // RFC 8210 §5: the "zero" octet is ignored on receipt.
    let _zero = body.u8()?;
    let addr = if pdu_type == PduType::Ipv4Prefix {
        IpAddr::V4(Ipv4Addr::from(body.array::<4>()?))
    } else {
        IpAddr::V6(Ipv6Addr::from(body.array::<16>()?))
    };
    let asn = Asn(body.u32()?);
    let bad = RtrError::BadPrefixLength {
        pdu_type: pdu_type.to_u8(),
        prefix_len,
        max_len,
    };
    // RFC 8210 §5.6, §5.7: Prefix Length is "0..32" ("0..128"). Prefix::new
    // refuses longer ones. It also clears address bits beyond the prefix
    // length, which RFC 8210 does not mention: a VRP is a prefix, and its
    // withdrawal must match its announcement.
    // NOTE(interop): BIRD and rtrlib (FRR) neither reject nor clear such
    // bits; caches never send them, since a ROA cannot hold them
    // (RFC 6482 §3.3 encodes the prefix as a BIT STRING of its length).
    let prefix = Prefix::new(addr, prefix_len).ok_or_else(|| bad.clone())?;
    // RFC 8210 §5.1: Max Length "MUST NOT be less than the Prefix Length
    // element"; §5.6, §5.7: it is "0..32" ("0..128"). Vrp::new enforces
    // both.
    let vrp = Vrp::new(prefix, max_len, asn).map_err(|_| bad)?;
    Ok(Pdu::Prefix {
        version,
        // RFC 8210 §5.1: the lowest-order Flags bit is 1 for an
        // announcement and 0 for a withdrawal; the other bits "MUST be
        // ignored on receipt". RFC 6810 §5 lets version 0 ignore them too.
        // NOTE(interop): rtrlib rejects Flags other than 0 and 1 as
        // Corrupt Data; BIRD, like this code, reads bit 0 only.
        announce: flags & 1 == 1,
        vrp,
    })
}

/// The body of a Router Key PDU (RFC 8210 §5.10), whose Flags are the
/// high octet of the header `field`. Only its length is checked: path
/// validation with router keys (RFC 8205) is out of scope, so the key is
/// not interpreted.
fn decode_router_key(body: &mut Body<'_>, field: u16) -> Result<Pdu, RtrError> {
    // RFC 8210 §5: the "zero" octet is ignored on receipt.
    let [flags, _zero] = field.to_be_bytes();
    let ski = body.array()?;
    let asn = Asn(body.u32()?);
    // Header::check bounded the Length by MAX_PDU_LEN, so the key fits.
    Ok(Pdu::RouterKey(RouterKey {
        // RFC 8210 §5.1: bit 0 announces or withdraws; the rest is ignored.
        announce: flags & 1 == 1,
        ski,
        asn,
        spki: body.r.rest().to_vec(),
    }))
}

/// The body of an Error Report PDU (RFC 8210 §5.11), whose Error Code is
/// the header `field`. Both inner lengths are bounded by what the PDU's
/// Length leaves for them.
fn decode_error_report(body: &mut Body<'_>, version: Version, field: u16) -> Result<Pdu, RtrError> {
    let pdu_len = body.u32()?;
    // The encapsulated PDU must leave room for the 4-octet Length of Error
    // Text that follows it.
    let room = body.r.remaining().saturating_sub(4);
    let n = usize::try_from(pdu_len).unwrap_or(usize::MAX);
    if n > room {
        return Err(RtrError::EncapsulatedPduOverrun {
            length: pdu_len,
            room,
        });
    }
    let pdu = body.take(n)?;
    let text_len = body.u32()?;
    // The text runs to the end of the PDU: neither past it nor short of it.
    let room = body.r.remaining();
    if usize::try_from(text_len).ok() != Some(room) {
        return Err(RtrError::ErrorTextLength {
            length: text_len,
            room,
        });
    }
    // RFC 8210 §5.11: the text "MUST be a string in UTF-8 encoding".
    let text = std::str::from_utf8(body.r.rest()).map_err(|_| RtrError::ErrorTextNotUtf8)?;
    // Header::check bounded the Length by MAX_PDU_LEN, so both parts fit.
    Ok(Pdu::ErrorReport(ErrorReport {
        version,
        code: ErrorCode::from_u16(field),
        pdu: pdu.to_vec(),
        text: text.to_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
    }

    fn spki() -> Vec<u8> {
        // The shape of an RFC 8208 ECDSA P-256 SubjectPublicKeyInfo: a
        // 91-octet DER SEQUENCE. The contents do not matter here.
        let mut k = vec![0x30, 0x59];
        k.resize(91, 0xab);
        k
    }

    fn error_report(version: Version, code: ErrorCode, pdu: &[u8], text: &str) -> Pdu {
        Pdu::ErrorReport(ErrorReport::new(version, code, pdu, text))
    }

    /// One PDU of every type and version, laid out row by row as in the
    /// figures of RFC 8210 §5 (version 1) and RFC 6810 §5 (version 0),
    /// with the value it decodes to.
    fn rfc_vectors() -> Vec<(Vec<u8>, Pdu)> {
        let mut v = Vec::new();
        for (version, ver) in [(Version::V0, 0u8), (Version::V1, 1)] {
            // §5.2 Serial Notify: Session ID 0x1234, Length=12, Serial.
            v.push((
                vec![ver, 0, 0x12, 0x34, 0, 0, 0, 12, 0xde, 0xad, 0xbe, 0xef],
                Pdu::SerialNotify {
                    version,
                    session_id: 0x1234,
                    serial: 0xdead_beef,
                },
            ));
            // §5.3 Serial Query.
            v.push((
                vec![ver, 1, 0xab, 0xcd, 0, 0, 0, 12, 0, 0, 0, 42],
                Pdu::SerialQuery {
                    version,
                    session_id: 0xabcd,
                    serial: 42,
                },
            ));
            // §5.4 Reset Query: zero, Length=8.
            v.push((vec![ver, 2, 0, 0, 0, 0, 0, 8], Pdu::ResetQuery { version }));
            // §5.5 Cache Response: Session ID, Length=8.
            v.push((
                vec![ver, 3, 0x12, 0x34, 0, 0, 0, 8],
                Pdu::CacheResponse {
                    version,
                    session_id: 0x1234,
                },
            ));
            // §5.6 IPv4 Prefix: zero, Length=20, Flags (announce), Prefix
            // Length 24, Max Length 32, zero, 192.0.2.0, AS64496.
            v.push((
                vec![
                    ver, 4, 0, 0, 0, 0, 0, 20, 1, 24, 32, 0, 192, 0, 2, 0, 0, 0, 0xfb, 0xf0,
                ],
                Pdu::Prefix {
                    version,
                    announce: true,
                    vrp: vrp("192.0.2.0/24", 32, 64_496),
                },
            ));
            // §5.7 IPv6 Prefix: zero, Length=32, Flags (withdraw), Prefix
            // Length 32, Max Length 48, zero, 2001:db8::, AS4200000000.
            v.push((
                vec![
                    ver, 6, 0, 0, 0, 0, 0, 32, 0, 32, 48, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0xfa, 0x56, 0xea, 0x00,
                ],
                Pdu::Prefix {
                    version,
                    announce: false,
                    vrp: vrp("2001:db8::/32", 48, 4_200_000_000),
                },
            ));
            // §5.9 Cache Reset: zero, Length=8.
            v.push((vec![ver, 8, 0, 0, 0, 0, 0, 8], Pdu::CacheReset { version }));
            // §5.11 Error Report: Error Code 7, Length, Length of
            // Encapsulated PDU 8, a Reset Query, Length of Error Text 3,
            // "dup".
            v.push((
                vec![
                    ver, 10, 0, 7, 0, 0, 0, 27, 0, 0, 0, 8, ver, 2, 0, 0, 0, 0, 0, 8, 0, 0, 0, 3,
                    b'd', b'u', b'p',
                ],
                error_report(
                    version,
                    ErrorCode::DuplicateAnnouncementReceived,
                    &[ver, 2, 0, 0, 0, 0, 0, 8],
                    "dup",
                ),
            ));
            // §5.11 with neither PDU nor text (a generic error).
            v.push((
                vec![ver, 10, 0, 1, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0],
                error_report(version, ErrorCode::InternalError, &[], ""),
            ));
        }
        // RFC 6810 §5.8 End of Data: Session ID, Length=12, Serial.
        v.push((
            vec![0, 7, 0x12, 0x34, 0, 0, 0, 12, 0, 0, 1, 0],
            Pdu::EndOfData {
                session_id: 0x1234,
                serial: 256,
                intervals: None,
            },
        ));
        // RFC 8210 §5.8 End of Data: Session ID, Length=24, Serial, then
        // Refresh 3600, Retry 600, Expire 7200.
        v.push((
            vec![
                1, 7, 0x12, 0x34, 0, 0, 0, 24, 0, 0, 1, 0, 0, 0, 0x0e, 0x10, 0, 0, 0x02, 0x58, 0,
                0, 0x1c, 0x20,
            ],
            Pdu::EndOfData {
                session_id: 0x1234,
                serial: 256,
                intervals: Some(Intervals::DEFAULT),
            },
        ));
        // RFC 8210 §5.10 Router Key: Flags (announce), zero, Length 123,
        // the 20-octet SKI, AS64496, the key.
        let mut rk = vec![1, 9, 1, 0, 0, 0, 0, 123];
        rk.extend(1..=20u8);
        rk.extend([0, 0, 0xfb, 0xf0]);
        rk.extend(spki());
        let ski: [u8; 20] = std::array::from_fn(|i| u8::try_from(i + 1).unwrap());
        v.push((
            rk,
            Pdu::RouterKey(RouterKey::new(true, ski, Asn(64_496), spki()).unwrap()),
        ));
        v
    }

    #[test]
    fn rfc_figures_decode_and_encode() {
        for (bytes, pdu) in rfc_vectors() {
            assert_eq!(Pdu::decode(&bytes), Ok(pdu.clone()), "{pdu:?}");
            assert_eq!(pdu.encode(), bytes, "{pdu:?}");
            assert_eq!(usize::from(bytes[7]), bytes.len());
            assert_eq!(pdu.version().to_u8(), bytes[0]);
            assert_eq!(pdu.pdu_type().to_u8(), bytes[1]);
        }
    }

    #[test]
    fn encode_into_appends() {
        let mut out = vec![0xff];
        Pdu::ResetQuery {
            version: Version::V1,
        }
        .encode_into(&mut out);
        Pdu::CacheReset {
            version: Version::V0,
        }
        .encode_into(&mut out);
        assert_eq!(out, [0xff, 1, 2, 0, 0, 0, 0, 0, 8, 0, 8, 0, 0, 0, 0, 0, 8]);
    }

    #[test]
    fn unknown_versions_are_unsupported() {
        // RFC 8210 §7, §12 code 4: checked before anything else, so even a
        // Length that would be wrong is not looked at.
        for version in [2, 3, 255] {
            for pdu_type in [0, 2, 10, 200] {
                let e = Pdu::decode(&[version, pdu_type, 0, 0, 0, 0, 0, 3]).unwrap_err();
                assert_eq!(e, RtrError::UnsupportedVersion { version, pdu_type });
                assert_eq!(e.code(), ErrorCode::UnsupportedProtocolVersion);
            }
        }
    }

    #[test]
    fn unknown_types_are_unsupported() {
        // RFC 8210 §14: 5 is unassigned and 255 reserved in both versions;
        // 9 (Router Key) is reserved in version 0; 11..=254 unassigned.
        for (ver, version) in [(0, Version::V0), (1, Version::V1)] {
            for pdu_type in [5, 11, 100, 254, 255] {
                let e = Pdu::decode(&[ver, pdu_type, 0, 0, 0, 0, 0, 8]).unwrap_err();
                assert_eq!(e, RtrError::UnsupportedPduType { version, pdu_type });
                assert_eq!(e.code(), ErrorCode::UnsupportedPduType);
            }
        }
        let mut rk = vec![0, 9, 1, 0, 0, 0, 0, 32];
        rk.resize(32, 0);
        assert_eq!(
            Pdu::decode(&rk),
            Err(RtrError::UnsupportedPduType {
                version: Version::V0,
                pdu_type: 9
            })
        );
        rk[0] = 1;
        assert!(matches!(Pdu::decode(&rk), Ok(Pdu::RouterKey(_))));
    }

    #[test]
    fn negotiated_version_is_checked_first() {
        // RFC 8210 §7: after negotiation, a PDU of any other version, known
        // or not, is Unexpected Protocol Version (§12 code 8).
        for (bytes, pdu) in rfc_vectors() {
            let version = pdu.version();
            assert_eq!(Pdu::decode_negotiated(&bytes, version), Ok(pdu.clone()));
            for other in [Version::V0, Version::V1] {
                if other == version {
                    continue;
                }
                let e = Pdu::decode_negotiated(&bytes, other).unwrap_err();
                assert_eq!(
                    e,
                    RtrError::UnexpectedVersion {
                        expected: other,
                        version: version.to_u8(),
                        pdu_type: bytes[1],
                    }
                );
                assert_eq!(e.code(), ErrorCode::UnexpectedProtocolVersion);
                // §7: "unless the PDU ... was itself an Error Report PDU".
                assert_eq!(e.may_report(), bytes[1] != 10);
            }
        }
        // Before anything else: a version 0 Router Key in a version 1
        // session is not an unknown type, nor is a garbage Length looked
        // at; an unknown version is unexpected rather than unsupported.
        let e = Pdu::decode_negotiated(&[0, 9, 0, 0, 0, 0, 0, 1], Version::V1).unwrap_err();
        assert_eq!(e.code(), ErrorCode::UnexpectedProtocolVersion);
        let e = Pdu::decode_negotiated(&[2, 0, 0, 0, 0, 0, 0, 12], Version::V0).unwrap_err();
        assert_eq!(
            e,
            RtrError::UnexpectedVersion {
                expected: Version::V0,
                version: 2,
                pdu_type: 0
            }
        );
    }

    #[test]
    fn every_type_has_its_length() {
        // (version, type, smallest legal Length, largest legal Length).
        let max = MAX_PDU_LEN;
        let cases = [
            (0, 0, 12, 12),
            (0, 1, 12, 12),
            (0, 2, 8, 8),
            (0, 3, 8, 8),
            (0, 4, 20, 20),
            (0, 6, 32, 32),
            (0, 7, 12, 12),
            (0, 8, 8, 8),
            (0, 10, 16, max),
            (1, 0, 12, 12),
            (1, 1, 12, 12),
            (1, 2, 8, 8),
            (1, 3, 8, 8),
            (1, 4, 20, 20),
            (1, 6, 32, 32),
            (1, 7, 24, 24),
            (1, 8, 8, 8),
            (1, 9, 32, max),
            (1, 10, 16, max),
        ];
        for (ver, ty, min, hi) in cases {
            let header = |length: u32| {
                let mut b = vec![ver, ty, 0, 0];
                b.extend(length.to_be_bytes());
                b
            };
            for length in [0, 7, 8, min - 1, hi + 1, u32::MAX] {
                if (min..=hi).contains(&length) {
                    continue;
                }
                let e = Pdu::decode(&header(length)).unwrap_err();
                let expected = if length < min {
                    RtrError::TooShort {
                        pdu_type: ty,
                        length,
                        min,
                    }
                } else {
                    RtrError::TooLong {
                        pdu_type: ty,
                        length,
                        max: hi,
                    }
                };
                assert_eq!(e, expected, "version {ver} type {ty} length {length}");
                assert_eq!(e.code(), ErrorCode::CorruptData);
            }
        }
    }

    #[test]
    fn end_of_data_length_follows_the_version() {
        // RFC 6810 §5.8: 12 octets in version 0; RFC 8210 §5.8: 24 in 1.
        let v1 = Pdu::EndOfData {
            session_id: 1,
            serial: 2,
            intervals: Some(Intervals::DEFAULT),
        }
        .encode();
        let mut as_v0 = v1.clone();
        as_v0[0] = 0;
        assert_eq!(
            Pdu::decode(&as_v0),
            Err(RtrError::TooLong {
                pdu_type: 7,
                length: 24,
                max: 12
            })
        );
        let v0 = Pdu::EndOfData {
            session_id: 1,
            serial: 2,
            intervals: None,
        }
        .encode();
        let mut as_v1 = v0.clone();
        as_v1[0] = 1;
        assert_eq!(
            Pdu::decode(&as_v1),
            Err(RtrError::TooShort {
                pdu_type: 7,
                length: 12,
                min: 24
            })
        );
        assert_eq!(Pdu::decode(&v0).unwrap().version(), Version::V0);
        assert_eq!(Pdu::decode(&v1).unwrap().version(), Version::V1);
    }

    #[test]
    fn slice_must_match_the_length_field() {
        let bytes = Pdu::SerialQuery {
            version: Version::V1,
            session_id: 7,
            serial: 9,
        }
        .encode();
        assert_eq!(
            Pdu::decode(&bytes[..11]),
            Err(RtrError::Truncated {
                pdu_type: Some(1),
                need: 12,
                have: 11
            })
        );
        assert_eq!(
            Pdu::decode(&bytes[..1]),
            Err(RtrError::Truncated {
                pdu_type: None,
                need: 8,
                have: 1
            })
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            Pdu::decode(&long),
            Err(RtrError::TrailingData {
                pdu_type: 1,
                length: 12,
                have: 13
            })
        );
    }

    #[test]
    fn reserved_fields_are_ignored() {
        // RFC 8210 §5: "zero" fields "MUST be ignored on receipt"; §5.1:
        // the Flags bits other than bit 0 likewise. RFC 6810 §5.1 says the
        // same of version 0.
        for (bytes, pdu) in rfc_vectors() {
            let mut noisy = bytes.clone();
            match bytes[1] {
                // The header field of Reset Query and Cache Reset.
                2 | 8 => noisy[2..4].copy_from_slice(&[0xff, 0xff]),
                // Prefix PDUs: the header field, Flags bits 1–7 and the
                // zero octet.
                4 | 6 => {
                    noisy[2..4].copy_from_slice(&[0xff, 0xff]);
                    noisy[8] |= 0xfe;
                    noisy[11] = 0xff;
                }
                // Router Key: Flags bits 1–7 and the zero octet.
                9 => {
                    noisy[2] |= 0xfe;
                    noisy[3] = 0xff;
                }
                _ => continue,
            }
            assert_eq!(Pdu::decode(&noisy), Ok(pdu.clone()), "{pdu:?}");
            // And they go out as zero again.
            assert_eq!(pdu.encode(), bytes);
        }
    }

    #[test]
    fn flags_bit_zero_announces() {
        // RFC 8210 §5.1: "1 for an announcement and 0 for a withdrawal".
        for (flags, announce) in [(0u8, false), (1, true), (2, false), (0xff, true)] {
            let mut b = vec![
                1, 4, 0, 0, 0, 0, 0, 20, flags, 8, 8, 0, 10, 0, 0, 0, 0, 0, 0, 1,
            ];
            assert!(
                matches!(Pdu::decode(&b), Ok(Pdu::Prefix { announce: a, .. }) if a == announce),
                "flags {flags:#x}"
            );
            b[1] = 9;
            b.resize(32, 0);
            b[2] = flags;
            b[3] = 0;
            b[7] = 32;
            assert!(
                matches!(Pdu::decode(&b), Ok(Pdu::RouterKey(k)) if k.announce() == announce),
                "flags {flags:#x}"
            );
        }
    }

    fn prefix_pdu(ty: u8, prefix_len: u8, max_len: u8) -> Vec<u8> {
        let mut b = vec![1, ty, 0, 0, 0, 0, 0, 0, 1, prefix_len, max_len, 0];
        b.resize(if ty == 4 { 16 } else { 28 }, 0);
        b.extend(64_496u32.to_be_bytes());
        b[7] = u8::try_from(b.len()).unwrap();
        b
    }

    #[test]
    fn prefix_lengths_are_bounded() {
        for (ty, bits) in [(4u8, 32u8), (6, 128)] {
            // RFC 8210 §5.6, §5.7: both lengths are 0..32 (0..128); §5.1:
            // Max Length is not less than Prefix Length.
            for (prefix_len, max_len) in [
                (bits + 1, bits + 1),
                (0, bits + 1),
                (bits, bits - 1),
                (9, 8),
                (u8::MAX, u8::MAX),
            ] {
                let e = Pdu::decode(&prefix_pdu(ty, prefix_len, max_len)).unwrap_err();
                assert_eq!(
                    e,
                    RtrError::BadPrefixLength {
                        pdu_type: ty,
                        prefix_len,
                        max_len
                    }
                );
                assert_eq!(e.code(), ErrorCode::CorruptData);
            }
            for (prefix_len, max_len) in [(0, 0), (0, bits), (bits, bits), (8, 8), (8, 9)] {
                let Ok(Pdu::Prefix { vrp, .. }) = Pdu::decode(&prefix_pdu(ty, prefix_len, max_len))
                else {
                    panic!("type {ty} {prefix_len}-{max_len}");
                };
                assert_eq!(vrp.prefix().prefix_len(), prefix_len);
                assert_eq!(vrp.max_len(), max_len);
            }
        }
    }

    #[test]
    fn host_bits_are_cleared() {
        // 192.0.2.1/24 is read as 192.0.2.0/24 and goes out canonically.
        let mut b = Pdu::Prefix {
            version: Version::V1,
            announce: true,
            vrp: vrp("192.0.2.0/24", 24, 64_496),
        }
        .encode();
        let canonical = b.clone();
        b[15] = 1;
        let pdu = Pdu::decode(&b).unwrap();
        assert_eq!(
            pdu,
            Pdu::Prefix {
                version: Version::V1,
                announce: true,
                vrp: vrp("192.0.2.0/24", 24, 64_496),
            }
        );
        assert_eq!(pdu.encode(), canonical);
    }

    #[test]
    fn as0_vrps_decode() {
        // RFC 6483 §4: an AS 0 ROA is legal; RFC 7607 does not forbid it
        // here, so the PDU is not corrupt.
        let pdu = Pdu::Prefix {
            version: Version::V1,
            announce: true,
            vrp: vrp("2001:db8::/32", 128, 0),
        };
        assert_eq!(Pdu::decode(&pdu.encode()), Ok(pdu));
    }

    fn error_report_bytes(pdu_len: u32, pdu: &[u8], text_len: u32, text: &[u8]) -> Vec<u8> {
        let mut b = vec![1, 10, 0, 0, 0, 0, 0, 0];
        b.put_u32(pdu_len);
        b.put_bytes(pdu);
        b.put_u32(text_len);
        b.put_bytes(text);
        let length = u32::try_from(b.len()).unwrap();
        b[4..8].copy_from_slice(&length.to_be_bytes());
        b
    }

    #[test]
    fn error_report_lengths_are_bounded() {
        // RFC 8210 §5.11: Length of Encapsulated PDU and Length of Error
        // Text must both fit in the PDU, and together fill it.
        let ok = error_report_bytes(2, &[1, 2], 2, b"hi");
        assert_eq!(
            Pdu::decode(&ok),
            Ok(error_report(
                Version::V1,
                ErrorCode::CorruptData,
                &[1, 2],
                "hi"
            ))
        );
        // The encapsulated PDU runs into the text length field: 8 octets
        // follow the field, and 4 of them are the Length of Error Text.
        assert_eq!(
            Pdu::decode(&error_report_bytes(5, &[1, 2], 2, b"hi")),
            Err(RtrError::EncapsulatedPduOverrun { length: 5, room: 4 })
        );
        // Exactly 4 fits, so the error shows up in the text length: it is
        // read from the octets 0, 2, 'h', 'i', and nothing is left for it.
        assert_eq!(
            Pdu::decode(&error_report_bytes(4, &[1, 2], 2, b"hi")),
            Err(RtrError::ErrorTextLength {
                length: u32::from_be_bytes([0, 2, b'h', b'i']),
                room: 0
            })
        );
        assert_eq!(
            Pdu::decode(&error_report_bytes(u32::MAX, &[1, 2], 2, b"hi")),
            Err(RtrError::EncapsulatedPduOverrun {
                length: u32::MAX,
                room: 4
            })
        );
        // The text runs past the end, or stops short of it.
        assert_eq!(
            Pdu::decode(&error_report_bytes(2, &[1, 2], 3, b"hi")),
            Err(RtrError::ErrorTextLength { length: 3, room: 2 })
        );
        assert_eq!(
            Pdu::decode(&error_report_bytes(2, &[1, 2], 1, b"hi")),
            Err(RtrError::ErrorTextLength { length: 1, room: 2 })
        );
        assert_eq!(
            Pdu::decode(&error_report_bytes(2, &[1, 2], u32::MAX, b"hi")),
            Err(RtrError::ErrorTextLength {
                length: u32::MAX,
                room: 2
            })
        );
        // RFC 8210 §5.11: the text "MUST be a string in UTF-8 encoding".
        let e = Pdu::decode(&error_report_bytes(0, &[], 2, &[0xc3, 0x28])).unwrap_err();
        assert_eq!(e, RtrError::ErrorTextNotUtf8);
        assert!(!e.may_report());
        // UTF-8 beyond ASCII is fine.
        assert!(Pdu::decode(&error_report_bytes(0, &[], 3, "é!".as_bytes())).is_ok());
        // Unknown error codes are carried, not rejected.
        let mut b = error_report_bytes(0, &[], 0, b"");
        b[2..4].copy_from_slice(&999u16.to_be_bytes());
        let Ok(Pdu::ErrorReport(e)) = Pdu::decode(&b) else {
            panic!("unknown code");
        };
        assert_eq!(e.code(), ErrorCode::Unknown(999));
    }

    #[test]
    fn error_report_new_fits_the_limit() {
        let room = MAX_PDU_USIZE - ERROR_REPORT_FIXED_LEN;
        // Short parts are kept whole.
        let e = ErrorReport::new(Version::V1, ErrorCode::CorruptData, &[1, 2, 3], "text");
        assert_eq!(e.erroneous_pdu(), &[1, 2, 3]);
        assert_eq!(e.text(), "text");
        assert_eq!(e.version(), Version::V1);
        assert_eq!(e.code(), ErrorCode::CorruptData);
        // An oversize PDU is truncated to leave the text whole.
        let big = vec![7u8; MAX_PDU_USIZE * 2];
        let e = ErrorReport::new(Version::V1, ErrorCode::CorruptData, &big, "why");
        assert_eq!(e.text(), "why");
        assert_eq!(e.erroneous_pdu().len(), room - 3);
        let bytes = Pdu::ErrorReport(e.clone()).encode();
        assert_eq!(bytes.len(), MAX_PDU_USIZE);
        assert_eq!(Pdu::decode(&bytes), Ok(Pdu::ErrorReport(e)));
        // Oversize text is cut at a character boundary, and then there is
        // no room for the PDU.
        let text = "é".repeat(MAX_PDU_USIZE);
        let e = ErrorReport::new(Version::V0, ErrorCode::InternalError, &[1], &text);
        assert_eq!(e.erroneous_pdu(), b"");
        assert_eq!(e.text().len(), room - room % 2);
        assert!(e.text().chars().all(|c| c == 'é'));
        let bytes = Pdu::ErrorReport(e.clone()).encode();
        assert!(bytes.len() <= MAX_PDU_USIZE);
        assert_eq!(Pdu::decode(&bytes), Ok(Pdu::ErrorReport(e)));
    }

    #[test]
    fn router_key_new_fits_the_limit() {
        let max = MAX_PDU_USIZE - ROUTER_KEY_FIXED_LEN;
        let k = RouterKey::new(false, [9; 20], Asn(65_000), vec![1; max]).unwrap();
        assert!(!k.announce());
        assert_eq!(k.ski(), [9; 20]);
        assert_eq!(k.asn(), Asn(65_000));
        assert_eq!(k.spki().len(), max);
        let bytes = Pdu::RouterKey(k.clone()).encode();
        assert_eq!(bytes.len(), MAX_PDU_USIZE);
        assert_eq!(Pdu::decode(&bytes), Ok(Pdu::RouterKey(k)));
        assert_eq!(
            RouterKey::new(true, [0; 20], Asn(1), vec![1; max + 1]),
            None
        );
        // The shortest Router Key has no key at all; only the length is
        // checked.
        let k = RouterKey::new(true, [0; 20], Asn(1), Vec::new()).unwrap();
        assert_eq!(Pdu::RouterKey(k).encode().len(), ROUTER_KEY_FIXED_LEN);
    }

    #[test]
    fn intervals_limits() {
        // RFC 8210 §6.
        assert!(Intervals::DEFAULT.within_limits());
        assert_eq!(Intervals::default(), Intervals::DEFAULT);
        let at = |refresh, retry, expire| {
            Intervals {
                refresh,
                retry,
                expire,
            }
            .within_limits()
        };
        assert!(at(1, 1, 600));
        assert!(at(86_400, 7_200, 172_800));
        assert!(!at(0, 600, 7_200));
        assert!(!at(86_401, 600, 172_800));
        assert!(!at(3_600, 0, 7_200));
        assert!(!at(3_600, 7_201, 7_200));
        assert!(!at(3_600, 600, 599));
        assert!(!at(3_600, 600, 172_801));
        // "larger than either Refresh Interval or Retry Interval".
        assert!(!at(7_200, 600, 7_200));
        assert!(!at(600, 600, 600));
    }

    #[test]
    fn types_and_versions_round_trip() {
        for version in Version::ALL {
            assert_eq!(Version::from_u8(version.to_u8()), Some(version));
            assert_eq!(version.to_string(), version.to_u8().to_string());
        }
        assert_eq!(Version::from_u8(2), None);
        for v in 0..=u8::MAX {
            for version in Version::ALL {
                if let Some(t) = PduType::from_u8(v, version) {
                    assert_eq!(t.to_u8(), v);
                    assert_eq!(t.to_string(), t.name());
                }
            }
        }
    }

    /// Octet values to try at each offset: all of them natively, a few
    /// under Miri, which is too slow for the whole range.
    fn garbage_values(original: u8) -> Vec<u8> {
        if cfg!(miri) {
            vec![
                0,
                1,
                0x7f,
                0x80,
                0xff,
                original ^ 1,
                original.wrapping_add(1),
            ]
        } else {
            (0..=u8::MAX).collect()
        }
    }

    #[test]
    fn truncation_at_every_offset_is_an_error() {
        for (bytes, _) in rfc_vectors() {
            for end in 0..bytes.len() {
                let e = Pdu::decode(&bytes[..end]).unwrap_err();
                assert_eq!(e.code(), ErrorCode::CorruptData, "{bytes:?} cut at {end}");
                assert!(
                    matches!(e, RtrError::Truncated { .. } | RtrError::TooShort { .. }),
                    "{e:?}"
                );
            }
        }
    }

    #[test]
    fn garbage_at_every_offset_never_panics() {
        for (bytes, _) in rfc_vectors() {
            for at in 0..bytes.len() {
                for v in garbage_values(bytes[at]) {
                    let mut b = bytes.clone();
                    b[at] = v;
                    if let Ok(pdu) = Pdu::decode(&b) {
                        // Whatever is accepted re-encodes canonically.
                        let again = pdu.encode();
                        assert_eq!(Pdu::decode(&again), Ok(pdu));
                        assert_eq!(again.len(), b.len());
                    }
                }
            }
        }
    }
}
