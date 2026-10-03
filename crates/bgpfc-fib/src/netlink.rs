//! Netlink message framing and attributes (`<linux/netlink.h>`,
//! `<linux/rtnetlink.h>`), pure: bytes in, bytes out, every access
//! bounds-checked. Multi-byte fields are in host byte order, as the
//! kernel expects.

use std::fmt;

/// `NLMSG_ERROR`.
pub const NLMSG_ERROR: u16 = 0x2;
/// `NLMSG_DONE`: end of a dump.
pub const NLMSG_DONE: u16 = 0x3;
/// `NLM_F_REQUEST`.
pub const NLM_F_REQUEST: u16 = 0x01;
/// `NLM_F_MULTI`: part of a multipart reply.
pub const NLM_F_MULTI: u16 = 0x02;
/// `NLM_F_ACK`: ask for an acknowledgement.
pub const NLM_F_ACK: u16 = 0x04;
/// `NLM_F_DUMP` = `NLM_F_ROOT | NLM_F_MATCH`.
pub const NLM_F_DUMP: u16 = 0x300;
/// `NLM_F_REPLACE`.
pub const NLM_F_REPLACE: u16 = 0x100;
/// `NLM_F_CREATE`.
pub const NLM_F_CREATE: u16 = 0x400;

/// `sizeof(struct nlmsghdr)`.
pub const HEADER_LEN: usize = 16;

/// `NLMSG_ALIGN` / `RTA_ALIGN`: four-byte alignment.
#[must_use]
pub const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// `struct nlmsghdr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// `nlmsg_len`: header and payload.
    pub len: u32,
    /// `nlmsg_type`.
    pub ty: u16,
    /// `nlmsg_flags`.
    pub flags: u16,
    /// `nlmsg_seq`.
    pub seq: u32,
    /// `nlmsg_pid`.
    pub pid: u32,
}

/// One message of a datagram, borrowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    /// The header.
    pub header: Header,
    /// Everything after the header, up to `nlmsg_len`.
    pub payload: &'a [u8],
}

/// A malformed datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetlinkError {
    /// Fewer bytes than a header, or a length field beyond the data.
    Truncated {
        /// Byte offset of the message.
        at: usize,
    },
    /// An attribute length below its own header or beyond the data.
    BadAttribute {
        /// Byte offset of the attribute within its payload.
        at: usize,
    },
    /// A route message payload shorter than `struct rtmsg`.
    ShortRoute,
}

impl fmt::Display for NetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetlinkError::Truncated { at } => write!(f, "truncated netlink message at offset {at}"),
            NetlinkError::BadAttribute { at } => write!(f, "bad netlink attribute at offset {at}"),
            NetlinkError::ShortRoute => f.write_str("route message shorter than struct rtmsg"),
        }
    }
}

impl std::error::Error for NetlinkError {}

/// Frame `payload` as a message with the given type, flags and sequence
/// number; `nlmsg_pid` is zero (the kernel fills in the port).
#[must_use]
pub fn encode(ty: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = align(HEADER_LEN + payload.len());
    let mut out = Vec::with_capacity(len);
    // invariant: netlink messages are far below 4 GiB.
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(len, 0);
    out
}

/// Split a datagram into messages.
///
/// # Errors
/// [`NetlinkError::Truncated`] when a length field disagrees with the
/// data (`NLMSG_OK` fails).
pub fn parse(buf: &[u8]) -> Result<Vec<Message<'_>>, NetlinkError> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let rest = &buf[at..];
        if rest.len() < HEADER_LEN {
            return Err(NetlinkError::Truncated { at });
        }
        let header = Header {
            len: u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]),
            ty: u16::from_ne_bytes([rest[4], rest[5]]),
            flags: u16::from_ne_bytes([rest[6], rest[7]]),
            seq: u32::from_ne_bytes([rest[8], rest[9], rest[10], rest[11]]),
            pid: u32::from_ne_bytes([rest[12], rest[13], rest[14], rest[15]]),
        };
        let len = usize::try_from(header.len).unwrap_or(usize::MAX);
        if len < HEADER_LEN || len > rest.len() {
            return Err(NetlinkError::Truncated { at });
        }
        out.push(Message {
            header,
            payload: &rest[HEADER_LEN..len],
        });
        at += align(len);
    }
    Ok(out)
}

/// One `struct rtattr` with its value, borrowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr<'a> {
    /// `rta_type`.
    pub ty: u16,
    /// The value, without padding.
    pub value: &'a [u8],
}

/// Parse a run of attributes.
///
/// # Errors
/// [`NetlinkError::BadAttribute`] when `RTA_OK` fails.
pub fn parse_attrs(buf: &[u8]) -> Result<Vec<Attr<'_>>, NetlinkError> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= buf.len() {
        let len = usize::from(u16::from_ne_bytes([buf[at], buf[at + 1]]));
        let ty = u16::from_ne_bytes([buf[at + 2], buf[at + 3]]);
        if len < 4 || at + len > buf.len() {
            return Err(NetlinkError::BadAttribute { at });
        }
        out.push(Attr {
            ty,
            value: &buf[at + 4..at + len],
        });
        at += align(len);
    }
    if at != buf.len() && at + 4 > buf.len() && at < buf.len() {
        return Err(NetlinkError::BadAttribute { at });
    }
    Ok(out)
}

/// Append an attribute, padded to four bytes.
pub fn push_attr(out: &mut Vec<u8>, ty: u16, value: &[u8]) {
    // invariant: callers pass addresses and integers, never 64 KiB.
    let len = u16::try_from(4 + value.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(value);
    let padded = align(out.len());
    out.resize(padded, 0);
}

/// The value of an `NLMSG_ERROR` payload: `struct nlmsgerr` starts with
/// a negative errno (zero for an ACK).
///
/// # Errors
/// [`NetlinkError::Truncated`] if shorter than four bytes.
pub fn parse_error(payload: &[u8]) -> Result<i32, NetlinkError> {
    match payload {
        [a, b, c, d, ..] => Ok(i32::from_ne_bytes([*a, *b, *c, *d])),
        _ => Err(NetlinkError::Truncated { at: 0 }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_pads_and_parse_splits() {
        let m1 = encode(24, NLM_F_REQUEST | NLM_F_ACK, 7, &[1, 2, 3]);
        assert_eq!(m1.len(), 20);
        assert_eq!(&m1[..4], &20u32.to_ne_bytes());
        let m2 = encode(NLMSG_DONE, NLM_F_MULTI, 7, &[0; 4]);
        let mut buf = m1.clone();
        buf.extend_from_slice(&m2);
        let msgs = parse(&buf).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].header.ty, 24);
        assert_eq!(msgs[0].header.seq, 7);
        assert_eq!(msgs[0].payload, &[1, 2, 3, 0]);
        assert_eq!(msgs[1].header.ty, NLMSG_DONE);
        assert_eq!(parse(&buf[..10]), Err(NetlinkError::Truncated { at: 0 }));
        let mut bad = m1;
        bad[0] = 100;
        assert_eq!(parse(&bad), Err(NetlinkError::Truncated { at: 0 }));
        assert_eq!(parse(&[]).unwrap().len(), 0);
    }

    #[test]
    fn attributes_round_trip_and_errors() {
        let mut out = Vec::new();
        push_attr(&mut out, 1, &[192, 0, 2, 0]);
        push_attr(&mut out, 6, &20u32.to_ne_bytes());
        push_attr(&mut out, 9, &[1]);
        assert_eq!(out.len(), 8 + 8 + 8);
        let attrs = parse_attrs(&out).unwrap();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].ty, 1);
        assert_eq!(attrs[0].value, &[192, 0, 2, 0]);
        assert_eq!(attrs[2].value, &[1]);
        let mut bad = out.clone();
        bad[0] = 2;
        assert_eq!(parse_attrs(&bad), Err(NetlinkError::BadAttribute { at: 0 }));
        bad[0] = 200;
        assert_eq!(parse_attrs(&bad), Err(NetlinkError::BadAttribute { at: 0 }));
        assert_eq!(
            parse_attrs(&out[..3]),
            Err(NetlinkError::BadAttribute { at: 0 })
        );
        assert_eq!(parse_error(&(-19i32).to_ne_bytes()), Ok(-19));
        assert!(parse_error(&[0, 0]).is_err());
        assert_eq!(
            NetlinkError::ShortRoute.to_string(),
            "route message shorter than struct rtmsg"
        );
    }
}
