//! The ROUTE-REFRESH message.
//!
//! Implements: RFC 2918 §3 (format: one `<AFI, Res, SAFI>`); RFC 7313 §3.2
//! (the Reserved octet is the Message Subtype: 0 a normal request, 1 the
//! beginning of a route refresh, 2 its end), §5 (a ROUTE-REFRESH of
//! subtype 1 or 2 whose length is not four octets is a ROUTE-REFRESH
//! Message Error). The §4 rules on when to send one and what to do on
//! receipt belong to the RIB.

use crate::error::{DecodeError, HeaderSubcode, RouteRefreshSubcode};
use crate::header::{HEADER_LEN, MessageType, frame};
use crate::reader::{Reader, WriteBytes as _};
use crate::types::{AddressFamily, Afi, Safi};

/// Length of the ROUTE-REFRESH body (RFC 2918 §3).
pub const ROUTE_REFRESH_LEN: usize = 4;

/// Where the Message Subtype sits in the body: after the AFI (RFC 7313
/// §3.2, which redefines the Reserved octet of RFC 2918 §3).
const SUBTYPE_AT: usize = 2;

/// The Message Subtype of a ROUTE-REFRESH (RFC 7313 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefreshSubtype {
    /// 0: a normal route refresh request (RFC 2918 §3, RFC 5291).
    Request,
    /// 1: the beginning of a route refresh operation, `BoRR` (RFC 7313 §3.2).
    BeginOfRefresh,
    /// 2: the end of a route refresh operation, `EoRR` (RFC 7313 §3.2).
    EndOfRefresh,
    /// Any other value: 255 is reserved and the rest unassigned (RFC 7313
    /// §3.2, §6). A speaker that has the capability ignores such a message
    /// (§5).
    Unknown(u8),
}

impl RefreshSubtype {
    /// From the wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => RefreshSubtype::Request,
            1 => RefreshSubtype::BeginOfRefresh,
            2 => RefreshSubtype::EndOfRefresh,
            v => RefreshSubtype::Unknown(v),
        }
    }

    /// Wire value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            RefreshSubtype::Request => 0,
            RefreshSubtype::BeginOfRefresh => 1,
            RefreshSubtype::EndOfRefresh => 2,
            RefreshSubtype::Unknown(v) => v,
        }
    }
}

/// A ROUTE-REFRESH message body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    /// The `<AFI, SAFI>` whose Adj-RIB-Out the sender wants re-advertised,
    /// or whose re-advertisement the message begins or ends.
    pub family: AddressFamily,
    /// What the message is (RFC 7313 §3.2).
    pub subtype: RefreshSubtype,
}

impl RouteRefreshMessage {
    /// A request for `family` (RFC 2918 §3).
    #[must_use]
    pub const fn request(family: AddressFamily) -> Self {
        RouteRefreshMessage {
            family,
            subtype: RefreshSubtype::Request,
        }
    }

    /// The `BoRR` that begins a route refresh of `family` (RFC 7313 §4).
    #[must_use]
    pub const fn begin(family: AddressFamily) -> Self {
        RouteRefreshMessage {
            family,
            subtype: RefreshSubtype::BeginOfRefresh,
        }
    }

    /// The `EoRR` that ends a route refresh of `family` (RFC 7313 §4).
    #[must_use]
    pub const fn end(family: AddressFamily) -> Self {
        RouteRefreshMessage {
            family,
            subtype: RefreshSubtype::EndOfRefresh,
        }
    }

    /// Encode the body: AFI, Message Subtype, SAFI (RFC 7313 §3.2; RFC 2918
    /// §3 has a zero Reserved octet where the subtype is).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROUTE_REFRESH_LEN);
        out.put_u16(self.family.afi.to_u16());
        out.put_u8(self.subtype.to_u8());
        out.put_u8(self.family.safi.to_u8());
        out
    }

    /// The whole message, header included, ready to write.
    ///
    /// # Panics
    /// Never: a header and four octets are 23 octets, far below any length
    /// limit.
    #[must_use]
    pub fn frame(&self) -> Vec<u8> {
        // invariant: see `# Panics`.
        frame(MessageType::RouteRefresh, &self.encode()).unwrap()
    }

    /// Decode a body. `echo` is `Some` when RFC 7313 applies to the
    /// session, because both sides advertised Enhanced Route Refresh, and
    /// then the most octets of Data a NOTIFICATION to the peer can carry
    /// ([`max_data_len`](crate::notification::max_data_len)). Either way
    /// the subtype is read and handed on; it is for the caller to read
    /// every message as a request when `echo` is `None`, as RFC 2918 §3 has
    /// a receiver ignore the Reserved octet.
    ///
    /// # Errors
    /// With `echo`, a message of subtype 1 or 2 whose body is not four
    /// octets is ROUTE-REFRESH Message Error / Invalid Message Length, the
    /// Data field being the complete message, header included (RFC 7313
    /// §5); a message too long for a NOTIFICATION to hold is cut at what it
    /// holds, `echo` octets. Any other body that is not four octets is Bad
    /// Message Length (Data: the message's Length field): RFC 2918 fixes the
    /// size and RFC 4271 §4.1 lets a type constrain its Length, but neither
    /// names an error for it. A subtype 0 message may be longer with
    /// Outbound Route Filtering (RFC 5291), which this implementation does
    /// not advertise.
    pub fn decode(body: &[u8], echo: Option<usize>) -> Result<Self, DecodeError> {
        if body.len() != ROUTE_REFRESH_LEN {
            // RFC 7313 §5: "The error handling specified in this section is
            // applicable only when a BGP speaker has received the Enhanced
            // Route Refresh Capability from a peer", and the length rule is
            // for "Message Subtype 1 and 2", which a body that stops short
            // of the subtype octet does not show.
            let subtype = body.get(SUBTYPE_AT).map(|v| RefreshSubtype::from_u8(*v));
            if let Some(room) = echo
                && matches!(
                    subtype,
                    Some(RefreshSubtype::BeginOfRefresh | RefreshSubtype::EndOfRefresh)
                )
            {
                return Err(DecodeError::route_refresh(
                    RouteRefreshSubcode::InvalidMessageLength,
                    complete(body, room),
                ));
            }
            let total = u16::try_from(body.len() + HEADER_LEN).unwrap_or(u16::MAX);
            return Err(DecodeError::header(
                HeaderSubcode::BadMessageLength,
                total.to_be_bytes().to_vec(),
            ));
        }
        let mut r = Reader::new(body);
        // Exactly four octets are present, so these reads cannot fail.
        let afi = Afi::from_u16(r.u16().unwrap_or_default());
        let subtype = RefreshSubtype::from_u8(r.u8().unwrap_or_default());
        let safi = Safi::from_u8(r.u8().unwrap_or_default());
        Ok(RouteRefreshMessage {
            family: AddressFamily { afi, safi },
            subtype,
        })
    }
}

/// The message `body` came in, header included, as far as a NOTIFICATION
/// can carry it, `room` octets (RFC 7313 §5: "The Data field of the
/// NOTIFICATION message MUST contain the complete ROUTE-REFRESH message").
fn complete(body: &[u8], room: usize) -> Vec<u8> {
    let mut message = frame(MessageType::RouteRefresh, body).unwrap_or_default();
    message.truncate(room);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use crate::notification::max_data_len;

    /// Room for the whole message in a NOTIFICATION to a peer without
    /// Extended Message.
    const ROOM: Option<usize> = Some(max_data_len(false));

    #[test]
    fn route_refresh_round_trips() {
        let m = RouteRefreshMessage::request(AddressFamily::IPV6_UNICAST);
        assert_eq!(m.encode(), [0, 2, 0, 1]);
        assert_eq!(RouteRefreshMessage::decode(&[0, 2, 0, 1], None).unwrap(), m);
        assert_eq!(RouteRefreshMessage::decode(&[0, 2, 0, 1], ROOM).unwrap(), m);
        // RFC 2918 §3: the Reserved octet is ignored by the receiver, so a
        // peer without Enhanced Route Refresh is read as asking for a
        // refresh whatever it put there; the caller does that, the subtype
        // is what was on the wire.
        let odd = RouteRefreshMessage::decode(&[0, 2, 0xff, 1], None).unwrap();
        assert_eq!(odd.family, AddressFamily::IPV6_UNICAST);
        assert_eq!(odd.subtype, RefreshSubtype::Unknown(0xff));
        assert_eq!(odd.encode(), [0, 2, 0xff, 1]);
        let odd = RouteRefreshMessage::decode(&[0x40, 0, 0, 0x80], None).unwrap();
        assert_eq!(odd.family.afi, Afi::Unknown(0x4000));
        assert_eq!(odd.family.safi, Safi::Unknown(0x80));
    }

    #[test]
    fn subtypes_follow_rfc_7313() {
        // RFC 7313 §3.2: 0 request, 1 BoRR, 2 EoRR, 255 reserved, the
        // rest unassigned.
        let v4 = AddressFamily::IPV4_UNICAST;
        for (wire, subtype) in [
            (0, RefreshSubtype::Request),
            (1, RefreshSubtype::BeginOfRefresh),
            (2, RefreshSubtype::EndOfRefresh),
            (3, RefreshSubtype::Unknown(3)),
            (255, RefreshSubtype::Unknown(255)),
        ] {
            assert_eq!(RefreshSubtype::from_u8(wire), subtype);
            assert_eq!(subtype.to_u8(), wire);
            let m = RouteRefreshMessage::decode(&[0, 1, wire, 1], ROOM).unwrap();
            assert_eq!(
                m,
                RouteRefreshMessage {
                    family: v4,
                    subtype
                }
            );
            assert_eq!(m.encode(), [0, 1, wire, 1]);
        }
        assert_eq!(RouteRefreshMessage::begin(v4).encode(), [0, 1, 1, 1]);
        assert_eq!(RouteRefreshMessage::end(v4).encode(), [0, 1, 2, 1]);
        assert_eq!(RouteRefreshMessage::request(v4).encode(), [0, 1, 0, 1]);
    }

    #[test]
    fn framed_messages_are_twenty_three_octets() {
        // RFC 7313 §3.2 and RFC 2918 §3: the header (marker, Length 23,
        // type 5), then <AFI, subtype, SAFI>.
        let mut want = vec![0xff; 16];
        want.extend_from_slice(&[0, 23, 5, 0, 2, 1, 1]);
        assert_eq!(
            RouteRefreshMessage::begin(AddressFamily::IPV6_UNICAST).frame(),
            want
        );
    }

    #[test]
    fn wrong_length_is_bad_message_length_without_the_capability() {
        for body in [&[][..], &[0, 1, 0][..], &[0, 1, 0, 1, 0][..]] {
            for subtype in [0u8, 1, 2] {
                let mut body = body.to_vec();
                if body.len() > 2 {
                    body[2] = subtype;
                }
                let e = RouteRefreshMessage::decode(&body, None).unwrap_err();
                let total = u16::try_from(body.len() + HEADER_LEN).unwrap();
                assert_eq!(
                    e,
                    DecodeError::header(
                        HeaderSubcode::BadMessageLength,
                        total.to_be_bytes().to_vec()
                    )
                );
            }
        }
    }

    #[test]
    fn wrong_length_of_borr_or_eorr_is_a_route_refresh_error_with_the_capability() {
        // RFC 7313 §5: error code 7, subcode 1, "the complete ROUTE-REFRESH
        // message" as data.
        for subtype in [1u8, 2] {
            for body in [
                vec![0, 1, subtype],
                vec![0, 1, subtype, 1, 0],
                vec![0, 1, subtype, 1, 9, 9, 9, 9],
            ] {
                let e = RouteRefreshMessage::decode(&body, ROOM).unwrap_err();
                assert_eq!((e.code, e.subcode), (ErrorCode::RouteRefresh, 1));
                let mut whole = vec![0xff; 16];
                whole.extend_from_slice(&[0, u8::try_from(19 + body.len()).unwrap(), 5]);
                whole.extend_from_slice(&body);
                assert_eq!(e.data, whole);
            }
        }
    }

    #[test]
    fn wrong_length_of_other_subtypes_keeps_the_header_error_with_the_capability() {
        // RFC 7313 §5 names the length rule for subtypes 1 and 2 alone; a
        // normal request may carry ORF entries (RFC 5291), and a body too
        // short to hold a subtype shows none.
        for body in [
            &[][..],
            &[0, 1][..],
            &[0, 1, 0][..],
            &[0, 1, 0, 1, 0][..],
            &[0, 1, 3, 1, 0][..],
            &[0, 1, 255][..],
        ] {
            let e = RouteRefreshMessage::decode(body, ROOM).unwrap_err();
            let total = u16::try_from(body.len() + HEADER_LEN).unwrap();
            assert_eq!(
                e,
                DecodeError::header(
                    HeaderSubcode::BadMessageLength,
                    total.to_be_bytes().to_vec()
                )
            );
        }
    }

    #[test]
    fn a_message_too_long_to_echo_is_cut_to_what_a_notification_holds() {
        let mut body = vec![0, 1, 1, 1];
        body.resize(4000, 7);
        let e = RouteRefreshMessage::decode(&body, ROOM).unwrap_err();
        assert_eq!((e.code, e.subcode), (ErrorCode::RouteRefresh, 1));
        assert_eq!(e.data.len(), 19 + 4000);
        body.resize(5000, 7);
        // Without Extended Message, 4096 octets less the NOTIFICATION's
        // header, code and subcode (RFC 4271 §4.1).
        let e = RouteRefreshMessage::decode(&body, ROOM).unwrap_err();
        assert_eq!(e.data.len(), 4096 - 21);
        assert_eq!(&e.data[..16], &[0xff; 16]);
        // With it, the whole of a message of 5019 octets goes (RFC 8654 §5),
        // and the longest a header can announce, 65535 octets, goes but for
        // the 21 octets a NOTIFICATION needs besides.
        let big = Some(max_data_len(true));
        let e = RouteRefreshMessage::decode(&body, big).unwrap_err();
        assert_eq!(e.data.len(), 19 + 5000);
        body.resize(65_535 - 19, 7);
        let e = RouteRefreshMessage::decode(&body, big).unwrap_err();
        assert_eq!(e.data.len(), 65_535 - 21);
    }
}
