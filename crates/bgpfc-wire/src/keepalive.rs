//! The KEEPALIVE message.
//!
//! Implements: RFC 4271 §4.4 (a KEEPALIVE is the 19-octet header alone).
//! The timing rules of §4.4 (at most one per second, none when the Hold
//! Time is zero) belong to the FSM.

use crate::header::{HEADER_LEN, MessageType};

/// A complete KEEPALIVE message as sent on the wire: the marker, length 19
/// and type 4 (RFC 4271 §4.4). It has no body, so there is nothing to
/// decode; the header decoder's exact-19 check (§6.1) is the whole check.
pub const KEEPALIVE: [u8; HEADER_LEN] = {
    let mut m = [0xff; HEADER_LEN];
    m[16] = 0;
    m[17] = 19;
    m[18] = MessageType::Keepalive as u8;
    m
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, MARKER, frame};

    #[test]
    fn keepalive_is_the_bare_header() {
        assert_eq!(&KEEPALIVE[..16], &MARKER);
        assert_eq!(
            KEEPALIVE,
            frame(MessageType::Keepalive, &[]).unwrap().as_slice()
        );
        let h = Header::decode(&KEEPALIVE, false).unwrap();
        assert_eq!(h.kind, MessageType::Keepalive);
        assert_eq!(h.body_len(), 0);
    }
}
