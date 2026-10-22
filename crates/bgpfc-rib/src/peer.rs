//! What the RIB knows about a session.

use std::net::IpAddr;

use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::PeerKind;

/// The session parameters the RIB needs: who the peer is, which families
/// it speaks, and how to encode UPDATEs for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// The peer's address, which identifies it.
    pub addr: IpAddr,
    /// Our address on the session: the next hop we advertise to external
    /// peers (RFC 4271 §5.1.3).
    pub local_addr: IpAddr,
    /// The peer's AS.
    pub remote_as: Asn,
    /// The peer's BGP Identifier (RFC 4271 §9.1.2.2 g).
    pub router_id: RouterId,
    /// Internal or external session.
    pub kind: PeerKind,
    /// Families negotiated with the peer (RFC 4760 §8).
    pub families: Vec<AddressFamily>,
    /// Both sides speak four-octet ASNs (RFC 6793 §3).
    pub four_octet_as: bool,
    /// Both sides accept 65535-octet messages (RFC 8654 §4).
    pub extended_messages: bool,
}

impl PeerInfo {
    /// The largest UPDATE we may send this peer (RFC 4271 §4.1, RFC 8654
    /// §4), header included.
    #[must_use]
    pub fn max_message_len(&self) -> usize {
        if self.extended_messages {
            65_535
        } else {
            4_096
        }
    }

    /// Whether `family` was negotiated.
    #[must_use]
    pub fn speaks(&self, family: AddressFamily) -> bool {
        self.families.contains(&family)
    }
}
