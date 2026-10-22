//! What the RIB knows about a session.
//!
//! Implements: RFC 4760 §8 (negotiated families); RFC 8654 §4 (message
//! size); RFC 8950 §4 (which next hops a peer takes); RFC 4271 §6.7 (the
//! per-family prefix limit), §6.3 a) (our own address is no next hop).

use std::net::IpAddr;
use std::time::Duration;

use bgpfc_wire::mp::NextHop;
use bgpfc_wire::types::{AddressFamily, Afi, Asn, RouterId};
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
    /// Families whose routes may carry an IPv6 next hop to and from this
    /// peer, because both sides advertised Extended Next Hop Encoding for
    /// them (RFC 8950 §4): IPv4 unicast or nothing.
    pub extended_next_hop: Vec<AddressFamily>,
    /// The `MinRouteAdvertisementIntervalTimer` (RFC 4271 §9.2.1.1): the
    /// least time between two advertisements of a destination to this
    /// peer. Zero sends every change at once.
    /// [`default_interval`](crate::pacing::default_interval) gives the
    /// RFC 4271 §10 default.
    pub advertisement_interval: Duration,
    /// The upper bound on the routes of each listed family the peer may
    /// have in the Adj-RIB-In (RFC 4271 §6.7); exceeding it ends the
    /// session (see [`Output::PrefixLimitExceeded`](crate::Output)).
    /// Families not listed have none.
    pub prefix_limits: Vec<(AddressFamily, u32)>,
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

    /// The prefix limit for `family`, if there is one (RFC 4271 §6.7).
    #[must_use]
    pub fn prefix_limit(&self, family: AddressFamily) -> Option<u32> {
        self.prefix_limits
            .iter()
            .find(|(f, _)| *f == family)
            .map(|(_, l)| *l)
    }

    /// Whether `next_hop` is our own address on this session, which RFC
    /// 4271 §6.3 a) makes semantically incorrect in a route received over
    /// it. What counts is where traffic would go: the global address of an
    /// IPv6 next hop (RFC 2545 §3). Compared in canonical form, so that an
    /// IPv4-mapped IPv6 next hop (RFC 4291 §2.5.5.2) holding our IPv4
    /// address is ours too.
    #[must_use]
    pub fn is_own_address(&self, next_hop: &NextHop) -> bool {
        let addr = match next_hop {
            NextHop::Ipv4(a) => IpAddr::V4(*a),
            NextHop::Ipv6 { global, .. } => IpAddr::V6(*global),
        };
        addr.to_canonical() == self.local_addr.to_canonical()
    }

    /// Whether a route of `family` may go to this peer with `next_hop`:
    /// an IPv6 next hop for IPv4 NLRI only where the peer advertised
    /// Extended Next Hop Encoding for the family (RFC 8950 §4).
    #[must_use]
    pub fn takes_next_hop(&self, family: AddressFamily, next_hop: &NextHop) -> bool {
        match next_hop {
            NextHop::Ipv6 { .. } if family.afi == Afi::Ipv4 => {
                self.extended_next_hop.contains(&family)
            }
            _ => true,
        }
    }
}
