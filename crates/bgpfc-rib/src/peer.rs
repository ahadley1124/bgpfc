//! What the RIB knows about a session.
//!
//! Implements: RFC 4760 §8 (families sent and taken); RFC 8654 §4 (message
//! size); RFC 8950 §4 (which next hops a peer takes); RFC 4271 §6.7 (the
//! per-family prefix limit), §6.3 a) (our own address is no next hop);
//! RFC 7911 §5 (the families sent and taken with Path Identifiers, and how
//! many paths are sent); RFC 9234 §4 (our BGP Role on the session);
//! RFC 4724 §4, §4.2 (Graceful Restart on the session).

use std::net::IpAddr;
use std::time::Duration;

use bgpfc_wire::mp::NextHop;
use bgpfc_wire::role::Role;
use bgpfc_wire::types::{AddressFamily, Afi, Asn, RouterId};
use bgpfc_wire::update::PeerKind;

use crate::restart::Restart;

/// How many paths of a prefix to send a peer with ADD-PATH (RFC 7911 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathLimit {
    /// The `n` best by the decision process, among those export policy
    /// accepts; `n` is at least one.
    Best(u32),
    /// Every path export policy accepts.
    All,
}

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
    /// Families negotiated with the peer, which both sides advertised
    /// (RFC 4760 §8): the ones whose routes it is sent.
    pub families: Vec<AddressFamily>,
    /// Families we advertised to the peer (RFC 4760 §8): it may send routes
    /// of these even when it did not advertise them itself (RFC 5492 §3).
    /// Routes of a family in neither list are ignored.
    pub receive_families: Vec<AddressFamily>,
    /// Both sides speak four-octet ASNs (RFC 6793 §3).
    pub four_octet_as: bool,
    /// Both sides accept 65535-octet messages (RFC 8654 §4).
    pub extended_messages: bool,
    /// Families whose routes may go to this peer with an IPv6 next hop,
    /// because it advertised Extended Next Hop Encoding for them, and so
    /// did we (RFC 8950 §4): IPv4 unicast or nothing. Which next hops are
    /// taken from the peer is the decoder's business.
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
    /// The families the peer sends us routes of with a Path Identifier
    /// before each prefix, several paths for one (RFC 7911 §5). Within
    /// `receive_families`.
    pub add_path_receive: Vec<AddressFamily>,
    /// The families we send the peer routes of with Path Identifiers, and
    /// how many paths of a prefix (RFC 7911 §5). Within `families`. The
    /// routes of any other family go as before, one best path per prefix.
    pub add_path_send: Vec<(AddressFamily, PathLimit)>,
    /// Our BGP Role on the session, when one is configured and the session
    /// external (RFC 9234 §4): the session takes part in the Only to
    /// Customer procedures of §5 (see [`otc`](crate::otc)). `None` for a
    /// session with no Role, which leaves the attribute alone.
    pub role: Option<Role>,
    /// Graceful Restart (RFC 4724), when we advertised the capability to
    /// this peer: the End-of-RIB marker ends the initial update of each
    /// family (§4), and if the peer advertised it too its routes are kept
    /// as stale when the session ends (§4.2). `None` leaves the session as
    /// RFC 4271 has it.
    pub restart: Option<Restart>,
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

    /// Whether `family` was negotiated: routes of it go to the peer.
    #[must_use]
    pub fn speaks(&self, family: AddressFamily) -> bool {
        self.families.contains(&family)
    }

    /// Whether routes of `family` are taken from the peer: we advertised
    /// it, or it was negotiated (RFC 4760 §8, RFC 5492 §3).
    #[must_use]
    pub fn receives(&self, family: AddressFamily) -> bool {
        self.receive_families.contains(&family) || self.speaks(family)
    }

    /// Whether the peer sends routes of `family` with Path Identifiers.
    #[must_use]
    pub fn receives_paths(&self, family: AddressFamily) -> bool {
        self.add_path_receive.contains(&family)
    }

    /// How many paths of a prefix of `family` to send the peer, if it is
    /// sent them with Path Identifiers at all (RFC 7911 §5).
    #[must_use]
    pub fn path_limit(&self, family: AddressFamily) -> Option<PathLimit> {
        self.add_path_send
            .iter()
            .find(|(f, _)| *f == family)
            .map(|(_, l)| *l)
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
