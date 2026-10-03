//! Messages between the daemon's threads (AGENTS.md §3).
//!
//! Each peer thread owns one channel of [`PeerInput`]; connection reader
//! threads and the coordinator write to it, and the control plane will
//! once it exists. Peer threads send [`RibMsg`] to the RIB thread over a
//! bounded channel so that a flooding peer blocks instead of growing
//! memory.

use std::net::{IpAddr, TcpStream};

use bgpfc_fsm::Session;
use bgpfc_wire::error::DecodeError;
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::route_refresh::RouteRefreshMessage;
use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::DecodedUpdate;

/// Identifies one TCP connection of a peer, so that a reader thread of a
/// connection that was dropped meanwhile cannot confuse the peer thread.
pub(crate) type ConnId = u64;

/// Who opened a TCP connection (RFC 4271 §6.8 keeps the one initiated by
/// the speaker with the higher BGP Identifier).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Initiator {
    /// We connected to the peer.
    Local,
    /// The peer connected to us.
    Remote,
}

/// A message read and decoded from a connection by its reader thread.
#[derive(Debug)]
pub(crate) enum Inbound {
    /// A syntactically valid OPEN.
    Open(OpenMessage),
    /// The body of an UPDATE; decoded by the peer thread, which knows the
    /// session parameters RFC 7606 handling depends on.
    Update(Vec<u8>),
    /// A NOTIFICATION.
    Notification(NotificationMessage),
    /// A KEEPALIVE.
    Keepalive,
    /// A ROUTE-REFRESH.
    RouteRefresh(RouteRefreshMessage),
}

/// Everything that can wake a peer thread.
#[derive(Debug)]
pub(crate) enum PeerInput {
    /// Our outgoing connection attempt finished.
    Connected {
        /// The attempt this answers.
        attempt: u64,
        /// The stream, or why connecting failed.
        result: Result<TcpStream, std::io::Error>,
    },
    /// The coordinator accepted a connection from this peer's address.
    Incoming(TcpStream),
    /// A message, or a header/OPEN/ROUTE-REFRESH decode error, from the
    /// reader of connection `conn`.
    Message {
        /// Which connection.
        conn: ConnId,
        /// What was read.
        message: Result<Inbound, DecodeError>,
    },
    /// The reader of connection `conn` hit EOF or an I/O error.
    Closed {
        /// Which connection.
        conn: ConnId,
    },
    /// Framed UPDATE messages from the RIB thread, to write in order while
    /// Established (RFC 4271 §9.2).
    Send(Vec<Vec<u8>>),
    /// Shut the session down (`ManualStop`, RFC 4271 §8.1.2 event 2) and
    /// end the thread.
    Stop,
}

/// What the RIB thread tells the FIB thread.
#[derive(Debug)]
pub(crate) enum FibMsg {
    /// A Loc-RIB change (RFC 4271 §9.3).
    Change(bgpfc_rib::FibChange),
    /// Remove every installed route and reply on the sender.
    Shutdown(std::sync::mpsc::SyncSender<()>),
}

/// What peer threads tell the RIB thread.
#[derive(Debug)]
pub(crate) enum RibMsg {
    /// A session reached Established.
    PeerUp {
        /// Peer address.
        peer: IpAddr,
        /// Our address on the connection: the next hop for external
        /// peers (RFC 4271 §5.1.3).
        local_addr: IpAddr,
        /// Negotiated parameters.
        session: Session,
    },
    /// A decoded UPDATE (announcements, withdrawals, or treat-as-withdraw).
    Update {
        /// Peer address.
        peer: IpAddr,
        /// The decoded message.
        update: DecodedUpdate,
    },
    /// An UPDATE's multiprotocol attribute was unusable (RFC 4760 §7): drop
    /// the family's routes from this peer and ignore it from now on.
    FamilyDisabled {
        /// Peer address.
        peer: IpAddr,
        /// The family.
        family: AddressFamily,
    },
    /// The peer asked for its Adj-RIB-Out of a family again (RFC 2918 §4).
    RouteRefresh {
        /// Peer address.
        peer: IpAddr,
        /// The family.
        family: AddressFamily,
    },
    /// The session left Established: delete its routes.
    PeerDown {
        /// Peer address.
        peer: IpAddr,
    },
}
