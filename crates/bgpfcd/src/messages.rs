//! Messages between the daemon's threads (AGENTS.md §3).
//!
//! Each peer thread owns one channel of [`PeerInput`]; connection reader
//! threads, the coordinator and the control plane write to it. Peer
//! threads send [`RibMsg`] to the RIB thread over a bounded channel so
//! that a flooding peer blocks instead of growing memory, and so does the
//! RTR client with its validation changes.

use std::collections::HashMap;
use std::net::{IpAddr, TcpStream};
use std::sync::mpsc::SyncSender;
use std::time::Duration;

use bgpfc_fsm::Session;
use bgpfc_wire::error::{CeaseSubcode, DecodeError};
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
    /// Shut the session down with this Cease subcode (a `ManualStop`, RFC
    /// 4271 §8.1.2 event 2, with the RFC 4486 §4 subcode for the reason)
    /// and end the thread.
    Stop(CeaseSubcode),
    /// Reset the session: Cease / Administrative Reset, with a shutdown
    /// communication when given (RFC 9003), then start again.
    Reset(Option<String>),
    /// Soft reset: ask the peer for its routes again with ROUTE-REFRESH
    /// (RFC 2918 §4) for every negotiated family; the RIB re-sends ours.
    SoftReset,
    /// Only the first half of a soft reset: ask the peer for its routes
    /// again (after an import policy change).
    RequestRoutes,
    /// Report the session's state on the sender.
    Report(SyncSender<PeerReport>),
    /// The RIB found more routes of `family` than the neighbor's
    /// `maximum-prefix` allows and dropped them (RFC 4271 §6.7): end the
    /// session with Cease / Maximum Number of Prefixes Reached (RFC 4486
    /// §4).
    PrefixLimit {
        /// The family over its limit.
        family: AddressFamily,
        /// The limit.
        limit: u32,
    },
}

/// What a peer thread reports about itself.
#[derive(Clone, Debug)]
pub(crate) struct PeerReport {
    /// The neighbour's address.
    pub(crate) addr: IpAddr,
    /// Configured remote AS.
    pub(crate) remote_as: bgpfc_wire::types::Asn,
    /// FSM state.
    pub(crate) state: bgpfc_fsm::State,
    /// How long the state has been held.
    pub(crate) since: Duration,
    /// Negotiated session, when Established.
    pub(crate) session: Option<Session>,
    /// UPDATEs received since the thread started.
    pub(crate) updates_in: u64,
    /// UPDATE batches sent.
    pub(crate) updates_out: u64,
    /// Administratively stopped (a `ManualStop` with no restart).
    pub(crate) admin_down: bool,
    /// Left Idle by the restart limit (RFC 4486 §4) until cleared.
    pub(crate) restart_limit_reached: bool,
}

/// What the RIB thread tells the FIB thread, and what the control plane
/// asks it.
#[derive(Debug)]
pub(crate) enum FibMsg {
    /// A Loc-RIB change (RFC 4271 §9.3).
    Change(bgpfc_rib::FibChange),
    /// Switch between dry-run and install; the reply says what was done.
    SetMode(bgpfc_fib::Mode, SyncSender<usize>),
    /// Report the tables on the sender.
    Query(SyncSender<FibReport>),
    /// Remove every installed route and reply on the sender.
    Shutdown(SyncSender<()>),
}

/// A snapshot of the FIB manager.
#[derive(Clone, Debug)]
pub(crate) struct FibReport {
    /// The mode.
    pub(crate) mode: bgpfc_fib::Mode,
    /// Desired routes.
    pub(crate) desired: bgpfc_fib::Table,
    /// Routes believed installed.
    pub(crate) installed: bgpfc_fib::Table,
}

/// A question for the RIB thread.
#[derive(Clone, Debug)]
pub(crate) enum RibQuery {
    /// Per-peer route counts and session facts.
    Peers,
    /// Loc-RIB routes of a family, optionally one prefix with all its
    /// candidates.
    Routes {
        /// The family.
        family: AddressFamily,
        /// Only this destination.
        prefix: Option<bgpfc_wire::prefix::Prefix>,
    },
}

/// One Loc-RIB route or candidate in a reply.
#[derive(Clone, Debug)]
pub(crate) struct RouteReport {
    /// The destination.
    pub(crate) prefix: bgpfc_wire::prefix::Prefix,
    /// The peer it came from.
    pub(crate) peer: IpAddr,
    /// Its attributes.
    pub(crate) attrs: std::sync::Arc<bgpfc_rib::PathAttrs>,
    /// Whether it is the chosen route.
    pub(crate) best: bool,
    /// Its RFC 6811 §2 origin validation state, judged on the route as
    /// received; `Disabled` while there is no validation source.
    pub(crate) rov: bgpfc_rib::RovState,
}

/// The RIB's answer.
#[derive(Clone, Debug)]
pub(crate) enum RibReply {
    /// Answer to [`RibQuery::Peers`].
    Peers(Vec<(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)>),
    /// Answer to [`RibQuery::Routes`].
    Routes(Vec<RouteReport>),
}

/// What the coordinator reports about the `rpki` block.
#[derive(Clone, Debug)]
pub(crate) struct RpkiReport {
    /// The running block.
    pub(crate) config: bgpfc_config::ast::Rpki,
    /// The RTR client's status, if one runs. Its VRPs are the data the
    /// RIB validates with.
    pub(crate) status: Option<bgpfc_rtr::client::Status>,
}

/// Each neighbor's configured `advertisement-interval` (RFC 4271
/// §9.2.1.1); `None` takes the RFC 4271 §10 default for the session type.
pub(crate) type Intervals = HashMap<IpAddr, Option<Duration>>;

/// Each neighbor's `maximum-prefix` limits per family (RFC 4271 §6.7).
pub(crate) type PrefixLimits = HashMap<IpAddr, Vec<(AddressFamily, u32)>>;

/// The per-neighbor settings the RIB thread applies to sessions as they
/// come up, and to running ones after a reload.
#[derive(Clone, Debug, Default)]
pub(crate) struct RibSettings {
    /// `advertisement-interval`s.
    pub(crate) intervals: Intervals,
    /// `maximum-prefix` limits.
    pub(crate) prefix_limits: PrefixLimits,
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
    /// A decoded UPDATE (announcements, withdrawals, treat-as-withdraw, and
    /// the families an incorrect MP attribute disabled, RFC 4760 §7).
    Update {
        /// Peer address.
        peer: IpAddr,
        /// The decoded message.
        update: DecodedUpdate,
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
    /// A control-plane question.
    Query(RibQuery, SyncSender<RibReply>),
    /// New policies after a reload; `reexport` lists the peers whose
    /// export policy changed and whose Adj-RIB-Out is recomputed.
    SetPolicies {
        /// The compiled policies.
        policies: NewPolicies,
        /// Peers to re-export to.
        reexport: Vec<IpAddr>,
    },
    /// The advertisement intervals after a reload: sessions that are up
    /// follow at once, without a reset; later sessions start with them.
    SetIntervals(Intervals),
    /// The prefix limits after a reload, applied like the intervals; a
    /// session already over a new limit ends (RFC 4271 §6.7).
    SetPrefixLimits(PrefixLimits),
    /// Re-send the Adj-RIB-Out of every family to `peer` in full (a soft
    /// reset, RFC 2918 §4).
    Resend {
        /// Peer address.
        peer: IpAddr,
    },
    /// The validation source changed (issue #56): validate again the
    /// routes the change affects (RFC 6811 §4). The RTR client sends it on
    /// the same bounded channel as the peers, so it waits behind what is
    /// queued and cannot outrun the RIB thread (AGENTS.md §3); so does the
    /// coordinator when a reload turns validation off.
    Validation(bgpfc_rpki::ValidationChange),
}

/// A policy set on its way to the RIB thread (`dyn Policies` has no
/// `Debug`, and the message enum wants one).
pub(crate) struct NewPolicies(pub(crate) Box<dyn bgpfc_rib::Policies>);

impl std::fmt::Debug for NewPolicies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPolicies")
    }
}
