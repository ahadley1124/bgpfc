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
#[cfg(feature = "profiling")]
use std::time::Instant;

use bgpfc_fsm::Session;
use bgpfc_wire::error::{CeaseSubcode, DecodeError};
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::prefix::Prefix;
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
    /// The body of a ROUTE-REFRESH; decoded by the peer thread, which knows
    /// whether Enhanced Route Refresh was negotiated, on which the error for
    /// a body of the wrong length depends (RFC 7313 §5).
    RouteRefresh(Vec<u8>),
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
    /// UPDATEs from the RIB thread wait in the peer's outbox (a wake-up;
    /// see `peer::PeerHandle::send_updates`).
    Updates,
    /// Shut the session down with this Cease subcode (a `ManualStop`, RFC
    /// 4271 §8.1.2 event 2, with the RFC 4486 §4 subcode for the reason)
    /// and end the thread.
    Stop(CeaseSubcode),
    /// Reset the session: Cease / Administrative Reset, with a shutdown
    /// communication when given (RFC 9003), then start again. A Hard Reset
    /// (RFC 8538 §3) carries that Cease in the data of another, which has
    /// the peer delete our routes at once instead of keeping them as stale
    /// ones, where the peer sent the Graceful Notification bit.
    Reset {
        /// The Shutdown Communication.
        message: Option<String>,
        /// Send a Hard Reset.
        hard: bool,
    },
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
    /// The Restart Time we advertise, for a neighbor with `graceful-restart
    /// yes` (RFC 4724 §3).
    pub(crate) restart_time: Option<bgpfc_wire::types::RestartTime>,
}

/// What the RIB thread tells the FIB thread, and what the control plane
/// asks it.
#[derive(Debug)]
pub(crate) enum FibMsg {
    /// Loc-RIB changes, in order (RFC 4271 §9.3).
    Changes(Vec<bgpfc_rib::FibChange>),
    /// Switch between dry-run and install. Sent by the RIB thread only
    /// (`RibMsg::FibMode`): going to install, a reconcile of its routes
    /// follows; either way `ReconcileEnd` ends the switch.
    SetMode(bgpfc_fib::Mode),
    /// Begin reconciling the routes of one family, or of all for `None`,
    /// against the RIB's, which follow as `Reconcile`; one in progress ends
    /// first. Sent for a switch to install, and when the RIB's route
    /// selection for a family stops being deferred (RFC 4724 §4.1), which
    /// removes the routes kept across a restart and not learned again.
    ReconcileFamily(Option<bgpfc_wire::types::Afi>),
    /// The RIB's routes, continuing in prefix order those sent since
    /// `ReconcileFamily`.
    Reconcile(Vec<(Prefix, IpAddr)>),
    /// The end of a reconcile; the reply says how many operations it and
    /// the ones before it since `SetMode` took.
    ReconcileEnd(SyncSender<usize>),
    /// Report the mode on the sender.
    Mode(SyncSender<bgpfc_fib::Mode>),
    /// Report the mode and a page of the installed routes: at most
    /// [`PAGE`], after `after`, in prefix order.
    Query {
        /// The last route of the page before, if any.
        after: Option<Prefix>,
        /// Where the report goes.
        reply: SyncSender<FibReport>,
    },
    /// Remove every installed route and reply on the sender.
    Shutdown(SyncSender<()>),
}

/// Routes in one page of a long listing (`show routes`, `show fib`): the
/// control plane takes a full table a page at a time, so that answering
/// costs a page of memory rather than copies of the table.
pub(crate) const PAGE: usize = 4096;

/// The FIB manager's mode and a page of its installed routes. What the
/// RIB wants is the RIB's to say (`RibQuery::FibRoutes`).
#[derive(Clone, Debug)]
pub(crate) struct FibReport {
    /// The mode.
    pub(crate) mode: bgpfc_fib::Mode,
    /// Routes believed installed: a page.
    pub(crate) installed: Vec<(Prefix, IpAddr)>,
}

/// A question for the RIB thread.
#[derive(Clone, Debug)]
pub(crate) enum RibQuery {
    /// Per-peer route counts and session facts.
    Peers,
    /// Loc-RIB routes of a family, a page after `after`; or one prefix
    /// with all its candidates, and the routes held for their validation
    /// state.
    Routes {
        /// The family.
        family: AddressFamily,
        /// Only this destination.
        prefix: Option<Prefix>,
        /// Without `prefix`: the last route of the page before, if any.
        after: Option<Prefix>,
    },
    /// The next hop of the destinations after `after`, as the FIB is to
    /// install them: a page.
    FibRoutes {
        /// The last route of the page before, if any.
        after: Option<Prefix>,
    },
    /// Graceful Restart: the families whose route selection waits for
    /// End-of-RIB markers, and the peers whose routes are kept as stale
    /// ones (RFC 4724 §4.1, §4.2).
    Restart,
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
    /// The Path Identifier its peer sent it with (RFC 7911 §3), for a
    /// family the peer sends them for.
    pub(crate) path_id: Option<bgpfc_wire::types::PathId>,
    /// Whether it is the chosen route.
    pub(crate) best: bool,
    /// Whether it is a route the Adj-RIB-In holds that is no candidate:
    /// refused for its validation state (RFC 6811 §2), by `invalid drop`
    /// or by import policy.
    pub(crate) held: bool,
    /// Its peer's session ended and the route is kept until the peer
    /// sends it again (RFC 4724 §4.2).
    pub(crate) stale: bool,
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
    /// Answer to [`RibQuery::FibRoutes`].
    FibRoutes(Vec<(Prefix, IpAddr)>),
    /// Answer to [`RibQuery::Restart`].
    Restart(RestartReport),
}

/// A peer whose routes are kept as stale ones, and how many per family.
#[derive(Clone, Debug)]
pub(crate) struct StaleReport {
    /// What the RIB knows of it.
    pub(crate) peer: bgpfc_rib::StalePeer,
    /// Stale routes held, for each family that has some.
    pub(crate) routes: Vec<(AddressFamily, usize)>,
}

/// A route refresh a peer has begun and not ended, with how many routes
/// are still stale in it (RFC 7313 §4).
#[derive(Clone, Debug)]
pub(crate) struct RefreshingReport {
    /// What the RIB knows of it.
    pub(crate) refresh: bgpfc_rib::RefreshReport,
    /// Routes of the family still stale.
    pub(crate) routes: usize,
}

/// The Graceful Restart state of the RIB (RFC 4724 §4.1, §4.2), and the
/// route refreshes under way (RFC 7313 §4), which leave routes stale the
/// same way.
#[derive(Clone, Debug, Default)]
pub(crate) struct RestartReport {
    /// Families whose route selection is deferred, with how many peers
    /// are waited for and for how much longer at most.
    pub(crate) deferred: Vec<(AddressFamily, usize, Duration)>,
    /// Peers with stale routes.
    pub(crate) stale: Vec<StaleReport>,
    /// Route refreshes begun and not ended.
    pub(crate) refreshing: Vec<RefreshingReport>,
}

/// What the coordinator reports about the `rpki` block.
#[derive(Clone, Debug)]
pub(crate) struct RpkiReport {
    /// The running block.
    pub(crate) config: bgpfc_config::ast::Rpki,
    /// The RTR client's status, if one runs. Its VRPs are the data the
    /// RIB validates with.
    pub(crate) status: Option<bgpfc_rtr::client::Status>,
    /// The Routinator sidecar's status, in `mode sidecar` while it runs.
    pub(crate) sidecar: Option<SidecarReport>,
}

/// What the coordinator reports about the Routinator sidecar.
#[derive(Clone, Debug)]
pub(crate) struct SidecarReport {
    /// Where supervision stands: the state, the child, the restarts.
    pub(crate) status: bgpfc_sidecar::SidecarStatus,
    /// The version the binary reported when it was last checked.
    pub(crate) version: bgpfc_sidecar::Version,
    /// The binary it runs.
    pub(crate) binary: std::path::PathBuf,
}

/// Each neighbor's configured `advertisement-interval` (RFC 4271
/// §9.2.1.1); `None` takes the RFC 4271 §10 default for the session type.
pub(crate) type Intervals = HashMap<IpAddr, Option<Duration>>;

/// Each neighbor's `maximum-prefix` limits per family (RFC 4271 §6.7).
pub(crate) type PrefixLimits = HashMap<IpAddr, Vec<(AddressFamily, u32)>>;

/// Each neighbor's `add-path send` limits per family (RFC 7911 §5).
pub(crate) type AddPathLimits = HashMap<IpAddr, Vec<(AddressFamily, bgpfc_rib::PathLimit)>>;

/// The per-neighbor settings the RIB thread applies to sessions as they
/// come up, and to running ones after a reload.
#[derive(Clone, Debug, Default)]
pub(crate) struct RibSettings {
    /// `advertisement-interval`s.
    pub(crate) intervals: Intervals,
    /// `maximum-prefix` limits.
    pub(crate) prefix_limits: PrefixLimits,
    /// `add-path send` limits.
    pub(crate) add_path_send: AddPathLimits,
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
        /// The neighbor's `stale-time` (RFC 8538 §4.1) when it has
        /// `graceful-restart yes`.
        stale_time: Option<Duration>,
        /// The neighbor's `refresh-stale-time` (RFC 7313 §4) when it has
        /// `enhanced-refresh yes`.
        refresh_stale_time: Option<Duration>,
    },
    /// A decoded UPDATE (announcements, withdrawals, treat-as-withdraw, and
    /// the families an incorrect MP attribute disabled, RFC 4760 §7).
    Update {
        /// Peer address.
        peer: IpAddr,
        /// The decoded message.
        update: DecodedUpdate,
        /// When the peer thread started decoding it, for `update_total`
        /// (`docs/PROFILING.md`); `None` with spans off.
        #[cfg(feature = "profiling")]
        started: Option<Instant>,
    },
    /// The peer asked for its Adj-RIB-Out of a family again (RFC 2918 §4).
    RouteRefresh {
        /// Peer address.
        peer: IpAddr,
        /// The family.
        family: AddressFamily,
    },
    /// The peer began a route refresh of a family with a `BoRR` (RFC 7313
    /// §4).
    RefreshBegin {
        /// Peer address.
        peer: IpAddr,
        /// The family.
        family: AddressFamily,
    },
    /// The peer ended a route refresh of a family with an `EoRR` (RFC 7313
    /// §4).
    RefreshEnd {
        /// Peer address.
        peer: IpAddr,
        /// The family.
        family: AddressFamily,
    },
    /// The peer sent its End-of-RIB marker for a family (RFC 4724 §2): the
    /// initial update of the family is complete.
    EndOfRib {
        /// Peer address.
        peer: IpAddr,
        /// The family.
        family: AddressFamily,
    },
    /// The session left Established: delete its routes, or keep those the
    /// FSM names as stale ones until the peer is back (RFC 4724 §4.2,
    /// RFC 8538 §4).
    PeerDown {
        /// Peer address.
        peer: IpAddr,
        /// The routes to keep, if any.
        retain: Option<bgpfc_fsm::Retain>,
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
    /// The `add-path send` limits after a reload: a running session sends
    /// the number of paths it now says, without a reset (RFC 7911 §5);
    /// which families have ADD-PATH is a session parameter and resets.
    SetAddPathLimits(AddPathLimits),
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
    /// What the RIB does with Invalid routes by itself changed, with a
    /// reload (RFC 6811 §5): the RIB judges the routes it holds that are
    /// Invalid again, with no session reset and no ROUTE-REFRESH.
    SetInvalidAction(bgpfc_rpki::InvalidAction),
    /// Switch the FIB between dry-run and install: the RIB thread passes
    /// it on, with its routes for the reconcile going to install. The
    /// FIB replies with the number of operations it took.
    FibMode(bgpfc_fib::Mode, SyncSender<usize>),
}

/// A policy set on its way to the RIB thread (`dyn Policies` has no
/// `Debug`, and the message enum wants one).
pub(crate) struct NewPolicies(pub(crate) Box<dyn bgpfc_rib::Policies>);

impl std::fmt::Debug for NewPolicies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPolicies")
    }
}
