//! Messages between the daemon's threads (AGENTS.md §3).
//!
//! Each peer thread owns one channel of [`PeerInput`]; connection reader
//! threads, the coordinator and the control plane write to it. Peer
//! threads send [`RibMsg`] to the RIB thread over a bounded channel so
//! that a flooding peer blocks instead of growing memory, and so do the
//! RTR client with its validation changes and the kernel thread with the
//! kernel's routing table.

use std::collections::HashMap;
use std::net::{IpAddr, TcpStream};
use std::num::NonZeroU8;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant, SystemTime};

use bgpfc_fsm::Session;
use bgpfc_wire::error::{CeaseSubcode, DecodeError};
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::prefix::Prefix;
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
    /// UPDATEs from the RIB thread wait in the peer's outbox (a wake-up;
    /// see `peer::PeerHandle::send_updates`).
    Updates,
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
    /// Ask the peer for its routes of these families again with
    /// ROUTE-REFRESH (RFC 2918 §4): import policy dropped some of them,
    /// which the Adj-RIB-In does not keep, and the policy a reload brought
    /// may take them (`bgpfc_rib::Output::RequestRoutes`).
    RequestRoutes(Vec<AddressFamily>),
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
    /// Our address on the connection the FSM runs on, else the configured
    /// `local-address`, if any.
    pub(crate) local_addr: Option<IpAddr>,
    /// The TTL sent to the neighbor; `None` for the system's.
    pub(crate) ttl: Option<NonZeroU8>,
    /// The last connection error and how long ago it was, until a session
    /// comes up: a failed connect, or a socket error a connection closed
    /// with before its session was up (`docs/config.md`, "Neighbors").
    pub(crate) last_error: Option<(String, Duration)>,
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
    /// Loc-RIB changes, in order (RFC 4271 §9.3): a batch of what the
    /// RIB made of one of its inputs.
    Changes {
        /// The changes.
        changes: Vec<bgpfc_rib::FibChange>,
        /// Whether more batches of the same input follow. The FIB thread
        /// writes the line of an input that comes alone once its last
        /// batch is in, and bounds its error lines per input (see
        /// `crate::fib`, "Logging"); an input whose changes all went in
        /// batches marked so ends with an empty one.
        more: bool,
    },
    /// Switch between dry-run and install. Sent by the RIB thread only
    /// (`RibMsg::FibMode`): going to install, its routes follow as
    /// `Reconcile`; either way `ReconcileEnd` ends the switch.
    SetMode(bgpfc_fib::Mode),
    /// The RIB's routes, continuing in prefix order those sent since
    /// `SetMode`.
    Reconcile(Vec<(Prefix, bgpfc_fib::Hop)>),
    /// The end of a switch; the reply says how many operations it took.
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
    /// Routes believed installed, each with its hop: a page.
    pub(crate) installed: Vec<(Prefix, bgpfc_fib::Hop)>,
}

/// A question for the RIB thread.
#[derive(Clone, Debug)]
pub(crate) enum RibQuery {
    /// Per-peer route counts and session facts.
    Peers,
    /// Loc-RIB routes of a family, a page after `after`; or one prefix
    /// with every route the Adj-RIBs-In hold for it.
    Routes {
        /// The family.
        family: AddressFamily,
        /// Only this destination.
        prefix: Option<Prefix>,
        /// Without `prefix`: the last route of the page before, if any.
        after: Option<Prefix>,
        /// Only the routes held, for their validation state (RFC 6811 §2)
        /// or an unresolvable next hop (RFC 4271 §9.1.2), which are no
        /// candidates: of the destination, or without
        /// `prefix`, a page of the family's after `after`, which ends
        /// between two destinations.
        held: bool,
    },
    /// The hop of the destinations after `after`, gateway and interface,
    /// as the FIB is to install them: a page.
    FibRoutes {
        /// The last route of the page before, if any.
        after: Option<Prefix>,
    },
    /// The most recent changes of a route's RFC 6811 state (issue #59).
    Transitions,
    /// Every next hop the routes use, and what it resolves to (RFC 4271
    /// §9.1.2).
    NextHops,
}

/// One route in a reply: of the Loc-RIB, a candidate, or a route held
/// for its validation state.
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
    /// The state import policy set, which the route is used with in
    /// place of `rov` (RFC 6811 §3), if it set one.
    pub(crate) rov_set: Option<bgpfc_rib::RovState>,
    /// Why the Adj-RIB-In holds it while it is no candidate, if it does.
    pub(crate) held: Option<bgpfc_rib::Held>,
}

/// The RIB's answer.
#[derive(Clone, Debug)]
pub(crate) enum RibReply {
    /// Answer to [`RibQuery::Peers`].
    Peers(Vec<(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)>),
    /// Answer to [`RibQuery::Routes`].
    Routes(Vec<RouteReport>),
    /// Answer to [`RibQuery::FibRoutes`].
    FibRoutes(Vec<(Prefix, bgpfc_fib::Hop)>),
    /// Answer to [`RibQuery::Transitions`].
    Transitions(TransitionsReport),
    /// Answer to [`RibQuery::NextHops`].
    NextHops(NextHopsReport),
}

/// The next hops the RIB's routes use, and the size of its copy of the
/// kernel's routing table they resolve against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NextHopsReport {
    /// Each next hop in use, in address order.
    pub(crate) next_hops: Vec<bgpfc_rib::nexthop::NextHopReport>,
    /// Routes in the copy of the kernel's table; `None` without one, when
    /// every next hop resolves to itself (never in bgpfcd, which gives
    /// the RIB a table before any route).
    pub(crate) kernel_routes: Option<usize>,
}

/// A route's move from one RFC 6811 state to another, as the RIB thread
/// keeps it (issue #59: "An operator needs to see that a prefix went
/// Valid → Invalid at a specific time").
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Recorded {
    /// When the RIB thread applied the change (a log timestamp, AGENTS.md
    /// §3): the time of its log lines, give or take the moment it took to
    /// write them.
    pub(crate) at: SystemTime,
    /// The same moment on the monotonic clock, for how long ago it was.
    pub(crate) when: Instant,
    /// The route, its move, and what became of it.
    pub(crate) transition: bgpfc_rib::Transition,
}

/// The changes of state the RIB thread keeps: the most recent of those
/// the RIB listed (`bgpfc_rib::Revalidation::transitions`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransitionsReport {
    /// The most it keeps.
    pub(crate) capacity: usize,
    /// Changes of state it was never given, since it started: those
    /// beyond what the RIB lists for one change of the validation source.
    pub(crate) unrecorded: u64,
    /// The changes kept, oldest first.
    pub(crate) entries: Vec<Recorded>,
}

/// What the coordinator reports about the `rpki` block.
#[derive(Clone, Debug)]
pub(crate) struct RpkiReport {
    /// The running block.
    pub(crate) config: bgpfc_config::ast::Rpki,
    /// The RTR client's status, if one runs. Its VRPs are the data the
    /// RIB validates with.
    pub(crate) status: Option<bgpfc_rtr::client::Status>,
    /// Since when every route has waited, `disabled`, for the client's
    /// first full set, while it still does (issue #71; m14 design §3.3).
    pub(crate) waiting_since: Option<Instant>,
    /// Routinator, while a sidecar runs (`mode sidecar`).
    pub(crate) sidecar: Option<SidecarReport>,
}

/// What the coordinator reports about Routinator, read from the sidecar
/// at each request: its version may change at a restart, after the binary
/// was replaced (`bgpfc_sidecar::Sidecar::version`).
#[derive(Clone, Debug)]
pub(crate) struct SidecarReport {
    /// Where supervision stands, and the address Routinator serves RTR on.
    pub(crate) status: bgpfc_sidecar::SidecarStatus,
    /// The version the binary reported when it was last checked.
    pub(crate) version: bgpfc_sidecar::Version,
    /// The binary, as the `sidecar` block names it.
    pub(crate) binary: PathBuf,
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
    /// The session left Established: delete its routes.
    PeerDown {
        /// Peer address.
        peer: IpAddr,
    },
    /// A control-plane question.
    Query(RibQuery, SyncSender<RibReply>),
    /// New policies after a reload: `reexport` lists the peers whose
    /// export policy changed and whose Adj-RIB-Out is recomputed from the
    /// Loc-RIB, then `reimport` those whose import policy changed and
    /// whose routes are imported again from the Adj-RIB-In (RFC 4271 §3),
    /// with ROUTE-REFRESH only for the families of what it did not keep
    /// (RFC 2918).
    SetPolicies {
        /// The compiled policies.
        policies: NewPolicies,
        /// Peers to import from again.
        reimport: Vec<IpAddr>,
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
    /// The `rpki` block's `enforcement` after a reload changed it: judge
    /// every route again under it (RFC 6811 §5), holding or releasing
    /// routes and choosing again, with no UPDATE and no ROUTE-REFRESH.
    SetEnforcement(bgpfc_rpki::Enforcement),
    /// The startup setting in effect (`rpki::startup`), after a reload or
    /// before validation is turned off: judge again every route not
    /// validated yet, `disabled`, holding it under `hold` and releasing it
    /// under `accept` (RFC 6811 §2: only "explicitly configured" routes
    /// leave the decision process for their state), with no UPDATE and no
    /// ROUTE-REFRESH. The same setting again changes nothing.
    SetStartup(bgpfc_rpki::Startup),
    /// Switch the FIB between dry-run and install: the RIB thread passes
    /// it on, with its routes for the reconcile going to install. The
    /// FIB replies with the number of operations it took.
    FibMode(bgpfc_fib::Mode, SyncSender<usize>),
    /// The kernel's routing table, whole or what changed in it, from the
    /// kernel thread (`crate::kernel`): resolve again the next hops it may
    /// change, and decide again the destinations of those whose
    /// resolution it changed (RFC 4271 §9.1.2). On the same bounded
    /// channel as the peers, so a busy RIB slows the kernel thread, whose
    /// socket may then overflow and is read again whole.
    Kernel(bgpfc_rib::nexthop::KernelUpdate),
}

/// A policy set on its way to the RIB thread (`dyn Policies` has no
/// `Debug`, and the message enum wants one).
pub(crate) struct NewPolicies(pub(crate) Box<dyn bgpfc_rib::Policies>);

impl std::fmt::Debug for NewPolicies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPolicies")
    }
}
