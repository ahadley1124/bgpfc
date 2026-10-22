//! BGP-4 session state machine. Pure: `(State, Event, Instant) -> (State,
//! Vec<Action>)`. It never reads the clock and never touches a socket; the
//! peer thread feeds it events (messages, TCP outcomes, timer expiries) and
//! executes the actions it returns.
//!
//! Timers are deadlines on an injected [`Instant`]. The caller asks
//! [`Fsm::next_deadline`] how long it may block, and on wake-up calls
//! [`Fsm::expired`] to turn elapsed timers into events.
//!
//! Implements: RFC 4271 §4.2 (Hold Time negotiation), §6.8 (collision
//! resolution hooks), §8 (events 1–28, all states), §10 (timer defaults and
//! jitter); RFC 9687 §4, §5 (`SendHoldTimer`, event 29); RFC 6608 §4 (FSM
//! error subcodes with the offending message type); RFC 4486 §4 (Cease
//! subcodes for administrative stops and collisions; damping after the
//! Cease subcodes it names, and a bound on consecutive automatic
//! restarts); RFC 5492 §5
//! (Unsupported Capability); RFC 4760 §8 (a family goes both ways when both
//! sides advertised it; routes of every family we advertised are taken);
//! RFC 6793 §3 (four-octet AS negotiation); RFC 8654 §4 (Extended Message
//! negotiation); RFC 8950 §4 (Extended Next Hop Encoding negotiation);
//! RFC 7607 §2 (never claim AS 0).
#![forbid(unsafe_code)]

mod machine;
mod timers;

use std::fmt;
use std::time::{Duration, Instant};

use bgpfc_wire::capability::Capability;
use bgpfc_wire::error::DecodeError;
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};
pub use bgpfc_wire::update::PeerKind;

pub use machine::{Fsm, SEND_HOLD_TIMER_EXPIRED};
pub use timers::Timer;

/// The six FSM states (RFC 4271 §8.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// Refusing connections; no resources allocated.
    Idle,
    /// Waiting for the outgoing TCP connection to complete.
    Connect,
    /// Listening for an incoming TCP connection.
    Active,
    /// OPEN sent; waiting for the peer's OPEN.
    OpenSent,
    /// Peer's OPEN accepted; waiting for its KEEPALIVE.
    OpenConfirm,
    /// Session up; UPDATEs flow.
    Established,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            State::Idle => "Idle",
            State::Connect => "Connect",
            State::Active => "Active",
            State::OpenSent => "OpenSent",
            State::OpenConfirm => "OpenConfirm",
            State::Established => "Established",
        })
    }
}

/// FSM input events, numbered as in RFC 4271 §8.1 (and RFC 9687 §4.2 for
/// event 29). Events 3, 6 and 7 collapse onto [`Event::AutomaticStart`]:
/// whether a start is passive or damped comes from [`Config`], not from
/// the event; event 5 is kept for a one-off passive restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// 1: operator starts the peer.
    ManualStart,
    /// 2: the operator stops the peer, with the Cease to send where the
    /// state sends one (RFC 4486 §4: Administrative Shutdown to stop it,
    /// Administrative Reset to restart it, Peer De-configured or Other
    /// Configuration Change after a reload; with an RFC 9003 Shutdown
    /// Communication when the operator gave one). The peer stays Idle until
    /// started again. It is no failure of the peer: nothing is damped or
    /// counted toward the restart limit.
    ManualStop(NotificationMessage),
    /// 3, 6, 7: the local system restarts the peer (after an
    /// `IdleHoldTimer` expiry, or at daemon start for configured peers).
    AutomaticStart,
    /// 4: as 1 with `PassiveTcpEstablishment`. Kept distinct so that a
    /// one-off passive start is possible without changing the config.
    ManualStartPassive,
    /// 5: as 3 with `PassiveTcpEstablishment`: the local system restarts
    /// the peer once without opening a connection itself. The coordinator
    /// uses it to go on with the connection that won a collision (RFC 4271
    /// §6.8); unlike event 4 it is no administrative intervention (RFC
    /// 4486 §4), so it leaves the run of damped failures as it is, and,
    /// like event 3, does nothing once the restart limit cleared
    /// `AllowAutomaticStart`.
    AutomaticStartPassive,
    /// 8: the local system stops the peer (prefix limit, resource
    /// exhaustion) with the Cease to send (RFC 4486 §4 picks the subcode by
    /// reason); it restarts after the `IdleHoldTimer`, unless the
    /// [`Damping::restart_limit`] is reached.
    AutomaticStop(NotificationMessage),
    /// 9.
    ConnectRetryTimerExpires,
    /// 10.
    HoldTimerExpires,
    /// 11.
    KeepaliveTimerExpires,
    /// 12.
    DelayOpenTimerExpires,
    /// 13.
    IdleHoldTimerExpires,
    /// 14: an incoming TCP connection request from the right address.
    TcpConnectionValid,
    /// 15: an incoming TCP connection request from a wrong address or port.
    TcpCrInvalid,
    /// 16: our outgoing TCP connection completed.
    TcpCrAcked,
    /// 17: an incoming TCP connection completed.
    TcpConnectionConfirmed,
    /// 18: the TCP connection failed or closed.
    TcpConnectionFails,
    /// 19 or 20: a syntactically valid OPEN was received; whether the
    /// `DelayOpenTimer` is running decides which (§8.1.5).
    BgpOpen(OpenMessage),
    /// 21: a message header failed the RFC 4271 §6.1 checks.
    BgpHeaderErr(DecodeError),
    /// 22: an OPEN failed the §6.2 checks.
    BgpOpenMsgErr(DecodeError),
    /// 23: the coordinator resolved a collision (§6.8) against this
    /// connection, and goes on with the other one
    /// ([`Event::AutomaticStartPassive`]). Not a failure of the peer, so
    /// not damped.
    OpenCollisionDump,
    /// 24: a NOTIFICATION with OPEN Message Error / Unsupported Version.
    NotifMsgVerErr,
    /// 25: any other NOTIFICATION.
    NotifMsg(NotificationMessage),
    /// 26.
    KeepAliveMsg,
    /// 27: a valid UPDATE was received; the RIB processes it, the FSM
    /// only restarts the `HoldTimer`.
    UpdateMsg,
    /// 28: an UPDATE failed with a session reset (RFC 7606); the
    /// NOTIFICATION to send.
    UpdateMsgErr(DecodeError),
    /// 29: the `SendHoldTimer` expired (RFC 9687 §4.2).
    SendHoldTimerExpires,
    /// A ROUTE-REFRESH was received (RFC 2918 §3). RFC 4271 defines no
    /// event for it: in Established it is the RIB's business and does not
    /// touch the `HoldTimer` (§6.5 names only KEEPALIVE, UPDATE and
    /// NOTIFICATION); before Established it is an unexpected message
    /// (RFC 6608 §4 lists it for `OpenSent` and `OpenConfirm`).
    RouteRefreshMsg,
}

impl Event {
    /// RFC 4271 §8.1 / RFC 9687 §4.2 event number, for logs.
    #[must_use]
    pub const fn number(&self) -> u8 {
        match self {
            Event::ManualStart => 1,
            Event::ManualStop(_) => 2,
            Event::AutomaticStart => 3,
            Event::ManualStartPassive => 4,
            Event::AutomaticStartPassive => 5,
            Event::AutomaticStop(_) => 8,
            Event::ConnectRetryTimerExpires => 9,
            Event::HoldTimerExpires => 10,
            Event::KeepaliveTimerExpires => 11,
            Event::DelayOpenTimerExpires => 12,
            Event::IdleHoldTimerExpires => 13,
            Event::TcpConnectionValid => 14,
            Event::TcpCrInvalid => 15,
            Event::TcpCrAcked => 16,
            Event::TcpConnectionConfirmed => 17,
            Event::TcpConnectionFails => 18,
            Event::BgpOpen(_) => 19,
            Event::BgpHeaderErr(_) => 21,
            Event::BgpOpenMsgErr(_) => 22,
            Event::OpenCollisionDump => 23,
            Event::NotifMsgVerErr => 24,
            Event::NotifMsg(_) => 25,
            Event::KeepAliveMsg => 26,
            Event::UpdateMsg => 27,
            Event::UpdateMsgErr(_) => 28,
            Event::SendHoldTimerExpires => 29,
            // Not numbered by RFC 4271; RFC 6608 §4 treats it like any
            // unexpected message.
            Event::RouteRefreshMsg => 0,
        }
    }
}

/// What the caller must do after an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Initiate the outgoing TCP connection (RFC 4271 §8.2.2 Idle/Connect).
    /// Listening for incoming connections is always on and needs no action.
    Connect,
    /// Close the TCP connection, if any.
    DropConnection,
    /// Reject an incoming TCP connection request (event 15).
    RejectConnection,
    /// Write this OPEN.
    SendOpen(OpenMessage),
    /// Write a KEEPALIVE.
    SendKeepalive,
    /// Write this NOTIFICATION, then expect [`Action::DropConnection`].
    SendNotification(NotificationMessage),
    /// The session reached Established with these negotiated parameters;
    /// tell the RIB (`PeerUp`).
    SessionUp(Session),
    /// The session left Established; delete every route learned from it
    /// (RFC 4271 §8.2.2 "deletes all routes associated with this
    /// connection") and tell the RIB (`PeerDown`).
    SessionDown,
    /// Log at error level (RFC 9687 §5 requires it for Send Hold Timer
    /// Expired; also used for FSM errors).
    LogError(&'static str),
    /// The damped failure just handled exceeded
    /// [`Damping::restart_limit`] (RFC 4486 §4): the peer stays Idle, with
    /// automatic starts ignored, until a `ManualStart`. The caller logs it.
    RestartLimitReached {
        /// Consecutive damped failures, this one included.
        failures: u32,
    },
}

/// Parameters agreed in the OPEN exchange, fixed for the session's life.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    /// The peer's ASN (RFC 6793 §3: from its capability when present).
    pub peer_as: Asn,
    /// The peer's BGP Identifier.
    pub peer_router_id: RouterId,
    /// Internal (same AS) or external (RFC 4271 §8.2.2 "internal
    /// connection"); what the UPDATE decoder needs as its `PeerKind`.
    pub peer: PeerKind,
    /// `min(configured, received)` (RFC 4271 §4.2).
    pub hold_time: HoldTime,
    /// Interval between KEEPALIVEs; zero when `hold_time` is zero.
    pub keepalive_time: Duration,
    /// Both sides advertised the Four-octet AS capability (RFC 6793 §3).
    pub four_octet_as: bool,
    /// Both sides advertised Extended Message (RFC 8654 §4).
    pub extended_messages: bool,
    /// The peer advertised Route Refresh (RFC 2918 §4).
    pub route_refresh: bool,
    /// Families both sides advertised (RFC 4760 §8), or IPv4 unicast alone
    /// when neither side used the Multiprotocol capability: they go both
    /// ways. Only these are sent to the peer.
    pub families: Vec<AddressFamily>,
    /// Families we advertised (RFC 4760 §8), or IPv4 unicast alone without
    /// a Multiprotocol capability: the peer may send us routes of these,
    /// whether or not it advertised them too, since a sender may use a
    /// capability its receiver advertised (RFC 5492 §3). Includes
    /// `families`.
    pub receive_families: Vec<AddressFamily>,
    /// The families in `receive_families` whose routes the peer may send us
    /// with an IPv6 next hop (RFC 8950 §3): we advertised Extended Next Hop
    /// Encoding for them, which tells the peer we take one (§4), whether or
    /// not the peer advertised it too. Only IPv4 unicast with an IPv6 next
    /// hop is ever advertised, so this is that family or nothing.
    pub extended_next_hop_receive: Vec<AddressFamily>,
    /// The families in `families` whose routes we may send the peer with
    /// an IPv6 next hop: the peer advertised Extended Next Hop Encoding for
    /// them (RFC 8950 §4), and so did we. Within
    /// `extended_next_hop_receive`.
    pub extended_next_hop_send: Vec<AddressFamily>,
    /// Capabilities the peer advertised, verbatim.
    pub peer_capabilities: Vec<Capability>,
}

/// Peer oscillation damping (RFC 4271 §8.1.1 group 1): how long to hold
/// the peer in Idle before an automatic restart, doubling on each failure,
/// and how many such restarts in a row are allowed (RFC 4486 §4).
///
/// A damped failure is one after which RFC 4271 §8.2.2 says "(optionally)
/// performs peer oscillation damping", or a received Cease whose subcode
/// RFC 4486 §4 names. Consecutive damped failures form a run; a manual
/// start, or a session that stayed Established for `forget_after`, ends it.
/// Other failures, such as a refused TCP connection, neither count nor end
/// a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Damping {
    /// `IdleHoldTime` after the first failure of a run.
    pub initial: Duration,
    /// Upper bound for the doubled `IdleHoldTime`.
    pub max: Duration,
    /// RFC 4486 §4: the most automatic restarts after consecutive damped
    /// failures; the next damped failure leaves the peer Idle until a
    /// `ManualStart`. `None` restarts without bound; `Some(0)` never
    /// restarts after a damped failure.
    pub restart_limit: Option<u32>,
    /// How long a session must stay Established for its end to start a
    /// new run. A shorter session, such as one torn down by a prefix limit
    /// as soon as the peer sends its table, is part of the oscillation the
    /// damping is for.
    pub forget_after: Duration,
}

/// The default [`Damping::restart_limit`]: with the default doubling this
/// is about a quarter of an hour of failures (10 + 20 + 40 + 80 + 6 × 120
/// seconds of `IdleHoldTime`) before the peer is left Idle.
pub const DEFAULT_RESTART_LIMIT: u32 = 10;

impl Default for Damping {
    /// 10 s doubling up to 120 s, the figure RFC 4271 §8.1.1 uses as its
    /// example; [`DEFAULT_RESTART_LIMIT`] restarts; a run forgotten after
    /// five minutes Established.
    fn default() -> Self {
        Damping {
            initial: Duration::from_secs(10),
            max: Duration::from_secs(120),
            restart_limit: Some(DEFAULT_RESTART_LIMIT),
            // NOTE(interop): BIRD's `error forget time` defaults to 300 s.
            forget_after: Duration::from_mins(5),
        }
    }
}

/// How the `SendHoldTime` is chosen (RFC 9687 §4.4, §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendHoldTime {
    /// The RFC 9687 §6 recommendation: the greater of 8 minutes and twice
    /// the negotiated Hold Time.
    Default,
    /// A fixed value; must exceed the negotiated Hold Time (§4.4), else
    /// the default is used.
    Fixed(Duration),
    /// No `SendHoldTimer`.
    Disabled,
}

/// Per-peer FSM configuration: the mandatory and optional session
/// attributes of RFC 4271 §8 that this implementation supports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Our ASN; also what makes a session internal or external.
    pub local_as: Asn,
    /// Our BGP Identifier.
    pub router_id: RouterId,
    /// The peer's expected ASN (RFC 4271 §6.2 Bad Peer AS otherwise).
    pub remote_as: Asn,
    /// Configured Hold Time; RFC 4271 §10 suggests 90 s.
    pub hold_time: HoldTime,
    /// `KeepaliveTime`; `None` means one third of the negotiated Hold Time
    /// (RFC 4271 §10).
    pub keepalive_time: Option<Duration>,
    /// `ConnectRetryTime`; RFC 4271 §10 suggests 120 s.
    pub connect_retry_time: Duration,
    /// The "large value" for the `HoldTimer` while waiting for the peer's
    /// OPEN; RFC 4271 §8.2.2 suggests 4 minutes.
    pub open_hold_time: Duration,
    /// `DelayOpen` with its `DelayOpenTime`, or none.
    pub delay_open: Option<Duration>,
    /// `DampPeerOscillations` with its `IdleHoldTime` schedule, or none, in
    /// which case automatic restarts wait `connect_retry_time`.
    pub damping: Option<Damping>,
    /// `SendHoldTime` (RFC 9687).
    pub send_hold_time: SendHoldTime,
    /// Capabilities to advertise. Four-octet AS is added automatically.
    pub capabilities: Vec<Capability>,
    /// Seed for timer jitter (RFC 4271 §10); zero disables jitter, which
    /// tests rely on.
    pub jitter_seed: u64,
    /// `PassiveTcpEstablishment`: never initiate the TCP connection.
    pub passive: bool,
    /// `SendNOTIFICATIONwithoutOPEN`: answer a bad OPEN or header received
    /// before we sent our OPEN with a NOTIFICATION anyway.
    pub send_notification_without_open: bool,
    /// `CollisionDetectEstablishedState`: honour an `OpenCollisionDump` while
    /// Established.
    pub collision_detect_established: bool,
}

impl Config {
    /// A configuration with the RFC 4271 §10 suggested values, damping on,
    /// the RFC 9687 default `SendHoldTime`, and no jitter.
    #[must_use]
    pub fn new(local_as: Asn, router_id: RouterId, remote_as: Asn) -> Config {
        Config {
            local_as,
            router_id,
            remote_as,
            // invariant: 90 is a valid Hold Time (RFC 4271 §4.2).
            hold_time: HoldTime::new(90).unwrap_or(HoldTime::ZERO),
            keepalive_time: None,
            connect_retry_time: Duration::from_secs(120),
            open_hold_time: Duration::from_secs(240),
            delay_open: None,
            damping: Some(Damping::default()),
            send_hold_time: SendHoldTime::Default,
            capabilities: Vec::new(),
            jitter_seed: 0,
            passive: false,
            send_notification_without_open: false,
            collision_detect_established: false,
        }
    }
}

/// A trait-free hook for the tests and the daemon to turn an elapsed
/// deadline into the event the RFC names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimerKind {
    /// `ConnectRetryTimer` (event 9).
    ConnectRetry,
    /// `HoldTimer` (event 10).
    Hold,
    /// `KeepaliveTimer` (event 11).
    Keepalive,
    /// `DelayOpenTimer` (event 12).
    DelayOpen,
    /// `IdleHoldTimer` (event 13).
    IdleHold,
    /// `SendHoldTimer` (event 29, RFC 9687).
    SendHold,
}

impl TimerKind {
    /// The event this timer's expiry raises.
    #[must_use]
    pub const fn event(self) -> Event {
        match self {
            TimerKind::ConnectRetry => Event::ConnectRetryTimerExpires,
            TimerKind::Hold => Event::HoldTimerExpires,
            TimerKind::Keepalive => Event::KeepaliveTimerExpires,
            TimerKind::DelayOpen => Event::DelayOpenTimerExpires,
            TimerKind::IdleHold => Event::IdleHoldTimerExpires,
            TimerKind::SendHold => Event::SendHoldTimerExpires,
        }
    }
}

/// Deadline helper re-exported for callers that build their own waits.
#[must_use]
pub fn remaining(deadline: Instant, now: Instant) -> Duration {
    deadline.saturating_duration_since(now)
}
