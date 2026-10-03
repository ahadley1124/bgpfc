//! The transition function: RFC 4271 §8.2.2 state by state, with the
//! RFC 9687 additions.
//!
//! Every arm cites the paragraph it implements. "Releases all BGP
//! resources" is [`Fsm::release_resources`]; "performs peer oscillation
//! damping" is the `damp` argument of [`Fsm::go_idle`].

use std::time::{Duration, Instant};

use bgpfc_wire::capability::Capability;
use bgpfc_wire::error::{CeaseSubcode, DecodeError, ErrorCode, FsmSubcode, OpenSubcode};
use bgpfc_wire::header::MessageType;
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::types::{AddressFamily, HoldTime};
use bgpfc_wire::update::PeerKind;

use crate::timers::{Jitter, Timer};
use crate::{Action, Config, Event, SendHoldTime, Session, State, TimerKind};

/// NOTIFICATION error code "Send Hold Timer Expired" (RFC 9687 §9).
pub const SEND_HOLD_TIMER_EXPIRED: ErrorCode = ErrorCode::Unknown(8);

/// One peer's session state machine.
#[derive(Clone, Debug)]
pub struct Fsm {
    config: Config,
    state: State,
    connect_retry_counter: u32,
    connect_retry: Timer,
    hold: Timer,
    keepalive: Timer,
    delay_open: Timer,
    idle_hold: Timer,
    send_hold: Timer,
    jitter: Jitter,
    /// Current `IdleHoldTime` under damping; doubles on each damped failure.
    idle_hold_time: Duration,
    /// Set by `ManualStop`: no automatic restart until `ManualStart`.
    admin_down: bool,
    /// A `ManualStartPassive` asked for one passive attempt.
    passive_once: bool,
    session: Option<Session>,
}

impl Fsm {
    /// A new FSM in Idle. Nothing happens until a start event.
    #[must_use]
    pub fn new(config: Config) -> Fsm {
        let idle_hold_time = config
            .damping
            .map_or(config.connect_retry_time, |d| d.initial);
        Fsm {
            jitter: Jitter::new(config.jitter_seed),
            idle_hold_time,
            config,
            state: State::Idle,
            connect_retry_counter: 0,
            connect_retry: Timer::default(),
            hold: Timer::default(),
            keepalive: Timer::default(),
            delay_open: Timer::default(),
            idle_hold: Timer::default(),
            send_hold: Timer::default(),
            admin_down: false,
            passive_once: false,
            session: None,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// The configuration this FSM runs with.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// `ConnectRetryCounter` (RFC 4271 §8).
    #[must_use]
    pub const fn connect_retry_counter(&self) -> u32 {
        self.connect_retry_counter
    }

    /// Negotiated session parameters, from the peer's OPEN onwards
    /// (`OpenConfirm` and Established).
    #[must_use]
    pub const fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Whether the operator stopped this peer (RFC 4271 §8.1.2 event 2).
    #[must_use]
    pub const fn is_admin_down(&self) -> bool {
        self.admin_down
    }

    /// The timer of the given kind.
    #[must_use]
    pub const fn timer(&self, kind: TimerKind) -> Timer {
        match kind {
            TimerKind::ConnectRetry => self.connect_retry,
            TimerKind::Hold => self.hold,
            TimerKind::Keepalive => self.keepalive,
            TimerKind::DelayOpen => self.delay_open,
            TimerKind::IdleHold => self.idle_hold,
            TimerKind::SendHold => self.send_hold,
        }
    }

    const ALL_TIMERS: [TimerKind; 6] = [
        TimerKind::ConnectRetry,
        TimerKind::Hold,
        TimerKind::Keepalive,
        TimerKind::DelayOpen,
        TimerKind::IdleHold,
        TimerKind::SendHold,
    ];

    /// The earliest running deadline: how long the caller may block.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        Self::ALL_TIMERS
            .iter()
            .filter_map(|k| self.timer(*k).deadline())
            .min()
    }

    /// The expired timer with the earliest deadline, if any. Feed
    /// [`TimerKind::event`] to [`Fsm::handle`] and ask again.
    #[must_use]
    pub fn expired(&self, now: Instant) -> Option<TimerKind> {
        Self::ALL_TIMERS
            .iter()
            .copied()
            .filter(|k| self.timer(*k).has_expired(now))
            .min_by_key(|k| self.timer(*k).deadline())
    }

    /// Tell the FSM the caller wrote a message (an UPDATE) on its own:
    /// restarts the `KeepaliveTimer` (RFC 4271 §8.2.2 Established, "each time
    /// the local system sends a KEEPALIVE or UPDATE") and the `SendHoldTimer`
    /// (RFC 9687 §4.3).
    pub fn message_sent(&mut self, now: Instant) {
        if self.state != State::Established {
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        if session.hold_time.is_zero() {
            return;
        }
        let keepalive = self.jitter.apply(session.keepalive_time);
        self.keepalive.start(now, keepalive);
        self.restart_send_hold(now);
    }

    /// Apply one event (RFC 4271 §8.2.2; RFC 9687 §4.3).
    pub fn handle(&mut self, event: Event, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        match self.state {
            State::Idle => self.in_idle(&event, now, &mut actions),
            State::Connect => self.in_connect(event, now, &mut actions),
            State::Active => self.in_active(event, now, &mut actions),
            State::OpenSent => self.in_open_sent(event, now, &mut actions),
            State::OpenConfirm => self.in_open_confirm(event, now, &mut actions),
            State::Established => self.in_established(event, now, &mut actions),
        }
        actions
    }

    // ------------------------------------------------------------ Idle

    fn in_idle(&mut self, event: &Event, now: Instant, actions: &mut Vec<Action>) {
        match event {
            // RFC 4271 §8.2.2 Idle: events 1, 3 (and 4, 5–7 via config).
            Event::ManualStart => {
                self.admin_down = false;
                self.reset_damping();
                self.start(now, self.config.passive, actions);
            }
            Event::ManualStartPassive => {
                self.admin_down = false;
                self.reset_damping();
                self.passive_once = true;
                self.start(now, true, actions);
            }
            // RFC 4271 §8.2.2 Idle: event 13 ends the damping hold.
            Event::AutomaticStart | Event::IdleHoldTimerExpires if !self.admin_down => {
                self.start(now, self.config.passive, actions);
            }
            // RFC 4271 §8.2.2 Idle: ManualStop is ignored for the state, but
            // it must cancel a pending automatic restart.
            Event::ManualStop => {
                self.admin_down = true;
                self.idle_hold.stop();
            }
            // RFC 4271 §8.2.2 Idle: every other event does nothing.
            _ => {}
        }
    }

    /// RFC 4271 §8.2.2 Idle, start events: initialise, zero the counter,
    /// start the `ConnectRetryTimer`, and connect (Connect) or only listen
    /// (Active, with `PassiveTcpEstablishment`).
    fn start(&mut self, now: Instant, passive: bool, actions: &mut Vec<Action>) {
        self.idle_hold.stop();
        self.connect_retry_counter = 0;
        let retry = self.jitter.apply(self.config.connect_retry_time);
        self.connect_retry.start(now, retry);
        if passive {
            self.state = State::Active;
        } else {
            actions.push(Action::Connect);
            self.state = State::Connect;
        }
    }

    // --------------------------------------------------------- Connect

    fn in_connect(&mut self, event: Event, now: Instant, actions: &mut Vec<Action>) {
        match event {
            // RFC 4271 §8.2.2 Connect: start events are ignored, and event 14
            // (a valid incoming request) just lets the connection proceed.
            Event::ManualStart
            | Event::ManualStartPassive
            | Event::AutomaticStart
            | Event::TcpConnectionValid => {}
            // RFC 4271 §8.2.2 Connect: ManualStop.
            Event::ManualStop => self.manual_stop(now, actions),
            // RFC 4271 §8.2.2 Connect: ConnectRetryTimer_Expires.
            Event::ConnectRetryTimerExpires => {
                actions.push(Action::DropConnection);
                let retry = self.jitter.apply(self.config.connect_retry_time);
                self.connect_retry.start(now, retry);
                self.delay_open.stop();
                actions.push(Action::Connect);
            }
            // RFC 4271 §8.2.2 Connect: DelayOpenTimer_Expires.
            Event::DelayOpenTimerExpires => self.send_open_and_wait(now, actions),
            // RFC 4271 §8.2.2 Connect: event 15.
            Event::TcpCrInvalid => actions.push(Action::RejectConnection),
            // RFC 4271 §8.2.2 Connect: events 16 and 17.
            Event::TcpCrAcked | Event::TcpConnectionConfirmed => {
                self.tcp_connected(now, actions);
            }
            // RFC 4271 §8.2.2 Connect: TcpConnectionFails.
            Event::TcpConnectionFails => {
                if self.delay_open.is_running() {
                    let retry = self.jitter.apply(self.config.connect_retry_time);
                    self.connect_retry.start(now, retry);
                    self.delay_open.stop();
                    self.state = State::Active;
                } else {
                    self.connect_retry.stop();
                    self.go_idle(now, false, false, actions);
                }
            }
            // RFC 4271 §8.2.2 Connect: event 20.
            Event::BgpOpen(open) if self.delay_open.is_running() => {
                self.open_during_delay(&open, now, actions);
            }
            // RFC 4271 §8.2.2 Connect: events 21 and 22.
            Event::BgpHeaderErr(e) | Event::BgpOpenMsgErr(e) => {
                if self.config.send_notification_without_open {
                    actions.push(Action::SendNotification(
                        NotificationMessage::from_decode_error(e),
                    ));
                }
                self.connect_retry.stop();
                self.go_idle(now, true, true, actions);
            }
            // RFC 4271 §8.2.2 Connect: event 24.
            Event::NotifMsgVerErr => {
                let delayed = self.delay_open.is_running();
                self.connect_retry.stop();
                self.delay_open.stop();
                self.go_idle(now, !delayed, !delayed, actions);
            }
            // RFC 4271 §8.2.2 Connect: any other event (8, 10–11, 13, 19,
            // 23, 25–28, and 29).
            _ => {
                self.connect_retry.stop();
                self.delay_open.stop();
                self.go_idle(now, true, true, actions);
            }
        }
    }

    // ---------------------------------------------------------- Active

    fn in_active(&mut self, event: Event, now: Instant, actions: &mut Vec<Action>) {
        match event {
            // RFC 4271 §8.2.2 Active: start events ignored; event 14 proceeds.
            Event::ManualStart
            | Event::ManualStartPassive
            | Event::AutomaticStart
            | Event::TcpConnectionValid => {}
            // RFC 4271 §8.2.2 Active: ManualStop, with the optional Cease
            // when an OPEN was being delayed.
            Event::ManualStop => {
                if self.delay_open.is_running() && self.config.send_notification_without_open {
                    actions.push(Action::SendNotification(NotificationMessage::cease(
                        CeaseSubcode::AdministrativeShutdown,
                    )));
                }
                self.manual_stop(now, actions);
            }
            // RFC 4271 §8.2.2 Active: ConnectRetryTimer_Expires goes to
            // Connect and initiates a connection.
            // NOTE(interop): a PassiveTcpEstablishment peer never initiates
            // (BIRD, FRR "passive"); it restarts the timer and stays Active.
            Event::ConnectRetryTimerExpires => {
                let retry = self.jitter.apply(self.config.connect_retry_time);
                self.connect_retry.start(now, retry);
                if !(self.config.passive || self.passive_once) {
                    actions.push(Action::Connect);
                    self.state = State::Connect;
                }
            }
            // RFC 4271 §8.2.2 Active: DelayOpenTimer_Expires.
            Event::DelayOpenTimerExpires => self.send_open_and_wait(now, actions),
            Event::TcpCrInvalid => actions.push(Action::RejectConnection),
            Event::TcpCrAcked | Event::TcpConnectionConfirmed => {
                self.tcp_connected(now, actions);
            }
            // RFC 4271 §8.2.2 Active: TcpConnectionFails restarts the
            // ConnectRetryTimer and goes to Idle with damping.
            Event::TcpConnectionFails => {
                let retry = self.jitter.apply(self.config.connect_retry_time);
                self.connect_retry.start(now, retry);
                self.delay_open.stop();
                self.go_idle(now, true, true, actions);
            }
            Event::BgpOpen(open) if self.delay_open.is_running() => {
                self.open_during_delay(&open, now, actions);
            }
            Event::BgpHeaderErr(e) | Event::BgpOpenMsgErr(e) => {
                if self.config.send_notification_without_open {
                    actions.push(Action::SendNotification(
                        NotificationMessage::from_decode_error(e),
                    ));
                }
                self.connect_retry.stop();
                self.go_idle(now, true, true, actions);
            }
            Event::NotifMsgVerErr => {
                let delayed = self.delay_open.is_running();
                self.connect_retry.stop();
                self.delay_open.stop();
                self.go_idle(now, !delayed, !delayed, actions);
            }
            // RFC 4271 §8.2.2 Active: any other event.
            _ => {
                self.connect_retry.stop();
                self.go_idle(now, true, true, actions);
            }
        }
    }

    // -------------------------------------------------------- OpenSent

    fn in_open_sent(&mut self, event: Event, now: Instant, actions: &mut Vec<Action>) {
        match event {
            // Start events are ignored; a second TCP connection (events 14,
            // 16, 17) is tracked by the coordinator per §6.8 and an invalid
            // request (15) is ignored.
            Event::ManualStart
            | Event::ManualStartPassive
            | Event::AutomaticStart
            | Event::TcpConnectionValid
            | Event::TcpCrAcked
            | Event::TcpConnectionConfirmed
            | Event::TcpCrInvalid => {}
            // RFC 4271 §8.2.2 OpenSent: ManualStop sends a Cease.
            Event::ManualStop => {
                actions.push(Action::SendNotification(NotificationMessage::cease(
                    CeaseSubcode::AdministrativeShutdown,
                )));
                self.manual_stop(now, actions);
            }
            // RFC 4271 §8.2.2 OpenSent: AutomaticStop sends a Cease.
            Event::AutomaticStop(cease) => {
                actions.push(Action::SendNotification(cease));
                self.connect_retry.stop();
                self.go_idle(now, true, true, actions);
            }
            // RFC 4271 §8.2.2 OpenSent: HoldTimer_Expires.
            Event::HoldTimerExpires => {
                actions.push(Action::SendNotification(
                    NotificationMessage::hold_timer_expired(),
                ));
                self.connect_retry.stop();
                self.go_idle(now, true, true, actions);
            }
            // RFC 4271 §8.2.2 OpenSent: TcpConnectionFails goes to Active.
            Event::TcpConnectionFails => {
                actions.push(Action::DropConnection);
                let retry = self.jitter.apply(self.config.connect_retry_time);
                self.connect_retry.start(now, retry);
                self.release_resources();
                self.state = State::Active;
            }
            // RFC 4271 §8.2.2 OpenSent: BGPOpen (event 19).
            Event::BgpOpen(open) => match self.accept_open(&open) {
                Ok(session) => {
                    self.delay_open.stop();
                    self.connect_retry.stop();
                    actions.push(Action::SendKeepalive);
                    self.start_session_timers(&session, now);
                    self.session = Some(session);
                    self.state = State::OpenConfirm;
                }
                // RFC 4271 §8.2.2 OpenSent: an OPEN that fails the §6.2
                // checks is event 22.
                Err(e) => self.open_error(e, now, actions),
            },
            Event::BgpHeaderErr(e) | Event::BgpOpenMsgErr(e) => self.open_error(e, now, actions),
            // RFC 4271 §8.2.2 OpenSent: OpenCollisionDump.
            Event::OpenCollisionDump => self.collision_dump(now, false, actions),
            // RFC 4271 §8.2.2 OpenSent: NotifMsgVerErr, no counter change.
            Event::NotifMsgVerErr => {
                self.connect_retry.stop();
                self.go_idle(now, false, false, actions);
            }
            // RFC 4271 §8.2.2 OpenSent: any other event is an FSM error.
            other => self.fsm_error(
                &other,
                FsmSubcode::UnexpectedInOpenSent,
                now,
                false,
                actions,
            ),
        }
    }

    // ----------------------------------------------------- OpenConfirm

    fn in_open_confirm(&mut self, event: Event, now: Instant, actions: &mut Vec<Action>) {
        match event {
            // Start events are ignored; a second TCP connection (events 14,
            // 16, 17) is tracked by the coordinator per §6.8 and an invalid
            // request (15) is ignored.
            // Start events are ignored; a second TCP connection (events 14,
            // 16, 17) is tracked by the coordinator per §6.8, an invalid
            // request (15) is ignored, and a valid OPEN (19) goes to
            // collision detection (§6.8), which the coordinator runs and
            // answers with OpenCollisionDump if this side loses.
            Event::ManualStart
            | Event::ManualStartPassive
            | Event::AutomaticStart
            | Event::TcpConnectionValid
            | Event::TcpCrAcked
            | Event::TcpConnectionConfirmed
            | Event::TcpCrInvalid
            | Event::BgpOpen(_) => {}
            Event::ManualStop => {
                actions.push(Action::SendNotification(NotificationMessage::cease(
                    CeaseSubcode::AdministrativeShutdown,
                )));
                self.manual_stop(now, actions);
            }
            Event::AutomaticStop(cease) => {
                actions.push(Action::SendNotification(cease));
                self.connect_retry.stop();
                self.go_idle(now, true, true, actions);
            }
            Event::HoldTimerExpires => {
                actions.push(Action::SendNotification(
                    NotificationMessage::hold_timer_expired(),
                ));
                self.connect_retry.stop();
                self.go_idle(now, true, true, actions);
            }
            // RFC 4271 §8.2.2 OpenConfirm: KeepaliveTimer_Expires.
            Event::KeepaliveTimerExpires => {
                actions.push(Action::SendKeepalive);
                if let Some(s) = &self.session {
                    let k = self.jitter.apply(s.keepalive_time);
                    self.keepalive.start(now, k);
                }
            }
            // RFC 4271 §8.2.2 OpenConfirm: TcpConnectionFails or NotifMsg.
            Event::TcpConnectionFails | Event::NotifMsg(_) => {
                self.connect_retry.stop();
                self.go_idle(now, true, true, actions);
            }
            Event::NotifMsgVerErr => {
                self.connect_retry.stop();
                self.go_idle(now, false, false, actions);
            }
            Event::BgpHeaderErr(e) | Event::BgpOpenMsgErr(e) => self.open_error(e, now, actions),
            Event::OpenCollisionDump => self.collision_dump(now, false, actions),
            // RFC 4271 §8.2.2 OpenConfirm: KeepAliveMsg → Established;
            // RFC 9687 §4.3: also start the SendHoldTimer.
            Event::KeepAliveMsg => {
                let Some(session) = self.session.clone() else {
                    // invariant: OpenConfirm is only entered with a session.
                    return;
                };
                if !session.hold_time.is_zero() {
                    self.hold.start(
                        now,
                        Duration::from_secs(u64::from(session.hold_time.secs())),
                    );
                }
                self.state = State::Established;
                self.restart_send_hold(now);
                self.reset_damping();
                actions.push(Action::SessionUp(session));
            }
            other => {
                self.fsm_error(
                    &other,
                    FsmSubcode::UnexpectedInOpenConfirm,
                    now,
                    false,
                    actions,
                );
            }
        }
    }

    // ----------------------------------------------------- Established

    fn in_established(&mut self, event: Event, now: Instant, actions: &mut Vec<Action>) {
        match event {
            // RFC 4271 §8.2.2 Established: ManualStop deletes routes too.
            Event::ManualStop => {
                actions.push(Action::SendNotification(NotificationMessage::cease(
                    CeaseSubcode::AdministrativeShutdown,
                )));
                actions.push(Action::SessionDown);
                self.manual_stop(now, actions);
            }
            Event::AutomaticStop(cease) => {
                actions.push(Action::SendNotification(cease));
                self.session_down(now, true, actions);
            }
            Event::HoldTimerExpires => {
                actions.push(Action::SendNotification(
                    NotificationMessage::hold_timer_expired(),
                ));
                self.session_down(now, true, actions);
            }
            // RFC 4271 §8.2.2 Established: KeepaliveTimer_Expires, restart
            // unless the negotiated Hold Time is zero.
            Event::KeepaliveTimerExpires => {
                actions.push(Action::SendKeepalive);
                self.message_sent(now);
            }
            Event::OpenCollisionDump if self.config.collision_detect_established => {
                self.collision_dump(now, true, actions);
            }
            // Start events are ignored; a second TCP connection (events 14,
            // 16, 17) is tracked by the coordinator per §6.8 and an invalid
            // request (15) is ignored. A valid OPEN (19) goes to collision
            // detection only with CollisionDetectEstablishedState, and
            // RFC 4271 §8.1.5 says collisions are otherwise ignored here.
            Event::ManualStart
            | Event::ManualStartPassive
            | Event::AutomaticStart
            | Event::TcpConnectionValid
            | Event::TcpCrAcked
            | Event::TcpConnectionConfirmed
            | Event::TcpCrInvalid
            | Event::BgpOpen(_)
            | Event::OpenCollisionDump => {}
            // RFC 4271 §8.2.2 Established: NOTIFICATION or TCP failure; no
            // damping named.
            Event::NotifMsgVerErr | Event::NotifMsg(_) | Event::TcpConnectionFails => {
                self.session_down(now, false, actions);
            }
            // RFC 4271 §8.2.2 Established: KEEPALIVE / UPDATE restart the
            // HoldTimer when the negotiated Hold Time is non-zero.
            Event::KeepAliveMsg | Event::UpdateMsg => {
                if let Some(s) = &self.session
                    && !s.hold_time.is_zero()
                {
                    self.hold
                        .start(now, Duration::from_secs(u64::from(s.hold_time.secs())));
                }
            }
            // RFC 4271 §8.2.2 Established: UpdateMsgErr sends the UPDATE error.
            // RFC 4271 §6.1: a header error carries its own NOTIFICATION.
            // NOTE(interop): §8.2.2 lists event 21 under "FSM error" for
            // Established, but §6.1 is a MUST and what BIRD and FRR send.
            Event::UpdateMsgErr(e) | Event::BgpHeaderErr(e) => {
                actions.push(Action::SendNotification(
                    NotificationMessage::from_decode_error(e),
                ));
                self.session_down(now, true, actions);
            }
            // RFC 9687 §4.3: SendHoldTimer_Expires.
            Event::SendHoldTimerExpires => {
                actions.push(Action::SendNotification(NotificationMessage {
                    code: SEND_HOLD_TIMER_EXPIRED,
                    subcode: 0,
                    data: Vec::new(),
                }));
                actions.push(Action::LogError("send hold timer expired"));
                self.session_down(now, true, actions);
            }
            // RFC 4271 §8.2.2 Established: any other event (9, 12–13, 22).
            other => {
                self.fsm_error(
                    &other,
                    FsmSubcode::UnexpectedInEstablished,
                    now,
                    true,
                    actions,
                );
            }
        }
    }

    // --------------------------------------------------------- helpers

    /// RFC 4271 §8.2.2 Connect/Active, events 16 and 17.
    fn tcp_connected(&mut self, now: Instant, actions: &mut Vec<Action>) {
        self.connect_retry.stop();
        if let Some(delay) = self.config.delay_open {
            self.delay_open.start(now, delay);
        } else {
            self.send_open_and_wait(now, actions);
        }
    }

    /// Send our OPEN, set the `HoldTimer` to the large value, go to `OpenSent`
    /// (RFC 4271 §8.2.2 Connect/Active).
    fn send_open_and_wait(&mut self, now: Instant, actions: &mut Vec<Action>) {
        self.connect_retry.stop();
        self.delay_open.stop();
        actions.push(Action::SendOpen(self.build_open()));
        self.hold.start(now, self.config.open_hold_time);
        self.state = State::OpenSent;
    }

    /// RFC 4271 §8.2.2 Connect/Active, event 20: the peer's OPEN arrived
    /// while ours was delayed. Answer with OPEN and KEEPALIVE and go
    /// straight to `OpenConfirm`.
    fn open_during_delay(&mut self, open: &OpenMessage, now: Instant, actions: &mut Vec<Action>) {
        self.connect_retry.stop();
        self.delay_open.stop();
        match self.accept_open(open) {
            Ok(session) => {
                actions.push(Action::SendOpen(self.build_open()));
                actions.push(Action::SendKeepalive);
                self.start_session_timers(&session, now);
                self.session = Some(session);
                self.state = State::OpenConfirm;
            }
            Err(e) => {
                if self.config.send_notification_without_open {
                    actions.push(Action::SendNotification(
                        NotificationMessage::from_decode_error(e),
                    ));
                }
                self.go_idle(now, true, true, actions);
            }
        }
    }

    /// Our OPEN (RFC 4271 §4.2; RFC 6793 §3 adds the Four-octet AS
    /// capability and `AS_TRANS`; RFC 7607 §2 never AS 0, which the config
    /// type cannot express).
    fn build_open(&self) -> OpenMessage {
        OpenMessage::new(
            self.config.local_as,
            self.config.hold_time,
            self.config.router_id,
            self.config.capabilities.clone(),
        )
    }

    /// The §6.2 checks the codec cannot do, and capability negotiation.
    fn accept_open(&self, open: &OpenMessage) -> Result<Session, DecodeError> {
        // RFC 4271 §6.2: an unacceptable AS is Bad Peer AS; here that is any
        // AS but the configured one.
        let peer_as = open.asn();
        if peer_as != self.config.remote_as {
            return Err(DecodeError::open(OpenSubcode::BadPeerAs, Vec::new()));
        }
        // RFC 4271 §4.2: the Hold Timer is the smaller of the two.
        let secs = self.config.hold_time.secs().min(open.hold_time.secs());
        // invariant: the minimum of two valid Hold Times is valid.
        let hold_time = HoldTime::new(secs).unwrap_or(open.hold_time);
        // RFC 4271 §10: KeepaliveTime one third of the Hold Time unless
        // configured smaller.
        let third = Duration::from_secs(u64::from(secs) / 3);
        let keepalive_time = if hold_time.is_zero() {
            Duration::ZERO
        } else {
            self.config.keepalive_time.map_or(third, |k| k.min(third))
        };
        // RFC 6793 §3 / RFC 8654 §4: both sides must advertise.
        let ours = &self.config.capabilities;
        let four_octet_as = open.has(&Capability::FourOctetAs(peer_as))
            || open
                .capabilities
                .iter()
                .any(|c| matches!(c, Capability::FourOctetAs(_)));
        let extended_messages =
            ours.contains(&Capability::ExtendedMessage) && open.has(&Capability::ExtendedMessage);
        // RFC 2918 §4: send ROUTE-REFRESH only if the peer advertised it.
        let route_refresh = open.has(&Capability::RouteRefresh);
        let families = negotiate_families(ours, &open.capabilities);
        if families.is_empty() {
            // RFC 5492 §5: Unsupported Capability, Data = the capabilities
            // we require, encoded as in the OPEN.
            let mut data = Vec::new();
            for c in ours
                .iter()
                .filter(|c| matches!(c, Capability::Multiprotocol(_)))
            {
                // Our own capabilities encoded once already; an encode
                // error here is impossible for known variants.
                let _ = c.encode(&mut data);
            }
            return Err(DecodeError::open(OpenSubcode::UnsupportedCapability, data));
        }
        Ok(Session {
            peer_as,
            peer_router_id: open.router_id,
            // RFC 4271 §8.2.2: same AS means an internal connection.
            peer: if peer_as == self.config.local_as {
                PeerKind::Internal
            } else {
                PeerKind::External
            },
            hold_time,
            keepalive_time,
            four_octet_as,
            extended_messages,
            route_refresh,
            families,
            peer_capabilities: open.capabilities.clone(),
        })
    }

    /// RFC 4271 §8.2.2 `OpenSent` event 19: start the `KeepaliveTimer` and set
    /// the `HoldTimer` to the negotiated value, or neither when it is zero.
    fn start_session_timers(&mut self, session: &Session, now: Instant) {
        if session.hold_time.is_zero() {
            self.keepalive.stop();
            self.hold.stop();
        } else {
            let k = self.jitter.apply(session.keepalive_time);
            self.keepalive.start(now, k);
            self.hold.start(
                now,
                Duration::from_secs(u64::from(session.hold_time.secs())),
            );
        }
    }

    /// RFC 9687 §4.3: restart the `SendHoldTimer` on every message sent,
    /// unless `SendHoldTime` or the negotiated Hold Time is zero.
    fn restart_send_hold(&mut self, now: Instant) {
        let Some(session) = &self.session else {
            return;
        };
        if session.hold_time.is_zero() {
            self.send_hold.stop();
            return;
        }
        let hold = Duration::from_secs(u64::from(session.hold_time.secs()));
        // RFC 9687 §6: the greater of 8 minutes and twice the Hold Time;
        // §4.4: a configured value must exceed the Hold Time.
        let default = Duration::from_mins(8).max(hold * 2);
        let after = match self.config.send_hold_time {
            SendHoldTime::Disabled => {
                self.send_hold.stop();
                return;
            }
            SendHoldTime::Fixed(d) if d > hold => d,
            SendHoldTime::Fixed(_) | SendHoldTime::Default => default,
        };
        self.send_hold.start(now, after);
    }

    /// RFC 4271 §8.2.2 `OpenSent`/`OpenConfirm`, events 21 and 22: send the
    /// NOTIFICATION and go to Idle with damping.
    fn open_error(&mut self, e: DecodeError, now: Instant, actions: &mut Vec<Action>) {
        actions.push(Action::SendNotification(
            NotificationMessage::from_decode_error(e),
        ));
        self.connect_retry.stop();
        self.go_idle(now, true, true, actions);
    }

    /// RFC 4271 §8.2.2 event 23: Cease / Connection Collision Resolution
    /// (RFC 4486 §4).
    fn collision_dump(&mut self, now: Instant, established: bool, actions: &mut Vec<Action>) {
        actions.push(Action::SendNotification(NotificationMessage::cease(
            CeaseSubcode::ConnectionCollisionResolution,
        )));
        if established {
            self.session_down(now, true, actions);
        } else {
            self.connect_retry.stop();
            self.go_idle(now, true, true, actions);
        }
    }

    /// RFC 4271 §8.2.2 "any other event" in `OpenSent`, `OpenConfirm` and
    /// Established: NOTIFICATION with Finite State Machine Error, using the
    /// RFC 6608 §4 subcode and message type for an unexpected message.
    fn fsm_error(
        &mut self,
        event: &Event,
        subcode: FsmSubcode,
        now: Instant,
        established: bool,
        actions: &mut Vec<Action>,
    ) {
        let kind = match event {
            Event::BgpOpen(_) | Event::BgpOpenMsgErr(_) => Some(MessageType::Open),
            Event::UpdateMsg | Event::UpdateMsgErr(_) => Some(MessageType::Update),
            Event::NotifMsg(_) => Some(MessageType::Notification),
            Event::KeepAliveMsg => Some(MessageType::Keepalive),
            _ => None,
        };
        let notification = match kind {
            Some(t) => NotificationMessage::fsm(subcode, vec![t as u8]),
            // A timer that should not have been running: no message type.
            None => NotificationMessage::fsm(FsmSubcode::Unspecified, Vec::new()),
        };
        actions.push(Action::SendNotification(notification));
        actions.push(Action::LogError("unexpected event for state"));
        if established {
            self.session_down(now, true, actions);
        } else {
            self.connect_retry.stop();
            self.go_idle(now, true, true, actions);
        }
    }

    /// Leave Established: delete routes, then the common Idle path.
    fn session_down(&mut self, now: Instant, damp: bool, actions: &mut Vec<Action>) {
        actions.push(Action::SessionDown);
        self.connect_retry.stop();
        self.go_idle(now, true, damp, actions);
    }

    /// RFC 4271 §8.2.2 `ManualStop` (all non-Idle states): no NOTIFICATION
    /// here, the caller adds one where the state requires it; counter to
    /// zero; no automatic restart.
    fn manual_stop(&mut self, now: Instant, actions: &mut Vec<Action>) {
        self.admin_down = true;
        self.connect_retry.stop();
        self.go_idle(now, false, false, actions);
        self.connect_retry_counter = 0;
    }

    /// "Releases all BGP resources": every timer but `ConnectRetry` and
    /// `IdleHold`, and the negotiated session.
    fn release_resources(&mut self) {
        self.hold.stop();
        self.keepalive.stop();
        self.delay_open.stop();
        self.send_hold.stop();
        self.session = None;
    }

    /// The common tail of every transition to Idle: drop the connection,
    /// release resources, bump the counter, damp, and schedule the
    /// automatic restart unless the operator stopped the peer.
    fn go_idle(&mut self, now: Instant, increment: bool, damp: bool, actions: &mut Vec<Action>) {
        actions.push(Action::DropConnection);
        self.release_resources();
        if increment {
            self.connect_retry_counter += 1;
        }
        self.state = State::Idle;
        self.passive_once = false;
        if self.admin_down {
            self.idle_hold.stop();
            return;
        }
        // RFC 4271 §8.1.1 group 1: hold the peer in Idle for IdleHoldTime
        // before an automatic restart; damping lengthens that hold.
        let wait = self.jitter.apply(self.idle_hold_time);
        self.idle_hold.start(now, wait);
        if damp && let Some(d) = self.config.damping {
            self.idle_hold_time = (self.idle_hold_time * 2).min(d.max);
        }
    }

    /// A successful session or a manual start ends the damping escalation.
    fn reset_damping(&mut self) {
        self.idle_hold_time = self
            .config
            .damping
            .map_or(self.config.connect_retry_time, |d| d.initial);
    }
}

/// RFC 4760 §8: a family is usable only if both sides advertised it. A side
/// with no Multiprotocol capability at all is an IPv4-unicast-only speaker.
fn negotiate_families(ours: &[Capability], theirs: &[Capability]) -> Vec<AddressFamily> {
    fn families(caps: &[Capability]) -> Vec<AddressFamily> {
        let mut v: Vec<AddressFamily> = caps
            .iter()
            .filter_map(|c| match c {
                Capability::Multiprotocol(f) => Some(*f),
                _ => None,
            })
            .collect();
        if v.is_empty() {
            v.push(AddressFamily::IPV4_UNICAST);
        }
        v.sort();
        v.dedup();
        v
    }
    let theirs = families(theirs);
    families(ours)
        .into_iter()
        .filter(|f| theirs.contains(f))
        .collect()
}

#[cfg(test)]
mod tests;
