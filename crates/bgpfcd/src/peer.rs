//! One thread per configured neighbour: owns the TCP connection and the
//! peer's FSM, turns bytes and timers into events, and executes the
//! actions the FSM returns (AGENTS.md §3).
//!
//! Implements: RFC 4271 §1, §4.5 (a NOTIFICATION is delivered before the TCP
//! connection is closed), §6.8 (collision resolution between this peer's two
//! connections), §8.2.1 (one FSM per connection; a second connection is
//! tracked until its OPEN), §8.2.2 (Idle refuses connections); RFC 4760 §7
//! (AFI/SAFI disable is reported to the RIB, the session kept); RFC 2918
//! §4 (ROUTE-REFRESH for an unadvertised family is ignored); RFC 9003 §2
//! (a received Shutdown Communication is logged); RFC 4724 §2, §4.2, §5 and
//! RFC 8538 §4 (the End-of-RIB marker goes to the RIB, a session that ends
//! gracefully leaves its routes there as stale ones, and a connection from a
//! peer that restarted replaces the established session); RFC 7313 §3.2,
//! §4, §5 (the Message Subtype of a ROUTE-REFRESH is read only on a session
//! with Enhanced Route Refresh, where a `BoRR` and an `EoRR` go to the RIB, an
//! unknown subtype is ignored and logged, and a wrong length is a
//! ROUTE-REFRESH Message Error).

use std::io::Write;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, channel, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_fsm::{Action, Event, Fsm, Session, State};
use bgpfc_wire::error::{CeaseSubcode, DecodeError, ErrorCode, OpenSubcode};
use bgpfc_wire::header::{MessageType, frame};
use bgpfc_wire::keepalive::KEEPALIVE;
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::route_refresh::{RefreshSubtype, RouteRefreshMessage};
use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::{DecodeContext, PeerKind, UpdateMessage};

use crate::messages::{ConnId, Inbound, Initiator, PeerInput, PeerReport, RibMsg};
use crate::reader;
use crate::restart::RestartState;

/// How long an outgoing TCP connect may take; RFC 4271 §8.2.2 asks the
/// `ConnectRetryTime` to leave room for it, and 120 s does.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A blocked write to a peer that stopped reading is reported as a TCP
/// failure after this long (RFC 9687 motivates not waiting forever).
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Inputs a peer thread will queue before its producers block.
const INPUT_QUEUE: usize = 256;

/// How long the connection of an Established session stays open after the
/// NOTIFICATION that ends it, for the neighbor to read the NOTIFICATION
/// and close first; see [`Linger`].
const NOTIFICATION_LINGER: Duration = Duration::from_secs(3);

/// Octets of UPDATEs that may wait for a peer thread to write them. More
/// means the peer has fallen too far behind, and its session is reset
/// (AGENTS.md §3, backpressure). Room for a few full tables of UPDATEs
/// (7.4 MB for a million IPv4 prefixes), which another peer's table load
/// can produce faster than a slow peer reads.
const OUTBOX_BYTES: usize = 32 << 20;

/// What the daemon knows about one neighbour.
#[derive(Clone, Debug)]
pub(crate) struct PeerConfig {
    /// The neighbour's address.
    pub(crate) addr: IpAddr,
    /// TCP port to connect to (179 unless testing).
    pub(crate) port: u16,
    /// FSM configuration.
    pub(crate) fsm: bgpfc_fsm::Config,
    /// Accept `AS_SET` in UPDATEs (RFC 9774 §3 override).
    pub(crate) allow_as_set: bool,
    /// `stale-time` of a neighbor with `graceful-restart yes` (RFC 8538
    /// §4.1): the RIB bounds the wait for the End-of-RIB marker with it.
    pub(crate) stale_time: Option<Duration>,
    /// `refresh-stale-time` of a neighbor with `enhanced-refresh yes` (RFC
    /// 7313 §4): the RIB bounds the wait for an `EoRR` with it.
    pub(crate) refresh_stale_time: Option<Duration>,
}

/// How other threads reach a peer thread.
#[derive(Clone, Debug)]
pub(crate) struct PeerHandle {
    /// The neighbour's address.
    pub(crate) addr: IpAddr,
    /// Its input queue.
    pub(crate) tx: SyncSender<PeerInput>,
    /// UPDATEs for the peer, from the RIB thread: see [`Outbox`].
    outbox: Sender<Vec<Vec<u8>>>,
    /// Shared with the peer thread.
    state: Arc<Outbox>,
    /// Set by the RIB thread when the peer exceeded a prefix limit and
    /// [`PeerInput::PrefixLimit`] did not fit in the full queue: the peer
    /// thread, busy with what fills it, ends the session after its
    /// current input (RFC 4271 §6.7), with the right Cease rather than
    /// the overrun's.
    pub(crate) prefix_limit: Arc<Mutex<Option<(AddressFamily, u32)>>>,
}

/// UPDATEs the RIB thread has encoded and the peer thread has not written
/// yet travel apart from the input queue. That queue is full whenever the
/// peer sends a table (its reader fills it), and a route the RIB sends
/// the peer meanwhile must not find it full. They are bounded by octets
/// rather than by messages: one entry can be a whole table (the initial
/// Adj-RIB-Out, RFC 2918 refresh).
#[derive(Debug, Default)]
struct Outbox {
    /// Octets queued.
    queued: AtomicUsize,
    /// Set when UPDATEs had to be dropped: the peer thread resets the
    /// session rather than leave the peer with a partial view (AGENTS.md
    /// §3, backpressure).
    overrun: AtomicBool,
}

/// Why UPDATEs were not queued.
#[derive(Debug)]
pub(crate) enum SendError {
    /// The peer is too far behind; its session will be reset.
    Overrun,
    /// The peer thread has ended.
    Gone,
}

impl PeerHandle {
    /// A handle on the input queue `tx` alone, with no peer thread behind
    /// it, for tests that watch what a peer is told.
    #[cfg(test)]
    pub(crate) fn on(addr: IpAddr, tx: SyncSender<PeerInput>) -> PeerHandle {
        PeerHandle {
            addr,
            tx,
            outbox: channel().0,
            state: Arc::default(),
            prefix_limit: Arc::default(),
        }
    }

    /// Queue UPDATEs for the peer thread to write, in order. Never blocks
    /// the caller (the RIB thread).
    ///
    /// # Errors
    /// [`SendError::Overrun`] when more than [`OUTBOX_BYTES`] already
    /// wait: the UPDATEs are dropped and the session is reset. Whatever
    /// its size, a batch is taken when nothing waits.
    pub(crate) fn send_updates(&self, messages: Vec<Vec<u8>>) -> Result<(), SendError> {
        let octets: usize = messages.iter().map(Vec::len).sum();
        // Only this thread adds and only the peer thread subtracts, so
        // the figure can only have dropped by the time it is added to.
        let queued = self.state.queued.load(Ordering::Relaxed);
        let result = if queued > 0 && queued + octets > OUTBOX_BYTES {
            self.state.overrun.store(true, Ordering::Relaxed);
            Err(SendError::Overrun)
        } else {
            self.state.queued.fetch_add(octets, Ordering::Relaxed);
            self.outbox.send(messages).map_err(|_| SendError::Gone)
        };
        // A wake-up for a thread waiting on its input queue. When the
        // queue is full the thread is busy, and it looks at the outbox
        // after every input.
        let _ = self.tx.try_send(PeerInput::Updates);
        result
    }
}

struct Conn {
    id: ConnId,
    stream: TcpStream,
    extended: Arc<AtomicBool>,
    initiator: Initiator,
}

/// A connection a NOTIFICATION was written on, kept open until the
/// neighbor closes it or `until` passes.
///
/// RFC 4271 §4.5 closes the connection after a NOTIFICATION, and RFC 4724
/// §4.2 has a neighbor that sees the TCP connection fail keep our routes
/// where it would delete them on a NOTIFICATION. Closing at once puts the
/// FIN right behind the NOTIFICATION, and a neighbor that reads both in
/// one go may take the end for a failure of the transport: the Hard Reset
/// of RFC 8538 §3.2, which exists to have the routes deleted, is then
/// lost. The neighbor closes when it has processed the NOTIFICATION
/// (RFC 4271 §6), so waiting for that close delivers the NOTIFICATION
/// as such. A reader thread goes on reading the connection and reports its
/// end, which is also what keeps unread data from turning our close into
/// a reset.
///
/// NOTE(interop): FRR 8.4 reads the NOTIFICATION and the FIN in one pass
/// of its I/O thread under load, queues the connection closing for its main
/// thread and never processes the NOTIFICATION behind it: it keeps the
/// routes for its restart time after a Hard Reset that came with the FIN.
struct Linger {
    id: ConnId,
    stream: TcpStream,
    until: Instant,
}

/// One neighbour's thread state.
pub(crate) struct Peer {
    cfg: PeerConfig,
    fsm: Fsm,
    rx: Receiver<PeerInput>,
    tx: SyncSender<PeerInput>,
    rib: SyncSender<RibMsg>,
    /// The connection the FSM runs on.
    conn: Option<Conn>,
    /// A second connection, tracked until its OPEN arrives (RFC 4271
    /// §8.2.2 OpenSent/OpenConfirm) and then resolved per §6.8.
    pending: Option<Conn>,
    /// The connection of the session that just ended with a NOTIFICATION
    /// of ours, while it waits for the neighbor to close it.
    lingering: Option<Linger>,
    /// An outgoing connection the FSM asked for while `lingering`: made
    /// once the old connection is gone, so that the neighbor has dealt
    /// with the old session when the new OPEN reaches it (RFC 4271 §6.8
    /// would otherwise have it resolve a collision with a session that is
    /// ending).
    connect_waits: bool,
    next_conn: ConnId,
    attempt: u64,
    session: Option<Session>,
    write_failed: bool,
    outbox: Receiver<Vec<Vec<u8>>>,
    outbox_state: Arc<Outbox>,
    prefix_limit: Arc<Mutex<Option<(AddressFamily, u32)>>>,
    /// What the next OPEN says of a restart, kept by the FIB and RIB
    /// threads (RFC 4724 §3).
    restart: Arc<RestartState>,
    /// When the FSM last changed state.
    state_since: Instant,
    updates_in: u64,
    updates_out: u64,
    #[cfg(feature = "profiling")]
    open_timer: crate::profiling::OpenTimer,
}

/// Prepare a peer: its handle can go into the peer table before the
/// thread runs (listeners bind and privileges drop in between).
pub(crate) fn prepare(
    cfg: PeerConfig,
    rib: SyncSender<RibMsg>,
    restart: Arc<RestartState>,
) -> (PeerHandle, Peer) {
    let (tx, rx) = sync_channel(INPUT_QUEUE);
    // Unbounded in entries: send_updates bounds it by octets.
    let (outbox_tx, outbox) = channel();
    let state = Arc::new(Outbox::default());
    let prefix_limit = Arc::new(Mutex::new(None));
    let handle = PeerHandle {
        addr: cfg.addr,
        tx: tx.clone(),
        outbox: outbox_tx,
        state: Arc::clone(&state),
        prefix_limit: Arc::clone(&prefix_limit),
    };
    let fsm = Fsm::new(cfg.fsm.clone());
    let peer = Peer {
        cfg,
        fsm,
        rx,
        tx,
        rib,
        conn: None,
        pending: None,
        lingering: None,
        connect_waits: false,
        next_conn: 1,
        attempt: 0,
        session: None,
        write_failed: false,
        outbox,
        outbox_state: state,
        prefix_limit,
        restart,
        state_since: Instant::now(),
        updates_in: 0,
        updates_out: 0,
        #[cfg(feature = "profiling")]
        open_timer: crate::profiling::OpenTimer::default(),
    };
    (handle, peer)
}

impl Peer {
    /// Start the peer thread; it begins with a `ManualStart`.
    pub(crate) fn start(self) {
        let name = format!("peer-{}", self.cfg.addr);
        thread::Builder::new()
            .name(name)
            .spawn(move || self.run())
            .expect("spawning a peer thread");
    }

    fn run(mut self) {
        self.event(Event::ManualStart, Instant::now());
        loop {
            let now = Instant::now();
            let deadline = [
                self.fsm.next_deadline(),
                self.lingering.as_ref().map(|l| l.until),
            ]
            .into_iter()
            .flatten()
            .min();
            let timeout = deadline.map_or(Duration::from_secs(60), |d| {
                d.saturating_duration_since(now)
            });
            match self.rx.recv_timeout(timeout) {
                Ok(input) => {
                    if !self.input(input) {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            let now = Instant::now();
            self.expire_linger(now);
            // Every timer expiry either stops or restarts its timer, so a
            // handful of rounds drains them; the bound guards a bug.
            for _ in 0..8 {
                let Some(kind) = self.fsm.expired(now) else {
                    break;
                };
                self.event(kind.event(), now);
            }
        }
    }

    /// Feed one event to the FSM and execute what it asks for.
    fn event(&mut self, event: Event, now: Instant) {
        let before = self.fsm.state();
        if self.cfg.fsm.graceful_restart.is_some() && before != State::Established {
            // RFC 4724 §3, §4.1: the OPEN this event may send says whether
            // we have restarted and for which families the forwarding
            // state has been preserved, as of now.
            self.fsm.set_restart_advert(self.restart.advert());
        }
        let number = event.number();
        let actions = self.fsm.handle(event, now);
        let after = self.fsm.state();
        if before == after {
            bgpfc_log::trace!(
                "fsm event",
                peer = self.cfg.addr,
                state = after,
                event = number
            );
        } else {
            self.state_since = now;
            bgpfc_log::info!(
                "session state",
                peer = self.cfg.addr,
                from = before,
                to = after,
                event = number
            );
        }
        self.apply(actions, now);
        if self.write_failed {
            self.write_failed = false;
            if self.conn.is_some() {
                self.event(Event::TcpConnectionFails, now);
            }
        }
        if after == State::Established
            && let Some(p) = self.pending.take()
        {
            // RFC 4271 §6.8: a collision with an Established connection
            // closes the new one.
            close_with_cease(p, CeaseSubcode::ConnectionCollisionResolution);
        }
    }

    fn apply(&mut self, actions: Vec<Action>, _now: Instant) {
        // The session is over by the time the connection is dropped (the
        // `SessionDown` action comes first), so whether the NOTIFICATION
        // ends an Established session is settled here.
        let was_up = self.session.is_some();
        let mut notified = false;
        for action in actions {
            match action {
                Action::Connect if self.lingering.is_some() => self.connect_waits = true,
                Action::Connect => self.start_connect(),
                Action::DropConnection => {
                    self.drop_conn(notified && was_up && self.lingers_after_notification());
                    notified = false;
                }
                Action::RejectConnection => {}
                Action::SendOpen(open) => {
                    #[cfg(feature = "profiling")]
                    self.open_timer.open();
                    match open.encode() {
                        Ok(body) => self.write_message(MessageType::Open, &body),
                        Err(e) => {
                            bgpfc_log::error!(
                                "cannot encode OPEN",
                                peer = self.cfg.addr,
                                error = e
                            );
                        }
                    }
                }
                Action::SendKeepalive => self.write_raw(&KEEPALIVE),
                Action::SendNotification(n) => notified |= self.send_notification(&n),
                Action::SessionUp(session) => {
                    #[cfg(feature = "profiling")]
                    self.open_timer.established();
                    bgpfc_log::info!(
                        "session established",
                        peer = self.cfg.addr,
                        remote_as = session.peer_as,
                        router_id = session.peer_router_id,
                        hold = session.hold_time,
                        families = session.families.len()
                    );
                    if let Some(c) = &self.conn {
                        c.extended
                            .store(session.extended_messages, Ordering::Relaxed);
                    }
                    self.session = Some(session.clone());
                    let local_addr = self
                        .conn
                        .as_ref()
                        .and_then(|c| c.stream.local_addr().ok())
                        .map_or(self.cfg.addr, |a| crate::coordinator::canonical(a.ip()));
                    self.rib_send(RibMsg::PeerUp {
                        peer: self.cfg.addr,
                        local_addr,
                        session,
                        stale_time: self.cfg.stale_time,
                        refresh_stale_time: self.cfg.refresh_stale_time,
                    });
                }
                Action::SessionDown { retain } => {
                    #[cfg(feature = "profiling")]
                    bgpfc_prof::metrics::SESSIONS_DROPPED.inc();
                    bgpfc_log::info!(
                        "session down",
                        peer = self.cfg.addr,
                        routes_kept = retain.is_some()
                    );
                    self.session = None;
                    self.rib_send(RibMsg::PeerDown {
                        peer: self.cfg.addr,
                        retain,
                    });
                }
                Action::LogError(msg) => bgpfc_log::error!(msg, peer = self.cfg.addr),
                // RFC 4486 §4: automatic retries stop until the operator
                // intervenes; say so, and how.
                Action::RestartLimitReached { failures } => bgpfc_log::error!(
                    "restart limit reached, peer stays idle until `bgpfcctl clear neighbor`",
                    peer = self.cfg.addr,
                    damped_failures = failures,
                    restart_limit = self
                        .fsm
                        .config()
                        .damping
                        .and_then(|d| d.restart_limit)
                        .unwrap_or_default()
                ),
            }
        }
    }

    /// Write a NOTIFICATION on the FSM's connection. Whether it was framed
    /// and written.
    fn send_notification(&mut self, n: &NotificationMessage) -> bool {
        bgpfc_log::warn!(
            "sending notification",
            peer = self.cfg.addr,
            notification = n
        );
        let extended = self.session.as_ref().is_some_and(|s| s.extended_messages);
        match n.encode(extended) {
            Ok(body) => {
                self.write_message(MessageType::Notification, &body);
                true
            }
            Err(e) => {
                bgpfc_log::error!(
                    "cannot encode NOTIFICATION",
                    peer = self.cfg.addr,
                    error = e
                );
                false
            }
        }
    }

    /// Handle one input; `false` when the thread should end.
    fn input(&mut self, input: PeerInput) -> bool {
        let now = Instant::now();
        match input {
            PeerInput::Connected { attempt, result } => {
                if attempt != self.attempt {
                    // An attempt the FSM gave up on; the stream closes on drop.
                    return true;
                }
                match result {
                    Ok(stream) => self.accept_stream(stream, Initiator::Local, now),
                    Err(e) => {
                        bgpfc_log::debug!("connect failed", peer = self.cfg.addr, error = e);
                        if self.conn.is_none() {
                            self.event(Event::TcpConnectionFails, now);
                        }
                    }
                }
            }
            PeerInput::Incoming(stream) => self.accept_stream(stream, Initiator::Remote, now),
            PeerInput::Message { conn, message } => {
                if self.conn.as_ref().is_some_and(|c| c.id == conn) {
                    self.primary_message(message, now);
                } else if self.pending.as_ref().is_some_and(|c| c.id == conn) {
                    self.pending_message(message, now);
                }
                // Otherwise a reader of a connection already dropped.
            }
            PeerInput::Closed { conn } => {
                if self.conn.as_ref().is_some_and(|c| c.id == conn) {
                    self.event(Event::TcpConnectionFails, now);
                } else if self.pending.as_ref().is_some_and(|c| c.id == conn) {
                    self.pending = None;
                } else if self.lingering.as_ref().is_some_and(|l| l.id == conn) {
                    // The neighbor has read the NOTIFICATION and closed.
                    self.end_linger();
                }
            }
            // The outbox is written below, after every input.
            PeerInput::Updates => {}
            PeerInput::Stop(subcode) => {
                // RFC 4271 §8.2.2 ManualStop: the operator's doing, by
                // `bgpfcctl`, a reload or a shutdown, with the RFC 4486 §4
                // Cease for it (Administrative Shutdown, Peer De-configured,
                // Other Configuration Change). No failure of the peer, so
                // nothing is damped or counted toward the restart limit.
                let cease = self.hard_if_suggested(NotificationMessage::cease(subcode));
                self.event(Event::ManualStop(cease), now);
                self.drop_conn(false);
                self.finish_linger();
                return false;
            }
            PeerInput::Reset { message, hard } => {
                // RFC 8538 §4: a Hard Reset goes only to a peer that sent
                // the Graceful Notification bit ("SHOULD NOT" otherwise);
                // any other NOTIFICATION ends the session the old way for
                // a peer that did not, which is what a Hard Reset is for.
                let hard_reset = hard && self.graceful_notification();
                bgpfc_log::info!(
                    "session reset by operator",
                    peer = self.cfg.addr,
                    hard_reset = hard_reset
                );
                if hard && !hard_reset {
                    bgpfc_log::info!(
                        "the neighbor did not exchange the graceful notification bit, so the \
                         reset is the usual one",
                        peer = self.cfg.addr
                    );
                }
                for event in reset_events(message.as_deref(), hard_reset) {
                    self.event(event, now);
                }
            }
            PeerInput::SoftReset => {
                if self.request_routes(now) {
                    self.rib_send(RibMsg::Resend {
                        peer: self.cfg.addr,
                    });
                }
            }
            PeerInput::RequestRoutes => {
                self.request_routes(now);
            }
            PeerInput::Report(reply) => {
                let _ = reply.send(PeerReport {
                    addr: self.cfg.addr,
                    remote_as: self.cfg.fsm.remote_as,
                    state: self.fsm.state(),
                    since: now.saturating_duration_since(self.state_since),
                    session: self.session.clone(),
                    updates_in: self.updates_in,
                    updates_out: self.updates_out,
                    admin_down: self.fsm.is_admin_down(),
                    restart_limit_reached: !self.fsm.automatic_start_allowed(),
                    restart_time: self.cfg.fsm.graceful_restart.map(|g| g.restart_time),
                });
            }
            PeerInput::PrefixLimit { family, limit } => self.prefix_limit(family, limit, now),
        }
        self.flags(now);
        true
    }

    /// Whether both sides set the Graceful Notification bit on this
    /// session (RFC 8538 §2): a NOTIFICATION other than a Hard Reset leaves
    /// the routes of both as stale ones.
    fn graceful_notification(&self) -> bool {
        self.session
            .as_ref()
            .and_then(Session::peer_restart)
            .is_some_and(|r| r.notification)
    }

    /// `cease` as RFC 8538 §5.1 suggests sending it: a Hard Reset
    /// carrying it for the reasons that are no short-term matter, when the
    /// peer exchanged the Graceful Notification bit.
    fn hard_if_suggested(&self, cease: NotificationMessage) -> NotificationMessage {
        suggested_hard_reset(cease, self.graceful_notification())
    }

    /// What the RIB thread flagged because the queue was full when it had
    /// something to say.
    fn flags(&mut self, now: Instant) {
        let pending = self.prefix_limit.lock().ok().and_then(|mut p| p.take());
        if let Some((family, limit)) = pending {
            self.prefix_limit(family, limit, now);
        }
        self.write_outbox(now);
        if self.outbox_state.overrun.swap(false, Ordering::Relaxed)
            && self.fsm.state() == State::Established
        {
            // RFC 4486 §4: Out of Resources. The peer restarts and gets a
            // complete Adj-RIB-Out again.
            bgpfc_log::error!(
                "output queue overrun, resetting session",
                peer = self.cfg.addr
            );
            self.event(
                Event::AutomaticStop(NotificationMessage::cease(CeaseSubcode::OutOfResources)),
                now,
            );
        }
    }

    /// The RIB dropped this peer's routes for exceeding its `maximum-prefix`
    /// for `family`: end the session (RFC 4271 §6.7 (b)). Only while
    /// Established; otherwise the session it was about has ended already.
    fn prefix_limit(&mut self, family: AddressFamily, limit: u32, now: Instant) {
        if self.fsm.state() != State::Established {
            return;
        }
        // RFC 4271 §6.7: "The speaker MAY also log this locally."
        bgpfc_log::error!(
            "maximum prefixes reached, closing session",
            peer = self.cfg.addr,
            family = family,
            limit = limit
        );
        // RFC 4486 §4: Cease / Maximum Number of Prefixes Reached, with the
        // AFI, SAFI and upper bound of Figure 1 as its data. The FSM goes
        // to Idle through AutomaticStop (RFC 4271 §8.2.2), damped, so the
        // restart-limit bounds a peer that keeps sending too much.
        let cease =
            self.hard_if_suggested(NotificationMessage::max_prefixes_reached(family, limit));
        self.event(Event::AutomaticStop(cease), now);
    }

    /// RFC 2918 §4: ask for every negotiated family again, only if the
    /// peer advertised the capability. Without it the request is refused
    /// rather than turned into a hard reset. Whether anything was sent.
    fn request_routes(&mut self, now: Instant) -> bool {
        let Some(session) = self.session.clone() else {
            bgpfc_log::warn!(
                "route refresh: session not established",
                peer = self.cfg.addr
            );
            return false;
        };
        if !session.route_refresh.peer_advertised() {
            bgpfc_log::warn!(
                "route refresh: peer did not advertise the capability",
                peer = self.cfg.addr
            );
            return false;
        }
        for family in &session.families {
            let body = RouteRefreshMessage::request(*family).encode();
            self.write_message(MessageType::RouteRefresh, &body);
            bgpfc_log::info!("route refresh sent", peer = self.cfg.addr, family = family);
        }
        self.fsm.message_sent(now);
        true
    }

    /// A TCP connection completed, ours or theirs.
    fn accept_stream(&mut self, stream: TcpStream, initiator: Initiator, now: Instant) {
        match self.fsm.state() {
            // RFC 4271 §8.2.2 Idle: refuses all incoming connections.
            State::Idle => {
                bgpfc_log::debug!("connection while idle, closing", peer = self.cfg.addr);
                drop(stream);
            }
            State::Connect | State::Active => {
                if self.conn.is_some() {
                    // Cannot happen: the FSM has no connection in these states.
                    self.drop_conn(false);
                }
                self.conn = Some(self.new_conn(stream, initiator));
                let event = match initiator {
                    Initiator::Local => Event::TcpCrAcked,
                    Initiator::Remote => Event::TcpConnectionConfirmed,
                };
                self.event(event, now);
            }
            // RFC 4271 §8.2.2 OpenSent/OpenConfirm: track the second
            // connection until an OPEN arrives on it.
            State::OpenSent | State::OpenConfirm => self.track_pending(stream, initiator),
            State::Established if self.fsm.takes_over_on_connection() => {
                self.take_over(stream, initiator, now);
            }
            State::Established => {
                if self.fsm.config().collision_detect_established {
                    self.track_pending(stream, initiator);
                } else {
                    // RFC 4271 §6.8: closes the newly created connection.
                    bgpfc_log::debug!(
                        "connection while established, closing",
                        peer = self.cfg.addr
                    );
                    let conn = self.new_conn_untracked(stream, initiator);
                    close_with_cease(conn, CeaseSubcode::ConnectionCollisionResolution);
                }
            }
        }
    }

    /// RFC 4724 §4.2: a connection from a peer that advertised Graceful
    /// Restart while its session is Established means it has restarted
    /// and we have not noticed. "The previous TCP session MUST be closed,
    /// and the new one retained", with no NOTIFICATION, and the routes of
    /// the peer are kept. The FSM does that, ending in Connect (§5); the
    /// event of the new connection is then fed again for it to go on.
    fn take_over(&mut self, stream: TcpStream, initiator: Initiator, now: Instant) {
        bgpfc_log::info!(
            "connection from a restarted peer replaces the session",
            peer = self.cfg.addr
        );
        // The pending second connection of RFC 4271 §6.8 is moot.
        self.pending = None;
        let new = self.new_conn(stream, initiator);
        let event = match initiator {
            Initiator::Local => Event::TcpCrAcked,
            Initiator::Remote => Event::TcpConnectionConfirmed,
        };
        // Drops the old connection, which is `self.conn`, as an action.
        self.event(event.clone(), now);
        self.conn = Some(new);
        self.event(event, now);
    }

    fn track_pending(&mut self, stream: TcpStream, initiator: Initiator) {
        if self.pending.is_some() {
            bgpfc_log::debug!("third connection, closing", peer = self.cfg.addr);
            drop(stream);
            return;
        }
        bgpfc_log::debug!("second connection, tracking", peer = self.cfg.addr);
        self.pending = Some(self.new_conn(stream, initiator));
    }

    /// Wrap a stream and start its reader thread.
    fn new_conn(&mut self, stream: TcpStream, initiator: Initiator) -> Conn {
        let conn = self.new_conn_untracked(stream, initiator);
        if let Ok(reader) = conn.stream.try_clone() {
            let tx = self.tx.clone();
            let id = conn.id;
            let extended = Arc::clone(&conn.extended);
            let name = format!("read-{}-{id}", self.cfg.addr);
            if thread::Builder::new()
                .name(name)
                .spawn(move || reader::run(reader, id, &extended, &tx))
                .is_err()
            {
                bgpfc_log::error!("cannot spawn reader thread", peer = self.cfg.addr);
                let _ = self.tx.try_send(PeerInput::Closed { conn: id });
            }
        } else {
            let _ = self.tx.try_send(PeerInput::Closed { conn: conn.id });
        }
        conn
    }

    fn new_conn_untracked(&mut self, stream: TcpStream, initiator: Initiator) -> Conn {
        let id = self.next_conn;
        self.next_conn += 1;
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
        let _ = stream.set_nodelay(true);
        Conn {
            id,
            stream,
            extended: Arc::new(AtomicBool::new(false)),
            initiator,
        }
    }

    fn start_connect(&mut self) {
        self.attempt += 1;
        let attempt = self.attempt;
        let target = SocketAddr::new(self.cfg.addr, self.cfg.port);
        let tx = self.tx.clone();
        let spawned = thread::Builder::new()
            .name(format!("connect-{}", self.cfg.addr))
            .spawn(move || {
                let result = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT);
                let _ = tx.send(PeerInput::Connected { attempt, result });
            });
        if spawned.is_err() {
            let _ = self.tx.try_send(PeerInput::Connected {
                attempt,
                result: Err(std::io::Error::other("cannot spawn connect thread")),
            });
        }
    }

    /// Close the FSM's connection, or with `linger` leave it open for the
    /// neighbor to close first (see [`Linger`]).
    fn drop_conn(&mut self, linger: bool) {
        #[cfg(feature = "profiling")]
        self.open_timer.reset();
        let Some(c) = self.conn.take() else {
            return;
        };
        if linger && !self.write_failed {
            // One at a time: an older one, still waiting, goes now.
            if let Some(old) = self.lingering.take() {
                let _ = old.stream.shutdown(Shutdown::Both);
            }
            self.lingering = Some(Linger {
                id: c.id,
                stream: c.stream,
                until: Instant::now() + NOTIFICATION_LINGER,
            });
        } else {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
    }

    /// Whether the connection of a session that ends with our NOTIFICATION
    /// waits for the neighbor to close it. Only a neighbor with Graceful
    /// Restart on can tell the NOTIFICATION from a failure of the
    /// transport (RFC 4724 §4.2), and for the others the close is as
    /// before.
    fn lingers_after_notification(&self) -> bool {
        self.cfg.fsm.graceful_restart.is_some()
    }

    /// Close the connection that waited for the neighbor, and make the
    /// connection the FSM asked for meanwhile.
    fn end_linger(&mut self) {
        if let Some(l) = self.lingering.take() {
            let _ = l.stream.shutdown(Shutdown::Both);
        }
        if std::mem::take(&mut self.connect_waits) && self.fsm.state() == State::Connect {
            self.start_connect();
        }
    }

    /// Close the connection that waited for the neighbor if the time is up.
    fn expire_linger(&mut self, now: Instant) {
        if self.lingering.as_ref().is_some_and(|l| l.until <= now) {
            bgpfc_log::debug!(
                "the neighbor did not close after the notification, closing",
                peer = self.cfg.addr
            );
            self.end_linger();
        }
    }

    /// Before the thread ends: give the neighbor the time to close, as
    /// the thread would otherwise close the connection at once.
    fn finish_linger(&mut self) {
        while let Some(until) = self.lingering.as_ref().map(|l| l.until) {
            let left = until.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(PeerInput::Closed { conn })
                    if self.lingering.as_ref().is_some_and(|l| l.id == conn) =>
                {
                    break;
                }
                // The thread is ending; nothing else is of interest.
                Ok(_) if !left.is_zero() => {}
                _ => break,
            }
        }
        self.connect_waits = false;
        self.end_linger();
    }

    /// Write the UPDATEs waiting in the outbox, or drop them outside
    /// Established (RFC 4271 §9.2: UPDATEs go out only then; a new
    /// session starts from a full Adj-RIB-Out).
    fn write_outbox(&mut self, now: Instant) {
        while let Ok(messages) = self.outbox.try_recv() {
            if self.fsm.state() == State::Established {
                #[cfg(feature = "profiling")]
                bgpfc_prof::metrics::UPDATES_SENT.add(messages.len());
                for m in &messages {
                    self.write_raw(m);
                }
                self.updates_out += 1;
                self.fsm.message_sent(now);
            }
            let octets: usize = messages.iter().map(Vec::len).sum();
            self.outbox_state
                .queued
                .fetch_sub(octets, Ordering::Relaxed);
        }
    }

    fn write_message(&mut self, kind: MessageType, body: &[u8]) {
        match frame(kind, body) {
            Ok(bytes) => self.write_raw(&bytes),
            Err(e) => bgpfc_log::error!("cannot frame message", peer = self.cfg.addr, error = e),
        }
    }

    fn write_raw(&mut self, bytes: &[u8]) {
        let Some(c) = &mut self.conn else {
            return;
        };
        // Counted as attempted: a failed write ends the session anyway.
        #[cfg(feature = "profiling")]
        bgpfc_prof::metrics::BYTES_SENT.add(bytes.len());
        if let Err(e) = c.stream.write_all(bytes) {
            bgpfc_log::warn!("write failed", peer = self.cfg.addr, error = e);
            self.write_failed = true;
        }
    }

    fn rib_send(&self, msg: RibMsg) {
        // A bounded channel: a RIB that cannot keep up blocks this peer
        // rather than letting memory grow (AGENTS.md §3 backpressure).
        if self.rib.send(msg).is_err() {
            bgpfc_log::error!("rib thread gone", peer = self.cfg.addr);
        }
    }

    /// A message (or framing error) on the FSM's connection.
    fn primary_message(&mut self, message: Result<Inbound, DecodeError>, now: Instant) {
        match message {
            Ok(Inbound::Open(open)) => {
                #[cfg(feature = "profiling")]
                self.open_timer.open();
                self.event(Event::BgpOpen(open), now);
            }
            Ok(Inbound::Update(body)) => self.update(&body, now),
            Ok(Inbound::Notification(n)) => {
                match n.shutdown_communication() {
                    Some(Ok(text)) => bgpfc_log::warn!(
                        "notification received",
                        peer = self.cfg.addr,
                        notification = n,
                        shutdown_communication = text
                    ),
                    Some(Err(e)) => bgpfc_log::warn!(
                        "notification received",
                        peer = self.cfg.addr,
                        notification = n,
                        shutdown_communication_error = e
                    ),
                    None => bgpfc_log::warn!(
                        "notification received",
                        peer = self.cfg.addr,
                        notification = n
                    ),
                }
                // RFC 4271 §8.1.5: event 24 for a version error, 25 otherwise.
                if n.code == ErrorCode::Open
                    && n.subcode == OpenSubcode::UnsupportedVersionNumber as u8
                {
                    self.event(Event::NotifMsgVerErr, now);
                } else {
                    self.event(Event::NotifMsg(n), now);
                }
            }
            Ok(Inbound::Keepalive) => self.event(Event::KeepAliveMsg, now),
            Ok(Inbound::RouteRefresh(body)) => self.route_refresh(&body, now),
            Err(e) => {
                // RFC 4271 §8.1.5: event 22 for an OPEN that failed §6.2,
                // event 21 for anything the header checks rejected.
                if e.code == ErrorCode::Open {
                    self.event(Event::BgpOpenMsgErr(e), now);
                } else {
                    self.event(Event::BgpHeaderErr(e), now);
                }
            }
        }
    }

    /// A ROUTE-REFRESH. The RFC 7313 §3.2 Message Subtype is read only on a
    /// session that negotiated Enhanced Route Refresh; on any other the
    /// octet is the Reserved one of RFC 2918 §3, which the receiver ignores,
    /// and the message is a request.
    fn route_refresh(&mut self, body: &[u8], now: Instant) {
        let established = self.fsm.state() == State::Established;
        let enhanced = established
            && self
                .session
                .as_ref()
                .is_some_and(|s| s.route_refresh.enhanced());
        let message = match RouteRefreshMessage::decode(body, enhanced) {
            Ok(m) => m,
            // RFC 7313 §5, or RFC 4271 §6.1 where it does not apply.
            Err(e) => {
                self.event(Event::BgpHeaderErr(e), now);
                return;
            }
        };
        self.event(Event::RouteRefreshMsg, now);
        if !established {
            return;
        }
        bgpfc_log::debug!(
            "route refresh received",
            peer = self.cfg.addr,
            family = message.family,
            subtype = message.subtype.to_u8(),
            enhanced = enhanced
        );
        let family = message.family;
        let subtype = if enhanced {
            message.subtype
        } else {
            RefreshSubtype::Request
        };
        let Some(session) = &self.session else {
            return;
        };
        // RFC 2918 §4: a request for a family we did not negotiate is
        // ignored. The brackets of the peer's own refresh are for the routes
        // it sends, those of any family we advertised.
        let known = match subtype {
            RefreshSubtype::Request => session.families.contains(&family),
            _ => session.receive_families.contains(&family),
        };
        if !known {
            bgpfc_log::debug!(
                "route refresh for unadvertised family",
                peer = self.cfg.addr,
                family = family
            );
            return;
        }
        let peer = self.cfg.addr;
        match subtype {
            RefreshSubtype::Request => self.rib_send(RibMsg::RouteRefresh { peer, family }),
            RefreshSubtype::BeginOfRefresh => self.rib_send(RibMsg::RefreshBegin { peer, family }),
            RefreshSubtype::EndOfRefresh => self.rib_send(RibMsg::RefreshEnd { peer, family }),
            // RFC 7313 §5: "it MUST ignore the received ROUTE-REFRESH
            // message. It SHOULD log an error for further analysis."
            RefreshSubtype::Unknown(subtype) => bgpfc_log::error!(
                "route refresh with an unknown message subtype ignored",
                peer = peer,
                family = family,
                subtype = subtype
            ),
        }
    }

    fn update(&mut self, body: &[u8], now: Instant) {
        #[cfg(feature = "profiling")]
        let started = bgpfc_prof::now();
        #[cfg(feature = "profiling")]
        bgpfc_prof::metrics::UPDATES_RECEIVED.inc();
        let ctx = decode_context(self.session.as_ref(), self.cfg.allow_as_set);
        match UpdateMessage::decode(body, &ctx) {
            Ok(decoded) => {
                let established = self.fsm.state() == State::Established;
                self.event(Event::UpdateMsg, now);
                if established {
                    self.updates_in += 1;
                    for d in &decoded.disabled {
                        // RFC 4760 §7: the RIB drops the family and the
                        // session stays; the rest of the UPDATE is used.
                        bgpfc_log::warn!(
                            "disabling address family after malformed update",
                            peer = self.cfg.addr,
                            family = d.family,
                            error = d.error
                        );
                    }
                    let taken = self
                        .session
                        .as_ref()
                        .map_or(&[][..], |s| &s.receive_families);
                    for family in unadvertised(&decoded.message, taken) {
                        // RFC 4760 §8: the RIB ignores them.
                        bgpfc_log::warn!(
                            "ignoring routes of a family we did not advertise",
                            peer = self.cfg.addr,
                            family = family
                        );
                    }
                    if let Some(e) = &decoded.treated_as_withdraw {
                        bgpfc_log::warn!(
                            "update treated as withdraw",
                            peer = self.cfg.addr,
                            error = e
                        );
                    }
                    for d in &decoded.discarded {
                        bgpfc_log::debug!(
                            "attribute discarded",
                            peer = self.cfg.addr,
                            code = d.code,
                            reason = format!("{:?}", d.reason)
                        );
                    }
                    #[cfg(feature = "profiling")]
                    {
                        use bgpfc_prof::metrics::{PREFIXES_ANNOUNCED, PREFIXES_WITHDRAWN};
                        PREFIXES_ANNOUNCED.add(decoded.announcements().count());
                        PREFIXES_WITHDRAWN.add(decoded.withdrawals().count());
                    }
                    // RFC 4724 §2: an UPDATE that announces and withdraws
                    // nothing ends the initial update of a family. It
                    // carries no routes, and the RIB wants it as what it
                    // is. A damaged one (RFC 7606) is no marker.
                    let marker = decoded.message.end_of_rib_family().filter(|_| {
                        decoded.disabled.is_empty() && decoded.treated_as_withdraw.is_none()
                    });
                    if let Some(family) = marker {
                        bgpfc_log::debug!("end-of-rib", peer = self.cfg.addr, family = family);
                        self.rib_send(RibMsg::EndOfRib {
                            peer: self.cfg.addr,
                            family,
                        });
                        return;
                    }
                    self.rib_send(RibMsg::Update {
                        peer: self.cfg.addr,
                        update: decoded,
                        #[cfg(feature = "profiling")]
                        started,
                    });
                }
            }
            // RFC 7606 §2: session reset.
            Err(e) => self.event(Event::UpdateMsgErr(e.notification), now),
        }
    }

    /// A message on the tracked second connection: only its OPEN matters.
    fn pending_message(&mut self, message: Result<Inbound, DecodeError>, now: Instant) {
        match message {
            Ok(Inbound::Open(open)) => self.resolve_collision(&open, now),
            other => {
                bgpfc_log::debug!(
                    "unexpected traffic on second connection, closing",
                    peer = self.cfg.addr,
                    what = format!("{other:?}")
                );
                self.pending = None;
            }
        }
    }

    /// RFC 4271 §6.8: keep the connection initiated by the speaker with the
    /// higher BGP Identifier; on a tie keep the existing one.
    fn resolve_collision(&mut self, open: &OpenMessage, now: Instant) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let local = self.fsm.config().router_id.to_u32();
        let remote = open.router_id.to_u32();
        let keep_pending = match pending.initiator {
            Initiator::Local => local > remote,
            Initiator::Remote => local < remote,
        };
        bgpfc_log::info!(
            "connection collision",
            peer = self.cfg.addr,
            local_id = self.fsm.config().router_id,
            remote_id = open.router_id,
            keep = if keep_pending { "new" } else { "existing" }
        );
        if keep_pending {
            let [dump, restart @ ..] = collision_events(open);
            self.event(dump, now);
            self.conn = Some(pending);
            for event in restart {
                self.event(event, now);
            }
        } else {
            close_with_cease(pending, CeaseSubcode::ConnectionCollisionResolution);
        }
    }
}

/// What the FSM is fed for `bgpfcctl clear neighbor`: a `ManualStop` with
/// RFC 4486 §4 Administrative Reset, carrying the RFC 9003 communication
/// when one was given, then a `ManualStart`. With `hard_reset` the Cease is
/// the data of a Hard Reset (RFC 8538 §3.1, §5.2), which has both sides
/// delete the other's routes instead of keeping them as stale ones. The stop
/// is the operator's, not a failure of the peer, so it is neither damped nor
/// counted toward the restart limit, and the start is the "administrative
/// intervention" that ends a run of failures (RFC 4486 §4).
fn reset_events(message: Option<&str>, hard_reset: bool) -> [Event; 2] {
    let cease = match message {
        Some(m) => NotificationMessage::shutdown(CeaseSubcode::AdministrativeReset, m)
            .unwrap_or_else(|_| NotificationMessage::cease(CeaseSubcode::AdministrativeReset)),
        None => NotificationMessage::cease(CeaseSubcode::AdministrativeReset),
    };
    let cease = if hard_reset {
        NotificationMessage::hard_reset(&cease)
    } else {
        cease
    };
    [Event::ManualStop(cease), Event::ManualStart]
}

/// `cease` wrapped in a Hard Reset where RFC 8538 §5.1 suggests one and
/// `exchanged` says the peer can read it: Maximum Number of Prefixes
/// Reached, Administrative Shutdown and Peer De-configured end a session
/// for good, or for long, so "there is no realistic hope that forwarding
/// can continue or that the session will be re-established within the
/// deadline". The others (Other Configuration Change, Collision
/// Resolution, Out of Resources, Administrative Reset) stay graceful
/// Ceases; Administrative Reset is the operator's choice.
fn suggested_hard_reset(cease: NotificationMessage, exchanged: bool) -> NotificationMessage {
    let hard = exchanged
        && cease.code == ErrorCode::Cease
        && [
            CeaseSubcode::MaxPrefixesReached,
            CeaseSubcode::AdministrativeShutdown,
            CeaseSubcode::PeerDeconfigured,
        ]
        .iter()
        .any(|s| *s as u8 == cease.subcode);
    if hard {
        NotificationMessage::hard_reset(&cease)
    } else {
        cease
    }
}

/// What the FSM is fed when the connection it runs on loses a collision
/// to one whose OPEN was `open` (RFC 4271 §6.8). `OpenCollisionDump` on the
/// losing connection sends the Cease and drops it (§8.2.2 event 23); the
/// FSM then goes on with the winner, which carries the OPEN already read.
/// That restart is automatic and passive (event 5): a `ManualStart` would be
/// the "administrative intervention" of RFC 4486 §4 and end the run of
/// damped failures, so that a peer whose restarts collide would never
/// reach the restart limit.
fn collision_events(open: &OpenMessage) -> [Event; 4] {
    [
        Event::OpenCollisionDump,
        Event::AutomaticStartPassive,
        Event::TcpConnectionConfirmed,
        Event::BgpOpen(open.clone()),
    ]
}

/// RFC 4271 §6.8: the losing connection is closed with a Cease.
fn close_with_cease(mut conn: Conn, subcode: CeaseSubcode) {
    let n = NotificationMessage::cease(subcode);
    if let Ok(body) = n.encode(false)
        && let Ok(bytes) = frame(MessageType::Notification, &body)
    {
        let _ = conn.stream.write_all(&bytes);
    }
    let _ = conn.stream.shutdown(Shutdown::Both);
}

/// How to decode UPDATEs on `session`.
fn decode_context(session: Option<&Session>, allow_as_set: bool) -> DecodeContext {
    match session {
        Some(s) => DecodeContext {
            four_octet_as: s.four_octet_as,
            peer: s.peer,
            allow_as_set,
            // RFC 8950 §3, §4: once we advertised the capability, whether
            // or not the peer did; without it RFC 7606 §7.11 expects four
            // octets of next hop for IPv4 unicast.
            extended_next_hop: s
                .extended_next_hop_receive
                .contains(&AddressFamily::IPV4_UNICAST),
            // RFC 7911 §5: the peer sends Path Identifiers for the
            // families we advertised Receive for and it advertised Send.
            add_path: bgpfc_wire::update::AddPathFamilies::of(&s.add_path_receive),
        },
        None => DecodeContext {
            four_octet_as: false,
            peer: PeerKind::External,
            allow_as_set,
            extended_next_hop: false,
            add_path: bgpfc_wire::update::AddPathFamilies::NONE,
        },
    }
}

/// The families `m` carries routes of, announced or withdrawn, that are not
/// among `taken`, the families we advertised (RFC 4760 §8), each once.
fn unadvertised(m: &UpdateMessage, taken: &[AddressFamily]) -> Vec<AddressFamily> {
    let ipv4 =
        (!m.withdrawn.is_empty() || !m.nlri.is_empty()).then_some(AddressFamily::IPV4_UNICAST);
    let mut out = Vec::new();
    for family in ipv4
        .into_iter()
        .chain(m.mp_reach.as_ref().map(|r| r.family))
        .chain(m.mp_unreach.as_ref().map(|u| u.family))
    {
        if !taken.contains(&family) && !out.contains(&family) {
            out.push(family);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgpfc_wire::capability::Capability;
    use bgpfc_wire::mp::{MpReach, MpUnreach, NextHop};

    #[test]
    fn families_we_did_not_advertise_are_named_once() {
        let v4 = AddressFamily::IPV4_UNICAST;
        let v6 = AddressFamily::IPV6_UNICAST;
        let p = |s: &str| s.parse().unwrap();
        let mut m = UpdateMessage {
            withdrawn: vec![p("192.0.2.0/24")],
            mp_reach: Some(MpReach {
                family: v6,
                next_hop: NextHop::Ipv6 {
                    global: "2001:db8::1".parse().unwrap(),
                    link_local: None,
                },
                nlri: vec![p("2001:db8:1::/48")],
            }),
            mp_unreach: Some(MpUnreach {
                family: v6,
                withdrawn: vec![p("2001:db8:2::/48")],
            }),
            ..UpdateMessage::default()
        };
        assert_eq!(unadvertised(&m, &[v4]), vec![v6]);
        assert_eq!(unadvertised(&m, &[v6]), vec![v4]);
        assert_eq!(unadvertised(&m, &[v4, v6]), vec![]);
        assert_eq!(unadvertised(&m, &[]), vec![v4, v6]);
        m.withdrawn.clear();
        assert_eq!(unadvertised(&m, &[]), vec![v6]);
        assert_eq!(unadvertised(&UpdateMessage::default(), &[]), vec![]);
    }

    #[test]
    fn a_collision_keeps_the_run_of_damped_failures() {
        use bgpfc_wire::types::{Asn, HoldTime, RouterId};
        // RFC 4486 §4: one automatic restart allowed, and one damped
        // failure behind us.
        let mut cfg = bgpfc_fsm::Config::new(Asn(65_000), RouterId::new(1).unwrap(), Asn(65_001));
        cfg.damping = Some(bgpfc_fsm::Damping {
            restart_limit: Some(1),
            ..bgpfc_fsm::Damping::default()
        });
        let mut fsm = Fsm::new(cfg);
        let now = Instant::now();
        fsm.handle(Event::ManualStart, now);
        fsm.handle(Event::TcpCrAcked, now);
        fsm.handle(Event::HoldTimerExpires, now);
        fsm.handle(Event::IdleHoldTimerExpires, now);
        fsm.handle(Event::TcpCrAcked, now);
        assert_eq!(fsm.damped_failures(), 1);
        // The peer's connection wins the collision.
        let open = OpenMessage::new(
            Asn(65_001),
            HoldTime::new(90).unwrap(),
            RouterId::new(2).unwrap(),
            Vec::new(),
        );
        for event in collision_events(&open) {
            let actions = fsm.handle(event, now);
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, Action::RestartLimitReached { .. })),
                "{actions:?}"
            );
        }
        // On with the winner, the run neither grown nor ended.
        assert_eq!(fsm.state(), State::OpenConfirm);
        assert_eq!(fsm.damped_failures(), 1);
        assert!(fsm.automatic_start_allowed());
    }

    #[test]
    fn a_hard_clear_is_no_failure_and_restarts_the_peer() {
        use bgpfc_wire::types::{Asn, RouterId};
        // RFC 4486 §4: no automatic restart allowed at all; the operator's
        // reset must neither count as a failure nor claim the peer stays
        // down.
        let mut cfg = bgpfc_fsm::Config::new(Asn(65_000), RouterId::new(1).unwrap(), Asn(65_001));
        cfg.damping = Some(bgpfc_fsm::Damping {
            restart_limit: Some(0),
            ..bgpfc_fsm::Damping::default()
        });
        for message in [None, Some("maintenance")] {
            let mut fsm = Fsm::new(cfg.clone());
            let now = Instant::now();
            fsm.handle(Event::ManualStart, now);
            fsm.handle(Event::TcpCrAcked, now);
            assert_eq!(fsm.state(), State::OpenSent);
            let actions: Vec<Action> = reset_events(message, false)
                .into_iter()
                .flat_map(|e| fsm.handle(e, now))
                .collect();
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, Action::RestartLimitReached { .. })),
                "{actions:?}"
            );
            let sent: Vec<&NotificationMessage> = actions
                .iter()
                .filter_map(|a| match a {
                    Action::SendNotification(n) => Some(n),
                    _ => None,
                })
                .collect();
            assert_eq!(sent.len(), 1, "{actions:?}");
            assert_eq!(
                (sent[0].code, sent[0].subcode),
                (ErrorCode::Cease, CeaseSubcode::AdministrativeReset as u8)
            );
            assert_eq!(
                sent[0].shutdown_communication().and_then(Result::ok),
                message
            );
            assert_eq!(fsm.state(), State::Connect);
            assert_eq!(fsm.damped_failures(), 0);
            assert!(fsm.automatic_start_allowed());
        }
    }

    #[test]
    fn a_hard_clear_carries_the_reset_in_a_hard_reset() {
        // RFC 8538 §3.1: the Hard Reset encapsulates the NOTIFICATION that
        // says why; §5.2: a Shutdown Communication goes inside, with the
        // Administrative Reset.
        let [stop, start] = reset_events(Some("maintenance"), true);
        let Event::ManualStop(n) = stop else {
            panic!("{stop:?}");
        };
        assert!(n.is_hard_reset());
        let inner = n.hard_reset_inner().unwrap();
        assert_eq!(
            (inner.code, inner.subcode),
            (ErrorCode::Cease, CeaseSubcode::AdministrativeReset as u8)
        );
        assert_eq!(
            n.shutdown_communication().and_then(Result::ok),
            Some("maintenance")
        );
        assert_eq!(start, Event::ManualStart);
        let [stop, _] = reset_events(None, true);
        assert!(matches!(stop, Event::ManualStop(n) if n.is_hard_reset()));
    }

    #[test]
    fn hard_resets_are_suggested_for_the_reasons_rfc_8538_gives() {
        // RFC 8538 §5.1, the table: Hard Reset for Maximum Number of
        // Prefixes Reached, Administrative Shutdown and Peer De-configured,
        // a graceful Cease for the others.
        for (subcode, hard) in [
            (CeaseSubcode::MaxPrefixesReached, true),
            (CeaseSubcode::AdministrativeShutdown, true),
            (CeaseSubcode::PeerDeconfigured, true),
            (CeaseSubcode::AdministrativeReset, false),
            (CeaseSubcode::ConnectionRejected, false),
            (CeaseSubcode::OtherConfigurationChange, false),
            (CeaseSubcode::ConnectionCollisionResolution, false),
            (CeaseSubcode::OutOfResources, false),
        ] {
            let cease = NotificationMessage::cease(subcode);
            let sent = suggested_hard_reset(cease.clone(), true);
            assert_eq!(sent.is_hard_reset(), hard, "{subcode:?}");
            if hard {
                assert_eq!(sent.hard_reset_inner(), Some(cease.clone()));
            } else {
                assert_eq!(sent, cease);
            }
            // RFC 8538 §4: a peer that did not send the bit gets the
            // Cease as it was, which ends the session for it all the same.
            assert_eq!(suggested_hard_reset(cease.clone(), false), cease);
        }
        // The data of a Maximum Number of Prefixes Reached goes along.
        let max = NotificationMessage::max_prefixes_reached(AddressFamily::IPV4_UNICAST, 9);
        assert_eq!(
            suggested_hard_reset(max.clone(), true).hard_reset_inner(),
            Some(max)
        );
        // No other code, and no Hard Reset already, is touched.
        let hold = NotificationMessage::hold_timer_expired();
        assert_eq!(suggested_hard_reset(hold.clone(), true), hold);
        let already = NotificationMessage::hard_reset(&NotificationMessage::cease(
            CeaseSubcode::AdministrativeShutdown,
        ));
        assert_eq!(suggested_hard_reset(already.clone(), true), already);
    }

    /// The session an FSM advertising `ours` negotiates with a peer
    /// advertising `theirs`.
    fn negotiated(ours: Vec<Capability>, theirs: Vec<Capability>) -> Session {
        use bgpfc_wire::types::{Asn, HoldTime, RouterId};
        let mut cfg = bgpfc_fsm::Config::new(Asn(65_000), RouterId::new(1).unwrap(), Asn(65_001));
        cfg.capabilities = ours;
        let mut fsm = Fsm::new(cfg);
        let now = Instant::now();
        fsm.handle(Event::ManualStart, now);
        fsm.handle(Event::TcpCrAcked, now);
        let open = OpenMessage::new(
            Asn(65_001),
            HoldTime::new(90).unwrap(),
            RouterId::new(2).unwrap(),
            theirs,
        );
        fsm.handle(Event::BgpOpen(open), now);
        fsm.session().cloned().unwrap()
    }

    /// A peer thread's state, not running, whose neighbor is `listener`.
    fn idle_peer(graceful_restart: bool) -> (Peer, std::net::TcpListener) {
        use bgpfc_wire::types::{Asn, RestartTime, RouterId};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut fsm = bgpfc_fsm::Config::new(Asn(65_000), RouterId::new(1).unwrap(), Asn(65_001));
        if graceful_restart {
            fsm.graceful_restart = Some(bgpfc_fsm::GracefulRestart {
                restart_time: RestartTime::new(120).unwrap(),
            });
        }
        let cfg = PeerConfig {
            addr: "127.0.0.1".parse().unwrap(),
            port: listener.local_addr().unwrap().port(),
            fsm,
            allow_as_set: false,
            stale_time: None,
            refresh_stale_time: None,
        };
        let (rib, _) = sync_channel(4);
        let (_, peer) = prepare(cfg, rib, Arc::default());
        (peer, listener)
    }

    /// Give `peer` a connection to `listener` as the FSM's, with the
    /// neighbor's end of it.
    fn connect(peer: &mut Peer, listener: &std::net::TcpListener) -> (ConnId, TcpStream) {
        let ours = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (theirs, _) = listener.accept().unwrap();
        let conn = peer.new_conn(ours, Initiator::Local);
        let id = conn.id;
        peer.conn = Some(conn);
        (id, theirs)
    }

    /// Whether `theirs` has been closed by the other end (EOF or reset)
    /// within `wait`, whatever was sent before.
    fn closed_within(theirs: &mut TcpStream, wait: Duration) -> bool {
        use std::io::Read;
        theirs.set_read_timeout(Some(wait)).unwrap();
        loop {
            match theirs.read(&mut [0; 64]) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(e) => {
                    return !matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    );
                }
            }
        }
    }

    #[test]
    fn a_lingering_connection_stays_open_until_the_neighbor_closes_it() {
        let (mut peer, listener) = idle_peer(true);
        let (id, mut theirs) = connect(&mut peer, &listener);
        peer.drop_conn(true);
        assert!(peer.conn.is_none());
        assert!(peer.lingering.as_ref().is_some_and(|l| l.id == id));
        assert!(!closed_within(&mut theirs, Duration::from_millis(200)));
        // The reader thread reports the neighbor's close, which ends the
        // wait, and the connection goes with it.
        drop(theirs);
        let closed = peer.rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(closed, PeerInput::Closed { conn } if conn == id));
        assert!(peer.input(closed));
        assert!(peer.lingering.is_none());
    }

    #[test]
    fn a_lingering_connection_is_closed_when_its_time_is_up() {
        let (mut peer, listener) = idle_peer(true);
        let (_, mut theirs) = connect(&mut peer, &listener);
        peer.drop_conn(true);
        let until = peer.lingering.as_ref().unwrap().until;
        peer.expire_linger(Instant::now());
        assert!(peer.lingering.is_some());
        assert!(!closed_within(&mut theirs, Duration::from_millis(100)));
        peer.expire_linger(until);
        assert!(peer.lingering.is_none());
        assert!(closed_within(&mut theirs, Duration::from_secs(5)));
    }

    #[test]
    fn a_connection_is_made_after_the_lingering_one_is_gone() {
        let (mut peer, listener) = idle_peer(true);
        let (_, _theirs) = connect(&mut peer, &listener);
        peer.drop_conn(true);
        // RFC 4271 §8.2.2: the start brings the FSM to Connect and asks for
        // a connection, which waits for the neighbor to close the old one.
        peer.event(Event::ManualStart, Instant::now());
        assert_eq!(peer.fsm.state(), State::Connect);
        assert!(peer.connect_waits);
        listener.set_nonblocking(true).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert!(listener.accept().is_err());
        peer.end_linger();
        assert!(!peer.connect_waits);
        let deadline = Instant::now() + Duration::from_secs(5);
        while listener.accept().is_err() {
            assert!(Instant::now() < deadline, "no connection was made");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn no_connection_is_made_after_the_fsm_has_gone_idle() {
        let (mut peer, listener) = idle_peer(true);
        let (_, _theirs) = connect(&mut peer, &listener);
        peer.drop_conn(true);
        peer.event(Event::ManualStart, Instant::now());
        let stop = NotificationMessage::cease(CeaseSubcode::AdministrativeShutdown);
        peer.event(Event::ManualStop(stop), Instant::now());
        assert_eq!(peer.fsm.state(), State::Idle);
        assert!(peer.connect_waits);
        peer.end_linger();
        assert!(!peer.connect_waits);
        listener.set_nonblocking(true).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert!(listener.accept().is_err());
    }

    #[test]
    fn only_a_notification_that_ends_an_established_session_of_a_gr_neighbor_lingers() {
        use bgpfc_wire::capability::Capability;
        let session = negotiated(
            vec![Capability::Multiprotocol(AddressFamily::IPV4_UNICAST)],
            vec![Capability::Multiprotocol(AddressFamily::IPV4_UNICAST)],
        );
        let stop = || NotificationMessage::cease(CeaseSubcode::AdministrativeReset);
        // (graceful restart on, session up, NOTIFICATION sent, lingers)
        for (gr, up, notified, lingers) in [
            (true, true, true, true),
            // RFC 4724 §4.2: without the capability a NOTIFICATION and a
            // failure of the transport are the same to the neighbor.
            (false, true, true, false),
            // Nothing is kept of a session that never came up.
            (true, false, true, false),
            // A failure of the transport has no NOTIFICATION to deliver.
            (true, true, false, false),
        ] {
            let (mut peer, listener) = idle_peer(gr);
            let (_, mut theirs) = connect(&mut peer, &listener);
            peer.session = up.then(|| session.clone());
            let mut actions = Vec::new();
            if notified {
                actions.push(Action::SendNotification(stop()));
            }
            actions.push(Action::SessionDown { retain: None });
            actions.push(Action::DropConnection);
            peer.apply(actions, Instant::now());
            let case = (gr, up, notified);
            assert_eq!(peer.lingering.is_some(), lingers, "{case:?}");
            assert_eq!(
                closed_within(&mut theirs, Duration::from_millis(200)),
                !lingers,
                "{case:?}"
            );
        }
    }

    /// A peer thread with its session Established, whatever `ours` and
    /// `theirs` advertise, the RIB messages it sent so far read, and the
    /// neighbor's end of the connection.
    fn established(
        ours: &[Capability],
        theirs: &[Capability],
    ) -> (Peer, Receiver<RibMsg>, TcpStream) {
        use bgpfc_wire::types::{Asn, HoldTime, RouterId};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut fsm = bgpfc_fsm::Config::new(Asn(65_000), RouterId::new(1).unwrap(), Asn(65_001));
        fsm.capabilities = ours.to_vec();
        let cfg = PeerConfig {
            addr: "127.0.0.1".parse().unwrap(),
            port: listener.local_addr().unwrap().port(),
            fsm,
            allow_as_set: false,
            stale_time: None,
            refresh_stale_time: None,
        };
        let (rib_tx, rib) = sync_channel(16);
        let (_, mut peer) = prepare(cfg, rib_tx, Arc::default());
        let (_, stream) = connect(&mut peer, &listener);
        let now = Instant::now();
        peer.event(Event::ManualStart, now);
        peer.event(Event::TcpCrAcked, now);
        let open = OpenMessage::new(
            Asn(65_001),
            HoldTime::new(90).unwrap(),
            RouterId::new(2).unwrap(),
            theirs.to_vec(),
        );
        peer.event(Event::BgpOpen(open), now);
        peer.event(Event::KeepAliveMsg, now);
        assert_eq!(peer.fsm.state(), State::Established);
        assert!(matches!(rib.try_recv(), Ok(RibMsg::PeerUp { .. })));
        (peer, rib, stream)
    }

    /// The messages `theirs` has been sent, as (type, body), read until the
    /// connection is quiet or closed.
    fn received(theirs: &mut TcpStream) -> Vec<(u8, Vec<u8>)> {
        use std::io::Read;
        theirs
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut all = Vec::new();
        loop {
            let mut header = [0u8; 19];
            if theirs.read_exact(&mut header).is_err() {
                return all;
            }
            let mut body = vec![0; usize::from(u16::from_be_bytes([header[16], header[17]])) - 19];
            if theirs.read_exact(&mut body).is_err() {
                return all;
            }
            all.push((header[18], body));
        }
    }

    fn refresh_caps(enhanced: bool) -> Vec<Capability> {
        let mut caps = vec![
            Capability::Multiprotocol(AddressFamily::IPV4_UNICAST),
            Capability::RouteRefresh,
        ];
        if enhanced {
            caps.push(Capability::EnhancedRouteRefresh);
        }
        caps
    }

    #[test]
    fn the_subtypes_of_a_route_refresh_reach_the_rib_when_both_sides_have_the_capability() {
        let v4 = AddressFamily::IPV4_UNICAST;
        let caps = refresh_caps(true);
        let (mut peer, rib, _theirs) = established(&caps, &caps);
        assert!(peer.session.as_ref().unwrap().route_refresh.enhanced());
        let now = Instant::now();
        let mut sent = |body: &[u8]| {
            peer.primary_message(Ok(Inbound::RouteRefresh(body.to_vec())), now);
            rib.try_iter().collect::<Vec<_>>()
        };
        // RFC 7313 §3.2: 0 request, 1 BoRR, 2 EoRR.
        assert!(matches!(
            sent(&[0, 1, 0, 1])[..],
            [RibMsg::RouteRefresh { family, .. }] if family == v4
        ));
        assert!(matches!(
            sent(&[0, 1, 1, 1])[..],
            [RibMsg::RefreshBegin { family, .. }] if family == v4
        ));
        assert!(matches!(
            sent(&[0, 1, 2, 1])[..],
            [RibMsg::RefreshEnd { family, .. }] if family == v4
        ));
        // RFC 7313 §5: any other subtype is ignored (and logged), and the
        // session goes on.
        for subtype in [3, 100, 255] {
            assert!(sent(&[0, 1, subtype, 1]).is_empty());
        }
        // RFC 2918 §4: a request for a family we did not negotiate, and the
        // brackets of one we do not take routes of, are ignored.
        for subtype in [0, 1, 2] {
            assert!(sent(&[0, 2, subtype, 1]).is_empty());
        }
        assert_eq!(peer.fsm.state(), State::Established);
    }

    #[test]
    fn without_the_capability_on_both_sides_the_subtype_is_ignored_and_it_is_a_request() {
        // RFC 2918 §3: the receiver ignores the Reserved octet.
        for (ours, theirs) in [
            (refresh_caps(true), refresh_caps(false)),
            (refresh_caps(false), refresh_caps(true)),
            (refresh_caps(false), refresh_caps(false)),
        ] {
            let (mut peer, rib, _theirs) = established(&ours, &theirs);
            assert!(!peer.session.as_ref().unwrap().route_refresh.enhanced());
            for subtype in [0, 1, 2, 77] {
                peer.primary_message(
                    Ok(Inbound::RouteRefresh(vec![0, 1, subtype, 1])),
                    Instant::now(),
                );
                assert!(
                    matches!(
                        rib.try_iter().collect::<Vec<_>>()[..],
                        [RibMsg::RouteRefresh { .. }]
                    ),
                    "subtype {subtype}"
                );
            }
        }
    }

    #[test]
    fn a_borr_or_eorr_of_the_wrong_length_is_answered_with_a_route_refresh_message_error() {
        let caps = refresh_caps(true);
        for subtype in [1u8, 2] {
            let (mut peer, rib, mut theirs) = established(&caps, &caps);
            let body = vec![0, 1, subtype, 1, 0];
            peer.primary_message(Ok(Inbound::RouteRefresh(body.clone())), Instant::now());
            // RFC 7313 §5: code 7, subcode 1, "the complete ROUTE-REFRESH
            // message" as data, and the session ends.
            let notification = received(&mut theirs)
                .into_iter()
                .find(|(kind, _)| *kind == 3)
                .expect("a NOTIFICATION")
                .1;
            let mut whole = vec![0xff; 16];
            whole.extend_from_slice(&[0, 24, 5]);
            whole.extend_from_slice(&body);
            assert_eq!(notification[..2], [7, 1]);
            assert_eq!(notification[2..], whole[..]);
            assert_ne!(peer.fsm.state(), State::Established);
            assert!(matches!(
                rib.try_iter().collect::<Vec<_>>()[..],
                [RibMsg::PeerDown { .. }]
            ));
        }
        // A request of the wrong length, or the same where the capability is
        // not in use, is the header error it always was.
        for (caps, body) in [
            (refresh_caps(true), vec![0, 1, 0, 1, 0]),
            (refresh_caps(false), vec![0, 1, 1, 1, 0]),
        ] {
            let (mut peer, _rib, mut theirs) = established(&caps, &caps);
            peer.primary_message(Ok(Inbound::RouteRefresh(body)), Instant::now());
            let notification = received(&mut theirs)
                .into_iter()
                .find(|(kind, _)| *kind == 3)
                .expect("a NOTIFICATION")
                .1;
            // Message Header Error / Bad Message Length, with the Length
            // field as data.
            assert_eq!(notification, [1, 2, 0, 24]);
        }
    }

    #[test]
    fn path_identifiers_are_decoded_where_we_receive_them_and_only_there() {
        // RFC 7911 §5: for IPv4 unicast both sides agreed, so the NLRI
        // field carries an identifier before each prefix; for IPv6 unicast
        // the peer advertised Send but we never advertised Receive.
        use bgpfc_wire::capability::{AddPathMode, AddPathTuple};
        use bgpfc_wire::types::PathId;
        let v4 = AddressFamily::IPV4_UNICAST;
        let v6 = AddressFamily::IPV6_UNICAST;
        let tuple = |family, mode| AddPathTuple { family, mode };
        let ours = vec![
            Capability::Multiprotocol(v4),
            Capability::Multiprotocol(v6),
            Capability::AddPath(vec![tuple(v4, AddPathMode::Receive)]),
        ];
        let theirs = vec![
            Capability::Multiprotocol(v4),
            Capability::Multiprotocol(v6),
            Capability::AddPath(vec![
                tuple(v4, AddPathMode::Send),
                tuple(v6, AddPathMode::Send),
            ]),
        ];
        let s = negotiated(ours, theirs);
        assert_eq!(s.add_path_receive, vec![v4]);
        let ctx = decode_context(Some(&s), false);
        assert!(ctx.add_path.contains(v4));
        assert!(!ctx.add_path.contains(v6));
        // Before the session is up there are none.
        assert!(decode_context(None, false).add_path.is_empty());
        // 0 attributes, NLRI: id 7, 192.0.2.0/24.
        let body = [0, 0, 0, 0, 0, 0, 0, 7, 24, 192, 0, 2];
        let d = UpdateMessage::decode(&body, &ctx).unwrap();
        assert_eq!(d.message.nlri, vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(d.message.path_ids.unwrap().nlri, vec![PathId(7)]);
    }

    #[test]
    fn ipv6_next_hops_for_ipv4_routes_are_taken_once_we_advertised_rfc8950() {
        use bgpfc_wire::as_path::AsPath;
        use bgpfc_wire::attribute::Origin;
        use bgpfc_wire::capability::NextHopEncoding;
        use bgpfc_wire::types::Asn;
        use bgpfc_wire::update::EncodeContext;
        let v4 = AddressFamily::IPV4_UNICAST;
        let enh = Capability::ExtendedNextHop(vec![NextHopEncoding::IPV4_UNICAST_VIA_IPV6]);
        let mp = Capability::Multiprotocol(v4);
        let attrs = bgpfc_rib::PathAttrs {
            origin: Origin::Igp,
            as_path: AsPath::sequence(&[Asn(65_001)]),
            next_hop: NextHop::Ipv6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: None,
            },
            med: None,
            local_pref: None,
            atomic_aggregate: false,
            aggregator: None,
            communities: Box::default(),
            ext_communities: Box::default(),
            large_communities: Box::default(),
            unknown: Box::default(),
            otc: None,
        };
        let body = attrs
            .to_update(v4, vec!["192.0.2.0/24".parse().unwrap()])
            .encode(&EncodeContext {
                four_octet_as: true,
                extended_next_hop: true,
                add_path: bgpfc_wire::update::AddPathFamilies::NONE,
            })
            .unwrap();
        let decode = |s: &Session| UpdateMessage::decode(&body, &decode_context(Some(s), false));
        // RFC 8950 §4: our triple tells the peer it may send us an IPv6
        // next hop, whether or not it listed one itself (§3: the length
        // says which protocol the next hop is of).
        for theirs in [vec![mp.clone()], vec![mp.clone(), enh.clone()]] {
            let s = negotiated(vec![mp.clone(), enh.clone()], theirs);
            let d = decode(&s).unwrap();
            assert!(d.disabled.is_empty(), "{:?}", d.disabled);
            assert_eq!(d.message.mp_reach.unwrap().next_hop, attrs.next_hop);
        }
        // Without ours, only four octets are expected (RFC 7606 §7.11), even
        // when the peer listed the triple.
        let s = negotiated(vec![mp.clone()], vec![mp, enh]);
        let d = decode(&s).unwrap();
        assert_eq!(
            d.disabled.iter().map(|x| x.family).collect::<Vec<_>>(),
            vec![v4]
        );
    }
}
