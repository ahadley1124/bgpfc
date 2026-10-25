//! One thread per configured neighbour: owns the TCP connection and the
//! peer's FSM, turns bytes and timers into events, and executes the
//! actions the FSM returns (AGENTS.md §3).
//!
//! Implements: RFC 4271 §6.8 (collision resolution between this peer's two
//! connections), §8.2.1 (one FSM per connection; a second connection is
//! tracked until its OPEN), §8.2.2 (Idle refuses connections); RFC 4760 §7
//! (AFI/SAFI disable is reported to the RIB, the session kept); RFC 2918
//! §4 (ROUTE-REFRESH for an unadvertised family is ignored); RFC 9003 §2
//! (a received Shutdown Communication is logged).

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
use bgpfc_wire::route_refresh::RouteRefreshMessage;
use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::{DecodeContext, PeerKind, UpdateMessage};

use crate::messages::{ConnId, Inbound, Initiator, PeerInput, PeerReport, RibMsg};
use crate::reader;

/// How long an outgoing TCP connect may take; RFC 4271 §8.2.2 asks the
/// `ConnectRetryTime` to leave room for it, and 120 s does.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A blocked write to a peer that stopped reading is reported as a TCP
/// failure after this long (RFC 9687 motivates not waiting forever).
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Inputs a peer thread will queue before its producers block.
const INPUT_QUEUE: usize = 256;

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
    next_conn: ConnId,
    attempt: u64,
    session: Option<Session>,
    write_failed: bool,
    outbox: Receiver<Vec<Vec<u8>>>,
    outbox_state: Arc<Outbox>,
    prefix_limit: Arc<Mutex<Option<(AddressFamily, u32)>>>,
    /// When the FSM last changed state.
    state_since: Instant,
    updates_in: u64,
    updates_out: u64,
    #[cfg(feature = "profiling")]
    open_timer: crate::profiling::OpenTimer,
}

/// Prepare a peer: its handle can go into the peer table before the
/// thread runs (listeners bind and privileges drop in between).
pub(crate) fn prepare(cfg: PeerConfig, rib: SyncSender<RibMsg>) -> (PeerHandle, Peer) {
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
        next_conn: 1,
        attempt: 0,
        session: None,
        write_failed: false,
        outbox,
        outbox_state: state,
        prefix_limit,
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
            let timeout = self
                .fsm
                .next_deadline()
                .map_or(Duration::from_secs(60), |d| {
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
        for action in actions {
            match action {
                Action::Connect => self.start_connect(),
                Action::DropConnection => self.drop_conn(),
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
                Action::SendNotification(n) => {
                    bgpfc_log::warn!(
                        "sending notification",
                        peer = self.cfg.addr,
                        notification = n
                    );
                    let extended = self.session.as_ref().is_some_and(|s| s.extended_messages);
                    match n.encode(extended) {
                        Ok(body) => self.write_message(MessageType::Notification, &body),
                        Err(e) => bgpfc_log::error!(
                            "cannot encode NOTIFICATION",
                            peer = self.cfg.addr,
                            error = e
                        ),
                    }
                }
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
                    });
                }
                Action::SessionDown => {
                    #[cfg(feature = "profiling")]
                    bgpfc_prof::metrics::SESSIONS_DROPPED.inc();
                    bgpfc_log::info!("session down", peer = self.cfg.addr);
                    self.session = None;
                    self.rib_send(RibMsg::PeerDown {
                        peer: self.cfg.addr,
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
                self.event(Event::ManualStop(NotificationMessage::cease(subcode)), now);
                self.drop_conn();
                return false;
            }
            PeerInput::Reset(message) => {
                bgpfc_log::info!("session reset by operator", peer = self.cfg.addr);
                for event in reset_events(message.as_deref()) {
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
                });
            }
            PeerInput::PrefixLimit { family, limit } => self.prefix_limit(family, limit, now),
        }
        self.flags(now);
        true
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
        self.event(
            Event::AutomaticStop(NotificationMessage::max_prefixes_reached(family, limit)),
            now,
        );
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
        if !session.route_refresh {
            bgpfc_log::warn!(
                "route refresh: peer did not advertise the capability",
                peer = self.cfg.addr
            );
            return false;
        }
        for family in &session.families {
            let body = RouteRefreshMessage { family: *family }.encode();
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
                    self.drop_conn();
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

    fn drop_conn(&mut self) {
        #[cfg(feature = "profiling")]
        self.open_timer.reset();
        if let Some(c) = self.conn.take() {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
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
            Ok(Inbound::RouteRefresh(r)) => {
                let established = self.fsm.state() == State::Established;
                self.event(Event::RouteRefreshMsg, now);
                if established {
                    let known = self
                        .session
                        .as_ref()
                        .is_some_and(|s| s.families.contains(&r.family));
                    if known {
                        self.rib_send(RibMsg::RouteRefresh {
                            peer: self.cfg.addr,
                            family: r.family,
                        });
                    } else {
                        // RFC 2918 §4: a family we did not advertise is ignored.
                        bgpfc_log::debug!(
                            "route refresh for unadvertised family",
                            peer = self.cfg.addr,
                            family = r.family
                        );
                    }
                }
            }
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
/// when one was given, then a `ManualStart`. The stop is the operator's,
/// not a failure of the peer, so it is neither damped nor counted toward
/// the restart limit, and the start is the "administrative intervention"
/// that ends a run of failures (RFC 4486 §4).
fn reset_events(message: Option<&str>) -> [Event; 2] {
    let cease = match message {
        Some(m) => NotificationMessage::shutdown(CeaseSubcode::AdministrativeReset, m)
            .unwrap_or_else(|_| NotificationMessage::cease(CeaseSubcode::AdministrativeReset)),
        None => NotificationMessage::cease(CeaseSubcode::AdministrativeReset),
    };
    [Event::ManualStop(cease), Event::ManualStart]
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
        },
        None => DecodeContext {
            four_octet_as: false,
            peer: PeerKind::External,
            allow_as_set,
            extended_next_hop: false,
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
            let actions: Vec<Action> = reset_events(message)
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
