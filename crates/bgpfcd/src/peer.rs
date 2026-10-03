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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_fsm::{Action, Event, Fsm, Session, State};
use bgpfc_wire::error::{CeaseSubcode, DecodeError, ErrorCode, OpenSubcode};
use bgpfc_wire::header::{MessageType, frame};
use bgpfc_wire::keepalive::KEEPALIVE;
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::update::{DecodeContext, ErrorAction, PeerKind, UpdateMessage};

use crate::messages::{ConnId, Inbound, Initiator, PeerInput, RibMsg};
use crate::reader;

/// How long an outgoing TCP connect may take; RFC 4271 §8.2.2 asks the
/// `ConnectRetryTime` to leave room for it, and 120 s does.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A blocked write to a peer that stopped reading is reported as a TCP
/// failure after this long (RFC 9687 motivates not waiting forever).
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Inputs a peer thread will queue before its producers block.
const INPUT_QUEUE: usize = 256;

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
    /// Set by the RIB thread when the queue was full and UPDATEs had to be
    /// dropped: the peer thread resets the session rather than leave the
    /// peer with a partial view (AGENTS.md §3, backpressure).
    pub(crate) overrun: Arc<AtomicBool>,
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
    overrun: Arc<AtomicBool>,
}

/// Prepare a peer: its handle can go into the peer table before the
/// thread runs (listeners bind and privileges drop in between).
pub(crate) fn prepare(cfg: PeerConfig, rib: SyncSender<RibMsg>) -> (PeerHandle, Peer) {
    let (tx, rx) = sync_channel(INPUT_QUEUE);
    let overrun = Arc::new(AtomicBool::new(false));
    let handle = PeerHandle {
        addr: cfg.addr,
        tx: tx.clone(),
        overrun: Arc::clone(&overrun),
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
        overrun,
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
                Action::SendOpen(open) => match open.encode() {
                    Ok(body) => self.write_message(MessageType::Open, &body),
                    Err(e) => {
                        bgpfc_log::error!("cannot encode OPEN", peer = self.cfg.addr, error = e);
                    }
                },
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
                    bgpfc_log::info!("session down", peer = self.cfg.addr);
                    self.session = None;
                    self.rib_send(RibMsg::PeerDown {
                        peer: self.cfg.addr,
                    });
                }
                Action::LogError(msg) => bgpfc_log::error!(msg, peer = self.cfg.addr),
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
            PeerInput::Send(messages) => {
                if self.fsm.state() == State::Established {
                    for m in &messages {
                        self.write_raw(m);
                    }
                    self.fsm.message_sent(now);
                }
            }
            PeerInput::Stop => {
                // RFC 4271 §8.2.2 ManualStop: a Cease goes out (RFC 4486
                // §4 Administrative Shutdown) and the FSM returns to Idle.
                self.event(Event::ManualStop, now);
                self.drop_conn();
                return false;
            }
        }
        if self.overrun.swap(false, Ordering::Relaxed) && self.fsm.state() == State::Established {
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
        if let Some(c) = self.conn.take() {
            let _ = c.stream.shutdown(Shutdown::Both);
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

    fn decode_context(&self) -> DecodeContext {
        match &self.session {
            Some(s) => DecodeContext {
                four_octet_as: s.four_octet_as,
                peer: s.peer,
                allow_as_set: self.cfg.allow_as_set,
            },
            None => DecodeContext {
                four_octet_as: false,
                peer: PeerKind::External,
                allow_as_set: self.cfg.allow_as_set,
            },
        }
    }

    /// A message (or framing error) on the FSM's connection.
    fn primary_message(&mut self, message: Result<Inbound, DecodeError>, now: Instant) {
        match message {
            Ok(Inbound::Open(open)) => self.event(Event::BgpOpen(open), now),
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
        let ctx = self.decode_context();
        match UpdateMessage::decode(body, &ctx) {
            Ok(decoded) => {
                let established = self.fsm.state() == State::Established;
                self.event(Event::UpdateMsg, now);
                if established {
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
                    self.rib_send(RibMsg::Update {
                        peer: self.cfg.addr,
                        update: decoded,
                    });
                }
            }
            Err(e) => match e.action {
                ErrorAction::SessionReset => self.event(Event::UpdateMsgErr(e.notification), now),
                ErrorAction::AfiSafiDisable(family) => {
                    // RFC 4760 §7: drop the family, keep the session.
                    bgpfc_log::warn!(
                        "disabling address family after malformed update",
                        peer = self.cfg.addr,
                        family = family,
                        error = e.notification
                    );
                    self.event(Event::UpdateMsg, now);
                    self.rib_send(RibMsg::FamilyDisabled {
                        peer: self.cfg.addr,
                        family,
                    });
                }
            },
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
            // RFC 4271 §8.2.2: OpenCollisionDump on the losing connection
            // sends the Cease and drops it; then the FSM is restarted on the
            // winner, which carries the OPEN we just read.
            self.event(Event::OpenCollisionDump, now);
            self.conn = Some(pending);
            self.event(Event::ManualStartPassive, now);
            self.event(Event::TcpConnectionConfirmed, now);
            self.event(Event::BgpOpen(open.clone()), now);
        } else {
            close_with_cease(pending, CeaseSubcode::ConnectionCollisionResolution);
        }
    }
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
