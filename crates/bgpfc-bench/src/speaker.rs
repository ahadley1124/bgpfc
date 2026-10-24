//! A minimal BGP speaker over `std::net::TcpStream`: the OPEN/KEEPALIVE
//! handshake, KEEPALIVEs every third of the negotiated Hold Time, and a
//! reader that drains whatever the peer sends so it never blocks on us.
//!
//! Implements: RFC 4271 §4.2 (OPEN), §4.4 (KEEPALIVE), §4.2 and §10 (Hold
//! Time is the smaller of both; keepalives at a third of it), §6.8 is not
//! needed (one connection at a time); RFC 4760 §8 and RFC 8654 §4 (a family
//! and Extended Message are usable when both sides advertise them);
//! RFC 6793 §3 (four-octet ASNs).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bgpfc_wire::capability::Capability;
use bgpfc_wire::error::CeaseSubcode;
use bgpfc_wire::header::{HEADER_LEN, Header, MessageType, frame};
use bgpfc_wire::keepalive::KEEPALIVE;
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};

/// How long one TCP connect may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for the peer's OPEN and KEEPALIVE.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause between attempts while the peer refuses (for example while its
/// FSM holds the session in Idle after a reset).
const RETRY: Duration = Duration::from_millis(500);
/// A write to a peer that stopped reading fails after this long.
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// Messages are written in batches of about this many octets.
const WRITE_CHUNK: usize = 64 * 1024;

/// What we offer in our OPEN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeakerOpts {
    /// Our AS.
    pub asn: Asn,
    /// Our BGP Identifier.
    pub router_id: RouterId,
    /// Proposed Hold Time.
    pub hold_time: HoldTime,
    /// Families to advertise (RFC 4760 §8).
    pub families: Vec<AddressFamily>,
    /// Advertise Extended Message (RFC 8654 §3).
    pub extended: bool,
}

/// What both sides agreed on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// The peer's AS.
    pub peer_as: Asn,
    /// The peer's BGP Identifier.
    pub peer_router_id: RouterId,
    /// Negotiated Hold Time in seconds; 0 means no keepalives.
    pub hold_time: u16,
    /// Both speak four-octet ASNs.
    pub four_octet_as: bool,
    /// Both accept 65535-octet messages.
    pub extended: bool,
    /// Families both advertised.
    pub families: Vec<AddressFamily>,
}

/// Where the session comes from.
#[derive(Debug)]
pub enum Endpoint {
    /// Connect to the daemon.
    Connect(SocketAddr),
    /// Wait for the daemon to connect.
    Listen(TcpListener),
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Connect(a) => write!(f, "connect {a}"),
            Endpoint::Listen(l) => match l.local_addr() {
                Ok(a) => write!(f, "listen {a}"),
                Err(_) => f.write_str("listen"),
            },
        }
    }
}

/// Why a session could not be set up.
#[derive(Debug)]
pub enum SessionError {
    /// A socket error, or the peer closed the connection.
    Io(io::Error),
    /// The peer sent a NOTIFICATION.
    Notification(NotificationMessage),
    /// The peer sent something unexpected.
    Protocol(String),
    /// No session before the deadline.
    Timeout,
}

impl SessionError {
    /// Whether trying again may help: the connection was refused or
    /// closed, or the peer sent a Cease (a collision, or not ready).
    fn retryable(&self) -> bool {
        match self {
            SessionError::Io(_) => true,
            SessionError::Notification(n) => n.code == bgpfc_wire::error::ErrorCode::Cease,
            SessionError::Protocol(_) | SessionError::Timeout => false,
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Io(e) => write!(f, "{e}"),
            SessionError::Notification(n) => write!(f, "peer sent NOTIFICATION {n}"),
            SessionError::Protocol(m) => f.write_str(m),
            SessionError::Timeout => f.write_str("no session before the deadline"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        SessionError::Io(e)
    }
}

#[derive(Debug, Default)]
struct Shared {
    stop: AtomicBool,
    closed: AtomicBool,
    updates_rx: AtomicU64,
    notification: Mutex<Option<String>>,
}

/// An Established session.
#[derive(Debug)]
pub struct Session {
    writer: Arc<Mutex<TcpStream>>,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
    /// What was negotiated.
    pub negotiated: Negotiated,
    /// Our end of the connection.
    pub local: SocketAddr,
}

impl Session {
    /// Set up a session, trying again while the peer refuses, until
    /// `timeout` has passed.
    ///
    /// # Errors
    /// [`SessionError`] from the last attempt, or [`SessionError::Timeout`].
    pub fn establish(
        endpoint: &Endpoint,
        opts: &SpeakerOpts,
        timeout: Duration,
    ) -> Result<Session, SessionError> {
        let deadline = Instant::now() + timeout;
        loop {
            let attempt = match endpoint {
                Endpoint::Connect(addr) => TcpStream::connect_timeout(addr, CONNECT_TIMEOUT)
                    .map_err(SessionError::Io)
                    .and_then(|s| handshake(s, opts)),
                Endpoint::Listen(l) => accept(l, deadline).and_then(|s| handshake(s, opts)),
            };
            match attempt {
                Ok(s) => return Ok(s),
                Err(e) if e.retryable() && Instant::now() < deadline => thread::sleep(RETRY),
                Err(e) => return Err(e),
            }
        }
    }

    /// Write `messages` in order, batched into large writes. Returns the
    /// octets written.
    ///
    /// # Errors
    /// The write error; the session is unusable after one.
    pub fn send(&self, messages: &[Vec<u8>]) -> io::Result<u64> {
        let mut buf = Vec::with_capacity(WRITE_CHUNK + 65_536);
        let mut total = 0u64;
        for m in messages {
            buf.extend_from_slice(m);
            if buf.len() >= WRITE_CHUNK {
                self.write(&buf)?;
                total += buf.len() as u64;
                buf.clear();
            }
        }
        if !buf.is_empty() {
            self.write(&buf)?;
            total += buf.len() as u64;
        }
        Ok(total)
    }

    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        write_locked(&self.writer, bytes)
    }

    /// Whether the peer closed the session.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Relaxed)
    }

    /// Wait until the peer closes the session or `timeout` passes (`None`:
    /// forever); whether it closed.
    #[must_use]
    pub fn wait_closed(&self, timeout: Option<Duration>) -> bool {
        let deadline = timeout.map(|t| Instant::now() + t);
        while !self.is_closed() {
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
        true
    }

    /// The NOTIFICATION the peer closed the session with, if any.
    #[must_use]
    pub fn notification(&self) -> Option<String> {
        self.shared.notification.lock().ok()?.clone()
    }

    /// UPDATEs the peer sent us.
    #[must_use]
    pub fn updates_received(&self) -> u64 {
        self.shared.updates_rx.load(Relaxed)
    }

    /// End the session with a Cease (RFC 4486 §4: Administrative
    /// Shutdown) and close the connection.
    ///
    /// # Errors
    /// If the NOTIFICATION cannot be written; the connection is closed
    /// anyway.
    pub fn close(mut self) -> io::Result<()> {
        let n = NotificationMessage::cease(CeaseSubcode::AdministrativeShutdown);
        let result = n
            .encode(self.negotiated.extended)
            .and_then(|body| frame(MessageType::Notification, &body))
            .map_err(io::Error::other)
            .and_then(|bytes| self.write(&bytes));
        self.stop();
        result
    }

    fn stop(&mut self) {
        self.shared.stop.store(true, Relaxed);
        if let Ok(w) = self.writer.lock() {
            let _ = w.shutdown(Shutdown::Both);
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

fn write_locked(writer: &Mutex<TcpStream>, bytes: &[u8]) -> io::Result<()> {
    let mut w = writer
        .lock()
        .map_err(|_| io::Error::other("writer lock poisoned"))?;
    w.write_all(bytes)
}

fn accept(l: &TcpListener, deadline: Instant) -> Result<TcpStream, SessionError> {
    l.set_nonblocking(true)?;
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false)?;
                return Ok(s);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(SessionError::Timeout);
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(SessionError::Io(e)),
        }
    }
}

/// Read one message: its type and body.
///
/// # Errors
/// I/O errors (EOF included) and header errors.
pub fn read_message(
    r: &mut impl Read,
    extended: bool,
) -> Result<(MessageType, Vec<u8>), SessionError> {
    let mut header = [0u8; HEADER_LEN];
    r.read_exact(&mut header)?;
    let h = Header::decode(&header, extended)
        .map_err(|e| SessionError::Protocol(format!("bad header: {e}")))?;
    let mut body = vec![0; h.body_len()];
    r.read_exact(&mut body)?;
    Ok((h.kind, body))
}

fn notification(body: &[u8]) -> SessionError {
    match NotificationMessage::decode(body) {
        Ok(n) => SessionError::Notification(n),
        Err(_) => SessionError::Protocol("truncated NOTIFICATION".to_owned()),
    }
}

fn handshake(mut stream: TcpStream, opts: &SpeakerOpts) -> Result<Session, SessionError> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let mut caps: Vec<Capability> = opts
        .families
        .iter()
        .map(|f| Capability::Multiprotocol(*f))
        .collect();
    caps.push(Capability::RouteRefresh);
    if opts.extended {
        caps.push(Capability::ExtendedMessage);
    }
    let ours = OpenMessage::new(opts.asn, opts.hold_time, opts.router_id, caps);
    let body = ours
        .encode()
        .map_err(|e| SessionError::Protocol(format!("cannot encode OPEN: {e}")))?;
    let bytes = frame(MessageType::Open, &body)
        .map_err(|e| SessionError::Protocol(format!("cannot frame OPEN: {e}")))?;
    stream.write_all(&bytes)?;

    let theirs = match read_message(&mut stream, false)? {
        (MessageType::Open, body) => OpenMessage::decode(&body)
            .map_err(|e| SessionError::Protocol(format!("bad OPEN: {e}")))?,
        (MessageType::Notification, body) => return Err(notification(&body)),
        (kind, _) => {
            return Err(SessionError::Protocol(format!(
                "expected OPEN, got {kind:?}"
            )));
        }
    };
    let negotiated = negotiate(opts, &ours, &theirs);
    stream.write_all(&KEEPALIVE)?;
    // RFC 4271 §8.2.2 OpenConfirm: only a KEEPALIVE or a NOTIFICATION may
    // come next.
    match read_message(&mut stream, negotiated.extended)? {
        (MessageType::Keepalive, _) => {}
        (MessageType::Notification, body) => return Err(notification(&body)),
        (kind, _) => {
            return Err(SessionError::Protocol(format!(
                "expected KEEPALIVE, got {kind:?}"
            )));
        }
    }
    stream.set_read_timeout(None)?;
    let local = stream.local_addr()?;
    let reader = stream.try_clone()?;
    let writer = Arc::new(Mutex::new(stream));
    let shared = Arc::new(Shared::default());
    let mut threads = Vec::new();
    {
        let shared = Arc::clone(&shared);
        let extended = negotiated.extended;
        threads.push(
            thread::Builder::new()
                .name("loadgen-read".to_owned())
                .spawn(move || drain(reader, extended, &shared))?,
        );
    }
    if negotiated.hold_time > 0 {
        // RFC 4271 §10: KeepaliveTime is a third of the Hold Time.
        let every = Duration::from_secs(u64::from(negotiated.hold_time)) / 3;
        let shared = Arc::clone(&shared);
        let writer = Arc::clone(&writer);
        threads.push(
            thread::Builder::new()
                .name("loadgen-keepalive".to_owned())
                .spawn(move || keepalives(&writer, every, &shared))?,
        );
    }
    Ok(Session {
        writer,
        shared,
        threads,
        negotiated,
        local,
    })
}

fn negotiate(opts: &SpeakerOpts, ours: &OpenMessage, theirs: &OpenMessage) -> Negotiated {
    // RFC 4760 §8: a speaker without Multiprotocol capabilities speaks
    // IPv4 unicast only.
    let mut their_families: Vec<AddressFamily> = theirs
        .capabilities
        .iter()
        .filter_map(|c| match c {
            Capability::Multiprotocol(f) => Some(*f),
            _ => None,
        })
        .collect();
    if their_families.is_empty() {
        their_families.push(AddressFamily::IPV4_UNICAST);
    }
    Negotiated {
        peer_as: theirs.asn(),
        peer_router_id: theirs.router_id,
        hold_time: ours.hold_time.secs().min(theirs.hold_time.secs()),
        four_octet_as: theirs
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::FourOctetAs(_))),
        extended: opts.extended && theirs.has(&Capability::ExtendedMessage),
        families: opts
            .families
            .iter()
            .copied()
            .filter(|f| their_families.contains(f))
            .collect(),
    }
}

/// Read and discard until the connection ends, noting UPDATEs and a
/// NOTIFICATION.
fn drain(mut stream: TcpStream, extended: bool, shared: &Shared) {
    loop {
        match read_message(&mut stream, extended) {
            Ok((MessageType::Update, _)) => {
                shared.updates_rx.fetch_add(1, Relaxed);
            }
            Ok((MessageType::Notification, body)) => {
                let text = match NotificationMessage::decode(&body) {
                    Ok(n) => n.to_string(),
                    Err(_) => "truncated".to_owned(),
                };
                if let Ok(mut n) = shared.notification.lock() {
                    *n = Some(text);
                }
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    shared.closed.store(true, Relaxed);
}

fn keepalives(writer: &Mutex<TcpStream>, every: Duration, shared: &Shared) {
    let mut next = Instant::now() + every;
    while !shared.stop.load(Relaxed) && !shared.closed.load(Relaxed) {
        if Instant::now() >= next {
            if write_locked(writer, &KEEPALIVE).is_err() {
                return;
            }
            next += every;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn opts(asn: u32, id: u8) -> SpeakerOpts {
        SpeakerOpts {
            asn: Asn(asn),
            router_id: RouterId::from(Ipv4Addr::new(192, 0, 2, id)),
            hold_time: HoldTime::new(9).unwrap(),
            families: vec![AddressFamily::IPV4_UNICAST],
            extended: true,
        }
    }

    #[test]
    fn two_speakers_establish_and_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            Session::establish(
                &Endpoint::Listen(listener),
                &opts(65_000, 1),
                Duration::from_secs(10),
            )
        });
        let client = Session::establish(
            &Endpoint::Connect(addr),
            &SpeakerOpts {
                hold_time: HoldTime::new(30).unwrap(),
                ..opts(4_200_000_001, 2)
            },
            Duration::from_secs(10),
        )
        .unwrap();
        let server = server.join().unwrap().unwrap();
        // RFC 4271 §4.2: the smaller Hold Time; RFC 6793 §3: the real ASN.
        assert_eq!(client.negotiated.hold_time, 9);
        assert_eq!(server.negotiated.peer_as, Asn(4_200_000_001));
        assert_eq!(client.negotiated.peer_as, Asn(65_000));
        assert!(client.negotiated.four_octet_as && client.negotiated.extended);
        assert_eq!(
            client.negotiated.families,
            vec![AddressFamily::IPV4_UNICAST]
        );

        let eor = crate::pack::Packer::new(true, true)
            .end_of_rib(AddressFamily::IPV4_UNICAST)
            .unwrap();
        assert_eq!(client.send(&[eor.clone(), eor]).unwrap(), 46);
        let deadline = Instant::now() + Duration::from_secs(5);
        while server.updates_received() < 2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(server.updates_received(), 2);

        client.close().unwrap();
        assert!(server.wait_closed(Some(Duration::from_secs(5))));
        assert!(
            server.notification().unwrap().contains("Cease"),
            "{:?}",
            server.notification()
        );
    }

    #[test]
    fn a_closed_port_times_out() {
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let err = Session::establish(
            &Endpoint::Connect(addr),
            &opts(65_001, 2),
            Duration::from_millis(600),
        )
        .unwrap_err();
        assert!(matches!(err, SessionError::Io(_)), "{err}");
    }
}
