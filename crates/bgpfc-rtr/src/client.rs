//! The RTR client: a thread that keeps the router supplied with
//! Validated ROA Payloads from one of its RPKI caches.
//!
//! [`Client::start`] spawns the thread. It is the I/O shell around a
//! [`Session`]: it connects with [`TcpStream::connect_timeout`], blocks
//! in each read no longer than [`Session::next_deadline`], cuts the
//! cache's octets into PDUs with a [`Framer`], hands every PDU, decoding
//! error, connection and disconnection to [`Session::step`], and carries
//! out the actions: it writes the PDUs, closes and opens connections,
//! writes the log lines with `bgpfc_log`, and publishes every commit
//! through a [`ValidationSink`] as a [`ValidationChange`]. The control
//! plane reads a [`Status`] snapshot with [`Client::status`] or a
//! [`StatusHandle`].
//!
//! # Several caches
//!
//! The caches are tried in order of preference, lowest value first, as
//! RFC 8210 §10 has it; caches of equal preference keep their configured
//! order. The client talks to one cache at a time. When an attempt fails,
//! or a connection ends in an error or before the cache has brought the
//! router in sync, the next cache in that order is tried after the
//! back-off, wrapping round to the most preferred. When the cache or the
//! network closes a connection that was in sync, the client starts again
//! from the most preferred cache after the shortest delay.
//!
//! Moving to another cache does not drop the data: the RIB goes on
//! validating with the previous cache's data until the new cache has sent
//! a full set, which then replaces it whole, or until that data expires
//! (§10, §6). Each cache gets a session of its own, so the new cache is
//! asked with a Reset Query.
//!
//! The same holds across clients. When the router's cache list or the
//! client's settings change, the old client is stopped and a new one
//! started; [`Client::start_holding`] gives the new one the data the old
//! one published ([`Status::held`]), which it treats like data from a
//! cache it moved away from.
//!
//! A cache that answers No Data Available is left for the next cache, as
//! after a failed attempt (§8.4: "the router SHOULD attempt to connect to
//! any other caches in its cache list, in preference order"). One that
//! answers a Serial Query with a Cache Reset while more-preferred caches
//! are configured is left for the most preferred (§8.3). The data stays
//! in use meanwhile, as on any move. With no other cache, or none more
//! preferred, the client stays: it reloads after a Cache Reset, and
//! repeats the Reset Query to a cache without data after each back-off.
//!
//! # Reconnecting
//!
//! After a failure the client waits a back-off that starts at
//! [`Backoff::min`] and doubles with each consecutive failure up to
//! [`Backoff::max`], lengthened by a jitter of up to half that is fixed by
//! [`Config::jitter_seed`] (issue #57). A cache that restarts is picked
//! up again within seconds without the operator, and routers that lost it
//! at the same moment do not all come back at the same moment. The last
//! data stays in use meanwhile, until it expires.
//!
//! # Stopping
//!
//! [`Client::stop`], or dropping the [`Client`], shuts the connection
//! down and joins the thread, which a stop wakes from any wait but one: a
//! [`ValidationSink::publish`] that waits for room in a full queue, until
//! the consumer makes some. Neither a connection attempt nor the name
//! lookup before it can be cut short, and an attempt may take as long as
//! [`Config::connect_timeout`], a lookup longer; so each runs on a thread
//! of its own, which the client thread waits for unless it is stopped. A
//! stopped client leaves an attempt under way to end by itself and closes
//! whatever connection it makes. So a stop, and with it a new
//! configuration, never waits for a cache that does not answer.
//!
//! RFC 8210 §9 says routers SHOULD enable TCP keep-alives. std offers no
//! way to set the socket option, so the client does without: the polls
//! of the Refresh Interval and the response timeout find a dead
//! connection instead.
//!
//! Implements: RFC 8210 §8.3 and §8.4 (other caches first after a Cache
//! Reset or No Data Available), §9 (unprotected TCP to the rpki-rtr port,
//! 323), §10 (the list of caches in order of preference; the data from one
//! cache at a time, replaced only by a full set from another; the
//! previous cache's data kept until then, also across a new cache list),
//! §6 (data not kept past its Expire Interval across a move to another
//! cache or client; the reconnect delay, see [`Backoff`]); RFC 6810 §7
//! (port 323 for version 0), §8 (the cache list).

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::{self, ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, TcpStream, ToSocketAddrs as _};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bgpfc_log::{Field, Level};
use bgpfc_rpki::{AffectedPrefixes, ValidationChange, ValidationSink, VrpSet};
use bgpfc_wire::prefix::Prefix;

use crate::framer::{Framer, Received};
use crate::pdu::{Pdu, Version};
use crate::session::{self, Action, Commit, Event, Fallback, LogLine, Session, State};

/// The rpki-rtr port. RFC 8210 §9: "Caches and routers MUST implement
/// unprotected transport over TCP using a port, rpki-rtr (323)"; RFC 6810
/// §7 says the same for version 0.
pub const DEFAULT_PORT: u16 = 323;

/// Octets read from the socket at a time. The framer holds less than one
/// PDU between reads, so this bounds what a connection buffers.
const READ_BUFFER: usize = 16 * 1024;

/// One cache the client may use: an entry of the router's cache list
/// (RFC 8210 §10).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cache {
    /// "The IP address or fully qualified domain name of the cache"
    /// (RFC 8210 §10). A name is looked up again at every connection
    /// attempt, and each of its addresses is tried in turn.
    pub host: String,
    /// The TCP port: [`DEFAULT_PORT`] unless the cache listens elsewhere.
    pub port: u16,
    /// "The router's preference to connect to that cache; the lower the
    /// value, the more preferred" (RFC 8210 §10). Several caches may
    /// share a value.
    pub preference: u32,
}

impl Cache {
    /// The cache at `host` on the rpki-rtr port, with preference 0.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Cache {
        Cache {
            host: host.into(),
            port: DEFAULT_PORT,
            preference: 0,
        }
    }
}

impl fmt::Display for Cache {
    /// `host:port`, with an IPv6 address in brackets: `[2001:db8::1]:323`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// How long the client waits before it connects again after a failure.
///
/// After `n` consecutive failures it waits `min · 2ⁿ⁻¹`, at most `max`,
/// lengthened by a jitter of up to half that delay. The jitter depends
/// only on [`Config::jitter_seed`] and `n`, so a router's schedule can be
/// reproduced, and routers with different seeds spread out. A connection
/// lost after the cache had brought the router in sync is not a failure:
/// the next attempt waits `min`.
///
/// RFC 8210 §6 says the router "SHOULD NOT retry sooner than" the Retry
/// Interval, 600 seconds unless the cache sent another value. The client
/// does retry sooner, on purpose (issue #57): when a validator restarts,
/// the router reconnects within seconds instead of ten minutes, and the
/// back-off, not the cache, keeps a cache that stays away from being
/// hammered. [`Backoff::DEFAULT`] grows to that default Retry Interval,
/// and the jitter only lengthens a delay, so a cache that stays away is
/// tried no more often than the RFC asks once the back-off has grown.
/// The same goes for the periodic Reset Queries to the only cache when it
/// has No Data Available (§8.4), which is how a restarting validator
/// answers until its first run. The other queries on an open connection
/// keep the cache's Refresh Interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// The delay after the first failure. Raised to 1 ms if lower.
    pub min: Duration,
    /// The longest delay before the jitter. Raised to `min` if lower.
    pub max: Duration,
}

impl Backoff {
    /// One second, doubling up to 600 seconds, the default Retry Interval
    /// of RFC 8210 §6.
    pub const DEFAULT: Backoff = Backoff {
        min: Duration::from_secs(1),
        max: Duration::from_secs(600),
    };

    /// The delay before the next attempt after `failures` consecutive
    /// failures (0 after a connection that was in sync was lost).
    fn delay(&self, failures: u32, seed: u64) -> Duration {
        let min = self.min.max(Duration::from_millis(1));
        let max = self.max.max(min);
        let doublings = failures.saturating_sub(1);
        let nominal = 1u32
            .checked_shl(doublings)
            .and_then(|factor| min.checked_mul(factor))
            .map_or(max, |d| d.min(max));
        // A fraction in [0, 1/2): the top 32 bits of a hash of the seed
        // and the attempt, over 2^33.
        let hash = splitmix64(seed ^ splitmix64(u64::from(failures)));
        let top = u32::try_from(hash >> 32).unwrap_or(u32::MAX);
        let fraction = f64::from(top) / 8_589_934_592.0;
        nominal.saturating_add(nominal.mul_f64(fraction))
    }
}

impl Default for Backoff {
    fn default() -> Backoff {
        Backoff::DEFAULT
    }
}

/// `SplitMix64`'s output function: a cheap, well-mixed 64-bit hash.
const fn splitmix64(x: u64) -> u64 {
    let x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// What the operator configures for the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The caches to use, in any order; the client sorts them by
    /// preference. [`Client::start`] refuses an empty list.
    pub caches: Vec<Cache>,
    /// The longest a connection attempt may take, the name lookup
    /// included where the resolver allows. The client cuts it to the
    /// session's [`response_timeout`](session::Config::response_timeout),
    /// and raises it to at least 1 ms.
    pub connect_timeout: Duration,
    /// The reconnect back-off.
    pub backoff: Backoff,
    /// The seed of the back-off's jitter. Give each router its own, such
    /// as its BGP Identifier, so that routers that lose a cache at the
    /// same moment come back at different moments.
    pub jitter_seed: u64,
    /// The protocol version to offer, the response timeout and the expiry
    /// override ([`max_expire`](session::Config::max_expire)), for the
    /// session with each cache.
    pub session: session::Config,
}

impl Config {
    /// The default [`Config::connect_timeout`]. No RFC gives one; ten
    /// seconds is ample on the controlled network RFC 8210 §9 asks for.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// The given caches, with the default timeout, back-off and session
    /// settings, and jitter seed 0.
    #[must_use]
    pub fn new(caches: Vec<Cache>) -> Config {
        Config {
            caches,
            connect_timeout: Config::DEFAULT_CONNECT_TIMEOUT,
            backoff: Backoff::DEFAULT,
            jitter_seed: 0,
            session: session::Config::default(),
        }
    }
}

/// A snapshot of the client, for the control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The cache in use, or the one the client is trying next.
    pub cache: Cache,
    /// Where the session with that cache stands.
    pub state: State,
    /// Whether a transport connection to it is open.
    pub connected: bool,
    /// The protocol version the client speaks to it: the configured one,
    /// or a lower one after a downgrade (RFC 8210 §7).
    pub version: Version,
    /// The cache's Session ID, while the client can go on with a Serial
    /// Query.
    pub session_id: Option<u16>,
    /// The Serial Number of the data, likewise.
    pub serial: Option<u32>,
    /// When the client was last in sync with the cache: its last End of
    /// Data.
    pub synced_at: Option<Instant>,
    /// When the client last published a change.
    pub last_commit: Option<Instant>,
    /// When the published data expires unless a cache refreshes it.
    pub expires_at: Option<Instant>,
    /// The published data: what the RIB validates with. `None` before the
    /// first change.
    pub vrps: Option<Arc<VrpSet>>,
    /// IPv4 VRPs in [`Status::vrps`].
    pub vrps_ipv4: usize,
    /// IPv6 VRPs in [`Status::vrps`].
    pub vrps_ipv6: usize,
    /// Consecutive failures, as the back-off counts them: attempts that
    /// failed, connections that ended in an error or before the cache
    /// brought the router in sync, and No Data Available answers. Each
    /// time the cache brings the router in sync it goes back to 0, and a
    /// connection that was in sync and that the cache or the network then
    /// closed does not count.
    pub failures: u32,
    /// The last warning or error the client logged: its message, then its
    /// fields as the log line has them, each value quoted and escaped
    /// where it holds whitespace, a quote or a control character.
    pub last_error: Option<String>,
    /// When it was logged.
    pub last_error_at: Option<Instant>,
    /// Whether the thread runs: false once stopped, or once the sink was
    /// closed.
    pub running: bool,
}

impl Status {
    /// What a client started after this one must keep using:
    /// [`Status::vrps`] until [`Status::expires_at`]. `None` if this client
    /// never published, in which case the RIB has no data from it.
    ///
    /// Read it once the client has stopped, so that nothing it publishes
    /// later is missed.
    #[must_use]
    pub fn held(&self) -> Option<Held> {
        self.vrps.as_ref().map(|vrps| Held {
            vrps: Arc::clone(vrps),
            expires_at: self.expires_at,
        })
    }
}

/// Data a client starts with because the RIB validates with it already:
/// what an earlier client published (see [`Client::start_holding`]).
///
/// RFC 8210 §10: "If a client loses connectivity to a cache it is using or
/// otherwise decides to switch to a new cache, it SHOULD retain the data
/// from the previous cache until it has a full set of data from one or
/// more other caches." A new cache list is such a decision. §6: the data
/// still expires when its Expire Interval says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    /// The data, as the RIB has it.
    pub vrps: Arc<VrpSet>,
    /// When it expires. `None` for data that has nothing left to expire:
    /// the empty set a client publishes once its data expired.
    pub expires_at: Option<Instant>,
}

/// A cloneable reader of a [`Client`]'s [`Status`], for the control
/// thread. It stays valid after the client is gone, with
/// [`Status::running`] false.
#[derive(Clone, Debug)]
pub struct StatusHandle {
    status: Arc<Mutex<Status>>,
}

impl StatusHandle {
    /// The current snapshot.
    #[must_use]
    pub fn status(&self) -> Status {
        lock(&self.status).clone()
    }
}

/// What the client and its thread share.
#[derive(Debug, Default)]
struct Shared {
    /// Set by [`Client::stop`].
    stop: AtomicBool,
    /// What a stop must reach, under the mutex the thread waits on.
    slot: Mutex<Slot>,
    /// Wakes the thread from its sleep, or from its wait for a connection
    /// attempt.
    wake: Condvar,
}

/// See [`Shared::slot`].
#[derive(Debug, Default)]
struct Slot {
    /// A clone of the thread's connection, for [`Client::stop`] to shut
    /// down.
    stream: Option<TcpStream>,
    /// The outcome of the connection attempt under way, once it has one.
    attempt: Option<io::Result<TcpStream>>,
}

impl Shared {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Stop the thread: wake it, and cut short any read or write on its
    /// connection.
    fn stop(&self) {
        let mut slot = lock(&self.slot);
        self.stop.store(true, Ordering::Release);
        if let Some(stream) = slot.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        // A connection the thread will not take now is closed.
        slot.attempt = None;
        self.wake.notify_all();
    }

    /// Make the connection `stream` is a clone of one that a stop shuts
    /// down. False if the client is stopping already.
    fn register(&self, stream: TcpStream) -> bool {
        let mut slot = lock(&self.slot);
        if self.stopping() {
            return false;
        }
        slot.stream = Some(stream);
        true
    }

    fn unregister(&self) {
        lock(&self.slot).stream.take();
    }

    /// Sleep for `timeout`, or until a stop or a nudge.
    fn sleep(&self, timeout: Option<Duration>) {
        let guard = lock(&self.slot);
        if self.stopping() {
            return;
        }
        // A spurious wake-up only makes the thread look at its timers
        // early. Poisoning cannot leave the slot half-updated.
        match timeout {
            Some(timeout) => drop(self.wake.wait_timeout(guard, timeout)),
            None => drop(self.wake.wait(guard)),
        }
    }

    /// Connect to `cache` within `timeout`, as [`open`] does, and return
    /// the outcome, or `None` once the client is stopped.
    ///
    /// Neither the connection attempt nor the name lookup before it can be
    /// cut short, so they run on a thread of their own, and a stop wakes
    /// the client thread from its wait at once. The attempt then ends by
    /// itself, within `timeout` once the name is looked up, and the
    /// connection it may make is closed.
    fn connect(
        self: &Arc<Self>,
        cache: &Cache,
        timeout: Duration,
    ) -> Option<io::Result<TcpStream>> {
        let shared = Arc::clone(self);
        let cache = cache.clone();
        let spawned = thread::Builder::new()
            .name("rtr-connect".to_owned())
            .spawn(move || {
                let outcome = open(&cache, timeout);
                let mut slot = lock(&shared.slot);
                if !shared.stopping() {
                    slot.attempt = Some(outcome);
                }
                shared.wake.notify_all();
            });
        if let Err(e) = spawned {
            return Some(Err(e));
        }
        let mut slot = lock(&self.slot);
        loop {
            if self.stopping() {
                return None;
            }
            if let Some(outcome) = slot.attempt.take() {
                return Some(outcome);
            }
            slot = self.wake.wait(slot).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Lock a mutex, whether or not a thread panicked while holding it: none
/// of the data behind these mutexes can be left half-updated.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The thread's clock: [`Instant::now`], plus a skew that only tests set,
/// so that they can reach the expiry of RFC 8210 §6, ten minutes at the
/// least, without waiting for it.
#[derive(Clone, Debug, Default)]
struct Clock {
    /// Nanoseconds added to the real time. Always 0 outside tests.
    skew: Arc<AtomicU64>,
}

impl Clock {
    fn now(&self) -> Instant {
        let skew = Duration::from_nanos(self.skew.load(Ordering::Acquire));
        Instant::now()
            .checked_add(skew)
            .unwrap_or_else(Instant::now)
    }
}

/// The RTR client: a thread that keeps a session with one of the
/// configured caches and publishes the data it commits.
///
/// [`Client::stop`] or dropping the client stops the thread.
#[derive(Debug)]
pub struct Client {
    shared: Arc<Shared>,
    status: Arc<Mutex<Status>>,
    thread: Option<JoinHandle<()>>,
    #[cfg(test)]
    clock: Clock,
}

impl Client {
    /// Start the client thread. It connects to the most preferred cache
    /// at once and publishes every change to `sink`, starting with the
    /// first full set, which affects every route
    /// ([`AffectedPrefixes::All`]).
    ///
    /// The client publishes nothing when it stops: to stop validating,
    /// publish [`ValidationChange::disabled`] to the RIB after
    /// [`Client::stop`].
    ///
    /// # Errors
    /// [`ErrorKind::InvalidInput`] if `config` names no cache, or the
    /// error of spawning the thread.
    pub fn start<S>(config: Config, sink: S) -> io::Result<Client>
    where
        S: ValidationSink + 'static,
    {
        Client::start_holding(config, sink, None)
    }

    /// [`Client::start`] for a client that takes over from an earlier one,
    /// whose data, `held`, the RIB validates with: what
    /// [`Status::held`] of the stopped client gives.
    ///
    /// The new client keeps that data, as it keeps the data of a cache it
    /// moved away from (RFC 8210 §10): its status shows it, and the first
    /// full set a cache sends replaces it, affecting only the routes the
    /// two sets judge differently. If no cache sends one before
    /// [`Held::expires_at`], the client publishes an empty set then, so
    /// that every route is `NotFound` (§6). With `held` `None` it is
    /// [`Client::start`]: the first set replaces whatever source the RIB
    /// has, and affects every route.
    ///
    /// # Errors
    /// As [`Client::start`].
    pub fn start_holding<S>(config: Config, sink: S, held: Option<Held>) -> io::Result<Client>
    where
        S: ValidationSink + 'static,
    {
        Client::spawn(config, sink, held, Clock::default())
    }

    fn spawn<S>(config: Config, sink: S, held: Option<Held>, clock: Clock) -> io::Result<Client>
    where
        S: ValidationSink + 'static,
    {
        if config.caches.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "no RTR cache configured",
            ));
        }
        let shared = Arc::new(Shared::default());
        #[cfg(test)]
        let client_clock = clock.clone();
        let mut worker = Worker::new(config, sink, Arc::clone(&shared), clock);
        if let Some(held) = held {
            worker.hold(held);
        }
        let status = Arc::clone(&worker.status);
        let thread = thread::Builder::new()
            .name("rtr-client".to_owned())
            .spawn(move || worker.run())?;
        Ok(Client {
            shared,
            status,
            thread: Some(thread),
            #[cfg(test)]
            clock: client_clock,
        })
    }

    /// The current snapshot.
    #[must_use]
    pub fn status(&self) -> Status {
        lock(&self.status).clone()
    }

    /// A reader of the snapshot that the control thread can keep.
    #[must_use]
    pub fn status_handle(&self) -> StatusHandle {
        StatusHandle {
            status: Arc::clone(&self.status),
        }
    }

    /// Close the connection and join the thread. Calling it again does
    /// nothing. See the module documentation for how long it can take.
    pub fn stop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.shared.stop();
        if thread.join().is_err() {
            bgpfc_log::error!("rtr client thread panicked");
        }
        lock(&self.status).running = false;
    }
}

#[cfg(test)]
impl Client {
    /// Move the thread's clock forward by `by`, and wake it if it sleeps.
    fn advance(&self, by: Duration) {
        let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        self.clock.skew.fetch_add(nanos, Ordering::AcqRel);
        let _guard = lock(&self.shared.slot);
        self.shared.wake.notify_all();
    }
}

impl Drop for Client {
    /// [`Client::stop`].
    fn drop(&mut self) {
        self.stop();
    }
}

/// A transport connection and the framer for its byte stream.
struct Conn {
    /// Tells this connection from the ones before it.
    id: u64,
    stream: TcpStream,
    framer: Framer,
}

/// The client thread's state.
struct Worker<S> {
    /// The caches, most preferred first. Never empty.
    caches: Vec<Cache>,
    connect_timeout: Duration,
    backoff: Backoff,
    jitter_seed: u64,
    session_config: session::Config,
    sink: S,
    shared: Arc<Shared>,
    status: Arc<Mutex<Status>>,
    clock: Clock,
    /// The session with `caches[current]`.
    session: Session,
    /// Index of the cache in use or being tried. Always in range.
    current: usize,
    conn: Option<Conn>,
    next_conn_id: u64,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    /// The octets of the PDU being handed to the session.
    pdu_buf: Vec<u8>,
    /// Consecutive failed attempts, for the back-off.
    failures: u32,
    /// Whether the current connection has brought the router in sync.
    synced_on_conn: bool,
    /// Whether the session has not committed yet: its first set replaces
    /// whatever the RIB has, which may come from another cache.
    fresh_session: bool,
    /// The data the RIB validates with, as last published.
    published: Option<Arc<VrpSet>>,
    /// VRPs in `published`: IPv4, IPv6.
    counts: (usize, usize),
    /// When `published` expires, while it came from a session the client
    /// has moved away from (RFC 8210 §10: kept until another cache has a
    /// full set; §6: not past its Expire Interval).
    held_expires: Option<Instant>,
    /// Since when no connection has been in sync, after one was.
    down_since: Option<Instant>,
    last_commit: Option<Instant>,
    last_error: Option<(Instant, String)>,
    /// The level of the line in `last_error`, if the step at hand wrote
    /// it: a step's most severe line explains it best.
    step_level: Option<Level>,
    /// Why the transport failed, for the log lines of the next step.
    pending_error: Option<String>,
    /// Set once the sink is closed: the thread ends.
    exit: bool,
}

impl<S: ValidationSink> Worker<S> {
    fn new(config: Config, sink: S, shared: Arc<Shared>, clock: Clock) -> Worker<S> {
        let mut caches = config.caches;
        // RFC 8210 §10: "the lower the value, the more preferred". A stable
        // sort keeps caches of equal preference in their configured order.
        caches.sort_by_key(|cache| cache.preference);
        let now = clock.now();
        let session = Session::new(config.session, now);
        let connect_timeout = config
            .connect_timeout
            .min(session.config().response_timeout)
            .max(Duration::from_millis(1));
        let status = Status {
            // invariant: Client::spawn refused an empty list.
            cache: caches[0].clone(),
            state: session.state(),
            connected: false,
            version: session.version(),
            session_id: None,
            serial: None,
            synced_at: None,
            last_commit: None,
            expires_at: None,
            vrps: None,
            vrps_ipv4: 0,
            vrps_ipv6: 0,
            failures: 0,
            last_error: None,
            last_error_at: None,
            running: true,
        };
        Worker {
            caches,
            connect_timeout,
            backoff: config.backoff,
            jitter_seed: config.jitter_seed,
            session_config: config.session,
            sink,
            shared,
            status: Arc::new(Mutex::new(status)),
            clock,
            session,
            current: 0,
            conn: None,
            next_conn_id: 0,
            read_buf: vec![0; READ_BUFFER],
            write_buf: Vec::new(),
            pdu_buf: Vec::new(),
            failures: 0,
            synced_on_conn: false,
            fresh_session: true,
            published: None,
            counts: (0, 0),
            held_expires: None,
            down_since: None,
            last_commit: None,
            last_error: None,
            step_level: None,
            pending_error: None,
            exit: false,
        }
    }

    /// Start out with `held`, the data an earlier client published, as if
    /// it came from a cache this client moved away from (RFC 8210 §10):
    /// the first commit replaces it with only the routes the two sets
    /// disagree on affected, and it expires at its time (§6).
    fn hold(&mut self, held: Held) {
        self.counts = count(&held.vrps);
        self.published = Some(held.vrps);
        self.held_expires = held.expires_at;
        self.tell_held();
        self.publish_status(true);
    }

    /// Tell a session that has not committed yet what the RIB validates
    /// with meanwhile, for its lines about stale data.
    fn tell_held(&mut self) {
        if self.fresh_session {
            let vrps = self.published.as_ref().map_or(0, |v| v.len());
            self.session.set_held(vrps, self.held_expires);
        }
    }

    /// When the data the RIB validates with expires: that of the session
    /// once it has committed, and until then what the client holds from
    /// elsewhere.
    fn expires_at(&self) -> Option<Instant> {
        if self.fresh_session {
            self.held_expires
        } else {
            self.session.expires_at()
        }
    }

    fn cache(&self) -> &Cache {
        // invariant: `current` is always an index into the non-empty list.
        &self.caches[self.current]
    }

    fn run(mut self) {
        while !self.exit && !self.shared.stopping() {
            let now = self.clock.now();
            let wake = self.next_wake();
            if wake.is_some_and(|at| at <= now) {
                self.handle(Event::Tick);
            } else if self.conn.is_some() {
                self.read(wake, now);
            } else {
                self.shared
                    .sleep(wake.map(|at| at.saturating_duration_since(now)));
            }
            self.publish_status(true);
        }
        self.close();
        self.publish_status(false);
    }

    /// When the thread must next step the session without input: its
    /// timers, or the expiry of data held over from another cache.
    fn next_wake(&self) -> Option<Instant> {
        match (self.session.next_deadline(), self.held_expires) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    // ------------------------------------------------------------ input

    /// Read what the cache sent, waiting until `wake` at the latest.
    fn read(&mut self, wake: Option<Instant>, now: Instant) {
        let Some(conn) = &mut self.conn else {
            return;
        };
        // A zero timeout would mean "block forever" to the socket; the
        // deadline is in the future, so wait at least a millisecond.
        let timeout = wake.map(|at| {
            at.saturating_duration_since(now)
                .max(Duration::from_millis(1))
        });
        let result = conn
            .stream
            .set_read_timeout(timeout)
            .and_then(|()| conn.stream.read(&mut self.read_buf));
        match result {
            Ok(0) => self.lost("the cache closed the connection".to_owned()),
            Ok(n) => {
                conn.framer.feed(self.read_buf.get(..n).unwrap_or_default());
                self.drain();
            }
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(e) => self.lost(e.to_string()),
        }
    }

    /// Hand the session every PDU the framer has, in order, until the
    /// connection they came on is gone.
    fn drain(&mut self) {
        // The session needs each PDU's octets for an Error Report about it
        // (RFC 8210 §5.11). They are copied out of the framer, which the
        // step may close, into one buffer used over and over: no
        // allocation per PDU.
        let mut octets = std::mem::take(&mut self.pdu_buf);
        while let Some(conn) = &mut self.conn {
            let id = conn.id;
            octets.clear();
            let decoded = match conn.framer.next_received() {
                Ok(None) => break,
                Ok(Some(received)) => {
                    octets.extend_from_slice(received.octets);
                    Ok(received.pdu)
                }
                Err(error) => {
                    octets.extend_from_slice(conn.framer.erroneous_pdu());
                    Err(error)
                }
            };
            let failed = decoded.is_err();
            self.handle(match decoded {
                Ok(pdu) => Event::Pdu(Received {
                    pdu,
                    octets: &octets,
                }),
                Err(error) => Event::DecodeError {
                    error,
                    erroneous_pdu: &octets,
                },
            });
            // After a decoding error nothing more can be framed (RFC 8210
            // §12: the error is fatal), and PDUs still buffered from a
            // connection the session let go of are not read.
            if failed
                || self.exit
                || self.shared.stopping()
                || self.conn.as_ref().map(|c| c.id) != Some(id)
            {
                break;
            }
        }
        self.pdu_buf = octets;
    }

    /// The transport failed: close it and tell the session.
    fn lost(&mut self, why: String) {
        if self.shared.stopping() {
            // Client::stop shut the socket down; not a failure.
            return;
        }
        self.close();
        self.pending_error = Some(why);
        self.handle(Event::Disconnected);
    }

    // ------------------------------------------------------------ steps

    /// Step the session with `event`, and with whatever follows from its
    /// actions, until nothing does.
    fn handle(&mut self, event: Event<'_>) {
        let mut next = Some(event);
        while let Some(event) = next.take() {
            if self.exit {
                return;
            }
            next = self.step(event);
        }
    }

    /// One step of the session and its actions. Returns the event that
    /// follows: the outcome of a connection attempt, or the loss of a
    /// connection that failed while the step wrote to it.
    fn step(&mut self, event: Event<'_>) -> Option<Event<'static>> {
        let now = self.clock.now();
        self.step_level = None;
        self.expire_held(now);
        // A connection that was in sync and then broke is the cache going
        // away, such as a validator restarting: the back-off starts over
        // and the most preferred cache comes first again. Anything else
        // that ends a connection is a failure.
        let healthy_loss = matches!(event, Event::Disconnected) && self.synced_on_conn;
        let failures = if healthy_loss {
            0
        } else {
            self.failures.saturating_add(1)
        };
        let delay = self.backoff.delay(failures, self.jitter_seed);
        // NOTE: sooner than the Retry Interval of RFC 8210 §6; see Backoff.
        self.session.set_retry_delay(Some(delay));
        let context = self.pending_error.take();
        let before = self.session.state();
        let synced_before = self.session.synced_at();
        let mut connect = false;
        let mut fallback = None;
        let mut leaving = false;
        for action in self.session.step(event, now) {
            match action {
                // After the other actions of the step: a Close comes first.
                Action::Connect => connect = true,
                // The query the session sends in place of the other caches
                // goes with the connection.
                Action::Send(_) if leaving => {}
                Action::Send(pdu) => self.send(&pdu),
                Action::Close => self.close(),
                Action::Negotiated(version) => {
                    if let Some(conn) = &mut self.conn {
                        conn.framer.set_version(version);
                    }
                }
                // The session logs it, and queries in the new version.
                Action::Downgrade(_) => {}
                Action::Commit(commit) => self.publish(commit, now),
                Action::Log(line) => self.log(&line, context.as_deref(), now),
                Action::Fallback(why) => {
                    leaving = self.leaves(why);
                    fallback = Some(why);
                }
            }
        }
        if self.session.synced_at() != synced_before {
            self.on_sync(now);
        }
        match fallback {
            Some(why) if leaving => {
                self.leave(why, failures, delay, now);
                self.pending_error = None;
                return None;
            }
            Some(Fallback::NoData) => {
                // RFC 8210 §8.4 with no other cache: the session stays and
                // issues "periodic Reset Queries", each after the back-off,
                // which grows with every No Data Available like with every
                // failed attempt.
                self.failures = failures;
                self.synced_on_conn = false;
            }
            _ => {}
        }
        let after = self.session.state();
        let connected = matches!(after, State::Querying | State::Receiving | State::Idle);
        if connected && self.conn.is_none() {
            // A write failed, and took the connection with it.
            return Some(Event::Disconnected);
        }
        if !connected {
            // Whatever the session let go of is closed.
            self.close();
        }
        if after == State::Disconnected && before != State::Disconnected {
            self.on_failure(healthy_loss, failures, delay, now);
        }
        if connect && after == State::Connecting {
            return self.connect();
        }
        // A transport error not followed by a step is stale by now.
        self.pending_error = None;
        None
    }

    /// Whether to leave the cache that cannot serve the router for `why`.
    fn leaves(&self, why: Fallback) -> bool {
        match why {
            // RFC 8210 §8.4: "any other caches in its cache list".
            Fallback::NoData => self.caches.len() > 1,
            // RFC 8210 §8.3: "any more-preferred caches in its cache list":
            // a lower preference value (§10), not an equal one.
            Fallback::CacheReset => self
                .caches
                .first()
                .is_some_and(|first| first.preference < self.cache().preference),
        }
    }

    /// Close the connection to a cache that cannot serve the router for
    /// `why`, and try the others, keeping its data meanwhile (§10).
    fn leave(&mut self, why: Fallback, failures: u32, delay: Duration, now: Instant) {
        self.close();
        match why {
            // RFC 8210 §8.4: "the router SHOULD attempt to connect to any
            // other caches in its cache list, in preference order": as after
            // a failed attempt, the next one in that order, wrapping round,
            // after the back-off.
            Fallback::NoData => self.on_failure(false, failures, delay, now),
            // RFC 8210 §8.3: "the router SHOULD attempt to connect to any
            // more-preferred caches in its cache list": the most preferred,
            // then on down the list as attempts fail. The cache works; that
            // is no failure.
            Fallback::CacheReset => {
                self.synced_on_conn = false;
                let delay = self.backoff.delay(0, self.jitter_seed);
                let at = now.checked_add(delay).unwrap_or(now);
                self.switch_to(0, at, now);
            }
        }
    }

    /// The connection ended, or an attempt failed, and the session waits
    /// `delay` before its next attempt: count the failure, and move on to
    /// the next cache if there is one.
    fn on_failure(&mut self, healthy_loss: bool, failures: u32, delay: Duration, now: Instant) {
        let was_in_sync = self.synced_on_conn;
        self.synced_on_conn = false;
        self.failures = failures;
        if was_in_sync && self.down_since.is_none() {
            self.down_since = Some(now);
            let mut fields = vec![field(
                "serving_vrps",
                self.published.as_ref().map_or(0, |v| v.len()),
            )];
            if let Some(at) = self.expires_at() {
                // Whole seconds, as the session's lines give it.
                let secs = at.saturating_duration_since(now).as_secs();
                fields.push(field("expires_in", format_args!("{secs}s")));
            }
            fields.push(field("reconnect_in", Millis(delay)));
            self.shell_log(
                Level::Warn,
                "rtr lost the cache; serving the last data while reconnecting",
                fields,
                now,
            );
        }
        // RFC 8210 §10: caches are tried "in preference order". A cache
        // that was in sync is lost: start again from the most preferred.
        // Otherwise try the next one.
        let next = if healthy_loss {
            0
        } else {
            (self.current + 1) % self.caches.len()
        };
        if next != self.current {
            let at = now.checked_add(delay).unwrap_or(now);
            self.switch_to(next, at, now);
        }
    }

    /// Use the cache at `next` from now on, connecting at `connect_at`.
    fn switch_to(&mut self, next: usize, connect_at: Instant, now: Instant) {
        if !self.fresh_session {
            // The RIB has this session's data. RFC 8210 §10: "If a client
            // loses connectivity to a cache it is using or otherwise decides
            // to switch to a new cache, it SHOULD retain the data from the
            // previous cache until it has a full set of data from one or
            // more other caches." But not past its Expire Interval (§6).
            self.held_expires = self.session.expires_at();
        }
        self.current = next;
        self.session = Session::new(self.session_config, connect_at);
        self.fresh_session = true;
        self.tell_held();
        let fields = vec![
            field("preference", self.cache().preference),
            field("in", Millis(connect_at.saturating_duration_since(now))),
        ];
        self.shell_log(Level::Info, "rtr trying the next cache", fields, now);
    }

    fn on_sync(&mut self, now: Instant) {
        self.synced_on_conn = true;
        // A success ends the run of failures: the next one waits the
        // shortest back-off again.
        self.failures = 0;
        if let Some(since) = self.down_since.take() {
            let fields = vec![field(
                "down_for",
                Millis(now.saturating_duration_since(since)),
            )];
            self.shell_log(Level::Info, "rtr cache reachable again", fields, now);
        }
    }

    // ----------------------------------------------------------- output

    /// Open a connection to the current cache. `None` if the client is
    /// stopping.
    fn connect(&mut self) -> Option<Event<'static>> {
        if self.shared.stopping() {
            return None;
        }
        // The control plane sees the attempt while it lasts.
        self.publish_status(true);
        let stream = match self.shared.connect(self.cache(), self.connect_timeout)? {
            Ok(stream) => stream,
            Err(e) => {
                self.pending_error = Some(e.to_string());
                return Some(Event::Disconnected);
            }
        };
        let _ = stream.set_nodelay(true);
        // A cache that stops reading must not wedge the thread: a write
        // blocked this long fails the connection.
        let _ = stream.set_write_timeout(Some(self.session.config().response_timeout));
        let clone = match stream.try_clone() {
            Ok(clone) => clone,
            Err(e) => {
                let _ = stream.shutdown(Shutdown::Both);
                self.pending_error = Some(e.to_string());
                return Some(Event::Disconnected);
            }
        };
        if !self.shared.register(clone) {
            let _ = stream.shutdown(Shutdown::Both);
            return None;
        }
        self.next_conn_id += 1;
        self.conn = Some(Conn {
            id: self.next_conn_id,
            stream,
            framer: Framer::new(),
        });
        self.synced_on_conn = false;
        Some(Event::Connected)
    }

    fn send(&mut self, pdu: &Pdu) {
        let Some(conn) = &mut self.conn else {
            return;
        };
        self.write_buf.clear();
        pdu.encode_into(&mut self.write_buf);
        if let Err(e) = conn.stream.write_all(&self.write_buf) {
            self.pending_error = Some(e.to_string());
            self.close();
        }
    }

    fn close(&mut self) {
        if let Some(conn) = self.conn.take() {
            let _ = conn.stream.shutdown(Shutdown::Both);
            self.shared.unregister();
        }
    }

    /// Publish a commit of the session.
    fn publish(&mut self, commit: Commit, now: Instant) {
        let Commit { vrps, affected } = commit;
        let affected = match (&self.published, self.fresh_session) {
            // The session's first set replaces data from another cache, or
            // from an earlier session with this one (RFC 8210 §10): only
            // the routes the two sets disagree on need validating again.
            (Some(old), true) => AffectedPrefixes::between(old, &vrps),
            _ => affected,
        };
        self.fresh_session = false;
        self.held_expires = None;
        self.send_change(vrps, affected, now);
    }

    /// Drop data held over from another cache once it expires.
    fn expire_held(&mut self, now: Instant) {
        if self.held_expires.is_none_or(|at| at > now) {
            return;
        }
        self.held_expires = None;
        let Some(old) = self.published.clone() else {
            return;
        };
        // RFC 8210 §6 Expire Interval: "The router MUST NOT retain the data
        // past the time indicated by this parameter."
        let fields = vec![field("vrps", old.len())];
        self.shell_log(
            Level::Error,
            "rtr data from the previous cache expired before another cache sent a full set; every route is now not-found",
            fields,
            now,
        );
        let empty = Arc::new(VrpSet::new());
        let affected = AffectedPrefixes::between(&old, &empty);
        self.send_change(empty, affected, now);
        self.tell_held();
    }

    fn send_change(&mut self, vrps: Arc<VrpSet>, affected: AffectedPrefixes, now: Instant) {
        self.counts = count(&vrps);
        self.published = Some(Arc::clone(&vrps));
        self.last_commit = Some(now);
        let change = ValidationChange {
            source: vrps,
            affected,
        };
        if let Err(e) = self.sink.publish(change) {
            let fields = vec![field("error", e)];
            self.shell_log(
                Level::Error,
                "rtr validation changes have nowhere to go; stopping the client",
                fields,
                now,
            );
            self.exit = true;
        }
    }

    // ---------------------------------------------------------- logging

    /// Write a line of the session, or of the client, with the cache and
    /// any transport error first. Keep the most severe warning or error of
    /// the step for [`Status::last_error`].
    fn log(&mut self, line: &LogLine, error: Option<&str>, now: Instant) {
        let cache = self.cache().to_string();
        let mut context: Vec<Field<'_>> = vec![("cache", &cache)];
        if let Some(error) = &error {
            context.push(("error", error));
        }
        line.write(&context);
        // Level orders the most severe first.
        if line.level <= Level::Warn && self.step_level.is_none_or(|kept| line.level <= kept) {
            self.step_level = Some(line.level);
            let mut text = line.message.to_owned();
            for (key, value) in &context {
                push_field(&mut text, key, &value.to_string());
            }
            for (key, value) in &line.fields {
                push_field(&mut text, key, value);
            }
            self.last_error = Some((now, text));
        }
    }

    fn shell_log(
        &mut self,
        level: Level,
        message: &'static str,
        fields: Vec<(&'static str, String)>,
        now: Instant,
    ) {
        let line = LogLine {
            level,
            message,
            fields,
        };
        self.log(&line, None, now);
    }

    fn publish_status(&self, running: bool) {
        let status = Status {
            cache: self.cache().clone(),
            state: self.session.state(),
            connected: self.conn.is_some(),
            version: self.session.version(),
            session_id: self.session.session_id(),
            serial: self.session.serial(),
            synced_at: self.session.synced_at(),
            last_commit: self.last_commit,
            expires_at: self.expires_at(),
            vrps: self.published.clone(),
            vrps_ipv4: self.counts.0,
            vrps_ipv6: self.counts.1,
            failures: self.failures,
            last_error: self.last_error.as_ref().map(|(_, text)| text.clone()),
            last_error_at: self.last_error.as_ref().map(|(at, _)| *at),
            running,
        };
        *lock(&self.status) = status;
    }
}

/// Connect to `cache` within `timeout`, trying each of its addresses.
fn open(cache: &Cache, timeout: Duration) -> io::Result<TcpStream> {
    let deadline = Instant::now().checked_add(timeout);
    let mut last = io::Error::new(ErrorKind::NotFound, "the name has no address");
    for addr in (cache.host.as_str(), cache.port).to_socket_addrs()? {
        let left = match deadline {
            Some(deadline) => deadline.saturating_duration_since(Instant::now()),
            None => timeout,
        };
        if left.is_zero() {
            return Err(io::Error::new(ErrorKind::TimedOut, "connection timed out"));
        }
        match TcpStream::connect_timeout(&addr, left) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// IPv4 and IPv6 VRPs in `vrps`.
fn count(vrps: &VrpSet) -> (usize, usize) {
    vrps.iter()
        .fold((0, 0), |(v4, v6), vrp| match vrp.prefix() {
            Prefix::V4 { .. } => (v4 + 1, v6),
            Prefix::V6 { .. } => (v4, v6 + 1),
        })
}

fn field(key: &'static str, value: impl fmt::Display) -> (&'static str, String) {
    (key, value.to_string())
}

/// Append ` key=value` to `text` as the log line has it: the value quoted
/// and escaped where it needs to be. Text from the cache, an Error
/// Report's say, may hold anything UTF-8 allows (RFC 8210 §5.11), a
/// newline included; [`Status::last_error`] keeps it on one line, as the
/// log does.
fn push_field(text: &mut String, key: &str, value: &str) {
    text.push(' ');
    text.push_str(key);
    text.push('=');
    bgpfc_log::push_value(text, value);
}

/// A duration for the log: `1.5s`, `250ms`.
struct Millis(Duration);

impl fmt::Display for Millis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = self.0.as_millis();
        if ms < 1_000 {
            write!(f, "{ms}ms")
        } else {
            write!(f, "{}.{}s", ms / 1_000, ms % 1_000 / 100)
        }
    }
}
