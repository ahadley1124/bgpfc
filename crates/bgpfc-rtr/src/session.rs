//! The router's side of an RTR session with one cache: a pure state
//! machine, `(event, now) -> actions`, in the style of `bgpfc-fsm`.
//!
//! [`Session::step`] takes an [`Event`] and the current time and returns
//! the [`Action`]s to carry out, in order. It never reads the clock and
//! never touches a socket. The I/O shell, the RTR client thread of
//! `bgpfcd`, owns the transport connection and a [`Framer`], and loops:
//!
//! 1. Wait until the socket is readable or [`Session::next_deadline`]
//!    passes. On a timeout, call `step(Event::Tick, now)`.
//! 2. Feed what was read to the framer and hand each PDU it gives out to
//!    `step(Event::Pdu(pdu), now)`. A framer error goes in as
//!    [`Event::DecodeError`] with [`Framer::erroneous_pdu`]. End of stream
//!    or a transport error is [`Event::Disconnected`].
//! 3. Carry out the actions of each step before taking the next PDU from
//!    the framer: [`Action::Connect`] opens a connection and is answered
//!    with [`Event::Connected`] or [`Event::Disconnected`];
//!    [`Action::Negotiated`] is [`Framer::set_version`]; [`Action::Close`]
//!    closes the connection and drops its framer with whatever it still
//!    holds; [`Action::Commit`] goes to the RIB through a
//!    [`ValidationSink`](bgpfc_rpki::ValidationSink), see
//!    [`Commit::into_change`].
//!
//! After a failure the session reconnects when the cache's Retry Interval
//! has run out (RFC 8210 §6), unless the shell paces reconnects itself
//! with [`Session::set_retry_delay`].
//!
//! # What the RIB sees
//!
//! Nothing but whole data sets (issue #58). The PDUs of a reply are
//! staged apart from the committed set; only End of Data commits them,
//! as one new [`VrpSet`], together with the [`AffectedPrefixes`] that
//! must be validated again (issue #59): the diff of the old and new sets
//! for a full reload, the changed prefixes for an incremental update. A
//! reply that fails half-way, for whatever reason, is dropped whole.
//!
//! # Stale data
//!
//! When the cache cannot be reached, or has no data, the session keeps
//! serving the last committed set, and says so at warning level on every
//! failed attempt, until the Expire Interval of RFC 8210 §6 runs out
//! (issue #57). Then it commits an empty set, so that every route is
//! `NotFound`, and logs at error level. The operator's
//! [`Config::max_expire`] can shorten that time, never lengthen it past
//! the cache's Expire Interval or the RFC's two days.
//!
//! # One cache
//!
//! A session talks to one cache. RFC 8210 §8.3 and §8.4 say a router
//! SHOULD try more-preferred, or other, caches after a Cache Reset or a
//! No Data Available; with a single configured cache, this session does
//! what the RFC requires when there are none: a Reset Query after a
//! Cache Reset, and periodic Reset Queries while there is no data.
//!
//! Implements: RFC 8210 §4 (Serial Notify is a hint; the router's
//! serial is the one in End of Data), §5.1 (a Session ID mismatch drops
//! the session and flushes the data), §5.2 (Serial Notify), §5.3 (Serial
//! Query), §5.4 (Reset Query), §5.5 (Cache Response; a reply to a Reset
//! Query only announces), §5.6, §5.7 (Duplicate Announcement Received),
//! §5.8 (End of Data matches its Cache Response), §5.9 (Cache Reset),
//! §5.10 (Router Keys accepted, not used), §5.11 (no Error Report about
//! an Error Report), §6 (Refresh, Retry and Expire), §7 (version
//! negotiation and downgrade), §8.1–§8.4 (the protocol sequences), §10
//! (keep the data while the cache is away), §12 (fatal errors drop the
//! session; codes 6 and 7);
//! RFC 6810 §6.1 (poll at least hourly in version 0), §8 (version 0 data
//! is deleted after twice the polling period).
//!
//! [`Framer`]: crate::Framer
//! [`Framer::erroneous_pdu`]: crate::Framer::erroneous_pdu
//! [`Framer::set_version`]: crate::Framer::set_version

mod staging;
#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_log::{Field, Level};
use bgpfc_rpki::{AffectedPrefixes, ValidationChange, Vrp, VrpSet};

use crate::error::{ErrorCode, RtrError};
use crate::pdu::{ErrorReport, Intervals, Pdu, Version};
use staging::Staging;

/// Settings of a [`Session`] that come from the operator rather than from
/// the cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// The protocol version to offer first (RFC 8210 §7): version 1,
    /// unless the operator pins version 0 for an old cache.
    pub version: Version,
    /// The longest the router keeps using data it cannot refresh
    /// (issue #57). The cache's Expire Interval applies when it is
    /// shorter: RFC 8210 §6 says "The router MUST NOT retain the data past
    /// the time indicated by this parameter". [`Session::new`] clamps the
    /// value to [`Config::MIN_EXPIRE`]`..=`[`Config::MAX_EXPIRE`], the
    /// range §6 allows the cache. A value below the cache's Refresh
    /// Interval lets the data lapse between two polls, and is logged.
    pub max_expire: Duration,
    /// How long to wait for the transport to connect, for the cache to
    /// start answering a query, and between two PDUs of an answer. A
    /// Serial Notify is part of no answer and does not restart it.
    /// RFC 8210 sets no such limit, but without one a cache that accepts a
    /// query and never answers would stall the session until the data
    /// expired. [`Session::new`] raises it to at least one second.
    pub response_timeout: Duration,
}

/// The longest time between two queries in a version 0 session:
/// RFC 6810 §6.1, "no less frequently than once an hour".
const VERSION_0_POLL: Duration = Duration::from_secs(3_600);

impl Config {
    /// The shortest Expire Interval RFC 8210 §6 allows: "Minimum allowed
    /// value: 600 seconds (10 minutes)".
    pub const MIN_EXPIRE: Duration = Duration::from_secs(600);

    /// The longest Expire Interval RFC 8210 §6 allows: "Maximum allowed
    /// value: 172800 seconds (2 days)".
    pub const MAX_EXPIRE: Duration = Duration::from_hours(48);

    /// The default [`Config::response_timeout`]. No RFC gives one. A
    /// minute leaves a busy cache time to start answering, and since the
    /// timer restarts with every PDU of the answer, a full load over a slow
    /// link does not trip it.
    pub const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
}

impl Default for Config {
    /// Version 1, the cache's Expire Interval up to the RFC maximum, and
    /// the default response timeout.
    fn default() -> Config {
        Config {
            version: Version::V1,
            max_expire: Config::MAX_EXPIRE,
            response_timeout: Config::DEFAULT_RESPONSE_TIMEOUT,
        }
    }
}

/// What happened, as the I/O shell reports it to [`Session::step`].
///
/// Every step first runs the timers that are due at `now`, so
/// [`Event::Tick`] is all the shell sends when only time has passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Time passed; only the timers run.
    Tick,
    /// The transport connection to the cache is up.
    Connected,
    /// A PDU from the cache, as [`Framer::next_pdu`](crate::Framer::next_pdu)
    /// handed it out.
    Pdu(Pdu),
    /// The framer failed on the cache's byte stream. Every such error is
    /// fatal (RFC 8210 §12): the session sends an Error Report if it may,
    /// and drops the connection.
    DecodeError {
        /// The error.
        error: RtrError,
        /// [`Framer::erroneous_pdu`](crate::Framer::erroneous_pdu): the
        /// octets for the Error Report.
        erroneous_pdu: Vec<u8>,
    },
    /// The transport connection closed or failed, or an attempt to open
    /// one failed.
    Disconnected,
}

/// What the I/O shell must do, in the order given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Open a transport connection to the cache, then report
    /// [`Event::Connected`] or [`Event::Disconnected`].
    Connect,
    /// Write this PDU to the cache.
    Send(Pdu),
    /// Close the transport connection and drop its framer. The session
    /// already counts as disconnected; no [`Event::Disconnected`] is
    /// needed, and PDUs still buffered from that connection are ignored.
    Close,
    /// The protocol version of this transport connection is settled
    /// (RFC 8210 §7): call [`Framer::set_version`](crate::Framer::set_version),
    /// so that a PDU of any other version is Unexpected Protocol Version.
    Negotiated(Version),
    /// From now on the session speaks this lower protocol version to the
    /// cache (RFC 8210 §7). Informational: the session sends its queries
    /// in the right version by itself.
    Downgrade(Version),
    /// Use this data for validation from now on.
    Commit(Commit),
    /// Write this line to the log.
    Log(LogLine),
}

/// A complete VRP set to validate with from now on, and the routes to
/// validate again: the payload of a
/// [`ValidationChange`].
///
/// The first commit of a session affects every route, since it replaces
/// whatever source the RIB used before it ([`bgpfc_rpki::NullSource`]
/// while the RTR client has no data). Later commits hold the routes that
/// the change between the two sets can affect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    /// The new VRP set.
    pub vrps: Arc<VrpSet>,
    /// The routes whose validation state may differ from the previous
    /// set's.
    pub affected: AffectedPrefixes,
}

impl Commit {
    /// The change to publish through a
    /// [`ValidationSink`](bgpfc_rpki::ValidationSink).
    #[must_use]
    pub fn into_change(self) -> ValidationChange {
        ValidationChange {
            source: self.vrps,
            affected: self.affected,
        }
    }
}

impl From<Commit> for ValidationChange {
    fn from(commit: Commit) -> ValidationChange {
        commit.into_change()
    }
}

/// A log line the session wants written: a level, a fixed message and
/// `key=value` fields, as `bgpfc_log` writes them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    /// The level.
    pub level: Level,
    /// The message.
    pub message: &'static str,
    /// The fields, values already formatted.
    pub fields: Vec<(&'static str, String)>,
}

impl LogLine {
    /// Write the line with [`bgpfc_log::log`], `context` (the cache's
    /// address, say) before the line's own fields.
    pub fn write(&self, context: &[Field<'_>]) {
        let fields: Vec<Field<'_>> = context
            .iter()
            .copied()
            .chain(
                self.fields
                    .iter()
                    .map(|(key, value)| (*key, value as &dyn fmt::Display)),
            )
            .collect();
        bgpfc_log::log(self.level, self.message, &fields);
    }
}

/// Where a [`Session`] stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// No transport connection. [`Action::Connect`] follows when the
    /// Retry Interval has run out.
    Disconnected,
    /// [`Action::Connect`] was given; waiting for the transport.
    Connecting,
    /// A Reset Query or Serial Query is out; waiting for the cache to
    /// answer.
    Querying,
    /// The Cache Response arrived; collecting the payload PDUs until End
    /// of Data.
    Receiving,
    /// Connected, with no query out: waiting for the Refresh Interval or a
    /// Serial Notify, or, after No Data Available, for the Retry Interval.
    Idle,
}

impl State {
    /// The state's name, as logs print it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            State::Disconnected => "disconnected",
            State::Connecting => "connecting",
            State::Querying => "querying",
            State::Receiving => "receiving",
            State::Idle => "idle",
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The Session ID and Serial Number the committed data corresponds to:
/// what a Serial Query asks from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Position {
    session_id: u16,
    serial: u32,
}

/// The query that is out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Query {
    /// A Reset Query.
    Reset,
    /// A Serial Query from `position`. `stale` once the data it would
    /// update has expired.
    Serial { position: Position, stale: bool },
}

/// A reply being received.
#[derive(Clone, Debug)]
struct Reply {
    /// The Session ID of its Cache Response.
    session_id: u16,
    /// The payload so far.
    staging: Staging,
}

/// [`State`] with the data each state carries.
#[derive(Clone, Debug)]
enum Phase {
    Disconnected,
    Connecting,
    Querying(Query),
    Receiving(Reply),
    Idle,
}

/// The router's side of an RTR session with one cache (RFC 8210 §8).
///
/// It outlives transport connections: the committed data, the Session ID
/// and Serial Number it corresponds to, the timing intervals and the
/// protocol version carry over from one connection to the next.
#[derive(Clone, Debug)]
pub struct Session {
    config: Config,
    phase: Phase,
    /// When the current phase's timer fires: connect, give up connecting
    /// or waiting for an answer, or send the next query.
    deadline: Option<Instant>,
    /// The protocol version the session speaks to the cache. It only goes
    /// down, by RFC 8210 §7 negotiation, except when a cache refuses
    /// version 0 (see [`Session::negotiate_report`]).
    version: Version,
    /// The version settled on the current transport connection.
    negotiated: Option<Version>,
    /// The Session ID the cache gave on the current transport connection.
    connection_session_id: Option<u16>,
    /// Where the committed data stands, while a Serial Query may continue
    /// from it. `Some` implies `committed` is `Some`.
    position: Option<Position>,
    /// The data the RIB validates with, as last committed.
    committed: Option<Arc<VrpSet>>,
    /// The timing parameters in force (RFC 8210 §6).
    intervals: Intervals,
    /// When the committed data expires (RFC 8210 §6).
    expire_at: Option<Instant>,
    /// When the last End of Data arrived.
    synced_at: Option<Instant>,
    /// When the last query went out.
    queried_at: Option<Instant>,
    /// The serial of a Serial Notify that arrived while a query was out.
    notified: Option<u32>,
    /// The shell's delay before reconnecting after a failure, in place of
    /// the Retry Interval (see [`Session::set_retry_delay`]).
    retry_delay: Option<Duration>,
}

impl Session {
    /// A session whose first step at or after `connect_at` returns
    /// [`Action::Connect`]. That is usually the current time; a shell that
    /// moves to another cache after a back-off passes the time it means to
    /// connect.
    #[must_use]
    pub fn new(config: Config, connect_at: Instant) -> Session {
        let config = Config {
            max_expire: config
                .max_expire
                .clamp(Config::MIN_EXPIRE, Config::MAX_EXPIRE),
            response_timeout: config.response_timeout.max(Duration::from_secs(1)),
            ..config
        };
        Session {
            version: config.version,
            config,
            phase: Phase::Disconnected,
            deadline: Some(connect_at),
            negotiated: None,
            connection_session_id: None,
            position: None,
            committed: None,
            // RFC 8210 §6: "If the router has never issued a successful
            // query against a particular cache, it SHOULD retry
            // periodically using the default Retry Interval".
            intervals: Intervals::DEFAULT,
            expire_at: None,
            synced_at: None,
            queried_at: None,
            notified: None,
            retry_delay: None,
        }
    }

    /// Wait `delay` after a failure before the next [`Action::Connect`],
    /// in place of the Retry Interval; `None`, the default, goes back to
    /// the Retry Interval (RFC 8210 §6).
    ///
    /// This is for an I/O shell that paces its reconnects itself, with a
    /// back-off, say. It sets the delay before each step, so that
    /// [`Session::next_deadline`] and the `retry_in` of the session's log
    /// lines follow its schedule. A failure the session has already
    /// handled keeps the time it got.
    /// Queries on an open connection, such as the periodic Reset Queries
    /// after No Data Available (§8.4), still wait the Retry Interval.
    pub fn set_retry_delay(&mut self, delay: Option<Duration>) {
        self.retry_delay = delay;
    }

    /// The configuration, as clamped by [`Session::new`].
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Where the session stands.
    #[must_use]
    pub const fn state(&self) -> State {
        match self.phase {
            Phase::Disconnected => State::Disconnected,
            Phase::Connecting => State::Connecting,
            Phase::Querying(_) => State::Querying,
            Phase::Receiving(_) => State::Receiving,
            Phase::Idle => State::Idle,
        }
    }

    /// The protocol version the session speaks to the cache.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The version settled on the current transport connection, once the
    /// cache has answered (RFC 8210 §7).
    #[must_use]
    pub const fn negotiated(&self) -> Option<Version> {
        self.negotiated
    }

    /// The Session ID the committed data came with, while the next query
    /// can be a Serial Query.
    #[must_use]
    pub fn session_id(&self) -> Option<u16> {
        self.position.map(|p| p.session_id)
    }

    /// The Serial Number of the committed data, while the next query can
    /// be a Serial Query.
    #[must_use]
    pub fn serial(&self) -> Option<u32> {
        self.position.map(|p| p.serial)
    }

    /// The last committed VRP set; `None` before the first commit.
    #[must_use]
    pub const fn vrps(&self) -> Option<&Arc<VrpSet>> {
        self.committed.as_ref()
    }

    /// The timing intervals in force (RFC 8210 §6): the RFC defaults until
    /// a version 1 End of Data carries others, and again after a version 0
    /// one. Each Refresh and Retry Interval is the last one in its §6
    /// range; the Expire Interval is the last one the cache sent, whatever
    /// its value, since the router never keeps data past it.
    #[must_use]
    pub const fn intervals(&self) -> Intervals {
        self.intervals
    }

    /// When the committed data expires, if there is any.
    #[must_use]
    pub const fn expires_at(&self) -> Option<Instant> {
        self.expire_at
    }

    /// When the session was last in sync with the cache: the time of the
    /// last End of Data.
    #[must_use]
    pub const fn synced_at(&self) -> Option<Instant> {
        self.synced_at
    }

    /// The earliest time at which a timer fires: how long the shell may
    /// wait for the socket before calling [`Session::step`] with
    /// [`Event::Tick`].
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        match (self.deadline, self.expire_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Apply one event at time `now`: first the timers due by `now`, then
    /// the event, then any timer the event made due by `now`, such as the
    /// expiry of data whose End of Data gave an Expire Interval of 0. So
    /// after a step, [`Session::next_deadline`] is later than `now`
    /// unless a delay of zero was set.
    pub fn step(&mut self, event: Event, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        self.run_timers(now, &mut out);
        match event {
            Event::Tick => {}
            Event::Connected => self.on_connected(now, &mut out),
            Event::Disconnected => self.on_disconnected(now, &mut out),
            Event::Pdu(pdu) => self.on_pdu(&pdu, now, &mut out),
            Event::DecodeError {
                error,
                erroneous_pdu,
            } => self.on_decode_error(&error, &erroneous_pdu, now, &mut out),
        }
        self.run_timers(now, &mut out);
        out
    }

    // ------------------------------------------------------------ timers

    fn run_timers(&mut self, now: Instant, out: &mut Vec<Action>) {
        // First the data's expiry: whatever else is due, data past its
        // Expire Interval is not used again.
        if self.expire_at.is_some_and(|at| at <= now) {
            self.expire(now, out);
        }
        if self.deadline.is_some_and(|at| at <= now) {
            self.deadline = None;
            match self.phase {
                Phase::Disconnected => self.connect(now, out),
                Phase::Connecting => {
                    self.log_stale(Level::Warn, "rtr cache connection timed out", now, out);
                    out.push(Action::Close);
                    self.disconnect(now, false);
                }
                Phase::Querying(_) | Phase::Receiving(_) => {
                    // The query failed (RFC 8210 §6 Retry Interval). The
                    // data and its serial are intact: the next connection
                    // goes on with a Serial Query (§8.1).
                    self.log_stale(Level::Warn, "rtr cache stopped answering", now, out);
                    out.push(Action::Close);
                    self.disconnect(now, false);
                }
                Phase::Idle => self.send_query(now, out),
            }
        }
    }

    /// The committed data has reached its Expire Interval.
    fn expire(&mut self, now: Instant, out: &mut Vec<Action>) {
        let mut fields = vec![field(
            "vrps",
            self.committed.as_ref().map_or(0, |c| c.len()),
        )];
        if let Some(synced) = self.synced_at {
            fields.push(field("age", Secs(now.saturating_duration_since(synced))));
        }
        // RFC 8210 §6 Expire Interval: "The router MUST NOT retain the data
        // past the time indicated by this parameter." RFC 6810 §8: "A
        // client SHOULD delete the data from a cache when it has been
        // unable to refresh from that cache for a configurable timer
        // value."
        log(
            out,
            Level::Error,
            "rtr data expired without a successful query; discarding it, every route is now not-found",
            fields,
        );
        self.flush(out);
        // A Serial reply under way updates data that is gone now.
        match &mut self.phase {
            Phase::Querying(Query::Serial { stale, .. }) => *stale = true,
            Phase::Receiving(reply) if matches!(reply.staging, Staging::Delta(_)) => {
                reply.staging = Staging::Discard;
            }
            _ => {}
        }
    }

    // ------------------------------------------------------- transport

    fn connect(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.phase = Phase::Connecting;
        self.deadline = after(now, self.config.response_timeout);
        out.push(Action::Connect);
    }

    fn on_connected(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.is_connected() {
            // The shell replaced the connection; what the old one was in
            // the middle of is lost with it.
            log(
                out,
                Level::Warn,
                "rtr cache connection replaced",
                vec![field("state", self.state())],
            );
        }
        self.negotiated = None;
        self.connection_session_id = None;
        log(
            out,
            Level::Info,
            "rtr cache connected",
            vec![field("version", self.version)],
        );
        // RFC 8210 §7: "A router MUST start each transport connection by
        // issuing either a Reset Query or a Serial Query."
        self.send_query(now, out);
    }

    fn on_disconnected(&mut self, now: Instant, out: &mut Vec<Action>) {
        let message = match self.phase {
            Phase::Disconnected => return,
            Phase::Connecting => "rtr cache connection failed",
            _ => "rtr cache connection lost",
        };
        self.log_stale(Level::Warn, message, now, out);
        // A broken session keeps its serial: RFC 8210 §8.1 has the router
        // reconnect with a Serial Query when it "has significant unexpired
        // data from a broken session with the same cache".
        self.disconnect(now, false);
    }

    /// Enter Disconnected and start the Retry Interval. `forget` drops the
    /// serial, so that the next connection starts with a Reset Query.
    fn disconnect(&mut self, now: Instant, forget: bool) {
        self.phase = Phase::Disconnected;
        self.negotiated = None;
        self.connection_session_id = None;
        self.notified = None;
        if forget {
            self.position = None;
        }
        // RFC 8210 §6 Retry Interval: "Countdown for this timer starts upon
        // failure of the query and restarts after each subsequent failure
        // until a query succeeds." Or the shell's own delay.
        self.deadline = after(now, self.reconnect_delay());
    }

    /// How long to wait after a failure before connecting again: the
    /// shell's delay, or the Retry Interval (RFC 8210 §6).
    fn reconnect_delay(&self) -> Duration {
        self.retry_delay
            .unwrap_or_else(|| secs(self.intervals.retry))
    }

    /// Close the connection and open a new one at once: RFC 8210 §6 Retry
    /// Interval, "if the router needs to downgrade to a lower protocol
    /// version number, it MAY send the first Serial Query or Reset Query
    /// immediately."
    fn reconnect_now(&mut self, now: Instant, out: &mut Vec<Action>) {
        out.push(Action::Close);
        self.disconnect(now, false);
        self.connect(now, out);
    }

    const fn is_connected(&self) -> bool {
        matches!(
            self.phase,
            Phase::Querying(_) | Phase::Receiving(_) | Phase::Idle
        )
    }

    // ----------------------------------------------------------- queries

    fn send_query(&mut self, now: Instant, out: &mut Vec<Action>) {
        // RFC 8210 §8.1: a Serial Query "if the router has significant
        // unexpired data from a broken session with the same cache and
        // remembers the Session ID of that session ... In all other cases,
        // the router lacks the necessary data for fast resynchronization
        // and therefore MUST fall back to a Reset Query."
        let version = self.version;
        let (query, pdu) = match self.position {
            Some(position) => (
                Query::Serial {
                    position,
                    stale: false,
                },
                Pdu::SerialQuery {
                    version,
                    session_id: position.session_id,
                    serial: position.serial,
                },
            ),
            None => (Query::Reset, Pdu::ResetQuery { version }),
        };
        log(
            out,
            Level::Debug,
            "rtr query sent",
            vec![field("query", pdu.pdu_type())],
        );
        out.push(Action::Send(pdu));
        self.phase = Phase::Querying(query);
        self.notified = None;
        self.queried_at = Some(now);
        self.deadline = after(now, self.config.response_timeout);
    }

    // -------------------------------------------------------------- PDUs

    fn on_pdu(&mut self, pdu: &Pdu, now: Instant, out: &mut Vec<Action>) {
        if !self.is_connected() {
            // Left over from a connection the session has let go of.
            return;
        }
        match self.negotiated {
            None => {
                if !self.negotiate(pdu, now, out) {
                    return;
                }
            }
            Some(negotiated) if negotiated != pdu.version() => {
                // RFC 8210 §7: "If either party receives a PDU for a
                // different Protocol Version once the above negotiation
                // completes, that party MUST drop the session; unless the
                // PDU containing the unexpected Protocol Version was itself
                // an Error Report PDU, the party dropping the session SHOULD
                // send an Error Report with an error code of 8".
                let text = format!(
                    "{} PDU of protocol version {} in a version {negotiated} session",
                    pdu.pdu_type(),
                    pdu.version()
                );
                self.protocol_error(ErrorCode::UnexpectedProtocolVersion, pdu, &text, now, out);
                return;
            }
            Some(_) => {}
        }
        match pdu {
            Pdu::ErrorReport(report) => self.on_error_report(report, now, out),
            Pdu::SerialNotify {
                session_id, serial, ..
            } => self.on_serial_notify(*session_id, *serial, pdu, now, out),
            Pdu::CacheResponse { session_id, .. } if matches!(self.phase, Phase::Querying(_)) => {
                self.on_cache_response(*session_id, pdu, now, out);
            }
            Pdu::CacheReset { .. }
                if matches!(self.phase, Phase::Querying(Query::Serial { .. })) =>
            {
                self.on_cache_reset(now, out);
            }
            Pdu::Prefix { announce, vrp, .. } if matches!(self.phase, Phase::Receiving(_)) => {
                self.on_prefix(*announce, *vrp, pdu, now, out);
            }
            // RFC 8210 §5.10: Router Keys serve path validation (RFC 8205),
            // which is out of scope. They are part of a reply like any
            // payload PDU, and are accepted and dropped.
            Pdu::RouterKey(_) if matches!(self.phase, Phase::Receiving(_)) => {
                self.answer_goes_on(now);
            }
            Pdu::EndOfData {
                session_id,
                serial,
                intervals,
            } if matches!(self.phase, Phase::Receiving(_)) => {
                self.on_end_of_data(*session_id, *serial, *intervals, pdu, now, out);
            }
            _ => self.unexpected(pdu, now, out),
        }
    }

    /// RFC 8210 §7 for a PDU that arrives before the connection's version
    /// is settled. Returns whether to go on and handle the PDU.
    fn negotiate(&mut self, pdu: &Pdu, now: Instant, out: &mut Vec<Action>) -> bool {
        if let Pdu::SerialNotify { .. } = pdu {
            // RFC 8210 §7: "The router MUST ignore any Serial Notify PDUs
            // it might receive from the cache during this initial startup
            // period, regardless of the Protocol Version field" (also
            // §5.2).
            return false;
        }
        if let Pdu::ErrorReport(report) = pdu {
            self.negotiate_report(report, now, out);
            return false;
        }
        let version = pdu.version();
        match version.cmp(&self.version) {
            Ordering::Equal => {}
            Ordering::Less => {
                // RFC 8210 §7: "The cache may reply with a version 0
                // response. In this case, the router MUST either downgrade
                // to version 0 or terminate the connection."
                self.downgrade(version, out);
                if let Phase::Querying(Query::Serial { .. }) = self.phase {
                    // The query's Session ID and Serial belong to a session
                    // of the other version, and §5.1 says "routers MUST
                    // treat sessions with different Protocol Version fields
                    // as separate sessions": nothing in this reply can be
                    // applied to the data. Start again with a Reset Query
                    // in the new version.
                    self.reconnect_now(now, out);
                    return false;
                }
            }
            Ordering::Greater => {
                // The query offered a lower version, which the cache had to
                // accept or refuse with an Error Report (RFC 8210 §7), not
                // answer in its own. The version differs from the one the
                // router settled on for the connection: code 8.
                let text = format!(
                    "{} PDU of protocol version {version} in reply to a version {} query",
                    pdu.pdu_type(),
                    self.version
                );
                self.protocol_error(ErrorCode::UnexpectedProtocolVersion, pdu, &text, now, out);
                return false;
            }
        }
        self.settle(version, out);
        true
    }

    fn settle(&mut self, version: Version, out: &mut Vec<Action>) {
        self.negotiated = Some(version);
        out.push(Action::Negotiated(version));
    }

    /// An Error Report in reply to the first query of a connection
    /// (RFC 8210 §7).
    fn negotiate_report(&mut self, report: &ErrorReport, now: Instant, out: &mut Vec<Action>) {
        let theirs = report.version();
        match (report.code(), theirs.cmp(&self.version)) {
            // RFC 8210 §12: No Data Available is not fatal. In version 0 it
            // is "a version 0 response", which §7 has the router downgrade
            // for.
            (ErrorCode::NoDataAvailable, Ordering::Less | Ordering::Equal) => {
                self.downgrade(theirs, out);
                self.settle(theirs, out);
                self.no_data(report, now, out);
            }
            // RFC 8210 §7: "The cache may terminate the connection, perhaps
            // with a version 0 Error Report PDU. In this case, the router
            // MAY retry the connection using protocol version 0."
            (_, Ordering::Less) => {
                Self::log_report(report, out);
                self.downgrade(theirs, out);
                self.reconnect_now(now, out);
            }
            // The cache does not speak the version offered. Try the one
            // below it, as for a version 0 Error Report.
            (ErrorCode::UnsupportedProtocolVersion, Ordering::Equal)
                if self.version == Version::V1 =>
            {
                Self::log_report(report, out);
                self.downgrade(Version::V0, out);
                self.reconnect_now(now, out);
            }
            // RFC 8210 §7: a cache that speaks version 1 may answer a
            // version 0 query by sending "a version 1 Error Report PDU with
            // Error Code 4 ("Unsupported Protocol Version") and terminate
            // the connection". It no longer speaks version 0, so the next
            // connection offers the version it does, within the configured
            // one: a new session, not an upgrade within one.
            (ErrorCode::UnsupportedProtocolVersion, Ordering::Greater)
                if theirs <= self.config.version =>
            {
                Self::log_report(report, out);
                log(
                    out,
                    Level::Warn,
                    "rtr cache refuses this protocol version; the next connection offers its own",
                    vec![field("from", self.version), field("to", theirs)],
                );
                self.version = theirs;
                out.push(Action::Close);
                self.disconnect(now, true);
            }
            // RFC 8210 §12: every other code is fatal.
            _ => {
                Self::log_report(report, out);
                out.push(Action::Close);
                self.disconnect(now, true);
            }
        }
    }

    /// Speak `to` from now on, if it is lower than the current version.
    fn downgrade(&mut self, to: Version, out: &mut Vec<Action>) {
        if to >= self.version {
            return;
        }
        log(
            out,
            Level::Warn,
            "rtr protocol version downgraded",
            vec![field("from", self.version), field("to", to)],
        );
        self.version = to;
        // RFC 8210 §5.1: Session IDs and Serial Numbers of different
        // versions are not commensurate. The data stays until a full load
        // in the new version replaces it.
        self.position = None;
        out.push(Action::Downgrade(to));
    }

    fn on_error_report(&mut self, report: &ErrorReport, now: Instant, out: &mut Vec<Action>) {
        if report.code() == ErrorCode::NoDataAvailable {
            self.no_data(report, now, out);
        } else {
            // RFC 8210 §12: "Errors which are considered fatal MUST cause
            // the session to be dropped." No Error Report goes back: §5.11
            // "An Error Report PDU MUST NOT be sent for an Error Report
            // PDU."
            Self::log_report(report, out);
            out.push(Action::Close);
            self.disconnect(now, true);
        }
    }

    /// The cache has No Data Available (RFC 8210 §8.4, §12 code 2).
    fn no_data(&mut self, report: &ErrorReport, now: Instant, out: &mut Vec<Action>) {
        // RFC 8210 §8.4: "If no other caches are available, the router MUST
        // issue periodic Reset Queries until it gets a new usable load from
        // the cache." The period is the Retry Interval (§6), and the data
        // held stays in use until it expires.
        self.position = None;
        self.notified = None;
        self.phase = Phase::Idle;
        self.deadline = after(now, secs(self.intervals.retry));
        let mut fields = self.stale_fields(now);
        fields.push(field("text", report.text()));
        log(
            out,
            Level::Warn,
            "rtr cache has no data available; serving the last data until it expires",
            fields,
        );
    }

    fn on_serial_notify(
        &mut self,
        session_id: u16,
        serial: u32,
        pdu: &Pdu,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if let Some(current) = self.connection_session_id
            && current != session_id
        {
            // RFC 8210 §5.2: the Session ID "reassures the router that the
            // Serial Numbers are commensurate"; a different one is a
            // mismatch (§5.1).
            self.session_mismatch(current, session_id, pdu, now, out);
            return;
        }
        match self.phase {
            Phase::Idle => {
                if self.position.is_some_and(|p| p.serial == serial) {
                    // The router has that serial already.
                    return;
                }
                // RFC 8210 §5.2: "the router MAY issue an immediate Serial
                // Query (Section 5.3) or Reset Query (Section 5.4) without
                // waiting for the Refresh Interval timer"; §8.2.
                self.send_query(now, out);
            }
            // RFC 8210 §4: the notify "is only a hint". A query is out
            // already; if its End of Data leaves the router short of this
            // serial, it asks again then.
            _ => self.notified = Some(serial),
        }
    }

    fn on_cache_response(
        &mut self,
        session_id: u16,
        pdu: &Pdu,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Phase::Querying(query) = self.phase else {
            return;
        };
        let staging = match query {
            Query::Serial { position, stale } => {
                // RFC 8210 §5.5: "In response to a Serial Query, the Session
                // ID being the same reassures the router that the Serial
                // Numbers are commensurate"; a different one is a mismatch
                // (§5.1).
                if session_id != position.session_id {
                    self.session_mismatch(position.session_id, session_id, pdu, now, out);
                    return;
                }
                if stale {
                    Staging::Discard
                } else {
                    Staging::Delta(HashMap::new())
                }
            }
            // RFC 8210 §5.5: "In response to a Reset Query, the new value of
            // the Session ID tells the router the instance of the cache
            // session for future confirmation."
            Query::Reset => Staging::Full(VrpSet::new()),
        };
        self.connection_session_id = Some(session_id);
        self.phase = Phase::Receiving(Reply {
            session_id,
            staging,
        });
        self.answer_goes_on(now);
    }

    /// The cache sent a PDU of its answer, and the next may take another
    /// [`Config::response_timeout`]. Only the answer's own PDUs restart the
    /// timer: a Serial Notify is part of none, and a cache that sends them
    /// and never answers still times out.
    fn answer_goes_on(&mut self, now: Instant) {
        self.deadline = after(now, self.config.response_timeout);
    }

    fn on_cache_reset(&mut self, now: Instant, out: &mut Vec<Action>) {
        // RFC 8210 §8.3: "If there are no more-preferred caches, it MUST
        // issue a Reset Query and get an entire new load from the cache."
        // The data in use stays until the new load replaces it (§10).
        log(
            out,
            Level::Info,
            "rtr cache cannot update incrementally; reloading",
            Vec::new(),
        );
        self.position = None;
        self.send_query(now, out);
    }

    fn on_prefix(
        &mut self,
        announce: bool,
        vrp: Vrp,
        pdu: &Pdu,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Phase::Receiving(reply) = &mut self.phase else {
            return;
        };
        match reply
            .staging
            .apply(announce, vrp, self.committed.as_deref())
        {
            Ok(()) => self.answer_goes_on(now),
            Err(rejected) => {
                // RFC 8210 §12: codes 6 and 7 are fatal, like code 0. The
                // reply is dropped whole and the data stays as it was; §5.1
                // says of such a discrepancy that "a router will detect the
                // error and reset the session", which the Reset Query of the
                // next connection does.
                let text = format!("{}: {vrp}", rejected.reason);
                self.protocol_error(rejected.code, pdu, &text, now, out);
            }
        }
    }

    fn on_end_of_data(
        &mut self,
        session_id: u16,
        serial: u32,
        intervals: Option<Intervals>,
        pdu: &Pdu,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Phase::Receiving(reply) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            return;
        };
        if session_id != reply.session_id {
            // RFC 8210 §5.8: "The Session ID and Protocol Version MUST be
            // the same as that of the corresponding Cache Response"; a
            // different Session ID is a mismatch (§5.1). The version was
            // checked against the negotiated one already.
            self.session_mismatch(reply.session_id, session_id, pdu, now, out);
            return;
        }
        match reply.staging {
            Staging::Discard => {
                // The data this reply updates expired while it was under
                // way. RFC 8210 §8.1: the Reset Query sequence is for a
                // router that "fears that it has otherwise lost its way".
                log(
                    out,
                    Level::Warn,
                    "rtr incremental update arrived after the data expired; reloading",
                    vec![field("serial", serial)],
                );
                self.position = None;
                self.send_query(now, out);
                return;
            }
            Staging::Full(set) => {
                // Issue #59: diff the old and new sets, so that only the
                // routes they disagree on are validated again. The first
                // set replaces whatever source the RIB had: every route.
                let affected = match &self.committed {
                    Some(old) => AffectedPrefixes::between(old, &set),
                    None => AffectedPrefixes::All,
                };
                if !affected.is_empty() {
                    self.commit(set, affected, out);
                }
            }
            Staging::Delta(changes) => {
                let base = self.committed.clone().unwrap_or_default();
                if let Some((set, affected)) = staging::apply_delta(&base, changes) {
                    self.commit(set, affected, out);
                }
            }
        }
        // RFC 8210 §4: "When the router has received all data records from
        // the cache, it sets its current Serial Number to that of the
        // Serial Number in the received End of Data PDU."
        self.position = Some(Position { session_id, serial });
        self.adopt_intervals(intervals, out);
        self.synced_at = Some(now);
        // RFC 8210 §6, for both Refresh and Expire: "Countdown for this
        // timer starts upon receipt of the containing End Of Data PDU."
        self.expire_at = after(now, self.expire_interval());
        self.deadline = match intervals {
            Some(_) => after(now, secs(self.intervals.refresh)),
            // RFC 6810 §6.1: "a router MUST send either a Serial Query or a
            // Reset Query no less frequently than once an hour", since "the
            // cache MAY not keep updates for little more than one hour".
            // Version 0 has no Refresh Interval to count from End of Data,
            // so the hour counts from the query this End of Data answers:
            // however long the reply took, the next query goes out within
            // the hour of the last, or at once if the hour has passed.
            None => after(self.queried_at.unwrap_or(now), VERSION_0_POLL).map(|at| at.max(now)),
        };
        log(
            out,
            Level::Info,
            "rtr in sync with the cache",
            vec![
                field("session_id", session_id),
                field("serial", serial),
                field("vrps", self.committed.as_ref().map_or(0, |c| c.len())),
                field("refresh", Secs(secs(self.intervals.refresh))),
                field("expire", Secs(self.expire_interval())),
            ],
        );
        if let Some(notified) = self.notified.take()
            && notified != serial
        {
            // A Serial Notify announced a serial this reply did not reach
            // (RFC 8210 §5.2).
            self.send_query(now, out);
        }
    }

    /// Take the timing parameters of an End of Data (RFC 8210 §6).
    fn adopt_intervals(&mut self, intervals: Option<Intervals>, out: &mut Vec<Action>) {
        match intervals {
            // Version 0 has no timing parameters: the RFC 8210 §6 defaults
            // apply. They agree with RFC 6810: a poll "no less frequently
            // than once an hour" (§6.1), which on_end_of_data counts from
            // the query, and data deleted after "twice the polling period"
            // (§8).
            None => self.intervals = Intervals::DEFAULT,
            Some(intervals) => {
                if !intervals.within_limits() {
                    // RFC 8210 §6 bounds each interval, and "Caches MUST set
                    // Expire Interval to a value larger than either Refresh
                    // Interval or Retry Interval."
                    log(
                        out,
                        Level::Warn,
                        "rtr cache sent timing intervals out of range; ignoring a refresh or retry out of range, honouring the expiry",
                        vec![
                            field("refresh", intervals.refresh),
                            field("retry", intervals.retry),
                            field("expire", intervals.expire),
                        ],
                    );
                }
                self.intervals = merge_intervals(self.intervals, intervals);
            }
        }
        if self.expire_interval() <= secs(self.intervals.refresh) {
            log(
                out,
                Level::Warn,
                "rtr data expires before the next poll; raise the configured expiry",
                vec![
                    field("refresh", Secs(secs(self.intervals.refresh))),
                    field("expire", Secs(self.expire_interval())),
                ],
            );
        }
    }

    /// The Expire Interval in force: the cache's, or the RFC default, cut
    /// to the configured maximum.
    fn expire_interval(&self) -> Duration {
        secs(self.intervals.expire).min(self.config.max_expire)
    }

    fn commit(&mut self, set: VrpSet, affected: AffectedPrefixes, out: &mut Vec<Action>) {
        let vrps = Arc::new(set);
        log(
            out,
            Level::Info,
            "rtr validation data committed",
            vec![
                field("vrps", vrps.len()),
                field("affected", AffectedCount(&affected)),
            ],
        );
        self.committed = Some(Arc::clone(&vrps));
        out.push(Action::Commit(Commit { vrps, affected }));
    }

    /// Drop every VRP learned from the cache: commit an empty set, against
    /// which RFC 6811 §2 finds every route `NotFound`.
    fn flush(&mut self, out: &mut Vec<Action>) {
        self.expire_at = None;
        self.position = None;
        if let Some(old) = self.committed.clone()
            && !old.is_empty()
        {
            let empty = VrpSet::new();
            let affected = AffectedPrefixes::between(&old, &empty);
            self.commit(empty, affected, out);
        }
    }

    // ------------------------------------------------------------ errors

    /// RFC 8210 §5.1: "If, at any time after the protocol version has been
    /// negotiated (Section 7), either the router or the cache finds that
    /// the value of the Session ID is not the same as the other's, the
    /// party which detects the mismatch MUST immediately terminate the
    /// session with an Error Report PDU with code 0 ("Corrupt Data"), and
    /// the router MUST flush all data learned from that cache."
    fn session_mismatch(
        &mut self,
        expected: u16,
        got: u16,
        pdu: &Pdu,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let text = format!("Session ID {got} where {expected} was expected");
        self.protocol_error(ErrorCode::CorruptData, pdu, &text, now, out);
        self.flush(out);
    }

    /// A PDU that fits no sequence of RFC 8210 §8 in the current state.
    /// RFC 8210 §12 has no code for that, so it is Corrupt Data: "corrupt
    /// in a manner not specified by another error code".
    fn unexpected(&mut self, pdu: &Pdu, now: Instant, out: &mut Vec<Action>) {
        let text = format!("unexpected {} PDU while {}", pdu.pdu_type(), self.state());
        self.protocol_error(ErrorCode::CorruptData, pdu, &text, now, out);
    }

    /// The router found `pdu` in error: report it, unless it is an Error
    /// Report, and drop the session.
    fn protocol_error(
        &mut self,
        code: ErrorCode,
        pdu: &Pdu,
        text: &str,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        log(
            out,
            Level::Error,
            "rtr protocol error; dropping the session",
            vec![field("code", code), field("error", text)],
        );
        // RFC 8210 §5.11: "An Error Report PDU MUST NOT be sent for an
        // Error Report PDU." For any other PDU, the canonical re-encoding
        // stands for the octets received: the decoder accepted them, and
        // they differ at most in reserved bits.
        if !matches!(pdu, Pdu::ErrorReport(_)) {
            let report = ErrorReport::new(self.report_version(), code, &pdu.encode(), text);
            out.push(Action::Send(Pdu::ErrorReport(report)));
        }
        // RFC 8210 §12: every code but No Data Available is fatal and
        // "MUST cause the session to be dropped". The next connection
        // starts with a Reset Query (§8.1): the router "fears that it has
        // otherwise lost its way".
        out.push(Action::Close);
        self.disconnect(now, true);
    }

    fn on_decode_error(
        &mut self,
        error: &RtrError,
        erroneous_pdu: &[u8],
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if !self.is_connected() {
            return;
        }
        let text = error.to_string();
        log(
            out,
            Level::Error,
            "rtr malformed PDU from the cache; dropping the session",
            vec![field("code", error.code()), field("error", &text)],
        );
        // RFC 8210 §5.11 and §7: no Error Report about an Error Report.
        if error.may_report() {
            let report =
                ErrorReport::new(self.report_version(), error.code(), erroneous_pdu, &text);
            out.push(Action::Send(Pdu::ErrorReport(report)));
        }
        // RFC 8210 §12: every error the decoder reports is fatal.
        out.push(Action::Close);
        self.disconnect(now, true);
    }

    /// The version of an Error Report the router sends: the connection's,
    /// or the one its query offered.
    fn report_version(&self) -> Version {
        self.negotiated.unwrap_or(self.version)
    }

    // ----------------------------------------------------------- logging

    fn log_report(report: &ErrorReport, out: &mut Vec<Action>) {
        log(
            out,
            Level::Error,
            "rtr cache reported an error; dropping the session",
            vec![
                field("code", report.code()),
                field("version", report.version()),
                field("text", report.text()),
            ],
        );
    }

    /// Log a failure loudly, with what the router keeps serving and for
    /// how long (issue #57).
    fn log_stale(&self, level: Level, message: &'static str, now: Instant, out: &mut Vec<Action>) {
        let mut fields = self.stale_fields(now);
        fields.push(field("retry_in", Secs(self.reconnect_delay())));
        log(out, level, message, fields);
    }

    fn stale_fields(&self, now: Instant) -> Vec<(&'static str, String)> {
        let vrps = self.committed.as_ref().map_or(0, |c| c.len());
        let mut fields = vec![field("serving_vrps", vrps)];
        if let Some(at) = self.expire_at {
            fields.push(field("expires_in", Secs(at.saturating_duration_since(now))));
        }
        fields
    }
}

/// The timing parameters in force after a version 1 End of Data that
/// carried `new`, with `in_force` before it (RFC 8210 §6).
///
/// A Refresh or Retry Interval outside the range §6 allows the cache is
/// ignored, and the one in force stays: a cache that sends 0 or a week
/// does not get the router polling in a tight loop or not at all. The
/// Expire Interval is taken whatever its value, because "The router MUST
/// NOT retain the data past the time indicated by this parameter": one
/// below the 600-second minimum is the shorter time it says, and one above
/// the two-day maximum is cut by [`Config::max_expire`], which never
/// exceeds that maximum. So an End of Data out of range never lets the
/// router keep data longer than the cache said.
const fn merge_intervals(in_force: Intervals, new: Intervals) -> Intervals {
    Intervals {
        // RFC 8210 §6 Refresh Interval: "Minimum allowed value: 1 second",
        // "Maximum allowed value: 86400 seconds (1 day)".
        refresh: if matches!(new.refresh, 1..=86_400) {
            new.refresh
        } else {
            in_force.refresh
        },
        // RFC 8210 §6 Retry Interval: "Minimum allowed value: 1 second",
        // "Maximum allowed value: 7200 seconds (2 hours)".
        retry: if matches!(new.retry, 1..=7_200) {
            new.retry
        } else {
            in_force.retry
        },
        expire: new.expire,
    }
}

/// `now + d`, or no deadline at all if that is past what [`Instant`] can
/// hold.
fn after(now: Instant, d: Duration) -> Option<Instant> {
    now.checked_add(d)
}

/// An interval in seconds, as [`Intervals`] holds it.
fn secs(seconds: u32) -> Duration {
    Duration::from_secs(u64::from(seconds))
}

fn field(key: &'static str, value: impl fmt::Display) -> (&'static str, String) {
    (key, value.to_string())
}

fn log(
    out: &mut Vec<Action>,
    level: Level,
    message: &'static str,
    fields: Vec<(&'static str, String)>,
) {
    out.push(Action::Log(LogLine {
        level,
        message,
        fields,
    }));
}

/// A duration as whole seconds: `3600s`.
struct Secs(Duration);

impl fmt::Display for Secs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0.as_secs())
    }
}

/// How many prefixes a commit affects: `all`, or a count.
struct AffectedCount<'a>(&'a AffectedPrefixes);

impl fmt::Display for AffectedCount<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            AffectedPrefixes::All => f.write_str("all"),
            AffectedPrefixes::CoveredBy(prefixes) => write!(f, "{}", prefixes.len()),
        }
    }
}
