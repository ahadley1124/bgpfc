//! The RIB thread: the only owner of RIB state (AGENTS.md §3). It turns
//! peer messages into `bgpfc_rib::Rib` calls and delivers what comes out
//! as the RIB produces it: UPDATEs to peer threads, route changes to the
//! FIB thread in batches. Between messages it sleeps until the next RFC
//! 4271 §9.2.1.1 deadline and then releases the advertisements that were
//! held back; the pacing itself is `bgpfc_rib`'s. A peer over its RFC 4271
//! §6.7 prefix limit is told to end its session. Routes the RIB ignored
//! for a semantically incorrect next hop are logged (RFC 4271 §6.3), and
//! so is what a change of the validation source did to the routes' RFC
//! 6811 states, in one line per change, and what a change of the `rpki`
//! block's `enforcement` did to their use (RFC 6811 §5), in one line too,
//! as does a change of its `startup` (RFC 6811 §2), and what importing a
//! peer's routes again after its import policy changed did (RFC 4271 §3),
//! after which the peer is asked for the routes import policy dropped
//! earlier, if any, with ROUTE-REFRESH (RFC 2918 §4).
//!
//! Issue #59: "An operator needs to see that a prefix went Valid → Invalid
//! at a specific time." After the line of a change of the validation
//! source come the routes it moved among valid, invalid and not-found, a
//! line each: the first [`LOGGED`] at info, the rest the RIB lists at
//! debug. The thread also keeps the latest [`KEPT`] of them, with their
//! time, for `show rpki transitions` ([`RibQuery::Transitions`]). Moves
//! to and from `disabled`, validation being switched on or off, are only
//! counted, as is what the RIB does not list.
//!
//! Changes of the validation source arrive on the same channel, as
//! [`RibMsg::Validation`], and go the way an UPDATE goes (RFC 6811 §4):
//! the RIB validates the affected routes again, and what follows is
//! delivered like any other output. The RIB starts with no source (every
//! route `disabled`) and keeps it until a change says otherwise.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use bgpfc_fsm::Session;
use bgpfc_log::Level;
use bgpfc_rib::{
    FibChange, Output, PeerInfo, Reimport, Rejudged, Revalidation, Rib, RouteStatus, Sink,
    StartupChange, Transition,
};
use bgpfc_rpki::AffectedPrefixes;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::PeerKind;

use crate::coordinator::PeerTable;
use crate::messages::{
    FibMsg, Intervals, PAGE, PeerInput, Recorded, RibMsg, RibQuery, RibReply, RibSettings,
    RouteReport, TransitionsReport,
};
use crate::peer::SendError;

/// Start the RIB thread on `rib`, with the configured per-neighbor
/// settings.
pub(crate) fn spawn(
    rib: Rib,
    settings: RibSettings,
    rx: Receiver<RibMsg>,
    peers: PeerTable,
    fib: SyncSender<FibMsg>,
) {
    thread::Builder::new()
        .name("rib".to_owned())
        .spawn(move || run(rib, settings, &rx, &peers, &fib))
        .expect("spawning the rib thread");
}

fn run(
    mut rib: Rib,
    mut settings: RibSettings,
    rx: &Receiver<RibMsg>,
    peers: &PeerTable,
    fib: &SyncSender<FibMsg>,
) {
    let mut out = Deliver {
        peers,
        fib,
        changes: Vec::new(),
        open: false,
    };
    let mut transitions = Transitions::default();
    #[cfg(feature = "profiling")]
    let mut loads = crate::profiling::Loads::from_env();
    loop {
        #[cfg(not(feature = "profiling"))]
        let Ok(msg) = next(rx, rib.next_deadline()) else {
            return;
        };
        #[cfg(feature = "profiling")]
        let Ok(msg) = loads.recv(rx, &rib, rib.next_deadline()) else {
            return;
        };
        let now = Instant::now();
        #[cfg(feature = "profiling")]
        let seen = msg.as_ref().map(|m| loads.before(m));
        if let Some(msg) = msg {
            handle(
                &mut rib,
                &mut settings,
                &mut transitions,
                msg,
                now,
                fib,
                &mut out,
            );
        }
        // RFC 4271 §9.2.1.1: release what is due. After a message too, so
        // that a busy channel cannot starve the deadlines.
        rib.flush(now, &mut out);
        out.flush();
        #[cfg(feature = "profiling")]
        if let Some(seen) = seen {
            loads.after(seen, &rib);
        }
    }
}

/// Every sender to the RIB thread is gone.
#[derive(Debug)]
pub(crate) struct Closed;

/// Wait for the next message (`Some`), or until `deadline`, when there is
/// one, passes first (`None`).
pub(crate) fn next(
    rx: &Receiver<RibMsg>,
    deadline: Option<Instant>,
) -> Result<Option<RibMsg>, Closed> {
    let Some(deadline) = deadline else {
        return rx.recv().map(Some).map_err(|_| Closed);
    };
    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(m) => Ok(Some(m)),
        Err(RecvTimeoutError::Timeout) => Ok(None),
        Err(RecvTimeoutError::Disconnected) => Err(Closed),
    }
}

/// Apply one message to the RIB, its outputs going to `out`; the routes
/// a change of the validation source moved are kept in `transitions`.
fn handle(
    rib: &mut Rib,
    settings: &mut RibSettings,
    transitions: &mut Transitions,
    msg: RibMsg,
    now: Instant,
    fib: &SyncSender<FibMsg>,
    out: &mut impl Sink,
) {
    match msg {
        RibMsg::PeerUp {
            peer,
            local_addr,
            session,
        } => {
            let interval =
                advertisement_interval(configured(&settings.intervals, peer), session.peer);
            let limits = prefix_limits(settings, peer);
            bgpfc_log::info!(
                "rib: peer up",
                peer = peer,
                local = local_addr,
                families = session
                    .families
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                extended_next_hop_send = session
                    .extended_next_hop_send
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                advertisement_interval = interval.as_secs()
            );
            let mut info = peer_info(peer, local_addr, &session, interval);
            info.prefix_limits = limits;
            rib.peer_up(info, now, out);
        }
        RibMsg::Update { peer, update, .. } => {
            log_update(peer, &update);
            rib.update(peer, &update, now, out);
        }
        RibMsg::RouteRefresh { peer, family } => {
            bgpfc_log::info!("rib: route refresh", peer = peer, family = family);
            rib.refresh(peer, family, now, out);
        }
        RibMsg::PeerDown { peer } => {
            let stats = rib.peer_stats(peer).unwrap_or_default();
            bgpfc_log::info!(
                "rib: peer down",
                peer = peer,
                routes_deleted = stats.received.iter().map(|(_, n)| n).sum::<usize>()
            );
            rib.peer_down(peer, now, out);
        }
        RibMsg::Query(q, reply) => {
            let _ = reply.send(answer(rib, transitions, &q));
        }
        RibMsg::SetPolicies {
            policies,
            reimport,
            reexport,
        } => set_policies(rib, policies.0, (&reimport, &reexport), now, out),
        RibMsg::SetIntervals(new) => {
            settings.intervals = new;
            follow_intervals(rib, settings, now, out);
        }
        RibMsg::SetPrefixLimits(new) => {
            settings.prefix_limits = new;
            follow_prefix_limits(rib, settings, now, out);
        }
        RibMsg::Resend { peer } => {
            let families: Vec<_> = rib
                .peer(peer)
                .map(|p| p.families.clone())
                .unwrap_or_default();
            for family in families {
                bgpfc_log::info!("rib: resend", peer = peer, family = family);
                rib.refresh(peer, family, now, out);
            }
        }
        RibMsg::Validation(change) => {
            bgpfc_log::debug!(
                "rib: validation change",
                affected = describe_affected(&change.affected)
            );
            let mut out = Recording {
                transitions,
                out,
                when: now,
            };
            rib.validation_changed(change, now, &mut out);
        }
        RibMsg::SetEnforcement(mode) => {
            bgpfc_log::debug!("rib: rpki enforcement", mode = mode);
            rib.set_enforcement(mode, now, out);
        }
        RibMsg::SetStartup(startup) => {
            bgpfc_log::debug!("rib: rpki startup", startup = startup);
            rib.set_startup(startup, now, out);
        }
        // The changes of earlier messages went to the FIB first: the loop
        // hands them on after each.
        RibMsg::FibMode(mode, reply) => fib_mode(rib, fib, mode, reply),
    }
}

/// A reload's policies: export again to the peers in `reexport`, first,
/// so that they have what the new export policy makes of the Loc-RIB
/// before importing again changes it; then import again from the
/// Adj-RIBs-In the routes of those in `reimport` (RFC 4271 §3), with no
/// ROUTE-REFRESH but for the families of what the RIB did not keep (RFC
/// 2918), each of which the peer then sends again whole.
fn set_policies(
    rib: &mut Rib,
    policies: Box<dyn bgpfc_rib::Policies>,
    (reimport, reexport): (&[IpAddr], &[IpAddr]),
    now: Instant,
    out: &mut impl Sink,
) {
    for peer in reexport {
        bgpfc_log::info!("rib: re-export", peer = peer);
    }
    rib.set_policies(policies, reexport, now, out);
    rib.reimport(reimport, now, out);
}

/// Routes in one `FibMsg::Reconcile`.
const RECONCILE_BATCH: usize = 4096;

/// Switch the FIB's mode. Going to install, the FIB reconciles what is
/// installed against every route the RIB has (README, "FIB dry-run"),
/// which go to it in batches through the bounded queue rather than as one
/// table-sized list.
fn fib_mode(rib: &Rib, fib: &SyncSender<FibMsg>, mode: bgpfc_fib::Mode, reply: SyncSender<usize>) {
    let send = |msg| fib.send(msg).is_ok();
    let mut ok = send(FibMsg::SetMode(mode));
    if mode == bgpfc_fib::Mode::Install {
        let mut batch = Vec::with_capacity(RECONCILE_BATCH);
        for (prefix, gateway) in rib.fib_routes() {
            batch.push((prefix, crate::fib::fib_hop(gateway)));
            if batch.len() == RECONCILE_BATCH {
                ok &= send(FibMsg::Reconcile(std::mem::take(&mut batch)));
                batch.reserve(RECONCILE_BATCH);
            }
        }
        ok &= send(FibMsg::Reconcile(batch));
    }
    ok &= send(FibMsg::ReconcileEnd(reply));
    if !ok {
        bgpfc_log::error!("fib thread gone");
    }
}

/// `all`, or how many changed VRP prefixes name the affected routes, for
/// a log line.
fn describe_affected(affected: &AffectedPrefixes) -> String {
    match affected {
        AffectedPrefixes::All => "all".to_owned(),
        AffectedPrefixes::CoveredBy(prefixes) => prefixes.len().to_string(),
    }
}

/// After a reload: running sessions take their new advertisement
/// interval (RFC 4271 §9.2.1.1) without a reset.
fn follow_intervals(rib: &mut Rib, settings: &RibSettings, now: Instant, out: &mut impl Sink) {
    let up: Vec<(IpAddr, PeerKind, Duration)> = rib
        .peers()
        .map(|p| (p.addr, p.kind, p.advertisement_interval))
        .collect();
    for (peer, kind, old) in up {
        let interval = advertisement_interval(configured(&settings.intervals, peer), kind);
        if interval != old {
            bgpfc_log::info!(
                "rib: advertisement interval",
                peer = peer,
                seconds = interval.as_secs()
            );
            rib.set_advertisement_interval(peer, interval, now, out);
        }
    }
}

/// After a reload: running sessions take their new prefix limits
/// (RFC 4271 §6.7) without a reset; one already over a new limit ends as
/// if it had just crossed it.
fn follow_prefix_limits(rib: &mut Rib, settings: &RibSettings, now: Instant, out: &mut impl Sink) {
    let up: Vec<(IpAddr, Vec<_>)> = rib
        .peers()
        .map(|p| (p.addr, p.prefix_limits.clone()))
        .collect();
    for (peer, old) in up {
        let limits = prefix_limits(settings, peer);
        if limits != old {
            bgpfc_log::info!(
                "rib: prefix limits",
                peer = peer,
                limits = describe_limits(&limits)
            );
            rib.set_prefix_limits(peer, limits, now, out);
        }
    }
}

/// The `maximum-prefix` limits configured for `peer` (RFC 4271 §6.7).
fn prefix_limits(settings: &RibSettings, peer: IpAddr) -> Vec<(AddressFamily, u32)> {
    settings
        .prefix_limits
        .get(&peer)
        .cloned()
        .unwrap_or_default()
}

/// `ipv4-unicast=1000,ipv6-unicast=200` for a log line; `none` if empty.
fn describe_limits(limits: &[(AddressFamily, u32)]) -> String {
    if limits.is_empty() {
        return "none".to_owned();
    }
    limits
        .iter()
        .map(|(f, l)| format!("{f}={l}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The `advertisement-interval` configured for `peer`, if any.
fn configured(intervals: &Intervals, peer: IpAddr) -> Option<Duration> {
    intervals.get(&peer).copied().flatten()
}

/// The interval a session runs with: the configured one, else the
/// RFC 4271 §10 default for its type (30 s external, 5 s internal).
fn advertisement_interval(configured: Option<Duration>, kind: PeerKind) -> Duration {
    configured.unwrap_or_else(|| bgpfc_rib::pacing::default_interval(kind))
}

fn peer_info(peer: IpAddr, local_addr: IpAddr, s: &Session, interval: Duration) -> PeerInfo {
    PeerInfo {
        addr: peer,
        local_addr,
        remote_as: s.peer_as,
        router_id: s.peer_router_id,
        kind: s.peer,
        families: s.families.clone(),
        receive_families: s.receive_families.clone(),
        four_octet_as: s.four_octet_as,
        extended_messages: s.extended_messages,
        route_refresh: s.route_refresh,
        // RFC 8950 §4: what the RIB needs is what may be sent; what may
        // be received is the decoder's business.
        extended_next_hop: s.extended_next_hop_send.clone(),
        advertisement_interval: interval,
        prefix_limits: Vec::new(),
    }
}

/// FIB changes sent in one message at most: one per channel operation
/// costs the RIB thread more than the change itself.
pub(crate) const FIB_BATCH: usize = 256;

/// Hands RIB outputs to the FIB and peer threads as the RIB produces them;
/// FIB changes go in batches, sent when full and after each input, the
/// last batch of an input marked as such for the FIB thread's log.
struct Deliver<'a> {
    peers: &'a PeerTable,
    fib: &'a SyncSender<FibMsg>,
    changes: Vec<FibChange>,
    /// Whether a batch of this input's changes went out with more to
    /// follow, so that its end must be sent even with no change left.
    open: bool,
}

impl Deliver<'_> {
    /// At the end of an input: the rest of its changes, as its last batch.
    fn flush(&mut self) {
        self.send(false);
    }

    /// Send the changes held, `more` if the input has more to come.
    fn send(&mut self, more: bool) {
        if self.changes.is_empty() && (more || !self.open) {
            return;
        }
        // The next input likely changes about as many destinations.
        let next = Vec::with_capacity(self.changes.len());
        let changes = std::mem::replace(&mut self.changes, next);
        self.open = more;
        // A bounded channel: a slow kernel slows the RIB rather than
        // growing memory (AGENTS.md §3 backpressure).
        if self.fib.send(FibMsg::Changes { changes, more }).is_err() {
            bgpfc_log::error!("fib thread gone");
        }
    }

    fn handle(&self, peer: IpAddr) -> Option<crate::peer::PeerHandle> {
        self.peers.read().ok().and_then(|t| t.get(&peer).cloned())
    }
}

impl Sink for Deliver<'_> {
    fn put(&mut self, output: Output) {
        match output {
            Output::Fib(c) => {
                self.changes.push(c);
                if self.changes.len() >= FIB_BATCH {
                    self.send(true);
                }
            }
            Output::Send { peer, messages } => {
                let Some(handle) = self.handle(peer) else {
                    return;
                };
                bgpfc_log::debug!("rib: send", peer = peer, messages = messages.len());
                match handle.send_updates(messages) {
                    Ok(()) => {}
                    Err(SendError::Overrun) => {
                        // AGENTS.md §3: never drop updates silently; the
                        // peer thread resets the session.
                        bgpfc_log::warn!("rib: peer outbox full", peer = peer);
                    }
                    Err(SendError::Gone) => {
                        bgpfc_log::warn!("rib: peer thread gone", peer = peer);
                    }
                }
            }
            Output::EncodeFailed { peer, error } => {
                bgpfc_log::error!("rib: cannot encode update", peer = peer, error = error);
            }
            Output::PrefixLimitExceeded {
                peer,
                family,
                limit,
            } => {
                bgpfc_log::error!(
                    "rib: prefix limit exceeded, routes dropped",
                    peer = peer,
                    family = family,
                    limit = limit
                );
                let Some(handle) = self.handle(peer) else {
                    return;
                };
                // RFC 4271 §6.7: the session must end. A full queue means
                // the peer thread is busy and checks the slot after its
                // current input; the RIB never blocks on a peer
                // (AGENTS.md §3).
                match handle.tx.try_send(PeerInput::PrefixLimit { family, limit }) {
                    Ok(()) | Err(TrySendError::Disconnected(_)) => {}
                    Err(TrySendError::Full(_)) => {
                        if let Ok(mut slot) = handle.prefix_limit.lock() {
                            *slot = Some((family, limit));
                        }
                    }
                }
            }
            Output::InvalidNextHop {
                peer,
                family,
                next_hop,
                prefixes,
            } => {
                // RFC 4271 §6.3: a semantically incorrect next hop "SHOULD
                // be logged"; no NOTIFICATION, and the session stays up.
                bgpfc_log::warn!(
                    "rib: routes ignored, their next hop is our own address",
                    peer = peer,
                    family = family,
                    next_hop = next_hop,
                    routes = prefixes.len(),
                    prefixes = sample(&prefixes)
                );
            }
            Output::Revalidated(r) => {
                // RFC 6811 §4: the routes a change of the validation source
                // moved, counted in one line however many routes it moved:
                // turning validation on or off, or the expiry of the VRPs,
                // moves every route of the table, and a line per route
                // would hold the RIB thread and flood the log. Then a line
                // per route it moved among valid, invalid and not-found
                // (issue #59), as many as `LOGGED` at info.
                let debug = bgpfc_log::enabled(Level::Debug);
                for line in revalidation_lines(&r, debug) {
                    log_line(line.level, line.msg, &line.fields);
                }
            }
            Output::Enforcement(r) => {
                // RFC 6811 §5: every route judged again under the
                // operator's new enforcement mode, counted in one line.
                log_line(Level::Info, ENFORCEMENT_CHANGED, &rejudged(&r));
            }
            Output::Startup(r) => {
                // RFC 6811 §2: the routes not validated yet held or used
                // under the operator's new startup setting, in one line.
                log_line(Level::Info, STARTUP_CHANGED, &startup_changed(&r));
            }
            Output::Reimported(r) => {
                // RFC 4271 §3 (a): a peer's routes put through its new
                // import policy again, counted in one line however many;
                // then what only the peer can send again and cannot be
                // asked for, a line each.
                log_line(Level::Info, REIMPORTED, &reimported(&r));
                for (peer, family) in &r.missing {
                    bgpfc_log::warn!(MISSING, peer = peer, family = family);
                }
            }
            Output::RequestRoutes { peer, families } => self.request_routes(peer, families),
        }
    }
}

impl Deliver<'_> {
    /// RFC 4271 §3 (b), RFC 2918 §4: have `peer`'s thread send a
    /// ROUTE-REFRESH for each of `families`. A full queue means it is busy
    /// and reads the slot after its current input; the RIB never blocks on
    /// a peer (AGENTS.md §3).
    fn request_routes(&self, peer: IpAddr, families: Vec<AddressFamily>) {
        let Some(handle) = self.handle(peer) else {
            return;
        };
        match handle.tx.try_send(PeerInput::RequestRoutes(families)) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(input)) => {
                if let (PeerInput::RequestRoutes(families), Ok(mut slot)) =
                    (input, handle.refresh.lock())
                {
                    for f in families {
                        if !slot.contains(&f) {
                            slot.push(f);
                        }
                    }
                }
            }
        }
    }
}

/// Log a line whose field values are already text.
pub(crate) fn log_line(level: Level, msg: &str, values: &[(&'static str, String)]) {
    let fields: Vec<bgpfc_log::Field<'_>> = values
        .iter()
        .map(|(k, v)| (*k, v as &dyn std::fmt::Display))
        .collect();
    bgpfc_log::log(level, msg, &fields);
}

/// The message of the line logged for what a change of the validation
/// source did to the routes' RFC 6811 states.
const REVALIDATED: &str = "rib: validation states changed";

/// The fields of that line: the routes validated again, how many of them
/// changed state, those per change of state (`disabled->valid:1000,...`),
/// the destinations they are for with the first few of them, the
/// destinations whose best route changed, the routes the change took out
/// of use (`held`) and put back into use (`released`) under the
/// `enforcement` and import policy (RFC 6811 §2, §5), and of the routes
/// it moved among valid, invalid and not-found, those with a line of
/// their own at info (`logged`) and those without (`unlogged`). The first
/// six are m11's, in m11's order, which scripts may read.
fn revalidated(r: &Revalidation) -> [(&'static str, String); 10] {
    let changes = r
        .changes
        .iter()
        .map(|(from, to, n)| format!("{from}->{to}:{n}"))
        .collect::<Vec<_>>()
        .join(",");
    let logged = r.transitions.len().min(LOGGED);
    let unlogged = r.transitions.len() - logged + r.unlisted;
    [
        ("routes", r.routes.to_string()),
        ("changed", r.changed().to_string()),
        ("changes", changes),
        ("destinations", r.destinations.to_string()),
        ("prefixes", listed(&r.sample, r.destinations)),
        ("best_changed", r.best_changed.to_string()),
        ("held", r.held.to_string()),
        ("released", r.released.to_string()),
        ("logged", logged.to_string()),
        ("unlogged", unlogged.to_string()),
    ]
}

/// Routes a change of the validation source moved among valid, invalid
/// and not-found that get a line of their own at info: the first this
/// many the RIB lists, in prefix order. Ordinary RTR deltas move few
/// routes, as most VRP churn re-issues ROAs that are already Valid, so a
/// hundred logs a typical delta whole, line by line. The changes that move
/// many routes (VRPs that expire, failover to a cache with other data, a
/// bulk ROA operation) then cost about 15 KB of log, not a line per route
/// of a table of a million or more. The rest the RIB lists, at most
/// [`Revalidation::LISTED`] in all, go out at debug; every move is
/// counted on the summary line. Not configurable: no value of it is more
/// correct than another, and `show routes` gives every route's state.
pub(crate) const LOGGED: usize = 100;

/// The message of the line per route a change of the validation source
/// moved (issue #59).
const TRANSITION: &str = "rib: route validation state changed";

/// One line to log, its field values already text.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Line {
    /// The level it is logged at.
    pub(crate) level: Level,
    /// The message.
    pub(crate) msg: &'static str,
    /// The fields, in order.
    pub(crate) fields: Vec<(&'static str, String)>,
}

/// What a change of the validation source is logged with: the summary
/// line first, then a line per route it moved among valid, invalid and
/// not-found that the RIB lists: the first [`LOGGED`] at info, and with
/// `debug` the others at debug, which are not built otherwise.
fn revalidation_lines(r: &Revalidation, debug: bool) -> Vec<Line> {
    let shown = if debug {
        r.transitions.len()
    } else {
        r.transitions.len().min(LOGGED)
    };
    let mut lines = Vec::with_capacity(1 + shown);
    lines.push(Line {
        level: Level::Info,
        msg: REVALIDATED,
        fields: revalidated(r).into(),
    });
    for (i, t) in r.transitions[..shown].iter().enumerate() {
        lines.push(Line {
            level: if i < LOGGED {
                Level::Info
            } else {
                Level::Debug
            },
            msg: TRANSITION,
            fields: transition(t),
        });
    }
    lines
}

/// The fields of the line for one route a change moved: its destination,
/// the peer it came from, its Route Origin ASN (RFC 6811 §2), the states
/// the lookup gave it before and after, and what it is now: `best`,
/// `candidate`, or `held` with `by` the reason (`enforcement` or
/// `policy`).
fn transition(t: &Transition) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("prefix", t.prefix.to_string()),
        ("peer", t.peer.to_string()),
        ("origin", t.origin.to_string()),
        ("from", t.from.to_string()),
        ("to", t.to.to_string()),
        ("route", status_name(t.route).to_owned()),
    ];
    if let RouteStatus::Held(by) = t.route {
        fields.push(("by", by.to_string()));
    }
    fields
}

/// What a route is after the decision process, as logs and the control
/// plane name it: `best`, `candidate` or `held`.
pub(crate) const fn status_name(s: RouteStatus) -> &'static str {
    match s {
        RouteStatus::Best => "best",
        RouteStatus::Candidate => "candidate",
        RouteStatus::Held(_) => "held",
    }
}

/// Changes of state kept for `show rpki transitions`: the most recent of
/// those the RIB lists, as many as one change of the validation source
/// lists at most ([`Revalidation::LISTED`]), so that the last large one
/// shows whole. About 90 KB: 88 bytes an entry on a 64-bit target, the
/// [`Transition`] and its two times. Not configurable, as [`LOGGED`] is
/// not.
pub(crate) const KEPT: usize = 1024;

/// The RIB thread's memory of the routes changes of the validation source
/// moved among valid, invalid and not-found: the latest [`KEPT`], each
/// with when it happened, and a count of those it was never given.
#[derive(Debug, Default)]
pub(crate) struct Transitions {
    kept: VecDeque<Recorded>,
    unrecorded: u64,
}

impl Transitions {
    /// Keep what `r` lists, which happened at `at` (`when` on the
    /// monotonic clock), dropping the oldest beyond [`KEPT`], and count
    /// what it does not list.
    fn record(&mut self, r: &Revalidation, at: SystemTime, when: Instant) {
        let listed = &r.transitions[r.transitions.len().saturating_sub(KEPT)..];
        let room = KEPT - listed.len();
        if self.kept.len() > room {
            self.kept.drain(..self.kept.len() - room);
        }
        self.kept.extend(listed.iter().map(|t| Recorded {
            at,
            when,
            transition: t.clone(),
        }));
        self.unrecorded = self
            .unrecorded
            .saturating_add(u64::try_from(r.unlisted).unwrap_or(u64::MAX));
    }

    /// What is kept, oldest first, for the control plane.
    fn report(&self) -> TransitionsReport {
        TransitionsReport {
            capacity: KEPT,
            unrecorded: self.unrecorded,
            entries: self.kept.iter().cloned().collect(),
        }
    }
}

/// Passes outputs on to `out`, keeping in `transitions` first what the
/// report of a change of the validation source lists.
struct Recording<'a, S> {
    transitions: &'a mut Transitions,
    out: &'a mut S,
    /// When the change was taken from the channel.
    when: Instant,
}

impl<S: Sink> Sink for Recording<'_, S> {
    fn put(&mut self, output: Output) {
        if let Output::Revalidated(r) = &output {
            self.transitions.record(r, SystemTime::now(), self.when);
        }
        self.out.put(output);
    }
}

/// The message of the line logged when the `enforcement` changes.
const ENFORCEMENT_CHANGED: &str = "rib: rpki enforcement changed";

/// The fields of that line: the mode before and after, the routes judged
/// again (every route the Adj-RIBs-In hold), those the new mode took out
/// of use and put back into use, and the destinations whose best route
/// changed.
fn rejudged(r: &Rejudged) -> [(&'static str, String); 6] {
    [
        ("from", r.from.to_string()),
        ("to", r.to.to_string()),
        ("routes", r.routes.to_string()),
        ("held", r.held.to_string()),
        ("released", r.released.to_string()),
        ("best_changed", r.best_changed.to_string()),
    ]
}

/// The message of the line logged when the `startup` setting the RIB
/// applies changes.
const STARTUP_CHANGED: &str = "rib: rpki startup changed";

/// The fields of that line: the setting before and after, the routes
/// judged again (those not validated yet, `disabled`), those the new
/// setting took out of use and put back into use, and the destinations
/// whose best route changed.
fn startup_changed(r: &StartupChange) -> [(&'static str, String); 6] {
    [
        ("from", r.from.to_string()),
        ("to", r.to.to_string()),
        ("routes", r.routes.to_string()),
        ("held", r.held.to_string()),
        ("released", r.released.to_string()),
        ("best_changed", r.best_changed.to_string()),
    ]
}

/// The message of the line logged for what importing routes again after
/// a change of import policy did.
const REIMPORTED: &str = "rib: re-import";

/// The message of the line logged for a family whose routes import policy
/// dropped earlier, which the peer cannot be asked for again (RFC 2918
/// §4): they come back when the peer sends them again, or with a hard
/// `clear neighbor`.
const MISSING: &str = "rib: re-import cannot ask the peer for the routes import policy dropped";

/// The fields of that line: the peers whose routes were imported again,
/// the routes put through import policy again, those it now makes
/// something else of, those it took out of use (`held`), put back into
/// use (`released`) and no longer keeps (`dropped`), the destinations
/// whose best route changed, and the families each peer is asked for
/// again with ROUTE-REFRESH (`refresh`, as `FAMILY@PEER`), or `none`.
fn reimported(r: &Reimport) -> [(&'static str, String); 8] {
    let refresh = if r.refresh.is_empty() {
        "none".to_owned()
    } else {
        r.refresh
            .iter()
            .map(|(peer, family)| format!("{family}@{peer}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    [
        (
            "peers",
            r.peers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("routes", r.routes.to_string()),
        ("changed", r.changed.to_string()),
        ("held", r.held.to_string()),
        ("released", r.released.to_string()),
        ("dropped", r.dropped.to_string()),
        ("best_changed", r.best_changed.to_string()),
        ("refresh", refresh),
    ]
}

/// The first few of `prefixes` for a log line, `...` marking the rest.
fn sample(prefixes: &[Prefix]) -> String {
    const SHOWN: usize = 8;
    listed(&prefixes[..prefixes.len().min(SHOWN)], prefixes.len())
}

/// `shown`, the first of `total` prefixes, for a log line, `...` marking
/// the rest.
pub(crate) fn listed(shown: &[Prefix], total: usize) -> String {
    let mut s = shown
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if total > shown.len() {
        s.push_str(",...");
    }
    s
}

fn log_update(peer: IpAddr, update: &bgpfc_wire::update::DecodedUpdate) {
    // Counting the prefixes costs more than the test.
    if !bgpfc_log::enabled(bgpfc_log::Level::Debug) {
        return;
    }
    let announced = update.announcements().count();
    let withdrawn = update.withdrawals().count();
    bgpfc_log::debug!(
        "rib: update",
        peer = peer,
        announced = announced,
        withdrawn = withdrawn
    );
    if bgpfc_log::enabled(bgpfc_log::Level::Trace) {
        for (family, prefix) in update.announcements() {
            bgpfc_log::trace!(
                "rib: announce",
                peer = peer,
                family = family,
                prefix = prefix
            );
        }
        for (family, prefix) in update.withdrawals() {
            bgpfc_log::trace!(
                "rib: withdraw",
                peer = peer,
                family = family,
                prefix = prefix
            );
        }
    }
}

/// `r`, a route to `prefix`, for the control plane.
fn route_report(prefix: Prefix, r: &bgpfc_rib::RouteRef<'_>, best: bool) -> RouteReport {
    RouteReport {
        prefix,
        peer: r.peer,
        attrs: std::sync::Arc::clone(r.attrs),
        best,
        rov: r.rov,
        rov_set: r.rov_set,
        held: r.held,
    }
}

fn answer(rib: &Rib, transitions: &Transitions, q: &RibQuery) -> RibReply {
    match q {
        RibQuery::Transitions => RibReply::Transitions(transitions.report()),
        RibQuery::Peers => RibReply::Peers(
            rib.peers()
                .map(|p| (p.clone(), rib.peer_stats(p.addr).unwrap_or_default()))
                .collect(),
        ),
        RibQuery::Routes {
            family,
            prefix: Some(prefix),
            held,
            ..
        } => RibReply::Routes(
            // RFC 6811 §2: the Adj-RIBs-In keep a route held for its
            // state; it comes after the candidates, of which the first is
            // the best.
            rib.routes(*family, *prefix)
                .iter()
                .enumerate()
                .filter(|(_, r)| !held || r.held.is_some())
                .map(|(i, r)| route_report(*prefix, r, i == 0 && r.held.is_none()))
                .collect(),
        ),
        RibQuery::Routes {
            family,
            prefix: None,
            after,
            held: false,
        } => RibReply::Routes(
            rib.loc_rib_after(*family, *after)
                .take(PAGE)
                .map(|(prefix, b)| route_report(prefix, &b, true))
                .collect(),
        ),
        RibQuery::Routes {
            family,
            prefix: None,
            after,
            held: true,
        } => {
            let mut page: Vec<RouteReport> = Vec::new();
            for (prefix, r) in rib.held_after(*family, *after) {
                // A page ends between two destinations, so that the next,
                // after the last prefix, misses none of their routes.
                if page.len() >= PAGE && page.last().is_some_and(|l| l.prefix != prefix) {
                    break;
                }
                page.push(route_report(prefix, &r, false));
            }
            RibReply::Routes(page)
        }
        RibQuery::FibRoutes { after } => {
            RibReply::FibRoutes(rib.fib_routes_after(*after).take(PAGE).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    use bgpfc_rib::RovState;
    use bgpfc_rpki::ValidationChange;

    use bgpfc_wire::types::{Asn, HoldTime, RouterId};

    const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

    /// [`super::handle`], with what it put out.
    fn handle(rib: &mut Rib, settings: &mut RibSettings, msg: RibMsg, now: Instant) -> Vec<Output> {
        handle_with(rib, settings, &mut Transitions::default(), msg, now)
    }

    /// [`handle`], keeping the transitions in `transitions`.
    fn handle_with(
        rib: &mut Rib,
        settings: &mut RibSettings,
        transitions: &mut Transitions,
        msg: RibMsg,
        now: Instant,
    ) -> Vec<Output> {
        let (fib, _) = sync_channel(1);
        let mut out = Vec::new();
        super::handle(rib, settings, transitions, msg, now, &fib, &mut out);
        out
    }

    /// `outputs` through a [`Deliver`], as the thread hands them on.
    fn deliver(outputs: Vec<Output>, peers: &PeerTable, fib: &SyncSender<FibMsg>) {
        let mut out = Deliver {
            peers,
            fib,
            changes: Vec::new(),
            open: false,
        };
        for o in outputs {
            out.put(o);
        }
        out.flush();
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn session(peer_as: u32, kind: PeerKind) -> Session {
        Session {
            peer_as: Asn(peer_as),
            peer_router_id: RouterId::new(1).unwrap(),
            peer: kind,
            hold_time: HoldTime::new(90).unwrap(),
            keepalive_time: Duration::from_secs(30),
            four_octet_as: true,
            extended_messages: false,
            route_refresh: true,
            families: vec![AddressFamily::IPV4_UNICAST],
            receive_families: vec![AddressFamily::IPV4_UNICAST],
            extended_next_hop_receive: Vec::new(),
            extended_next_hop_send: Vec::new(),
            peer_capabilities: Vec::new(),
        }
    }

    fn up(peer: &str, peer_as: u32, kind: PeerKind) -> RibMsg {
        RibMsg::PeerUp {
            peer: ip(peer),
            local_addr: ip("192.0.2.254"),
            session: session(peer_as, kind),
        }
    }

    #[test]
    fn intervals_default_by_session_type() {
        // RFC 4271 §10: 30 s on EBGP, 5 s on IBGP, unless configured.
        let ext = advertisement_interval(None, PeerKind::External);
        assert_eq!(ext, Duration::from_secs(30));
        let int = advertisement_interval(None, PeerKind::Internal);
        assert_eq!(int, Duration::from_secs(5));
        let off = advertisement_interval(Some(Duration::ZERO), PeerKind::External);
        assert_eq!(off, Duration::ZERO);
        let mut i = Intervals::new();
        assert_eq!(configured(&i, ip("192.0.2.1")), None);
        i.insert(ip("192.0.2.1"), Some(Duration::from_secs(9)));
        assert_eq!(
            configured(&i, ip("192.0.2.1")),
            Some(Duration::from_secs(9))
        );
    }

    #[test]
    fn sessions_start_and_follow_the_configured_intervals() {
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        settings
            .intervals
            .insert(ip("192.0.2.3"), Some(Duration::from_secs(2)));
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.2", 65_000, PeerKind::Internal),
            now,
        );
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.3", 65_003, PeerKind::External),
            now,
        );
        let interval = |rib: &Rib, a: &str| rib.peer(ip(a)).unwrap().advertisement_interval;
        assert_eq!(interval(&rib, "192.0.2.1"), Duration::from_secs(30));
        assert_eq!(interval(&rib, "192.0.2.2"), Duration::from_secs(5));
        assert_eq!(interval(&rib, "192.0.2.3"), Duration::from_secs(2));
        // A reload: running sessions follow, no reset.
        let mut new = Intervals::new();
        new.insert(ip("192.0.2.1"), Some(Duration::ZERO));
        handle(&mut rib, &mut settings, RibMsg::SetIntervals(new), now);
        assert_eq!(interval(&rib, "192.0.2.1"), Duration::ZERO);
        assert_eq!(interval(&rib, "192.0.2.2"), Duration::from_secs(5));
        assert_eq!(interval(&rib, "192.0.2.3"), Duration::from_secs(30));
        assert_eq!(rib.peers().count(), 3);
    }

    /// An UPDATE from `peer` announcing `prefixes` with a path from its AS.
    fn routes(peer: &str, peer_as: u32, prefixes: &[&str]) -> RibMsg {
        use bgpfc_wire::as_path::AsPath;
        use bgpfc_wire::attribute::{Origin, PathAttribute};
        let message = bgpfc_wire::update::UpdateMessage {
            nlri: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(peer_as)])),
                PathAttribute::NextHop(peer.parse().unwrap()),
            ],
            ..Default::default()
        };
        RibMsg::Update {
            peer: ip(peer),
            update: bgpfc_wire::update::DecodedUpdate {
                message,
                ..Default::default()
            },
            #[cfg(feature = "profiling")]
            started: None,
        }
    }

    #[test]
    fn routes_via_our_own_session_address_are_ignored_and_logged() {
        // RFC 4271 §6.3 a): the PeerUp's local address is our address on
        // the session; a route back through it is ignored, the session
        // stays, and the routes are logged.
        use bgpfc_wire::attribute::PathAttribute;
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        let peer = ip("192.0.2.1");
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        let mut msg = routes("192.0.2.1", 65_001, &["198.51.100.0/24"]);
        if let RibMsg::Update { update, .. } = &mut msg {
            update.message.attributes[2] = PathAttribute::NextHop("192.0.2.254".parse().unwrap());
        }
        let out = handle(&mut rib, &mut settings, msg, now);
        assert!(
            matches!(&out[..], [Output::InvalidNextHop { peer: p, family: V4, .. }] if *p == peer),
            "{out:?}"
        );
        assert!(rib.peer(peer).is_some());
        assert_eq!(rib.loc_rib(V4).count(), 0);
        let (fib_tx, fib_rx) = sync_channel(4);
        let table: PeerTable = std::sync::Arc::default();
        deliver(out, &table, &fib_tx);
        assert!(fib_rx.try_recv().is_err());
        let prefixes: Vec<_> = (0..9)
            .map(|i| format!("10.{i}.0.0/16").parse().unwrap())
            .collect();
        assert_eq!(sample(&prefixes[..2]), "10.0.0.0/16,10.1.0.0/16");
        assert!(sample(&prefixes).ends_with(",10.7.0.0/16,..."));
    }

    fn limit_hits(out: &[Output]) -> Vec<(IpAddr, AddressFamily, u32)> {
        out.iter()
            .filter_map(|o| match o {
                Output::PrefixLimitExceeded {
                    peer,
                    family,
                    limit,
                } => Some((*peer, *family, *limit)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn sessions_start_with_and_follow_the_configured_prefix_limits() {
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        settings
            .prefix_limits
            .insert(ip("192.0.2.1"), vec![(V4, 1)]);
        for (peer, peer_as) in [("192.0.2.1", 65_001), ("192.0.2.2", 65_002)] {
            handle(
                &mut rib,
                &mut settings,
                up(peer, peer_as, PeerKind::External),
                now,
            );
        }
        assert_eq!(rib.peer(ip("192.0.2.1")).unwrap().prefix_limit(V4), Some(1));
        assert_eq!(rib.peer(ip("192.0.2.2")).unwrap().prefix_limit(V4), None);
        // RFC 4271 §6.7: two routes against a limit of one.
        let msg = routes("192.0.2.1", 65_001, &["198.51.100.0/24", "203.0.113.0/24"]);
        let out = handle(&mut rib, &mut settings, msg, now);
        assert_eq!(limit_hits(&out), vec![(ip("192.0.2.1"), V4, 1)]);
        assert!(rib.peer(ip("192.0.2.1")).is_none());
        // A reload lowers the other peer's limit below what it holds: its
        // session ends too; an unchanged limit does nothing.
        let msg = routes("192.0.2.2", 65_002, &["198.51.100.0/24", "203.0.113.0/24"]);
        assert_eq!(
            limit_hits(&handle(&mut rib, &mut settings, msg, now)),
            vec![]
        );
        let mut new = settings.prefix_limits.clone();
        new.insert(ip("192.0.2.2"), vec![(V4, 5)]);
        let out = handle(
            &mut rib,
            &mut settings,
            RibMsg::SetPrefixLimits(new.clone()),
            now,
        );
        assert_eq!(out, vec![]);
        assert_eq!(rib.peer(ip("192.0.2.2")).unwrap().prefix_limit(V4), Some(5));
        new.insert(ip("192.0.2.2"), vec![(V4, 1)]);
        let out = handle(&mut rib, &mut settings, RibMsg::SetPrefixLimits(new), now);
        assert_eq!(limit_hits(&out), vec![(ip("192.0.2.2"), V4, 1)]);
        assert_eq!(rib.peers().count(), 0);
        assert_eq!(
            describe_limits(&[(V4, 1), (AddressFamily::IPV6_UNICAST, 2)]),
            "ipv4-unicast=1,ipv6-unicast=2"
        );
        assert_eq!(describe_limits(&[]), "none");
    }

    /// A peer handle on a queue of one, for watching what the RIB thread
    /// tells a peer.
    fn handle_on_queue(addr: IpAddr) -> (crate::peer::PeerHandle, Receiver<PeerInput>) {
        let (tx, rx) = sync_channel(1);
        (crate::peer::PeerHandle::on(addr, tx), rx)
    }

    #[test]
    fn a_prefix_limit_reaches_the_peer_even_through_a_full_queue() {
        let addr = ip("192.0.2.1");
        let (h, rx) = handle_on_queue(addr);
        let table: PeerTable = std::sync::Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::from([(addr, h.clone())]),
        ));
        let (fib_tx, _fib_rx) = sync_channel(4);
        let hit = || {
            vec![Output::PrefixLimitExceeded {
                peer: addr,
                family: V4,
                limit: 7,
            }]
        };
        deliver(hit(), &table, &fib_tx);
        assert!(matches!(
            rx.try_recv(),
            Ok(PeerInput::PrefixLimit {
                family: V4,
                limit: 7
            })
        ));
        // The queue full: the slot the peer thread checks after each input.
        h.tx.try_send(PeerInput::SoftReset).unwrap();
        deliver(hit(), &table, &fib_tx);
        assert_eq!(*h.prefix_limit.lock().unwrap(), Some((V4, 7)));
        assert!(matches!(rx.try_recv(), Ok(PeerInput::SoftReset)));
        assert!(rx.try_recv().is_err());
        // An unknown peer: nothing to tell.
        let other = vec![Output::PrefixLimitExceeded {
            peer: ip("192.0.2.9"),
            family: V4,
            limit: 7,
        }];
        deliver(other, &table, &fib_tx);
    }

    /// Read one framed message: its type and the whole frame.
    fn read_message(conn: &mut std::net::TcpStream) -> (u8, Vec<u8>) {
        use std::io::Read as _;
        let mut frame = vec![0u8; 19];
        conn.read_exact(&mut frame).unwrap();
        let len = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
        frame.resize(len, 0);
        conn.read_exact(&mut frame[19..]).unwrap();
        (frame[18], frame)
    }

    /// Act as the neighbor on the next connection bgpfcd makes: answer its
    /// OPEN with ours and a KEEPALIVE, and wait for the session to be up.
    fn establish(
        listener: &std::net::TcpListener,
        rib_rx: &Receiver<RibMsg>,
    ) -> std::net::TcpStream {
        use bgpfc_wire::capability::Capability;
        establish_with(listener, rib_rx, vec![Capability::Multiprotocol(V4)])
    }

    /// [`establish`], with the neighbor advertising `capabilities`.
    fn establish_with(
        listener: &std::net::TcpListener,
        rib_rx: &Receiver<RibMsg>,
        capabilities: Vec<bgpfc_wire::capability::Capability>,
    ) -> std::net::TcpStream {
        use bgpfc_wire::header::{MessageType, frame};
        use std::io::Write as _;
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        assert_eq!(read_message(&mut conn).0, MessageType::Open as u8);
        let open = bgpfc_wire::open::OpenMessage::new(
            Asn(65_001),
            HoldTime::new(90).unwrap(),
            RouterId::new(2).unwrap(),
            capabilities,
        );
        conn.write_all(&frame(MessageType::Open, &open.encode().unwrap()).unwrap())
            .unwrap();
        conn.write_all(&bgpfc_wire::keepalive::KEEPALIVE).unwrap();
        match rib_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(RibMsg::PeerUp { .. }) => {}
            other => panic!("expected PeerUp, got {other:?}"),
        }
        conn
    }

    /// The frames on `conn` up to its NOTIFICATION, which is returned.
    fn notification(conn: &mut std::net::TcpStream) -> Vec<u8> {
        loop {
            let (kind, frame) = read_message(conn);
            if kind == bgpfc_wire::header::MessageType::Notification as u8 {
                return frame;
            }
        }
    }

    #[test]
    fn a_prefix_limit_ends_the_session_with_the_rfc4486_cease() {
        // The whole path through a real peer thread on loopback: the RIB's
        // output, the peer input (and the slot), the FSM's AutomaticStop
        // and the bytes on the wire.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ip("127.0.0.1");
        let mut fsm = bgpfc_fsm::Config::new(Asn(65_000), RouterId::new(1).unwrap(), Asn(65_001));
        fsm.capabilities = vec![bgpfc_wire::capability::Capability::Multiprotocol(V4)];
        let cfg = crate::peer::PeerConfig {
            addr,
            port: listener.local_addr().unwrap().port(),
            fsm,
            allow_as_set: false,
            ttl: None,
            local: None,
            single_hop: false,
        };
        let (rib_tx, rib_rx) = sync_channel(64);
        let (h, peer) = crate::peer::prepare(cfg, rib_tx);
        let table: PeerTable = std::sync::Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::from([(addr, h.clone())]),
        ));
        let (fib_tx, _fib_rx) = sync_channel(4);
        peer.start();
        // RFC 4486 §4 Figure 1: Cease (6) / Maximum Number of Prefixes
        // Reached (1), AFI 1, SAFI 1, upper bound 1000.
        let mut expected = vec![0xff; 16];
        expected.extend([0, 28, 3, 6, 1, 0, 1, 1, 0, 0, 0x03, 0xe8]);
        let mut conn = establish(&listener, &rib_rx);
        let hit = vec![Output::PrefixLimitExceeded {
            peer: addr,
            family: V4,
            limit: 1000,
        }];
        deliver(hit, &table, &fib_tx);
        assert_eq!(notification(&mut conn), expected);
        // RFC 4271 §8.2.2: the FSM deletes the session's routes.
        assert!(matches!(
            rib_rx.recv_timeout(Duration::from_secs(10)),
            Ok(RibMsg::PeerDown { .. })
        ));
        // The same through the slot a full queue falls back to: a clear
        // starts the peer again, and the next input it handles finds it.
        h.tx.send(PeerInput::Reset(None)).unwrap();
        let mut conn = establish(&listener, &rib_rx);
        *h.prefix_limit.lock().unwrap() = Some((V4, 1000));
        let (report, _) = sync_channel(1);
        h.tx.send(PeerInput::Report(report)).unwrap();
        assert_eq!(notification(&mut conn), expected);
        assert!(matches!(
            rib_rx.recv_timeout(Duration::from_secs(10)),
            Ok(RibMsg::PeerDown { .. })
        ));
        // Out of Established a stale request is ignored.
        h.tx.send(PeerInput::PrefixLimit {
            family: V4,
            limit: 1000,
        })
        .unwrap();
        h.tx.send(PeerInput::Stop(
            bgpfc_wire::error::CeaseSubcode::AdministrativeShutdown,
        ))
        .unwrap();
    }

    #[test]
    fn a_request_for_routes_reaches_the_wire_for_the_negotiated_families() {
        // RFC 2918 §4 through a real peer thread on loopback: the RIB asks
        // for IPv4 and IPv6, the session negotiated IPv4 alone, so one
        // ROUTE-REFRESH goes out, for <1, 0, 1>; then the same through the
        // slot a full queue falls back to.
        use bgpfc_wire::capability::Capability;
        use bgpfc_wire::header::MessageType;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ip("127.0.0.1");
        let mut fsm = bgpfc_fsm::Config::new(Asn(65_000), RouterId::new(1).unwrap(), Asn(65_001));
        fsm.capabilities = vec![Capability::Multiprotocol(V4), Capability::RouteRefresh];
        let cfg = crate::peer::PeerConfig {
            addr,
            port: listener.local_addr().unwrap().port(),
            fsm,
            allow_as_set: false,
            ttl: None,
            local: None,
            single_hop: false,
        };
        let (rib_tx, rib_rx) = sync_channel(64);
        let (h, peer) = crate::peer::prepare(cfg, rib_tx);
        let table: PeerTable = std::sync::Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::from([(addr, h.clone())]),
        ));
        let (fib_tx, _fib_rx) = sync_channel(4);
        peer.start();
        let mut conn = establish_with(
            &listener,
            &rib_rx,
            vec![Capability::Multiprotocol(V4), Capability::RouteRefresh],
        );
        let mut expected = vec![0xff; 16];
        expected.extend([0, 23, MessageType::RouteRefresh as u8, 0, 1, 0, 1]);
        let asked = vec![Output::RequestRoutes {
            peer: addr,
            families: vec![V4, AddressFamily::IPV6_UNICAST],
        }];
        deliver(asked, &table, &fib_tx);
        let next = |conn: &mut std::net::TcpStream| loop {
            let (kind, frame) = read_message(conn);
            if kind != MessageType::Keepalive as u8 {
                return frame;
            }
        };
        assert_eq!(next(&mut conn), expected);
        // Through the slot: the next input the peer thread handles finds
        // it. Had IPv6 gone out above, it would be read here instead.
        h.refresh.lock().unwrap().push(V4);
        let (report, _) = sync_channel(1);
        h.tx.send(PeerInput::Report(report)).unwrap();
        assert_eq!(next(&mut conn), expected);
        assert!(h.refresh.lock().unwrap().is_empty());
        h.tx.send(PeerInput::Stop(
            bgpfc_wire::error::CeaseSubcode::AdministrativeShutdown,
        ))
        .unwrap();
    }

    #[test]
    fn a_request_for_routes_waits_in_the_slot_when_the_queue_is_full() {
        let addr = ip("192.0.2.1");
        let (h, rx) = handle_on_queue(addr);
        let table: PeerTable = std::sync::Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::from([(addr, h.clone())]),
        ));
        let (fib_tx, _fib_rx) = sync_channel(4);
        let ask = |families: Vec<AddressFamily>| {
            vec![Output::RequestRoutes {
                peer: addr,
                families,
            }]
        };
        deliver(ask(vec![V4]), &table, &fib_tx);
        assert!(matches!(rx.try_recv(), Ok(PeerInput::RequestRoutes(f)) if f == [V4]));
        // The queue full: the families wait in the slot, each once.
        h.tx.try_send(PeerInput::SoftReset).unwrap();
        let v6 = AddressFamily::IPV6_UNICAST;
        deliver(ask(vec![V4]), &table, &fib_tx);
        deliver(ask(vec![V4, v6]), &table, &fib_tx);
        assert_eq!(*h.refresh.lock().unwrap(), vec![V4, v6]);
        assert!(matches!(rx.try_recv(), Ok(PeerInput::SoftReset)));
        assert!(rx.try_recv().is_err());
        // An unknown peer: nothing to ask.
        let other = vec![Output::RequestRoutes {
            peer: ip("192.0.2.9"),
            families: vec![V4],
        }];
        deliver(other, &table, &fib_tx);
    }

    /// A configuration with neighbor 192.0.2.1 under import policy `IN`
    /// and export policy `OUT`, as `policies` defines them, and the
    /// internal 192.0.2.2 under `OUT` and an import policy that takes all.
    fn policy_config(policies: &str) -> bgpfc_config::Config {
        bgpfc_config::parse_str(
            "t",
            &format!(
                "router-id 192.0.2.254; local-as 65000; {policies}
                 policy ALL {{ term all {{ action accept; }} }}
                 neighbor 192.0.2.1 {{ remote-as 65001; import IN; export OUT; }}
                 neighbor 192.0.2.2 {{ remote-as 65000; import ALL; export OUT; }}"
            ),
        )
        .unwrap()
    }

    /// What a reload from `old` to `new` tells the RIB thread about the
    /// policies, as the coordinator builds it.
    fn set_policies(old: &bgpfc_config::Config, new: &bgpfc_config::Config) -> RibMsg {
        let diff = bgpfc_config::diff::ConfigDiff::between(old, new);
        RibMsg::SetPolicies {
            policies: crate::messages::NewPolicies(Box::new(
                bgpfc_policy::Engine::new(new).unwrap(),
            )),
            reimport: diff.import_changed,
            reexport: diff.export_changed,
        }
    }

    #[test]
    fn a_policy_reload_imports_again_with_no_route_refresh() {
        // RFC 4271 §3 (a): a new import policy for 192.0.2.1 applies to
        // its routes at once, from the Adj-RIB-In; an export change alone
        // imports nothing; only the route import policy dropped needs the
        // peer again, and is asked for (§3 (b), RFC 2918 §4).
        let accept = "policy IN { term all { action accept; } }
                      policy OUT { term all { action accept; } }";
        let strict = "policy IN {
                          term drop { match prefix 198.51.100.0/24; action reject; }
                          term all { set local-pref 200; action accept; }
                      }
                      policy OUT { term all { action accept; } }";
        let tagged = "policy IN { term all { action accept; } }
                      policy OUT { term all { set med 7; action accept; } }";
        let (a, b, c) = (
            policy_config(accept),
            policy_config(strict),
            policy_config(tagged),
        );
        let now = Instant::now();
        let mut rib = Rib::with_policies(
            Asn(65_000),
            Box::new(bgpfc_policy::Engine::new(&a).unwrap()),
        );
        let mut settings = RibSettings::default();
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.2", 65_000, PeerKind::Internal),
            now,
        );
        let msg = routes("192.0.2.1", 65_001, &["198.51.100.0/24", "203.0.113.0/24"]);
        handle(&mut rib, &mut settings, msg, now);
        let asked = |out: &[Output]| -> Vec<(IpAddr, Vec<AddressFamily>)> {
            out.iter()
                .filter_map(|o| match o {
                    Output::RequestRoutes { peer, families } => Some((*peer, families.clone())),
                    _ => None,
                })
                .collect()
        };

        let out = handle(&mut rib, &mut settings, set_policies(&a, &b), now);
        let Some(Output::Reimported(r)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!(r.peers, vec![ip("192.0.2.1")]);
        assert_eq!((r.routes, r.changed, r.dropped), (2, 2, 1));
        assert_eq!(asked(&out), vec![]);
        assert_eq!(rib.loc_rib(V4).count(), 1);
        let (_, best) = rib.loc_rib(V4).next().unwrap();
        assert_eq!(best.attrs.local_pref, Some(200));

        // Back: the dropped route only the peer can send again.
        let out = handle(&mut rib, &mut settings, set_policies(&b, &a), now);
        let Some(Output::Reimported(r)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!(r.refresh, vec![(ip("192.0.2.1"), V4)]);
        assert_eq!(asked(&out), vec![(ip("192.0.2.1"), vec![V4])]);
        let (_, best) = rib.loc_rib(V4).next().unwrap();
        assert_eq!(best.attrs.local_pref, None);

        // An export change alone: sent again to both, imported again from
        // neither, no ROUTE-REFRESH.
        let out = handle(&mut rib, &mut settings, set_policies(&a, &c), now);
        assert!(
            !out.iter()
                .any(|o| matches!(o, Output::Reimported(_) | Output::RequestRoutes { .. })),
            "{out:?}"
        );
        assert_eq!(rib.loc_rib(V4).count(), 1);
    }

    #[test]
    fn a_reimport_is_one_info_line() {
        // RFC 4271 §3: a peer's routes imported again under its new import
        // policy, counted in one line, with the families asked for again.
        let r = bgpfc_rib::Reimport {
            peers: vec![ip("192.0.2.1"), ip("2001:db8::2")],
            routes: 1000,
            changed: 10,
            held: 1,
            released: 2,
            dropped: 3,
            best_changed: 12,
            refresh: vec![
                (ip("192.0.2.1"), V4),
                (ip("2001:db8::2"), AddressFamily::IPV6_UNICAST),
            ],
            missing: vec![],
        };
        assert_eq!(
            formatted(bgpfc_log::Level::Info, REIMPORTED, &reimported(&r)),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: re-import\" \
             peers=192.0.2.1,2001:db8::2 routes=1000 changed=10 held=1 released=2 \
             dropped=3 best_changed=12 \
             refresh=ipv4-unicast@192.0.2.1,ipv6-unicast@2001:db8::2\n"
        );
        let none = bgpfc_rib::Reimport {
            peers: vec![ip("192.0.2.1")],
            ..bgpfc_rib::Reimport::default()
        };
        assert_eq!(reimported(&none)[7], ("refresh", "none".to_owned()));
    }

    #[test]
    fn an_incorrect_mp_attribute_disables_its_family_and_keeps_the_session() {
        // RFC 4760 §7 through a real peer thread on loopback: an UPDATE
        // with an IPv4 route in its NLRI field and an MP_REACH_NLRI whose
        // next hop length is wrong for IPv6 (RFC 7606 §7.11). The RIB gets
        // the IPv4 route with IPv6 disabled, and no NOTIFICATION is sent.
        use bgpfc_wire::as_path::AsPath;
        use bgpfc_wire::attribute::{Origin, PathAttribute};
        use bgpfc_wire::header::{MessageType, frame};
        use bgpfc_wire::update::{EncodeContext, UpdateMessage};
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ip("127.0.0.1");
        let mut fsm = bgpfc_fsm::Config::new(Asn(65_000), RouterId::new(1).unwrap(), Asn(65_001));
        fsm.capabilities = vec![bgpfc_wire::capability::Capability::Multiprotocol(V4)];
        let cfg = crate::peer::PeerConfig {
            addr,
            port: listener.local_addr().unwrap().port(),
            fsm,
            allow_as_set: false,
            ttl: None,
            local: None,
            single_hop: false,
        };
        let (rib_tx, rib_rx) = sync_channel(64);
        let (h, peer) = crate::peer::prepare(cfg, rib_tx);
        peer.start();
        let mut conn = establish(&listener, &rib_rx);
        let route: bgpfc_wire::prefix::Prefix = "198.51.100.0/24".parse().unwrap();
        let m = UpdateMessage {
            nlri: vec![route],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
                PathAttribute::NextHop("192.0.2.7".parse().unwrap()),
            ],
            ..UpdateMessage::default()
        };
        let enc = EncodeContext {
            four_octet_as: true,
            extended_next_hop: false,
        };
        let mut body = m.encode(&enc).unwrap();
        let bad_reach = [0x80, 14, 9, 0, 2, 1, 4, 1, 2, 3, 4, 0];
        body[3] += 12;
        body.splice(4..4, bad_reach);
        conn.write_all(&frame(MessageType::Update, &body).unwrap())
            .unwrap();
        match rib_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(RibMsg::Update { peer, update, .. }) => {
                assert_eq!(peer, addr);
                assert_eq!(update.disabled.len(), 1);
                assert!(update.disables(AddressFamily::IPV6_UNICAST));
                assert_eq!(update.treated_as_withdraw, None, "{update:?}");
                assert_eq!(update.announcements().collect::<Vec<_>>(), [(V4, route)]);
            }
            other => panic!("expected the UPDATE, got {other:?}"),
        }
        // What bgpfcd sends from here on (the KEEPALIVE that completed
        // the session among it) holds no NOTIFICATION, and the session
        // does not end.
        conn.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        loop {
            let mut header = [0u8; 19];
            match conn.read_exact(&mut header) {
                Ok(()) => {
                    assert_ne!(header[18], MessageType::Notification as u8);
                    let len = usize::from(u16::from_be_bytes([header[16], header[17]]));
                    let mut body = vec![0u8; len - 19];
                    conn.read_exact(&mut body).unwrap();
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(e) => panic!("the session ended: {e:?}"),
            }
        }
        assert!(rib_rx.try_recv().is_err());
        h.tx.send(PeerInput::Stop(
            bgpfc_wire::error::CeaseSubcode::AdministrativeShutdown,
        ))
        .unwrap();
    }

    #[test]
    fn waits_for_a_message_or_the_deadline() {
        let (tx, rx) = sync_channel(4);
        let down = || RibMsg::PeerDown {
            peer: ip("192.0.2.1"),
        };
        tx.send(down()).unwrap();
        assert!(matches!(next(&rx, None), Ok(Some(RibMsg::PeerDown { .. }))));
        // A deadline already passed: no wait.
        assert!(matches!(next(&rx, Some(Instant::now())), Ok(None)));
        // A deadline ahead: the thread sleeps until it.
        let start = Instant::now();
        let deadline = start + Duration::from_millis(50);
        assert!(matches!(next(&rx, Some(deadline)), Ok(None)));
        assert!(Instant::now() >= deadline);
        // A message wakes it before a later deadline.
        tx.send(down()).unwrap();
        let later = Some(Instant::now() + Duration::from_secs(60));
        assert!(matches!(next(&rx, later), Ok(Some(_))));
        drop(tx);
        assert!(matches!(next(&rx, None), Err(Closed)));
        assert!(matches!(next(&rx, later), Err(Closed)));
    }

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> bgpfc_rpki::Vrp {
        bgpfc_rpki::Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
    }

    /// Validation on, from `vrps`: every route affected.
    fn all(vrps: &[bgpfc_rpki::Vrp]) -> ValidationChange {
        let set: bgpfc_rpki::VrpSet = vrps.iter().copied().collect();
        ValidationChange {
            source: std::sync::Arc::new(set),
            affected: AffectedPrefixes::All,
        }
    }

    /// The IPv4 Loc-RIB, as the control plane is told it: each route with
    /// its validation state.
    fn states(rib: &Rib) -> Vec<(String, RovState)> {
        let q = RibQuery::Routes {
            family: V4,
            prefix: None,
            after: None,
            held: false,
        };
        match answer(rib, &Transitions::default(), &q) {
            RibReply::Routes(routes) => routes
                .iter()
                .map(|r| (r.prefix.to_string(), r.rov))
                .collect(),
            other => panic!("asked for routes, got {other:?}"),
        }
    }

    /// The changes of state reported among `out`.
    fn rov_changes(out: &[Output]) -> Vec<(RovState, RovState, usize)> {
        out.iter()
            .find_map(|o| match o {
                Output::Revalidated(r) => Some(r.changes.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    #[test]
    fn validation_changes_on_the_channel_validate_the_routes_again() {
        // RFC 6811 §4 through the RIB thread's channel: a change sent on
        // it is a message `handle` applies, and the states of the affected
        // routes follow it in place. The invalid route stays in the
        // Loc-RIB (RFC 6811 §2).
        use RovState::{Disabled, Invalid, NotFound, Valid};
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        let msg = routes("192.0.2.1", 65_001, &["198.51.100.0/24", "203.0.113.0/24"]);
        handle(&mut rib, &mut settings, msg, now);
        let s = |p: &str, rov| (p.to_owned(), rov);
        assert_eq!(
            states(&rib),
            [
                s("198.51.100.0/24", Disabled),
                s("203.0.113.0/24", Disabled)
            ]
        );
        let (tx, rx) = sync_channel(4);
        let mut apply = |rib: &mut Rib, change| {
            tx.send(RibMsg::Validation(change)).unwrap();
            handle(rib, &mut settings, rx.try_recv().unwrap(), now)
        };
        // Validation on: AS 65001 may originate the first prefix, and only
        // AS 64496 the second.
        let gone = vrp("203.0.113.0/24", 24, 64_496);
        let out = apply(&mut rib, all(&[vrp("198.51.100.0/24", 24, 65_001), gone]));
        assert_eq!(
            rov_changes(&out),
            [(Disabled, Valid, 1), (Disabled, Invalid, 1)]
        );
        assert_eq!(
            states(&rib),
            [s("198.51.100.0/24", Valid), s("203.0.113.0/24", Invalid)]
        );
        // A delta: the VRP that made the second route invalid goes, and
        // only that route is validated again.
        let out = apply(
            &mut rib,
            ValidationChange {
                source: std::sync::Arc::new(
                    [vrp("198.51.100.0/24", 24, 65_001)]
                        .into_iter()
                        .collect::<bgpfc_rpki::VrpSet>(),
                ),
                affected: AffectedPrefixes::from_vrps([gone]),
            },
        );
        assert_eq!(rov_changes(&out), [(Invalid, NotFound, 1)]);
        assert_eq!(
            states(&rib),
            [s("198.51.100.0/24", Valid), s("203.0.113.0/24", NotFound)]
        );
        // Off again.
        let out = apply(&mut rib, ValidationChange::disabled());
        assert_eq!(
            rov_changes(&out),
            [(Valid, Disabled, 1), (NotFound, Disabled, 1)]
        );
        assert_eq!(
            states(&rib),
            [
                s("198.51.100.0/24", Disabled),
                s("203.0.113.0/24", Disabled)
            ]
        );
        // The best routes stayed the same, so the FIB hears nothing; the
        // changes are only logged.
        let (fib_tx, fib_rx) = sync_channel(4);
        deliver(out, &PeerTable::default(), &fib_tx);
        assert!(fib_rx.try_recv().is_err());
        assert_eq!(describe_affected(&AffectedPrefixes::All), "all");
        assert_eq!(describe_affected(&AffectedPrefixes::from_vrps([gone])), "1");
    }

    #[test]
    fn the_rib_thread_applies_validation_changes_in_order_with_updates() {
        // The thread itself: changes interleave with UPDATEs and queries
        // on one channel and take effect in the order they were sent.
        use RovState::{Disabled, Invalid, Valid};
        let (tx, rx) = sync_channel(16);
        let (fib_tx, fib_rx) = sync_channel(16);
        spawn(
            Rib::new(Asn(65_000)),
            RibSettings::default(),
            rx,
            PeerTable::default(),
            fib_tx,
        );
        let query = |tx: &SyncSender<RibMsg>| {
            let (reply, answer) = sync_channel(1);
            let q = RibQuery::Routes {
                family: V4,
                prefix: None,
                after: None,
                held: false,
            };
            tx.send(RibMsg::Query(q, reply)).unwrap();
            match answer.recv_timeout(Duration::from_secs(10)) {
                Ok(RibReply::Routes(routes)) => routes
                    .iter()
                    .map(|r| (r.prefix.to_string(), r.rov))
                    .collect::<Vec<_>>(),
                other => panic!("expected routes, got {other:?}"),
            }
        };
        tx.send(up("192.0.2.1", 65_001, PeerKind::External))
            .unwrap();
        // Validation is on before the routes arrive: they get their state
        // as they arrive.
        tx.send(RibMsg::Validation(all(&[
            vrp("198.51.100.0/24", 24, 65_001),
            vrp("203.0.113.0/24", 24, 64_496),
        ])))
        .unwrap();
        tx.send(routes(
            "192.0.2.1",
            65_001,
            &["198.51.100.0/24", "203.0.113.0/24"],
        ))
        .unwrap();
        let s = |p: &str, rov| (p.to_owned(), rov);
        assert_eq!(
            query(&tx),
            [s("198.51.100.0/24", Valid), s("203.0.113.0/24", Invalid)]
        );
        tx.send(RibMsg::Validation(ValidationChange::disabled()))
            .unwrap();
        assert_eq!(
            query(&tx),
            [
                s("198.51.100.0/24", Disabled),
                s("203.0.113.0/24", Disabled)
            ]
        );
        // Both routes reached the FIB, the invalid one too: a RIB acts on
        // no state until it is given an enforcement mode, which `wiring`
        // does from the `rpki` block. Turning validation off changed no
        // best route.
        let installed: Vec<_> = fib_rx
            .try_iter()
            .flat_map(|m| match m {
                FibMsg::Changes { changes, .. } => {
                    changes.into_iter().map(|c| c.prefix.to_string())
                }
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(installed, ["198.51.100.0/24", "203.0.113.0/24"]);
    }

    /// The line [`log_line`] writes, at the epoch.
    fn formatted(level: bgpfc_log::Level, msg: &str, values: &[(&'static str, String)]) -> String {
        let fields: Vec<bgpfc_log::Field<'_>> = values
            .iter()
            .map(|(k, v)| (*k, v as &dyn std::fmt::Display))
            .collect();
        bgpfc_log::format_line(std::time::UNIX_EPOCH, level, msg, &fields)
    }

    /// The FIB thread logs a line per input (`crate::fib`, "Logging"):
    /// an input's changes go in batches of [`FIB_BATCH`] at most, all but
    /// the last marked `more`, and one that filled its last batch exactly
    /// ends with an empty one.
    #[test]
    fn the_last_fib_batch_of_an_input_is_marked() {
        let change = |i: usize| {
            Output::Fib(FibChange {
                family: V4,
                prefix: format!("10.{}.{}.0/24", i / 256, i % 256).parse().unwrap(),
                next_hop: Some(ip("192.0.2.1")),
                previous: None,
            })
        };
        for (n, want) in [
            (0, vec![]),
            (1, vec![(1, false)]),
            (FIB_BATCH - 1, vec![(FIB_BATCH - 1, false)]),
            (FIB_BATCH, vec![(FIB_BATCH, true), (0, false)]),
            (
                2 * FIB_BATCH + 3,
                vec![(FIB_BATCH, true), (FIB_BATCH, true), (3, false)],
            ),
        ] {
            let (fib_tx, fib_rx) = sync_channel(8);
            deliver((0..n).map(change).collect(), &PeerTable::default(), &fib_tx);
            let batches: Vec<(usize, bool)> = fib_rx
                .try_iter()
                .map(|m| match m {
                    FibMsg::Changes { changes, more } => (changes.len(), more),
                    other => panic!("unexpected {other:?}"),
                })
                .collect();
            assert_eq!(batches, want, "{n} changes");
        }
        // The next input starts afresh.
        let (fib_tx, fib_rx) = sync_channel(8);
        let mut out = Deliver {
            peers: &PeerTable::default(),
            fib: &fib_tx,
            changes: Vec::new(),
            open: false,
        };
        for i in 0..FIB_BATCH {
            out.put(change(i));
        }
        out.flush();
        out.flush();
        out.put(change(0));
        out.flush();
        let batches: Vec<(usize, bool)> = fib_rx
            .try_iter()
            .map(|m| match m {
                FibMsg::Changes { changes, more } => (changes.len(), more),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(batches, [(FIB_BATCH, true), (0, false), (1, false)]);
    }

    #[test]
    fn a_validation_change_is_one_info_line_however_many_routes_it_moved() {
        let line =
            |r: &Revalidation| formatted(bgpfc_log::Level::Info, REVALIDATED, &revalidated(r));
        let p = |s: &str| -> Prefix { s.parse().unwrap() };
        // A full table turned on: counts, and the first destinations.
        let sample: Vec<Prefix> = (0..8).map(|i| p(&format!("1.0.{i}.0/24"))).collect();
        let on = Revalidation {
            routes: 1_250_000,
            changes: vec![
                (RovState::Disabled, RovState::Valid, 600_000),
                (RovState::Disabled, RovState::Invalid, 50_000),
                (RovState::Disabled, RovState::NotFound, 600_000),
            ],
            destinations: 1_000_000,
            sample,
            best_changed: 2,
            ..Default::default()
        };
        assert_eq!(
            line(&on),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: validation states changed\" \
             routes=1250000 changed=1250000 \
             changes=disabled->valid:600000,disabled->invalid:50000,disabled->not-found:600000 \
             destinations=1000000 \
             prefixes=1.0.0.0/24,1.0.1.0/24,1.0.2.0/24,1.0.3.0/24,1.0.4.0/24,1.0.5.0/24,\
             1.0.6.0/24,1.0.7.0/24,... best_changed=2 held=0 released=0 \
             logged=0 unlogged=0\n"
        );
        // A small delta: every destination named.
        let delta = Revalidation {
            routes: 3,
            changes: vec![(RovState::NotFound, RovState::Invalid, 2)],
            destinations: 1,
            sample: vec![p("2001:db8::/32")],
            best_changed: 0,
            ..Default::default()
        };
        assert_eq!(
            line(&delta),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: validation states changed\" \
             routes=3 changed=2 changes=not-found->invalid:2 destinations=1 \
             prefixes=2001:db8::/32 best_changed=0 held=0 released=0 logged=0 unlogged=0\n"
        );
        // Under drop-invalid the two invalid routes were taken out of use
        // and a third put back (RFC 6811 §5): the same line, counted.
        let enforced = Revalidation {
            changes: vec![
                (RovState::NotFound, RovState::Invalid, 2),
                (RovState::Invalid, RovState::Valid, 1),
            ],
            held: 2,
            released: 1,
            best_changed: 1,
            ..delta
        };
        assert_eq!(
            line(&enforced),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: validation states changed\" \
             routes=3 changed=3 changes=not-found->invalid:2,invalid->valid:1 destinations=1 \
             prefixes=2001:db8::/32 best_changed=1 held=2 released=1 logged=0 unlogged=0\n"
        );
        assert_eq!(listed(&[], 0), "");
    }

    #[test]
    fn set_enforcement_message_rejudges_and_logs_one_line() {
        // A reload's new mode through the channel (RFC 6811 §5): every
        // route judged again, one report first, then what changed.
        use bgpfc_rib::Enforcement;
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        let msg = routes("192.0.2.1", 65_001, &["198.51.100.0/24", "203.0.113.0/24"]);
        handle(&mut rib, &mut settings, msg, now);
        let on = all(&[vrp("203.0.113.0/24", 24, 64_496)]);
        handle(&mut rib, &mut settings, RibMsg::Validation(on), now);
        let (tx, rx) = sync_channel(4);
        let mut send = |rib: &mut Rib, mode| {
            tx.send(RibMsg::SetEnforcement(mode)).unwrap();
            handle(rib, &mut settings, rx.try_recv().unwrap(), now)
        };
        let out = send(&mut rib, Enforcement::DropInvalid);
        let reports: Vec<&bgpfc_rib::Rejudged> = out
            .iter()
            .filter_map(|o| match o {
                Output::Enforcement(r) => Some(r),
                _ => None,
            })
            .collect();
        assert_eq!(reports.len(), 1, "{out:?}");
        assert!(matches!(out[0], Output::Enforcement(_)), "{out:?}");
        assert_eq!(
            formatted(
                bgpfc_log::Level::Info,
                ENFORCEMENT_CHANGED,
                &rejudged(reports[0])
            ),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: rpki enforcement changed\" \
             from=off to=drop-invalid routes=2 held=1 released=0 best_changed=1\n"
        );
        assert!(
            matches!(&out[1..], [Output::Fib(c)] if c.prefix.to_string() == "203.0.113.0/24"),
            "{out:?}"
        );
        assert_eq!(rib.enforcement(), Enforcement::DropInvalid);
        // The same mode again: nothing to do, nothing logged.
        assert_eq!(send(&mut rib, Enforcement::DropInvalid), vec![]);
        // prefer-valid uses the invalid route again, last in rank.
        let out = send(&mut rib, Enforcement::PreferValid);
        assert!(
            matches!(&out[..], [Output::Enforcement(r), Output::Fib(_)] if r.released == 1),
            "{out:?}"
        );
    }

    #[test]
    fn an_enforcement_change_is_one_info_line() {
        // RFC 6811 §5: the operator's mode applied to routes the RIB
        // holds. Validation on, then the mode: the invalid route of two is
        // held under drop-invalid, the destination losing its only route.
        use bgpfc_rib::Enforcement;
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        let msg = routes("192.0.2.1", 65_001, &["198.51.100.0/24", "203.0.113.0/24"]);
        handle(&mut rib, &mut settings, msg, now);
        let on = all(&[
            vrp("198.51.100.0/24", 24, 65_001),
            vrp("203.0.113.0/24", 24, 64_496),
        ]);
        handle(&mut rib, &mut settings, RibMsg::Validation(on), now);
        let mut out = Vec::new();
        rib.set_enforcement(Enforcement::DropInvalid, now, &mut out);
        let Some(Output::Enforcement(r)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!(
            formatted(bgpfc_log::Level::Info, ENFORCEMENT_CHANGED, &rejudged(r)),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: rpki enforcement changed\" \
             from=off to=drop-invalid routes=2 held=1 released=0 best_changed=1\n"
        );
        // The withdrawn destination reaches the FIB after the line.
        let (fib_tx, fib_rx) = sync_channel(4);
        deliver(out, &PeerTable::default(), &fib_tx);
        match fib_rx.try_recv() {
            Ok(FibMsg::Changes { changes: c, more }) => {
                assert!(!more);
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].prefix.to_string(), "203.0.113.0/24");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            states(&rib),
            [("198.51.100.0/24".to_owned(), RovState::Valid)]
        );
        // And back: released, the route used again with no UPDATE.
        let mut out = Vec::new();
        rib.set_enforcement(Enforcement::Off, now, &mut out);
        let Some(Output::Enforcement(r)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!(
            rejudged(r).map(|(_, v)| v),
            ["drop-invalid", "off", "2", "0", "1", "1"].map(str::to_owned)
        );
        assert_eq!(states(&rib).len(), 2);
    }

    #[test]
    fn a_startup_message_is_one_info_line() {
        // RFC 6811 §2: with no validation data yet, every route is
        // `disabled`; `startup hold` through the channel holds both, and
        // `accept` uses them again, each change in one line.
        use bgpfc_rib::Startup;
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        let msg = routes("192.0.2.1", 65_001, &["198.51.100.0/24", "203.0.113.0/24"]);
        handle(&mut rib, &mut settings, msg, now);
        let out = handle(
            &mut rib,
            &mut settings,
            RibMsg::SetStartup(Startup::Hold),
            now,
        );
        let Some(Output::Startup(r)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!(
            formatted(bgpfc_log::Level::Info, STARTUP_CHANGED, &startup_changed(r)),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: rpki startup changed\" \
             from=accept to=hold routes=2 held=2 released=0 best_changed=2\n"
        );
        // Both destinations lose their only route, after the line.
        let (fib_tx, fib_rx) = sync_channel(4);
        deliver(out, &PeerTable::default(), &fib_tx);
        match fib_rx.try_recv() {
            Ok(FibMsg::Changes { changes: c, more }) => {
                assert!(!more);
                assert_eq!(c.len(), 2);
                assert!(c.iter().all(|c| c.next_hop.is_none()), "{c:?}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(states(&rib), []);
        // The same setting again: nothing to do, nothing logged.
        let again = RibMsg::SetStartup(Startup::Hold);
        assert_eq!(handle(&mut rib, &mut settings, again, now), vec![]);
        let out = handle(
            &mut rib,
            &mut settings,
            RibMsg::SetStartup(Startup::Accept),
            now,
        );
        let Some(Output::Startup(r)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!(
            startup_changed(r).map(|(_, v)| v),
            ["hold", "accept", "2", "0", "2", "2"].map(str::to_owned)
        );
        assert_eq!(states(&rib).len(), 2);
    }

    /// The lines of `lines` as the log writes them, at the epoch.
    fn written(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|l| formatted(l.level, l.msg, &l.fields))
            .collect()
    }

    #[test]
    fn a_small_change_logs_a_line_per_route_after_the_summary() {
        // Issue #59: each route a VRP change moved among valid, invalid
        // and not-found, with its time, after the summary of the change.
        // Under drop-invalid one route becomes Invalid and is held, the
        // other leaves Invalid and is used again.
        use bgpfc_rib::Enforcement;
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        rib.set_enforcement(Enforcement::DropInvalid, now, &mut Vec::new());
        let mut settings = RibSettings::default();
        let mut kept = Transitions::default();
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.1", 65_001, PeerKind::External),
            now,
        );
        let msg = routes("192.0.2.1", 65_001, &["198.51.100.0/24", "203.0.113.0/24"]);
        handle(&mut rib, &mut settings, msg, now);
        let mut apply = |rib: &mut Rib, change| {
            handle_with(
                rib,
                &mut settings,
                &mut kept,
                RibMsg::Validation(change),
                now,
            )
        };
        // Validation switched on: disabled->X, counted and not listed.
        let theirs = vrp("203.0.113.0/24", 24, 64_496);
        let ours = vrp("198.51.100.0/24", 24, 65_001);
        let out = apply(&mut rib, all(&[ours, theirs]));
        let Some(Output::Revalidated(r)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!(written(&revalidation_lines(r, true)).len(), 1);
        // The VRPs trade places.
        let change = ValidationChange {
            source: std::sync::Arc::new(
                [
                    vrp("198.51.100.0/24", 24, 64_496),
                    vrp("203.0.113.0/24", 24, 65_001),
                ]
                .into_iter()
                .collect::<bgpfc_rpki::VrpSet>(),
            ),
            affected: AffectedPrefixes::from_vrps([ours, theirs]),
        };
        let out = apply(&mut rib, change);
        let Some(Output::Revalidated(r)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!(
            written(&revalidation_lines(r, false)),
            [
                "1970-01-01T00:00:00.000Z INFO  msg=\"rib: validation states changed\" \
                 routes=2 changed=2 changes=valid->invalid:1,invalid->valid:1 \
                 destinations=2 prefixes=198.51.100.0/24,203.0.113.0/24 best_changed=2 \
                 held=1 released=1 logged=2 unlogged=0\n",
                "1970-01-01T00:00:00.000Z INFO  msg=\"rib: route validation state changed\" \
                 prefix=198.51.100.0/24 peer=192.0.2.1 origin=AS65001 from=valid to=invalid \
                 route=held by=enforcement\n",
                "1970-01-01T00:00:00.000Z INFO  msg=\"rib: route validation state changed\" \
                 prefix=203.0.113.0/24 peer=192.0.2.1 origin=AS65001 from=invalid to=valid \
                 route=best\n",
            ]
        );
        // Nothing more at debug: every listed move has its info line.
        assert_eq!(revalidation_lines(r, true), revalidation_lines(r, false));
        // Both kept, with the moment the change was applied.
        let report = kept.report();
        assert_eq!((report.capacity, report.unrecorded), (KEPT, 0));
        let moved: Vec<_> = report
            .entries
            .iter()
            .map(|e| {
                assert_eq!(e.when, now);
                (
                    e.transition.prefix.to_string(),
                    e.transition.from,
                    e.transition.to,
                    e.transition.route,
                )
            })
            .collect();
        assert_eq!(
            moved,
            [
                (
                    "198.51.100.0/24".to_owned(),
                    RovState::Valid,
                    RovState::Invalid,
                    RouteStatus::Held(bgpfc_rib::Held::Enforcement)
                ),
                (
                    "203.0.113.0/24".to_owned(),
                    RovState::Invalid,
                    RovState::Valid,
                    RouteStatus::Best
                ),
            ]
        );
    }

    /// `n` routes of AS 65001 from 192.0.2.1 moved from valid to invalid,
    /// the i-th to 10.x.y.0/24 for i = 256 x + y, starting at `first`.
    fn moved(first: usize, n: usize) -> Vec<Transition> {
        (first..first + n)
            .map(|i| {
                let [_, _, x, y] = u32::try_from(i).unwrap().to_be_bytes();
                Transition {
                    family: V4,
                    prefix: format!("10.{x}.{y}.0/24").parse().unwrap(),
                    peer: ip("192.0.2.1"),
                    origin: bgpfc_rpki::RouteOrigin::As(Asn(65_001)),
                    from: RovState::Valid,
                    to: RovState::Invalid,
                    route: RouteStatus::Candidate,
                }
            })
            .collect()
    }

    #[test]
    fn a_large_change_logs_a_hundred_lines_and_counts_the_rest() {
        // A change that moves more routes than the RIB lists: the first
        // LOGGED at info, the rest listed at debug, the others counted.
        let r = Revalidation {
            routes: 2000,
            changes: vec![(RovState::Valid, RovState::Invalid, 2000)],
            destinations: 2000,
            transitions: moved(0, Revalidation::LISTED),
            unlisted: 2000 - Revalidation::LISTED,
            ..Default::default()
        };
        let info = revalidation_lines(&r, false);
        assert_eq!(info.len(), 1 + LOGGED);
        assert!(info.iter().all(|l| l.level == Level::Info));
        let summary = &written(&info)[0];
        assert!(
            summary.ends_with(" logged=100 unlogged=1900\n"),
            "{summary}"
        );
        assert!(
            written(&info)[LOGGED].contains(" prefix=10.0.99.0/24 "),
            "{:?}",
            info[LOGGED]
        );
        // At debug, the rest of those listed, after them.
        let all = revalidation_lines(&r, true);
        assert_eq!(all.len(), 1 + Revalidation::LISTED);
        assert_eq!(all[..=LOGGED], info[..]);
        assert!(all[LOGGED + 1..].iter().all(|l| l.level == Level::Debug));
        assert_eq!(
            written(&all).last().map(String::as_str),
            Some(
                "1970-01-01T00:00:00.000Z DEBUG msg=\"rib: route validation state changed\" \
                 prefix=10.3.255.0/24 peer=192.0.2.1 origin=AS65001 from=valid to=invalid \
                 route=candidate\n"
            )
        );
        // A route dropped by the change, which import policy rejects in
        // every state, is not listed but counted.
        let dropped = Revalidation {
            transitions: moved(0, 3),
            unlisted: 1,
            ..Default::default()
        };
        assert!(
            written(&revalidation_lines(&dropped, true))[0].ends_with(" logged=3 unlogged=1\n")
        );
        // A route without an origin, as RFC 6811 §2 has NONE.
        let mut none = moved(0, 1);
        none[0].origin = bgpfc_rpki::RouteOrigin::None;
        none[0].route = RouteStatus::Held(bgpfc_rib::Held::Policy);
        let fields = transition(&none[0]);
        assert_eq!(fields[2], ("origin", "none".to_owned()));
        assert_eq!(
            fields[5..],
            [("route", "held".to_owned()), ("by", "policy".to_owned())]
        );
    }

    /// A route as `answer` lists it: prefix, peer, best, the looked-up
    /// state, the one set, and why it is held.
    type Listed = (
        String,
        String,
        bool,
        RovState,
        Option<RovState>,
        Option<bgpfc_rib::Held>,
    );

    /// What `answer` says to a routes query.
    fn listed_routes(rib: &Rib, q: &RibQuery) -> Vec<Listed> {
        match answer(rib, &Transitions::default(), q) {
            RibReply::Routes(routes) => routes
                .iter()
                .map(|r| {
                    (
                        r.prefix.to_string(),
                        r.peer.to_string(),
                        r.best,
                        r.rov,
                        r.rov_set,
                        r.held,
                    )
                })
                .collect(),
            other => panic!("asked for routes, got {other:?}"),
        }
    }

    /// A RIB under drop-invalid with VRPs for AS 64496 alone, and routes:
    /// 192.0.2.1 (AS 65001) to two prefixes, both Invalid and held;
    /// 192.0.2.2 (AS 64496) to 203.0.113.0/24, Valid; 192.0.2.3 (AS
    /// 65003) to 198.51.100.0/24, Invalid, which import policy sets valid
    /// (RFC 6811 §3).
    fn held_routes() -> Rib {
        use bgpfc_rib::Enforcement;
        let cfg = bgpfc_config::parse_str(
            "t",
            "router-id 192.0.2.254; local-as 65000;
             policy IN {
                 term pin { match neighbor 192.0.2.3; set rpki valid; action accept; }
                 term all { action accept; }
             }
             policy OUT { term all { action accept; } }
             neighbor 192.0.2.1 { remote-as 65001; import IN; export OUT; }
             neighbor 192.0.2.2 { remote-as 64496; import IN; export OUT; }
             neighbor 192.0.2.3 { remote-as 65003; import IN; export OUT; }",
        )
        .unwrap();
        let engine = bgpfc_policy::Engine::new(&cfg).unwrap();
        let now = Instant::now();
        let mut rib = Rib::with_policies(Asn(65_000), Box::new(engine));
        rib.set_enforcement(Enforcement::DropInvalid, now, &mut Vec::new());
        let mut settings = RibSettings::default();
        let on = all(&[
            vrp("203.0.113.0/24", 24, 64_496),
            vrp("198.51.100.0/24", 24, 64_496),
        ]);
        handle(&mut rib, &mut settings, RibMsg::Validation(on), now);
        let both: &[&str] = &["198.51.100.0/24", "203.0.113.0/24"];
        for (peer, peer_as, prefixes) in [
            ("192.0.2.1", 65_001, both),
            ("192.0.2.2", 64_496, &both[1..]),
            ("192.0.2.3", 65_003, &both[..1]),
        ] {
            let msg = up(peer, peer_as, PeerKind::External);
            handle(&mut rib, &mut settings, msg, now);
            handle(
                &mut rib,
                &mut settings,
                routes(peer, peer_as, prefixes),
                now,
            );
        }
        rib
    }

    #[test]
    fn routes_query_lists_held_routes() {
        // RFC 6811 §2: under drop-invalid the Adj-RIB-In keeps the Invalid
        // route, which `show routes PREFIX` lists after the candidates and
        // `show routes held` alone; an import policy that sets the state
        // (RFC 6811 §3) shows it beside the one looked up.
        use RovState::{Invalid, Valid};
        let rib = held_routes();
        let query = |prefix: Option<&str>, held| RibQuery::Routes {
            family: V4,
            prefix: prefix.map(|p| p.parse().unwrap()),
            after: None,
            held,
        };
        let r = |p: &str, peer: &str, best, rov, set, held| {
            (p.to_owned(), peer.to_owned(), best, rov, set, held)
        };
        let by = Some(bgpfc_rib::Held::Enforcement);
        // Every route to a destination: the best, then the held one.
        assert_eq!(
            listed_routes(&rib, &query(Some("203.0.113.0/24"), false)),
            [
                r("203.0.113.0/24", "192.0.2.2", true, Valid, None, None),
                r("203.0.113.0/24", "192.0.2.1", false, Invalid, None, by),
            ]
        );
        // Import policy set valid on the route from 192.0.2.3, which is
        // used, and best; 192.0.2.1's own is held.
        assert_eq!(
            listed_routes(&rib, &query(Some("198.51.100.0/24"), false)),
            [
                r(
                    "198.51.100.0/24",
                    "192.0.2.3",
                    true,
                    Invalid,
                    Some(Valid),
                    None
                ),
                r("198.51.100.0/24", "192.0.2.1", false, Invalid, None, by),
            ]
        );
        // Only the held: of the destination, and of the family.
        assert_eq!(
            listed_routes(&rib, &query(Some("203.0.113.0/24"), true)),
            [r("203.0.113.0/24", "192.0.2.1", false, Invalid, None, by)]
        );
        let held = [
            r("198.51.100.0/24", "192.0.2.1", false, Invalid, None, by),
            r("203.0.113.0/24", "192.0.2.1", false, Invalid, None, by),
        ];
        assert_eq!(listed_routes(&rib, &query(None, true)), held);
        // The next page starts after a destination.
        let after = RibQuery::Routes {
            family: V4,
            prefix: None,
            after: Some("198.51.100.0/24".parse().unwrap()),
            held: true,
        };
        assert_eq!(listed_routes(&rib, &after), held[1..]);
        // The Loc-RIB has the best routes only.
        assert_eq!(
            listed_routes(&rib, &query(None, false)),
            [
                r(
                    "198.51.100.0/24",
                    "192.0.2.3",
                    true,
                    Invalid,
                    Some(Valid),
                    None
                ),
                r("203.0.113.0/24", "192.0.2.2", true, Valid, None, None),
            ]
        );
        assert_eq!(listed_routes(&rib, &query(Some("192.0.2.0/24"), false)), []);
    }

    #[test]
    fn a_page_of_held_routes_ends_between_destinations() {
        // `show routes held` takes the routes a page at a time, each page
        // after the last prefix of the one before: one that ended inside
        // a destination would lose the rest of its routes.
        use bgpfc_rib::Enforcement;
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        rib.set_enforcement(Enforcement::DropInvalid, now, &mut Vec::new());
        let mut settings = RibSettings::default();
        let on = all(&[vrp("10.0.0.0/8", 24, 64_496)]);
        handle(&mut rib, &mut settings, RibMsg::Validation(on), now);
        // One route to the first destination, two to each of the others:
        // the page reaches PAGE inside a destination.
        let prefixes: Vec<String> = (0..=PAGE / 2 + 1)
            .map(|i| {
                let [_, _, x, y] = u32::try_from(i).unwrap().to_be_bytes();
                format!("10.{x}.{y}.0/24")
            })
            .collect();
        let all_of: Vec<&str> = prefixes.iter().map(String::as_str).collect();
        for (peer, peer_as, sent) in [
            ("192.0.2.1", 65_001, &all_of[..]),
            ("192.0.2.2", 65_002, &all_of[1..]),
        ] {
            handle(
                &mut rib,
                &mut settings,
                up(peer, peer_as, PeerKind::External),
                now,
            );
            handle(&mut rib, &mut settings, routes(peer, peer_as, sent), now);
        }
        let page = |after: Option<&str>| {
            let q = RibQuery::Routes {
                family: V4,
                prefix: None,
                after: after.map(|p| p.parse().unwrap()),
                held: true,
            };
            listed_routes(&rib, &q)
        };
        let first = page(None);
        // 1 + 2 * 2047 routes, then both of the next destination's.
        assert_eq!(first.len(), PAGE + 1);
        let last = &prefixes[PAGE / 2];
        assert_eq!(first[PAGE - 1].0, *last);
        assert_eq!(first[PAGE].0, *last);
        let second = page(Some(last));
        assert_eq!(
            second
                .iter()
                .map(|r| (r.0.as_str(), r.1.as_str()))
                .collect::<Vec<_>>(),
            [
                (prefixes[PAGE / 2 + 1].as_str(), "192.0.2.1"),
                (prefixes[PAGE / 2 + 1].as_str(), "192.0.2.2")
            ]
        );
    }

    #[test]
    fn the_transition_ring_keeps_the_latest_1024() {
        let now = Instant::now();
        let at = std::time::UNIX_EPOCH + Duration::from_secs(1_791_030_896);
        let mut kept = Transitions::default();
        let report = |transitions, unlisted| Revalidation {
            transitions,
            unlisted,
            ..Default::default()
        };
        kept.record(&report(moved(0, 600), 0), at, now);
        assert_eq!(kept.report().entries.len(), 600);
        // Past the capacity, the oldest go first.
        kept.record(&report(moved(600, 600), 5), at, now);
        let r = kept.report();
        assert_eq!((r.capacity, r.unrecorded), (1024, 5));
        assert_eq!(r.entries.len(), KEPT);
        assert_eq!(r.entries[0].transition, moved(176, 1)[0]);
        assert_eq!(r.entries[KEPT - 1].transition, moved(1199, 1)[0]);
        // A change that lists the most the RIB lists replaces them all.
        kept.record(&report(moved(2000, Revalidation::LISTED), 7), at, now);
        let r = kept.report();
        assert_eq!(r.unrecorded, 12);
        assert_eq!(r.entries[0].transition, moved(2000, 1)[0]);
        assert!(r.entries.iter().all(|e| e.at == at && e.when == now));
        // The same through the channel's query.
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        let (tx, rx) = sync_channel(1);
        handle_with(
            &mut rib,
            &mut settings,
            &mut kept,
            RibMsg::Query(RibQuery::Transitions, tx),
            now,
        );
        match rx.try_recv() {
            Ok(RibReply::Transitions(answer)) => assert_eq!(answer, r),
            other => panic!("{other:?}"),
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_transition_ring_holds_about_90_kb() {
        // docs/control.md and `KEPT`: the ring is "about 90 KB", and a
        // `show rpki transitions` clones as much into its reply. Entries
        // have a fixed size, so the bound is the capacity times it.
        let entry = std::mem::size_of::<Recorded>();
        assert_eq!(entry, 88);
        let bytes = KEPT * entry;
        assert!((85_000..=95_000).contains(&bytes), "{bytes}");
    }
}
