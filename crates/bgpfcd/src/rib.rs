//! The RIB thread: the only owner of RIB state (AGENTS.md §3). It turns
//! peer messages into `bgpfc_rib::Rib` calls and delivers what comes out
//! as the RIB produces it: UPDATEs to peer threads, route changes to the
//! FIB thread in batches. Between messages it sleeps until the next RFC
//! 4271 §9.2.1.1 deadline and then releases the advertisements that were
//! held back; the pacing itself is `bgpfc_rib`'s. A peer over its RFC 4271
//! §6.7 prefix limit is told to end its session. Routes the RIB ignored
//! for a semantically incorrect next hop are logged (RFC 4271 §6.3), and
//! so is what a change of the validation source did to the routes' RFC
//! 6811 states, in one line per change.
//!
//! Changes of the validation source arrive on the same channel, as
//! [`RibMsg::Validation`], and go the way an UPDATE goes (RFC 6811 §4):
//! the RIB validates the affected routes again, and what follows is
//! delivered like any other output. The RIB starts with no source (every
//! route `disabled`) and keeps it until a change says otherwise.

use std::net::IpAddr;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_fsm::Session;
use bgpfc_rib::{FibChange, Output, PathLimit, PeerInfo, Revalidation, Rib, Sink};
use bgpfc_rpki::AffectedPrefixes;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::PeerKind;

use crate::coordinator::PeerTable;
use crate::messages::{
    FibMsg, Intervals, PAGE, PeerInput, RibMsg, RibQuery, RibReply, RibSettings, RouteReport,
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
    };
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
            handle(&mut rib, &mut settings, msg, now, fib, &mut out);
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

/// Apply one message to the RIB, its outputs going to `out`.
fn handle(
    rib: &mut Rib,
    settings: &mut RibSettings,
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
                role = session
                    .role
                    .map_or_else(|| "none".to_owned(), |r| r.to_string()),
                advertisement_interval = interval.as_secs()
            );
            let mut info = peer_info(peer, local_addr, &session, interval);
            info.prefix_limits = limits;
            info.add_path_send = add_path_send(settings, peer, &session.add_path_send);
            if !info.add_path_receive.is_empty() || !info.add_path_send.is_empty() {
                bgpfc_log::info!(
                    "rib: add-path",
                    peer = peer,
                    receive = families(&info.add_path_receive),
                    send = describe_path_limits(&info.add_path_send)
                );
            }
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
            let _ = reply.send(answer(rib, &q));
        }
        RibMsg::SetPolicies { policies, reexport } => {
            for peer in &reexport {
                bgpfc_log::info!("rib: re-export", peer = peer);
            }
            rib.set_policies(policies.0, &reexport, now, out);
        }
        RibMsg::SetIntervals(new) => {
            settings.intervals = new;
            follow_intervals(rib, settings, now, out);
        }
        RibMsg::SetPrefixLimits(new) => {
            settings.prefix_limits = new;
            follow_prefix_limits(rib, settings, now, out);
        }
        RibMsg::SetAddPathLimits(new) => {
            settings.add_path_send = new;
            follow_add_path_limits(rib, settings, now, out);
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
            rib.validation_changed(change, now, out);
        }
        // The changes of earlier messages went to the FIB first: the loop
        // hands them on after each.
        RibMsg::FibMode(mode, reply) => fib_mode(rib, fib, mode, reply),
    }
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
        for route in rib.fib_routes() {
            batch.push(route);
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

/// After a reload: running sessions send the number of paths the new file
/// says (RFC 7911 §5) without a reset. The families a session sends paths
/// for were negotiated in its OPEN, and a change to them reset it, so only
/// the number can differ here.
fn follow_add_path_limits(
    rib: &mut Rib,
    settings: &RibSettings,
    now: Instant,
    out: &mut impl Sink,
) {
    let up: Vec<(IpAddr, Vec<_>)> = rib
        .peers()
        .filter(|p| !p.add_path_send.is_empty())
        .map(|p| (p.addr, p.add_path_send.clone()))
        .collect();
    for (peer, old) in up {
        let families: Vec<_> = old.iter().map(|(f, _)| *f).collect();
        let limits = add_path_send(settings, peer, &families);
        if limits != old {
            bgpfc_log::info!(
                "rib: add-path send",
                peer = peer,
                limits = describe_path_limits(&limits)
            );
            rib.set_add_path_limits(peer, &limits, now, out);
        }
    }
}

/// How many paths `peer` is sent for each of `negotiated`, the families
/// both sides agreed to exchange Path Identifiers for in the OPEN (RFC 7911
/// §5). A family the file no longer configures, which only a reload racing
/// the reset of the session can leave, still has to be encoded with
/// identifiers, so it sends its best path alone.
fn add_path_send(
    settings: &RibSettings,
    peer: IpAddr,
    negotiated: &[AddressFamily],
) -> Vec<(AddressFamily, PathLimit)> {
    let configured = settings.add_path_send.get(&peer);
    negotiated
        .iter()
        .map(|family| {
            let limit = configured
                .and_then(|l| l.iter().find(|(f, _)| f == family))
                .map_or(PathLimit::Best(1), |(_, l)| *l);
            (*family, limit)
        })
        .collect()
}

/// `ipv4-unicast,ipv6-unicast` for a log line; `none` if empty.
fn families(families: &[AddressFamily]) -> String {
    if families.is_empty() {
        return "none".to_owned();
    }
    families
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// `ipv4-unicast=all,ipv6-unicast=2` for a log line; `none` if empty.
fn describe_path_limits(limits: &[(AddressFamily, PathLimit)]) -> String {
    if limits.is_empty() {
        return "none".to_owned();
    }
    limits
        .iter()
        .map(|(f, l)| match l {
            PathLimit::All => format!("{f}=all"),
            PathLimit::Best(n) => format!("{f}={n}"),
        })
        .collect::<Vec<_>>()
        .join(",")
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
        // RFC 8950 §4: what the RIB needs is what may be sent; what may
        // be received is the decoder's business.
        extended_next_hop: s.extended_next_hop_send.clone(),
        advertisement_interval: interval,
        prefix_limits: Vec::new(),
        // RFC 7911 §5: the families the peer sends several paths for. What
        // we send it is configured (`add_path_send`).
        add_path_receive: s.add_path_receive.clone(),
        add_path_send: Vec::new(),
        role: s.role,
        restart: None,
    }
}

/// FIB changes sent in one message at most: one per channel operation
/// costs the RIB thread more than the change itself.
pub(crate) const FIB_BATCH: usize = 256;

/// Hands RIB outputs to the FIB and peer threads as the RIB produces them;
/// FIB changes go in batches, sent when full and after each input.
struct Deliver<'a> {
    peers: &'a PeerTable,
    fib: &'a SyncSender<FibMsg>,
    changes: Vec<FibChange>,
}

impl Deliver<'_> {
    fn flush(&mut self) {
        if self.changes.is_empty() {
            return;
        }
        // The next input likely changes about as many destinations.
        let next = Vec::with_capacity(self.changes.len());
        let changes = std::mem::replace(&mut self.changes, next);
        // A bounded channel: a slow kernel slows the RIB rather than
        // growing memory (AGENTS.md §3 backpressure).
        if self.fib.send(FibMsg::Changes(changes)).is_err() {
            bgpfc_log::error!("fib thread gone");
        }
    }

    fn handle(&self, peer: IpAddr) -> Option<crate::peer::PeerHandle> {
        self.peers.read().ok().and_then(|t| t.get(&peer).cloned())
    }

    /// A peer is over its prefix limit (RFC 4271 §6.7): log it and tell the
    /// peer thread to end the session.
    fn prefix_limit_exceeded(&self, peer: IpAddr, family: AddressFamily, limit: u32) {
        bgpfc_log::error!(
            "rib: prefix limit exceeded, routes dropped",
            peer = peer,
            family = family,
            limit = limit
        );
        let Some(handle) = self.handle(peer) else {
            return;
        };
        // RFC 4271 §6.7: the session must end. A full queue means the peer
        // thread is busy and checks the slot after its current input; the
        // RIB never blocks on a peer (AGENTS.md §3).
        match handle.tx.try_send(PeerInput::PrefixLimit { family, limit }) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                if let Ok(mut slot) = handle.prefix_limit.lock() {
                    *slot = Some((family, limit));
                }
            }
        }
    }
}

impl Sink for Deliver<'_> {
    fn put(&mut self, output: Output) {
        match output {
            Output::Fib(c) => {
                self.changes.push(c);
                if self.changes.len() >= FIB_BATCH {
                    self.flush();
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
            } => self.prefix_limit_exceeded(peer, family, limit),
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
            Output::RouteLeak {
                peer,
                family,
                otc,
                routes,
                first,
            } => {
                // RFC 9234 §5: a route leak "MUST be considered
                // ineligible"; nothing is sent to the peer, and the
                // session stays up. One line per UPDATE part.
                bgpfc_log::warn!(
                    "rib: route leak, routes ignored",
                    peer = peer,
                    family = family,
                    otc = otc.0,
                    routes = routes,
                    first = first
                );
            }
            Output::StaleRemoved {
                peer,
                family,
                routes,
                why,
            } => {
                // RFC 4724 §4.2: the routes of a restarted neighbor that
                // were kept and are now deleted. The FIB changes and the
                // UPDATEs for other peers have come out with it.
                bgpfc_log::info!(
                    "rib: stale routes removed",
                    peer = peer,
                    family = family.map_or_else(|| "all".to_owned(), |f| f.to_string()),
                    routes = routes,
                    why = why
                );
            }
            Output::SelectionDone { .. } => {}
            Output::Revalidated(r) => {
                // RFC 6811 §4: the routes a change of the validation source
                // moved, counted. One line per change, however many routes
                // it moved: turning validation on or off moves every route
                // of the table, and a line per route would hold the RIB
                // thread and flood the log.
                let values = revalidated(&r);
                let fields: Vec<bgpfc_log::Field<'_>> = values
                    .iter()
                    .map(|(k, v)| (*k, v as &dyn std::fmt::Display))
                    .collect();
                bgpfc_log::log(bgpfc_log::Level::Info, REVALIDATED, &fields);
            }
        }
    }
}

/// The message of the line logged for what a change of the validation
/// source did to the routes' RFC 6811 states.
const REVALIDATED: &str = "rib: validation states changed";

/// The fields of that line: the routes validated again, how many of them
/// changed state, those per change of state (`disabled->valid:1000,...`),
/// the destinations they are for with the first few of them, and the
/// destinations whose best route changed.
fn revalidated(r: &Revalidation) -> [(&'static str, String); 6] {
    let changes = r
        .changes
        .iter()
        .map(|(from, to, n)| format!("{from}->{to}:{n}"))
        .collect::<Vec<_>>()
        .join(",");
    [
        ("routes", r.routes.to_string()),
        ("changed", r.changed().to_string()),
        ("changes", changes),
        ("destinations", r.destinations.to_string()),
        ("prefixes", listed(&r.sample, r.destinations)),
        ("best_changed", r.best_changed.to_string()),
    ]
}

/// The first few of `prefixes` for a log line, `...` marking the rest.
fn sample(prefixes: &[Prefix]) -> String {
    const SHOWN: usize = 8;
    listed(&prefixes[..prefixes.len().min(SHOWN)], prefixes.len())
}

/// `shown`, the first of `total` prefixes, for a log line, `...` marking
/// the rest.
fn listed(shown: &[Prefix], total: usize) -> String {
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

fn answer(rib: &Rib, q: &RibQuery) -> RibReply {
    match q {
        RibQuery::Peers => RibReply::Peers(
            rib.peers()
                .map(|p| (p.clone(), rib.peer_stats(p.addr).unwrap_or_default()))
                .collect(),
        ),
        RibQuery::Routes {
            family,
            prefix,
            after,
        } => match prefix {
            Some(prefix) => {
                // With ADD-PATH one peer can have several candidates: the
                // best is one path of one peer (RFC 7911 §2).
                let best = rib
                    .loc_rib(*family)
                    .find(|(p, _)| p == prefix)
                    .map(|(_, b)| (b.peer, b.path_id));
                RibReply::Routes(
                    rib.candidates(*family, *prefix)
                        .iter()
                        .map(|c| RouteReport {
                            prefix: *prefix,
                            peer: c.peer,
                            attrs: std::sync::Arc::clone(c.attrs),
                            path_id: c.path_id,
                            best: best == Some((c.peer, c.path_id)),
                            rov: c.rov,
                        })
                        .collect(),
                )
            }
            None => RibReply::Routes(
                rib.loc_rib_after(*family, *after)
                    .take(PAGE)
                    .map(|(prefix, b)| RouteReport {
                        prefix,
                        peer: b.peer,
                        attrs: std::sync::Arc::clone(b.attrs),
                        path_id: b.path_id,
                        best: true,
                        rov: b.rov,
                    })
                    .collect(),
            ),
        },
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

    use crate::messages::AddPathLimits;

    use bgpfc_wire::types::{Asn, HoldTime, RouterId};

    const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

    /// [`super::handle`], with what it put out.
    fn handle(rib: &mut Rib, settings: &mut RibSettings, msg: RibMsg, now: Instant) -> Vec<Output> {
        let (fib, _) = sync_channel(1);
        let mut out = Vec::new();
        super::handle(rib, settings, msg, now, &fib, &mut out);
        out
    }

    /// `outputs` through a [`Deliver`], as the thread hands them on.
    fn deliver(outputs: Vec<Output>, peers: &PeerTable, fib: &SyncSender<FibMsg>) {
        let mut out = Deliver {
            peers,
            fib,
            changes: Vec::new(),
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
            add_path_receive: Vec::new(),
            add_path_send: Vec::new(),
            role: None,
            restart: None,
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

    /// An UPDATE from `peer` (AS `peer_as`) with a path for each of
    /// `prefix`'s Path Identifiers (RFC 7911 §3), one NLRI entry each.
    fn paths(peer: &str, peer_as: u32, prefix: &str, ids: &[u32]) -> Vec<RibMsg> {
        use bgpfc_wire::types::PathId;
        use bgpfc_wire::update::PathIds;
        ids.iter()
            .map(|id| {
                let mut msg = routes(peer, peer_as, &[prefix]);
                if let RibMsg::Update { update, .. } = &mut msg {
                    // A longer path for the higher identifiers, so that
                    // the decision process has something to choose by.
                    let hops: Vec<Asn> = std::iter::repeat_n(Asn(peer_as), *id as usize).collect();
                    update.message.attributes[1] = bgpfc_wire::attribute::PathAttribute::AsPath(
                        bgpfc_wire::as_path::AsPath::sequence(&hops),
                    );
                    update.message.path_ids = Some(Box::new(PathIds {
                        nlri: vec![PathId(*id)],
                        ..PathIds::default()
                    }));
                }
                msg
            })
            .collect()
    }

    /// A RIB with peer 1 (sends several paths, we receive them), peer 2
    /// (is sent all of them, with no MRAI so that each change goes out at
    /// once, RFC 4271 §9.2.1.1) and plain peer 3 up, as RFC 7911 §5 has
    /// the three negotiate.
    fn add_path_rib(now: Instant) -> (Rib, RibSettings) {
        let mut rib = Rib::new(Asn(65_000));
        let mut settings = RibSettings::default();
        settings
            .add_path_send
            .insert(ip("192.0.2.2"), vec![(V4, PathLimit::All)]);
        settings
            .intervals
            .insert(ip("192.0.2.2"), Some(Duration::ZERO));
        let mut receiving = session(65_001, PeerKind::External);
        receiving.add_path_receive = vec![V4];
        let mut sending = session(65_002, PeerKind::External);
        sending.add_path_send = vec![V4];
        for (peer, s) in [("192.0.2.1", receiving), ("192.0.2.2", sending)] {
            let msg = RibMsg::PeerUp {
                peer: ip(peer),
                local_addr: ip("192.0.2.254"),
                session: s,
            };
            handle(&mut rib, &mut settings, msg, now);
        }
        handle(
            &mut rib,
            &mut settings,
            up("192.0.2.3", 65_003, PeerKind::External),
            now,
        );
        (rib, settings)
    }

    #[test]
    fn add_path_sessions_start_with_and_follow_the_configured_limits() {
        // RFC 7911 §5: paths in from peer 1 (it sends, we receive) and
        // from plain peer 3, paths out to peer 2 (we send, it receives).
        use bgpfc_wire::types::PathId;
        let now = Instant::now();
        let (mut rib, mut settings) = add_path_rib(now);
        let info = |rib: &Rib, a: &str| {
            let p = rib.peer(ip(a)).unwrap();
            (p.add_path_receive.clone(), p.add_path_send.clone())
        };
        assert_eq!(info(&rib, "192.0.2.1"), (vec![V4], vec![]));
        assert_eq!(
            info(&rib, "192.0.2.2"),
            (vec![], vec![(V4, PathLimit::All)])
        );
        assert_eq!(info(&rib, "192.0.2.3"), (vec![], vec![]));
        for msg in paths("192.0.2.1", 65_001, "198.51.100.0/24", &[7, 9]) {
            handle(&mut rib, &mut settings, msg, now);
        }
        let out = handle(
            &mut rib,
            &mut settings,
            routes("192.0.2.3", 65_003, &["198.51.100.0/24"]),
            now,
        );
        // Peer 2 gets every path, under identifiers of ours.
        let ids = |rib: &Rib| {
            rib.sent_paths(ip("192.0.2.2"), V4)
                .into_iter()
                .map(|(_, id, _)| id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&rib), vec![PathId(1), PathId(2), PathId(3)]);
        assert!(
            out.iter()
                .any(|o| matches!(o, Output::Send { peer, .. } if *peer == ip("192.0.2.2")))
        );
        // The control plane sees them all, the best flagged once, with
        // the identifiers the peers sent where they sent any.
        let prefix = "198.51.100.0/24".parse().unwrap();
        let RibReply::Routes(reports) = answer(
            &rib,
            &RibQuery::Routes {
                family: V4,
                prefix: Some(prefix),
                after: None,
            },
        ) else {
            panic!("routes expected");
        };
        let mut seen: Vec<_> = reports
            .iter()
            .map(|r| (r.peer, r.path_id.map(|p| p.0), r.best))
            .collect();
        seen.sort();
        assert_eq!(seen.iter().filter(|r| r.2).count(), 1, "{seen:?}");
        assert_eq!(
            seen.iter().map(|r| (r.0, r.1)).collect::<Vec<_>>(),
            vec![
                (ip("192.0.2.1"), Some(7)),
                (ip("192.0.2.1"), Some(9)),
                (ip("192.0.2.3"), None)
            ]
        );
        // A reload that sends the best path alone: the others are
        // withdrawn from peer 2 without a reset.
        let mut new = AddPathLimits::new();
        new.insert(ip("192.0.2.2"), vec![(V4, PathLimit::Best(1))]);
        let out = handle(&mut rib, &mut settings, RibMsg::SetAddPathLimits(new), now);
        assert_eq!(
            rib.peer(ip("192.0.2.2")).unwrap().add_path_send,
            vec![(V4, PathLimit::Best(1))]
        );
        assert_eq!(ids(&rib).len(), 1);
        assert!(
            out.iter()
                .any(|o| matches!(o, Output::Send { peer, .. } if *peer == ip("192.0.2.2")))
        );
        // The same again changes nothing; a session that sends no paths is
        // left alone whatever the file says.
        let mut same = AddPathLimits::new();
        same.insert(ip("192.0.2.2"), vec![(V4, PathLimit::Best(1))]);
        same.insert(ip("192.0.2.3"), vec![(V4, PathLimit::All)]);
        let out = handle(&mut rib, &mut settings, RibMsg::SetAddPathLimits(same), now);
        assert_eq!(out, vec![]);
        assert_eq!(info(&rib, "192.0.2.3"), (vec![], vec![]));
    }

    #[test]
    fn a_negotiated_family_the_file_no_longer_configures_sends_its_best_path() {
        // Only a reload racing the reset of the session can leave it: the
        // encoding still has identifiers (RFC 7911 §5), one path goes.
        let settings = RibSettings::default();
        assert_eq!(
            add_path_send(&settings, ip("192.0.2.2"), &[V4]),
            vec![(V4, PathLimit::Best(1))]
        );
        assert_eq!(add_path_send(&settings, ip("192.0.2.2"), &[]), vec![]);
        assert_eq!(
            describe_path_limits(&[
                (V4, PathLimit::All),
                (AddressFamily::IPV6_UNICAST, PathLimit::Best(2))
            ]),
            "ipv4-unicast=all,ipv6-unicast=2"
        );
        assert_eq!(describe_path_limits(&[]), "none");
        assert_eq!(
            families(&[V4, AddressFamily::IPV6_UNICAST]),
            "ipv4-unicast,ipv6-unicast"
        );
        assert_eq!(families(&[]), "none");
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
            vec![Capability::Multiprotocol(V4)],
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
            add_path: bgpfc_wire::update::AddPathFamilies::NONE,
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
        };
        match answer(rib, &q) {
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
        // Both routes reached the FIB, the invalid one too: nothing acts
        // on the state yet. Turning validation off changed no best route.
        let installed: Vec<_> = fib_rx
            .try_iter()
            .flat_map(|m| match m {
                FibMsg::Changes(c) => c.into_iter().map(|c| c.prefix.to_string()),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(installed, ["198.51.100.0/24", "203.0.113.0/24"]);
    }

    #[test]
    fn a_validation_change_is_one_info_line_however_many_routes_it_moved() {
        let line = |r: &Revalidation| {
            let values = revalidated(r);
            let fields: Vec<bgpfc_log::Field<'_>> = values
                .iter()
                .map(|(k, v)| (*k, v as &dyn std::fmt::Display))
                .collect();
            bgpfc_log::format_line(
                std::time::UNIX_EPOCH,
                bgpfc_log::Level::Info,
                REVALIDATED,
                &fields,
            )
        };
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
        };
        assert_eq!(
            line(&on),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: validation states changed\" \
             routes=1250000 changed=1250000 \
             changes=disabled->valid:600000,disabled->invalid:50000,disabled->not-found:600000 \
             destinations=1000000 \
             prefixes=1.0.0.0/24,1.0.1.0/24,1.0.2.0/24,1.0.3.0/24,1.0.4.0/24,1.0.5.0/24,\
             1.0.6.0/24,1.0.7.0/24,... best_changed=2\n"
        );
        // A small delta: every destination named.
        let delta = Revalidation {
            routes: 3,
            changes: vec![(RovState::NotFound, RovState::Invalid, 2)],
            destinations: 1,
            sample: vec![p("2001:db8::/32")],
            best_changed: 0,
        };
        assert_eq!(
            line(&delta),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: validation states changed\" \
             routes=3 changed=2 changes=not-found->invalid:2 destinations=1 \
             prefixes=2001:db8::/32 best_changed=0\n"
        );
        assert_eq!(listed(&[], 0), "");
    }
}
