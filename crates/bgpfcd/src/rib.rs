//! The RIB thread: the only owner of RIB state (AGENTS.md §3). It turns
//! peer messages into `bgpfc_rib::Rib` calls and delivers what comes out:
//! UPDATEs to peer threads, route changes to the FIB thread. Between
//! messages it sleeps until the next RFC 4271 §9.2.1.1 deadline and then
//! releases the advertisements that were held back; the pacing itself is
//! `bgpfc_rib`'s. A peer over its RFC 4271 §6.7 prefix limit is told to
//! end its session. Routes the RIB ignored for a semantically incorrect
//! next hop are logged (RFC 4271 §6.3), as is every change of a route's
//! RFC 6811 validation state (issue #59).
//!
//! Changes of the validation source arrive on the same channel, from
//! whoever holds a [`RibSink`], and go the way an UPDATE goes (RFC 6811
//! §4): the RIB validates the affected routes again, and what follows
//! is delivered like any other output. The RIB starts with no source
//! (every route `disabled`) and keeps it until a change says otherwise.

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_fsm::Session;
use bgpfc_rib::{Output, PeerInfo, Rib, RouteOrigin, RovState};
use bgpfc_rpki::{AffectedPrefixes, RpkiError, ValidationChange, ValidationSink};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::PeerKind;

use crate::coordinator::PeerTable;
use crate::messages::{
    FibMsg, Intervals, PeerInput, RibMsg, RibQuery, RibReply, RibSettings, RouteReport,
};

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
    loop {
        let Ok(msg) = next(rx, rib.next_deadline()) else {
            return;
        };
        let now = Instant::now();
        let mut outputs = match msg {
            Some(m) => handle(&mut rib, &mut settings, m, now),
            None => Vec::new(),
        };
        // RFC 4271 §9.2.1.1: release what is due. After a message too, so
        // that a busy channel cannot starve the deadlines.
        outputs.extend(rib.flush(now));
        deliver(outputs, peers, fib);
    }
}

/// The [`ValidationSink`] a producer of validation changes, such as the
/// RTR client thread, is given (issue #56). Each change goes to the RIB
/// thread as a [`RibMsg::Validation`] on its bounded channel, in order and
/// behind the messages already queued, and is applied by the path an
/// UPDATE takes: import policy, the decision process, the Adj-RIBs-Out and
/// their RFC 4271 §9.2.1.1 pacing. `publish` blocks while the channel is
/// full, so a producer cannot outrun the RIB (AGENTS.md §3,
/// backpressure), and fails with [`RpkiError::SinkClosed`] once the RIB
/// thread is gone.
#[derive(Clone, Debug)]
pub(crate) struct RibSink {
    tx: SyncSender<RibMsg>,
}

impl RibSink {
    /// A sink onto the RIB thread's channel.
    // Nothing produces validation changes before the RTR client
    // (AGENTS.md §9, step 12), the producer this sink is for. Once that
    // client calls it the expectation is no longer met, which fails the
    // build, so the attribute cannot outlive its reason.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the RTR client of step 12 is the first producer")
    )]
    pub(crate) fn new(tx: SyncSender<RibMsg>) -> RibSink {
        RibSink { tx }
    }
}

impl ValidationSink for RibSink {
    fn publish(&mut self, change: ValidationChange) -> Result<(), RpkiError> {
        self.tx
            .send(RibMsg::Validation(change))
            .map_err(|_| RpkiError::SinkClosed)
    }
}

/// Every sender to the RIB thread is gone.
#[derive(Debug)]
struct Closed;

/// Wait for the next message (`Some`), or until `deadline`, when there is
/// one, passes first (`None`).
fn next(rx: &Receiver<RibMsg>, deadline: Option<Instant>) -> Result<Option<RibMsg>, Closed> {
    let Some(deadline) = deadline else {
        return rx.recv().map(Some).map_err(|_| Closed);
    };
    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(m) => Ok(Some(m)),
        Err(RecvTimeoutError::Timeout) => Ok(None),
        Err(RecvTimeoutError::Disconnected) => Err(Closed),
    }
}

/// Apply one message to the RIB.
fn handle(rib: &mut Rib, settings: &mut RibSettings, msg: RibMsg, now: Instant) -> Vec<Output> {
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
            rib.peer_up(info, now)
        }
        RibMsg::Update { peer, update } => {
            log_update(peer, &update);
            rib.update(peer, &update, now)
        }
        RibMsg::RouteRefresh { peer, family } => {
            bgpfc_log::info!("rib: route refresh", peer = peer, family = family);
            rib.refresh(peer, family, now)
        }
        RibMsg::PeerDown { peer } => {
            let stats = rib.peer_stats(peer).unwrap_or_default();
            bgpfc_log::info!(
                "rib: peer down",
                peer = peer,
                routes_deleted = stats.received.iter().map(|(_, n)| n).sum::<usize>()
            );
            rib.peer_down(peer, now)
        }
        RibMsg::Query(q, reply) => {
            let _ = reply.send(answer(rib, &q));
            Vec::new()
        }
        RibMsg::SetPolicies { policies, reexport } => {
            rib.set_policies(policies.0);
            let mut out = Vec::new();
            for peer in reexport {
                let families: Vec<_> = rib
                    .peer(peer)
                    .map(|p| p.families.clone())
                    .unwrap_or_default();
                for family in families {
                    bgpfc_log::info!("rib: re-export", peer = peer, family = family);
                    out.extend(rib.reexport(peer, family, now));
                }
            }
            out
        }
        RibMsg::SetIntervals(new) => {
            settings.intervals = new;
            follow_intervals(rib, settings, now)
        }
        RibMsg::SetPrefixLimits(new) => {
            settings.prefix_limits = new;
            follow_prefix_limits(rib, settings, now)
        }
        RibMsg::Resend { peer } => {
            let families: Vec<_> = rib
                .peer(peer)
                .map(|p| p.families.clone())
                .unwrap_or_default();
            let mut out = Vec::new();
            for family in families {
                bgpfc_log::info!("rib: resend", peer = peer, family = family);
                out.extend(rib.refresh(peer, family, now));
            }
            out
        }
        RibMsg::Validation(change) => {
            bgpfc_log::debug!(
                "rib: validation change",
                affected = describe_affected(&change.affected)
            );
            rib.validation_changed(change, now)
        }
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
fn follow_intervals(rib: &mut Rib, settings: &RibSettings, now: Instant) -> Vec<Output> {
    let up: Vec<(IpAddr, PeerKind, Duration)> = rib
        .peers()
        .map(|p| (p.addr, p.kind, p.advertisement_interval))
        .collect();
    let mut out = Vec::new();
    for (peer, kind, old) in up {
        let interval = advertisement_interval(configured(&settings.intervals, peer), kind);
        if interval != old {
            bgpfc_log::info!(
                "rib: advertisement interval",
                peer = peer,
                seconds = interval.as_secs()
            );
            out.extend(rib.set_advertisement_interval(peer, interval, now));
        }
    }
    out
}

/// After a reload: running sessions take their new prefix limits
/// (RFC 4271 §6.7) without a reset; one already over a new limit ends as
/// if it had just crossed it.
fn follow_prefix_limits(rib: &mut Rib, settings: &RibSettings, now: Instant) -> Vec<Output> {
    let up: Vec<(IpAddr, Vec<_>)> = rib
        .peers()
        .map(|p| (p.addr, p.prefix_limits.clone()))
        .collect();
    let mut out = Vec::new();
    for (peer, old) in up {
        let limits = prefix_limits(settings, peer);
        if limits != old {
            bgpfc_log::info!(
                "rib: prefix limits",
                peer = peer,
                limits = describe_limits(&limits)
            );
            out.extend(rib.set_prefix_limits(peer, limits, now));
        }
    }
    out
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
    }
}

fn deliver(outputs: Vec<Output>, peers: &PeerTable, fib: &SyncSender<FibMsg>) {
    for o in outputs {
        match o {
            Output::Fib(c) => {
                // A bounded channel: a slow kernel slows the RIB rather
                // than growing memory (AGENTS.md §3 backpressure).
                if fib.send(FibMsg::Change(c)).is_err() {
                    bgpfc_log::error!("fib thread gone");
                }
            }
            Output::Send { peer, messages } => {
                let handle = peers.read().ok().and_then(|t| t.get(&peer).cloned());
                let Some(handle) = handle else {
                    continue;
                };
                bgpfc_log::debug!("rib: send", peer = peer, messages = messages.len());
                match handle.tx.try_send(PeerInput::Send(messages)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        // AGENTS.md §3: never drop updates silently; the
                        // peer thread resets the session.
                        bgpfc_log::warn!("rib: peer queue full", peer = peer);
                        handle.overrun.store(true, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => {
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
                let handle = peers.read().ok().and_then(|t| t.get(&peer).cloned());
                let Some(handle) = handle else {
                    continue;
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
            Output::RovStateChanged {
                peer,
                prefix,
                origin,
                from,
                to,
            } => {
                // Issue #59: every change of a route's validation state.
                let fields = rov_change(&peer, &prefix, &origin, &from, &to);
                bgpfc_log::log(bgpfc_log::Level::Info, ROV_CHANGED, &fields);
            }
        }
    }
}

/// The message of the line logged for each change of a route's RFC 6811
/// validation state.
const ROV_CHANGED: &str = "rib: validation state changed";

/// The fields of that line: the route (`peer`, `prefix`), its Route
/// Origin ASN (RFC 6811 §2), and its state before and after.
fn rov_change<'a>(
    peer: &'a IpAddr,
    prefix: &'a Prefix,
    origin: &'a RouteOrigin,
    from: &'a RovState,
    to: &'a RovState,
) -> [bgpfc_log::Field<'a>; 5] {
    [
        ("peer", peer),
        ("prefix", prefix),
        ("origin", origin),
        ("from", from),
        ("to", to),
    ]
}

/// The first few of `prefixes` for a log line, `...` marking the rest.
fn sample(prefixes: &[Prefix]) -> String {
    const SHOWN: usize = 8;
    let mut s = prefixes
        .iter()
        .take(SHOWN)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if prefixes.len() > SHOWN {
        s.push_str(",...");
    }
    s
}

fn log_update(peer: IpAddr, update: &bgpfc_wire::update::DecodedUpdate) {
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
        RibQuery::Routes { family, prefix } => match prefix {
            Some(prefix) => {
                let best = rib
                    .loc_rib(*family)
                    .find(|(p, _)| p == prefix)
                    .map(|(_, b)| b.peer);
                RibReply::Routes(
                    rib.candidates(*family, *prefix)
                        .iter()
                        .map(|c| RouteReport {
                            prefix: *prefix,
                            peer: c.peer,
                            attrs: std::sync::Arc::clone(&c.attrs),
                            best: best == Some(c.peer),
                            rov: c.rov,
                        })
                        .collect(),
                )
            }
            None => RibReply::Routes(
                rib.loc_rib(*family)
                    .map(|(prefix, b)| RouteReport {
                        prefix,
                        peer: b.peer,
                        attrs: std::sync::Arc::clone(&b.attrs),
                        best: true,
                        rov: b.rov,
                    })
                    .collect(),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    use bgpfc_wire::types::{Asn, HoldTime, RouterId};

    const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

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
                treated_as_withdraw: None,
                discarded: Vec::new(),
                disabled: Vec::new(),
            },
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
        let handle = crate::peer::PeerHandle {
            addr,
            tx,
            overrun: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            prefix_limit: std::sync::Arc::new(std::sync::Mutex::new(None)),
        };
        (handle, rx)
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
        };
        let mut body = m.encode(&enc).unwrap();
        let bad_reach = [0x80, 14, 9, 0, 2, 1, 4, 1, 2, 3, 4, 0];
        body[3] += 12;
        body.splice(4..4, bad_reach);
        conn.write_all(&frame(MessageType::Update, &body).unwrap())
            .unwrap();
        match rib_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(RibMsg::Update { peer, update }) => {
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
        };
        match answer(rib, &q) {
            RibReply::Routes(routes) => routes
                .iter()
                .map(|r| (r.prefix.to_string(), r.rov))
                .collect(),
            RibReply::Peers(_) => panic!("asked for routes"),
        }
    }

    /// The validation state changes among `out`.
    fn rov_changes(out: &[Output]) -> Vec<(String, RovState, RovState)> {
        out.iter()
            .filter_map(|o| match o {
                Output::RovStateChanged {
                    prefix, from, to, ..
                } => Some((prefix.to_string(), *from, *to)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn validation_changes_from_the_sink_validate_the_routes_again() {
        // RFC 6811 §4 through the RIB thread's channel: a change published
        // through the sink is a message `handle` applies, and the states
        // of the affected routes follow it in place. The invalid route
        // stays in the Loc-RIB (RFC 6811 §2).
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
        let mut sink = RibSink::new(tx);
        let mut apply = |change| {
            sink.publish(change).unwrap();
            handle(&mut rib, &mut settings, rx.try_recv().unwrap(), now)
        };
        // Validation on: AS 65001 may originate the first prefix, and only
        // AS 64496 the second.
        let gone = vrp("203.0.113.0/24", 24, 64_496);
        let out = apply(all(&[vrp("198.51.100.0/24", 24, 65_001), gone]));
        let c = |p: &str, from, to| (p.to_owned(), from, to);
        assert_eq!(
            rov_changes(&out),
            [
                c("198.51.100.0/24", Disabled, Valid),
                c("203.0.113.0/24", Disabled, Invalid)
            ]
        );
        // A delta: the VRP that made the second route invalid goes, and
        // only that route is validated again.
        let out = apply(ValidationChange {
            source: std::sync::Arc::new(
                [vrp("198.51.100.0/24", 24, 65_001)]
                    .into_iter()
                    .collect::<bgpfc_rpki::VrpSet>(),
            ),
            affected: AffectedPrefixes::from_vrps([gone]),
        });
        assert_eq!(rov_changes(&out), [c("203.0.113.0/24", Invalid, NotFound)]);
        // Off again.
        let out = apply(ValidationChange::disabled());
        assert_eq!(
            rov_changes(&out),
            [
                c("198.51.100.0/24", Valid, Disabled),
                c("203.0.113.0/24", NotFound, Disabled)
            ]
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
    fn the_validation_sink_waits_for_room_and_fails_once_the_rib_is_gone() {
        use std::sync::atomic::AtomicBool;
        let (tx, rx) = sync_channel(1);
        let mut sink = RibSink::new(tx.clone());
        // An UPDATE fills the queue: the change waits behind it (AGENTS.md
        // §3, backpressure) and comes after it.
        tx.send(routes("192.0.2.1", 65_001, &["198.51.100.0/24"]))
            .unwrap();
        let published = std::sync::Arc::new(AtomicBool::new(false));
        let producer = {
            let published = std::sync::Arc::clone(&published);
            thread::spawn(move || {
                let result = sink.publish(ValidationChange::disabled());
                published.store(true, Ordering::SeqCst);
                result
            })
        };
        thread::sleep(Duration::from_millis(50));
        assert!(!published.load(Ordering::SeqCst), "did not wait for room");
        assert!(matches!(rx.recv(), Ok(RibMsg::Update { .. })));
        assert!(matches!(
            rx.recv(),
            Ok(RibMsg::Validation(change)) if change.affected == AffectedPrefixes::All
        ));
        assert_eq!(producer.join().unwrap(), Ok(()));
        // The RIB thread gone, its receiver with it: the producer is told
        // to stop.
        drop(rx);
        let mut sink = RibSink::new(tx);
        assert_eq!(
            sink.publish(ValidationChange::disabled()),
            Err(RpkiError::SinkClosed)
        );
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
        let mut sink = RibSink::new(tx.clone());
        tx.send(up("192.0.2.1", 65_001, PeerKind::External))
            .unwrap();
        // Validation is on before the routes arrive: they get their state
        // as they arrive.
        sink.publish(all(&[
            vrp("198.51.100.0/24", 24, 65_001),
            vrp("203.0.113.0/24", 24, 64_496),
        ]))
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
        sink.publish(ValidationChange::disabled()).unwrap();
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
            .map(|m| match m {
                FibMsg::Change(c) => c.prefix.to_string(),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(installed, ["198.51.100.0/24", "203.0.113.0/24"]);
    }

    #[test]
    fn a_validation_state_change_is_one_info_line() {
        // Issue #59: msg, peer, prefix, origin, from, to.
        let line = |origin: RouteOrigin, from: RovState, to: RovState| {
            let (peer, prefix) = (ip("192.0.2.1"), "198.51.100.0/24".parse().unwrap());
            let fields = rov_change(&peer, &prefix, &origin, &from, &to);
            bgpfc_log::format_line(
                std::time::UNIX_EPOCH,
                bgpfc_log::Level::Info,
                ROV_CHANGED,
                &fields,
            )
        };
        assert_eq!(
            line(
                RouteOrigin::As(Asn(64_496)),
                RovState::NotFound,
                RovState::Valid
            ),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: validation state changed\" \
             peer=192.0.2.1 prefix=198.51.100.0/24 origin=AS64496 from=not-found to=valid\n"
        );
        assert_eq!(
            line(RouteOrigin::None, RovState::Disabled, RovState::Invalid),
            "1970-01-01T00:00:00.000Z INFO  msg=\"rib: validation state changed\" \
             peer=192.0.2.1 prefix=198.51.100.0/24 origin=none from=disabled to=invalid\n"
        );
    }
}
