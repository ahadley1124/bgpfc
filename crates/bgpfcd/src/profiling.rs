//! Profiling builds only (`--features profiling`, `docs/PROFILING.md`):
//! the report line and when it is written, the table-load measurement and
//! the OPEN-to-Established timer. Nothing here changes what the daemon
//! does; it only observes.
//!
//! The environment tunes it:
//!
//! - `BGP_PROFILE_INTERVAL_SECS=N`: also report every `N` seconds (off by
//!   default).
//! - `BGP_PROFILE_SPANS=0`: no span timing; the histograms stay empty and
//!   the instrumentation costs only its counters.
//! - `BGP_PROFILE_LOAD_IDLE_SECS=N`: a table load with no End-of-RIB ends
//!   `N` seconds after its last UPDATE (default 10; `0` waits for the
//!   End-of-RIB marker only).
//!
//! Implements: RFC 4724 §2 (recognising the End-of-RIB marker; the daemon
//! does not otherwise act on it).

use std::collections::HashMap;
use std::fmt::Display;
use std::io::Write as _;
use std::net::IpAddr;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant, SystemTime};

use bgpfc_prof::Line;
use bgpfc_prof::metrics::{
    ADJ_RIB_IN, ADJ_RIB_OUT, FSM_OPEN_TO_ESTABLISHED, RIB_PREFIXES, RIB_UPDATE,
    SESSIONS_ESTABLISHED, UPDATE_TOTAL,
};
use bgpfc_rib::Rib;
use bgpfc_sys::alloc::AllocStats;
use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::DecodedUpdate;

use crate::messages::RibMsg;
use crate::rib::Closed;

/// How long a table load may go without an UPDATE before it is taken as
/// finished, when the peer sends no End-of-RIB.
const DEFAULT_LOAD_IDLE: Duration = Duration::from_secs(10);

/// How often the RIB thread looks for idle table loads.
const TICK: Duration = Duration::from_secs(1);

fn env_secs(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.trim().parse().ok()
}

/// Read the environment, start the interval reporter, and log what the
/// build does.
pub(crate) fn init() {
    bgpfc_prof::metrics::mark_start();
    if std::env::var("BGP_PROFILE_SPANS").is_ok_and(|v| v.trim() == "0") {
        bgpfc_prof::set_spans(false);
    }
    let interval = env_secs("BGP_PROFILE_INTERVAL_SECS").filter(|s| *s > 0);
    bgpfc_log::info!(
        "profiling build",
        spans = bgpfc_prof::spans(),
        interval_secs = interval.unwrap_or(0)
    );
    if let Some(secs) = interval {
        let spawned = std::thread::Builder::new()
            .name("profile".to_owned())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(secs));
                    emit(&report("interval", |_| {}));
                }
            });
        if let Err(e) = spawned {
            bgpfc_log::error!("cannot start the interval reporter", error = e);
        }
    }
}

/// The report line for `event`: the fields `extra` adds, then memory,
/// table sizes, counters and histograms.
pub(crate) fn report(event: &str, extra: impl FnOnce(&mut Line)) -> Line {
    report_with(event, bgpfc_sys::alloc::stats(), extra)
}

/// [`report`] with allocator figures already taken.
fn report_with(event: &str, a: AllocStats, extra: impl FnOnce(&mut Line)) -> Line {
    let mut line = Line::new(event);
    extra(&mut line);
    line.field("live", a.live)
        .field("peak", a.peak)
        .field("allocs", a.allocs)
        .field("deallocs", a.deallocs)
        .process_memory()
        .gauges()
        .counters()
        .histograms();
    line
}

/// Write `line` to stderr as a log line with `msg="profile"`, whatever the
/// log level: a profiling build was asked for these lines.
pub(crate) fn emit(line: &Line) {
    let pairs: Vec<(&str, &str)> = line.pairs().collect();
    let fields: Vec<bgpfc_log::Field<'_>> =
        pairs.iter().map(|(k, v)| (*k, v as &dyn Display)).collect();
    let text = bgpfc_log::format_line(
        SystemTime::now(),
        bgpfc_log::Level::Info,
        "profile",
        &fields,
    );
    let _ = std::io::stderr().lock().write_all(text.as_bytes());
}

/// `fsm_open_to_established` for one peer: from the first OPEN sent or
/// received on a connection to Established.
#[derive(Debug, Default)]
pub(crate) struct OpenTimer(Option<Instant>);

impl OpenTimer {
    /// An OPEN went out or came in; the first one starts the clock.
    pub(crate) fn open(&mut self) {
        if self.0.is_none() {
            self.0 = bgpfc_prof::now();
        }
    }

    /// The session is Established: record the time and count it.
    pub(crate) fn established(&mut self) {
        FSM_OPEN_TO_ESTABLISHED.record_since(self.0.take());
        SESSIONS_ESTABLISHED.inc();
    }

    /// The connection is gone; the next one starts afresh.
    pub(crate) fn reset(&mut self) {
        self.0 = None;
    }
}

/// RFC 4724 §2: an UPDATE with no withdrawn routes, no attributes and no
/// NLRI is the IPv4 unicast End-of-RIB marker; one with only an empty
/// `MP_UNREACH_NLRI` is the marker for that attribute's family.
pub(crate) fn end_of_rib(u: &DecodedUpdate) -> Option<AddressFamily> {
    let m = &u.message;
    if !m.withdrawn.is_empty()
        || !m.nlri.is_empty()
        || !m.attributes.is_empty()
        || m.mp_reach.is_some()
        || u.treated_as_withdraw.is_some()
        || !u.disabled.is_empty()
    {
        return None;
    }
    match &m.mp_unreach {
        None => Some(AddressFamily::IPV4_UNICAST),
        Some(un) if un.withdrawn.is_empty() => Some(un.family),
        Some(_) => None,
    }
}

/// What the RIB thread is about to handle, noted before the message is
/// consumed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Seen {
    what: What,
    /// When the RIB thread took the message, for `rib_update`.
    started: Option<Instant>,
}

#[derive(Clone, Copy, Debug)]
enum What {
    PeerUp,
    Update {
        peer: IpAddr,
        end_of_rib: Option<AddressFamily>,
        decoded: Option<Instant>,
    },
    PeerDown(IpAddr),
    Other,
}

/// One peer's table load: from its first UPDATE after Established to its
/// End-of-RIB (for every negotiated family) or to the idle timeout.
#[derive(Debug)]
struct PeerLoad {
    up: Instant,
    live_before: u64,
    /// Families whose End-of-RIB has not arrived.
    pending: Vec<AddressFamily>,
    first: Option<Instant>,
    last: Instant,
    updates: u64,
    /// The load was reported; later End-of-RIB markers are sync points.
    done: bool,
}

/// The RIB thread's table-load bookkeeping.
#[derive(Debug)]
pub(crate) struct Loads {
    idle: Option<Duration>,
    last_idle_check: Instant,
    peers: HashMap<IpAddr, PeerLoad>,
}

impl Loads {
    /// Bookkeeping with the idle timeout from the environment.
    pub(crate) fn from_env() -> Loads {
        let idle = match env_secs("BGP_PROFILE_LOAD_IDLE_SECS") {
            Some(0) => None,
            Some(s) => Some(Duration::from_secs(s)),
            None => Some(DEFAULT_LOAD_IDLE),
        };
        Loads {
            idle,
            last_idle_check: Instant::now(),
            peers: HashMap::new(),
        }
    }

    /// The next message (`Some`), or `None` once `deadline`, when there
    /// is one, passes first (`crate::rib::next`), waking up now and then
    /// to end idle table loads.
    ///
    /// # Errors
    /// When every sender is gone.
    pub(crate) fn recv(
        &mut self,
        rx: &Receiver<RibMsg>,
        rib: &Rib,
        deadline: Option<Instant>,
    ) -> Result<Option<RibMsg>, Closed> {
        loop {
            let tick = Instant::now() + TICK;
            let wake = deadline.map_or(tick, |d| d.min(tick));
            if let Some(m) = crate::rib::next(rx, Some(wake))? {
                return Ok(Some(m));
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(None);
            }
            self.check_idle(rib);
        }
    }

    /// Note `msg` before the RIB handles it.
    pub(crate) fn before(&mut self, msg: &RibMsg) -> Seen {
        let taken = bgpfc_prof::now();
        let what = match msg {
            RibMsg::PeerUp { peer, session, .. } => {
                // Measured before the RIB adds anything for the peer.
                let now = Instant::now();
                self.peers.insert(
                    *peer,
                    PeerLoad {
                        up: now,
                        live_before: bgpfc_sys::alloc::stats().live,
                        pending: session.families.clone(),
                        first: None,
                        last: now,
                        updates: 0,
                        done: false,
                    },
                );
                What::PeerUp
            }
            RibMsg::Update {
                peer,
                update,
                started,
            } => What::Update {
                peer: *peer,
                end_of_rib: end_of_rib(update),
                decoded: *started,
            },
            RibMsg::PeerDown { peer } => What::PeerDown(*peer),
            _ => What::Other,
        };
        Seen {
            what,
            started: taken,
        }
    }

    /// The RIB handled the message and its outputs were delivered.
    pub(crate) fn after(&mut self, seen: Seen, rib: &Rib) {
        let sizes = rib.sizes();
        RIB_PREFIXES.set(sizes.destinations);
        ADJ_RIB_IN.set(sizes.adj_rib_in);
        ADJ_RIB_OUT.set(sizes.adj_rib_out);
        match seen.what {
            What::Update {
                peer,
                end_of_rib,
                decoded,
            } => {
                RIB_UPDATE.record_since(seen.started);
                UPDATE_TOTAL.record_since(decoded);
                let now = Instant::now();
                if let Some(p) = self.peers.get_mut(&peer)
                    && !p.done
                {
                    p.first.get_or_insert(now);
                    p.last = now;
                    p.updates += 1;
                }
                if let Some(family) = end_of_rib {
                    self.end_of_rib(peer, family, now, rib);
                }
            }
            What::PeerDown(peer) => {
                if self.peers.remove(&peer).is_some() {
                    emit(&report("peer_down", |l| {
                        l.field("peer", peer);
                    }));
                }
            }
            What::PeerUp | What::Other => {}
        }
        if self.last_idle_check.elapsed() >= TICK {
            self.check_idle(rib);
        }
    }

    fn end_of_rib(&mut self, peer: IpAddr, family: AddressFamily, now: Instant, rib: &Rib) {
        let Some(p) = self.peers.get_mut(&peer) else {
            return;
        };
        if p.done {
            // A marker after the table load: a sync point a load generator
            // sends after withdrawals or churn.
            emit(&report("eor", |l| {
                l.field("peer", peer).field("family", family);
            }));
            emit(&duplication(peer, rib));
            return;
        }
        p.pending.retain(|f| *f != family);
        if p.pending.is_empty() {
            self.complete(peer, "eor", now, rib);
        }
    }

    fn check_idle(&mut self, rib: &Rib) {
        let now = Instant::now();
        self.last_idle_check = now;
        let Some(idle) = self.idle else {
            return;
        };
        let due: Vec<(IpAddr, Instant)> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                !p.done && p.first.is_some() && now.saturating_duration_since(p.last) >= idle
            })
            .map(|(a, p)| (*a, p.last))
            .collect();
        for (peer, last) in due {
            self.complete(peer, "idle", last, rib);
        }
    }

    /// Report a finished table load; `end` is when its last UPDATE was
    /// handled.
    fn complete(&mut self, peer: IpAddr, how: &str, end: Instant, rib: &Rib) {
        let Some(p) = self.peers.get_mut(&peer) else {
            return;
        };
        p.done = true;
        let prefixes: usize = rib
            .peer_stats(peer)
            .map_or(0, |s| s.received.iter().map(|(_, n)| n).sum());
        let took = end.saturating_duration_since(p.first.unwrap_or(p.up));
        let a = bgpfc_sys::alloc::stats();
        let per_prefix = a
            .live
            .saturating_sub(p.live_before)
            .checked_div(prefixes as u64)
            .unwrap_or(0);
        let (updates, live_before) = (p.updates, p.live_before);
        emit(&report_with("table_load", a, |l| {
            l.field("peer", peer)
                .field("end", how)
                .field("prefixes", prefixes)
                .field("updates", updates)
                .field("load_ms", took.as_millis())
                .field("load_us", took.as_micros())
                .field("updates_per_s", per_second(updates, took))
                .field("prefixes_per_s", per_second(prefixes as u64, took))
                .field("live_before", live_before)
                .field("bytes_per_prefix", per_prefix);
        }));
        // After the load line, so the walk's own allocations are not in
        // its peak.
        emit(&duplication(peer, rib));
    }
}

/// The duplication report (`event=duplication`): how often attribute sets
/// and `AS_PATH`s repeat in the RIB as it is now.
fn duplication(peer: IpAddr, rib: &Rib) -> Line {
    let started = Instant::now();
    let d = rib.duplication();
    let mut l = Line::new("duplication");
    l.field("peer", peer)
        .field("destinations", d.destinations)
        .field("routes", d.routes)
        .field("attr_sets", d.attr_sets)
        .field("attr_values", d.attr_values)
        .field("interned", d.interned)
        .field("as_paths", d.as_paths)
        .field("as_path_bytes", d.as_path_bytes)
        .field("as_path_bytes_if_interned", d.as_path_bytes_if_interned)
        .field("candidate_bytes", d.candidate_bytes)
        .field("adj_rib_out", d.adj_rib_out)
        .field("pre_policy", d.pre_policy)
        .field("pacing_bytes", d.pacing_bytes)
        .field("walk_ms", started.elapsed().as_millis());
    l
}

/// `--print-sizes`: `size_of` of what a route, a message and a peer are
/// made of.
pub(crate) fn print_sizes() {
    use std::mem::size_of;
    let mut rows = bgpfc_rib::profiling::type_sizes();
    rows.extend([
        (
            "Ipv4Key + gateway [IPv4 installed route]",
            bgpfc_fib::reconcile::ROUTE_SIZE,
        ),
        (
            "UpdateMessage",
            size_of::<bgpfc_wire::update::UpdateMessage>(),
        ),
        ("DecodedUpdate", size_of::<DecodedUpdate>()),
        (
            "PathAttribute",
            size_of::<bgpfc_wire::attribute::PathAttribute>(),
        ),
        ("RibMsg [RIB queue slot]", size_of::<RibMsg>()),
        (
            "FibMsg [FIB queue slot]",
            size_of::<crate::messages::FibMsg>(),
        ),
        (
            "PeerInput [peer queue slot]",
            size_of::<crate::messages::PeerInput>(),
        ),
        ("Peer [peer thread state]", size_of::<crate::peer::Peer>()),
        ("PeerHandle", size_of::<crate::peer::PeerHandle>()),
    ]);
    println!("{:48} {:>6}", "type", "bytes");
    for (name, size) in rows {
        println!("{name:48} {size:>6}");
    }
}

/// `n` events in `d`, per second; integer arithmetic.
fn per_second(n: u64, d: Duration) -> u64 {
    let us = d.as_micros().max(1);
    u64::try_from(u128::from(n) * 1_000_000 / us).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgpfc_wire::mp::MpUnreach;
    use bgpfc_wire::update::UpdateMessage;

    fn decoded(message: UpdateMessage) -> DecodedUpdate {
        DecodedUpdate {
            message,
            ..DecodedUpdate::default()
        }
    }

    #[test]
    fn recognises_end_of_rib_markers() {
        assert_eq!(
            end_of_rib(&decoded(UpdateMessage::default())),
            Some(AddressFamily::IPV4_UNICAST)
        );
        let v6 = UpdateMessage {
            mp_unreach: Some(MpUnreach {
                family: AddressFamily::IPV6_UNICAST,
                withdrawn: Vec::new(),
            }),
            ..UpdateMessage::default()
        };
        assert_eq!(end_of_rib(&decoded(v6)), Some(AddressFamily::IPV6_UNICAST));
        let withdraw = UpdateMessage {
            withdrawn: vec!["192.0.2.0/24".parse().unwrap()],
            ..UpdateMessage::default()
        };
        assert_eq!(end_of_rib(&decoded(withdraw)), None);
        let v6_withdraw = UpdateMessage {
            mp_unreach: Some(MpUnreach {
                family: AddressFamily::IPV6_UNICAST,
                withdrawn: vec!["2001:db8::/32".parse().unwrap()],
            }),
            ..UpdateMessage::default()
        };
        assert_eq!(end_of_rib(&decoded(v6_withdraw)), None);
    }

    #[test]
    fn duplication_report_parses() {
        let rib = Rib::new(bgpfc_wire::types::Asn(65_000));
        let text = duplication("192.0.2.1".parse().unwrap(), &rib).to_string();
        assert!(text.starts_with("event=duplication "), "{text}");
        for key in [
            "routes",
            "attr_sets",
            "as_paths",
            "interned",
            "pre_policy",
            "pacing_bytes",
            "walk_ms",
        ] {
            assert_eq!(bgpfc_prof::report::get_u64(&text, key), Some(0), "{key}");
        }
    }

    #[test]
    fn rates_are_per_second() {
        assert_eq!(per_second(500, Duration::from_millis(250)), 2000);
        assert_eq!(per_second(7, Duration::ZERO), 7_000_000);
    }

    #[test]
    fn reports_carry_the_standard_sections() {
        let line = report("stats", |l| {
            l.field("x", 1);
        });
        let text = line.to_string();
        assert!(text.starts_with("event=stats uptime_ms="), "{text}");
        for key in ["x", "live", "peak", "allocs", "rib_prefixes", "updates_rx"] {
            assert!(bgpfc_prof::report::get_u64(&text, key).is_some(), "{key}");
        }
        // The allocator is registered in this test binary too.
        assert!(bgpfc_prof::report::get_u64(&text, "allocs").unwrap() > 0);
    }
}
