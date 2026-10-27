//! The control plane (AGENTS.md §3, "Control thread(s)"): the Unix socket
//! `bgpfcctl` talks to and the loopback HTTP/JSON API. Both answer the
//! same commands; the data comes from the other threads over
//! request/response channels, never from shared state.
//!
//! Implements: `docs/control.md`; RFC 2918 §4 (soft reset asks for a
//! route refresh); RFC 9003 §3 (a shutdown communication of at most 128
//! octets); RFC 4486 §4 (Administrative Reset; whether the restart limit
//! left a neighbor Idle); RFC 4271 §6.7 (routes received per family
//! against the prefix limit); RFC 8210 §10 (the cache list, the cache
//! whose data is in use, marked as to source, and the one the client talks
//! to); RFC 6811 §2 (a route's validation state against the VRPs in use,
//! with the VRPs that Cover and Match it; the routes the Adj-RIBs-In hold
//! for their state, listed and counted), §3 (the state import policy set
//! beside the one looked up), §5 (the `enforcement` that acts on the
//! state); issue #59 (the latest routes whose state changed, with when);
//! issues #70 and #71 (Routinator's supervision with the alarm of one that
//! keeps failing, and whether the routes still wait for the first full
//! set).

use std::collections::VecDeque;
use std::io::{BufRead as _, BufReader, BufWriter, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_config::ast::{RpkiCache, RpkiMode};
use bgpfc_control::http;
use bgpfc_control::json::Json;
use bgpfc_control::proto;
use bgpfc_fib::Mode;
use bgpfc_rib::{Held, RouteStatus};
use bgpfc_rpki::{RouteOrigin, RovState, Startup, Vrp, VrpSet};
use bgpfc_sidecar::SidecarState;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};

use crate::coordinator::PeerTable;
use crate::messages::{
    FibMsg, FibReport, PAGE, PeerInput, PeerReport, RibMsg, RibQuery, RibReply, RouteReport,
    RpkiReport, SidecarReport, TransitionsReport,
};

/// How long a request may take to arrive or a reply to be written.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a thread may take to answer a query.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Octets of a listing gathered before a write to the client.
const LISTING_BUFFER: usize = 64 << 10;
/// HTTP connections served at once; the rest are refused with 503.
const MAX_HTTP_CONNECTIONS: usize = 16;
/// RFC 9003 §3: a communication longer than this may not reach a peer
/// that does not support the RFC, so the operator is asked to shorten it.
const MAX_SHUTDOWN_COMMUNICATION: usize = 128;

/// What the coordinator (the main thread) is asked.
#[derive(Debug)]
pub(crate) enum CoordMsg {
    /// A signal arrived.
    Signal(bgpfc_sys::Signal),
    /// Reload the configuration; the reply is a summary or an error.
    Reload(SyncSender<Result<String, String>>),
    /// Report the `rpki` block and its RTR client.
    Rpki(SyncSender<RpkiReport>),
}

/// Everything a command needs.
#[derive(Clone)]
pub(crate) struct Ctx {
    pub(crate) peers: PeerTable,
    pub(crate) rib: SyncSender<RibMsg>,
    pub(crate) fib: SyncSender<FibMsg>,
    pub(crate) coord: SyncSender<CoordMsg>,
    pub(crate) local_as: Asn,
    pub(crate) router_id: RouterId,
    /// `writes yes;` for the HTTP API.
    pub(crate) writes: bool,
    /// The bearer token every HTTP request must carry, if configured.
    pub(crate) token: Option<String>,
}

/// A parsed command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    ShowNeighbors,
    ShowNeighbor(IpAddr),
    ShowRoutes {
        family: AddressFamily,
        prefix: Option<Prefix>,
        /// Only the routes held for their validation state.
        held: bool,
    },
    ShowFib,
    ShowStatus,
    ShowRpki,
    /// The latest routes whose RFC 6811 state changed (issue #59).
    ShowRpkiTransitions,
    ValidateRpki {
        prefix: Prefix,
        origin: Asn,
    },
    ClearNeighbor {
        addr: IpAddr,
        soft: bool,
        message: Option<String>,
    },
    Reload,
    FibMode(Mode),
    /// The profiling report line (`docs/PROFILING.md`); profiling builds
    /// only, and only over the Unix socket.
    #[cfg(feature = "profiling")]
    Stats,
}

impl Command {
    /// Whether the command changes anything (HTTP: needs `writes yes;`).
    pub(crate) const fn is_write(&self) -> bool {
        matches!(
            self,
            Command::ClearNeighbor { .. } | Command::Reload | Command::FibMode(_)
        )
    }

    /// From the words of a `bgpfcctl` request.
    pub(crate) fn parse(words: &[String]) -> Result<Command, String> {
        let w: Vec<&str> = words.iter().map(String::as_str).collect();
        match w.as_slice() {
            ["show", "neighbors"] => Ok(Command::ShowNeighbors),
            ["show", "neighbor", a] => Ok(Command::ShowNeighbor(parse_addr(a)?)),
            ["show", "routes", rest @ ..] => {
                let mut family = AddressFamily::IPV4_UNICAST;
                let mut prefix = None;
                let mut held = false;
                for r in rest {
                    match *r {
                        "ipv4" => family = AddressFamily::IPV4_UNICAST,
                        "ipv6" => family = AddressFamily::IPV6_UNICAST,
                        "held" => held = true,
                        p => {
                            let parsed: Prefix = p.parse().map_err(|_| {
                                format!("`{p}` is not ipv4, ipv6, held or a prefix")
                            })?;
                            family = if matches!(parsed, Prefix::V6 { .. }) {
                                AddressFamily::IPV6_UNICAST
                            } else {
                                AddressFamily::IPV4_UNICAST
                            };
                            prefix = Some(parsed);
                        }
                    }
                }
                Ok(Command::ShowRoutes {
                    family,
                    prefix,
                    held,
                })
            }
            ["show", "fib"] => Ok(Command::ShowFib),
            ["show", "status"] => Ok(Command::ShowStatus),
            ["show", "rpki"] => Ok(Command::ShowRpki),
            ["show", "rpki", "transitions"] => Ok(Command::ShowRpkiTransitions),
            ["show", "rpki", "validate", p, a] => Ok(Command::ValidateRpki {
                prefix: p.parse().map_err(|_| format!("`{p}` is not a prefix"))?,
                origin: parse_asn(a)?,
            }),
            ["clear", "neighbor", a, rest @ ..] => {
                let addr = parse_addr(a)?;
                let (soft, rest) = match rest {
                    ["soft", r @ ..] => (true, r),
                    r => (false, r),
                };
                let message = match rest {
                    [] => None,
                    [m] => Some(check_communication(m)?),
                    _ => return Err("too many arguments".to_owned()),
                };
                if soft && message.is_some() {
                    return Err("a soft reset sends no message".to_owned());
                }
                Ok(Command::ClearNeighbor {
                    addr,
                    soft,
                    message,
                })
            }
            ["reload"] => Ok(Command::Reload),
            ["fib", "mode", "dry-run"] => Ok(Command::FibMode(Mode::DryRun)),
            ["fib", "mode", "install"] => Ok(Command::FibMode(Mode::Install)),
            #[cfg(feature = "profiling")]
            ["stats"] => Ok(Command::Stats),
            _ => Err(format!(
                "unknown command `{}`; see bgpfcctl --help",
                w.join(" ")
            )),
        }
    }

    /// From an HTTP request (`docs/control.md`, "HTTP API"); the error
    /// carries the status code.
    pub(crate) fn from_http(r: &http::Request) -> Result<Command, (u16, String)> {
        let segments: Vec<&str> = r.path.trim_matches('/').split('/').collect();
        let method = r.method.as_str();
        let not_found = || (404, format!("no such resource {}", r.path));
        match (method, segments.as_slice()) {
            ("GET", ["v1", "status"]) => Ok(Command::ShowStatus),
            ("GET", ["v1", "neighbors"]) => Ok(Command::ShowNeighbors),
            ("GET", ["v1", "neighbors", a]) => parse_addr(a)
                .map(Command::ShowNeighbor)
                .map_err(|e| (400, e)),
            ("GET", ["v1", "routes"]) => {
                let family = match r.param("family") {
                    None | Some("ipv4") => AddressFamily::IPV4_UNICAST,
                    Some("ipv6") => AddressFamily::IPV6_UNICAST,
                    Some(f) => return Err((400, format!("unknown family {f}"))),
                };
                let prefix = r
                    .param("prefix")
                    .map(|p| {
                        p.parse::<Prefix>()
                            .map_err(|_| (400, format!("bad prefix {p}")))
                    })
                    .transpose()?;
                let held = matches!(r.param("held"), Some("1" | "true" | "yes"));
                Ok(Command::ShowRoutes {
                    family,
                    prefix,
                    held,
                })
            }
            ("GET", ["v1", "fib"]) => Ok(Command::ShowFib),
            ("GET", ["v1", "rpki"]) => Ok(Command::ShowRpki),
            ("GET", ["v1", "rpki", "transitions"]) => Ok(Command::ShowRpkiTransitions),
            ("GET", ["v1", "rpki", "validate"]) => {
                let (Some(p), Some(a)) = (r.param("prefix"), r.param("origin")) else {
                    return Err((400, "needs prefix and origin".to_owned()));
                };
                let prefix = p
                    .parse::<Prefix>()
                    .map_err(|_| (400, format!("bad prefix {p}")))?;
                let origin = parse_asn(a).map_err(|e| (400, e))?;
                Ok(Command::ValidateRpki { prefix, origin })
            }
            ("POST", ["v1", "reload"]) => Ok(Command::Reload),
            ("POST", ["v1", "neighbors", a, "clear"]) => {
                let addr = parse_addr(a).map_err(|e| (400, e))?;
                let soft = matches!(r.param("soft"), Some("1" | "true" | "yes"));
                let message = r
                    .param("message")
                    .map(|m| check_communication(m).map_err(|e| (400, e)))
                    .transpose()?;
                Ok(Command::ClearNeighbor {
                    addr,
                    soft,
                    message,
                })
            }
            ("POST", ["v1", "fib", "mode", "install"]) => Ok(Command::FibMode(Mode::Install)),
            ("POST", ["v1", "fib", "mode", "dry-run"]) => Ok(Command::FibMode(Mode::DryRun)),
            ("GET" | "POST", _) => Err(not_found()),
            _ => Err((405, "only GET and POST".to_owned())),
        }
    }
}

fn parse_addr(a: &str) -> Result<IpAddr, String> {
    a.parse().map_err(|_| format!("`{a}` is not an IP address"))
}

/// An origin AS: `64496` or `AS64496`.
fn parse_asn(a: &str) -> Result<Asn, String> {
    let digits = a
        .strip_prefix("AS")
        .or_else(|| a.strip_prefix("as"))
        .unwrap_or(a);
    digits
        .parse()
        .map(Asn)
        .map_err(|_| format!("`{a}` is not an AS number"))
}

fn check_communication(m: &str) -> Result<String, String> {
    if m.len() > MAX_SHUTDOWN_COMMUNICATION {
        return Err(format!(
            "shutdown communication longer than {MAX_SHUTDOWN_COMMUNICATION} octets (RFC 9003 §3)"
        ));
    }
    Ok(m.to_owned())
}

/// A command's result in both renderings.
pub(crate) struct Reply {
    pub(crate) lines: Vec<String>,
    pub(crate) json: String,
}

/// What a command answers.
pub(crate) enum Answer<'a> {
    /// Everything at once.
    Reply(Reply),
    /// A long listing, taken and written a page at a time.
    Listing(Listing<'a>),
}

/// Run a command. The error is a message for the operator.
pub(crate) fn execute<'a>(ctx: &'a Ctx, cmd: &Command) -> Result<Answer<'a>, String> {
    match cmd {
        Command::ShowRoutes {
            family,
            prefix: None,
            held,
        } => Listing::routes(ctx, *family, *held).map(Answer::Listing),
        Command::ShowFib => Listing::fib(ctx).map(Answer::Listing),
        _ => reply(ctx, cmd).map(Answer::Reply),
    }
}

fn reply(ctx: &Ctx, cmd: &Command) -> Result<Reply, String> {
    match cmd {
        Command::ShowNeighbors => {
            let reports = peer_reports(ctx, None)?;
            let stats = rib_peers(ctx)?;
            Ok(render_neighbors(&reports, &stats))
        }
        Command::ShowNeighbor(addr) => {
            let reports = peer_reports(ctx, Some(*addr))?;
            if reports.is_empty() {
                return Err(format!("no neighbor {addr}"));
            }
            let stats = rib_peers(ctx)?;
            Ok(render_neighbor(&reports[0], &stats))
        }
        // One destination and every route the Adj-RIBs-In hold for it.
        // Without one, execute answers with a listing.
        Command::ShowRoutes {
            family,
            prefix,
            held,
        } => Ok(render_routes(&rib_routes(
            ctx, *family, *prefix, None, *held,
        )?)),
        // invariant: execute answers it with a listing.
        Command::ShowFib => unreachable!("show fib is a listing"),
        Command::ShowStatus => status(ctx),
        Command::ShowRpki => Ok(render_rpki(&rpki_report(ctx)?, Instant::now())),
        Command::ShowRpkiTransitions => {
            Ok(render_transitions(&rib_transitions(ctx)?, Instant::now()))
        }
        Command::ValidateRpki { prefix, origin } => {
            Ok(render_validation(&rpki_report(ctx)?, *prefix, *origin))
        }
        Command::ClearNeighbor {
            addr,
            soft,
            message,
        } => clear_neighbor(ctx, *addr, *soft, message.as_deref()),
        Command::Reload => {
            let (tx, rx) = sync_channel(1);
            ctx.coord
                .send(CoordMsg::Reload(tx))
                .map_err(|_| "coordinator gone".to_owned())?;
            let summary = rx
                .recv_timeout(Duration::from_secs(60))
                .map_err(|_| "reload did not finish".to_owned())??;
            Ok(ok_reply(&summary))
        }
        Command::FibMode(mode) => {
            let (tx, rx) = sync_channel(1);
            ctx.rib
                .send(RibMsg::FibMode(*mode, tx))
                .map_err(|_| "rib thread gone".to_owned())?;
            let ops = rx
                .recv_timeout(QUERY_TIMEOUT)
                .map_err(|_| "fib did not answer".to_owned())?;
            Ok(ok_reply(&format!("fib mode {mode}; {ops} operations")))
        }
        // The HTTP API never maps a request here: metrics are not exported
        // over the network (docs/PROFILING.md), so there is no JSON form.
        #[cfg(feature = "profiling")]
        Command::Stats => Ok(Reply {
            lines: vec![crate::profiling::report("stats", |_| {}).to_string()],
            json: String::new(),
        }),
    }
}

/// What `show status` reports, as the threads answered.
struct StatusReport {
    local_as: Asn,
    router_id: RouterId,
    neighbors: usize,
    established: usize,
    /// `None` if the FIB thread did not answer in time.
    fib_mode: Option<Mode>,
    /// `None` if the coordinator did not answer in time, as while it
    /// applies a reload that stops a slow Routinator.
    rpki: Option<RpkiReport>,
}

fn status(ctx: &Ctx) -> Result<Reply, String> {
    let reports = peer_reports(ctx, None)?;
    let established = reports
        .iter()
        .filter(|r| r.state == bgpfc_fsm::State::Established)
        .count();
    let (tx, rx) = sync_channel(1);
    let fib_mode = ctx
        .fib
        .send(FibMsg::Mode(tx))
        .ok()
        .and_then(|()| rx.recv_timeout(QUERY_TIMEOUT).ok());
    Ok(render_status(&StatusReport {
        local_as: ctx.local_as,
        router_id: ctx.router_id,
        neighbors: reports.len(),
        established,
        fib_mode,
        // Over CoordMsg::Rpki, as `show rpki` asks: the control threads
        // read no shared state (AGENTS.md §3).
        rpki: rpki_report(ctx).ok(),
    }))
}

/// The alarms `show status` raises, as `GET /v1/status` names them: what
/// needs an operator now. A Routinator that has failed `failure-threshold`
/// times in a row may leave the speaker enforcing RPKI with a validator
/// that is not running, which issue #70 wants surfaced "as an operational
/// error, not just a log line"; the line gives its failures in a row.
///
/// So does a block whose mode validates with nothing running, after a
/// reload that could not start Routinator or the RTR client: every route
/// is `disabled` while enforcement is expected, which issue #71 forbids
/// to happen silently. The next reload starts it again
/// (`Rpki::in_effect`).
fn alarms(r: &RpkiReport) -> Vec<(&'static str, String)> {
    let mut alarms = Vec::new();
    if r.status.is_none() {
        match (r.config.mode, &r.sidecar) {
            (RpkiMode::Disabled, _) => {}
            (RpkiMode::Sidecar, None) => alarms.push((
                "rpki-sidecar-not-running",
                "rpki sidecar not running: validation is off".to_owned(),
            )),
            (RpkiMode::External | RpkiMode::Sidecar, _) => alarms.push((
                "rpki-client-not-running",
                "rpki client not running: validation is off".to_owned(),
            )),
        }
    }
    if let Some(s) = &r.sidecar
        && let SidecarState::Failed { failures: n, .. } = s.status.state
    {
        alarms.push((
            "rpki-sidecar-failed",
            format!("rpki sidecar failed: {} in a row", failures(n)),
        ));
    }
    alarms
}

/// `show status`: the daemon, its neighbors, the FIB mode, where route
/// origin validation stands, and the alarms: the one reply a monitoring
/// system needs to poll (m14 design §4.6; not a health check, issue #73).
/// A thread that did not answer is reported as unknown: `null` in the
/// JSON, the alarms included, since none can be ruled out.
fn render_status(s: &StatusReport) -> Reply {
    let alarms = s.rpki.as_ref().map(alarms);
    let mut j = Json::new();
    j.begin_object()
        .field_str("version", env!("CARGO_PKG_VERSION"))
        .field_num("local_as", s.local_as.0)
        .field_display("router_id", s.router_id)
        .field_num("neighbors", num(s.neighbors))
        .field_num("established", num(s.established))
        .field_opt("fib_mode", s.fib_mode)
        .key("rpki");
    if let Some(r) = &s.rpki {
        j.begin_object()
            .field_display("mode", r.config.mode)
            .field_str("validation", Validation::of(r).as_str())
            .end_object();
    } else {
        j.null();
    }
    j.key("alarms");
    if let Some(alarms) = &alarms {
        j.begin_array();
        for (name, _) in alarms {
            j.string(name);
        }
        j.end_array();
    } else {
        j.null();
    }
    j.end_object();
    let mut lines = vec![
        format!("bgpfcd {}", env!("CARGO_PKG_VERSION")),
        format!("local-as {} router-id {}", s.local_as, s.router_id),
        format!("neighbors {} established {}", s.neighbors, s.established),
        format!(
            "fib mode {}",
            s.fib_mode.map_or("unknown".to_owned(), |m| m.to_string())
        ),
        s.rpki.as_ref().map_or_else(
            || "rpki unknown".to_owned(),
            |r| {
                format!(
                    "rpki {}, validation {}",
                    r.config.mode,
                    Validation::of(r).as_str()
                )
            },
        ),
    ];
    lines.extend(
        alarms
            .into_iter()
            .flatten()
            .map(|(_, text)| format!("alarm {text}")),
    );
    Reply {
        lines,
        json: j.finish(),
    }
}

fn clear_neighbor(
    ctx: &Ctx,
    addr: IpAddr,
    soft: bool,
    message: Option<&str>,
) -> Result<Reply, String> {
    let handle = ctx
        .peers
        .read()
        .map_err(|_| "peer table poisoned".to_owned())?
        .get(&addr)
        .cloned()
        .ok_or_else(|| format!("no neighbor {addr}"))?;
    let input = if soft {
        PeerInput::SoftReset
    } else {
        PeerInput::Reset(message.map(str::to_owned))
    };
    handle
        .tx
        .try_send(input)
        .map_err(|_| format!("neighbor {addr} is busy"))?;
    Ok(ok_reply(&format!(
        "{} reset of {addr} requested",
        if soft { "soft" } else { "hard" }
    )))
}

fn ok_reply(message: &str) -> Reply {
    let mut j = Json::new();
    j.begin_object()
        .field_bool("ok", true)
        .field_str("message", message)
        .end_object();
    Reply {
        lines: vec![message.to_owned()],
        json: j.finish(),
    }
}

/// Ask the coordinator about the `rpki` block.
///
/// The coordinator also applies reloads, and one that stops a slow
/// Routinator holds it for up to `stop-timeout`. The question waits up to
/// [`QUERY_TIMEOUT`] for the answer, but never for room on the
/// coordinator's queue: a question that timed out stays queued until the
/// coordinator gets to it, so a monitoring system that polls `show status`
/// through such a reload would fill the queue, and every request after
/// that would wait, holding one of the HTTP server's few connections. A
/// full queue is answered at once instead, as a coordinator that did not
/// answer is.
fn rpki_report(ctx: &Ctx) -> Result<RpkiReport, String> {
    let (tx, rx) = sync_channel(1);
    ctx.coord
        .try_send(CoordMsg::Rpki(tx))
        .map_err(|e| match e {
            TrySendError::Full(_) => "coordinator busy".to_owned(),
            TrySendError::Disconnected(_) => "coordinator gone".to_owned(),
        })?;
    rx.recv_timeout(QUERY_TIMEOUT)
        .map_err(|_| "coordinator did not answer".to_owned())
}

/// Whole seconds from `earlier` to `later`; 0 if `later` is not later.
fn seconds_between(earlier: Instant, later: Instant) -> u64 {
    later.saturating_duration_since(earlier).as_secs()
}

/// `show rpki`: the block's mode, its enforcement (RFC 6811 §5), where
/// validation stands, Routinator with `mode sidecar`, the cache list, and
/// where the client stands with the cache it uses (RFC 8210 §10).
fn render_rpki(r: &RpkiReport, now: Instant) -> Reply {
    let mut j = Json::new();
    write_rpki(&mut j, r, now);
    Reply {
        lines: rpki_lines(r, now),
        json: j.finish(),
    }
}

/// Whether the RIB validates with VRPs from `cache`: RFC 8210 §10, the
/// data of one cache of the list at a time, "marked as to source".
fn in_use(status: Option<&bgpfc_rtr::client::Status>, cache: &RpkiCache) -> bool {
    status
        .and_then(|s| s.source.as_ref())
        .is_some_and(|source| cache.is_at(&source.host, source.port))
}

/// Whether the client talks to `cache`: is connected to it, or tries it
/// next. The `state` line is about that session. After a move it is
/// another cache than the one [`in_use`] marks, until that cache has sent
/// a full set (RFC 8210 §10).
fn current(status: Option<&bgpfc_rtr::client::Status>, cache: &RpkiCache) -> bool {
    status.is_some_and(|s| s.running && cache.is_at(&s.cache.host, s.cache.port))
}

/// Where route origin validation stands (issue #71: the startup window is
/// not silent; m14 design §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Validation {
    /// No client runs, so every route is `disabled`: `mode disabled`, or
    /// a reload that could not start the client or Routinator.
    Off,
    /// The client runs and has published no full set yet: every route has
    /// been `disabled` since then, and used as received.
    Waiting(Instant),
    /// The RIB validates with VRPs a cache sent, or with those held from
    /// one, which expire as RFC 8210 §6 has it.
    Active,
}

impl Validation {
    fn of(r: &RpkiReport) -> Validation {
        match (&r.status, r.waiting_since) {
            (None, _) => Validation::Off,
            (Some(_), Some(since)) => Validation::Waiting(since),
            (Some(_), None) => Validation::Active,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Validation::Off => "off",
            Validation::Waiting(_) => "waiting",
            Validation::Active => "active",
        }
    }
}

/// What becomes of the routes while validation waits for the first full
/// set, under the block's `startup` (RFC 6811 §2). A client runs while
/// validation waits, so the block's mode validates and its setting is the
/// one in effect (`rpki::startup`).
const fn waiting_routes(startup: Startup) -> &'static str {
    match startup {
        Startup::Accept => "every route is disabled and used unvalidated",
        Startup::Hold => "every route is disabled and held (startup hold)",
    }
}

/// `n failures`, or `1 failure`.
fn failures(n: u32) -> String {
    if n == 1 {
        "1 failure".to_owned()
    } else {
        format!("{n} failures")
    }
}

/// The cache the client has with a sidecar: Routinator's address, at
/// preference 0, written as the client writes it (`rpki::client_config`),
/// so that [`in_use`] and [`current`] find it as they find a configured
/// one.
fn sidecar_cache(s: &SidecarReport) -> RpkiCache {
    RpkiCache {
        host: s.status.rtr.ip().to_string(),
        port: s.status.rtr.port(),
        preference: 0,
    }
}

/// The caches `show rpki` lists: the block's, and the sidecar's, marked
/// `true`. A block with `mode sidecar` has no `cache`, so the client's
/// one cache is listed like any other.
fn listed_caches(r: &RpkiReport) -> Vec<(RpkiCache, bool)> {
    let mut caches: Vec<_> = r.config.caches.iter().map(|c| (c.clone(), false)).collect();
    caches.extend(r.sidecar.as_ref().map(|s| (sidecar_cache(s), true)));
    caches
}

/// The two lines on Routinator: where supervision stands, with the alarm
/// in upper case, and its RTR address and history.
fn sidecar_lines(s: &SidecarReport, now: Instant) -> [String; 2] {
    let st = &s.status;
    let state = match st.state {
        SidecarState::Running { pid, since } => {
            format!("running pid {pid} for {}s", seconds_between(since, now))
        }
        SidecarState::BackingOff { until, failures: n } => format!(
            "backing-off after {}, next attempt in {}s",
            failures(n),
            seconds_between(now, until)
        ),
        SidecarState::Failed { until, failures: n } => format!(
            "FAILED after {} in a row, next attempt in {}s",
            failures(n),
            seconds_between(now, until)
        ),
        SidecarState::ShuttingDown { pid: Some(pid) } => format!("shutting-down pid {pid}"),
        other => other.name().to_owned(),
    };
    [
        format!(
            "sidecar {state}, routinator {} ({})",
            s.version,
            one_line(&s.binary.to_string_lossy())
        ),
        format!(
            "sidecar rtr {}, restarts {}, failures {}{}",
            st.rtr,
            st.restarts,
            st.consecutive_failures,
            st.last_exit.as_ref().map_or(String::new(), |e| format!(
                ", last exit: {}",
                one_line(&e.to_string())
            ))
        ),
    ]
}

fn rpki_lines(r: &RpkiReport, now: Instant) -> Vec<String> {
    let status = r.status.as_ref();
    let mut lines = vec![
        format!("mode {}", r.config.mode),
        format!("enforcement {}", r.config.enforcement),
        format!("startup {}", r.config.startup),
        match Validation::of(r) {
            Validation::Waiting(since) => format!(
                "validation waiting {}s for the first full set: {}; enforcement acts once \
                 it arrives",
                seconds_between(since, now),
                waiting_routes(r.config.startup)
            ),
            v => format!("validation {}", v.as_str()),
        },
    ];
    if let Some(s) = &r.sidecar {
        lines.extend(sidecar_lines(s, now));
    } else if r.config.mode == RpkiMode::Sidecar {
        // A reload could not start it, and turned validation off.
        lines.push("sidecar not running".to_owned());
    }
    for (c, sidecar) in listed_caches(r) {
        lines.push(format!(
            "cache {c}{} preference {}{}{}",
            if sidecar { " (sidecar)" } else { "" },
            c.preference,
            if in_use(status, &c) { ", in use" } else { "" },
            if current(status, &c) { ", current" } else { "" }
        ));
    }
    let Some(s) = status else {
        return lines;
    };
    let dash = |v: Option<String>| v.unwrap_or_else(|| "-".to_owned());
    lines.push(format!(
        "state {}{}, version {}",
        if s.running {
            s.state.as_str()
        } else {
            "stopped"
        },
        if s.connected { ", connected" } else { "" },
        s.version
    ));
    lines.push(format!(
        "session-id {} serial {}",
        dash(s.session_id.map(|v| v.to_string())),
        dash(s.serial.map(|v| v.to_string()))
    ));
    lines.push(s.synced_at.map_or_else(
        || "last sync never".to_owned(),
        |at| format!("last sync {}s ago", seconds_between(at, now)),
    ));
    lines.push(if s.vrps.is_some() {
        format!(
            "vrps ipv4 {} ipv6 {}{}{}",
            s.vrps_ipv4,
            s.vrps_ipv6,
            s.source
                .as_ref()
                .map_or(String::new(), |source| format!(" from {source}")),
            s.expires_at.map_or(String::new(), |at| format!(
                ", expire in {}s",
                seconds_between(now, at)
            ))
        )
    } else {
        "vrps none yet: every route is disabled".to_owned()
    });
    lines.push(format!("failures {}", s.failures));
    if let (Some(e), Some(at)) = (&s.last_error, s.last_error_at) {
        lines.push(format!(
            "last error {}s ago: {}",
            seconds_between(at, now),
            one_line(e)
        ));
    }
    lines
}

/// `text` with its control characters escaped (`\n`, `\r`, `\t`,
/// `\u{001b}`), for a line of a reply. The line protocol of
/// `docs/control.md` ends a line at a newline and a reply at a line of a
/// lone `.`, so text from outside the daemon, such as an Error Report a
/// cache sent (RFC 8210 §5.11: any UTF-8), must neither end its line nor
/// reach the operator's terminal as an escape sequence.
fn one_line(text: &str) -> std::borrow::Cow<'_, str> {
    use std::fmt::Write as _;

    if !text.chars().any(char::is_control) {
        return text.into();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:04x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.into()
}

/// The `sidecar` member of `GET /v1/rpki`.
fn write_sidecar(j: &mut Json, s: &SidecarReport, now: Instant) {
    let st = &s.status;
    let (running, retry) = match st.state {
        SidecarState::Running { since, .. } => (Some(seconds_between(since, now)), None),
        SidecarState::BackingOff { until, .. } | SidecarState::Failed { until, .. } => {
            (None, Some(seconds_between(now, until)))
        }
        _ => (None, None),
    };
    j.begin_object()
        .field_str("state", st.state.name())
        .field_bool("alarm", matches!(st.state, SidecarState::Failed { .. }))
        .field_opt_num("pid", st.pid)
        .field_opt_num("running_seconds", running)
        .field_opt_num("retry_in_seconds", retry)
        .field_num("restarts", st.restarts)
        .field_num("consecutive_failures", st.consecutive_failures)
        .field_opt("last_exit", st.last_exit.as_ref())
        .field_display("rtr", st.rtr)
        .field_display("binary", s.binary.display())
        .field_display("version", &s.version)
        .end_object();
}

fn write_rpki(j: &mut Json, r: &RpkiReport, now: Instant) {
    let status = r.status.as_ref();
    let validation = Validation::of(r);
    j.begin_object()
        .field_display("mode", r.config.mode)
        .field_display("enforcement", r.config.enforcement)
        .field_display("startup", r.config.startup)
        .field_str("validation", validation.as_str())
        .field_opt_num(
            "waiting_seconds",
            match validation {
                Validation::Waiting(since) => Some(seconds_between(since, now)),
                Validation::Off | Validation::Active => None,
            },
        )
        .key("sidecar");
    if let Some(s) = &r.sidecar {
        write_sidecar(j, s, now);
    } else {
        j.null();
    }
    j.key("caches").begin_array();
    for (c, _) in listed_caches(r) {
        j.begin_object()
            .field_str("host", &c.host)
            .field_num("port", c.port)
            .field_num("preference", c.preference)
            .field_bool("in_use", in_use(status, &c))
            .field_bool("current", current(status, &c))
            .end_object();
    }
    j.end_array();
    let Some(s) = status else {
        // The same members without a client, so that a reader needs no
        // second shape.
        j.field_bool("running", false)
            .field_opt("state", None::<&str>)
            .field_bool("connected", false);
        for key in [
            "version",
            "session_id",
            "serial",
            "synced_seconds_ago",
            "expires_in_seconds",
            "vrps",
        ] {
            j.key(key).null();
        }
        j.field_num("failures", 0)
            .field_opt("last_error", None::<&str>)
            .field_opt_num("last_error_seconds_ago", None::<u64>)
            .end_object();
        return;
    };
    j.field_bool("running", s.running)
        .field_str("state", s.state.as_str())
        .field_bool("connected", s.connected)
        .field_num("version", s.version.to_u8())
        .field_opt_num("session_id", s.session_id)
        .field_opt_num("serial", s.serial)
        .field_opt_num(
            "synced_seconds_ago",
            s.synced_at.map(|at| seconds_between(at, now)),
        )
        .field_opt_num(
            "expires_in_seconds",
            s.expires_at.map(|at| seconds_between(now, at)),
        )
        .key("vrps");
    if s.vrps.is_some() {
        j.begin_object()
            .field_num("ipv4", u64::try_from(s.vrps_ipv4).unwrap_or(u64::MAX))
            .field_num("ipv6", u64::try_from(s.vrps_ipv6).unwrap_or(u64::MAX))
            .key("from");
        if let Some(source) = &s.source {
            j.begin_object()
                .field_str("host", &source.host)
                .field_num("port", source.port)
                .end_object();
        } else {
            j.null();
        }
        j.end_object();
    } else {
        j.null();
    }
    j.field_num("failures", s.failures)
        .field_opt("last_error", s.last_error.as_deref())
        .field_opt_num(
            "last_error_seconds_ago",
            s.last_error_at.map(|at| seconds_between(at, now)),
        )
        .end_object();
}

/// Ask the RIB thread for the routes whose state changed last.
fn rib_transitions(ctx: &Ctx) -> Result<TransitionsReport, String> {
    let (tx, rx) = sync_channel(1);
    ctx.rib
        .send(RibMsg::Query(RibQuery::Transitions, tx))
        .map_err(|_| "rib thread gone".to_owned())?;
    match rx.recv_timeout(QUERY_TIMEOUT) {
        Ok(RibReply::Transitions(r)) => Ok(r),
        Ok(_) => Err("unexpected reply".to_owned()),
        Err(_) => Err("rib did not answer".to_owned()),
    }
}

/// `show rpki transitions` (issue #59: "An operator needs to see that a
/// prefix went Valid → Invalid at a specific time"): the latest routes a
/// change of the validation source moved among valid, invalid and
/// not-found, oldest first, each at the time its log line has, and what
/// became of it; then how many are kept and how many the RIB thread was
/// never given. `now` is the moment of the report.
fn render_transitions(r: &TransitionsReport, now: Instant) -> Reply {
    let mut lines = Vec::with_capacity(r.entries.len() + 1);
    let mut j = Json::new();
    j.begin_object()
        .field_num("capacity", num(r.capacity))
        .field_num("unrecorded", r.unrecorded)
        .key("transitions")
        .begin_array();
    for e in &r.entries {
        let t = &e.transition;
        let mut time = String::with_capacity(24);
        bgpfc_log::push_timestamp(&mut time, e.at);
        let held_by = match t.route {
            RouteStatus::Held(by) => Some(by),
            RouteStatus::Best | RouteStatus::Candidate => None,
        };
        lines.push(format!(
            "{time} {} peer {} origin {} {}->{} {}{}",
            t.prefix,
            t.peer,
            t.origin,
            t.from,
            t.to,
            crate::rib::status_name(t.route),
            held_by.map_or(String::new(), |by| format!(" by {by}"))
        ));
        j.begin_object()
            .field_str("time", &time)
            .field_num("seconds_ago", seconds_between(e.when, now))
            .field_display("family", t.family)
            .field_display("prefix", t.prefix)
            .field_display("peer", t.peer)
            .field_opt_num(
                "origin",
                match t.origin {
                    RouteOrigin::As(asn) => Some(asn.0),
                    RouteOrigin::None => None,
                },
            )
            .field_str("from", t.from.as_str())
            .field_str("to", t.to.as_str())
            .field_str("route", crate::rib::status_name(t.route))
            .field_opt("held_by", held_by.map(Held::as_str))
            .end_object();
    }
    j.end_array().end_object();
    lines.push(format!(
        "{} kept (most recent {}); {} not recorded",
        r.entries.len(),
        r.capacity,
        r.unrecorded
    ));
    Reply {
        lines,
        json: j.finish(),
    }
}

/// Whether `vrp` Covers `route`: it is the route's prefix or less specific
/// (RFC 6811 §2).
fn covers(vrp: Prefix, route: Prefix) -> bool {
    vrp.prefix_len() <= route.prefix_len()
        && Prefix::new(route.addr(), vrp.prefix_len()) == Some(vrp)
}

/// `show rpki validate`: the RFC 6811 §2 state of a route to `prefix`
/// from `origin` against the VRPs the RIB validates with, and the VRPs
/// that Cover it, marked where they Match.
fn render_validation(r: &RpkiReport, prefix: Prefix, origin: Asn) -> Reply {
    let route = RouteOrigin::As(origin);
    let vrps = r.status.as_ref().and_then(|s| s.vrps.as_deref());
    let rov = vrps.map_or(RovState::Disabled, |v| v.validate(prefix, route));
    let mut covering: Vec<(Vrp, bool)> = vrps
        .into_iter()
        .flat_map(VrpSet::iter)
        .filter(|vrp| covers(vrp.prefix(), prefix))
        .map(|vrp| {
            // Matched as VrpSet::validate has it, one VRP at a time.
            let one: VrpSet = [vrp].into_iter().collect();
            (vrp, one.validate(prefix, route) == RovState::Valid)
        })
        .collect();
    covering.sort_unstable();
    let mut lines = vec![format!("{prefix} origin {origin}: {rov}")];
    if vrps.is_none() {
        lines.push("  no VRPs: validation is disabled or has no data yet".to_owned());
    }
    let mut j = Json::new();
    j.begin_object()
        .field_display("prefix", prefix)
        .field_num("origin", origin.0)
        .field_str("rov", rov.as_str())
        .key("vrps")
        .begin_array();
    for (vrp, matches) in &covering {
        lines.push(format!("  {vrp}{}", if *matches { " matches" } else { "" }));
        j.begin_object()
            .field_display("prefix", vrp.prefix())
            .field_num("max_length", vrp.max_len())
            .field_num("asn", vrp.asn().0)
            .field_bool("matches", *matches)
            .end_object();
    }
    j.end_array().end_object();
    Reply {
        lines,
        json: j.finish(),
    }
}

/// Ask every peer thread (or one) for its state.
fn peer_reports(ctx: &Ctx, only: Option<IpAddr>) -> Result<Vec<PeerReport>, String> {
    let handles: Vec<_> = {
        let table = ctx
            .peers
            .read()
            .map_err(|_| "peer table poisoned".to_owned())?;
        let mut v: Vec<_> = table
            .values()
            .filter(|h| only.is_none_or(|a| h.addr == a))
            .cloned()
            .collect();
        v.sort_by_key(|h| h.addr);
        v
    };
    let mut reports = Vec::with_capacity(handles.len());
    for h in handles {
        let (tx, rx) = sync_channel(1);
        if h.tx.try_send(PeerInput::Report(tx)).is_err() {
            continue;
        }
        if let Ok(r) = rx.recv_timeout(QUERY_TIMEOUT) {
            reports.push(r);
        }
    }
    Ok(reports)
}

fn rib_peers(ctx: &Ctx) -> Result<Vec<(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)>, String> {
    let (tx, rx) = sync_channel(1);
    ctx.rib
        .send(RibMsg::Query(RibQuery::Peers, tx))
        .map_err(|_| "rib thread gone".to_owned())?;
    match rx.recv_timeout(QUERY_TIMEOUT) {
        Ok(RibReply::Peers(p)) => Ok(p),
        Ok(_) => Err("unexpected reply".to_owned()),
        Err(_) => Err("rib did not answer".to_owned()),
    }
}

/// A neighbor's routes, in all or in one family: received (what the RFC
/// 4271 §6.7 limit counts), how many of those the Adj-RIB-In holds for
/// their validation state and are no candidates (RFC 6811 §2), and
/// advertised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    received: usize,
    held: usize,
    advertised: usize,
}

/// `n` for JSON.
fn num(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn counts(stats: &[(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)], addr: IpAddr) -> Counts {
    let sum = |v: &[(AddressFamily, usize)]| v.iter().map(|(_, n)| n).sum();
    stats
        .iter()
        .find(|(i, _)| i.addr == addr)
        .map_or(Counts::default(), |(_, s)| Counts {
            received: sum(&s.received),
            held: sum(&s.held),
            advertised: sum(&s.advertised),
        })
}

/// Per family of an Established neighbor: its routes, and the limit.
fn per_family(
    stats: &[(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)],
    addr: IpAddr,
) -> Vec<(AddressFamily, Counts, Option<u32>)> {
    let Some((info, s)) = stats.iter().find(|(i, _)| i.addr == addr) else {
        return Vec::new();
    };
    let of = |v: &[(AddressFamily, usize)], family| {
        v.iter().find(|(f, _)| *f == family).map_or(0, |(_, n)| *n)
    };
    s.received
        .iter()
        .map(|&(family, received)| {
            let counts = Counts {
                received,
                held: of(&s.held, family),
                advertised: of(&s.advertised, family),
            };
            (family, counts, info.prefix_limit(family))
        })
        .collect()
}

fn write_neighbor(
    j: &mut Json,
    r: &PeerReport,
    stats: &[(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)],
) {
    let all = counts(stats, r.addr);
    j.begin_object()
        .field_display("address", r.addr)
        .field_num("remote_as", r.remote_as.0)
        .field_display("state", r.state)
        .field_num("since_seconds", r.since.as_secs())
        .field_bool("admin_down", r.admin_down)
        .field_bool("restart_limit_reached", r.restart_limit_reached)
        .field_num("updates_in", r.updates_in)
        .field_num("updates_out", r.updates_out)
        .field_num("received", num(all.received))
        .field_num("held", num(all.held))
        .field_num("advertised", num(all.advertised));
    j.key("prefixes").begin_array();
    for (family, c, limit) in per_family(stats, r.addr) {
        j.begin_object()
            .field_display("family", family)
            .field_num("received", num(c.received))
            .field_num("held", num(c.held))
            .field_num("advertised", num(c.advertised))
            .field_opt_num("limit", limit)
            .end_object();
    }
    j.end_array();
    j.key("session");
    match &r.session {
        Some(s) => {
            j.begin_object()
                .field_display("router_id", s.peer_router_id)
                .field_num("hold_time", s.hold_time.secs())
                .field_num("keepalive_time", s.keepalive_time.as_secs())
                .field_bool("four_octet_as", s.four_octet_as)
                .field_bool("extended_messages", s.extended_messages)
                .field_bool("route_refresh", s.route_refresh)
                .key("families")
                .begin_array();
            for f in &s.families {
                j.display(f);
            }
            // RFC 8950 §4: families that may carry an IPv6 next hop, from
            // the peer and to it.
            j.end_array()
                .key("extended_next_hop")
                .begin_object()
                .key("receive")
                .begin_array();
            for f in &s.extended_next_hop_receive {
                j.display(f);
            }
            j.end_array().key("send").begin_array();
            for f in &s.extended_next_hop_send {
                j.display(f);
            }
            j.end_array().end_object().end_object();
        }
        None => {
            j.null();
        }
    }
    j.end_object();
}

fn render_neighbors(
    reports: &[PeerReport],
    stats: &[(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)],
) -> Reply {
    let mut lines = vec![format!(
        "{:<40} {:>10} {:<12} {:>9} {:>9} {:>9}",
        "neighbor", "as", "state", "since", "received", "advertised"
    )];
    let mut j = Json::new();
    j.begin_array();
    for r in reports {
        let c = counts(stats, r.addr);
        lines.push(format!(
            "{:<40} {:>10} {:<12} {:>8}s {:>9} {:>9}",
            r.addr,
            r.remote_as.0,
            // `State` writes itself without the padding a width asks for.
            r.state.to_string(),
            r.since.as_secs(),
            c.received,
            c.advertised
        ));
        write_neighbor(&mut j, r, stats);
    }
    j.end_array();
    Reply {
        lines,
        json: j.finish(),
    }
}

fn render_neighbor(r: &PeerReport, stats: &[(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)]) -> Reply {
    let all = counts(stats, r.addr);
    let mut lines = vec![
        format!("neighbor {}", r.addr),
        format!("  remote-as {}", r.remote_as),
        format!("  state {} for {}s", r.state, r.since.as_secs()),
        format!("  updates in {} out {}", r.updates_in, r.updates_out),
        format!(
            "  routes received {} held {} advertised {}",
            all.received, all.held, all.advertised
        ),
    ];
    for (family, c, limit) in per_family(stats, r.addr) {
        lines.push(format!(
            "    {family} received {} held {} advertised {}{}",
            c.received,
            c.held,
            c.advertised,
            limit.map_or(String::new(), |l| format!(" maximum-prefix {l}"))
        ));
    }
    if r.admin_down {
        lines.push("  administratively down".to_owned());
    }
    if r.restart_limit_reached {
        // RFC 4486 §4: no more automatic retries until the operator acts.
        lines.push("  restart limit reached: idle until `bgpfcctl clear neighbor`".to_owned());
    }
    if let Some(s) = &r.session {
        lines.push(format!("  router-id {}", s.peer_router_id));
        lines.push(format!(
            "  hold-time {}s keepalive {}s",
            s.hold_time.secs(),
            s.keepalive_time.as_secs()
        ));
        lines.push(format!(
            "  capabilities four-octet-as={} extended-messages={} route-refresh={}",
            s.four_octet_as, s.extended_messages, s.route_refresh
        ));
        if !s.extended_next_hop_receive.is_empty() || !s.extended_next_hop_send.is_empty() {
            let list = |families: &[AddressFamily]| {
                if families.is_empty() {
                    "none".to_owned()
                } else {
                    families
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                }
            };
            lines.push(format!(
                "  extended-next-hop receive {} send {}",
                list(&s.extended_next_hop_receive),
                list(&s.extended_next_hop_send)
            ));
        }
        lines.push(format!(
            "  families {}",
            s.families
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    let mut j = Json::new();
    write_neighbor(&mut j, r, stats);
    Reply {
        lines,
        json: j.finish(),
    }
}

const ROUTES_HEADER: &str = "prefix                                       next-hop                                 origin   lpref     med rov       path";

/// Routes few enough to answer whole.
fn render_routes(routes: &[RouteReport]) -> Reply {
    let mut lines = vec![ROUTES_HEADER.to_owned()];
    lines.extend(routes.iter().map(route_line));
    let mut j = Json::new();
    j.begin_array();
    for r in routes {
        route_json(&mut j, r);
    }
    j.end_array();
    Reply {
        lines,
        json: j.finish(),
    }
}

/// One route of `show routes`: `*` marks the best, `!` a route held for
/// its validation state, whose reason follows the peer. The `rov` column
/// has the state the lookup gave the route (RFC 6811 §2) and, after `>`,
/// the one import policy set (RFC 6811 §3), which the route is used with;
/// it outgrows its column then.
fn route_line(r: &RouteReport) -> String {
    let a = &r.attrs;
    let path: Vec<String> = a.as_path.asns().map(|x| x.0.to_string()).collect();
    let rov = match r.rov_set {
        Some(set) => format!("{}>{}", r.rov, set),
        None => r.rov.as_str().to_owned(),
    };
    // `Prefix` and `Origin` write themselves without the padding a width
    // asks for, so they are padded as strings.
    format!(
        "{}{:<43} {:<40} {:<8} {:>5} {:>7} {:<9} {} via {}{}",
        match (r.best, r.held) {
            (true, _) => "*",
            (false, Some(_)) => "!",
            (false, None) => " ",
        },
        r.prefix.to_string(),
        a.next_hop_addr(),
        a.origin.to_string(),
        a.local_pref.map_or("-".to_owned(), |v| v.to_string()),
        a.med.map_or("-".to_owned(), |v| v.to_string()),
        rov,
        if path.is_empty() {
            "-".to_owned()
        } else {
            path.join(" ")
        },
        r.peer,
        r.held.map_or(String::new(), |by| format!(" held by {by}"))
    )
}

fn route_json(j: &mut Json, r: &RouteReport) {
    let a = &r.attrs;
    j.begin_object()
        .field_display("prefix", r.prefix)
        .field_display("next_hop", a.next_hop_addr())
        .field_display("origin", a.origin)
        .field_opt_num("local_pref", a.local_pref)
        .field_opt_num("med", a.med)
        .field_display("peer", r.peer)
        .field_bool("best", r.best)
        .field_str("rov", r.rov.as_str())
        .field_opt("rov_set", r.rov_set.map(RovState::as_str))
        .field_opt("held", r.held.map(Held::as_str))
        .key("as_path")
        .begin_array();
    for asn in a.as_path.asns() {
        j.number(asn.0);
    }
    j.end_array().key("communities").begin_array();
    for c in &a.communities {
        j.display(c);
    }
    j.end_array().key("large_communities").begin_array();
    for c in &a.large_communities {
        j.display(c);
    }
    j.end_array().end_object();
}

/// A page of the Loc-RIB of `family` after `after`, or every route the
/// Adj-RIBs-In hold for `prefix`; with `held`, only those held for their
/// validation state.
fn rib_routes(
    ctx: &Ctx,
    family: AddressFamily,
    prefix: Option<Prefix>,
    after: Option<Prefix>,
    held: bool,
) -> Result<Vec<RouteReport>, String> {
    let (tx, rx) = sync_channel(1);
    ctx.rib
        .send(RibMsg::Query(
            RibQuery::Routes {
                family,
                prefix,
                after,
                held,
            },
            tx,
        ))
        .map_err(|_| "rib thread gone".to_owned())?;
    match rx.recv_timeout(QUERY_TIMEOUT) {
        Ok(RibReply::Routes(routes)) => Ok(routes),
        Ok(_) => Err("unexpected reply".to_owned()),
        Err(_) => Err("rib did not answer".to_owned()),
    }
}

/// A page of the routes the RIB wants in the FIB.
fn rib_fib_routes(ctx: &Ctx, after: Option<Prefix>) -> Result<Vec<(Prefix, IpAddr)>, String> {
    let (tx, rx) = sync_channel(1);
    ctx.rib
        .send(RibMsg::Query(RibQuery::FibRoutes { after }, tx))
        .map_err(|_| "rib thread gone".to_owned())?;
    match rx.recv_timeout(QUERY_TIMEOUT) {
        Ok(RibReply::FibRoutes(routes)) => Ok(routes),
        Ok(_) => Err("unexpected reply".to_owned()),
        Err(_) => Err("rib did not answer".to_owned()),
    }
}

/// The FIB's mode and a page of its installed routes.
fn fib_report(ctx: &Ctx, after: Option<Prefix>) -> Result<FibReport, String> {
    let (tx, rx) = sync_channel(1);
    ctx.fib
        .send(FibMsg::Query { after, reply: tx })
        .map_err(|_| "fib thread gone".to_owned())?;
    rx.recv_timeout(QUERY_TIMEOUT)
        .map_err(|_| "fib did not answer".to_owned())
}

/// Gets the page of a listing after an item (from the start for `None`).
type Fetch<'a, T> = dyn FnMut(Option<Prefix>) -> Result<Vec<T>, String> + 'a;

/// A listing's items, fetched a page ([`PAGE`]) at a time, in prefix
/// order: each page continues after the last item of the one before.
/// Pages are taken at different times, so a listing is not a snapshot.
pub(crate) struct Pages<'a, T> {
    fetch: Box<Fetch<'a, T>>,
    key: fn(&T) -> Prefix,
    page: VecDeque<T>,
    /// The page held is the last.
    last: bool,
    /// The key of the last item taken.
    taken: Option<Prefix>,
}

impl<'a, T> Pages<'a, T> {
    fn starting(
        first: Vec<T>,
        fetch: impl FnMut(Option<Prefix>) -> Result<Vec<T>, String> + 'a,
        key: fn(&T) -> Prefix,
    ) -> Pages<'a, T> {
        Pages {
            last: first.len() < PAGE,
            page: first.into(),
            fetch: Box::new(fetch),
            key,
            taken: None,
        }
    }

    fn open(
        mut fetch: impl FnMut(Option<Prefix>) -> Result<Vec<T>, String> + 'a,
        key: fn(&T) -> Prefix,
    ) -> Result<Pages<'a, T>, String> {
        let first = fetch(None)?;
        Ok(Pages::starting(first, fetch, key))
    }

    /// The next item, left in place.
    fn peek(&mut self) -> Result<Option<&T>, String> {
        if self.page.is_empty() && !self.last {
            let page = (self.fetch)(self.taken)?;
            self.last = page.len() < PAGE;
            self.page = page.into();
        }
        Ok(self.page.front())
    }

    fn take(&mut self) -> Result<Option<T>, String> {
        self.peek()?;
        let item = self.page.pop_front();
        if let Some(i) = &item {
            self.taken = Some((self.key)(i));
        }
        Ok(item)
    }
}

/// A long listing: `show routes` of a whole family, of its Loc-RIB or of
/// the routes held for their validation state, and `show fib`. A full
/// table has a million routes or more, so it is taken from the RIB and the
/// FIB a page at a time and written as it comes, rather than copied,
/// rendered in both forms and written whole (which took several hundred
/// megabytes for a million routes).
pub(crate) enum Listing<'a> {
    Routes(Pages<'a, RouteReport>),
    /// The routes the RIB wants merged with those installed, in prefix
    /// order: each wanted route is installed or pending, and an installed
    /// route not wanted is stale.
    Fib {
        mode: Mode,
        desired: Pages<'a, (Prefix, IpAddr)>,
        installed: Pages<'a, (Prefix, IpAddr)>,
    },
}

/// One `show fib` row.
struct FibRow {
    prefix: Prefix,
    gateway: IpAddr,
    installed: bool,
    stale: bool,
}

impl<'a> Listing<'a> {
    fn routes(ctx: &'a Ctx, family: AddressFamily, held: bool) -> Result<Listing<'a>, String> {
        let pages = Pages::open(
            move |after| rib_routes(ctx, family, None, after, held),
            |r: &RouteReport| r.prefix,
        )?;
        Ok(Listing::Routes(pages))
    }

    fn fib(ctx: &'a Ctx) -> Result<Listing<'a>, String> {
        // What is installed first: a route the RIB adds meanwhile shows as
        // pending rather than as stale.
        let first = fib_report(ctx, None)?;
        let installed = Pages::starting(
            first.installed,
            move |after| fib_report(ctx, after).map(|r| r.installed),
            |r: &(Prefix, IpAddr)| r.0,
        );
        let desired = Pages::open(move |after| rib_fib_routes(ctx, after), |r| r.0)?;
        Ok(Listing::Fib {
            mode: first.mode,
            desired,
            installed,
        })
    }

    /// The next `show fib` row.
    fn next_fib_row(
        desired: &mut Pages<'_, (Prefix, IpAddr)>,
        installed: &mut Pages<'_, (Prefix, IpAddr)>,
    ) -> Result<Option<FibRow>, String> {
        let d = desired.peek()?.copied();
        let i = installed.peek()?.copied();
        let wanted = |(prefix, gateway): (Prefix, IpAddr), installed| FibRow {
            prefix,
            gateway,
            installed,
            stale: false,
        };
        Ok(match (d, i) {
            (None, None) => None,
            (Some(d), i) if i.is_none_or(|i| d.0 < i.0) => {
                desired.take()?;
                Some(wanted(d, false))
            }
            (Some(d), Some(i)) if d.0 == i.0 => {
                desired.take()?;
                installed.take()?;
                Some(wanted(d, d.1 == i.1))
            }
            (_, Some(i)) => {
                installed.take()?;
                Some(FibRow {
                    prefix: i.0,
                    gateway: i.1,
                    installed: true,
                    stale: true,
                })
            }
            // invariant: the first arm takes (Some, None).
            (Some(_), None) => unreachable!(),
        })
    }

    /// Write as protocol lines. Stops at the first error, leaving the
    /// response unterminated.
    fn write_lines(self, out: &mut proto::Lines<'_, impl Write>) -> Result<(), String> {
        let io = |e: std::io::Error| e.to_string();
        match self {
            Listing::Routes(mut pages) => {
                out.line(ROUTES_HEADER).map_err(io)?;
                while let Some(r) = pages.take()? {
                    out.line(&route_line(&r)).map_err(io)?;
                }
            }
            Listing::Fib {
                mode,
                mut desired,
                mut installed,
            } => {
                out.line(&format!("mode {mode}")).map_err(io)?;
                while let Some(r) = Listing::next_fib_row(&mut desired, &mut installed)? {
                    let state = match (r.stale, r.installed) {
                        (true, _) => "stale",
                        (false, true) => "installed",
                        (false, false) => "pending",
                    };
                    // `Prefix` writes itself without the padding a width
                    // asks for.
                    let prefix = r.prefix.to_string();
                    out.line(&format!("{prefix:<44} via {:<40} {state}", r.gateway))
                        .map_err(io)?;
                }
            }
        }
        Ok(())
    }

    /// Write as a JSON document. Stops at the first error, leaving the
    /// document incomplete.
    fn write_json(self, out: &mut impl Write) -> Result<(), String> {
        let io = |e: std::io::Error| e.to_string();
        let mut first = true;
        let mut item = |out: &mut dyn Write, j: Json| -> Result<(), String> {
            if !std::mem::take(&mut first) {
                out.write_all(b",").map_err(io)?;
            }
            out.write_all(j.finish().as_bytes()).map_err(io)
        };
        match self {
            Listing::Routes(mut pages) => {
                out.write_all(b"[").map_err(io)?;
                while let Some(r) = pages.take()? {
                    let mut j = Json::new();
                    route_json(&mut j, &r);
                    item(out, j)?;
                }
                out.write_all(b"]").map_err(io)?;
            }
            Listing::Fib {
                mode,
                mut desired,
                mut installed,
            } => {
                let mut j = Json::new();
                j.begin_object().field_display("mode", mode).key("routes");
                out.write_all(j.finish().as_bytes()).map_err(io)?;
                out.write_all(b"[").map_err(io)?;
                while let Some(r) = Listing::next_fib_row(&mut desired, &mut installed)? {
                    let mut j = Json::new();
                    j.begin_object()
                        .field_display("prefix", r.prefix)
                        .field_display("gateway", r.gateway)
                        .field_bool("installed", r.installed);
                    if r.stale {
                        j.field_bool("stale", true);
                    }
                    j.end_object();
                    item(out, j)?;
                }
                out.write_all(b"]}").map_err(io)?;
            }
        }
        out.flush().map_err(io)
    }
}

/// Listen on the Unix socket; one thread per connection.
pub(crate) fn serve_unix(path: &Path, ctx: Ctx) -> std::io::Result<()> {
    if path.exists() {
        // A stale socket from a previous run; nobody can be listening on
        // it if we got this far (the daemon is single-instance per path).
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    bgpfc_log::info!("control socket", path = path.display());
    thread::Builder::new()
        .name("control-unix".to_owned())
        .spawn(move || {
            for conn in listener.incoming() {
                let Ok(stream) = conn else { continue };
                let ctx = ctx.clone();
                let _ = thread::Builder::new()
                    .name("control-conn".to_owned())
                    .spawn(move || unix_connection(&stream, &ctx));
            }
        })?;
    Ok(())
}

fn unix_connection(stream: &UnixStream, ctx: &Ctx) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut w = stream;
    let answer = proto::Request::parse(line.trim_end_matches(['\r', '\n']))
        .map_err(|e| e.to_string())
        .and_then(|req| Command::parse(&req.words))
        .and_then(|c| execute(ctx, &c));
    let _ = match answer {
        Ok(Answer::Reply(reply)) => proto::Response::ok(reply.lines).write_to(&mut w),
        Ok(Answer::Listing(listing)) => {
            // A write per line would be several million system calls.
            let mut b = BufWriter::with_capacity(LISTING_BUFFER, &mut w);
            proto::Lines::begin(&mut b).and_then(|mut lines| {
                match listing.write_lines(&mut lines) {
                    Ok(()) => lines.end(),
                    // The client sees the response cut short.
                    Err(e) => {
                        bgpfc_log::warn!("control: listing cut short", error = e);
                        Ok(())
                    }
                }
            })
        }
        Err(e) => proto::Response::error(e).write_to(&mut w),
    };
}

/// Listen for HTTP on a loopback address (config validation guarantees
/// loopback); a bounded number of connections at once.
pub(crate) fn serve_http(addr: SocketAddr, ctx: Ctx) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    bgpfc_log::info!(
        "http api",
        address = addr,
        writes = ctx.writes,
        token = ctx.token.is_some()
    );
    let active = Arc::new(AtomicUsize::new(0));
    thread::Builder::new()
        .name("control-http".to_owned())
        .spawn(move || {
            for conn in listener.incoming() {
                let Ok(stream) = conn else { continue };
                if active.load(Ordering::Relaxed) >= MAX_HTTP_CONNECTIONS {
                    let mut s = &stream;
                    let _ = http::Response::error(503, "too many connections").write_to(&mut s);
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);
                let ctx = ctx.clone();
                let active = Arc::clone(&active);
                let _ = thread::Builder::new()
                    .name("http-conn".to_owned())
                    .spawn(move || {
                        http_connection(&stream, &ctx);
                        active.fetch_sub(1, Ordering::Relaxed);
                    });
            }
        })?;
    Ok(())
}

fn http_connection(stream: &TcpStream, ctx: &Ctx) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut reader = BufReader::new(stream);
    let mut w = stream;
    let response = match http::Request::read_from(&mut reader) {
        Err(http::HttpError::TooLarge) => http::Response::error(413, "request too large"),
        Err(e) => http::Response::error(400, &e.to_string()),
        Ok(req) => match http_respond(ctx, &req) {
            HttpAnswer::Response(response) => response,
            HttpAnswer::Listing(listing) => {
                // The body runs until the connection closes, as it is
                // produced.
                let head = http::Response::json(200, String::new());
                let mut b = BufWriter::with_capacity(LISTING_BUFFER, &mut w);
                if head.write_head_until_close(&mut b).is_ok()
                    && let Err(e) = listing.write_json(&mut b)
                {
                    bgpfc_log::warn!("control: listing cut short", error = e);
                }
                return;
            }
        },
    };
    let _ = response.write_to(&mut w);
}

/// What an HTTP request is answered with.
enum HttpAnswer<'a> {
    Response(http::Response),
    /// A listing, the body of a 200 response.
    Listing(Listing<'a>),
}

fn http_respond<'a>(ctx: &'a Ctx, req: &http::Request) -> HttpAnswer<'a> {
    // RFC 6750 §2.1: the token, when configured, is required on every
    // request, before the resource is even looked at.
    if let Some(token) = &ctx.token
        && req.bearer_token() != Some(token.as_str())
    {
        let mut r = http::Response::error(401, "bearer token required");
        r.extra
            .push(("WWW-Authenticate".to_owned(), "Bearer".to_owned()));
        return HttpAnswer::Response(r);
    }
    let cmd = match Command::from_http(req) {
        Ok(c) => c,
        Err((status, m)) => return HttpAnswer::Response(http::Response::error(status, &m)),
    };
    if cmd.is_write() && !ctx.writes {
        return HttpAnswer::Response(http::Response::error(
            403,
            "write endpoints are disabled (control { http { writes yes; } })",
        ));
    }
    match execute(ctx, &cmd) {
        Ok(Answer::Reply(reply)) => HttpAnswer::Response(http::Response::json(200, reply.json)),
        Ok(Answer::Listing(listing)) => HttpAnswer::Listing(listing),
        Err(e) => HttpAnswer::Response(http::Response::error(
            if e.starts_with("no neighbor") {
                404
            } else {
                500
            },
            &e,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgpfc_rib::RovState;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    fn fib_route(prefix: &str, gateway: &str) -> (Prefix, IpAddr) {
        (prefix.parse().unwrap(), gateway.parse().unwrap())
    }

    #[test]
    fn fib_rows_merge_wanted_and_installed_in_prefix_order() {
        let none = |_| Ok(Vec::new());
        let mut desired = Pages::starting(
            vec![
                fib_route("10.0.0.0/8", "192.0.2.1"),
                fib_route("10.2.0.0/16", "192.0.2.2"),
                fib_route("2001:db8::/32", "fe80::1"),
            ],
            none,
            |r| r.0,
        );
        let mut installed = Pages::starting(
            vec![
                fib_route("10.0.0.0/8", "192.0.2.1"),
                fib_route("10.1.0.0/16", "192.0.2.9"),
                fib_route("10.2.0.0/16", "192.0.2.3"),
            ],
            none,
            |r| r.0,
        );
        let mut rows = Vec::new();
        while let Some(r) = Listing::next_fib_row(&mut desired, &mut installed).unwrap() {
            rows.push((r.prefix.to_string(), r.installed, r.stale));
        }
        let row = |p: &str, installed, stale| (p.to_owned(), installed, stale);
        assert_eq!(
            rows,
            vec![
                row("10.0.0.0/8", true, false),
                row("10.1.0.0/16", true, true),
                row("10.2.0.0/16", false, false),
                row("2001:db8::/32", false, false),
            ]
        );
    }

    #[test]
    fn pages_continue_after_the_last_item_of_a_full_page() {
        let all: Vec<(Prefix, IpAddr)> = (0..=PAGE)
            .map(|i| {
                let [a, b] = u16::try_from(i).unwrap().to_be_bytes();
                let p = Prefix::new(IpAddr::from([10, a, b, 0]), 24).unwrap();
                (p, "192.0.2.1".parse().unwrap())
            })
            .collect();
        let mut fetches = Vec::new();
        let mut pages = Pages::open(
            |after| {
                fetches.push(after);
                let from = after.map_or(0, |a| all.iter().position(|r| r.0 == a).unwrap() + 1);
                Ok(all[from..].iter().take(PAGE).copied().collect())
            },
            |r| r.0,
        )
        .unwrap();
        let mut n = 0;
        while pages.take().unwrap().is_some() {
            n += 1;
        }
        drop(pages);
        assert_eq!(n, PAGE + 1);
        assert_eq!(fetches, vec![None, Some(all[PAGE - 1].0)]);
    }

    #[test]
    fn neighbor_detail_shows_the_extended_next_hop_families() {
        use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};
        let mut session = bgpfc_fsm::Session {
            peer_as: Asn(65_001),
            peer_router_id: RouterId::new(2).unwrap(),
            peer: bgpfc_wire::update::PeerKind::External,
            hold_time: HoldTime::new(90).unwrap(),
            keepalive_time: Duration::from_secs(30),
            four_octet_as: true,
            extended_messages: true,
            route_refresh: true,
            families: vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST],
            receive_families: vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST],
            extended_next_hop_receive: vec![AddressFamily::IPV4_UNICAST],
            extended_next_hop_send: vec![AddressFamily::IPV4_UNICAST],
            peer_capabilities: Vec::new(),
        };
        let mut report = PeerReport {
            addr: "2001:db8::2".parse().unwrap(),
            remote_as: Asn(65_001),
            state: bgpfc_fsm::State::Established,
            since: Duration::from_secs(5),
            session: Some(session.clone()),
            updates_in: 0,
            updates_out: 0,
            admin_down: false,
            restart_limit_reached: false,
        };
        let r = render_neighbor(&report, &[]);
        assert!(
            r.lines
                .contains(&"  extended-next-hop receive ipv4-unicast send ipv4-unicast".to_owned()),
            "{:?}",
            r.lines
        );
        assert!(
            r.json.contains(
                r#""extended_next_hop":{"receive":["ipv4-unicast"],"send":["ipv4-unicast"]}"#
            ),
            "{}",
            r.json
        );
        // RFC 8950 §4 advertised by us alone: taken, not sent.
        session.extended_next_hop_send.clear();
        report.session = Some(session.clone());
        let r = render_neighbor(&report, &[]);
        assert!(
            r.lines
                .contains(&"  extended-next-hop receive ipv4-unicast send none".to_owned()),
            "{:?}",
            r.lines
        );
        assert!(
            r.json
                .contains(r#""extended_next_hop":{"receive":["ipv4-unicast"],"send":[]}"#),
            "{}",
            r.json
        );
        // Not at all: no line, empty lists.
        session.extended_next_hop_receive.clear();
        report.session = Some(session);
        let r = render_neighbor(&report, &[]);
        assert!(!r.lines.iter().any(|l| l.contains("extended-next-hop")));
        assert!(
            r.json
                .contains(r#""extended_next_hop":{"receive":[],"send":[]}"#),
            "{}",
            r.json
        );
    }

    #[test]
    fn neighbor_detail_counts_routes_per_family_against_the_limit() {
        use bgpfc_wire::types::HoldTime;
        let addr: IpAddr = "192.0.2.2".parse().unwrap();
        let v4 = AddressFamily::IPV4_UNICAST;
        let v6 = AddressFamily::IPV6_UNICAST;
        let info = bgpfc_rib::PeerInfo {
            addr,
            local_addr: "192.0.2.1".parse().unwrap(),
            remote_as: Asn(65_001),
            router_id: RouterId::new(2).unwrap(),
            kind: bgpfc_wire::update::PeerKind::External,
            families: vec![v4, v6],
            receive_families: vec![v4, v6],
            four_octet_as: true,
            extended_messages: false,
            route_refresh: true,
            extended_next_hop: Vec::new(),
            advertisement_interval: Duration::ZERO,
            prefix_limits: vec![(v4, 1000)],
        };
        let stats = bgpfc_rib::PeerStats {
            received: vec![(v4, 12), (v6, 3)],
            held: vec![(v4, 2), (v6, 0)],
            advertised: vec![(v4, 4), (v6, 0)],
        };
        let report = PeerReport {
            addr,
            remote_as: Asn(65_001),
            state: bgpfc_fsm::State::Established,
            since: Duration::from_secs(5),
            session: Some(bgpfc_fsm::Session {
                peer_as: Asn(65_001),
                peer_router_id: RouterId::new(2).unwrap(),
                peer: bgpfc_wire::update::PeerKind::External,
                hold_time: HoldTime::new(90).unwrap(),
                keepalive_time: Duration::from_secs(30),
                four_octet_as: true,
                extended_messages: false,
                route_refresh: true,
                families: vec![v4, v6],
                receive_families: vec![v4, v6],
                extended_next_hop_receive: Vec::new(),
                extended_next_hop_send: Vec::new(),
                peer_capabilities: Vec::new(),
            }),
            updates_in: 7,
            updates_out: 1,
            admin_down: false,
            restart_limit_reached: false,
        };
        let r = render_neighbor(&report, &[(info, stats)]);
        // RFC 4271 §6.7: what the limit counts, next to the limit, with
        // the routes held for their validation state among them.
        for line in [
            "  routes received 15 held 2 advertised 4",
            "    ipv4-unicast received 12 held 2 advertised 4 maximum-prefix 1000",
            "    ipv6-unicast received 3 held 0 advertised 0",
        ] {
            assert!(r.lines.contains(&line.to_owned()), "{line}: {:?}", r.lines);
        }
        assert!(
            r.json.contains(concat!(
                r#""received":15,"held":2,"advertised":4,"prefixes":["#,
                r#"{"family":"ipv4-unicast","received":12,"held":2,"advertised":4,"limit":1000},"#,
                r#"{"family":"ipv6-unicast","received":3,"held":0,"advertised":0,"limit":null}]"#
            )),
            "{}",
            r.json
        );
        // Not up in the RIB: no families.
        let r = render_neighbor(&report, &[]);
        assert!(r.json.contains(r#""prefixes":[]"#), "{}", r.json);
    }

    #[test]
    fn neighbor_detail_says_when_the_restart_limit_stopped_it() {
        let mut report = PeerReport {
            addr: "192.0.2.2".parse().unwrap(),
            remote_as: Asn(65_001),
            state: bgpfc_fsm::State::Idle,
            since: Duration::from_secs(5),
            session: None,
            updates_in: 0,
            updates_out: 0,
            admin_down: false,
            restart_limit_reached: false,
        };
        let r = render_neighbor(&report, &[]);
        assert!(!r.lines.iter().any(|l| l.contains("restart limit")));
        assert!(
            r.json.contains(r#""restart_limit_reached":false"#),
            "{}",
            r.json
        );
        // RFC 4486 §4: the operator must act, and is told how.
        report.restart_limit_reached = true;
        let r = render_neighbor(&report, &[]);
        assert!(
            r.lines.contains(
                &"  restart limit reached: idle until `bgpfcctl clear neighbor`".to_owned()
            ),
            "{:?}",
            r.lines
        );
        assert!(
            r.json.contains(r#""restart_limit_reached":true"#),
            "{}",
            r.json
        );
    }

    #[test]
    fn neighbors_and_fib_render_in_columns() {
        let report = PeerReport {
            addr: "192.0.2.2".parse().unwrap(),
            remote_as: Asn(65_001),
            state: bgpfc_fsm::State::Idle,
            since: Duration::from_secs(5),
            session: None,
            updates_in: 0,
            updates_out: 0,
            admin_down: false,
            restart_limit_reached: false,
        };
        let r = render_neighbors(&[report], &[]);
        assert_eq!(
            r.lines[1],
            format!(
                "{:<40} {:>10} {:<12} {:>8}s {:>9} {:>9}",
                "192.0.2.2", "65001", "Idle", "5", "0", "0"
            )
        );
        let gw = "198.51.100.1";
        let none = |_| Ok(Vec::new());
        let listing = Listing::Fib {
            mode: Mode::Install,
            desired: Pages::starting(
                vec![
                    fib_route("192.0.2.0/24", gw),
                    fib_route("198.51.100.0/24", gw),
                ],
                none,
                |r| r.0,
            ),
            installed: Pages::starting(
                vec![
                    fib_route("192.0.2.0/24", gw),
                    fib_route("203.0.113.0/24", gw),
                ],
                none,
                |r| r.0,
            ),
        };
        let mut text = Vec::new();
        let mut lines = proto::Lines::begin(&mut text).unwrap();
        listing.write_lines(&mut lines).unwrap();
        let text = String::from_utf8(text).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[2..],
            [
                format!(
                    "{:<44} via {:<40} installed",
                    "192.0.2.0/24", "198.51.100.1"
                ),
                format!(
                    "{:<44} via {:<40} pending",
                    "198.51.100.0/24", "198.51.100.1"
                ),
                format!("{:<44} via {:<40} stale", "203.0.113.0/24", "198.51.100.1"),
            ]
        );
    }

    /// A route to `prefix` from `peer` along `path`, not the best, and
    /// not validated.
    fn route(
        prefix: &str,
        peer: &str,
        path: &[u32],
        local_pref: Option<u32>,
        med: Option<u32>,
    ) -> RouteReport {
        use bgpfc_wire::as_path::AsPath;
        use bgpfc_wire::attribute::Origin;
        use bgpfc_wire::community::Community;
        use bgpfc_wire::mp::NextHop;
        let peer: std::net::Ipv4Addr = peer.parse().unwrap();
        let path: Vec<Asn> = path.iter().map(|&a| Asn(a)).collect();
        RouteReport {
            prefix: prefix.parse().unwrap(),
            peer: IpAddr::V4(peer),
            attrs: Arc::new(bgpfc_rib::PathAttrs {
                origin: Origin::Igp,
                as_path: AsPath::sequence(&path),
                next_hop: NextHop::Ipv4(peer),
                med,
                local_pref,
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![Community(0xFBFF_0064)].into(),
                ext_communities: Box::default(),
                large_communities: Box::default(),
                unknown: Box::default(),
            }),
            best: false,
            rov: RovState::Disabled,
            rov_set: None,
            held: None,
        }
    }

    #[test]
    fn routes_render_as_lines_and_json() {
        // Two routes to one destination, from different origin ASes: a
        // VRP for AS 64496 makes one valid and the other invalid. The
        // invalid one stays a candidate (RFC 6811 §2) where nothing acts
        // on its state, as under `enforcement off`.
        let mut best = route(
            "192.0.2.0/24",
            "198.51.100.1",
            &[64_511, 64_496],
            Some(100),
            None,
        );
        best.best = true;
        best.rov = RovState::Valid;
        let mut other = route("192.0.2.0/24", "198.51.100.2", &[64_497], None, Some(50));
        other.rov = RovState::Invalid;
        let r = render_routes(&[best, other]);
        // Every column starts where its header does; `*` marks the best.
        assert_eq!(
            r.lines,
            [
                format!(
                    "{:<44} {:<40} {:<8} {:>5} {:>7} {:<9} path",
                    "prefix", "next-hop", "origin", "lpref", "med", "rov"
                ),
                format!(
                    "{:<44} {:<40} {:<8} {:>5} {:>7} {:<9} 64511 64496 via 198.51.100.1",
                    "*192.0.2.0/24", "198.51.100.1", "igp", "100", "-", "valid"
                ),
                format!(
                    "{:<44} {:<40} {:<8} {:>5} {:>7} {:<9} 64497 via 198.51.100.2",
                    " 192.0.2.0/24", "198.51.100.2", "igp", "-", "50", "invalid"
                ),
            ]
        );
        // docs/control.md: `local_pref` and `med` are numbers, or null;
        // `rov` is the state's name; nothing set or held.
        assert_eq!(
            r.json,
            concat!(
                r#"[{"prefix":"192.0.2.0/24","next_hop":"198.51.100.1","origin":"igp","#,
                r#""local_pref":100,"med":null,"peer":"198.51.100.1","best":true,"#,
                r#""rov":"valid","rov_set":null,"held":null,"as_path":[64511,64496],"#,
                r#""communities":["64511:100"],"large_communities":[]},"#,
                r#"{"prefix":"192.0.2.0/24","next_hop":"198.51.100.2","origin":"igp","#,
                r#""local_pref":null,"med":50,"peer":"198.51.100.2","best":false,"#,
                r#""rov":"invalid","rov_set":null,"held":null,"as_path":[64497],"#,
                r#""communities":["64511:100"],"large_communities":[]}]"#
            )
        );
        // Every state, by its name, both ways.
        for rov in RovState::ALL {
            let mut r = route("2001:db8::/32", "198.51.100.1", &[], None, None);
            r.rov = rov;
            let out = render_routes(&[r]);
            assert!(
                out.lines[1].contains(&format!(" {:<9} - via ", rov.as_str())),
                "{:?}",
                out.lines
            );
            assert!(
                out.json.contains(&format!(r#""rov":"{rov}""#)),
                "{}",
                out.json
            );
        }
    }

    #[test]
    fn routes_render_held_routes_and_overrides() {
        // RFC 6811 §2: the routes the Adj-RIB-In holds for their state are
        // listed after the candidates, marked `!` with the reason; §3: a
        // state import policy set is shown after the looked-up one.
        let mut best = route("192.0.2.0/24", "198.51.100.1", &[64_496], None, None);
        best.best = true;
        best.rov = RovState::Invalid;
        best.rov_set = Some(RovState::Valid);
        let mut dropped = route("192.0.2.0/24", "198.51.100.2", &[64_497], None, None);
        dropped.rov = RovState::Invalid;
        dropped.held = Some(Held::Enforcement);
        let mut rejected = route("192.0.2.0/24", "198.51.100.3", &[64_498], None, None);
        rejected.rov = RovState::NotFound;
        rejected.held = Some(Held::Policy);
        let r = render_routes(&[best, dropped, rejected]);
        assert_eq!(
            r.lines[1..],
            [
                format!(
                    "{:<44} {:<40} {:<8} {:>5} {:>7} {:<9} 64496 via 198.51.100.1",
                    "*192.0.2.0/24", "198.51.100.1", "igp", "-", "-", "invalid>valid"
                ),
                format!(
                    "{:<44} {:<40} {:<8} {:>5} {:>7} {:<9} 64497 via 198.51.100.2 \
                     held by enforcement",
                    "!192.0.2.0/24", "198.51.100.2", "igp", "-", "-", "invalid"
                ),
                format!(
                    "{:<44} {:<40} {:<8} {:>5} {:>7} {:<9} 64498 via 198.51.100.3 \
                     held by policy",
                    "!192.0.2.0/24", "198.51.100.3", "igp", "-", "-", "not-found"
                ),
            ]
        );
        assert_eq!(
            r.json,
            concat!(
                r#"[{"prefix":"192.0.2.0/24","next_hop":"198.51.100.1","origin":"igp","#,
                r#""local_pref":null,"med":null,"peer":"198.51.100.1","best":true,"#,
                r#""rov":"invalid","rov_set":"valid","held":null,"as_path":[64496],"#,
                r#""communities":["64511:100"],"large_communities":[]},"#,
                r#"{"prefix":"192.0.2.0/24","next_hop":"198.51.100.2","origin":"igp","#,
                r#""local_pref":null,"med":null,"peer":"198.51.100.2","best":false,"#,
                r#""rov":"invalid","rov_set":null,"held":"enforcement","as_path":[64497],"#,
                r#""communities":["64511:100"],"large_communities":[]},"#,
                r#"{"prefix":"192.0.2.0/24","next_hop":"198.51.100.3","origin":"igp","#,
                r#""local_pref":null,"med":null,"peer":"198.51.100.3","best":false,"#,
                r#""rov":"not-found","rov_set":null,"held":"policy","as_path":[64498],"#,
                r#""communities":["64511:100"],"large_communities":[]}]"#
            )
        );
        // The same lines in a listing of the held routes of a family.
        let mut held = route("2001:db8::/32", "198.51.100.2", &[64_497], None, None);
        held.rov = RovState::Invalid;
        held.held = Some(Held::Enforcement);
        let listing = Listing::Routes(Pages::starting(
            vec![held.clone()],
            |_| Ok(Vec::new()),
            |r| r.prefix,
        ));
        let mut text = Vec::new();
        let mut lines = proto::Lines::begin(&mut text).unwrap();
        listing.write_lines(&mut lines).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert_eq!(text.lines().nth(2), Some(route_line(&held).as_str()));
        assert!(route_line(&held).starts_with("!2001:db8::/32 "));
    }

    #[test]
    fn neighbor_detail_counts_held_routes() {
        // The summary table keeps its columns; the JSON of every neighbor
        // has the held routes, in all and per family.
        let addr: IpAddr = "192.0.2.2".parse().unwrap();
        let v4 = AddressFamily::IPV4_UNICAST;
        let info = bgpfc_rib::PeerInfo {
            addr,
            local_addr: "192.0.2.1".parse().unwrap(),
            remote_as: Asn(65_001),
            router_id: RouterId::new(2).unwrap(),
            kind: bgpfc_wire::update::PeerKind::External,
            families: vec![v4],
            receive_families: vec![v4],
            four_octet_as: true,
            extended_messages: false,
            route_refresh: true,
            extended_next_hop: Vec::new(),
            advertisement_interval: Duration::ZERO,
            prefix_limits: Vec::new(),
        };
        let stats = bgpfc_rib::PeerStats {
            received: vec![(v4, 7)],
            held: vec![(v4, 3)],
            advertised: vec![(v4, 1)],
        };
        let report = PeerReport {
            addr,
            remote_as: Asn(65_001),
            state: bgpfc_fsm::State::Established,
            since: Duration::from_secs(5),
            session: None,
            updates_in: 0,
            updates_out: 0,
            admin_down: false,
            restart_limit_reached: false,
        };
        let all = [(info, stats)];
        let r = render_neighbors(std::slice::from_ref(&report), &all);
        assert_eq!(
            r.lines[1],
            format!(
                "{:<40} {:>10} {:<12} {:>8}s {:>9} {:>9}",
                "192.0.2.2", "65001", "Established", "5", "7", "1"
            )
        );
        assert!(
            r.json.contains(concat!(
                r#""received":7,"held":3,"advertised":1,"prefixes":["#,
                r#"{"family":"ipv4-unicast","received":7,"held":3,"advertised":1,"limit":null}]"#
            )),
            "{}",
            r.json
        );
        let r = render_neighbor(&report, &all);
        assert!(
            r.lines
                .contains(&"    ipv4-unicast received 7 held 3 advertised 1".to_owned()),
            "{:?}",
            r.lines
        );
        // Not in the RIB: nothing held.
        let r = render_neighbor(&report, &[]);
        assert!(
            r.lines
                .contains(&"  routes received 0 held 0 advertised 0".to_owned()),
            "{:?}",
            r.lines
        );
        assert!(
            r.json.contains(r#""received":0,"held":0,"advertised":0"#),
            "{}",
            r.json
        );
    }

    #[test]
    fn parses_held_and_transitions_commands() {
        let p = |s: &str| -> Prefix { s.parse().unwrap() };
        let routes = |family, prefix: Option<&str>, held| Command::ShowRoutes {
            family,
            prefix: prefix.map(p),
            held,
        };
        let v4 = AddressFamily::IPV4_UNICAST;
        let v6 = AddressFamily::IPV6_UNICAST;
        for (text, expected) in [
            ("show routes held", routes(v4, None, true)),
            ("show routes ipv6 held", routes(v6, None, true)),
            ("show routes held ipv6", routes(v6, None, true)),
            (
                "show routes 192.0.2.0/24 held",
                routes(v4, Some("192.0.2.0/24"), true),
            ),
            (
                "show routes 2001:db8::/32",
                routes(v6, Some("2001:db8::/32"), false),
            ),
        ] {
            assert_eq!(Command::parse(&words(text)), Ok(expected), "{text}");
        }
        let err = Command::parse(&words("show routes hold")).unwrap_err();
        assert!(err.contains("ipv4, ipv6, held or a prefix"), "{err}");
        assert!(!routes(v4, None, true).is_write());
        let get = |path: &str| {
            http::Request::read_from(&mut format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
                .unwrap()
        };
        assert_eq!(
            Command::parse(&words("show rpki transitions")),
            Ok(Command::ShowRpkiTransitions)
        );
        for bad in ["show rpki transitions all", "show rpki transition"] {
            assert!(Command::parse(&words(bad)).is_err(), "{bad}");
        }
        assert!(!Command::ShowRpkiTransitions.is_write());
        for (path, expected) in [
            ("/v1/rpki/transitions", Command::ShowRpkiTransitions),
            ("/v1/routes?held=1", routes(v4, None, true)),
            ("/v1/routes?family=ipv6&held=yes", routes(v6, None, true)),
            ("/v1/routes?family=ipv4&held=0", routes(v4, None, false)),
            (
                "/v1/routes?prefix=192.0.2.0/24&held=true",
                routes(v4, Some("192.0.2.0/24"), true),
            ),
        ] {
            assert_eq!(Command::from_http(&get(path)), Ok(expected), "{path}");
        }
    }

    #[test]
    fn parses_commands() {
        assert_eq!(
            Command::parse(&words("show neighbors")),
            Ok(Command::ShowNeighbors)
        );
        assert_eq!(
            Command::parse(&words("show neighbor 10.0.0.1")),
            Ok(Command::ShowNeighbor("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            Command::parse(&words("show routes ipv6")),
            Ok(Command::ShowRoutes {
                family: AddressFamily::IPV6_UNICAST,
                prefix: None,
                held: false
            })
        );
        assert_eq!(
            Command::parse(&words("show routes 2001:db8::/32")),
            Ok(Command::ShowRoutes {
                family: AddressFamily::IPV6_UNICAST,
                prefix: Some("2001:db8::/32".parse().unwrap()),
                held: false
            })
        );
        assert_eq!(
            Command::parse(&words("clear neighbor 10.0.0.1 soft")),
            Ok(Command::ClearNeighbor {
                addr: "10.0.0.1".parse().unwrap(),
                soft: true,
                message: None
            })
        );
        let m = Command::parse(&[
            "clear".into(),
            "neighbor".into(),
            "10.0.0.1".into(),
            "bye now".into(),
        ])
        .unwrap();
        assert_eq!(
            m,
            Command::ClearNeighbor {
                addr: "10.0.0.1".parse().unwrap(),
                soft: false,
                message: Some("bye now".into())
            }
        );
        assert!(m.is_write());
        assert!(!Command::ShowFib.is_write());
        assert_eq!(
            Command::parse(&words("fib mode install")),
            Ok(Command::FibMode(Mode::Install))
        );
        assert_eq!(Command::parse(&words("reload")), Ok(Command::Reload));
        for bad in [
            "show",
            "show neighbor nope",
            "show routes ipv7",
            "clear neighbor 10.0.0.1 soft msg",
            "clear neighbor 10.0.0.1 a b",
            "fib mode maybe",
        ] {
            assert!(Command::parse(&words(bad)).is_err(), "{bad}");
        }
        let long = vec![
            "clear".into(),
            "neighbor".into(),
            "10.0.0.1".into(),
            "x".repeat(129),
        ];
        assert!(Command::parse(&long).unwrap_err().contains("RFC 9003"));
    }

    #[test]
    fn stats_exists_only_in_profiling_builds() {
        let parsed = Command::parse(&words("stats"));
        #[cfg(feature = "profiling")]
        assert_eq!(parsed, Ok(Command::Stats));
        #[cfg(not(feature = "profiling"))]
        assert!(parsed.is_err());
        // Never over HTTP (docs/PROFILING.md: no network export).
        let req =
            http::Request::read_from(&mut "GET /v1/stats HTTP/1.1\r\n\r\n".as_bytes()).unwrap();
        assert_eq!(Command::from_http(&req).unwrap_err().0, 404);
    }

    #[test]
    fn maps_http_routes() {
        let get = |path: &str| {
            http::Request::read_from(&mut format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
                .unwrap()
        };
        let post = |path: &str| {
            http::Request::read_from(&mut format!("POST {path} HTTP/1.1\r\n\r\n").as_bytes())
                .unwrap()
        };
        assert_eq!(
            Command::from_http(&get("/v1/neighbors")),
            Ok(Command::ShowNeighbors)
        );
        assert_eq!(
            Command::from_http(&get("/v1/routes?family=ipv6&prefix=2001:db8::/32")),
            Ok(Command::ShowRoutes {
                family: AddressFamily::IPV6_UNICAST,
                prefix: Some("2001:db8::/32".parse().unwrap()),
                held: false
            })
        );
        assert_eq!(
            Command::from_http(&get("/v1/status")),
            Ok(Command::ShowStatus)
        );
        assert_eq!(
            Command::from_http(&post("/v1/fib/mode/dry-run")),
            Ok(Command::FibMode(Mode::DryRun))
        );
        assert_eq!(
            Command::from_http(&post("/v1/neighbors/10.0.0.1/clear?soft=1")),
            Ok(Command::ClearNeighbor {
                addr: "10.0.0.1".parse().unwrap(),
                soft: true,
                message: None
            })
        );
        assert_eq!(Command::from_http(&get("/v1/nope")).unwrap_err().0, 404);
        assert_eq!(
            Command::from_http(&get("/v1/routes?family=x"))
                .unwrap_err()
                .0,
            400
        );
        assert_eq!(
            Command::from_http(&post("/v1/neighbors/zz/clear"))
                .unwrap_err()
                .0,
            400
        );
        let put =
            http::Request::read_from(&mut "PUT /v1/reload HTTP/1.1\r\n\r\n".as_bytes()).unwrap();
        assert_eq!(Command::from_http(&put).unwrap_err().0, 405);
    }

    fn rpki_block(text: &str) -> bgpfc_config::ast::Rpki {
        bgpfc_config::parse_str("t", &format!("router-id 192.0.2.1; local-as 65000; {text}"))
            .unwrap()
            .rpki
    }

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
    }

    /// A client in sync with the cache of preference 10, `now` being the
    /// moment of the report.
    fn rpki_report(now: Instant, vrps: &[Vrp]) -> RpkiReport {
        use bgpfc_rtr::client::{Cache, Status};
        let set: VrpSet = vrps.iter().copied().collect();
        RpkiReport {
            config: rpki_block(
                "rpki { mode external; cache 127.0.0.1 port 3323;
                 cache rtr.example.net preference 10; }",
            ),
            status: Some(Status {
                cache: Cache {
                    preference: 10,
                    ..Cache::new("rtr.example.net")
                },
                state: bgpfc_rtr::session::State::Idle,
                connected: true,
                version: bgpfc_rtr::Version::V1,
                session_id: Some(4242),
                serial: Some(17),
                synced_at: now.checked_sub(Duration::from_secs(12)),
                last_commit: now.checked_sub(Duration::from_secs(12)),
                expires_at: Some(now + Duration::from_secs(7_188)),
                vrps: Some(Arc::new(set)),
                source: Some(Cache {
                    preference: 10,
                    ..Cache::new("rtr.example.net")
                }),
                vrps_ipv4: 2,
                vrps_ipv6: 1,
                failures: 0,
                last_error: Some("rtr cache connection timed out cache=127.0.0.1:3323".to_owned()),
                last_error_at: now.checked_sub(Duration::from_secs(30)),
                running: true,
            }),
            waiting_since: None,
            sidecar: None,
        }
    }

    #[test]
    fn rpki_status_renders_as_lines_and_json() {
        let now = Instant::now();
        let r = render_rpki(&rpki_report(now, &[]), now);
        // RFC 8210 §10: the cache list, the one cache whose VRPs are in
        // use, and the one the client talks to: the same, in sync.
        assert_eq!(
            r.lines,
            [
                "mode external",
                "enforcement drop-invalid",
                "startup accept",
                "validation active",
                "cache 127.0.0.1:3323 preference 0",
                "cache rtr.example.net:323 preference 10, in use, current",
                "state idle, connected, version 1",
                "session-id 4242 serial 17",
                "last sync 12s ago",
                "vrps ipv4 2 ipv6 1 from rtr.example.net:323, expire in 7188s",
                "failures 0",
                "last error 30s ago: rtr cache connection timed out cache=127.0.0.1:3323",
            ]
        );
        assert_eq!(
            r.json,
            concat!(
                r#"{"mode":"external","enforcement":"drop-invalid","startup":"accept","validation":"active","#,
                r#""waiting_seconds":null,"sidecar":null,"caches":["#,
                r#"{"host":"127.0.0.1","port":3323,"preference":0,"in_use":false,"#,
                r#""current":false},"#,
                r#"{"host":"rtr.example.net","port":323,"preference":10,"in_use":true,"#,
                r#""current":true}],"#,
                r#""running":true,"state":"idle","connected":true,"version":1,"#,
                r#""session_id":4242,"serial":17,"synced_seconds_ago":12,"#,
                r#""expires_in_seconds":7188,"#,
                r#""vrps":{"ipv4":2,"ipv6":1,"from":{"host":"rtr.example.net","port":323}},"#,
                r#""failures":0,"#,
                r#""last_error":"rtr cache connection timed out cache=127.0.0.1:3323","#,
                r#""last_error_seconds_ago":30}"#
            )
        );
    }

    #[test]
    fn rpki_status_before_any_data_and_without_a_client() {
        let now = Instant::now();
        let mut report = rpki_report(now, &[]);
        if let Some(s) = &mut report.status {
            s.connected = false;
            s.state = bgpfc_rtr::session::State::Connecting;
            (s.session_id, s.serial, s.synced_at, s.expires_at) = (None, None, None, None);
            (s.vrps, s.source, s.last_error, s.last_error_at) = (None, None, None, None);
            s.failures = 3;
        }
        report.waiting_since = now.checked_sub(Duration::from_secs(3));
        let r = render_rpki(&report, now);
        assert!(
            r.lines[3].starts_with("validation waiting 3s "),
            "{:?}",
            r.lines
        );
        assert_eq!(
            r.lines[6..],
            [
                "state connecting, version 1",
                "session-id - serial -",
                "last sync never",
                "vrps none yet: every route is disabled",
                "failures 3",
            ]
        );
        assert!(
            r.json.contains(
                r#""session_id":null,"serial":null,"synced_seconds_ago":null,"expires_in_seconds":null,"vrps":null,"failures":3,"last_error":null"#
            ),
            "{}",
            r.json
        );
        // A client that stopped itself.
        if let Some(s) = &mut report.status {
            s.running = false;
        }
        assert_eq!(
            render_rpki(&report, now).lines[6],
            "state stopped, version 1"
        );
        // Disabled: the configured caches, nothing else, every member there.
        let report = RpkiReport {
            config: rpki_block("rpki { mode disabled; cache 192.0.2.10; }"),
            status: None,
            waiting_since: None,
            sidecar: None,
        };
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines,
            [
                "mode disabled",
                "enforcement drop-invalid",
                "startup accept",
                "validation off",
                "cache 192.0.2.10:323 preference 0"
            ]
        );
        assert_eq!(
            r.json,
            concat!(
                r#"{"mode":"disabled","enforcement":"drop-invalid","startup":"accept","validation":"off","#,
                r#""waiting_seconds":null,"sidecar":null,"#,
                r#""caches":[{"host":"192.0.2.10","port":323,"#,
                r#""preference":0,"in_use":false,"current":false}],"#,
                r#""running":false,"state":null,"#,
                r#""connected":false,"version":null,"session_id":null,"serial":null,"#,
                r#""synced_seconds_ago":null,"expires_in_seconds":null,"vrps":null,"#,
                r#""failures":0,"last_error":null,"last_error_seconds_ago":null}"#
            )
        );
        let none = RpkiReport {
            config: bgpfc_config::ast::Rpki::default(),
            status: None,
            waiting_since: None,
            sidecar: None,
        };
        assert_eq!(
            render_rpki(&none, now).lines,
            [
                "mode disabled",
                "enforcement drop-invalid",
                "startup accept",
                "validation off"
            ]
        );
    }

    #[test]
    fn the_cache_in_use_is_the_source_of_the_vrps() {
        use bgpfc_rtr::client::Cache;
        let now = Instant::now();
        // The cache of preference 10 went away; the client tries the
        // other, whose session has nothing yet. Its VRPs stay in use until
        // the other has sent a full set (RFC 8210 §10).
        let mut report = rpki_report(now, &[]);
        if let Some(s) = &mut report.status {
            s.cache = Cache {
                port: 3323,
                ..Cache::new("127.0.0.1")
            };
            s.state = bgpfc_rtr::session::State::Connecting;
            s.connected = false;
            (s.session_id, s.serial, s.synced_at) = (None, None, None);
        }
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines[4..10],
            [
                "cache 127.0.0.1:3323 preference 0, current",
                "cache rtr.example.net:323 preference 10, in use",
                "state connecting, version 1",
                "session-id - serial -",
                "last sync never",
                "vrps ipv4 2 ipv6 1 from rtr.example.net:323, expire in 7188s",
            ]
        );
        assert!(
            r.json.contains(concat!(
                r#"{"host":"127.0.0.1","port":3323,"preference":0,"in_use":false,"#,
                r#""current":true},{"host":"rtr.example.net","port":323,"#,
                r#""preference":10,"in_use":true,"current":false}]"#
            )),
            "{}",
            r.json
        );
        // A reload replaced the list: the VRPs held come from a cache it
        // no longer has, which the vrps line names.
        if let Some(s) = &mut report.status {
            s.source = Some(Cache::new("192.0.2.99"));
        }
        let r = render_rpki(&report, now);
        assert!(
            r.lines.iter().all(|l| !l.contains("in use")),
            "{:?}",
            r.lines
        );
        assert_eq!(
            r.lines[9],
            "vrps ipv4 2 ipv6 1 from 192.0.2.99:323, expire in 7188s"
        );
        assert!(
            r.json
                .contains(r#""vrps":{"ipv4":2,"ipv6":1,"from":{"host":"192.0.2.99","port":323}}"#),
            "{}",
            r.json
        );
        // The list names the cache in use another way: still that cache.
        let mut respelled = rpki_report(now, &[]);
        respelled.config = rpki_block(
            "rpki { mode external; cache 127.0.0.1 port 3323;
             cache RTR.Example.NET. preference 10; }",
        );
        assert_eq!(
            render_rpki(&respelled, now).lines[5],
            "cache RTR.Example.NET.:323 preference 10, in use, current"
        );
        // Held data that expired is no cache's: every route not-found.
        if let Some(s) = &mut report.status {
            s.source = None;
            s.vrps = Some(Arc::new(VrpSet::new()));
            (s.vrps_ipv4, s.vrps_ipv6, s.expires_at) = (0, 0, None);
        }
        let r = render_rpki(&report, now);
        assert_eq!(r.lines[9], "vrps ipv4 0 ipv6 0");
        assert!(
            r.json.contains(r#""vrps":{"ipv4":0,"ipv6":0,"from":null}"#),
            "{}",
            r.json
        );
    }

    #[test]
    fn rpki_status_shows_the_enforcement() {
        // RFC 6811 §5: what acts on the state, next to the mode that
        // turns validation on (design §D1.3), whether written or the
        // default, with a client or without.
        let now = Instant::now();
        for (statement, mode) in [
            ("", "drop-invalid"),
            ("enforcement drop-invalid;", "drop-invalid"),
            ("enforcement prefer-valid;", "prefer-valid"),
            ("enforcement off;", "off"),
        ] {
            for (block, status) in [
                (
                    "mode external; cache 192.0.2.10;",
                    rpki_report(now, &[]).status,
                ),
                ("mode disabled;", None),
            ] {
                let report = RpkiReport {
                    config: rpki_block(&format!("rpki {{ {block} {statement} }}")),
                    status,
                    waiting_since: None,
                    sidecar: None,
                };
                let r = render_rpki(&report, now);
                assert_eq!(r.lines[1], format!("enforcement {mode}"), "{block}");
                assert!(
                    r.json.contains(&format!(
                        r#""enforcement":"{mode}","startup":"accept","validation":"#
                    )),
                    "{}",
                    r.json
                );
            }
        }
    }

    /// Routinator in `state`, serving RTR at 127.0.0.1:41234, restarted
    /// once after a `SIGKILL`; the client in sync with it.
    fn sidecar_report(now: Instant, state: SidecarState) -> RpkiReport {
        use bgpfc_rtr::client::Cache;
        let mut r = rpki_report(now, &[]);
        r.config = rpki_block("rpki { mode sidecar; }");
        let rtr = Cache {
            port: 41_234,
            ..Cache::new("127.0.0.1")
        };
        if let Some(s) = &mut r.status {
            s.cache = rtr.clone();
            s.source = Some(rtr);
            (s.last_error, s.last_error_at) = (None, None);
        }
        let pid = match state {
            SidecarState::Running { pid, .. } => Some(pid),
            SidecarState::ShuttingDown { pid } => pid,
            _ => None,
        };
        r.sidecar = Some(SidecarReport {
            status: bgpfc_sidecar::SidecarStatus {
                state,
                pid,
                restarts: 1,
                consecutive_failures: 0,
                last_exit: Some(bgpfc_sidecar::ExitReason::Signal {
                    number: 9,
                    core_dumped: false,
                }),
                rtr: "127.0.0.1:41234".parse().unwrap(),
            },
            version: bgpfc_sidecar::TESTED_VERSION,
            binary: "/usr/bin/routinator".into(),
        });
        r
    }

    /// The names of the members of the JSON object `json`, of its
    /// outermost level only, in order: enough of a reader for what the
    /// writer writes, which has no white space.
    fn members(json: &str) -> Vec<String> {
        let b = json.as_bytes();
        let (mut names, mut depth, mut i) = (Vec::new(), 0, 0);
        while i < b.len() {
            match b[i] {
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                b'"' => {
                    let start = i + 1;
                    i += 1;
                    while b[i] != b'"' {
                        i += if b[i] == b'\\' { 2 } else { 1 };
                    }
                    if depth == 1 && b.get(i + 1) == Some(&b':') {
                        names.push(json[start..i].to_owned());
                    }
                }
                _ => {}
            }
            i += 1;
        }
        names
    }

    #[test]
    fn rpki_status_shows_a_running_sidecar() {
        // Issues #26, #70, #71 (m14 design §4.6): Routinator's state, pid,
        // uptime, version and binary, its RTR address and history, and the
        // client's one cache, at that address, listed like a configured one.
        let now = Instant::now();
        let since = now.checked_sub(Duration::from_secs(312)).unwrap();
        let report = sidecar_report(now, SidecarState::Running { pid: 4242, since });
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines,
            [
                "mode sidecar",
                "enforcement drop-invalid",
                "startup accept",
                "validation active",
                "sidecar running pid 4242 for 312s, routinator 0.15.3 (/usr/bin/routinator)",
                "sidecar rtr 127.0.0.1:41234, restarts 1, failures 0, \
                 last exit: killed by signal 9 (SIGKILL)",
                "cache 127.0.0.1:41234 (sidecar) preference 0, in use, current",
                "state idle, connected, version 1",
                "session-id 4242 serial 17",
                "last sync 12s ago",
                "vrps ipv4 2 ipv6 1 from 127.0.0.1:41234, expire in 7188s",
                "failures 0",
            ]
        );
        assert_eq!(
            r.json,
            concat!(
                r#"{"mode":"sidecar","enforcement":"drop-invalid","startup":"accept","validation":"active","#,
                r#""waiting_seconds":null,"#,
                r#""sidecar":{"state":"running","alarm":false,"pid":4242,"#,
                r#""running_seconds":312,"retry_in_seconds":null,"restarts":1,"#,
                r#""consecutive_failures":0,"last_exit":"killed by signal 9 (SIGKILL)","#,
                r#""rtr":"127.0.0.1:41234","binary":"/usr/bin/routinator","#,
                r#""version":"0.15.3"},"#,
                r#""caches":[{"host":"127.0.0.1","port":41234,"preference":0,"#,
                r#""in_use":true,"current":true}],"#,
                r#""running":true,"state":"idle","connected":true,"version":1,"#,
                r#""session_id":4242,"serial":17,"synced_seconds_ago":12,"#,
                r#""expires_in_seconds":7188,"#,
                r#""vrps":{"ipv4":2,"ipv6":1,"from":{"host":"127.0.0.1","port":41234}},"#,
                r#""failures":0,"last_error":null,"last_error_seconds_ago":null}"#
            )
        );
        // Before its first exit there is none to show; an address on ::1
        // is written as the client writes it.
        let mut fresh = sidecar_report(now, SidecarState::Running { pid: 4242, since });
        if let Some(s) = &mut fresh.sidecar {
            s.status.last_exit = None;
            s.status.restarts = 0;
            s.status.rtr = "[::1]:3323".parse().unwrap();
        }
        let r = render_rpki(&fresh, now);
        assert_eq!(
            r.lines[5..7],
            [
                "sidecar rtr [::1]:3323, restarts 0, failures 0",
                "cache [::1]:3323 (sidecar) preference 0",
            ]
        );
        assert!(
            r.json.contains(r#""last_exit":null,"rtr":"[::1]:3323""#)
                && r.json.contains(r#""caches":[{"host":"::1","port":3323,"#),
            "{}",
            r.json
        );
    }

    #[test]
    fn the_sidecar_line_names_each_state() {
        // m14 design §4.6: one line per state, with when the next attempt
        // starts while Routinator backs off or has failed.
        let now = Instant::now();
        let later = now + Duration::from_secs(3);
        let since = now.checked_sub(Duration::from_secs(5)).unwrap();
        let cases = [
            (SidecarState::Starting, "starting", "null", "null", "null"),
            (
                SidecarState::Running { pid: 7, since },
                "running pid 7 for 5s",
                "7",
                "5",
                "null",
            ),
            (
                SidecarState::BackingOff {
                    until: later,
                    failures: 1,
                },
                "backing-off after 1 failure, next attempt in 3s",
                "null",
                "null",
                "3",
            ),
            (
                SidecarState::BackingOff {
                    until: later,
                    failures: 2,
                },
                "backing-off after 2 failures, next attempt in 3s",
                "null",
                "null",
                "3",
            ),
            (
                SidecarState::Failed {
                    until: later,
                    failures: 1,
                },
                "FAILED after 1 failure in a row, next attempt in 3s",
                "null",
                "null",
                "3",
            ),
            (
                SidecarState::ShuttingDown { pid: Some(7) },
                "shutting-down pid 7",
                "7",
                "null",
                "null",
            ),
            (
                SidecarState::ShuttingDown { pid: None },
                "shutting-down",
                "null",
                "null",
                "null",
            ),
            (SidecarState::Stopped, "stopped", "null", "null", "null"),
        ];
        for (state, line, pid, running, retry) in cases {
            let r = render_rpki(&sidecar_report(now, state), now);
            assert_eq!(
                r.lines[4],
                format!("sidecar {line}, routinator 0.15.3 (/usr/bin/routinator)")
            );
            let alarm = matches!(state, SidecarState::Failed { .. });
            let json = format!(
                r#""sidecar":{{"state":"{}","alarm":{alarm},"pid":{pid},"running_seconds":{running},"retry_in_seconds":{retry},"#,
                state.name()
            );
            assert!(r.json.contains(&json), "{json}\n{}", r.json);
        }
    }

    #[test]
    fn rpki_status_shows_a_failed_sidecar_as_an_alarm() {
        // Issue #70: "Repeated restart failures must surface as an
        // operational error, not just a log line." The state is in upper
        // case, and the JSON says `alarm`.
        let now = Instant::now();
        let until = now + Duration::from_secs(280);
        let mut report = sidecar_report(now, SidecarState::Failed { until, failures: 7 });
        if let Some(s) = &mut report.sidecar {
            s.status.restarts = 6;
            s.status.consecutive_failures = 7;
            s.status.last_exit = Some(bgpfc_sidecar::ExitReason::Code(1));
        }
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines[4..6],
            [
                "sidecar FAILED after 7 failures in a row, next attempt in 280s, \
                 routinator 0.15.3 (/usr/bin/routinator)",
                "sidecar rtr 127.0.0.1:41234, restarts 6, failures 7, \
                 last exit: exited with status 1",
            ]
        );
        assert!(
            r.json.contains(concat!(
                r#""sidecar":{"state":"failed","alarm":true,"pid":null,"#,
                r#""running_seconds":null,"retry_in_seconds":280,"restarts":6,"#,
                r#""consecutive_failures":7,"last_exit":"exited with status 1","#,
                r#""rtr":"127.0.0.1:41234","binary":"/usr/bin/routinator","#,
                r#""version":"0.15.3"},"#
            )),
            "{}",
            r.json
        );
        // A replaced binary that is not of the series fails to start: the
        // reason, from the version check, stays on its line, and so does a
        // binary whose path has a newline.
        if let Some(s) = &mut report.sidecar {
            s.status.last_exit = Some(bgpfc_sidecar::ExitReason::SpawnFailed(
                "Routinator 0.16.0 is not supported:\nneeds 0.15".to_owned(),
            ));
            s.binary = "/opt/rout\ninator".into();
        }
        let r = render_rpki(&report, now);
        assert!(
            r.lines[4].ends_with(r"(/opt/rout\ninator)"),
            "{}",
            r.lines[4]
        );
        assert!(
            r.lines[5].ends_with(
                r"last exit: could not be started: Routinator 0.16.0 is not supported:\nneeds 0.15"
            ),
            "{}",
            r.lines[5]
        );
        assert!(r.lines.iter().all(|l| !l.chars().any(char::is_control)));
        assert!(
            r.json.contains(concat!(
                r#""last_exit":"could not be started: Routinator 0.16.0 is not supported:\nneeds 0.15","#,
                r#""rtr":"127.0.0.1:41234","binary":"/opt/rout\ninator""#
            )),
            "{}",
            r.json
        );
    }

    #[test]
    fn rpki_status_while_waiting_for_the_first_set() {
        // Issue #71, m14 design §3.3: until the client's first full set,
        // every route is `disabled` and used; `show rpki` says so, and for
        // how long. Routinator listens only after its first validation run.
        let now = Instant::now();
        let mut report = sidecar_report(
            now,
            SidecarState::Running {
                pid: 4242,
                since: now.checked_sub(Duration::from_secs(95)).unwrap(),
            },
        );
        report.waiting_since = now.checked_sub(Duration::from_secs(95));
        if let Some(s) = &mut report.status {
            s.state = bgpfc_rtr::session::State::Connecting;
            s.connected = false;
            (s.session_id, s.serial, s.synced_at, s.expires_at) = (None, None, None, None);
            (s.vrps, s.source) = (None, None);
            s.failures = 4;
        }
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines[2..4],
            [
                "startup accept",
                "validation waiting 95s for the first full set: every route is disabled \
                 and used unvalidated; enforcement acts once it arrives"
            ]
        );
        assert_eq!(
            r.lines[6..],
            [
                "cache 127.0.0.1:41234 (sidecar) preference 0, current",
                "state connecting, version 1",
                "session-id - serial -",
                "last sync never",
                "vrps none yet: every route is disabled",
                "failures 4",
            ]
        );
        assert!(
            r.json
                .contains(r#""validation":"waiting","waiting_seconds":95,"sidecar":{"#),
            "{}",
            r.json
        );
        // An external cache's window is the same, if normally short.
        let mut external = rpki_report(now, &[]);
        external.waiting_since = Some(now);
        let r = render_rpki(&external, now);
        assert!(
            r.lines[3].starts_with("validation waiting 0s for the first full set: "),
            "{}",
            r.lines[3]
        );
        assert!(
            r.json
                .contains(r#""validation":"waiting","waiting_seconds":0,"sidecar":null,"#),
            "{}",
            r.json
        );
    }

    #[test]
    fn rpki_status_says_the_routes_are_held_under_startup_hold() {
        // RFC 6811 §2: held only as configured, and `show rpki` says that
        // they are, while they wait; with data the setting holds nothing,
        // and it is shown all the same.
        let now = Instant::now();
        let mut report = rpki_report(now, &[]);
        report.config = rpki_block(
            "rpki { mode external; startup hold; cache 127.0.0.1 port 3323;
             cache rtr.example.net preference 10; }",
        );
        report.waiting_since = now.checked_sub(Duration::from_secs(7));
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines[1..4],
            [
                "enforcement drop-invalid",
                "startup hold",
                "validation waiting 7s for the first full set: every route is disabled \
                 and held (startup hold); enforcement acts once it arrives",
            ]
        );
        assert!(
            r.json.contains(
                r#""enforcement":"drop-invalid","startup":"hold","validation":"waiting","waiting_seconds":7,"#
            ),
            "{}",
            r.json
        );
        report.waiting_since = None;
        let r = render_rpki(&report, now);
        assert_eq!(r.lines[2..4], ["startup hold", "validation active"]);
    }

    #[test]
    fn the_json_has_the_same_members_without_a_sidecar() {
        // One shape in every mode, so that a reader needs no second one:
        // `sidecar` is null and `validation` off without a sidecar or a
        // client.
        let now = Instant::now();
        let disabled = RpkiReport {
            config: bgpfc_config::ast::Rpki::default(),
            status: None,
            waiting_since: None,
            sidecar: None,
        };
        let r = render_rpki(&disabled, now);
        assert_eq!(
            r.json,
            concat!(
                r#"{"mode":"disabled","enforcement":"drop-invalid","startup":"accept","validation":"off","#,
                r#""waiting_seconds":null,"sidecar":null,"caches":[],"#,
                r#""running":false,"state":null,"#,
                r#""connected":false,"version":null,"session_id":null,"serial":null,"#,
                r#""synced_seconds_ago":null,"expires_in_seconds":null,"vrps":null,"#,
                r#""failures":0,"last_error":null,"last_error_seconds_ago":null}"#
            )
        );
        // `mode sidecar` with none running: a reload could not start it,
        // and validation is off.
        let gone = RpkiReport {
            config: rpki_block("rpki { mode sidecar; }"),
            ..disabled.clone()
        };
        let not_running = render_rpki(&gone, now);
        assert_eq!(
            not_running.lines,
            [
                "mode sidecar",
                "enforcement drop-invalid",
                "startup accept",
                "validation off",
                "sidecar not running",
            ]
        );
        let mut waiting = sidecar_report(now, SidecarState::Starting);
        waiting.waiting_since = Some(now);
        let shapes = [
            render_rpki(&rpki_report(now, &[]), now),
            not_running,
            render_rpki(
                &sidecar_report(
                    now,
                    SidecarState::Failed {
                        until: now,
                        failures: 5,
                    },
                ),
                now,
            ),
            render_rpki(&waiting, now),
        ];
        let expected = members(&r.json);
        assert_eq!(expected.len(), 19, "{expected:?}");
        for shape in shapes {
            assert_eq!(members(&shape.json), expected, "{}", shape.json);
        }
    }

    /// Two neighbors, one established, the FIB in dry-run, and `rpki`.
    fn status_report(rpki: Option<RpkiReport>) -> StatusReport {
        StatusReport {
            local_as: Asn(65_000),
            router_id: RouterId::new(0xC000_0201).unwrap(),
            neighbors: 2,
            established: 1,
            fib_mode: Some(Mode::DryRun),
            rpki,
        }
    }

    #[test]
    fn status_lists_the_sidecar_alarm() {
        // Issue #70: a Routinator that keeps failing is an operational
        // error, listed where a monitoring system polls (m14 design §4.6).
        let now = Instant::now();
        let version = env!("CARGO_PKG_VERSION");
        let failed = sidecar_report(
            now,
            SidecarState::Failed {
                until: now + Duration::from_secs(280),
                failures: 7,
            },
        );
        let r = render_status(&status_report(Some(failed)));
        assert_eq!(
            r.lines,
            [
                format!("bgpfcd {version}"),
                "local-as AS65000 router-id 192.0.2.1".to_owned(),
                "neighbors 2 established 1".to_owned(),
                "fib mode dry-run".to_owned(),
                "rpki sidecar, validation active".to_owned(),
                "alarm rpki sidecar failed: 7 failures in a row".to_owned(),
            ]
        );
        assert_eq!(
            r.json,
            format!(
                "{{\"version\":\"{version}\",{}",
                concat!(
                    r#""local_as":65000,"router_id":"192.0.2.1","neighbors":2,"#,
                    r#""established":1,"fib_mode":"dry-run","#,
                    r#""rpki":{"mode":"sidecar","validation":"active"},"#,
                    r#""alarms":["rpki-sidecar-failed"]}"#
                )
            )
        );
        let one = sidecar_report(
            now,
            SidecarState::Failed {
                until: now,
                failures: 1,
            },
        );
        assert_eq!(
            render_status(&status_report(Some(one))).lines[5],
            "alarm rpki sidecar failed: 1 failure in a row"
        );
        // Below the threshold, or running again, there is no alarm, and
        // the list is empty.
        for state in [
            SidecarState::BackingOff {
                until: now,
                failures: 4,
            },
            SidecarState::Running { pid: 7, since: now },
            SidecarState::Starting,
        ] {
            let r = render_status(&status_report(Some(sidecar_report(now, state))));
            assert_eq!(r.lines.len(), 5, "{:?}", r.lines);
            assert_eq!(r.lines[4], "rpki sidecar, validation active");
            assert!(
                r.json
                    .ends_with(r#""rpki":{"mode":"sidecar","validation":"active"},"alarms":[]}"#),
                "{}",
                r.json
            );
        }
    }

    /// A busy coordinator, as during a reload that waits for a slow
    /// Routinator to stop, with its queue full of questions that timed
    /// out: `show status` still answers at once, with `rpki unknown`, and
    /// `show rpki` with an error, rather than waiting for room on the
    /// queue (docs/control.md, "Alarms").
    #[test]
    fn a_busy_coordinator_leaves_the_rpki_unknown_at_once() {
        let (coord, _queue) = sync_channel(1);
        coord
            .try_send(CoordMsg::Signal(bgpfc_sys::Signal::Hup))
            .unwrap();
        // A FIB thread that is gone, so that its mode is unknown at once.
        let (fib, _) = sync_channel(1);
        let (rib, _rib) = sync_channel(1);
        let ctx = Ctx {
            peers: PeerTable::default(),
            rib,
            fib,
            coord,
            local_as: Asn(65_000),
            router_id: RouterId::new(0xC000_0201).unwrap(),
            writes: false,
            token: None,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send((status(&ctx), super::rpki_report(&ctx).err()));
        });
        let (reply, rpki) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("show status waited for room on the coordinator's queue");
        let reply = reply.unwrap();
        assert_eq!(reply.lines[3..], ["fib mode unknown", "rpki unknown"]);
        assert!(
            reply.json.ends_with(r#""rpki":null,"alarms":null}"#),
            "{}",
            reply.json
        );
        assert_eq!(rpki.as_deref(), Some("coordinator busy"));
    }

    /// Issue #71: a block whose mode validates, with nothing running
    /// after a reload that could not start it, leaves every route
    /// `disabled` while enforcement is expected: an alarm, not only
    /// `validation off`.
    #[test]
    fn status_lists_an_rpki_block_that_is_not_running() {
        let off = |config: &str| RpkiReport {
            config: rpki_block(config),
            status: None,
            waiting_since: None,
            sidecar: None,
        };
        for (report, mode, name, line) in [
            (
                off("rpki { mode sidecar; }"),
                "sidecar",
                "rpki-sidecar-not-running",
                "alarm rpki sidecar not running: validation is off",
            ),
            (
                off("rpki { mode external; cache 192.0.2.10; }"),
                "external",
                "rpki-client-not-running",
                "alarm rpki client not running: validation is off",
            ),
        ] {
            let r = render_status(&status_report(Some(report)));
            assert_eq!(
                r.lines[4..],
                [format!("rpki {mode}, validation off"), line.to_owned()]
            );
            let json =
                format!(r#""rpki":{{"mode":"{mode}","validation":"off"}},"alarms":["{name}"]}}"#);
            assert!(r.json.ends_with(&json), "{}", r.json);
        }
        // A sidecar with no client, which no reload leaves behind, is said
        // as a client that is not running.
        let mut no_client = sidecar_report(Instant::now(), SidecarState::Starting);
        no_client.status = None;
        let r = render_status(&status_report(Some(no_client)));
        assert_eq!(
            r.lines[5],
            "alarm rpki client not running: validation is off"
        );
        // `mode disabled` wants no validation: no alarm.
        let r = render_status(&status_report(Some(off("rpki { mode disabled; }"))));
        assert_eq!(r.lines.len(), 5, "{:?}", r.lines);
        assert!(r.json.ends_with(r#""alarms":[]}"#), "{}", r.json);
    }

    #[test]
    fn status_says_where_validation_stands() {
        // m14 design §3.3: the mode and the validation state, in every
        // mode, as `show rpki` has them.
        let now = Instant::now();
        let mut waiting = sidecar_report(now, SidecarState::Starting);
        waiting.waiting_since = Some(now);
        let disabled = RpkiReport {
            config: bgpfc_config::ast::Rpki::default(),
            status: None,
            waiting_since: None,
            sidecar: None,
        };
        for (report, line, json) in [
            (
                waiting,
                "rpki sidecar, validation waiting",
                r#""rpki":{"mode":"sidecar","validation":"waiting"},"alarms":[]}"#,
            ),
            (
                rpki_report(now, &[]),
                "rpki external, validation active",
                r#""rpki":{"mode":"external","validation":"active"},"alarms":[]}"#,
            ),
            (
                disabled,
                "rpki disabled, validation off",
                r#""rpki":{"mode":"disabled","validation":"off"},"alarms":[]}"#,
            ),
        ] {
            let r = render_status(&status_report(Some(report)));
            assert_eq!(r.lines[4..], [line]);
            assert!(r.json.ends_with(json), "{}", r.json);
        }
        // A coordinator busy with a long reload: not known, rather than no
        // alarm; and so for a FIB thread that does not answer.
        let r = render_status(&StatusReport {
            fib_mode: None,
            ..status_report(None)
        });
        assert_eq!(r.lines[3..], ["fib mode unknown", "rpki unknown"]);
        assert!(
            r.json
                .ends_with(r#""fib_mode":null,"rpki":null,"alarms":null}"#),
            "{}",
            r.json
        );
    }

    /// Three routes that changed state, 12 s and 3 s before `now`, and
    /// five changes never recorded.
    fn transitions(now: Instant) -> TransitionsReport {
        use crate::messages::Recorded;
        use bgpfc_rib::Transition;
        // 2026-10-03T12:34:56.789Z, the example in AGENTS.md.
        let base = std::time::UNIX_EPOCH + Duration::from_millis(1_791_030_896_789);
        let p = |s: &str| -> Prefix { s.parse().unwrap() };
        let entry = |ago: u64, t: Transition| Recorded {
            at: base - Duration::from_secs(ago),
            when: now.checked_sub(Duration::from_secs(ago)).unwrap(),
            transition: t,
        };
        let moved = |prefix: &str, origin, from, to, route| Transition {
            family: if prefix.contains(':') {
                AddressFamily::IPV6_UNICAST
            } else {
                AddressFamily::IPV4_UNICAST
            },
            prefix: p(prefix),
            peer: "198.51.100.1".parse().unwrap(),
            origin,
            from,
            to,
            route,
        };
        let as65001 = RouteOrigin::As(Asn(65_001));
        TransitionsReport {
            capacity: 1024,
            unrecorded: 5,
            entries: vec![
                entry(
                    12,
                    moved(
                        "192.0.2.0/24",
                        as65001,
                        RovState::Valid,
                        RovState::Invalid,
                        RouteStatus::Held(Held::Enforcement),
                    ),
                ),
                entry(
                    3,
                    moved(
                        "2001:db8::/32",
                        RouteOrigin::None,
                        RovState::Invalid,
                        RovState::NotFound,
                        RouteStatus::Best,
                    ),
                ),
                entry(
                    3,
                    moved(
                        "203.0.113.0/24",
                        as65001,
                        RovState::NotFound,
                        RovState::Valid,
                        RouteStatus::Candidate,
                    ),
                ),
            ],
        }
    }

    #[test]
    fn transitions_render_as_lines_and_json() {
        // Issue #59: each route that went from one RFC 6811 state to
        // another, at the time its log line has, oldest first.
        let now = Instant::now();
        let report = transitions(now);
        let r = render_transitions(&report, now);
        assert_eq!(
            r.lines,
            [
                "2026-10-03T12:34:44.789Z 192.0.2.0/24 peer 198.51.100.1 origin AS65001 \
                 valid->invalid held by enforcement",
                "2026-10-03T12:34:53.789Z 2001:db8::/32 peer 198.51.100.1 origin none \
                 invalid->not-found best",
                "2026-10-03T12:34:53.789Z 203.0.113.0/24 peer 198.51.100.1 origin AS65001 \
                 not-found->valid candidate",
                "3 kept (most recent 1024); 5 not recorded",
            ]
        );
        assert_eq!(
            r.json,
            concat!(
                r#"{"capacity":1024,"unrecorded":5,"transitions":["#,
                r#"{"time":"2026-10-03T12:34:44.789Z","seconds_ago":12,"#,
                r#""family":"ipv4-unicast","prefix":"192.0.2.0/24","peer":"198.51.100.1","#,
                r#""origin":65001,"from":"valid","to":"invalid","route":"held","#,
                r#""held_by":"enforcement"},"#,
                r#"{"time":"2026-10-03T12:34:53.789Z","seconds_ago":3,"#,
                r#""family":"ipv6-unicast","prefix":"2001:db8::/32","peer":"198.51.100.1","#,
                r#""origin":null,"from":"invalid","to":"not-found","route":"best","#,
                r#""held_by":null},"#,
                r#"{"time":"2026-10-03T12:34:53.789Z","seconds_ago":3,"#,
                r#""family":"ipv4-unicast","prefix":"203.0.113.0/24","peer":"198.51.100.1","#,
                r#""origin":65001,"from":"not-found","to":"valid","route":"candidate","#,
                r#""held_by":null}]}"#
            )
        );
        // Nothing yet.
        let empty = TransitionsReport {
            capacity: 1024,
            unrecorded: 0,
            entries: Vec::new(),
        };
        let r = render_transitions(&empty, now);
        assert_eq!(r.lines, ["0 kept (most recent 1024); 0 not recorded"]);
        assert_eq!(
            r.json,
            r#"{"capacity":1024,"unrecorded":0,"transitions":[]}"#
        );
    }

    #[test]
    fn text_from_a_cache_stays_on_its_line() {
        // RFC 8210 §5.11: an Error Report's text is any UTF-8. A newline, a
        // lone `.` after it or an escape sequence must neither end the reply
        // early, nor add lines to it, nor reach the operator's terminal.
        let now = Instant::now();
        let mut report = rpki_report(now, &[]);
        if let Some(s) = &mut report.status {
            s.last_error = Some("rtr error text=boom\n.\nstate idle\u{1b}[2J\r\t".to_owned());
        }
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines.last().map(String::as_str),
            Some(r"last error 30s ago: rtr error text=boom\n.\nstate idle\u{001b}[2J\r\t")
        );
        assert!(r.lines.iter().all(|l| !l.chars().any(char::is_control)));
        // Through the line protocol and back: every line, and no other.
        let mut wire = Vec::new();
        proto::Response::ok(r.lines.clone())
            .write_to(&mut wire)
            .unwrap();
        let back = proto::Response::read_from(&mut wire.as_slice()).unwrap();
        assert_eq!(back.lines, r.lines);
        // JSON escapes it as RFC 8259 §7 has it.
        assert!(
            r.json
                .contains(r#""last_error":"rtr error text=boom\n.\nstate idle\u001b[2J\r\t""#),
            "{}",
            r.json
        );
        // Text without control characters is left alone.
        assert_eq!(one_line("a \"quoted\" \\ value"), "a \"quoted\" \\ value");
    }

    #[test]
    fn a_route_is_validated_against_the_vrps_in_use() {
        let now = Instant::now();
        let report = rpki_report(
            now,
            &[
                vrp("192.0.0.0/16", 24, 64_511),
                vrp("192.0.2.0/24", 24, 64_496),
                vrp("192.0.2.0/23", 23, 64_496),
                vrp("198.51.100.0/24", 24, 64_496),
                vrp("2001:db8::/32", 48, 64_496),
            ],
        );
        let p = |s: &str| -> Prefix { s.parse().unwrap() };
        // RFC 6811 §2: Valid when a VRP Matches; the others that Cover the
        // route are listed too. A VRP too short for the route's length
        // Covers it without Matching.
        let r = render_validation(&report, p("192.0.2.0/24"), Asn(64_496));
        assert_eq!(
            r.lines,
            [
                "192.0.2.0/24 origin AS64496: valid",
                "  192.0.0.0/16-24 AS64511",
                "  192.0.2.0/23-23 AS64496",
                "  192.0.2.0/24-24 AS64496 matches",
            ]
        );
        assert_eq!(
            r.json,
            concat!(
                r#"{"prefix":"192.0.2.0/24","origin":64496,"rov":"valid","vrps":["#,
                r#"{"prefix":"192.0.0.0/16","max_length":24,"asn":64511,"matches":false},"#,
                r#"{"prefix":"192.0.2.0/23","max_length":23,"asn":64496,"matches":false},"#,
                r#"{"prefix":"192.0.2.0/24","max_length":24,"asn":64496,"matches":true}]}"#
            )
        );
        // Covered and not Matched: Invalid.
        let r = render_validation(&report, p("192.0.2.0/24"), Asn(64_497));
        assert_eq!(r.lines[0], "192.0.2.0/24 origin AS64497: invalid");
        assert_eq!(r.lines.len(), 4);
        // Not Covered: NotFound, nothing listed.
        let r = render_validation(&report, p("203.0.113.0/24"), Asn(64_496));
        assert_eq!(r.lines, ["203.0.113.0/24 origin AS64496: not-found"]);
        assert!(
            r.json.ends_with(r#""rov":"not-found","vrps":[]}"#),
            "{}",
            r.json
        );
        let r = render_validation(&report, p("2001:db8:1::/48"), Asn(64_496));
        assert_eq!(
            r.lines,
            [
                "2001:db8:1::/48 origin AS64496: valid",
                "  2001:db8::/32-48 AS64496 matches",
            ]
        );
        // No VRPs: what the RIB has, `disabled`.
        let off = RpkiReport {
            config: bgpfc_config::ast::Rpki::default(),
            status: None,
            waiting_since: None,
            sidecar: None,
        };
        let r = render_validation(&off, p("192.0.2.0/24"), Asn(64_496));
        assert_eq!(
            r.lines,
            [
                "192.0.2.0/24 origin AS64496: disabled",
                "  no VRPs: validation is disabled or has no data yet",
            ]
        );
        assert!(
            r.json.contains(r#""rov":"disabled","vrps":[]"#),
            "{}",
            r.json
        );
    }

    #[test]
    fn parses_rpki_commands() {
        let p = |s: &str| -> Prefix { s.parse().unwrap() };
        assert_eq!(Command::parse(&words("show rpki")), Ok(Command::ShowRpki));
        for asn in ["64496", "AS64496", "as64496"] {
            assert_eq!(
                Command::parse(&words(&format!("show rpki validate 192.0.2.0/24 {asn}"))),
                Ok(Command::ValidateRpki {
                    prefix: p("192.0.2.0/24"),
                    origin: Asn(64_496)
                })
            );
        }
        for bad in [
            "show rpki validate",
            "show rpki validate 192.0.2.0/24",
            "show rpki validate 192.0.2.0/33 64496",
            "show rpki validate 192.0.2.0/24 ASX",
            "show rpki validate 192.0.2.0/24 4294967296",
            "show rpki status",
        ] {
            assert!(Command::parse(&words(bad)).is_err(), "{bad}");
        }
        assert!(!Command::ShowRpki.is_write());
        let get = |path: &str| {
            http::Request::read_from(&mut format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
                .unwrap()
        };
        assert_eq!(Command::from_http(&get("/v1/rpki")), Ok(Command::ShowRpki));
        assert_eq!(
            Command::from_http(&get(
                "/v1/rpki/validate?prefix=2001:db8::/48&origin=AS64496"
            )),
            Ok(Command::ValidateRpki {
                prefix: p("2001:db8::/48"),
                origin: Asn(64_496)
            })
        );
        for bad in [
            "/v1/rpki/validate",
            "/v1/rpki/validate?prefix=192.0.2.0/24",
            "/v1/rpki/validate?prefix=x&origin=1",
            "/v1/rpki/validate?prefix=192.0.2.0/24&origin=x",
        ] {
            assert_eq!(Command::from_http(&get(bad)).unwrap_err().0, 400, "{bad}");
        }
    }
}
