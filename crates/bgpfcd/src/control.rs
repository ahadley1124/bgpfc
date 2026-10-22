//! The control plane (AGENTS.md §3, "Control thread(s)"): the Unix socket
//! `bgpfcctl` talks to and the loopback HTTP/JSON API. Both answer the
//! same commands; the data comes from the other threads over
//! request/response channels, never from shared state.
//!
//! Implements: `docs/control.md`; RFC 2918 §4 (soft reset asks for a
//! route refresh); RFC 9003 §3 (a shutdown communication of at most 128
//! octets); RFC 4486 §4 (Administrative Reset; whether the restart limit
//! left a neighbor Idle); RFC 4271 §6.7 (routes received per family
//! against the prefix limit); RFC 8210 §10 (the cache list and the one in
//! use); RFC 6811 §2 (a route's validation state against the VRPs in use,
//! with the VRPs that Cover and Match it).

use std::io::{BufRead as _, BufReader};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_control::http;
use bgpfc_control::json::Json;
use bgpfc_control::proto;
use bgpfc_fib::Mode;
use bgpfc_rpki::{RouteOrigin, RovState, Vrp, VrpSet};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};

use crate::coordinator::PeerTable;
use crate::messages::{
    FibMsg, FibReport, PeerInput, PeerReport, RibMsg, RibQuery, RibReply, RouteReport, RpkiReport,
};

/// How long a request may take to arrive or a reply to be written.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a thread may take to answer a query.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
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
    },
    ShowFib,
    ShowStatus,
    ShowRpki,
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
                for r in rest {
                    match *r {
                        "ipv4" => family = AddressFamily::IPV4_UNICAST,
                        "ipv6" => family = AddressFamily::IPV6_UNICAST,
                        p => {
                            let parsed: Prefix = p
                                .parse()
                                .map_err(|_| format!("`{p}` is not ipv4, ipv6 or a prefix"))?;
                            family = if matches!(parsed, Prefix::V6 { .. }) {
                                AddressFamily::IPV6_UNICAST
                            } else {
                                AddressFamily::IPV4_UNICAST
                            };
                            prefix = Some(parsed);
                        }
                    }
                }
                Ok(Command::ShowRoutes { family, prefix })
            }
            ["show", "fib"] => Ok(Command::ShowFib),
            ["show", "status"] => Ok(Command::ShowStatus),
            ["show", "rpki"] => Ok(Command::ShowRpki),
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
                Ok(Command::ShowRoutes { family, prefix })
            }
            ("GET", ["v1", "fib"]) => Ok(Command::ShowFib),
            ("GET", ["v1", "rpki"]) => Ok(Command::ShowRpki),
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

/// Run a command. The error is a message for the operator.
pub(crate) fn execute(ctx: &Ctx, cmd: &Command) -> Result<Reply, String> {
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
        Command::ShowRoutes { family, prefix } => {
            let (tx, rx) = sync_channel(1);
            ctx.rib
                .send(RibMsg::Query(
                    RibQuery::Routes {
                        family: *family,
                        prefix: *prefix,
                    },
                    tx,
                ))
                .map_err(|_| "rib thread gone".to_owned())?;
            match rx.recv_timeout(QUERY_TIMEOUT) {
                Ok(RibReply::Routes(routes)) => Ok(render_routes(&routes)),
                Ok(RibReply::Peers(_)) => Err("unexpected reply".to_owned()),
                Err(_) => Err("rib did not answer".to_owned()),
            }
        }
        Command::ShowFib => {
            let (tx, rx) = sync_channel(1);
            ctx.fib
                .send(FibMsg::Query(tx))
                .map_err(|_| "fib thread gone".to_owned())?;
            let report = rx
                .recv_timeout(QUERY_TIMEOUT)
                .map_err(|_| "fib did not answer".to_owned())?;
            Ok(render_fib(&report))
        }
        Command::ShowStatus => status(ctx),
        Command::ShowRpki => Ok(render_rpki(&rpki_report(ctx)?, Instant::now())),
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
            ctx.fib
                .send(FibMsg::SetMode(*mode, tx))
                .map_err(|_| "fib thread gone".to_owned())?;
            let ops = rx
                .recv_timeout(QUERY_TIMEOUT)
                .map_err(|_| "fib did not answer".to_owned())?;
            Ok(ok_reply(&format!("fib mode {mode}; {ops} operations")))
        }
    }
}

fn status(ctx: &Ctx) -> Result<Reply, String> {
    let reports = peer_reports(ctx, None)?;
    let established = reports
        .iter()
        .filter(|r| r.state == bgpfc_fsm::State::Established)
        .count();
    let (tx, rx) = sync_channel(1);
    let mode = ctx
        .fib
        .send(FibMsg::Query(tx))
        .ok()
        .and_then(|()| rx.recv_timeout(QUERY_TIMEOUT).ok())
        .map(|f| f.mode);
    let mut j = Json::new();
    j.begin_object()
        .field_str("version", env!("CARGO_PKG_VERSION"))
        .field_num("local_as", ctx.local_as.0)
        .field_display("router_id", ctx.router_id)
        .field_num(
            "neighbors",
            u64::try_from(reports.len()).unwrap_or(u64::MAX),
        )
        .field_num(
            "established",
            u64::try_from(established).unwrap_or(u64::MAX),
        )
        .field_opt("fib_mode", mode)
        .end_object();
    Ok(Reply {
        lines: vec![
            format!("bgpfcd {}", env!("CARGO_PKG_VERSION")),
            format!("local-as {} router-id {}", ctx.local_as, ctx.router_id),
            format!("neighbors {} established {}", reports.len(), established),
            format!(
                "fib mode {}",
                mode.map_or("unknown".to_owned(), |m| m.to_string())
            ),
        ],
        json: j.finish(),
    })
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
fn rpki_report(ctx: &Ctx) -> Result<RpkiReport, String> {
    let (tx, rx) = sync_channel(1);
    ctx.coord
        .send(CoordMsg::Rpki(tx))
        .map_err(|_| "coordinator gone".to_owned())?;
    rx.recv_timeout(QUERY_TIMEOUT)
        .map_err(|_| "coordinator did not answer".to_owned())
}

/// Whole seconds from `earlier` to `later`; 0 if `later` is not later.
fn seconds_between(earlier: Instant, later: Instant) -> u64 {
    later.saturating_duration_since(earlier).as_secs()
}

/// `show rpki`: the block's mode and cache list, and where the client
/// stands with the cache it uses (RFC 8210 §10).
fn render_rpki(r: &RpkiReport, now: Instant) -> Reply {
    let mut j = Json::new();
    write_rpki(&mut j, r, now);
    Reply {
        lines: rpki_lines(r, now),
        json: j.finish(),
    }
}

/// Whether the client uses `cache`: RFC 8210 §10, one cache of the list
/// at a time.
fn in_use(
    status: Option<&bgpfc_rtr::client::Status>,
    cache: &bgpfc_config::ast::RpkiCache,
) -> bool {
    status.is_some_and(|s| {
        s.cache.host == cache.host
            && s.cache.port == cache.port
            && s.cache.preference == cache.preference
    })
}

fn rpki_lines(r: &RpkiReport, now: Instant) -> Vec<String> {
    let status = r.status.as_ref();
    let mut lines = vec![format!("mode {}", r.config.mode)];
    for c in &r.config.caches {
        lines.push(format!(
            "cache {c} preference {}{}",
            c.preference,
            if in_use(status, c) { ", in use" } else { "" }
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
            "vrps ipv4 {} ipv6 {}{}",
            s.vrps_ipv4,
            s.vrps_ipv6,
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
        lines.push(format!("last error {}s ago: {e}", seconds_between(at, now)));
    }
    lines
}

fn write_rpki(j: &mut Json, r: &RpkiReport, now: Instant) {
    let status = r.status.as_ref();
    j.begin_object()
        .field_display("mode", r.config.mode)
        .key("caches")
        .begin_array();
    for c in &r.config.caches {
        j.begin_object()
            .field_str("host", &c.host)
            .field_num("port", c.port)
            .field_num("preference", c.preference)
            .field_bool("in_use", in_use(status, c))
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
            .end_object();
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
        Ok(RibReply::Routes(_)) => Err("unexpected reply".to_owned()),
        Err(_) => Err("rib did not answer".to_owned()),
    }
}

fn counts(stats: &[(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)], addr: IpAddr) -> (usize, usize) {
    stats
        .iter()
        .find(|(i, _)| i.addr == addr)
        .map_or((0, 0), |(_, s)| {
            (
                s.received.iter().map(|(_, n)| n).sum(),
                s.advertised.iter().map(|(_, n)| n).sum(),
            )
        })
}

/// Per family of an Established neighbor: routes received (what the
/// RFC 4271 §6.7 limit counts), routes advertised, and the limit.
fn per_family(
    stats: &[(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)],
    addr: IpAddr,
) -> Vec<(AddressFamily, usize, usize, Option<u32>)> {
    let Some((info, s)) = stats.iter().find(|(i, _)| i.addr == addr) else {
        return Vec::new();
    };
    s.received
        .iter()
        .map(|(family, received)| {
            let advertised = s
                .advertised
                .iter()
                .find(|(f, _)| f == family)
                .map_or(0, |(_, n)| *n);
            (*family, *received, advertised, info.prefix_limit(*family))
        })
        .collect()
}

fn write_neighbor(
    j: &mut Json,
    r: &PeerReport,
    stats: &[(bgpfc_rib::PeerInfo, bgpfc_rib::PeerStats)],
) {
    let (received, advertised) = counts(stats, r.addr);
    j.begin_object()
        .field_display("address", r.addr)
        .field_num("remote_as", r.remote_as.0)
        .field_display("state", r.state)
        .field_num("since_seconds", r.since.as_secs())
        .field_bool("admin_down", r.admin_down)
        .field_bool("restart_limit_reached", r.restart_limit_reached)
        .field_num("updates_in", r.updates_in)
        .field_num("updates_out", r.updates_out)
        .field_num("received", u64::try_from(received).unwrap_or(u64::MAX))
        .field_num("advertised", u64::try_from(advertised).unwrap_or(u64::MAX));
    j.key("prefixes").begin_array();
    for (family, received, advertised, limit) in per_family(stats, r.addr) {
        j.begin_object()
            .field_display("family", family)
            .field_num("received", u64::try_from(received).unwrap_or(u64::MAX))
            .field_num("advertised", u64::try_from(advertised).unwrap_or(u64::MAX))
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
        let (received, advertised) = counts(stats, r.addr);
        lines.push(format!(
            "{:<40} {:>10} {:<12} {:>8}s {:>9} {:>9}",
            r.addr,
            r.remote_as.0,
            // `State` writes itself without the padding a width asks for.
            r.state.to_string(),
            r.since.as_secs(),
            received,
            advertised
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
    let (received, advertised) = counts(stats, r.addr);
    let mut lines = vec![
        format!("neighbor {}", r.addr),
        format!("  remote-as {}", r.remote_as),
        format!("  state {} for {}s", r.state, r.since.as_secs()),
        format!("  updates in {} out {}", r.updates_in, r.updates_out),
        format!("  routes received {received} advertised {advertised}"),
    ];
    for (family, received, advertised, limit) in per_family(stats, r.addr) {
        lines.push(format!(
            "    {family} received {received} advertised {advertised}{}",
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

fn render_routes(routes: &[RouteReport]) -> Reply {
    let mut lines = vec![format!(
        "{:<44} {:<40} {:<8} {:>5} {:>7} {:<9} path",
        "prefix", "next-hop", "origin", "lpref", "med", "rov"
    )];
    let mut j = Json::new();
    j.begin_array();
    for r in routes {
        let a = &r.attrs;
        let path: Vec<String> = a.as_path.asns().map(|x| x.0.to_string()).collect();
        // `Prefix` and `Origin` write themselves without the padding a
        // width asks for, so they are padded as strings.
        lines.push(format!(
            "{}{:<43} {:<40} {:<8} {:>5} {:>7} {:<9} {} via {}",
            if r.best { "*" } else { " " },
            r.prefix.to_string(),
            a.next_hop_addr(),
            a.origin.to_string(),
            a.local_pref.map_or("-".to_owned(), |v| v.to_string()),
            a.med.map_or("-".to_owned(), |v| v.to_string()),
            r.rov.as_str(),
            if path.is_empty() {
                "-".to_owned()
            } else {
                path.join(" ")
            },
            r.peer
        ));
        j.begin_object()
            .field_display("prefix", r.prefix)
            .field_display("next_hop", a.next_hop_addr())
            .field_display("origin", a.origin)
            .field_opt_num("local_pref", a.local_pref)
            .field_opt_num("med", a.med)
            .field_display("peer", r.peer)
            .field_bool("best", r.best)
            .field_str("rov", r.rov.as_str())
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
    j.end_array();
    Reply {
        lines,
        json: j.finish(),
    }
}

fn render_fib(f: &FibReport) -> Reply {
    let mut lines = vec![format!("mode {}", f.mode)];
    let mut j = Json::new();
    j.begin_object()
        .field_display("mode", f.mode)
        .key("routes")
        .begin_array();
    for (prefix, gateway) in &f.desired {
        let installed = f.installed.get(prefix) == Some(gateway);
        // `Prefix` writes itself without the padding a width asks for.
        lines.push(format!(
            "{:<44} via {:<40} {}",
            prefix.to_string(),
            gateway,
            if installed { "installed" } else { "pending" }
        ));
        j.begin_object()
            .field_display("prefix", prefix)
            .field_display("gateway", gateway)
            .field_bool("installed", installed)
            .end_object();
    }
    for (prefix, gateway) in &f.installed {
        if !f.desired.contains_key(prefix) {
            lines.push(format!(
                "{:<44} via {gateway:<40} stale",
                prefix.to_string()
            ));
            j.begin_object()
                .field_display("prefix", prefix)
                .field_display("gateway", gateway)
                .field_bool("installed", true)
                .field_bool("stale", true)
                .end_object();
        }
    }
    j.end_array().end_object();
    Reply {
        lines,
        json: j.finish(),
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
    let response = match proto::Request::parse(line.trim_end_matches(['\r', '\n'])) {
        Err(e) => proto::Response::error(e.to_string()),
        Ok(req) => match Command::parse(&req.words).and_then(|c| execute(ctx, &c)) {
            Ok(reply) => proto::Response::ok(reply.lines),
            Err(e) => proto::Response::error(e),
        },
    };
    let mut w = stream;
    let _ = response.write_to(&mut w);
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
    let response = match http::Request::read_from(&mut reader) {
        Err(http::HttpError::TooLarge) => http::Response::error(413, "request too large"),
        Err(e) => http::Response::error(400, &e.to_string()),
        Ok(req) => http_respond(ctx, &req),
    };
    let mut w = stream;
    let _ = response.write_to(&mut w);
}

fn http_respond(ctx: &Ctx, req: &http::Request) -> http::Response {
    // RFC 6750 §2.1: the token, when configured, is required on every
    // request, before the resource is even looked at.
    if let Some(token) = &ctx.token
        && req.bearer_token() != Some(token.as_str())
    {
        let mut r = http::Response::error(401, "bearer token required");
        r.extra
            .push(("WWW-Authenticate".to_owned(), "Bearer".to_owned()));
        return r;
    }
    let cmd = match Command::from_http(req) {
        Ok(c) => c,
        Err((status, m)) => return http::Response::error(status, &m),
    };
    if cmd.is_write() && !ctx.writes {
        return http::Response::error(
            403,
            "write endpoints are disabled (control { http { writes yes; } })",
        );
    }
    match execute(ctx, &cmd) {
        Ok(reply) => http::Response::json(200, reply.json),
        Err(e) => http::Response::error(
            if e.starts_with("no neighbor") {
                404
            } else {
                500
            },
            &e,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgpfc_rib::RovState;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
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
            extended_next_hop: Vec::new(),
            advertisement_interval: Duration::ZERO,
            prefix_limits: vec![(v4, 1000)],
        };
        let stats = bgpfc_rib::PeerStats {
            received: vec![(v4, 12), (v6, 3)],
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
        // RFC 4271 §6.7: what the limit counts, next to the limit.
        for line in [
            "  routes received 15 advertised 4",
            "    ipv4-unicast received 12 advertised 4 maximum-prefix 1000",
            "    ipv6-unicast received 3 advertised 0",
        ] {
            assert!(r.lines.contains(&line.to_owned()), "{line}: {:?}", r.lines);
        }
        assert!(
            r.json.contains(
                r#""prefixes":[{"family":"ipv4-unicast","received":12,"advertised":4,"limit":1000},{"family":"ipv6-unicast","received":3,"advertised":0,"limit":null}]"#
            ),
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
        let p = |s: &str| -> Prefix { s.parse().unwrap() };
        let gw: IpAddr = "198.51.100.1".parse().unwrap();
        let report = FibReport {
            mode: Mode::Install,
            desired: [(p("192.0.2.0/24"), gw), (p("198.51.100.0/24"), gw)].into(),
            installed: [(p("192.0.2.0/24"), gw), (p("203.0.113.0/24"), gw)].into(),
        };
        let r = render_fib(&report);
        assert_eq!(
            r.lines[1..],
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
                communities: vec![Community(0xFBFF_0064)],
                ext_communities: Vec::new(),
                large_communities: Vec::new(),
                unknown: Vec::new(),
            }),
            best: false,
            rov: RovState::Disabled,
        }
    }

    #[test]
    fn routes_render_as_lines_and_json() {
        // Two routes to one destination, from different origin ASes: a
        // VRP for AS 64496 makes one valid and the other invalid. The
        // invalid one stays a candidate (RFC 6811 §2).
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
        // `rov` is the state's name.
        assert_eq!(
            r.json,
            concat!(
                r#"[{"prefix":"192.0.2.0/24","next_hop":"198.51.100.1","origin":"igp","#,
                r#""local_pref":100,"med":null,"peer":"198.51.100.1","best":true,"#,
                r#""rov":"valid","as_path":[64511,64496],"communities":["64511:100"],"#,
                r#""large_communities":[]},"#,
                r#"{"prefix":"192.0.2.0/24","next_hop":"198.51.100.2","origin":"igp","#,
                r#""local_pref":null,"med":50,"peer":"198.51.100.2","best":false,"#,
                r#""rov":"invalid","as_path":[64497],"communities":["64511:100"],"#,
                r#""large_communities":[]}]"#
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
                prefix: None
            })
        );
        assert_eq!(
            Command::parse(&words("show routes 2001:db8::/32")),
            Ok(Command::ShowRoutes {
                family: AddressFamily::IPV6_UNICAST,
                prefix: Some("2001:db8::/32".parse().unwrap())
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
                prefix: Some("2001:db8::/32".parse().unwrap())
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
                vrps_ipv4: 2,
                vrps_ipv6: 1,
                failures: 0,
                last_error: Some("rtr cache connection timed out cache=127.0.0.1:3323".to_owned()),
                last_error_at: now.checked_sub(Duration::from_secs(30)),
                running: true,
            }),
        }
    }

    #[test]
    fn rpki_status_renders_as_lines_and_json() {
        let now = Instant::now();
        let r = render_rpki(&rpki_report(now, &[]), now);
        // RFC 8210 §10: the cache list, and the one cache in use.
        assert_eq!(
            r.lines,
            [
                "mode external",
                "cache 127.0.0.1:3323 preference 0",
                "cache rtr.example.net:323 preference 10, in use",
                "state idle, connected, version 1",
                "session-id 4242 serial 17",
                "last sync 12s ago",
                "vrps ipv4 2 ipv6 1, expire in 7188s",
                "failures 0",
                "last error 30s ago: rtr cache connection timed out cache=127.0.0.1:3323",
            ]
        );
        assert_eq!(
            r.json,
            concat!(
                r#"{"mode":"external","caches":["#,
                r#"{"host":"127.0.0.1","port":3323,"preference":0,"in_use":false},"#,
                r#"{"host":"rtr.example.net","port":323,"preference":10,"in_use":true}],"#,
                r#""running":true,"state":"idle","connected":true,"version":1,"#,
                r#""session_id":4242,"serial":17,"synced_seconds_ago":12,"#,
                r#""expires_in_seconds":7188,"vrps":{"ipv4":2,"ipv6":1},"failures":0,"#,
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
            (s.vrps, s.last_error, s.last_error_at) = (None, None, None);
            s.failures = 3;
        }
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines[3..],
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
            render_rpki(&report, now).lines[3],
            "state stopped, version 1"
        );
        // Disabled: the configured caches, nothing else, every member there.
        let report = RpkiReport {
            config: rpki_block("rpki { mode disabled; cache 192.0.2.10; }"),
            status: None,
        };
        let r = render_rpki(&report, now);
        assert_eq!(
            r.lines,
            ["mode disabled", "cache 192.0.2.10:323 preference 0"]
        );
        assert_eq!(
            r.json,
            concat!(
                r#"{"mode":"disabled","caches":[{"host":"192.0.2.10","port":323,"#,
                r#""preference":0,"in_use":false}],"running":false,"state":null,"#,
                r#""connected":false,"version":null,"session_id":null,"serial":null,"#,
                r#""synced_seconds_ago":null,"expires_in_seconds":null,"vrps":null,"#,
                r#""failures":0,"last_error":null,"last_error_seconds_ago":null}"#
            )
        );
        let none = RpkiReport {
            config: bgpfc_config::ast::Rpki::default(),
            status: None,
        };
        assert_eq!(render_rpki(&none, now).lines, ["mode disabled"]);
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
