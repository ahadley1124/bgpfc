//! The control plane (AGENTS.md §3, "Control thread(s)"): the Unix socket
//! `bgpfcctl` talks to and the loopback HTTP/JSON API. Both answer the
//! same commands; the data comes from the other threads over
//! request/response channels, never from shared state.
//!
//! Implements: `docs/control.md`; RFC 2918 §4 (soft reset asks for a
//! route refresh); RFC 9003 §3 (a shutdown communication of at most 128
//! octets); RFC 4486 §4 (Administrative Reset).

use std::io::{BufRead as _, BufReader};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread;
use std::time::Duration;

use bgpfc_control::http;
use bgpfc_control::json::Json;
use bgpfc_control::proto;
use bgpfc_fib::Mode;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};

use crate::coordinator::PeerTable;
use crate::messages::{
    FibMsg, FibReport, PeerInput, PeerReport, RibMsg, RibQuery, RibReply, RouteReport,
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
        .field_num("updates_in", r.updates_in)
        .field_num("updates_out", r.updates_out)
        .field_num("received", u64::try_from(received).unwrap_or(u64::MAX))
        .field_num("advertised", u64::try_from(advertised).unwrap_or(u64::MAX));
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
            j.end_array().end_object();
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
            r.state,
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
    if r.admin_down {
        lines.push("  administratively down".to_owned());
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
        "{:<44} {:<40} {:<8} {:>5} {:>7} path",
        "prefix", "next-hop", "origin", "lpref", "med"
    )];
    let mut j = Json::new();
    j.begin_array();
    for r in routes {
        let a = &r.attrs;
        let path: Vec<String> = a.as_path.asns().map(|x| x.0.to_string()).collect();
        lines.push(format!(
            "{}{:<43} {:<40} {:<8} {:>5} {:>7} {} via {}",
            if r.best { "*" } else { " " },
            r.prefix,
            a.next_hop_addr(),
            a.origin,
            a.local_pref.map_or("-".to_owned(), |v| v.to_string()),
            a.med.map_or("-".to_owned(), |v| v.to_string()),
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
            .field_opt("local_pref", a.local_pref)
            .field_opt("med", a.med)
            .field_display("peer", r.peer)
            .field_bool("best", r.best)
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
        lines.push(format!(
            "{:<44} via {:<40} {}",
            prefix,
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
            lines.push(format!("{prefix:<44} via {gateway:<40} stale"));
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

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
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
}
