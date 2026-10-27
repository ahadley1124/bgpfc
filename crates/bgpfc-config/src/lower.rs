//! Give the generic statements meaning: keywords, argument counts, value
//! syntax, required and duplicate statements. Everything that needs only
//! one statement is checked here; cross-references between items are
//! [`validate`](crate::validate)'s job.
//!
//! Implements: RFC 4271 §4.2 (Hold Time 0 or ≥ 3; non-zero BGP
//! Identifier), §9.2.1.1 and §10 (`advertisement-interval`, the
//! `MinRouteAdvertisementIntervalTimer`), §10 (defaults); RFC 7607 §2 (AS 0
//! is never configurable); RFC 9687 §4.4 (`send-hold-time`); RFC 8950 §4
//! (`extended-next-hop`); RFC 4486 §4 (`restart-limit`); RFC 4271 §6.7
//! (`maximum-prefix`); RFC 8210 §6 (`max-expire` within the Expire
//! Interval's range; `backoff` within the Retry Interval's), §7
//! (`version`), §9 (port 323; the sidecar's RTR on loopback only), §10
//! (`cache` and its `preference`); RFC 1123 §2.1 (cache host names); RFC
//! 6811 §2 and §5 (`enforcement`: what the validation state does,
//! configured; `startup`: routes held until the first data only when
//! configured), §3 (`match rpki`, `set rpki`). Issues #70-#72: the
//! `sidecar` block of `rpki`, within the bounds of `bgpfc-sidecar`. The
//! `netns` statement, a name as iproute2 takes one or an absolute path
//! ([`netns_path`](crate::netns_path)).

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use bgpfc_rpki::{Enforcement, RovState, Startup};
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};

use crate::ast::{
    Action, CommunityOp, Config, Control, DEFAULT_RESTART_LIMIT, Fib, FibMode, Http, Match,
    Neighbor, Policy, PrefixEntry, PrefixList, Rpki, RpkiCache, RpkiKeepalive, RpkiMode,
    RpkiSidecar, SendHoldTime, SetAction, Term,
};
use crate::error::{ConfigError, Pos};
use crate::parser::{Arg, Statement};

/// Build a [`Config`] from top-level statements. On any error, `None` and
/// at least one error.
pub(crate) fn lower(statements: &[Statement]) -> Result<Config, Vec<ConfigError>> {
    let mut l = Lowerer { errors: Vec::new() };
    let cfg = l.file(statements);
    if l.errors.is_empty() {
        // invariant: `file` only returns `None` after pushing an error.
        cfg.ok_or_else(Vec::new)
    } else {
        Err(l.errors)
    }
}

struct Lowerer {
    errors: Vec<ConfigError>,
}

/// One optional statement that may appear at most once.
struct Once<T> {
    value: Option<T>,
    /// Whether the statement appeared at all, valid or not, so that a
    /// bad value is not also reported as a missing statement.
    seen: bool,
    keyword: &'static str,
}

impl<T> Once<T> {
    fn new(keyword: &'static str) -> Self {
        Once {
            value: None,
            seen: false,
            keyword,
        }
    }

    fn set(&mut self, l: &mut Lowerer, pos: Pos, value: Option<T>) {
        if self.seen {
            l.err(pos, format!("`{}` is given more than once", self.keyword));
            return;
        }
        self.seen = true;
        self.value = value;
    }
}

/// Where errors about the file as a whole point.
const FILE_START: Pos = Pos { line: 1, col: 1 };

impl Lowerer {
    fn err(&mut self, pos: Pos, message: impl Into<String>) {
        self.errors.push(ConfigError::new(pos, message));
    }

    /// Exactly `n` arguments and no block; the arguments on success.
    fn args<'s>(&mut self, s: &'s Statement, n: usize) -> Option<&'s [Arg]> {
        if s.block.is_some() {
            self.err(s.pos, format!("`{}` does not take a block", s.keyword));
            return None;
        }
        if s.args.len() != n {
            let what = match n {
                0 => "no arguments".to_owned(),
                1 => "one argument".to_owned(),
                n => format!("{n} arguments"),
            };
            self.err(
                s.pos,
                format!("`{}` takes {what}, found {}", s.keyword, s.args.len()),
            );
            return None;
        }
        Some(&s.args)
    }

    /// Exactly one argument, as text.
    fn arg<'s>(&mut self, s: &'s Statement) -> Option<&'s Arg> {
        self.args(s, 1).map(|a| &a[0])
    }

    /// A block, with `n` arguments before it.
    fn block<'s>(&mut self, s: &'s Statement, n: usize) -> Option<&'s [Statement]> {
        let Some(block) = &s.block else {
            self.err(s.pos, format!("`{}` needs a `{{ ... }}` block", s.keyword));
            return None;
        };
        if s.args.len() != n {
            self.err(
                s.pos,
                format!(
                    "`{}` takes {n} argument{} before its block, found {}",
                    s.keyword,
                    if n == 1 { "" } else { "s" },
                    s.args.len()
                ),
            );
            return None;
        }
        Some(block)
    }

    fn parse<T: FromStr>(&mut self, a: &Arg, what: &str) -> Option<T> {
        let v = a.value.parse().ok();
        if v.is_none() {
            self.err(a.pos, format!("`{}` is not {what}", a.value));
        }
        v
    }

    fn parse_arg<T: FromStr>(&mut self, s: &Statement, what: &str) -> Option<T> {
        let a = self.arg(s)?;
        self.parse(a, what)
    }

    /// RFC 7607 §2: AS 0 is never valid in configuration.
    fn asn(&mut self, a: &Arg) -> Option<Asn> {
        let n: u32 = self.parse(a, "an AS number")?;
        if n == 0 {
            self.err(a.pos, "AS 0 is reserved (RFC 7607)");
            return None;
        }
        Some(Asn(n))
    }

    fn secs(&mut self, s: &Statement) -> Option<Duration> {
        let a = self.arg(s)?;
        let n: u32 = self.parse(a, "a number of seconds")?;
        Some(Duration::from_secs(u64::from(n)))
    }

    fn yes_no(&mut self, s: &Statement) -> Option<bool> {
        let a = self.arg(s)?;
        match a.value.as_str() {
            "yes" | "on" | "true" => Some(true),
            "no" | "off" | "false" => Some(false),
            _ => {
                self.err(a.pos, format!("`{}` is not `yes` or `no`", a.value));
                None
            }
        }
    }

    fn unknown(&mut self, s: &Statement, context: &str) {
        self.err(
            s.pos,
            format!("unknown statement `{}` in {context}", s.keyword),
        );
    }

    fn file(&mut self, statements: &[Statement]) -> Option<Config> {
        let mut router_id = Once::new("router-id");
        let mut local_as = Once::new("local-as");
        let mut log_level = Once::new("log");
        let mut fib = Once::new("fib");
        let mut control = Once::new("control");
        let mut rpki = Once::new("rpki");
        let mut netns = Once::new("netns");
        let mut listen = Vec::new();
        let mut prefix_lists: Vec<PrefixList> = Vec::new();
        let mut policies: Vec<Policy> = Vec::new();
        let mut neighbors = Vec::new();
        for s in statements {
            match s.keyword.as_str() {
                "router-id" => {
                    let v = self.arg(s).and_then(|a| {
                        let ip: std::net::Ipv4Addr = self.parse(a, "an IPv4 address")?;
                        // RFC 4271 §4.2, §6.2: the BGP Identifier is non-zero.
                        let r = RouterId::new(u32::from(ip));
                        if r.is_none() {
                            self.err(a.pos, "router-id must not be 0.0.0.0");
                        }
                        r
                    });
                    router_id.set(self, s.pos, v);
                }
                "local-as" => {
                    let v = self.arg(s).and_then(|a| self.asn(a));
                    local_as.set(self, s.pos, v);
                }
                "log" => {
                    let v = self.log(s);
                    log_level.set(self, s.pos, v);
                }
                "listen" => listen.extend(self.listen(s)),
                "fib" => {
                    let v = self.fib(s);
                    fib.set(self, s.pos, v);
                }
                "control" => {
                    let v = self.control(s);
                    control.set(self, s.pos, v);
                }
                "rpki" => {
                    let v = self.rpki(s);
                    rpki.set(self, s.pos, v);
                }
                "netns" => {
                    let v = self.arg(s).and_then(|a| {
                        crate::netns_path(&a.value)
                            .map_err(|e| self.err(a.pos, format!("`netns` {e}")))
                            .ok()
                    });
                    netns.set(self, s.pos, v);
                }
                "prefix-list" => {
                    if let Some(p) = self.prefix_list(s) {
                        if prefix_lists.iter().any(|q| q.name == p.name) {
                            self.err(s.pos, format!("prefix-list `{}` is defined twice", p.name));
                        }
                        prefix_lists.push(p);
                    }
                }
                "policy" => {
                    if let Some(p) = self.policy(s) {
                        if policies.iter().any(|q| q.name == p.name) {
                            self.err(s.pos, format!("policy `{}` is defined twice", p.name));
                        }
                        policies.push(p);
                    }
                }
                "neighbor" => neighbors.extend(self.neighbor(s)),
                _ => self.unknown(s, "the file"),
            }
        }
        if !router_id.seen {
            self.err(FILE_START, "`router-id` is required");
        }
        if !local_as.seen {
            self.err(FILE_START, "`local-as` is required");
        }
        if listen.is_empty() {
            listen.push(SocketAddr::from(([0u16; 8], 179)));
        }
        Some(Config {
            router_id: router_id.value?,
            local_as: local_as.value?,
            log_level: log_level.value.unwrap_or(bgpfc_log::Level::Info),
            listen,
            fib: fib.value.unwrap_or_default(),
            control: control.value.unwrap_or_default(),
            rpki: rpki.value.unwrap_or_else(Rpki::implicit),
            netns: netns.value,
            prefix_lists,
            policies,
            neighbors,
        })
    }

    fn log(&mut self, s: &Statement) -> Option<bgpfc_log::Level> {
        let mut level = Once::new("level");
        for t in self.block(s, 0)? {
            match t.keyword.as_str() {
                "level" => {
                    let v = self.arg(t).and_then(|a| {
                        let l = bgpfc_log::Level::parse(&a.value);
                        if l.is_none() {
                            self.err(
                                a.pos,
                                format!(
                                    "`{}` is not a log level (error, warn, info, debug, trace)",
                                    a.value
                                ),
                            );
                        }
                        l
                    });
                    level.set(self, t.pos, v);
                }
                _ => self.unknown(t, "`log`"),
            }
        }
        Some(level.value.unwrap_or(bgpfc_log::Level::Info))
    }

    fn listen(&mut self, s: &Statement) -> Option<SocketAddr> {
        let mut address = Once::new("address");
        let mut port = Once::new("port");
        for t in self.block(s, 0)? {
            match t.keyword.as_str() {
                "address" => {
                    let v = self.parse_arg::<IpAddr>(t, "an IP address");
                    address.set(self, t.pos, v);
                }
                "port" => {
                    let v = self.parse_arg::<u16>(t, "a port number");
                    port.set(self, t.pos, v);
                }
                _ => self.unknown(t, "`listen`"),
            }
        }
        if !address.seen {
            self.err(s.pos, "`listen` needs an `address`");
        }
        let address = address.value?;
        Some(SocketAddr::new(address, port.value.unwrap_or(179)))
    }

    fn fib(&mut self, s: &Statement) -> Option<Fib> {
        let mut fib = Fib::default();
        let mut mode = Once::new("mode");
        let mut table = Once::new("table");
        let mut protocol = Once::new("protocol");
        for t in self.block(s, 0)? {
            match t.keyword.as_str() {
                "mode" => {
                    let v = self.arg(t).and_then(|a| match a.value.as_str() {
                        "dry-run" => Some(FibMode::DryRun),
                        "install" => Some(FibMode::Install),
                        _ => {
                            self.err(
                                a.pos,
                                format!("`{}` is not `dry-run` or `install`", a.value),
                            );
                            None
                        }
                    });
                    mode.set(self, t.pos, v);
                }
                "table" => {
                    let v = self.arg(t).and_then(|a| match a.value.as_str() {
                        // <linux/rtnetlink.h> rt_class_t
                        "main" => Some(254),
                        "local" => Some(255),
                        "default" => Some(253),
                        _ => self.parse::<u32>(a, "a table name or number"),
                    });
                    table.set(self, t.pos, v);
                }
                "protocol" => {
                    let v = self.parse_arg::<u8>(t, "a protocol number (0-255)");
                    protocol.set(self, t.pos, v);
                }
                _ => self.unknown(t, "`fib`"),
            }
        }
        if let Some(m) = mode.value {
            fib.mode = m;
        }
        if let Some(t) = table.value {
            fib.table = t;
        }
        if let Some(p) = protocol.value {
            fib.protocol = p;
        }
        Some(fib)
    }

    fn control(&mut self, s: &Statement) -> Option<Control> {
        let mut socket = Once::new("socket");
        let mut http = Once::new("http");
        for t in self.block(s, 0)? {
            match t.keyword.as_str() {
                "socket" => {
                    let v = self.arg(t).map(|a| PathBuf::from(&a.value));
                    socket.set(self, t.pos, v);
                }
                "http" => {
                    let v = self.http(t);
                    http.set(self, t.pos, v);
                }
                _ => self.unknown(t, "`control`"),
            }
        }
        Some(Control {
            socket: socket.value,
            http: http.value,
        })
    }

    fn http(&mut self, s: &Statement) -> Option<Http> {
        let mut listen = Once::new("listen");
        let mut writes = Once::new("writes");
        let mut token_file = Once::new("token-file");
        for t in self.block(s, 0)? {
            match t.keyword.as_str() {
                "listen" => {
                    let v = self
                        .parse_arg::<SocketAddr>(t, "an `address:port`")
                        .filter(|a| {
                            // README, "Operate": the HTTP API has no TLS and
                            // no access control beyond the token, so it is
                            // loopback-only.
                            let ok = a.ip().is_loopback();
                            if !ok {
                                self.err(
                                    t.pos,
                                    format!("http listen address {a} is not a loopback address"),
                                );
                            }
                            ok
                        });
                    listen.set(self, t.pos, v);
                }
                "writes" => {
                    let v = self.yes_no(t);
                    writes.set(self, t.pos, v);
                }
                "token-file" => {
                    let v = self.arg(t).map(|a| PathBuf::from(&a.value));
                    token_file.set(self, t.pos, v);
                }
                _ => self.unknown(t, "`http`"),
            }
        }
        if !listen.seen {
            self.err(s.pos, "`http` needs a `listen` address");
        }
        let listen = listen.value?;
        Some(Http {
            listen,
            writes: writes.value.unwrap_or(false),
            token_file: token_file.value,
        })
    }

    fn rpki(&mut self, s: &Statement) -> Option<Rpki> {
        let mut b = RpkiBuilder::new();
        for t in self.block(s, 0)? {
            b.statement(self, t);
        }
        b.finish(self, s.pos)
    }

    /// `sidecar { ... }` in `rpki`.
    fn sidecar(&mut self, s: &Statement) -> Option<RpkiSidecar> {
        let mut b = SidecarBuilder::new();
        for t in self.block(s, 0)? {
            b.statement(self, t);
        }
        Some(b.finish(s.pos))
    }

    /// One argument, an absolute path; `why` follows the error otherwise.
    fn absolute_path(&mut self, s: &Statement, why: &str) -> Option<PathBuf> {
        let a = self.arg(s)?;
        if !Path::new(&a.value).is_absolute() {
            self.err(
                a.pos,
                format!(
                    "`{}` needs an absolute path, found `{}`{why}",
                    s.keyword, a.value
                ),
            );
            return None;
        }
        Some(PathBuf::from(&a.value))
    }

    /// At least one argument, and no block: the arguments as written.
    fn words(&mut self, s: &Statement, what: &str) -> Option<Vec<String>> {
        if s.block.is_some() {
            self.err(s.pos, format!("`{}` does not take a block", s.keyword));
            return None;
        }
        if s.args.is_empty() {
            self.err(s.pos, format!("`{}` needs at least one {what}", s.keyword));
            return None;
        }
        Some(s.args.iter().map(|a| a.value.clone()).collect())
    }

    /// A number of seconds from 1 to `max`; `why` follows the error
    /// otherwise.
    fn secs_up_to(&mut self, s: &Statement, max: Duration, why: &str) -> Option<Duration> {
        let d = self.secs(s)?;
        if d.is_zero() || d > max {
            self.err(
                s.args[0].pos,
                format!(
                    "{} must be between 1 and {} seconds{why}",
                    s.keyword,
                    max.as_secs()
                ),
            );
            return None;
        }
        Some(d)
    }

    /// `rtr-listen ADDR [port N]`: where the sidecar serves RTR.
    fn rtr_listen(&mut self, s: &Statement) -> Option<SocketAddr> {
        if s.block.is_some() {
            self.err(s.pos, "`rtr-listen` does not take a block");
            return None;
        }
        let (addr, port) = match &s.args[..] {
            [addr] => (addr, None),
            [addr, kw, port] if kw.value == "port" => (addr, Some(port)),
            [_, kw, _] => {
                self.err(kw.pos, format!("expected `port`, found `{}`", kw.value));
                return None;
            }
            args => {
                self.err(
                    s.pos,
                    format!(
                        "`rtr-listen` takes an address and optionally `port N`, found {} \
                         arguments",
                        args.len()
                    ),
                );
                return None;
            }
        };
        let ip = self.parse::<IpAddr>(addr, "an IP address").filter(|ip| {
            // Issue #71, RFC 8210 §9: the sidecar's unprotected RTR never
            // leaves the host. `Ipv6Addr::is_loopback` holds for `::1`
            // alone, so `::ffff:127.0.0.1` is refused, as `bgpfc-sidecar`
            // refuses it.
            let ok = ip.is_loopback();
            if !ok {
                let mapped = matches!(ip, IpAddr::V6(v6)
                    if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()));
                self.err(
                    addr.pos,
                    format!(
                        "rtr-listen address {ip} is not a loopback address: the sidecar serves \
                         RTR on loopback only (issue #71){}",
                        if mapped {
                            "; write it as 127.0.0.1"
                        } else {
                            ""
                        }
                    ),
                );
            }
            ok
        });
        let port = match port {
            None => Some(RpkiSidecar::DEFAULT_RTR_LISTEN.port()),
            Some(p) => self
                .parse::<u16>(p, "a port number (0-65535)")
                .filter(|&n| {
                    // Routinator runs without capabilities (bgpfc-sidecar),
                    // so a privileged port fails at every start.
                    let ok = n == 0 || n >= RpkiSidecar::MIN_RTR_PORT;
                    if !ok {
                        self.err(
                            p.pos,
                            format!(
                                "rtr-listen port {n} is below {}: Routinator runs without \
                                 capabilities and cannot bind it; use 0, picked at start, or \
                                 {}-65535",
                                RpkiSidecar::MIN_RTR_PORT,
                                RpkiSidecar::MIN_RTR_PORT
                            ),
                        );
                    }
                    ok
                }),
        };
        Some(SocketAddr::new(ip?, port?))
    }

    /// `restart-backoff INITIAL CAP`, each within 1 s and
    /// [`RpkiSidecar::MAX_RESTART_BACKOFF`].
    fn restart_backoff(&mut self, s: &Statement) -> Option<(Duration, Duration)> {
        let [initial, cap] = self.args(s, 2)? else {
            return None;
        };
        let initial = self.restart_bound(initial);
        let cap = self.restart_bound(cap);
        let (initial, cap) = (initial?, cap?);
        if cap < initial {
            self.err(
                s.pos,
                format!(
                    "restart-backoff cap {}s is below its initial delay {}s",
                    cap.as_secs(),
                    initial.as_secs()
                ),
            );
            return None;
        }
        Some((initial, cap))
    }

    fn restart_bound(&mut self, a: &Arg) -> Option<Duration> {
        let n: u32 = self.parse(a, "a number of seconds")?;
        let d = Duration::from_secs(u64::from(n));
        if d.is_zero() || d > RpkiSidecar::MAX_RESTART_BACKOFF {
            self.err(
                a.pos,
                format!(
                    "a restart-backoff must be between 1 and {} seconds",
                    RpkiSidecar::MAX_RESTART_BACKOFF.as_secs()
                ),
            );
            return None;
        }
        Some(d)
    }

    /// `cache HOST [port N] [preference N]`.
    fn rpki_cache(&mut self, s: &Statement) -> Option<RpkiCache> {
        if s.block.is_some() {
            self.err(s.pos, "`cache` does not take a block");
            return None;
        }
        let Some(host) = s.args.first() else {
            self.err(s.pos, "`cache` needs an IP address or a host name");
            return None;
        };
        if !is_host(&host.value) {
            self.err(
                host.pos,
                format!("`{}` is not an IP address or a host name", host.value),
            );
            return None;
        }
        let mut port = None;
        let mut preference = None;
        let mut rest = s.args[1..].iter();
        while let Some(kw) = rest.next() {
            if !matches!(kw.value.as_str(), "port" | "preference") {
                self.err(
                    kw.pos,
                    format!("expected `port` or `preference`, found `{}`", kw.value),
                );
                return None;
            }
            let Some(value) = rest.next() else {
                self.err(kw.pos, format!("`{}` needs a value", kw.value));
                return None;
            };
            let slot_taken = if kw.value == "port" {
                port.is_some()
            } else {
                preference.is_some()
            };
            if slot_taken {
                self.err(kw.pos, format!("`{}` is given more than once", kw.value));
                return None;
            }
            if kw.value == "port" {
                let p = self
                    .parse::<u16>(value, "a port number (1-65535)")
                    .filter(|&p| {
                        if p == 0 {
                            self.err(value.pos, "`0` is not a port number (1-65535)");
                        }
                        p != 0
                    })?;
                port = Some(p);
            } else {
                preference = Some(self.parse::<u32>(value, "a preference (0-4294967295)")?);
            }
        }
        Some(RpkiCache {
            host: host.value.clone(),
            port: port.unwrap_or(Rpki::DEFAULT_PORT),
            preference: preference.unwrap_or(0),
        })
    }

    /// `tcp-keepalive [idle N] [interval N] [count N]`: each option at
    /// most once, in any order, and at least one; one not given keeps its
    /// default, as with the options of `cache`. Keywords rather than three
    /// numbers in a row, as `backoff` has two, so that the two times cannot
    /// be swapped unseen; named after the socket options they set
    /// (`TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`, `tcp(7)`). The
    /// bounds are the kernel's, which would refuse anything else with
    /// `EINVAL` when bgpfcd sets them.
    fn tcp_keepalive(&mut self, s: &Statement) -> Option<RpkiKeepalive> {
        if s.block.is_some() {
            self.err(s.pos, "`tcp-keepalive` does not take a block");
            return None;
        }
        if s.args.is_empty() {
            self.err(
                s.pos,
                "`tcp-keepalive` needs at least one of `idle N`, `interval N` and `count N`",
            );
            return None;
        }
        let mut idle = None;
        let mut interval = None;
        let mut count = None;
        let mut rest = s.args.iter();
        while let Some(kw) = rest.next() {
            let given = match kw.value.as_str() {
                "idle" => idle.is_some(),
                "interval" => interval.is_some(),
                "count" => count.is_some(),
                other => {
                    self.err(
                        kw.pos,
                        format!("expected `idle`, `interval` or `count`, found `{other}`"),
                    );
                    return None;
                }
            };
            let Some(value) = rest.next() else {
                self.err(kw.pos, format!("`{}` needs a value", kw.value));
                return None;
            };
            if given {
                self.err(kw.pos, format!("`{}` is given more than once", kw.value));
                return None;
            }
            match kw.value.as_str() {
                "idle" => {
                    idle = Some(self.keepalive_secs(value, "idle", RpkiKeepalive::MAX_IDLE)?);
                }
                "interval" => {
                    interval = Some(self.keepalive_secs(
                        value,
                        "interval",
                        RpkiKeepalive::MAX_INTERVAL,
                    )?);
                }
                _ => {
                    let n: u32 = self.parse(value, "a number of probes")?;
                    if !(1..=RpkiKeepalive::MAX_COUNT).contains(&n) {
                        self.err(
                            value.pos,
                            format!(
                                "tcp-keepalive count must be between 1 and {} (the kernel's \
                                 MAX_TCP_KEEPCNT)",
                                RpkiKeepalive::MAX_COUNT
                            ),
                        );
                        return None;
                    }
                    count = Some(n);
                }
            }
        }
        let d = RpkiKeepalive::DEFAULT;
        Some(RpkiKeepalive {
            idle: idle.unwrap_or(d.idle),
            interval: interval.unwrap_or(d.interval),
            count: count.unwrap_or(d.count),
        })
    }

    /// The seconds of a `tcp-keepalive` time `what`, from 1 to `max`.
    fn keepalive_secs(&mut self, a: &Arg, what: &str, max: Duration) -> Option<Duration> {
        let n: u32 = self.parse(a, "a number of seconds")?;
        let d = Duration::from_secs(u64::from(n));
        if d.is_zero() || d > max {
            let constant = if what == "idle" {
                "MAX_TCP_KEEPIDLE"
            } else {
                "MAX_TCP_KEEPINTVL"
            };
            self.err(
                a.pos,
                format!(
                    "tcp-keepalive {what} must be between 1 and {} seconds (the kernel's \
                     {constant})",
                    max.as_secs()
                ),
            );
            return None;
        }
        Some(d)
    }

    /// `max-expire N` within the range RFC 8210 §6 gives the Expire
    /// Interval it caps.
    fn max_expire(&mut self, s: &Statement) -> Option<Duration> {
        let d = self.secs(s)?;
        if !(Rpki::MIN_EXPIRE..=Rpki::MAX_EXPIRE).contains(&d) {
            self.err(
                s.args[0].pos,
                format!(
                    "max-expire must be between {} and {} seconds (RFC 8210 §6)",
                    Rpki::MIN_EXPIRE.as_secs(),
                    Rpki::MAX_EXPIRE.as_secs()
                ),
            );
            return None;
        }
        Some(d)
    }

    /// A number of seconds, at least one.
    fn positive_secs(&mut self, s: &Statement) -> Option<Duration> {
        let d = self.secs(s)?;
        if d.is_zero() {
            self.err(
                s.args[0].pos,
                format!("{} must be at least 1 second", s.keyword),
            );
            return None;
        }
        Some(d)
    }

    /// `backoff MIN MAX`, each within 1 s and [`Rpki::MAX_BACKOFF`].
    fn backoff(&mut self, s: &Statement) -> Option<(Duration, Duration)> {
        let [min, max] = self.args(s, 2)? else {
            return None;
        };
        let min = self.backoff_bound(min);
        let max = self.backoff_bound(max);
        let (min, max) = (min?, max?);
        if max < min {
            self.err(
                s.pos,
                format!(
                    "backoff maximum {}s is below its minimum {}s",
                    max.as_secs(),
                    min.as_secs()
                ),
            );
            return None;
        }
        Some((min, max))
    }

    fn backoff_bound(&mut self, a: &Arg) -> Option<Duration> {
        let n: u32 = self.parse(a, "a number of seconds")?;
        let d = Duration::from_secs(u64::from(n));
        // RFC 8210 §6: the back-off stands in for the Retry Interval, which
        // a cache may set between 1 and 7200 seconds.
        if d.is_zero() || d > Rpki::MAX_BACKOFF {
            self.err(
                a.pos,
                format!(
                    "a backoff must be between 1 and {} seconds (RFC 8210 §6)",
                    Rpki::MAX_BACKOFF.as_secs()
                ),
            );
            return None;
        }
        Some(d)
    }

    /// `PREFIX [ge N] [le N]` from `args`.
    fn prefix_entry(&mut self, pos: Pos, args: &[Arg]) -> Option<PrefixEntry> {
        let Some(first) = args.first() else {
            self.err(pos, "expected a prefix");
            return None;
        };
        let prefix: Prefix = self.parse(first, "a prefix (`address/length`)")?;
        let max = match prefix {
            Prefix::V4 { .. } => 32,
            Prefix::V6 { .. } => 128,
        };
        let mut ge = None;
        let mut le = None;
        let mut rest = args[1..].iter();
        while let Some(kw) = rest.next() {
            let Some(n) = rest.next() else {
                self.err(kw.pos, format!("`{}` needs a length", kw.value));
                return None;
            };
            let len: u8 = self.parse(n, "a prefix length")?;
            if len > max || len < prefix.prefix_len() {
                self.err(
                    n.pos,
                    format!(
                        "length {len} is not between {} and {max}",
                        prefix.prefix_len()
                    ),
                );
                return None;
            }
            match kw.value.as_str() {
                "ge" => ge = Some(len),
                "le" => le = Some(len),
                _ => {
                    self.err(
                        kw.pos,
                        format!("expected `ge` or `le`, found `{}`", kw.value),
                    );
                    return None;
                }
            }
        }
        if let (Some(g), Some(l)) = (ge, le)
            && g > l
        {
            self.err(pos, format!("`ge {g}` is greater than `le {l}`"));
            return None;
        }
        Some(PrefixEntry { prefix, ge, le })
    }

    fn prefix_list(&mut self, s: &Statement) -> Option<PrefixList> {
        let block = self.block(s, 1)?;
        let name = s.args[0].value.clone();
        let mut entries = Vec::new();
        for t in block {
            if t.block.is_some() {
                self.err(t.pos, "a prefix-list entry does not take a block");
                continue;
            }
            // The prefix is the statement's keyword; `ge`/`le` follow.
            let mut args = vec![Arg {
                pos: t.pos,
                value: t.keyword.clone(),
                quoted: false,
            }];
            args.extend(t.args.iter().cloned());
            entries.extend(self.prefix_entry(t.pos, &args));
        }
        Some(PrefixList {
            pos: s.pos,
            name,
            entries,
        })
    }

    fn policy(&mut self, s: &Statement) -> Option<Policy> {
        let block = self.block(s, 1)?;
        let name = s.args[0].value.clone();
        let mut terms: Vec<Term> = Vec::new();
        for t in block {
            match t.keyword.as_str() {
                "term" => {
                    if let Some(term) = self.term(t) {
                        if terms.iter().any(|u| u.name == term.name) {
                            self.err(
                                t.pos,
                                format!("term `{}` is defined twice in policy `{name}`", term.name),
                            );
                        }
                        terms.push(term);
                    }
                }
                _ => self.unknown(t, "`policy`"),
            }
        }
        Some(Policy {
            pos: s.pos,
            name,
            terms,
        })
    }

    fn term(&mut self, s: &Statement) -> Option<Term> {
        let block = self.block(s, 1)?;
        let name = s.args[0].value.clone();
        let mut matches = Vec::new();
        let mut sets = Vec::new();
        let mut action = Once::new("action");
        for t in block {
            match t.keyword.as_str() {
                "match" => matches.extend(self.match_clause(t)),
                "set" => sets.extend(self.set_action(t)),
                "action" => {
                    let v = self.arg(t).and_then(|a| match a.value.as_str() {
                        "accept" => Some(Action::Accept),
                        "reject" => Some(Action::Reject),
                        "next" => Some(Action::Next),
                        _ => {
                            self.err(
                                a.pos,
                                format!("`{}` is not `accept`, `reject` or `next`", a.value),
                            );
                            None
                        }
                    });
                    action.set(self, t.pos, v);
                }
                _ => self.unknown(t, "`term`"),
            }
        }
        if !action.seen {
            self.err(s.pos, format!("term `{name}` has no `action`"));
        }
        let action = action.value?;
        Some(Term {
            pos: s.pos,
            name,
            matches,
            sets,
            action,
        })
    }

    fn match_clause(&mut self, s: &Statement) -> Option<Match> {
        if s.block.is_some() {
            self.err(s.pos, "`match` does not take a block");
            return None;
        }
        let Some(kind) = s.args.first() else {
            self.err(s.pos, "`match` needs a clause");
            return None;
        };
        let rest = &s.args[1..];
        let one = |l: &mut Lowerer| -> Option<&Arg> {
            if rest.len() == 1 {
                Some(&rest[0])
            } else {
                l.err(
                    kind.pos,
                    format!(
                        "`match {}` takes one value, found {}",
                        kind.value,
                        rest.len()
                    ),
                );
                None
            }
        };
        match kind.value.as_str() {
            "prefix" => self.prefix_entry(kind.pos, rest).map(Match::Prefix),
            "prefix-list" => one(self).map(|a| Match::PrefixList(a.value.clone())),
            "as-path" => {
                let a = one(self)?;
                if !a.quoted {
                    self.err(a.pos, "an as-path regex must be a quoted string");
                    return None;
                }
                Some(Match::AsPath(a.value.clone()))
            }
            "community" => {
                let a = one(self)?;
                self.parse(a, "a community (`asn:value`)")
                    .map(Match::Community)
            }
            "ext-community" => {
                let a = one(self)?;
                self.parse(a, "an extended community")
                    .map(Match::ExtCommunity)
            }
            "large-community" => {
                let a = one(self)?;
                self.parse(a, "a large community (`a:b:c`)")
                    .map(Match::LargeCommunity)
            }
            "origin" => {
                let a = one(self)?;
                match a.value.as_str() {
                    "igp" => Some(Match::Origin(Origin::Igp)),
                    "egp" => Some(Match::Origin(Origin::Egp)),
                    "incomplete" => Some(Match::Origin(Origin::Incomplete)),
                    _ => {
                        self.err(
                            a.pos,
                            format!("`{}` is not `igp`, `egp` or `incomplete`", a.value),
                        );
                        None
                    }
                }
            }
            "neighbor" => {
                let a = one(self)?;
                self.parse(a, "an IP address").map(Match::Neighbor)
            }
            "rpki" => {
                // RFC 6811 §3: policy matches the validation state.
                let a = one(self)?;
                self.parse(a, "`valid`, `invalid`, `not-found` or `disabled`")
                    .map(Match::Rpki)
            }
            _ => {
                self.err(kind.pos, format!("unknown match clause `{}`", kind.value));
                None
            }
        }
    }

    fn community_op(&mut self, a: &Arg) -> Option<CommunityOp> {
        match a.value.as_str() {
            "add" => Some(CommunityOp::Add),
            "remove" => Some(CommunityOp::Remove),
            "replace" => Some(CommunityOp::Replace),
            _ => {
                self.err(
                    a.pos,
                    format!("`{}` is not `add`, `remove` or `replace`", a.value),
                );
                None
            }
        }
    }

    fn values<T: FromStr>(&mut self, kind: &Arg, args: &[Arg], what: &str) -> Option<Vec<T>> {
        if args.is_empty() {
            self.err(
                kind.pos,
                format!("`set {}` needs at least one value", kind.value),
            );
            return None;
        }
        args.iter().map(|a| self.parse(a, what)).collect()
    }

    fn set_action(&mut self, s: &Statement) -> Option<SetAction> {
        if s.block.is_some() {
            self.err(s.pos, "`set` does not take a block");
            return None;
        }
        let Some(kind) = s.args.first() else {
            self.err(s.pos, "`set` needs an action");
            return None;
        };
        let rest = &s.args[1..];
        let one = |l: &mut Lowerer| -> Option<&Arg> {
            if rest.len() == 1 {
                Some(&rest[0])
            } else {
                l.err(
                    kind.pos,
                    format!("`set {}` takes one value, found {}", kind.value, rest.len()),
                );
                None
            }
        };
        match kind.value.as_str() {
            "local-pref" => {
                let a = one(self)?;
                self.parse(a, "a number").map(SetAction::LocalPref)
            }
            "med" => {
                let a = one(self)?;
                self.parse(a, "a number").map(SetAction::Med)
            }
            "community" | "ext-community" | "large-community" => {
                let Some(op) = rest.first() else {
                    self.err(kind.pos, "expected `add`, `remove` or `replace`");
                    return None;
                };
                let op = self.community_op(op)?;
                let vals = &rest[1..];
                match kind.value.as_str() {
                    "community" => self
                        .values(kind, vals, "a community (`asn:value`)")
                        .map(|v| SetAction::Community(op, v)),
                    "ext-community" => self
                        .values(kind, vals, "an extended community")
                        .map(|v| SetAction::ExtCommunity(op, v)),
                    _ => self
                        .values(kind, vals, "a large community (`a:b:c`)")
                        .map(|v| SetAction::LargeCommunity(op, v)),
                }
            }
            "as-path" => {
                if rest.first().map(|a| a.value.as_str()) != Some("prepend") {
                    self.err(kind.pos, "expected `set as-path prepend ASN...`");
                    return None;
                }
                let vals = &rest[1..];
                if vals.is_empty() {
                    self.err(kind.pos, "`set as-path prepend` needs at least one AS");
                    return None;
                }
                vals.iter()
                    .map(|a| self.asn(a))
                    .collect::<Option<Vec<_>>>()
                    .map(SetAction::AsPathPrepend)
            }
            "next-hop" => {
                let a = one(self)?;
                if a.value == "self" {
                    Some(SetAction::NextHopSelf)
                } else {
                    self.err(a.pos, "only `set next-hop self` is supported");
                    None
                }
            }
            "rpki" => {
                // RFC 6811 §3: policy sets the validation state. `disabled`
                // says that no lookup was made, which is not policy's to
                // say.
                let a = one(self)?;
                match a.value.parse::<RovState>() {
                    Ok(RovState::Disabled) => {
                        self.err(
                            a.pos,
                            "`set rpki` takes `valid`, `invalid` or `not-found`: `disabled` means \
                             validation is off, which policy cannot set",
                        );
                        None
                    }
                    Ok(state) => Some(SetAction::Rpki(state)),
                    Err(_) => {
                        self.err(
                            a.pos,
                            format!("`{}` is not `valid`, `invalid` or `not-found`", a.value),
                        );
                        None
                    }
                }
            }
            _ => {
                self.err(kind.pos, format!("unknown set action `{}`", kind.value));
                None
            }
        }
    }

    fn neighbor(&mut self, s: &Statement) -> Option<Neighbor> {
        let block = self.block(s, 1)?;
        let addr: IpAddr = self.parse(&s.args[0], "an IP address")?;
        let mut b = NeighborBuilder::new();
        for t in block {
            b.statement(self, t);
        }
        b.finish(self, s.pos, addr)
    }

    fn families(&mut self, s: &Statement) -> Option<Vec<AddressFamily>> {
        if s.block.is_some() {
            self.err(s.pos, "`families` does not take a block");
            return None;
        }
        if s.args.is_empty() {
            self.err(s.pos, "`families` needs at least one family");
            return None;
        }
        let mut out: Vec<AddressFamily> = Vec::new();
        for a in &s.args {
            let fam = self.family(a)?;
            if out.contains(&fam) {
                self.err(a.pos, format!("family `{}` is listed twice", a.value));
                return None;
            }
            out.push(fam);
        }
        Some(out)
    }

    /// One family name.
    fn family(&mut self, a: &Arg) -> Option<AddressFamily> {
        match a.value.as_str() {
            "ipv4-unicast" => Some(AddressFamily::IPV4_UNICAST),
            "ipv6-unicast" => Some(AddressFamily::IPV6_UNICAST),
            _ => {
                self.err(
                    a.pos,
                    format!("`{}` is not `ipv4-unicast` or `ipv6-unicast`", a.value),
                );
                None
            }
        }
    }
}

/// Whether `host` can name an RTR cache: an IP address, or a host name
/// as RFC 1123 §2.1 has it: labels of letters, digits and hyphens, none
/// starting or ending with a hyphen, of at most 63 characters, at most
/// 253 in all, with an optional final dot. The last label must not be
/// all digits, since "a valid host name can never have the dotted-decimal
/// form #.#.#.#": the resolver would read `10.1` as the address 10.0.0.1.
fn is_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(label_ok)
        && name
            .rsplit('.')
            .next()
            .is_some_and(|last| !last.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether two `cache` statements name the same cache: see
/// [`RpkiCache::is_at`].
fn same_cache(a: &RpkiCache, b: &RpkiCache) -> bool {
    a.is_at(&b.host, b.port)
}

/// The statements of the `rpki` block, each at most once but `cache`.
struct RpkiBuilder {
    mode: Once<RpkiMode>,
    /// Where the first `mode` statement is.
    mode_pos: Option<Pos>,
    enforcement: Once<Enforcement>,
    startup: Once<Startup>,
    caches: Vec<RpkiCache>,
    /// Where every `cache` statement is, valid or not.
    cache_pos: Vec<Pos>,
    sidecar: Once<RpkiSidecar>,
    /// Where the first `sidecar` statement is, valid or not.
    sidecar_pos: Option<Pos>,
    version: Once<u8>,
    connect_timeout: Once<Duration>,
    response_timeout: Once<Duration>,
    reply_timeout: Once<Duration>,
    max_expire: Once<Duration>,
    max_vrps: Once<u32>,
    backoff: Once<(Duration, Duration)>,
    tcp_keepalive: Once<RpkiKeepalive>,
}

impl RpkiBuilder {
    fn new() -> Self {
        RpkiBuilder {
            mode: Once::new("mode"),
            mode_pos: None,
            enforcement: Once::new("enforcement"),
            startup: Once::new("startup"),
            caches: Vec::new(),
            cache_pos: Vec::new(),
            sidecar: Once::new("sidecar"),
            sidecar_pos: None,
            version: Once::new("version"),
            connect_timeout: Once::new("connect-timeout"),
            response_timeout: Once::new("response-timeout"),
            reply_timeout: Once::new("reply-timeout"),
            max_expire: Once::new("max-expire"),
            max_vrps: Once::new("max-vrps"),
            backoff: Once::new("backoff"),
            tcp_keepalive: Once::new("tcp-keepalive"),
        }
    }

    fn statement(&mut self, l: &mut Lowerer, t: &Statement) {
        match t.keyword.as_str() {
            "mode" => {
                let v = l.arg(t).and_then(|a| match a.value.as_str() {
                    "disabled" => Some(RpkiMode::Disabled),
                    "external" => Some(RpkiMode::External),
                    "sidecar" => Some(RpkiMode::Sidecar),
                    _ => {
                        l.err(
                            a.pos,
                            format!("`{}` is not `disabled`, `external` or `sidecar`", a.value),
                        );
                        None
                    }
                });
                self.mode_pos.get_or_insert(t.pos);
                self.mode.set(l, t.pos, v);
            }
            "enforcement" => {
                // RFC 6811 §5: filter on the state, or adjust the degree of
                // preference by it; or neither (RFC 8481 §5).
                let v = l.parse_arg::<Enforcement>(t, "`drop-invalid`, `prefer-valid` or `off`");
                self.enforcement.set(l, t.pos, v);
            }
            "startup" => {
                // RFC 6811 §2: routes leave the decision process for want
                // of a state only when "explicitly configured to do so".
                let v = l.parse_arg::<Startup>(t, "`accept` or `hold`");
                self.startup.set(l, t.pos, v);
            }
            "cache" => {
                self.cache_pos.push(t.pos);
                let Some(cache) = l.rpki_cache(t) else {
                    return;
                };
                if self.caches.iter().any(|c| same_cache(c, &cache)) {
                    l.err(t.pos, format!("cache {cache} is listed twice"));
                } else {
                    self.caches.push(cache);
                }
            }
            "sidecar" => {
                self.sidecar_pos.get_or_insert(t.pos);
                let v = l.sidecar(t);
                self.sidecar.set(l, t.pos, v);
            }
            "version" => {
                // RFC 8210 §7: version 1, or version 0 (RFC 6810).
                let v = l.arg(t).and_then(|a| match a.value.as_str() {
                    "0" => Some(0),
                    "1" => Some(1),
                    _ => {
                        l.err(
                            a.pos,
                            format!("`{}` is not an RTR protocol version (0 or 1)", a.value),
                        );
                        None
                    }
                });
                self.version.set(l, t.pos, v);
            }
            "connect-timeout" => {
                let v = l.positive_secs(t);
                self.connect_timeout.set(l, t.pos, v);
            }
            "response-timeout" => {
                let v = l.positive_secs(t);
                self.response_timeout.set(l, t.pos, v);
            }
            "reply-timeout" => {
                let v = l.positive_secs(t);
                self.reply_timeout.set(l, t.pos, v);
            }
            "max-expire" => {
                let v = l.max_expire(t);
                self.max_expire.set(l, t.pos, v);
            }
            "max-vrps" => {
                let v = l.arg(t).and_then(|a| {
                    let n: u32 = l.parse(a, "a number of VRPs (1-4294967295)")?;
                    if n == 0 {
                        l.err(a.pos, "max-vrps must be at least 1");
                        return None;
                    }
                    Some(n)
                });
                self.max_vrps.set(l, t.pos, v);
            }
            "backoff" => {
                let v = l.backoff(t);
                self.backoff.set(l, t.pos, v);
            }
            "tcp-keepalive" => {
                // RFC 8210 §9: routers "SHOULD enable keep-alives".
                let v = l.tcp_keepalive(t);
                self.tcp_keepalive.set(l, t.pos, v);
            }
            _ => l.unknown(t, "`rpki`"),
        }
    }

    fn finish(self, l: &mut Lowerer, pos: Pos) -> Option<Rpki> {
        // Issue #60: where validation data comes from is one setting the
        // operator states, never something implied by what else is there.
        if !self.mode.seen {
            l.err(
                pos,
                "`rpki` needs a `mode` (`disabled`, `external` or `sidecar`)",
            );
        }
        let mode = self.mode.value?;
        // The back-off default follows the mode.
        let d = Rpki::defaults(mode);
        let (backoff_min, backoff_max) =
            self.backoff.value.unwrap_or((d.backoff_min, d.backoff_max));
        // Without a block, `mode sidecar` runs the defaults, and what
        // bgpfcd finds wrong with them points at it.
        let sidecar = self.sidecar.value.unwrap_or_else(|| RpkiSidecar {
            pos: if mode == RpkiMode::Sidecar {
                self.mode_pos
            } else {
                None
            },
            ..d.sidecar
        });
        match mode {
            RpkiMode::External => {
                if self.cache_pos.is_empty() {
                    l.err(pos, "`mode external` needs at least one `cache`");
                }
                // Otherwise the file would list a sidecar that never runs
                // beside the caches that are used.
                if let Some(at) = self.sidecar_pos {
                    l.err(at, "`sidecar` is used with `mode sidecar` only");
                }
            }
            RpkiMode::Sidecar => {
                // The client takes the VRPs from the sidecar alone; a
                // listed cache would never be asked.
                for &at in &self.cache_pos {
                    l.err(
                        at,
                        "`cache` is not used with `mode sidecar`: the RTR client uses the \
                         sidecar's own listener; list caches with `mode external`",
                    );
                }
            }
            // Issue #60: turning validation off is a one-word change, so
            // the block may keep what the other modes use.
            RpkiMode::Disabled => {}
        }
        let rpki = Rpki {
            mode,
            enforcement: self.enforcement.value.unwrap_or(d.enforcement),
            startup: self.startup.value.unwrap_or(d.startup),
            caches: self.caches,
            sidecar,
            version: self.version.value.unwrap_or(d.version),
            connect_timeout: self.connect_timeout.value.unwrap_or(d.connect_timeout),
            response_timeout: self.response_timeout.value.unwrap_or(d.response_timeout),
            reply_timeout: self.reply_timeout.value.unwrap_or(d.reply_timeout),
            max_expire: self.max_expire.value.unwrap_or(d.max_expire),
            max_vrps: self.max_vrps.value.unwrap_or(d.max_vrps),
            backoff_min,
            backoff_max,
            tcp_keepalive: self.tcp_keepalive.value.unwrap_or(d.tcp_keepalive),
        };
        // The client would quietly cut the one to the other; say so instead.
        if rpki.connect_timeout > rpki.response_timeout {
            l.err(
                pos,
                format!(
                    "connect-timeout {}s exceeds response-timeout {}s",
                    rpki.connect_timeout.as_secs(),
                    rpki.response_timeout.as_secs()
                ),
            );
        }
        if rpki.reply_timeout < rpki.response_timeout {
            l.err(
                pos,
                format!(
                    "reply-timeout {}s is below response-timeout {}s",
                    rpki.reply_timeout.as_secs(),
                    rpki.response_timeout.as_secs()
                ),
            );
        }
        Some(rpki)
    }
}

/// The statements of the `sidecar` block of `rpki`, each at most once.
/// The bounds are those of `bgpfc-sidecar`, in whole seconds.
struct SidecarBuilder {
    binary: Once<PathBuf>,
    repository_dir: Once<PathBuf>,
    rtr_listen: Once<SocketAddr>,
    rir_tals: Once<bool>,
    tals: Once<Vec<String>>,
    extra_tals_dir: Once<PathBuf>,
    accept_arin_rpa: Once<bool>,
    refresh: Once<Duration>,
    config_file: Once<PathBuf>,
    global_args: Once<Vec<String>>,
    server_args: Once<Vec<String>>,
    restart_backoff: Once<(Duration, Duration)>,
    stable_after: Once<Duration>,
    stop_timeout: Once<Duration>,
    failure_threshold: Once<u32>,
}

impl SidecarBuilder {
    fn new() -> Self {
        SidecarBuilder {
            binary: Once::new("binary"),
            repository_dir: Once::new("repository-dir"),
            rtr_listen: Once::new("rtr-listen"),
            rir_tals: Once::new("rir-tals"),
            tals: Once::new("tals"),
            extra_tals_dir: Once::new("extra-tals-dir"),
            accept_arin_rpa: Once::new("accept-arin-rpa"),
            refresh: Once::new("refresh"),
            config_file: Once::new("config-file"),
            global_args: Once::new("global-args"),
            server_args: Once::new("server-args"),
            restart_backoff: Once::new("restart-backoff"),
            stable_after: Once::new("stable-after"),
            stop_timeout: Once::new("stop-timeout"),
            failure_threshold: Once::new("failure-threshold"),
        }
    }

    fn statement(&mut self, l: &mut Lowerer, t: &Statement) {
        match t.keyword.as_str() {
            "binary" => {
                // Issue #70: a BGP daemon must not run whatever happens to
                // be called `routinator`.
                let v = l.absolute_path(t, ": bgpfcd never searches PATH (issue #70)");
                self.binary.set(l, t.pos, v);
            }
            "repository-dir" => {
                let v = l.absolute_path(t, "");
                self.repository_dir.set(l, t.pos, v);
            }
            "rtr-listen" => {
                let v = l.rtr_listen(t);
                self.rtr_listen.set(l, t.pos, v);
            }
            "rir-tals" => {
                let v = l.yes_no(t);
                self.rir_tals.set(l, t.pos, v);
            }
            "tals" => {
                let v = l.words(t, "TAL name");
                self.tals.set(l, t.pos, v);
            }
            "extra-tals-dir" => {
                let v = l.absolute_path(t, "");
                self.extra_tals_dir.set(l, t.pos, v);
            }
            "accept-arin-rpa" => {
                let v = l.yes_no(t);
                self.accept_arin_rpa.set(l, t.pos, v);
            }
            "refresh" => {
                // RFC 8210 §6: the cache MUST set the Expire Interval above
                // the Refresh Interval Routinator announces from this, and
                // Routinator's Expire Interval is 7200 s.
                let v = l.secs_up_to(
                    t,
                    RpkiSidecar::MAX_REFRESH,
                    " (RFC 8210 §6: below Routinator's Expire Interval, 7200 seconds)",
                );
                self.refresh.set(l, t.pos, v);
            }
            "config-file" => {
                let v = l.absolute_path(t, "");
                self.config_file.set(l, t.pos, v);
            }
            "global-args" => {
                let v = l.words(t, "argument");
                self.global_args.set(l, t.pos, v);
            }
            "server-args" => {
                let v = l.words(t, "argument");
                self.server_args.set(l, t.pos, v);
            }
            "restart-backoff" => {
                let v = l.restart_backoff(t);
                self.restart_backoff.set(l, t.pos, v);
            }
            "stable-after" => {
                let v = l.secs_up_to(t, RpkiSidecar::MAX_STABLE_AFTER, "");
                self.stable_after.set(l, t.pos, v);
            }
            "stop-timeout" => {
                let v = l.secs_up_to(t, RpkiSidecar::MAX_STOP_TIMEOUT, "");
                self.stop_timeout.set(l, t.pos, v);
            }
            "failure-threshold" => {
                let v = l.arg(t).and_then(|a| {
                    let n: u32 = l.parse(a, "a number of failures (1-4294967295)")?;
                    if n == 0 {
                        l.err(a.pos, "failure-threshold must be at least 1");
                        return None;
                    }
                    Some(n)
                });
                self.failure_threshold.set(l, t.pos, v);
            }
            _ => l.unknown(t, "`sidecar`"),
        }
    }

    /// The block at `pos`, with the defaults for what it leaves out.
    fn finish(self, pos: Pos) -> RpkiSidecar {
        let d = RpkiSidecar::default();
        let (restart_initial, restart_cap) = self
            .restart_backoff
            .value
            .unwrap_or((d.restart_initial, d.restart_cap));
        RpkiSidecar {
            pos: Some(pos),
            binary: self.binary.value.unwrap_or(d.binary),
            repository_dir: self.repository_dir.value.unwrap_or(d.repository_dir),
            rtr_listen: self.rtr_listen.value.unwrap_or(d.rtr_listen),
            rir_tals: self.rir_tals.value.unwrap_or(d.rir_tals),
            tals: self.tals.value.unwrap_or(d.tals),
            extra_tals_dir: self.extra_tals_dir.value.or(d.extra_tals_dir),
            accept_arin_rpa: self.accept_arin_rpa.value.unwrap_or(d.accept_arin_rpa),
            refresh: self.refresh.value.unwrap_or(d.refresh),
            config_file: self.config_file.value.or(d.config_file),
            global_args: self.global_args.value.unwrap_or(d.global_args),
            server_args: self.server_args.value.unwrap_or(d.server_args),
            restart_initial,
            restart_cap,
            stable_after: self.stable_after.value.unwrap_or(d.stable_after),
            stop_timeout: self.stop_timeout.value.unwrap_or(d.stop_timeout),
            failure_threshold: self.failure_threshold.value.unwrap_or(d.failure_threshold),
        }
    }
}

/// The statements of one `neighbor` block, each at most once.
struct NeighborBuilder {
    remote_as: Once<Asn>,
    description: Once<String>,
    port: Once<u16>,
    hold_time: Once<HoldTime>,
    keepalive_time: Once<Duration>,
    connect_retry_time: Once<Duration>,
    send_hold_time: Once<SendHoldTime>,
    families: Once<Vec<AddressFamily>>,
    import: Once<String>,
    export: Once<String>,
    passive: Once<bool>,
    allow_as_set: Once<bool>,
    collision: Once<bool>,
    advertisement_interval: Once<Duration>,
    extended_next_hop: Once<bool>,
    restart_limit: Once<Option<u32>>,
    maximum_prefix: Vec<(AddressFamily, u32)>,
}

impl NeighborBuilder {
    fn new() -> Self {
        NeighborBuilder {
            remote_as: Once::new("remote-as"),
            description: Once::new("description"),
            port: Once::new("port"),
            hold_time: Once::new("hold-time"),
            keepalive_time: Once::new("keepalive-time"),
            connect_retry_time: Once::new("connect-retry-time"),
            send_hold_time: Once::new("send-hold-time"),
            families: Once::new("families"),
            import: Once::new("import"),
            export: Once::new("export"),
            passive: Once::new("passive"),
            allow_as_set: Once::new("allow-as-set"),
            collision: Once::new("collision-detect-established"),
            advertisement_interval: Once::new("advertisement-interval"),
            extended_next_hop: Once::new("extended-next-hop"),
            restart_limit: Once::new("restart-limit"),
            maximum_prefix: Vec::new(),
        }
    }

    fn statement(&mut self, l: &mut Lowerer, t: &Statement) {
        match t.keyword.as_str() {
            "remote-as" => {
                let v = l.arg(t).and_then(|a| l.asn(a));
                self.remote_as.set(l, t.pos, v);
            }
            "description" => {
                let v = l.arg(t).map(|a| a.value.clone());
                self.description.set(l, t.pos, v);
            }
            "port" => {
                let v = l.parse_arg::<u16>(t, "a port number");
                self.port.set(l, t.pos, v);
            }
            "hold-time" => {
                let v = l.arg(t).and_then(|a| {
                    let secs: u16 = l.parse(a, "a number of seconds (0-65535)")?;
                    // RFC 4271 §4.2: 1 and 2 are not acceptable.
                    let h = HoldTime::new(secs);
                    if h.is_none() {
                        l.err(a.pos, "hold-time must be 0 or at least 3 (RFC 4271 §4.2)");
                    }
                    h
                });
                self.hold_time.set(l, t.pos, v);
            }
            "keepalive-time" => {
                let v = l.secs(t);
                self.keepalive_time.set(l, t.pos, v);
            }
            "connect-retry-time" => {
                let v = l.secs(t);
                self.connect_retry_time.set(l, t.pos, v);
            }
            "send-hold-time" => {
                let v = l.arg(t).and_then(|a| {
                    if a.value == "off" {
                        Some(SendHoldTime::Off)
                    } else {
                        l.parse::<u16>(a, "a number of seconds or `off`")
                            .map(SendHoldTime::Seconds)
                    }
                });
                self.send_hold_time.set(l, t.pos, v);
            }
            "families" => {
                let v = l.families(t);
                self.families.set(l, t.pos, v);
            }
            "import" => {
                let v = l.arg(t).map(|a| a.value.clone());
                self.import.set(l, t.pos, v);
            }
            "export" => {
                let v = l.arg(t).map(|a| a.value.clone());
                self.export.set(l, t.pos, v);
            }
            "passive" => {
                let v = l.yes_no(t);
                self.passive.set(l, t.pos, v);
            }
            "allow-as-set" => {
                let v = l.yes_no(t);
                self.allow_as_set.set(l, t.pos, v);
            }
            "collision-detect-established" => {
                let v = l.yes_no(t);
                self.collision.set(l, t.pos, v);
            }
            "advertisement-interval" => {
                // RFC 4271 §10: "MAY allow the other timers to be
                // configurable"; zero turns the RFC 4271 §9.2.1.1 pacing
                // off.
                let v = l
                    .parse_arg::<u16>(t, "a number of seconds (0-65535)")
                    .map(|s| Duration::from_secs(u64::from(s)));
                self.advertisement_interval.set(l, t.pos, v);
            }
            "extended-next-hop" => {
                let v = l.yes_no(t);
                self.extended_next_hop.set(l, t.pos, v);
            }
            "restart-limit" => {
                // RFC 4486 §4: an upper bound on consecutive automatic
                // retries; `off` for none.
                let v = l.arg(t).and_then(|a| {
                    if a.value == "off" {
                        Some(None)
                    } else {
                        l.parse::<u32>(a, "a number of restarts or `off`").map(Some)
                    }
                });
                self.restart_limit.set(l, t.pos, v);
            }
            "maximum-prefix" => self.maximum_prefix(l, t),
            _ => l.unknown(t, "`neighbor`"),
        }
    }

    /// `maximum-prefix FAMILY N`, at most once per family (RFC 4271 §6.7).
    fn maximum_prefix(&mut self, l: &mut Lowerer, t: &Statement) {
        let Some([family, limit]) = l.args(t, 2) else {
            return;
        };
        let family = l.family(family);
        let limit = l.parse::<u32>(limit, "a number of prefixes (1-4294967295)");
        let (Some(family), Some(limit)) = (family, limit) else {
            return;
        };
        if limit == 0 {
            l.err(
                t.pos,
                "maximum-prefix must be at least 1; an import policy rejects routes",
            );
        } else if self.maximum_prefix.iter().any(|(f, _)| *f == family) {
            l.err(
                t.pos,
                format!("`maximum-prefix` is given more than once for {family}"),
            );
        } else {
            self.maximum_prefix.push((family, limit));
        }
    }

    fn finish(self, l: &mut Lowerer, pos: Pos, addr: IpAddr) -> Option<Neighbor> {
        for (present, kw) in [
            (self.remote_as.seen, "remote-as"),
            (self.import.seen, "import"),
            (self.export.seen, "export"),
        ] {
            if !present {
                l.err(pos, format!("neighbor {addr} has no `{kw}`"));
            }
        }
        Some(Neighbor {
            pos,
            addr,
            remote_as: self.remote_as.value?,
            description: self.description.value,
            port: self.port.value.unwrap_or(179),
            // RFC 4271 §10: 90 s suggested.
            hold_time: self
                .hold_time
                .value
                .unwrap_or(HoldTime::new(90).unwrap_or(HoldTime::ZERO)),
            keepalive_time: self.keepalive_time.value,
            connect_retry_time: self
                .connect_retry_time
                .value
                .unwrap_or(Duration::from_secs(120)),
            send_hold_time: self.send_hold_time.value.unwrap_or(SendHoldTime::Default),
            families: self
                .families
                .value
                .unwrap_or_else(|| vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST]),
            import: self.import.value?,
            export: self.export.value?,
            passive: self.passive.value.unwrap_or(false),
            allow_as_set: self.allow_as_set.value.unwrap_or(false),
            collision_detect_established: self.collision.value.unwrap_or(false),
            advertisement_interval: self.advertisement_interval.value,
            // RFC 8950 §4 allows only IPv4 NLRI with an IPv6 next hop, and
            // of those families bgpfc speaks IPv4 unicast.
            extended_next_hop: if self.extended_next_hop.value.unwrap_or(false) {
                vec![AddressFamily::IPV4_UNICAST]
            } else {
                Vec::new()
            },
            restart_limit: self
                .restart_limit
                .value
                .unwrap_or(Some(DEFAULT_RESTART_LIMIT)),
            maximum_prefix: self.maximum_prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hosts_are_addresses_or_host_names() {
        for good in [
            "192.0.2.1",
            "2001:db8::1",
            "::1",
            "localhost",
            "rtr.example.net",
            "rtr.example.net.",
            "rtr-1.example.net",
            "1rtr.example.net",
            "a.b-c.d0",
            &format!("{}.net", "a".repeat(63)),
        ] {
            assert!(is_host(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "rtr..example",
            "-rtr.example",
            "rtr-.example",
            "rtr_1.example",
            "[2001:db8::1]",
            "192.0.2.1:323",
            "fe80::1%eth0",
            // RFC 1123 §2.1: never the dotted-decimal form, which the
            // resolver would read as an address.
            "10.1",
            "192.0.2",
            "300.1.1.1",
            "rtr.example.123",
            &format!("{}.net", "a".repeat(64)),
            &format!("{}a", "a.".repeat(127)),
        ] {
            assert!(!is_host(bad), "{bad}");
        }
    }

    #[test]
    fn a_cache_is_its_address_or_name_and_port() {
        let cache = |host: &str, port, preference| RpkiCache {
            host: host.to_owned(),
            port,
            preference,
        };
        assert!(same_cache(
            &cache("2001:db8::1", 323, 0),
            &cache("2001:0db8:0::1", 323, 7)
        ));
        assert!(same_cache(
            &cache("RTR.Example.net.", 323, 0),
            &cache("rtr.example.net", 323, 0)
        ));
        assert!(!same_cache(
            &cache("rtr.example.net", 323, 0),
            &cache("rtr.example.net", 3323, 0)
        ));
        assert!(!same_cache(
            &cache("192.0.2.1", 323, 0),
            &cache("192.0.2.2", 323, 0)
        ));
    }
}
