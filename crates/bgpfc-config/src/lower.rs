//! Give the generic statements meaning: keywords, argument counts, value
//! syntax, required and duplicate statements. Everything that needs only
//! one statement is checked here; cross-references between items are
//! [`validate`](crate::validate)'s job.
//!
//! Implements: RFC 4271 §4.2 (Hold Time 0 or ≥ 3; non-zero BGP
//! Identifier), §10 (defaults); RFC 7607 §2 (AS 0 is never configurable);
//! RFC 9687 §4.4 (`send-hold-time`).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use bgpfc_wire::attribute::Origin;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};

use crate::ast::{
    Action, CommunityOp, Config, Control, Fib, FibMode, Http, Match, Neighbor, Policy, PrefixEntry,
    PrefixList, SendHoldTime, SetAction, Term,
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
            let fam = match a.value.as_str() {
                "ipv4-unicast" => AddressFamily::IPV4_UNICAST,
                "ipv6-unicast" => AddressFamily::IPV6_UNICAST,
                _ => {
                    self.err(
                        a.pos,
                        format!("`{}` is not `ipv4-unicast` or `ipv6-unicast`", a.value),
                    );
                    return None;
                }
            };
            if out.contains(&fam) {
                self.err(a.pos, format!("family `{}` is listed twice", a.value));
                return None;
            }
            out.push(fam);
        }
        Some(out)
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
            _ => l.unknown(t, "`neighbor`"),
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
        })
    }
}
