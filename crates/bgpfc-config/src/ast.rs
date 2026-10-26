//! The validated configuration: what the daemon runs from.
//!
//! Positions are kept on the items a later validation error may need to
//! point at (neighbors, policies, terms, prefix lists); everything else is
//! plain data so that reload diffing can compare values.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use bgpfc_rpki::{InvalidAction, RovState};
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::community::{Community, ExtendedCommunity, LargeCommunity};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::role::LocalRole;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RestartTime, RouterId};

use crate::error::Pos;

/// A whole configuration file, after validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `router-id`: our BGP Identifier (RFC 4271 §4.2).
    pub router_id: RouterId,
    /// `local-as`: our AS (RFC 4271 §4.2; never 0, RFC 7607 §2).
    pub local_as: Asn,
    /// `log { level ...; }`.
    pub log_level: bgpfc_log::Level,
    /// `listen { ... }` blocks; `[::]:179` when none is given.
    pub listen: Vec<SocketAddr>,
    /// `fib { ... }`.
    pub fib: Fib,
    /// `control { ... }`.
    pub control: Control,
    /// `rpki { ... }`; [`RpkiMode::Disabled`] when there is none.
    pub rpki: Rpki,
    /// `prefix-list NAME { ... }` blocks, in file order.
    pub prefix_lists: Vec<PrefixList>,
    /// `policy NAME { ... }` blocks, in file order.
    pub policies: Vec<Policy>,
    /// `neighbor ADDR { ... }` blocks, in file order.
    pub neighbors: Vec<Neighbor>,
}

impl Config {
    /// The prefix list called `name`.
    #[must_use]
    pub fn prefix_list(&self, name: &str) -> Option<&PrefixList> {
        self.prefix_lists.iter().find(|p| p.name == name)
    }

    /// The policy called `name`.
    #[must_use]
    pub fn policy(&self, name: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.name == name)
    }

    /// The neighbor at `addr`.
    #[must_use]
    pub fn neighbor(&self, addr: IpAddr) -> Option<&Neighbor> {
        self.neighbors.iter().find(|n| n.addr == addr)
    }
}

/// Whether kernel routes are written or only logged (README, "FIB dry-run").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FibMode {
    /// Compute and log every change, write nothing. The default.
    DryRun,
    /// Apply changes to the kernel.
    Install,
}

impl std::fmt::Display for FibMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FibMode::DryRun => "dry-run",
            FibMode::Install => "install",
        })
    }
}

/// The `fib` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fib {
    /// `mode`.
    pub mode: FibMode,
    /// `table`: the rtnetlink table id (`main` is 254, `<linux/rtnetlink.h>`).
    pub table: u32,
    /// `protocol`: the rtnetlink protocol number our routes carry
    /// (`RTPROT_BGP`, 186, by default).
    pub protocol: u8,
}

impl Default for Fib {
    fn default() -> Self {
        Fib {
            mode: FibMode::DryRun,
            table: 254,
            protocol: 186,
        }
    }
}

/// The `control` block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Control {
    /// `socket`: the Unix socket `bgpfcctl` talks to.
    pub socket: Option<PathBuf>,
    /// `http { ... }`, when the HTTP API is enabled.
    pub http: Option<Http>,
}

/// The `control { http { ... } }` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Http {
    /// `listen`: always a loopback address.
    pub listen: SocketAddr,
    /// `writes`: whether write endpoints are enabled.
    pub writes: bool,
    /// `token-file`: when set, every request needs the bearer token.
    pub token_file: Option<PathBuf>,
}

/// How routes get their RFC 6811 origin validation state: the `rpki`
/// block.
///
/// The durations are whole seconds. Every field has its default when the
/// block leaves it out, and the defaults are those of the RTR client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rpki {
    /// `mode`: required in the block.
    pub mode: RpkiMode,
    /// `cache` statements in file order: the router's cache list
    /// (RFC 8210 §10). At least one in [`RpkiMode::External`].
    pub caches: Vec<RpkiCache>,
    /// `version`: the RTR protocol version offered first, 0 or 1
    /// (RFC 8210 §7). Version 1 falls back to 0 for a cache that only
    /// speaks 0; `version 0` is for a cache that mishandles version 1.
    pub version: u8,
    /// `connect-timeout`: the longest a connection attempt may take.
    pub connect_timeout: Duration,
    /// `response-timeout`: the longest the cache may take to start
    /// answering a query, and between two PDUs of an answer.
    pub response_timeout: Duration,
    /// `reply-timeout`: the longest a whole answer may take, from the
    /// query to its End of Data.
    pub reply_timeout: Duration,
    /// `max-expire`: the longest VRPs that cannot be refreshed are kept.
    /// The cache's Expire Interval applies when it is shorter (RFC 8210
    /// §6), so this can only shorten it; between [`Rpki::MIN_EXPIRE`] and
    /// [`Rpki::MAX_EXPIRE`].
    pub max_expire: Duration,
    /// `max-vrps`: the most VRPs an answer may leave the router holding.
    pub max_vrps: u32,
    /// `backoff MIN MAX`: the delay before the first reconnect after a
    /// failure, doubling with each failure in a row up to the second.
    pub backoff_min: Duration,
    /// The longest reconnect delay.
    pub backoff_max: Duration,
    /// `invalid`: what the RIB does with a route whose state is Invalid,
    /// before the policies an operator wrote (RFC 6811 §5). Required in
    /// [`RpkiMode::External`]: RFC 8481 §5, "Absent specific operator
    /// configuration, policy MUST NOT be applied", so no action is taken
    /// that the operator did not name. [`InvalidAction::Policy`], which
    /// does nothing of its own, where the block leaves it out.
    pub invalid: InvalidAction,
    /// `routinator { ... }`: the Routinator bgpfcd runs and supervises as
    /// its cache. Required in [`RpkiMode::Sidecar`]; in
    /// [`RpkiMode::Disabled`] it is kept and not used, like the cache
    /// list.
    pub routinator: Option<Routinator>,
}

impl Rpki {
    /// The rpki-rtr port (RFC 8210 §9, RFC 6810 §7).
    pub const DEFAULT_PORT: u16 = 323;
    /// The default `connect-timeout`.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    /// The default `response-timeout`.
    pub const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_mins(1);
    /// The default `reply-timeout`.
    pub const DEFAULT_REPLY_TIMEOUT: Duration = Duration::from_mins(30);
    /// The shortest `max-expire`: RFC 8210 §6, Expire Interval, "Minimum
    /// allowed value: 600 seconds".
    pub const MIN_EXPIRE: Duration = Duration::from_mins(10);
    /// The longest `max-expire`, and the default, which leaves the cache's
    /// Expire Interval alone: RFC 8210 §6, "Maximum allowed value: 172800
    /// seconds".
    pub const MAX_EXPIRE: Duration = Duration::from_hours(48);
    /// The default `max-vrps`.
    pub const DEFAULT_MAX_VRPS: u32 = 4_000_000;
    /// The default first reconnect delay.
    pub const DEFAULT_BACKOFF_MIN: Duration = Duration::from_secs(1);
    /// The default longest reconnect delay: the default Retry Interval of
    /// RFC 8210 §6.
    pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_mins(10);
    /// The default longest reconnect delay with [`RpkiMode::Sidecar`].
    /// The cache is a process on this host that binds its RTR port only
    /// after its first validation run, which takes minutes on an empty
    /// repository, and the default for a remote cache would leave bgpfcd
    /// waiting up to ten minutes after it is ready. Trying a loopback port
    /// costs nothing.
    pub const DEFAULT_SIDECAR_BACKOFF_MAX: Duration = Duration::from_secs(30);
    /// The longest reconnect delay that may be configured: the largest
    /// Retry Interval RFC 8210 §6 allows a cache to ask for, "Maximum
    /// allowed value: 7200 seconds".
    pub const MAX_BACKOFF: Duration = Duration::from_hours(2);
}

impl Rpki {
    /// Whether `other` asks the RTR client for what `self` does: every
    /// setting the same, and the same caches in the same order with the
    /// same preferences, each host however it is spelled (see
    /// [`RpkiCache::is_at`]). A reload leaves the RTR client alone unless
    /// this is false. What the RIB does with Invalid routes
    /// ([`Rpki::invalid`]) is no concern of the client: it changes with
    /// the client running, and has its own change in a reload.
    #[must_use]
    pub fn same_as(&self, other: &Rpki) -> bool {
        // Destructured, so that a new setting cannot be left out.
        let Rpki {
            mode,
            caches,
            version,
            connect_timeout,
            response_timeout,
            reply_timeout,
            max_expire,
            max_vrps,
            backoff_min,
            backoff_max,
            routinator,
            invalid: _,
        } = self;
        *mode == other.mode
            && caches.len() == other.caches.len()
            && caches
                .iter()
                .zip(&other.caches)
                .all(|(a, b)| a.preference == b.preference && a.is_at(&b.host, b.port))
            && *version == other.version
            && *connect_timeout == other.connect_timeout
            && *response_timeout == other.response_timeout
            && *reply_timeout == other.reply_timeout
            && *max_expire == other.max_expire
            && *max_vrps == other.max_vrps
            && *backoff_min == other.backoff_min
            && *backoff_max == other.backoff_max
            && *routinator == other.routinator
    }

    /// The `routinator` block when it is the source of the VRPs, which is
    /// `mode sidecar`. A reload leaves the running sidecar alone unless
    /// this differs between the old block and the new.
    #[must_use]
    pub fn sidecar(&self) -> Option<&Routinator> {
        match self.mode {
            RpkiMode::Sidecar => self.routinator.as_ref(),
            RpkiMode::Disabled | RpkiMode::External => None,
        }
    }
}

impl Default for Rpki {
    /// No `rpki` block: disabled.
    fn default() -> Rpki {
        Rpki {
            mode: RpkiMode::Disabled,
            caches: Vec::new(),
            version: 1,
            connect_timeout: Rpki::DEFAULT_CONNECT_TIMEOUT,
            response_timeout: Rpki::DEFAULT_RESPONSE_TIMEOUT,
            reply_timeout: Rpki::DEFAULT_REPLY_TIMEOUT,
            max_expire: Rpki::MAX_EXPIRE,
            max_vrps: Rpki::DEFAULT_MAX_VRPS,
            backoff_min: Rpki::DEFAULT_BACKOFF_MIN,
            backoff_max: Rpki::DEFAULT_BACKOFF_MAX,
            invalid: InvalidAction::Policy,
            routinator: None,
        }
    }
}

/// Where VRPs come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpkiMode {
    /// No origin validation: every route's state is `disabled`.
    Disabled,
    /// VRPs from the configured RTR caches (RFC 8210).
    External,
    /// VRPs from a Routinator that bgpfcd runs and supervises as a child
    /// process and reads over RTR on the loopback (RFC 8210).
    Sidecar,
}

impl std::fmt::Display for RpkiMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RpkiMode::Disabled => "disabled",
            RpkiMode::External => "external",
            RpkiMode::Sidecar => "sidecar",
        })
    }
}

/// A `cache` statement: one entry of the router's cache list (RFC 8210
/// §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpkiCache {
    /// "The IP address or fully qualified domain name of the cache", as
    /// written.
    pub host: String,
    /// `port`: [`Rpki::DEFAULT_PORT`] unless given.
    pub port: u16,
    /// `preference`: "the lower the value, the more preferred"; 0 unless
    /// given.
    pub preference: u32,
}

impl RpkiCache {
    /// Whether `host` on `port` names this cache: the same port, and the
    /// same address however it is written (`2001:db8::1`,
    /// `2001:0db8::1`), or the same name in any case, with or without its
    /// final dot (RFC 4343 §3: a name lookup matches ASCII letters without
    /// regard to case). Two `cache` statements for one cache are an
    /// error, a reload that only respells a cache leaves the RTR client
    /// alone, and the control plane finds the cache the client uses by it.
    #[must_use]
    pub fn is_at(&self, host: &str, port: u16) -> bool {
        self.port == port && host_key(&self.host) == host_key(host)
    }
}

/// What tells hosts apart: an address in its canonical text form, or a
/// name in lower case without its final dot.
fn host_key(host: &str) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase(),
    }
}

impl std::fmt::Display for RpkiCache {
    /// `host:port`, with an IPv6 address in brackets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// The `routinator { ... }` block of `mode sidecar`: the Routinator
/// (an RPKI relying party) that bgpfcd runs as a child process,
/// restarts when it fails, and reads its VRPs from over RTR on the
/// loopback.
///
/// The settings are those of `bgpfc-sidecar`'s `SidecarConfig`, which
/// this crate cannot name: the sidecar crate reaches the operating system
/// (AGENTS.md §2) and this one must not. The daemon converts one into the
/// other, and a test there keeps the defaults the same. What is checked
/// here is what one statement shows, with its position: an absolute path,
/// a loopback address, a number in range. The rest (a TAL name Routinator
/// does not bundle, an extra argument bgpfcd reserves) the sidecar crate
/// checks when the daemon converts the block, also for `bgpfcd --check`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Routinator {
    /// `binary`: the Routinator executable. Absolute, and never looked up
    /// on `PATH`: a BGP daemon must not run whatever happens to be called
    /// `routinator`.
    pub binary: PathBuf,
    /// `repository-dir`: Routinator's cache of RPKI data. Absolute, and
    /// writable by the user the daemon runs as.
    pub repository_dir: PathBuf,
    /// `rtr-listen`: where Routinator serves RTR and where bgpfcd's RTR
    /// client connects. A loopback address (RFC 8210 §9: unprotected TCP
    /// only between a cache and a router on a trusted, controlled
    /// network; the loopback is the one network nothing else can reach).
    /// Port 0, the default, has the daemon pick a free port when it
    /// starts the sidecar.
    pub rtr_listen: SocketAddr,
    /// `rir-tals`: use the TALs of the five Regional Internet Registries
    /// that Routinator bundles, ARIN's only with
    /// [`accept_arin_rpa`](Self::accept_arin_rpa).
    pub rir_tals: bool,
    /// `tal` statements: further bundled TALs by name, such as
    /// `ripe-pilot`; with `rir-tals no`, naming RIR TALs selects some of
    /// them.
    pub tals: Vec<String>,
    /// `tal-dir`: a directory of `*.tal` files (RFC 8630) used as well.
    /// Absolute.
    pub tal_dir: Option<PathBuf>,
    /// `accept-arin-rpa`: that the operator accepts ARIN's Relying Party
    /// Agreement, the terms under which ARIN publishes its TAL. Without
    /// it the ARIN TAL is left out and routes in ARIN's address space
    /// validate as `not-found`.
    pub accept_arin_rpa: bool,
    /// `refresh`: seconds between Routinator's validation runs, and the
    /// Refresh Interval it announces to RTR clients (RFC 8210 §6); 1 to
    /// [`Routinator::MAX_REFRESH`] seconds.
    pub refresh: Duration,
    /// `config-file`: a Routinator configuration file for what bgpfcd
    /// does not model. Absolute.
    pub config_file: Option<PathBuf>,
    /// `global-arg` statements: options for Routinator before its
    /// `server` command, verbatim.
    pub global_args: Vec<String>,
    /// `server-arg` statements: options for Routinator after its `server`
    /// command, verbatim.
    pub server_args: Vec<String>,
    /// `restart-backoff INITIAL CAP`: the delay before the first restart
    /// of a Routinator that failed, doubling with each failure in a row up
    /// to the second.
    pub restart_backoff_initial: Duration,
    /// The longest restart delay.
    pub restart_backoff_cap: Duration,
    /// `stable-after`: how long Routinator must stay up for its next
    /// failure to count as the first of a series again.
    pub stable_after: Duration,
    /// `stop-timeout`: how long Routinator may take to stop after
    /// `SIGTERM` before it gets `SIGKILL`.
    pub stop_timeout: Duration,
    /// `failure-threshold`: how many failures in a row raise the `failed`
    /// state, an alarm that stays while the restarts keep failing.
    pub failure_threshold: u32,
}

impl Routinator {
    /// The default `refresh`: Routinator's own.
    pub const DEFAULT_REFRESH: Duration = Duration::from_mins(10);
    /// The longest `refresh`. RFC 8210 §6 allows a Refresh Interval up to
    /// 86400 seconds but requires the Expire Interval to be larger, and
    /// Routinator's is 7200 seconds unless its configuration says otherwise.
    pub const MAX_REFRESH: Duration = Duration::from_secs(7199);
    /// The default first restart delay.
    pub const DEFAULT_RESTART_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
    /// The default longest restart delay.
    pub const DEFAULT_RESTART_BACKOFF_CAP: Duration = Duration::from_mins(5);
    /// The longest restart delay and stop timeout that may be configured:
    /// a validator retried less often than hourly, or stopped more slowly,
    /// is not supervised in any useful sense.
    pub const MAX_DELAY: Duration = Duration::from_hours(1);
    /// The default `stable-after`.
    pub const DEFAULT_STABLE_AFTER: Duration = Duration::from_mins(5);
    /// The longest `stable-after`.
    pub const MAX_STABLE_AFTER: Duration = Duration::from_hours(24);
    /// The default `stop-timeout`.
    pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);
    /// The default `failure-threshold`.
    pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;

    /// A block with the two statements it needs and every default for the
    /// rest: RTR on `127.0.0.1` with a port picked at start, the RIR TALs
    /// without ARIN's, a ten minute refresh, no configuration file or
    /// extra arguments.
    #[must_use]
    pub fn new(binary: impl Into<PathBuf>, repository_dir: impl Into<PathBuf>) -> Routinator {
        Routinator {
            binary: binary.into(),
            repository_dir: repository_dir.into(),
            rtr_listen: SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            rir_tals: true,
            tals: Vec::new(),
            tal_dir: None,
            accept_arin_rpa: false,
            refresh: Self::DEFAULT_REFRESH,
            config_file: None,
            global_args: Vec::new(),
            server_args: Vec::new(),
            restart_backoff_initial: Self::DEFAULT_RESTART_BACKOFF_INITIAL,
            restart_backoff_cap: Self::DEFAULT_RESTART_BACKOFF_CAP,
            stable_after: Self::DEFAULT_STABLE_AFTER,
            stop_timeout: Self::DEFAULT_STOP_TIMEOUT,
            failure_threshold: Self::DEFAULT_FAILURE_THRESHOLD,
        }
    }
}

/// A prefix with optional length bounds, as in a prefix list or a
/// `match prefix` clause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixEntry {
    /// The prefix.
    pub prefix: Prefix,
    /// `ge N`: matched prefixes are at least this long. Without it, exactly
    /// the prefix's own length (unless `le` is given).
    pub ge: Option<u8>,
    /// `le N`: matched prefixes are at most this long.
    pub le: Option<u8>,
}

/// A named list of prefixes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixList {
    /// Where it is defined.
    pub pos: Pos,
    /// Its name.
    pub name: String,
    /// Its entries, in file order.
    pub entries: Vec<PrefixEntry>,
}

/// A named, ordered list of terms (AGENTS.md §3, "Policy").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Where it is defined.
    pub pos: Pos,
    /// Its name.
    pub name: String,
    /// Its terms, in file order.
    pub terms: Vec<Term>,
}

/// One term: every match clause must hold, then the set actions apply,
/// then the action decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    /// Where it is defined.
    pub pos: Pos,
    /// Its name.
    pub name: String,
    /// `match` clauses, all of which must hold.
    pub matches: Vec<Match>,
    /// `set` actions, applied in order when the term matches.
    pub sets: Vec<SetAction>,
    /// What happens when the term matches.
    pub action: Action,
}

/// A `match` clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match {
    /// `match prefix P [ge N] [le N]`.
    Prefix(PrefixEntry),
    /// `match prefix-list NAME`.
    PrefixList(String),
    /// `match as-path "REGEX"`: an AS-path regular expression over ASN
    /// tokens, compiled by the policy engine.
    AsPath(String),
    /// `match community C`.
    Community(Community),
    /// `match ext-community C`.
    ExtCommunity(ExtendedCommunity),
    /// `match large-community C`.
    LargeCommunity(LargeCommunity),
    /// `match origin igp|egp|incomplete`.
    Origin(Origin),
    /// `match neighbor ADDR`.
    Neighbor(IpAddr),
    /// `match rpki valid|invalid|not-found|disabled`: the route's origin
    /// validation state (RFC 6811 §3).
    Rpki(RovState),
}

/// How a `set ... community` action changes the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommunityOp {
    /// Add the listed values.
    Add,
    /// Remove the listed values.
    Remove,
    /// Replace the whole attribute with the listed values.
    Replace,
}

/// A `set` action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetAction {
    /// `set local-pref N`.
    LocalPref(u32),
    /// `set med N`.
    Med(u32),
    /// `set community add|remove|replace C...`.
    Community(CommunityOp, Vec<Community>),
    /// `set ext-community add|remove|replace C...`.
    ExtCommunity(CommunityOp, Vec<ExtendedCommunity>),
    /// `set large-community add|remove|replace C...`.
    LargeCommunity(CommunityOp, Vec<LargeCommunity>),
    /// `set as-path prepend ASN...`.
    AsPathPrepend(Vec<Asn>),
    /// `set next-hop self`.
    NextHopSelf,
    /// `set rpki valid|invalid|not-found|disabled`: the route's origin
    /// validation state from here on (RFC 6811 §3).
    Rpki(RovState),
}

/// How a term ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Accept the route; no further terms run.
    Accept,
    /// Reject the route; no further terms run.
    Reject,
    /// Keep the set actions and continue with the next term.
    Next,
}

/// `send-hold-time` (RFC 9687 §4.4, §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendHoldTime {
    /// The RFC 9687 §6 recommendation: max(8 minutes, 2 × Hold Time).
    Default,
    /// `send-hold-time off`.
    Off,
    /// `send-hold-time N` seconds; validation requires it to exceed the
    /// Hold Time.
    Seconds(u16),
}

/// What `add-path send` sends for a family (RFC 7911 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddPathSend {
    /// `add-path send FAMILY N`: the N best paths of each prefix by the
    /// decision process, among those export policy accepts.
    Best(u32),
    /// `add-path send FAMILY all`: every path export policy accepts.
    All,
}

/// `graceful-restart yes` and what goes with it (RFC 4724, RFC 8538).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GracefulRestart {
    /// `restart-time`: the Restart Time we advertise (RFC 4724 §3), the
    /// time the neighbor allows our session to come back in after a
    /// restart, and, after our own restart, the time we wait for the
    /// neighbors' End-of-RIB before the routes not learned again are
    /// removed (RFC 4724 §4.1). [`DEFAULT_RESTART_TIME`] when not given.
    pub restart_time: RestartTime,
    /// `stale-time`: the longest the stale routes of a neighbor that
    /// restarted are kept once its session is back, waiting for its
    /// End-of-RIB (RFC 4724 §4.2, RFC 8538 §4.1).
    /// [`DEFAULT_STALE_TIME`] seconds when not given.
    pub stale_time: Duration,
}

/// The `restart-time` of a neighbor that sets none, in seconds: 120.
///
/// NOTE(interop): RFC 4724 §4 only suggests "a value less than or equal to
/// the HOLDTIME carried in the OPEN". BIRD (`graceful restart time`) and FRR
/// (`bgp graceful-restart restart-time`) both default to 120 whatever the
/// Hold Time, and bgpfcd does too.
pub const DEFAULT_RESTART_TIME: u16 = 120;

/// The `stale-time` of a neighbor that sets none, in seconds: 360.
///
/// NOTE(interop): RFC 8538 §4.1 requires a stale timer and suggests 180
/// seconds; FRR (`bgp graceful-restart stalepath-time`) defaults to 360, and
/// bgpfcd follows it. BIRD's closest knob, `graceful restart wait`, defaults
/// to 240.
pub const DEFAULT_STALE_TIME: u16 = 360;

/// `enhanced-refresh yes` (the default) and what goes with it (RFC 7313).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnhancedRefresh {
    /// `refresh-stale-time`: the longest the routes of a neighbor that
    /// began a route refresh stay stale while its end is awaited (RFC 7313
    /// §4: "an implementation MAY impose a locally configurable upper
    /// bound on how long it would retain any stale routes").
    /// [`DEFAULT_REFRESH_STALE_TIME`] seconds when not given.
    pub stale_time: Duration,
}

/// The `refresh-stale-time` of a neighbor that sets none, in seconds: 360.
///
/// NOTE(interop): RFC 7313 §4 names no value. FRR bounds the wait for an
/// `EoRR` with its `bgp graceful-restart stalepath-time`, 360 seconds by
/// default, and bgpfcd follows it. BIRD has no setting for it.
pub const DEFAULT_REFRESH_STALE_TIME: u16 = 360;

/// A `neighbor` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    /// Where it is defined.
    pub pos: Pos,
    /// Its address.
    pub addr: IpAddr,
    /// `remote-as`.
    pub remote_as: Asn,
    /// `description`.
    pub description: Option<String>,
    /// `port`: TCP port to connect to (179 by default).
    pub port: u16,
    /// `hold-time` (RFC 4271 §4.2, §10: 90 s by default).
    pub hold_time: HoldTime,
    /// `keepalive-time`; `None` is one third of the Hold Time (RFC 4271 §10).
    pub keepalive_time: Option<Duration>,
    /// `connect-retry-time` (RFC 4271 §10: 120 s by default).
    pub connect_retry_time: Duration,
    /// `send-hold-time`.
    pub send_hold_time: SendHoldTime,
    /// `families`: IPv4 unicast and IPv6 unicast by default.
    pub families: Vec<AddressFamily>,
    /// `import`: the policy applied to routes received.
    pub import: String,
    /// `export`: the policy applied to routes sent.
    pub export: String,
    /// `passive`: never initiate the TCP connection.
    pub passive: bool,
    /// `allow-as-set`: accept `AS_SET` in UPDATEs (RFC 9774 §3 override).
    pub allow_as_set: bool,
    /// `collision-detect-established` (RFC 4271 §6.8, §8.1.1).
    pub collision_detect_established: bool,
    /// `advertisement-interval`: the `MinRouteAdvertisementIntervalTimer`
    /// (RFC 4271 §9.2.1.1), zero for none. `None` takes the RFC 4271 §10
    /// default for the session type once it is known: 30 s external, 5 s
    /// internal.
    pub advertisement_interval: Option<Duration>,
    /// `extended-next-hop`: the families listed in the Extended Next Hop
    /// Encoding capability with an IPv6 next hop (RFC 8950 §4).
    /// `extended-next-hop yes` gives IPv4 unicast, the one family RFC 8950
    /// covers that bgpfc speaks; empty by default.
    pub extended_next_hop: Vec<AddressFamily>,
    /// `restart-limit`: how many automatic restarts in a row after damped
    /// failures before the peer stays Idle until a manual start
    /// (RFC 4486 §4); `None` for `off`, no bound.
    /// [`DEFAULT_RESTART_LIMIT`] when not given.
    pub restart_limit: Option<u32>,
    /// `maximum-prefix FAMILY N`: the upper bound on the routes of the
    /// family accepted from the neighbor (RFC 4271 §6.7), in file order;
    /// exceeding it ends the session with Cease / Maximum Number of
    /// Prefixes Reached (RFC 4486 §4). Empty by default: no limit.
    pub maximum_prefix: Vec<(AddressFamily, u32)>,
    /// `add-path receive FAMILY yes`: the families to accept several paths
    /// per prefix for (RFC 7911 §4, §5), in file order. Empty by default.
    pub add_path_receive: Vec<AddressFamily>,
    /// `add-path send FAMILY N | all`: the families to send several paths
    /// per prefix for, and how many (RFC 7911 §5), in file order. Empty by
    /// default: one path per prefix.
    pub add_path_send: Vec<(AddressFamily, AddPathSend)>,
    /// `graceful-restart yes`, with `restart-time` and `stale-time`: the
    /// Graceful Restart capability is advertised, End-of-RIB follows the
    /// initial update, and the neighbor's routes are kept as stale when its
    /// session ends the way RFC 4724 §4.2 and RFC 8538 §4 describe. `None`,
    /// the default, advertises nothing and keeps RFC 4271's rules.
    pub graceful_restart: Option<GracefulRestart>,
    /// `enhanced-refresh`, with `refresh-stale-time`: the Enhanced Route
    /// Refresh capability is advertised, and where the neighbor advertised
    /// it too a route refresh is bracketed by `BoRR` and `EoRR` and the routes
    /// a neighbor does not send again in one are purged (RFC 7313 §3.1,
    /// §4). On by default, as RFC 7313 §4 has a speaker that supports it
    /// advertise it; `None` for `enhanced-refresh no`, which keeps RFC 2918's
    /// rules.
    pub enhanced_refresh: Option<EnhancedRefresh>,
    /// `role` and `role-strict`: our BGP Role on the session (RFC 9234
    /// §4), with strict mode (§4.2) if asked for. `None` by default: no
    /// Role is advertised and the Only to Customer procedures (§5) do not
    /// apply. Validation allows it only on an external session.
    pub role: Option<LocalRole>,
}

/// The `restart-limit` of a neighbor that sets none: the same figure as
/// `bgpfc_fsm::DEFAULT_RESTART_LIMIT`, which this crate does not depend on.
pub const DEFAULT_RESTART_LIMIT: u32 = 10;

impl Neighbor {
    /// Whether the session parameters, the ones a change to which needs
    /// the session reset, are the same. Description, policies, the
    /// advertisement interval, the prefix limits and how many paths
    /// `add-path send` sends are not session parameters: the interval
    /// paces what the RIB sends, the limits bound what it keeps and the
    /// paths sent are what it sends, and all change without a reset. The
    /// families `add-path` is on for are: the capability says so in the
    /// OPEN (RFC 7911 §4).
    #[must_use]
    pub fn same_session(&self, other: &Neighbor) -> bool {
        self.addr == other.addr
            && self.remote_as == other.remote_as
            && self.port == other.port
            && self.hold_time == other.hold_time
            && self.keepalive_time == other.keepalive_time
            && self.connect_retry_time == other.connect_retry_time
            && self.send_hold_time == other.send_hold_time
            && self.families == other.families
            && self.passive == other.passive
            && self.allow_as_set == other.allow_as_set
            && self.collision_detect_established == other.collision_detect_established
            && self.extended_next_hop == other.extended_next_hop
            && self.restart_limit == other.restart_limit
            && self.add_path_receive == other.add_path_receive
            // RFC 4724 §3: the capability is in the OPEN with the Restart
            // Time, and the stale time is read when a session comes up.
            && self.graceful_restart == other.graceful_restart
            // RFC 7313 §3.1: the capability is in the OPEN, and the stale
            // time is read when a session comes up.
            && self.enhanced_refresh == other.enhanced_refresh
            && self
                .add_path_send
                .iter()
                .map(|(family, _)| family)
                .eq(other.add_path_send.iter().map(|(family, _)| family))
            // RFC 9234 §4.1: the Role is in the OPEN, and the OTC
            // procedures of §5 follow it for routes already held.
            && self.role == other.role
    }
}
