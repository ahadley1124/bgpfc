//! The validated configuration: what the daemon runs from.
//!
//! Positions are kept on the items a later validation error may need to
//! point at (neighbors, policies, terms, prefix lists); everything else is
//! plain data so that reload diffing can compare values.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU8;
use std::path::PathBuf;
use std::time::Duration;

use bgpfc_rpki::{Enforcement, RovState, Startup};
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::community::{Community, ExtendedCommunity, LargeCommunity};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};

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
    /// `rpki { ... }`; [`Rpki::implicit`] when there is none.
    pub rpki: Rpki,
    /// `netns`: the file of the network namespace bgpfcd joins at startup,
    /// as [`netns_path`](crate::netns_path) resolves it; `None` runs it in
    /// the namespace it is started in.
    pub netns: Option<PathBuf>,
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

/// How routes get their RFC 6811 origin validation state, and what that
/// state does: the `rpki` block.
///
/// The durations are whole seconds. Every field has its default when the
/// block leaves it out, and the defaults of the RTR client's settings are
/// those of the RTR client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rpki {
    /// `mode`: required in the block.
    pub mode: RpkiMode,
    /// `enforcement`: what a route's validation state does to its use
    /// beyond what policy does with it; [`Rpki::DEFAULT_ENFORCEMENT`]
    /// unless given. RFC 6811 §2 lets a route leave the decision process
    /// for its state only when "explicitly configured to do so": the
    /// documented meaning of `mode external` includes the default, and
    /// with `mode disabled` only a state import policy sets is acted on.
    pub enforcement: Enforcement,
    /// `startup`: what a route not validated yet, `disabled`, does while
    /// validation waits for its first full set of VRPs;
    /// [`Rpki::DEFAULT_STARTUP`] unless given. RFC 6811 §2 lets a route
    /// leave the decision process for its state only when "explicitly
    /// configured to do so": [`Startup::Hold`] is that configuration.
    /// With [`RpkiMode::Disabled`] no data comes, so it holds nothing.
    pub startup: Startup,
    /// `cache` statements in file order: the router's cache list
    /// (RFC 8210 §10). At least one in [`RpkiMode::External`], none in
    /// [`RpkiMode::Sidecar`].
    pub caches: Vec<RpkiCache>,
    /// `sidecar { ... }`: the Routinator bgpfcd runs and supervises, used
    /// in [`RpkiMode::Sidecar`] only. Always present: the defaults where
    /// the block is not written.
    pub sidecar: RpkiSidecar,
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
    /// [`Rpki::default_backoff`] of the mode unless given.
    pub backoff_min: Duration,
    /// The longest reconnect delay.
    pub backoff_max: Duration,
    /// `tcp-keepalive [idle N] [interval N] [count N]`: how the kernel
    /// probes an idle connection to a cache, which bgpfcd sets on every one
    /// (RFC 8210 §9); [`RpkiKeepalive::DEFAULT`] where not given.
    pub tcp_keepalive: RpkiKeepalive,
}

impl Rpki {
    /// The `enforcement` of a file that writes none: Invalid routes are
    /// held and not used (issue #61: "Default policy: drop Invalid"; RFC
    /// 6811 §5: "rejecting all "invalid" routes"). RFC 8481 §5 would
    /// apply none ("Absent specific operator configuration, policy MUST
    /// NOT be applied"); `enforcement off` gives that.
    pub const DEFAULT_ENFORCEMENT: Enforcement = Enforcement::DropInvalid;
    /// The `startup` of a file that writes none: routes not validated yet
    /// are used as received until the first full set validates them. RFC
    /// 6811 §2: no route leaves the decision process for its state
    /// "unless explicitly configured to do so", and holding them would
    /// withdraw the whole table for as long as the cache takes, minutes
    /// with a cold sidecar.
    pub const DEFAULT_STARTUP: Startup = Startup::Accept;
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
    /// The longest reconnect delay that may be configured: the largest
    /// Retry Interval RFC 8210 §6 allows a cache to ask for, "Maximum
    /// allowed value: 7200 seconds".
    pub const MAX_BACKOFF: Duration = Duration::from_hours(2);
    /// The default longest reconnect delay with [`RpkiMode::Sidecar`].
    /// Routinator opens its RTR listener only once its first validation
    /// run has ended, minutes after it starts from a cold cache; with the
    /// 600 s of [`Rpki::DEFAULT_BACKOFF_MAX`] the client could then wait
    /// up to about 15 minutes more, with this cap about 45 s. The cache is
    /// the router's own child on loopback, so the attempts cost a SYN and
    /// a RST each. RFC 8210 §6 asks a router not to retry sooner than the
    /// Retry Interval; the default `backoff` already departs from that.
    pub const SIDECAR_BACKOFF_MAX: Duration = Duration::from_secs(30);

    /// The reconnect back-off, `(MIN, MAX)`, of a block in `mode` that
    /// writes no `backoff`.
    #[must_use]
    pub const fn default_backoff(mode: RpkiMode) -> (Duration, Duration) {
        match mode {
            RpkiMode::Disabled | RpkiMode::External => {
                (Rpki::DEFAULT_BACKOFF_MIN, Rpki::DEFAULT_BACKOFF_MAX)
            }
            RpkiMode::Sidecar => (Rpki::DEFAULT_BACKOFF_MIN, Rpki::SIDECAR_BACKOFF_MAX),
        }
    }

    /// What a block that states only `mode` runs with: every other
    /// setting at its default, the back-off that of the mode.
    #[must_use]
    pub fn defaults(mode: RpkiMode) -> Rpki {
        let (backoff_min, backoff_max) = Rpki::default_backoff(mode);
        Rpki {
            mode,
            enforcement: Rpki::DEFAULT_ENFORCEMENT,
            startup: Rpki::DEFAULT_STARTUP,
            caches: Vec::new(),
            sidecar: RpkiSidecar::default(),
            version: 1,
            connect_timeout: Rpki::DEFAULT_CONNECT_TIMEOUT,
            response_timeout: Rpki::DEFAULT_RESPONSE_TIMEOUT,
            reply_timeout: Rpki::DEFAULT_REPLY_TIMEOUT,
            max_expire: Rpki::MAX_EXPIRE,
            max_vrps: Rpki::DEFAULT_MAX_VRPS,
            backoff_min,
            backoff_max,
            tcp_keepalive: RpkiKeepalive::DEFAULT,
        }
    }

    /// What a file without an `rpki` block runs: the one place that
    /// decides it (issues #60, #72). Validation is off, as with `rpki {
    /// mode disabled; }`, so that a file that never asked for origin
    /// validation needs no validator on the host (issue #26: the daemon
    /// "must work without Routinator present"), and no route leaves route
    /// selection for its state without configuration (RFC 6811 §2).
    /// `rpki { mode sidecar; }` is the one line that turns it on with
    /// Routinator run by bgpfcd. Whether a file without the block should
    /// run the sidecar instead is the maintainer's decision; changing it
    /// here changes it everywhere.
    #[must_use]
    pub fn implicit() -> Rpki {
        Rpki::defaults(RpkiMode::Disabled)
    }
}

impl Rpki {
    /// Whether `other` asks the RTR client and the sidecar for what
    /// `self` does: every setting of the client the same, the same caches
    /// in the same order with the same preferences, each host however it
    /// is spelled (see [`RpkiCache::is_at`]), and the same sidecar
    /// settings (see [`RpkiSidecar::same_as`]). A reload leaves the RTR
    /// client and the sidecar alone unless this is false. Neither the
    /// `enforcement`, the `startup` nor the `tcp-keepalive` is compared.
    #[must_use]
    pub fn same_as(&self, other: &Rpki) -> bool {
        // Destructured, so that a new setting cannot be left out.
        let Rpki {
            mode,
            // Not the client's: what the state does is the RIB's business,
            // and the VRPs, the sessions with the caches and the states
            // they give the routes are the same whatever it is. A change
            // to it alone re-judges the routes; restarting the client for
            // it would reload every cache for nothing.
            enforcement: _,
            // Nor is this: it acts on the routes while the client has no
            // data, which the client neither knows nor changes.
            startup: _,
            // Nor this: bgpfcd sets it on the client's connections, the
            // one in use included, without a new client, which would load
            // every VRP afresh for a socket option.
            tcp_keepalive: _,
            caches,
            sidecar,
            version,
            connect_timeout,
            response_timeout,
            reply_timeout,
            max_expire,
            max_vrps,
            backoff_min,
            backoff_max,
        } = self;
        *mode == other.mode
            && caches.len() == other.caches.len()
            && caches
                .iter()
                .zip(&other.caches)
                .all(|(a, b)| a.preference == b.preference && a.is_at(&b.host, b.port))
            && sidecar.same_as(&other.sidecar)
            && *version == other.version
            && *connect_timeout == other.connect_timeout
            && *response_timeout == other.response_timeout
            && *reply_timeout == other.reply_timeout
            && *max_expire == other.max_expire
            && *max_vrps == other.max_vrps
            && *backoff_min == other.backoff_min
            && *backoff_max == other.backoff_max
    }
}

impl Default for Rpki {
    /// No `rpki` block: [`Rpki::implicit`].
    fn default() -> Rpki {
        Rpki::implicit()
    }
}

/// Where VRPs come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpkiMode {
    /// No origin validation: every route's state is `disabled`.
    Disabled,
    /// VRPs from the configured RTR caches (RFC 8210).
    External,
    /// VRPs from Routinator, which bgpfcd runs and supervises as set by
    /// the `sidecar` block, over RTR on loopback (issues #26, #70-#72).
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

/// The `sidecar` block of `rpki`: Routinator, run and supervised by
/// bgpfcd, serving RTR to bgpfcd's own client on loopback (issues #26,
/// #70-#72). bgpfcd turns it into the settings of the `bgpfc-sidecar`
/// crate, whose defaults and bounds these are, and checks there what is
/// Routinator's business: TAL names, the ARIN agreement, and the options
/// the escape hatches may not carry.
///
/// The durations are whole seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpkiSidecar {
    /// The `sidecar` statement, or the `mode sidecar` statement when there
    /// is no block; `None` when neither is written, as in
    /// [`Rpki::implicit`]. For the errors bgpfcd finds in the block (see
    /// [`parse_str_with`](crate::parse_str_with)). Not compared by
    /// [`RpkiSidecar::same_as`].
    pub pos: Option<Pos>,
    /// `binary`: the Routinator executable, an absolute path; bgpfcd never
    /// searches `PATH` for it (issue #70).
    pub binary: PathBuf,
    /// `repository-dir`: Routinator's cache of RPKI data, an absolute
    /// path.
    pub repository_dir: PathBuf,
    /// `rtr-listen ADDR [port N]`: where Routinator serves RTR, a loopback
    /// address (issue #71; RFC 8210 §9), on a port of
    /// [`RpkiSidecar::MIN_RTR_PORT`] or above, or 0 for one picked when the
    /// sidecar starts.
    pub rtr_listen: SocketAddr,
    /// `rir-tals`: whether the production TALs of the five RIRs are used
    /// (ARIN's only with `accept_arin_rpa`).
    pub rir_tals: bool,
    /// `tals`: further TALs Routinator bundles, by name.
    pub tals: Vec<String>,
    /// `extra-tals-dir`: a directory of more `.tal` files, an absolute
    /// path.
    pub extra_tals_dir: Option<PathBuf>,
    /// `accept-arin-rpa`: whether the operator accepts ARIN's Relying
    /// Party Agreement, without which ARIN's TAL is not used.
    pub accept_arin_rpa: bool,
    /// `refresh`: the time between Routinator's validation runs, which it
    /// also announces as the Refresh Interval (RFC 8210 §6).
    pub refresh: Duration,
    /// `config-file`: a Routinator config file, an absolute path, which
    /// bgpfcd passes on and does not read.
    pub config_file: Option<PathBuf>,
    /// `global-args`: escape hatch (issue #72), options passed verbatim
    /// before Routinator's `server` command.
    pub global_args: Vec<String>,
    /// `server-args`: escape hatch (issue #72), options passed verbatim
    /// after it.
    pub server_args: Vec<String>,
    /// `restart-backoff INITIAL CAP`: the delay before restarting a
    /// Routinator that failed, doubling with each failure in a row up to
    /// the cap.
    pub restart_initial: Duration,
    /// The longest restart delay.
    pub restart_cap: Duration,
    /// `stable-after`: how long Routinator must run before a failure no
    /// longer counts as one in a row.
    pub stable_after: Duration,
    /// `stop-timeout`: how long Routinator may take to stop after
    /// `SIGTERM` before it is killed.
    pub stop_timeout: Duration,
    /// `failure-threshold`: the failures in a row after which the sidecar
    /// is reported as failed.
    pub failure_threshold: u32,
}

impl RpkiSidecar {
    /// The default `binary`, where Routinator's own packages install it.
    pub const DEFAULT_BINARY: &str = "/usr/bin/routinator";
    /// The default `repository-dir`, under the service's state directory
    /// (`contrib/bgpfcd.service`).
    pub const DEFAULT_REPOSITORY_DIR: &str = "/var/lib/bgpfc/rpki";
    /// The default `rtr-listen`: `127.0.0.1`, with a port picked when the
    /// sidecar starts.
    pub const DEFAULT_RTR_LISTEN: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    /// The lowest `rtr-listen` port but 0: Routinator runs without
    /// capabilities, so it cannot bind a port below it on a host that
    /// keeps them privileged.
    pub const MIN_RTR_PORT: u16 = 1024;
    /// The default `refresh`, Routinator's own.
    pub const DEFAULT_REFRESH: Duration = Duration::from_mins(10);
    /// The longest `refresh`: RFC 8210 §6 wants the Expire Interval larger
    /// than the Refresh Interval, and Routinator's is 7200 s.
    pub const MAX_REFRESH: Duration = Duration::from_secs(7_199);
    /// The default first restart delay.
    pub const DEFAULT_RESTART_INITIAL: Duration = Duration::from_secs(1);
    /// The default longest restart delay.
    pub const DEFAULT_RESTART_CAP: Duration = Duration::from_mins(5);
    /// The longest restart delay that may be configured, either bound.
    pub const MAX_RESTART_BACKOFF: Duration = Duration::from_hours(1);
    /// The default `stable-after`.
    pub const DEFAULT_STABLE_AFTER: Duration = Duration::from_mins(5);
    /// The longest `stable-after`.
    pub const MAX_STABLE_AFTER: Duration = Duration::from_hours(24);
    /// The default `stop-timeout`.
    pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);
    /// The longest `stop-timeout`.
    pub const MAX_STOP_TIMEOUT: Duration = Duration::from_hours(1);
    /// The default `failure-threshold`.
    pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;

    /// Whether `other` runs Routinator as `self` does: every setting the
    /// same, wherever the block is. A reload restarts the sidecar only
    /// when this is false.
    #[must_use]
    pub fn same_as(&self, other: &RpkiSidecar) -> bool {
        // Destructured, so that a new setting cannot be left out.
        let RpkiSidecar {
            pos: _,
            binary,
            repository_dir,
            rtr_listen,
            rir_tals,
            tals,
            extra_tals_dir,
            accept_arin_rpa,
            refresh,
            config_file,
            global_args,
            server_args,
            restart_initial,
            restart_cap,
            stable_after,
            stop_timeout,
            failure_threshold,
        } = self;
        *binary == other.binary
            && *repository_dir == other.repository_dir
            && *rtr_listen == other.rtr_listen
            && *rir_tals == other.rir_tals
            && *tals == other.tals
            && *extra_tals_dir == other.extra_tals_dir
            && *accept_arin_rpa == other.accept_arin_rpa
            && *refresh == other.refresh
            && *config_file == other.config_file
            && *global_args == other.global_args
            && *server_args == other.server_args
            && *restart_initial == other.restart_initial
            && *restart_cap == other.restart_cap
            && *stable_after == other.stable_after
            && *stop_timeout == other.stop_timeout
            && *failure_threshold == other.failure_threshold
    }
}

impl Default for RpkiSidecar {
    /// The `DEFAULT_*` settings, with no position.
    fn default() -> RpkiSidecar {
        RpkiSidecar {
            pos: None,
            binary: PathBuf::from(RpkiSidecar::DEFAULT_BINARY),
            repository_dir: PathBuf::from(RpkiSidecar::DEFAULT_REPOSITORY_DIR),
            rtr_listen: RpkiSidecar::DEFAULT_RTR_LISTEN,
            rir_tals: true,
            tals: Vec::new(),
            extra_tals_dir: None,
            accept_arin_rpa: false,
            refresh: RpkiSidecar::DEFAULT_REFRESH,
            config_file: None,
            global_args: Vec::new(),
            server_args: Vec::new(),
            restart_initial: RpkiSidecar::DEFAULT_RESTART_INITIAL,
            restart_cap: RpkiSidecar::DEFAULT_RESTART_CAP,
            stable_after: RpkiSidecar::DEFAULT_STABLE_AFTER,
            stop_timeout: RpkiSidecar::DEFAULT_STOP_TIMEOUT,
            failure_threshold: RpkiSidecar::DEFAULT_FAILURE_THRESHOLD,
        }
    }
}

/// The `tcp-keepalive` statement of `rpki`: how the kernel probes an idle
/// connection to a cache (`tcp(7)`: `TCP_KEEPIDLE`, `TCP_KEEPINTVL`,
/// `TCP_KEEPCNT`), which bgpfcd turns on for every connection, with `mode
/// external` and `mode sidecar` alike. RFC 8210 §9: "To reduce exposure to
/// dropped but non-terminated sessions, both caches and routers SHOULD
/// enable keep-alives when available in the chosen transport protocol."
///
/// In sync, a connection is idle between polls, which come every Refresh
/// Interval, an hour by default (RFC 8210 §6). Without probes, a cache that
/// vanished without closing the connection (a crash, a power loss, a
/// network that drops its packets) is noticed only when the next poll goes
/// unanswered, more than an hour on; meanwhile the client neither moves to
/// another cache (§10) nor hears the cache's Serial Notifies. The host's
/// own default would probe only after two hours of silence (RFC 1122
/// §4.2.3.6). The kernel drops a connection [`RpkiKeepalive::detection_time`]
/// after its last segment, two minutes with the defaults.
///
/// Keep-alive acts only on a connection with nothing in flight. While a
/// query is unanswered, the session's `response-timeout` finds a dead
/// cache instead. Whole seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpkiKeepalive {
    /// `idle`: how long nothing must arrive on the connection before the
    /// first probe (`TCP_KEEPIDLE`).
    pub idle: Duration,
    /// `interval`: how long to wait for an answer to a probe before the
    /// next (`TCP_KEEPINTVL`).
    pub interval: Duration,
    /// `count`: how many probes in a row may go unanswered before the
    /// kernel drops the connection (`TCP_KEEPCNT`).
    pub count: u32,
}

impl RpkiKeepalive {
    /// The `idle` of a file that sets none: what Routinator sets on its
    /// own end of each RTR connection by default (`--rtr-tcp-keepalive
    /// 60`), so both ends start probing after the same minute of silence.
    /// One small exchange a minute per connection costs nothing on the
    /// controlled network RFC 8210 §9 asks for.
    pub const DEFAULT_IDLE: Duration = Duration::from_mins(1);
    /// The `interval` of a file that sets none. With
    /// [`RpkiKeepalive::DEFAULT_COUNT`], the cache is declared gone after a
    /// minute of unanswered probes, so a loss of a few seconds on that
    /// network does not reset a session that would have lived on, and a
    /// reconnect, which costs the cache a Serial Query at least (§8.1),
    /// comes only for a cache that is really gone.
    pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
    /// The `count` of a file that sets none.
    pub const DEFAULT_COUNT: u32 = 6;
    /// What a file that writes no `tcp-keepalive` runs with.
    pub const DEFAULT: RpkiKeepalive = RpkiKeepalive {
        idle: RpkiKeepalive::DEFAULT_IDLE,
        interval: RpkiKeepalive::DEFAULT_INTERVAL,
        count: RpkiKeepalive::DEFAULT_COUNT,
    };
    /// The longest `idle` the kernel takes: `MAX_TCP_KEEPIDLE`, 32767
    /// seconds, in the kernel's `include/net/tcp.h`. It refuses a longer
    /// one, and 0, with `EINVAL`.
    pub const MAX_IDLE: Duration = Duration::from_secs(32_767);
    /// The longest `interval` the kernel takes: `MAX_TCP_KEEPINTVL`, 32767
    /// seconds, in `include/net/tcp.h`.
    pub const MAX_INTERVAL: Duration = Duration::from_secs(32_767);
    /// The most probes the kernel takes: `MAX_TCP_KEEPCNT`, 127, in
    /// `include/net/tcp.h`.
    pub const MAX_COUNT: u32 = 127;

    /// The longest an idle connection to a cache that vanished stays open:
    /// the idle time, then every probe's interval.
    #[must_use]
    pub fn detection_time(&self) -> Duration {
        self.interval
            .saturating_mul(self.count)
            .saturating_add(self.idle)
    }
}

impl Default for RpkiKeepalive {
    /// [`RpkiKeepalive::DEFAULT`].
    fn default() -> RpkiKeepalive {
        RpkiKeepalive::DEFAULT
    }
}

impl std::fmt::Display for RpkiKeepalive {
    /// As the statement writes it: `idle 60 interval 10 count 6`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "idle {} interval {} count {}",
            self.idle.as_secs(),
            self.interval.as_secs(),
            self.count
        )
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
    /// validation state (RFC 6811 §3: "the ability to match and set the
    /// validation state of routes"), as
    /// [`RovState::satisfies`](bgpfc_rpki::RovState::satisfies) reads it:
    /// `not-found` holds for a route not validated (`disabled`) too.
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
    /// `set rpki valid|invalid|not-found`: the validation state the route
    /// is used with from then on in place of the one the lookup gave it
    /// (RFC 6811 §3). Never `disabled`, and only in import policies:
    /// validation rejects a policy that sets it and is some neighbor's
    /// export policy.
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
    /// `multihop`: the TTL (IPv4) or hop limit (IPv6) of every segment
    /// sent to the neighbor, as written, 255 for the bare keyword. `None`
    /// sends an external neighbor TTL 1, so that it must be directly
    /// connected, and an internal one the system's TTL, as FRR and BIRD
    /// do. Only what is sent: the TTL of what arrives is not checked
    /// (that would be GTSM, RFC 5082).
    pub multihop: Option<NonZeroU8>,
    /// `local-address`: the address the session runs from. bgpfcd binds
    /// its own connections to it, and refuses one the neighbor opens to
    /// another of its addresses. `None` lets the kernel choose the source
    /// by route, and accepts a connection on any local address.
    pub local_address: Option<IpAddr>,
}

/// The `restart-limit` of a neighbor that sets none: the same figure as
/// `bgpfc_fsm::DEFAULT_RESTART_LIMIT`, which this crate does not depend on.
pub const DEFAULT_RESTART_LIMIT: u32 = 10;

impl Neighbor {
    /// Whether the session parameters, the ones a change to which needs
    /// the session reset, are the same. Description, policies, the
    /// advertisement interval and the prefix limits are not session
    /// parameters: the interval paces what the RIB sends and the limits
    /// bound what it keeps, and both change without a reset. `multihop`
    /// and `local-address` are: the local address of a connection cannot
    /// change, and one rule serves both.
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
            && self.multihop == other.multihop
            && self.local_address == other.local_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No `rpki` block is `mode disabled` with every default (issues #60,
    /// #72): the file never asked for validation.
    #[test]
    fn the_implicit_rpki_block_is_disabled() {
        let implicit = Rpki::implicit();
        assert_eq!(implicit, Rpki::defaults(RpkiMode::Disabled));
        assert_eq!(Rpki::default(), implicit);
        assert_eq!(implicit.mode, RpkiMode::Disabled);
        assert_eq!(implicit.enforcement, Rpki::DEFAULT_ENFORCEMENT);
        assert_eq!(implicit.startup, Startup::Accept);
        assert_eq!(implicit.caches, []);
        assert_eq!(implicit.sidecar, RpkiSidecar::default());
        assert_eq!(implicit.sidecar.pos, None);
        assert_eq!(
            (implicit.backoff_min, implicit.backoff_max),
            (Rpki::DEFAULT_BACKOFF_MIN, Rpki::DEFAULT_BACKOFF_MAX)
        );
    }

    /// What acts on the routes' states is not the RTR client's business:
    /// a block that differs only there asks the client for the same. Nor
    /// is the keep-alive, which bgpfcd sets on the client's connections.
    #[test]
    fn the_client_is_the_same_whatever_acts_on_the_state() {
        let a = Rpki::defaults(RpkiMode::External);
        let b = Rpki {
            enforcement: Enforcement::Off,
            startup: Startup::Hold,
            tcp_keepalive: RpkiKeepalive {
                count: 3,
                ..RpkiKeepalive::DEFAULT
            },
            ..a.clone()
        };
        assert!(a.same_as(&b));
        assert_ne!(a, b);
        assert!(!a.same_as(&Rpki {
            version: 0,
            ..b.clone()
        }));
    }

    /// The keep-alive's defaults notice a dead cache within two minutes,
    /// and its bounds are the kernel's (`include/net/tcp.h`).
    #[test]
    fn the_keepalive_defaults_and_bounds() {
        let k = Rpki::implicit().tcp_keepalive;
        assert_eq!(k, RpkiKeepalive::DEFAULT);
        assert_eq!(k, RpkiKeepalive::default());
        assert_eq!(
            (k.idle, k.interval, k.count),
            (Duration::from_secs(60), Duration::from_secs(10), 6)
        );
        assert_eq!(k.detection_time(), Duration::from_secs(120));
        assert_eq!(k.to_string(), "idle 60 interval 10 count 6");
        // MAX_TCP_KEEPIDLE, MAX_TCP_KEEPINTVL, MAX_TCP_KEEPCNT.
        assert_eq!(RpkiKeepalive::MAX_IDLE.as_secs(), 32_767);
        assert_eq!(RpkiKeepalive::MAX_INTERVAL.as_secs(), 32_767);
        assert_eq!(RpkiKeepalive::MAX_COUNT, 127);
        let longest = RpkiKeepalive {
            idle: RpkiKeepalive::MAX_IDLE,
            interval: RpkiKeepalive::MAX_INTERVAL,
            count: RpkiKeepalive::MAX_COUNT,
        };
        assert_eq!(longest.detection_time(), Duration::from_secs(32_767 * 128));
    }

    /// The back-off follows the mode; nothing else does.
    #[test]
    fn the_defaults_differ_by_mode_in_the_backoff_only() {
        assert_eq!(
            Rpki::default_backoff(RpkiMode::External),
            (Duration::from_secs(1), Duration::from_secs(600))
        );
        assert_eq!(
            Rpki::default_backoff(RpkiMode::Sidecar),
            (Duration::from_secs(1), Duration::from_secs(30))
        );
        let sidecar = Rpki::defaults(RpkiMode::Sidecar);
        assert_eq!(sidecar.backoff_max, Rpki::SIDECAR_BACKOFF_MAX);
        let external = Rpki::defaults(RpkiMode::External);
        assert_eq!(
            Rpki {
                mode: RpkiMode::External,
                backoff_max: Rpki::DEFAULT_BACKOFF_MAX,
                ..sidecar
            },
            external
        );
    }

    /// Where the block is does not matter; any setting does.
    #[test]
    fn a_sidecar_is_the_same_wherever_it_is_written() {
        let a = RpkiSidecar::default();
        let moved = RpkiSidecar {
            pos: Some(Pos { line: 9, col: 5 }),
            ..a.clone()
        };
        assert!(a.same_as(&moved));
        assert_ne!(a, moved);
        let changed = [
            RpkiSidecar {
                binary: PathBuf::from("/opt/routinator/bin/routinator"),
                ..a.clone()
            },
            RpkiSidecar {
                rtr_listen: "127.0.0.1:3323".parse().unwrap(),
                ..a.clone()
            },
            RpkiSidecar {
                tals: vec!["ripe-pilot".to_owned()],
                ..a.clone()
            },
            RpkiSidecar {
                server_args: vec!["--rtr-tcp-keepalive=30".to_owned()],
                ..a.clone()
            },
            RpkiSidecar {
                failure_threshold: 6,
                ..a.clone()
            },
        ];
        for other in changed {
            assert!(!a.same_as(&other), "{other:?}");
        }
    }
}
