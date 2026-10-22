//! The validated configuration: what the daemon runs from.
//!
//! Positions are kept on the items a later validation error may need to
//! point at (neighbors, policies, terms, prefix lists); everything else is
//! plain data so that reload diffing can compare values.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

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
}

impl Neighbor {
    /// Whether the session parameters, the ones a change to which needs
    /// the session reset, are the same. Description and policies are not
    /// session parameters.
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
    }
}
