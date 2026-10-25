//! Route origin validation in `bgpfcd` (RFC 6811) with VRPs over RTR
//! (RFC 8210) from `StayRTR`, an independent RTR cache, for routes from
//! BIRD 2 (AGENTS.md §5, `interop/` row). Most scenarios test the RTR
//! transport and the states it gives the routes, so their `rpki` blocks
//! say `enforcement off;` (RFC 8481 §5, "Set State, Don't Act"): every
//! route is accepted and relayed whatever its state, and the state moves
//! nothing but itself. The others test what acts on the state (RFC 6811
//! §5): the default, `drop-invalid`, which holds the Invalid routes back
//! from the decision process, the relay and the kernel (issues #61, #59).
//!
//! One scenario serves the VRPs from this crate's `rtr-stub` instead: a
//! cache that restarts and brings `bgpfcd` back in sync, which `StayRTR`
//! 0.5.1 does only when its Error Report wins a race with its own close
//! (see `a_restarted_cache_brings_bgpfcd_back_in_sync`).
//! Another lists a cache whose address swallows every packet, so that a
//! connection attempt to it hangs until its timeout.
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird`, `birdc`,
//! `curl` and `stayrtr` on `PATH`, and a built `bgpfcd`. CI runs them with
//! `--include-ignored` under sudo.

use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, Lab, NeighborOpts, RtrStub, StayRtr, start_bgpfcd, wait_for,
};

const BGPFC_AS: u32 = 65_000;
const BIRD_AS: u32 = 65_001;
/// The AS of the second BIRD, which bgpfcd relays the routes to.
const RELAY_AS: u32 = 65_002;
const ESTABLISH: Duration = Duration::from_secs(40);
/// How long a new VRP file may take to reach the routes: `StayRTR` reads
/// it every second, then sends a Serial Notify.
const CHANGE: Duration = Duration::from_secs(20);
/// How long bgpfcd may take to notice that a cache went away or came
/// back: it tries again after `backoff 1 1`, one to one and a half
/// seconds.
const RECONNECT: Duration = Duration::from_secs(10);
/// The caches: RFC 8210 §9, unprotected TCP, so they run on the router's
/// own loopback.
const CACHES: [&str; 2] = ["127.0.0.1:3323", "127.0.0.1:3324"];
/// bgpfcd's HTTP API, inside its namespace.
const HTTP: &str = "127.0.0.1:8179";

/// The routes BIRD originates, in the order the states below list them.
const ROUTES: [&str; 4] = [
    "192.0.2.0/24",
    "192.0.2.128/25",
    "198.51.100.0/24",
    "203.0.113.0/24",
];

/// The VRPs most scenarios serve: (prefix, max length, origin AS).
const FIRST: [(&str, u8, u32); 2] = [
    ("192.0.2.0/24", 24, BIRD_AS),
    ("198.51.100.0/24", 24, 64_999),
];

/// What RFC 6811 §2 makes of BIRD's routes with [`FIRST`]: Matched;
/// Covered, but longer than the VRP's max length (RFC 9319 §3); Covered
/// for another origin AS; not Covered.
const VALIDATED: [(&str, &str); 4] = [
    ("192.0.2.0/24", "valid"),
    ("192.0.2.128/25", "invalid"),
    ("198.51.100.0/24", "invalid"),
    ("203.0.113.0/24", "not-found"),
];

/// VRPs that change the state of every route: 192.0.2.0/24 now for
/// another AS, the /25 authorised, 198.51.100.0/24 gone, 203.0.113.0/24
/// new.
const SECOND: [(&str, u8, u32); 3] = [
    ("192.0.2.0/24", 24, 64_999),
    ("192.0.2.128/25", 25, BIRD_AS),
    ("203.0.113.0/24", 24, BIRD_AS),
];

/// The states with [`SECOND`].
const FLIPPED: [(&str, &str); 4] = [
    ("192.0.2.0/24", "invalid"),
    ("192.0.2.128/25", "valid"),
    ("198.51.100.0/24", "not-found"),
    ("203.0.113.0/24", "valid"),
];

/// What the less preferred cache serves in the failover scenario: [`FIRST`]
/// and one VRP more, which makes 203.0.113.0/24 valid, so that its full set
/// shows when it replaces the first cache's.
const FAILOVER: [(&str, u8, u32); 3] = [
    ("192.0.2.0/24", 24, BIRD_AS),
    ("198.51.100.0/24", 24, 64_999),
    ("203.0.113.0/24", 24, BIRD_AS),
];

/// The states with [`FAILOVER`].
const FAILED_OVER: [(&str, &str); 4] = [
    ("192.0.2.0/24", "valid"),
    ("192.0.2.128/25", "invalid"),
    ("198.51.100.0/24", "invalid"),
    ("203.0.113.0/24", "valid"),
];

/// The states without validation (issue #52).
const DISABLED: [(&str, &str); 4] = [
    ("192.0.2.0/24", "disabled"),
    ("192.0.2.128/25", "disabled"),
    ("198.51.100.0/24", "disabled"),
    ("203.0.113.0/24", "disabled"),
];

/// The caches of a scenario.
#[derive(Clone, Copy)]
enum Caches {
    /// This many `StayRTR` caches, at the first [`CACHES`], in that order
    /// of preference.
    StayRtr(usize),
    /// One `rtr-stub` at the first of the [`CACHES`], Session ID 1.
    Stub,
}

/// What a scenario runs.
struct Opts {
    caches: Caches,
    /// What the `StayRTR` caches after the first serve, if not the same
    /// VRPs as the first.
    backup: Option<&'static [(&'static str, u8, u32)]>,
    /// Whether the cache list starts with one at [`Lab::blackhole`], whose
    /// every connection attempt hangs for its `connect-timeout`, 30 s.
    unanswered: bool,
    /// The `mode` of the `rpki` block.
    mode: &'static str,
    /// The `enforcement` of the `rpki` block; `None` writes none, which
    /// means `drop-invalid`.
    enforcement: Option<&'static str>,
    /// The import policy for BIRD in B, `policy NAME { ... }`; `None`
    /// accepts everything.
    import: Option<&'static str>,
    /// Whether bgpfcd installs its routes in the kernel (`fib { mode
    /// install; }`).
    fib_install: bool,
    /// Whether a second BIRD, in C, takes the routes from bgpfcd, and the
    /// prefixes it originates itself.
    relay: Option<&'static [&'static str]>,
    /// Whether BIRD in B sends its routes only once bgpfcd has the first
    /// cache's VRPs, which closes the startup window of `docs/config.md`
    /// ("RPKI"), in which a route that arrives before them is used as
    /// `disabled`.
    routes_after_vrps: bool,
}

impl Opts {
    /// `caches` with `mode external` and `enforcement off`, nothing else:
    /// the RTR transport scenarios, in which nothing acts on the states.
    fn external(caches: Caches) -> Opts {
        Opts {
            caches,
            backup: None,
            unanswered: false,
            mode: "external",
            enforcement: Some("off"),
            import: None,
            fib_install: false,
            relay: None,
            routes_after_vrps: false,
        }
    }

    /// One `StayRTR` cache with `mode external`, `enforcement` as given,
    /// and a relay that originates nothing: the enforcement scenarios.
    fn enforcing(enforcement: Option<&'static str>) -> Opts {
        Opts {
            enforcement,
            relay: Some(&[]),
            ..Opts::external(Caches::StayRtr(1))
        }
    }
}

/// BIRD in B sends its routes to bgpfcd in A, which validates them with
/// the VRPs of the caches beside it, and may pass them on to a second
/// BIRD in C.
struct Setup {
    /// The `StayRTR` caches, in order of preference.
    caches: Vec<StayRtr>,
    /// The stub cache, for [`Caches::Stub`].
    stub: Option<RtrStub>,
    bgpfcd: Daemon,
    bird: Bird,
    relay: Option<Bird>,
    socket: PathBuf,
    /// The address of the cache that never answers, with
    /// [`Opts::unanswered`].
    unanswered: Option<Ipv4Addr>,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl Setup {
    /// Start what `opts` asks for, the first cache serving `vrps`.
    fn start(tag: &str, subnet: u8, opts: &Opts, vrps: &[(&str, u8, u32)]) -> Setup {
        let mut lab = Lab::new(tag, subnet);
        let ns_a = lab.a.clone();
        let (caches, stub, binds) = match opts.caches {
            Caches::StayRtr(n) => (
                CACHES[..n]
                    .iter()
                    .enumerate()
                    .map(|(i, bind)| {
                        let served = if i == 0 {
                            vrps
                        } else {
                            opts.backup.unwrap_or(vrps)
                        };
                        StayRtr::start(&lab, &ns_a, bind, served)
                    })
                    .collect(),
                None,
                &CACHES[..n],
            ),
            Caches::Stub => (
                Vec::new(),
                Some(RtrStub::start(&lab, &ns_a, CACHES[0], 1, vrps)),
                &CACHES[..1],
            ),
        };
        let relay = opts.relay.map(|statics| start_relay(&mut lab, statics));
        let bird = start_bird(&lab, opts.routes_after_vrps);
        let socket = lab.dir.join("ctl.sock");
        let unanswered = opts.unanswered.then(|| lab.blackhole());
        let bgpfcd_opts = bgpfcd_opts(&lab, opts, &socket, binds, unanswered);
        let bgpfcd = start_bgpfcd(&lab, &ns_a, &bgpfcd_opts);
        let s = Setup {
            caches,
            stub,
            bgpfcd,
            bird,
            relay,
            socket,
            unanswered,
            lab,
        };
        if opts.routes_after_vrps {
            s.enable_bird_after_vrps();
        }
        s
    }

    /// Wait for bgpfcd to have the VRPs of a cache, then let BIRD in B
    /// start its session.
    fn enable_bird_after_vrps(&self) {
        let mut out = String::new();
        assert!(
            wait_for(ESTABLISH, || {
                out = self.ctl(&["show", "rpki"]).0;
                out.contains("vrps ipv4 ")
            }),
            "{out}\n{}",
            self.report()
        );
        let enabled = self.bird.birdc(&self.lab, &["enable", "peer"]);
        assert!(enabled.contains("peer: enabled"), "{enabled}");
    }

    /// bgpfcd's configuration file.
    fn config_path(&self) -> PathBuf {
        self.lab.dir.join(format!("bgpfcd-{}.conf", self.lab.a))
    }

    fn ctl(&self, args: &[&str]) -> (String, bool) {
        interop::bgpfcctl(&self.socket, args)
    }

    /// The body of `GET path` from bgpfcd's HTTP API.
    fn http(&self, path: &str) -> String {
        let mut cmd = self.lab.exec(&self.lab.a, "curl");
        cmd.args(["-s", "--max-time", "5", &format!("http://{HTTP}{path}")]);
        let out = cmd.output().expect("curl");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// What `show routes` says about each route: its prefix and its
    /// validation state, in the order of the prefixes as text.
    fn states(&self) -> Vec<(String, String)> {
        let (out, _) = self.ctl(&["show", "routes"]);
        let mut states: Vec<(String, String)> = out
            .lines()
            .skip(1)
            .filter_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                Some((
                    words.first()?.trim_start_matches('*').to_owned(),
                    (*words.get(5)?).to_owned(),
                ))
            })
            .collect();
        states.sort();
        states
    }

    /// What `GET /v1/routes` says about each route, as [`Setup::states`].
    fn http_states(&self) -> Vec<(String, String)> {
        let body = self.http("/v1/routes");
        let mut states: Vec<(String, String)> = body
            .split("{\"prefix\":\"")
            .skip(1)
            .filter_map(|route| {
                let prefix = route.split('"').next()?;
                let (_, rov) = route.split_once("\"rov\":\"")?;
                Some((prefix.to_owned(), rov.split('"').next()?.to_owned()))
            })
            .collect();
        states.sort();
        states
    }

    /// Wait up to `timeout` for `show routes` to give the routes
    /// `states`, then check that the HTTP API agrees.
    fn wait_for_states(&self, timeout: Duration, states: &[(&str, &str)]) {
        let want: Vec<(String, String)> = states
            .iter()
            .map(|(p, s)| ((*p).to_owned(), (*s).to_owned()))
            .collect();
        assert!(
            wait_for(timeout, || self.states() == want),
            "{}",
            self.report()
        );
        assert_eq!(self.http_states(), want, "{}", self.http("/v1/routes"));
    }

    /// Wait up to `timeout` for bgpfcd to log `line`.
    fn wait_for_log(&self, timeout: Duration, line: &str) {
        assert!(
            wait_for(timeout, || self.bgpfcd.log_text().contains(line)),
            "no `{line}`:\n{}",
            self.report()
        );
    }

    /// How often bgpfcd has logged `text`.
    fn count(&self, text: &str) -> usize {
        self.bgpfcd.log_text().matches(text).count()
    }

    /// What each "rib: validation states changed" line bgpfcd has logged
    /// says the change of the validation source did: how many routes
    /// changed state, and the changes of state, sorted
    /// (`invalid->valid:1`).
    fn revalidations(&self) -> Vec<(usize, Vec<String>)> {
        self.bgpfcd
            .log_text()
            .lines()
            .filter(|l| l.contains("msg=\"rib: validation states changed\""))
            .map(|l| {
                let field = |key: &str| {
                    l.split_whitespace()
                        .find_map(|w| w.strip_prefix(key))
                        .unwrap_or_default()
                        .to_owned()
                };
                let mut changes: Vec<String> = field("changes=")
                    .split(',')
                    .filter(|c| !c.is_empty())
                    .map(str::to_owned)
                    .collect();
                changes.sort();
                (field("changed=").parse().unwrap_or(usize::MAX), changes)
            })
            .collect()
    }

    /// Wait up to `timeout` for bgpfcd to log `count` more revalidation
    /// lines than it had logged when `before` was taken; those lines.
    fn new_revalidations(
        &self,
        timeout: Duration,
        before: usize,
        count: usize,
    ) -> Vec<(usize, Vec<String>)> {
        assert!(
            wait_for(timeout, || self.revalidations().len() >= before + count),
            "{}",
            self.report()
        );
        self.revalidations().split_off(before)
    }

    /// How many UPDATEs bgpfcd has taken from BIRD.
    fn updates_from_bird(&self) -> usize {
        self.count(&format!("msg=\"rib: update\" peer={} ", self.lab.b_addr))
    }

    /// Wait up to `timeout` for `show rpki` to say that bgpfcd lost its
    /// cache: no connection, failures counted and the last one named,
    /// and the last VRPs still in use, those of the first cache, which the
    /// warnings tell. Returns what it said.
    fn wait_for_lost_cache(&self, timeout: Duration) -> String {
        let lost = |out: &str| {
            !out.contains(", connected")
                && !out.contains("failures 0")
                && out.contains("last error")
                && out.contains("serving_vrps=2 expires_in=")
                && out.contains("vrps ipv4 2 ipv6 0 from 127.0.0.1:3323, expire in")
        };
        let mut out = String::new();
        assert!(
            wait_for(timeout, || {
                out = self.ctl(&["show", "rpki"]).0;
                lost(&out)
            }),
            "{out}\n{}",
            self.report()
        );
        out
    }

    /// The routes `show routes held` lists, every one marked `!`: prefix,
    /// validation state and why it is held (`enforcement` or `policy`),
    /// sorted.
    fn held(&self) -> Vec<(String, String, String)> {
        let (out, _) = self.ctl(&["show", "routes", "held"]);
        let mut held: Vec<(String, String, String)> = out
            .lines()
            .skip(1)
            .filter_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                Some((
                    words.first()?.strip_prefix('!')?.to_owned(),
                    (*words.get(5)?).to_owned(),
                    line.split_once(" held by ")?.1.to_owned(),
                ))
            })
            .collect();
        held.sort();
        held
    }

    /// The route lines of `show routes PREFIX`: every route the
    /// Adj-RIBs-In hold for it.
    fn routes_at(&self, prefix: &str) -> Vec<String> {
        let (out, _) = self.ctl(&["show", "routes", prefix]);
        out.lines().skip(1).map(str::to_owned).collect()
    }

    /// The prefixes the relay BIRD in C has a route to, sorted.
    fn relay_routes(&self) -> Vec<String> {
        let relay = self.relay.as_ref().expect("a relay");
        let mut routes: Vec<String> = relay
            .birdc(&self.lab, &["show", "route"])
            .lines()
            // A route's first line starts with its network; the lines of
            // its next hops and alternatives are indented.
            .filter(|l| !l.starts_with(char::is_whitespace))
            .filter_map(|l| l.split_whitespace().next())
            .filter(|w| w.contains('/'))
            .map(str::to_owned)
            .collect();
        routes.sort();
        routes.dedup();
        routes
    }

    /// How many route updates and withdrawals the relay BIRD in C has
    /// received from bgpfcd, by its `Import updates` and `Import
    /// withdraws` counters.
    fn relay_imports(&self) -> (usize, usize) {
        let relay = self.relay.as_ref().expect("a relay");
        let status = relay.peer_status(&self.lab);
        let received = |row: &str| {
            status
                .lines()
                .find_map(|l| l.trim().strip_prefix(row))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(usize::MAX)
        };
        (received("Import updates:"), received("Import withdraws:"))
    }

    /// The prefixes bgpfcd has installed in its namespace's kernel table
    /// with its protocol number (`ip route show proto 186`), sorted.
    fn kernel_routes(&self) -> Vec<String> {
        let out =
            interop::Daemon::ip_in(&self.lab, &self.lab.a, &["route", "show", "proto", "186"]);
        let mut routes: Vec<String> = out
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(str::to_owned)
            .collect();
        routes.sort();
        routes
    }

    /// The changes of state `show rpki transitions` keeps, oldest first and
    /// without their time (`PREFIX peer PEER origin ASN FROM->TO ROUTE`),
    /// and its closing line.
    fn transitions(&self) -> (Vec<String>, String) {
        let (out, _) = self.ctl(&["show", "rpki", "transitions"]);
        let mut lines: Vec<&str> = out.lines().collect();
        let last = lines.pop().unwrap_or_default().to_owned();
        let entries = lines
            .iter()
            .map(|l| l.split_once(' ').map_or("", |(_, rest)| rest).to_owned())
            .collect();
        (entries, last)
    }

    /// The changes of state `GET /v1/rpki/transitions` keeps, written as
    /// [`Setup::transitions`] writes them, and its `unrecorded`.
    fn http_transitions(&self) -> (Vec<String>, String) {
        let body = self.http("/v1/rpki/transitions");
        let entries = body
            .split("{\"time\":\"")
            .skip(1)
            .map(|t| {
                let origin = match json_value(t, "origin").as_str() {
                    "null" => "none".to_owned(),
                    asn => format!("AS{asn}"),
                };
                let by = match json_value(t, "held_by").as_str() {
                    "null" => String::new(),
                    by => format!(" by {by}"),
                };
                format!(
                    "{} peer {} origin {origin} {}->{} {}{by}",
                    json_value(t, "prefix"),
                    json_value(t, "peer"),
                    json_value(t, "from"),
                    json_value(t, "to"),
                    json_value(t, "route"),
                )
            })
            .collect();
        (entries, json_value(&body, "unrecorded"))
    }

    /// The "rib: route validation state changed" lines bgpfcd has logged,
    /// written as [`Setup::transitions`] writes the changes it keeps.
    fn route_lines(&self) -> Vec<String> {
        self.bgpfcd
            .log_text()
            .lines()
            .filter(|l| l.contains("msg=\"rib: route validation state changed\""))
            .map(|l| {
                let by = log_value(l, "by").map_or(String::new(), |by| format!(" by {by}"));
                let field = |key| log_value(l, key).unwrap_or_default();
                format!(
                    "{} peer {} origin {} {}->{} {}{by}",
                    field("prefix"),
                    field("peer"),
                    field("origin"),
                    field("from"),
                    field("to"),
                    field("route"),
                )
            })
            .collect()
    }

    /// The last line bgpfcd has logged with the message `msg`.
    fn last_line(&self, msg: &str) -> String {
        let needle = format!("msg=\"{msg}\"");
        self.bgpfcd
            .log_text()
            .lines()
            .rfind(|l| l.contains(&needle))
            .unwrap_or_default()
            .to_owned()
    }

    /// Everything a failed assertion needs.
    fn report(&self) -> String {
        let mut caches: Vec<String> = self.caches.iter().map(|c| c.daemon.log_text()).collect();
        caches.extend(self.stub.iter().map(|s| s.daemon.log_text()));
        let relay = self.relay.as_ref().map_or(String::new(), |r| {
            format!(
                "\n--- relay ---\n{}{}",
                r.birdc(&self.lab, &["show", "route"]),
                r.daemon.log_text()
            )
        });
        format!(
            "{:?}\n--- bgpfcd ---\n{}\n--- cache ---\n{}\n--- bird ---\n{}{relay}",
            self.states(),
            self.bgpfcd.log_text(),
            caches.join("\n--- cache ---\n"),
            self.bird.daemon.log_text()
        )
    }
}

/// The value of `key` in the first JSON member of that name in `text`: a
/// string without its quotes, or a bare number or `null`.
fn json_value(text: &str, key: &str) -> String {
    let Some((_, rest)) = text.split_once(&format!("\"{key}\":")) else {
        return String::new();
    };
    match rest.strip_prefix('"') {
        Some(s) => s.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    }
}

/// The value of the field `key` of a bgpfcd log line, which none of the
/// fields read here quotes (AGENTS.md §3, "Logging").
fn log_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
}

/// The `rpki` block for the caches at `binds`, in that order of
/// preference, after the one at `unanswered` if there is one, with the
/// `enforcement` given, or none.
fn rpki_block(
    mode: &str,
    enforcement: Option<&str>,
    binds: &[&str],
    unanswered: Option<Ipv4Addr>,
) -> String {
    let mut entries = String::new();
    if let Some(addr) = unanswered {
        let _ = write!(
            entries,
            " cache {addr} port 3323 preference 0; connect-timeout 30; response-timeout 60;"
        );
    }
    for (i, bind) in binds.iter().enumerate() {
        let port = bind.rsplit(':').next().unwrap_or(bind);
        let preference = i + usize::from(unanswered.is_some());
        let _ = write!(
            entries,
            " cache 127.0.0.1 port {port} preference {preference};"
        );
    }
    let enforcement = enforcement.map_or(String::new(), |e| format!(" enforcement {e};"));
    // The shortest back-off, so that a cache that comes back is found
    // within a second or two.
    format!("rpki {{ mode {mode};{enforcement}{entries} backoff 1 1; }}")
}

/// The relay BIRD, in a new namespace C: it takes the routes bgpfcd
/// passes on and originates `statics` itself.
fn start_relay(lab: &mut Lab, statics: &[&str]) -> Bird {
    let ns_c = lab.add_c();
    Bird::start(
        lab,
        &ns_c,
        &BirdOpts {
            local_as: RELAY_AS,
            local: lab.c_addr,
            local_port: 179,
            neighbor: lab.a2_addr,
            neighbor_port: 179,
            remote_as: BGPFC_AS,
            hold_time: 30,
            passive: true,
            statics: statics.iter().map(|&p| p.to_owned()).collect(),
            channel: String::new(),
            protocol: String::new(),
        },
    )
}

/// BIRD in B, which originates [`ROUTES`]; with `held_back`, its session
/// stays down until [`Setup::enable_bird_after_vrps`].
fn start_bird(lab: &Lab, held_back: bool) -> Bird {
    Bird::start(
        lab,
        &lab.b,
        &BirdOpts {
            local_as: BIRD_AS,
            local: lab.b_addr,
            local_port: 179,
            neighbor: lab.a_addr,
            neighbor_port: 179,
            remote_as: BGPFC_AS,
            hold_time: 30,
            passive: true,
            statics: ROUTES.map(str::to_owned).to_vec(),
            channel: String::new(),
            protocol: if held_back {
                "disabled;".to_owned()
            } else {
                String::new()
            },
        },
    )
}

/// bgpfcd's configuration for `opts`, with the caches at `binds`.
fn bgpfcd_opts(
    lab: &Lab,
    opts: &Opts,
    socket: &Path,
    binds: &[&str],
    unanswered: Option<Ipv4Addr>,
) -> BgpfcdOpts {
    let from_bird = NeighborOpts {
        import: opts
            .import
            .map_or_else(|| "ANY".to_owned(), |p| policy_name(p).to_owned()),
        // BIRD refuses the session until it is enabled: try again every
        // second rather than every 120.
        extra: if opts.routes_after_vrps {
            "connect-retry-time 1;".to_owned()
        } else {
            String::new()
        },
        ..NeighborOpts::new(lab.b_addr, BIRD_AS)
    };
    let mut bgpfcd_opts = BgpfcdOpts::single(BGPFC_AS, lab.a_addr, from_bird);
    if opts.relay.is_some() {
        // RFC 4271 §9.2.1.1 pacing, shortened from the 30 s EBGP default
        // so that the routes reach the relay quickly.
        let to_relay = NeighborOpts {
            advertisement_interval: Some(1),
            ..NeighborOpts::new(lab.c_addr, RELAY_AS)
        };
        bgpfcd_opts.neighbors.push(to_relay);
        bgpfcd_opts.listen.push(lab.a2_addr.into());
    }
    bgpfcd_opts.extra = format!(
        "control {{ socket {}; http {{ listen {HTTP}; }} }}\n{}{}\n{}",
        socket.display(),
        if opts.fib_install {
            "fib { mode install; }\n"
        } else {
            ""
        },
        rpki_block(opts.mode, opts.enforcement, binds, unanswered),
        opts.import.unwrap_or_default(),
    );
    bgpfcd_opts
}

/// The name of the policy `text` defines: `policy NAME { ... }`.
fn policy_name(text: &str) -> &str {
    text.split_whitespace().nth(1).unwrap_or_default()
}

/// Routes and their validation states: (prefix, state).
type States<'a> = Vec<(&'a str, &'a str)>;

/// `states` split into those of the routes `enforcement drop-invalid`
/// uses, which `show routes` lists, and those of the routes it holds: the
/// Invalid ones (RFC 6811 §5, "rejecting all "invalid" routes").
fn split_invalid<'a>(states: &[(&'a str, &'a str)]) -> (States<'a>, States<'a>) {
    states.iter().partition(|(_, rov)| *rov != "invalid")
}

/// The prefixes of `states`, sorted.
fn prefixes(states: &[(&str, &str)]) -> Vec<String> {
    let mut p: Vec<String> = states.iter().map(|(p, _)| (*p).to_owned()).collect();
    p.sort();
    p
}

/// The `session-id ... serial ...` line of `show rpki`.
fn session_line(show_rpki: &str) -> String {
    show_rpki
        .lines()
        .find(|l| l.starts_with("session-id "))
        .unwrap_or_default()
        .to_owned()
}

/// BIRD's routes come out valid, invalid (by length and by origin) and
/// not-found, by the CLI and the HTTP API, and all of them are relayed.
/// A new VRP file then changes the state of every route without any BGP
/// UPDATE: `StayRTR` sends a Serial Notify, bgpfcd asks for the changes
/// (RFC 8210 §8.2), and the routes they cover are validated again
/// (RFC 6811 §4, issue #59).
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn routes_are_validated_relayed_and_follow_the_vrps() {
    let opts = Opts {
        relay: Some(&[]),
        ..Opts::external(Caches::StayRtr(1))
    };
    let s = Setup::start("v", 15, &opts, &FIRST);
    s.wait_for_states(ESTABLISH, &VALIDATED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    for line in [
        "mode external",
        "cache 127.0.0.1:3323 preference 0, in use",
        "state idle, connected, version 1",
        "vrps ipv4 2 ipv6 0",
        "failures 0",
    ] {
        assert!(ok && out.contains(line), "{line}:\n{out}");
    }
    let body = s.http("/v1/rpki");
    assert!(
        body.contains("\"mode\":\"external\"")
            && body.contains("\"running\":true,\"state\":\"idle\",\"connected\":true"),
        "{body}"
    );
    let (out, ok) = s.ctl(&["show", "rpki", "validate", "198.51.100.0/24", "AS65001"]);
    assert!(
        ok && out.contains("198.51.100.0/24 origin AS65001: invalid")
            && out.contains("  198.51.100.0/24-24 AS64999\n"),
        "{out}"
    );
    let body = s.http("/v1/rpki/validate?prefix=192.0.2.128/25&origin=65001");
    assert!(
        body.contains("\"rov\":\"invalid\"")
            && body.contains(
                "{\"prefix\":\"192.0.2.0/24\",\"max_length\":24,\"asn\":65001,\"matches\":false}"
            ),
        "{body}"
    );

    // Nothing acts on the states yet: the invalid routes reach the relay
    // too.
    let relay = s.relay.as_ref().expect("relay");
    let relayed = || {
        let routes = relay.birdc(&s.lab, &["show", "route"]);
        ROUTES.iter().all(|p| routes.contains(p))
    };
    assert!(
        wait_for(Duration::from_secs(20), relayed),
        "{}\n{}",
        relay.birdc(&s.lab, &["show", "route"]),
        s.report()
    );

    let updates = s.updates_from_bird();
    let sessions = s.count("session established");
    let serial_queries = s.count("query=\"Serial Query\"");
    let revalidations = s.revalidations().len();
    s.caches[0].set_vrps(&SECOND);
    s.wait_for_states(CHANGE, &FLIPPED);
    // One change of the VRPs, one line: every route changed state.
    assert_eq!(
        s.new_revalidations(Duration::ZERO, revalidations, 1),
        [(
            4,
            vec![
                "invalid->not-found:1".to_owned(),
                "invalid->valid:1".to_owned(),
                "not-found->valid:1".to_owned(),
                "valid->invalid:1".to_owned(),
            ]
        )],
        "{}",
        s.report()
    );
    assert!(
        s.count("query=\"Serial Query\"") > serial_queries,
        "{}",
        s.report()
    );
    // No UPDATE came from BIRD, no session was reset, and every route is
    // still relayed.
    assert_eq!(s.updates_from_bird(), updates, "{}", s.report());
    assert_eq!(s.count("session established"), sessions, "{}", s.report());
    assert!(relayed(), "{}", relay.birdc(&s.lab, &["show", "route"]));
}

/// The only cache, `StayRTR`, goes away and comes back: bgpfcd keeps its
/// VRPs, says what happened in `show rpki`, and connects to the cache
/// again by itself (issue #57).
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn the_vrps_outlive_a_restarted_stayrtr() {
    let opts = Opts::external(Caches::StayRtr(1));
    let mut s = Setup::start("k", 16, &opts, &FIRST);
    s.wait_for_states(ESTABLISH, &VALIDATED);
    let session = session_line(&s.ctl(&["show", "rpki"]).0);
    assert!(session.starts_with("session-id "), "{}", s.report());

    s.caches[0].daemon.kill();
    s.wait_for_log(
        RECONNECT,
        "WARN  msg=\"rtr lost the cache; serving the last data while reconnecting\"",
    );
    let out = s.wait_for_lost_cache(RECONNECT);
    assert_eq!(session_line(&out), session, "{out}");
    s.wait_for_states(Duration::ZERO, &VALIDATED);

    // StayRTR again, on the same port with the same file: bgpfcd connects
    // and resumes its session with a Serial Query (RFC 8210 §8.1).
    let ns_a = s.lab.a.clone();
    let cache = StayRtr::start(&s.lab, &ns_a, CACHES[0], &FIRST);
    s.caches[0] = cache;
    let id = session.split_whitespace().nth(1).unwrap_or_default();
    let query = format!("Received PDU Serial Query v1 (session: {id})");
    assert!(
        wait_for(RECONNECT, || s.caches[0].daemon.log_text().contains(&query)),
        "no `{query}`:\n{}",
        s.report()
    );
    // NOTE(interop): StayRTR 0.5.1 has a new Session ID now. It answers
    // that query with an Error Report (Corrupt Data, "Session ID
    // mismatch") rather than the Cache Reset of RFC 8210 §8.3, but closes
    // the connection at the same time, so the report reaches bgpfcd in
    // some runs and is lost in others. With the report, the session ends
    // (§5.11) and bgpfcd loads the data afresh with a Reset Query; with a
    // bare close, bgpfcd keeps its VRPs and asks again, as BIRD 2.14 does,
    // until they expire (§6) or another cache answers. Either way the VRPs
    // stay in use and no route changes state, which is what this test is
    // about; `a_restarted_cache_brings_bgpfcd_back_in_sync` covers the
    // reload against a cache that answers with a Cache Reset.
    let refused = format!("Invalid request (client asked for session {id} but server is at");
    let mut out = String::new();
    assert!(
        wait_for(RECONNECT, || {
            out = s.ctl(&["show", "rpki"]).0;
            let reloaded = out.contains("state idle, connected, version 1")
                && out.contains("vrps ipv4 2 ipv6 0 from 127.0.0.1:3323,")
                && session_line(&out).starts_with("session-id ")
                && session_line(&out) != session;
            let asked_again = s.caches[0].daemon.log_text().matches(&refused).count() >= 2
                && !out.contains(", connected")
                && session_line(&out) == session
                && out.contains("vrps ipv4 2 ipv6 0 from 127.0.0.1:3323, expire in");
            reloaded || asked_again
        }),
        "{out}\n{}",
        s.report()
    );
    s.wait_for_states(Duration::ZERO, &VALIDATED);
}

/// A cache that restarts, under a new Session ID, answers bgpfcd's Serial
/// Query for the old session with a Cache Reset; bgpfcd then loads the
/// whole data set with a Reset Query (RFC 8210 §8.3) and is in sync again
/// without the operator (issue #57). The VRPs are the same as before, so
/// no route changes state at any point.
///
/// The cache is this crate's `rtr-stub`: `StayRTR` 0.5.1 answers that
/// Serial Query with an Error Report that its own close of the connection
/// sometimes loses (see `the_vrps_outlive_a_restarted_stayrtr`).
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn a_restarted_cache_brings_bgpfcd_back_in_sync() {
    let opts = Opts::external(Caches::Stub);
    let mut s = Setup::start("s", 17, &opts, &FIRST);
    s.wait_for_states(ESTABLISH, &VALIDATED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.contains("state idle, connected, version 1")
            && out.contains("session-id 1 serial 1"),
        "{out}"
    );
    let revalidations = s.count("msg=\"rib: validation states changed\"");

    if let Some(stub) = &mut s.stub {
        stub.daemon.kill();
    }
    s.wait_for_log(
        RECONNECT,
        "WARN  msg=\"rtr lost the cache; serving the last data while reconnecting\"",
    );
    let out = s.wait_for_lost_cache(RECONNECT);
    assert!(out.contains("session-id 1 serial 1"), "{out}");
    s.wait_for_states(Duration::ZERO, &VALIDATED);

    let ns_a = s.lab.a.clone();
    let stub = RtrStub::start(&s.lab, &ns_a, CACHES[0], 2, &FIRST);
    s.stub = Some(stub);
    s.wait_for_log(RECONNECT, "INFO  msg=\"rtr cache reachable again\"");
    s.wait_for_log(
        Duration::ZERO,
        "msg=\"rtr cache cannot update incrementally; reloading\"",
    );
    let log = s
        .stub
        .as_ref()
        .map(|t| t.daemon.log_text())
        .unwrap_or_default();
    assert!(
        log.contains("Serial Query v1 session 1 serial 1: Cache Reset")
            && log.contains("Reset Query v1: Cache Response, 2 VRPs, End of Data session 2"),
        "{log}"
    );
    let (out, ok) = s.ctl(&["show", "rpki"]);
    for line in [
        "state idle, connected, version 1",
        "session-id 2 serial 1",
        "vrps ipv4 2 ipv6 0",
        "failures 0",
    ] {
        assert!(ok && out.contains(line), "{line}:\n{out}");
    }
    s.wait_for_states(Duration::ZERO, &VALIDATED);
    assert_eq!(
        s.count("msg=\"rib: validation states changed\""),
        revalidations,
        "{}",
        s.report()
    );
}

/// With `mode disabled` every route reads `disabled`, and bgpfcd never
/// connects to the cache the block still lists.
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn with_mode_disabled_no_cache_is_asked() {
    let opts = Opts {
        mode: "disabled",
        ..Opts::external(Caches::StayRtr(1))
    };
    let s = Setup::start("d", 18, &opts, &FIRST);
    // A client would start before the neighbors, so it would have
    // connected by the time BIRD's routes are in.
    s.wait_for_states(ESTABLISH, &DISABLED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out == "mode disabled\nenforcement off\ncache 127.0.0.1:3323 preference 0\n",
        "{out}"
    );
    let body = s.http("/v1/rpki");
    assert!(
        body.contains("\"mode\":\"disabled\"")
            && body.contains("\"in_use\":false")
            && body.contains("\"running\":false"),
        "{body}"
    );
    let (out, ok) = s.ctl(&["show", "rpki", "validate", "192.0.2.0/24", "AS65001"]);
    assert!(
        ok && out.contains("192.0.2.0/24 origin AS65001: disabled"),
        "{out}"
    );
    s.wait_for_log(Duration::ZERO, "rpki=disabled");
    assert!(
        !s.bgpfcd.log_text().contains("msg=\"rtr "),
        "{}",
        s.report()
    );
    let log = s.caches[0].daemon.log_text();
    assert!(!log.contains("Accepted tcp connection"), "{log}");
}

/// The preferred of two caches goes away: bgpfcd warns, keeps its VRPs
/// (RFC 8210 §10) and moves to the other cache, whose full set, which
/// differs in one VRP, replaces them; when the preferred cache comes back,
/// bgpfcd returns to it within the Retry Interval (§4, §10). A reload that
/// names a cache that cannot be found fails and keeps the client (issue
/// #60). Then a reload to `mode disabled` and back.
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn the_vrps_outlive_their_cache_and_follow_a_reload() {
    let opts = Opts {
        backup: Some(&FAILOVER),
        ..Opts::external(Caches::StayRtr(2))
    };
    let mut s = Setup::start("w", 19, &opts, &FIRST);
    s.wait_for_states(ESTABLISH, &VALIDATED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.contains("cache 127.0.0.1:3323 preference 0, in use, current\n")
            && out.contains("cache 127.0.0.1:3324 preference 1\n"),
        "{out}"
    );
    let revalidations = s.revalidations().len();
    // A warning, and the VRPs stay in use while bgpfcd tries the cache
    // again and then the other one (an info line when in sync again).
    s.caches[0].daemon.kill();
    s.wait_for_log(
        RECONNECT,
        "WARN  msg=\"rtr lost the cache; serving the last data while reconnecting\"",
    );
    s.wait_for_log(RECONNECT, "INFO  msg=\"rtr cache reachable again\"");
    s.wait_for_states(CHANGE, &FAILED_OVER);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    for line in [
        "cache 127.0.0.1:3323 preference 0\n",
        "cache 127.0.0.1:3324 preference 1, in use, current\n",
        "state idle, connected",
        "vrps ipv4 3 ipv6 0 from 127.0.0.1:3324, expire in",
    ] {
        assert!(ok && out.contains(line), "{line}:\n{out}");
    }
    // One change since the cache went away, which moved one route: the
    // first cache's VRPs stayed in use until the other's full set
    // replaced them, and only what the two sets judge differently changed.
    assert_eq!(
        s.new_revalidations(Duration::ZERO, revalidations, 1),
        [(1, vec!["not-found->valid:1".to_owned()])],
        "{}",
        s.report()
    );

    // The preferred cache comes back. In sync with the other, bgpfcd looks
    // for it every Retry Interval, two seconds here (RFC 8210 §6), and
    // moves back to it: §4, the most preferred cache that accepts.
    let revalidations = s.revalidations().len();
    let ns_a = s.lab.a.clone();
    s.caches[0] = StayRtr::start(&s.lab, &ns_a, CACHES[0], &FIRST);
    s.wait_for_log(
        RECONNECT,
        "INFO  msg=\"rtr moving to a more preferred cache\"",
    );
    s.wait_for_states(CHANGE, &VALIDATED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    for line in [
        "cache 127.0.0.1:3323 preference 0, in use, current\n",
        "cache 127.0.0.1:3324 preference 1\n",
        "state idle, connected",
        "vrps ipv4 2 ipv6 0 from 127.0.0.1:3323, expire in",
    ] {
        assert!(ok && out.contains(line), "{line}:\n{out}");
    }
    assert_eq!(
        s.new_revalidations(Duration::ZERO, revalidations, 1),
        [(1, vec!["valid->not-found:1".to_owned()])],
        "{}",
        s.report()
    );

    // Issue #60: a reload that adds a cache whose name does not resolve
    // fails, and the running client goes on as it was.
    let cfg_path = s.config_path();
    let external = fs::read_to_string(&cfg_path).unwrap();
    // RFC 2606 §2: a name under `.invalid` never resolves.
    fs::write(
        &cfg_path,
        external.replace(
            " backoff 1 1;",
            " cache rtr.invalid preference 5; backoff 1 1;",
        ),
    )
    .unwrap();
    let (out, ok) = s.ctl(&["reload"]);
    assert!(
        !ok && out.contains("cannot resolve rpki cache rtr.invalid"),
        "{out}"
    );
    s.wait_for_log(Duration::ZERO, "reload failed; running configuration kept");
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.contains("cache 127.0.0.1:3323 preference 0, in use, current\n")
            && out.contains("state idle, connected")
            && !out.contains("rtr.invalid"),
        "{out}"
    );
    s.wait_for_states(Duration::ZERO, &VALIDATED);

    // A reload to `mode disabled` turns validation off for every route,
    // and one back to `mode external` brings the states back.
    fs::write(
        &cfg_path,
        external.replace("mode external", "mode disabled"),
    )
    .unwrap();
    let (out, ok) = s.ctl(&["reload"]);
    assert!(ok && out.contains("rpki: validation disabled"), "{out}");
    s.wait_for_states(Duration::from_secs(10), &DISABLED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(ok && out.starts_with("mode disabled\n"), "{out}");
    fs::write(&cfg_path, &external).unwrap();
    let (out, ok) = s.ctl(&["reload"]);
    assert!(ok && out.contains("rpki: rtr client started"), "{out}");
    s.wait_for_states(CHANGE, &VALIDATED);
    // None of this touched the BGP session.
    assert_eq!(s.count("session established"), 1, "{}", s.report());
}

/// A cache whose address swallows every packet comes first in the list,
/// with a connection attempt of up to 30 seconds. A reload that drops it
/// does not wait for the attempt, nor does a shutdown during one: the
/// peer gets its Cease at once.
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn a_cache_that_never_answers_holds_up_neither_reload_nor_shutdown() {
    let opts = Opts {
        unanswered: true,
        ..Opts::external(Caches::StayRtr(1))
    };
    let mut s = Setup::start("h", 20, &opts, &FIRST);
    let unanswered = s.unanswered.expect("the unanswered cache");
    let hanging = format!("cache {unanswered}:3323 preference 0, current\n");
    // The routes come in while bgpfcd still waits for the first cache.
    s.wait_for_states(ESTABLISH, &DISABLED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.contains(&hanging) && out.contains("state connecting, version 1"),
        "{out}"
    );

    // A reload without that cache: the client restarts at once.
    let cfg_path = s.config_path();
    let with = fs::read_to_string(&cfg_path).unwrap();
    let entry = format!(" cache {unanswered} port 3323 preference 0;");
    assert!(with.contains(&entry), "{with}");
    fs::write(&cfg_path, with.replace(&entry, "")).unwrap();
    let reloading = Instant::now();
    let (out, ok) = s.ctl(&["reload"]);
    assert!(ok && out.contains("rpki: rtr client restarted"), "{out}");
    assert!(
        reloading.elapsed() < Duration::from_secs(5),
        "{:?}",
        reloading.elapsed()
    );
    s.wait_for_states(CHANGE, &VALIDATED);

    // Back to the list that starts with it, and a shutdown during the
    // attempt: the Cease, the FIB cleanup and the exit do not wait.
    fs::write(&cfg_path, &with).unwrap();
    let (out, ok) = s.ctl(&["reload"]);
    assert!(ok && out.contains("rpki: rtr client restarted"), "{out}");
    assert!(
        wait_for(RECONNECT, || {
            let out = s.ctl(&["show", "rpki"]).0;
            out.contains(&hanging) && out.contains("state connecting")
        }),
        "{}",
        s.report()
    );
    let stopping = Instant::now();
    assert!(
        s.bgpfcd.terminate(Duration::from_secs(10)),
        "{}",
        s.report()
    );
    assert!(
        stopping.elapsed() < Duration::from_secs(5),
        "{:?}\n{}",
        stopping.elapsed(),
        s.report()
    );
    s.wait_for_log(Duration::ZERO, "msg=\"bgpfcd stopped\"");
    assert!(
        wait_for(Duration::from_secs(10), || s
            .bird
            .daemon
            .log_text()
            .contains("Received: Administrative shutdown")),
        "{}",
        s.bird.daemon.log_text()
    );
}

/// What `show routes held` gives for routes in `states`, all held by `by`.
fn held_by(states: &[(&str, &str)], by: &str) -> Vec<(String, String, String)> {
    let mut held: Vec<(String, String, String)> = states
        .iter()
        .map(|(p, rov)| ((*p).to_owned(), (*rov).to_owned(), by.to_owned()))
        .collect();
    held.sort();
    held
}

impl Setup {
    /// The changes of state of BIRD's routes, `(prefix, "FROM->TO ROUTE")`,
    /// as [`Setup::transitions`] writes them.
    fn moved(&self, changes: &[(&str, &str)]) -> Vec<String> {
        changes
            .iter()
            .map(|(prefix, change)| {
                format!(
                    "{prefix} peer {} origin AS{BIRD_AS} {change}",
                    self.lab.b_addr
                )
            })
            .collect()
    }

    /// Wait up to `timeout` for the relay BIRD and the kernel to have
    /// routes to exactly the prefixes of `used`.
    fn wait_for_used(&self, timeout: Duration, used: &[(&str, &str)]) {
        let want = prefixes(used);
        assert!(
            wait_for(timeout, || self.relay_routes() == want
                && self.kernel_routes() == want),
            "relay {:?} kernel {:?}, not {want:?}\n{}",
            self.relay_routes(),
            self.kernel_routes(),
            self.report()
        );
    }
}

/// Issue #61: "Invalid routes are dropped by default". With `mode
/// external` and no `enforcement` statement, bgpfcd holds BIRD's two
/// Invalid routes in the Adj-RIB-In, out of the decision process (RFC 6811
/// §2: "unless explicitly configured to do so"; §5: "rejecting all
/// "invalid" routes"), and uses the Valid and the `NotFound` one. Only those
/// two are installed and relayed: the relay never hears of the others,
/// since BIRD sends its routes once bgpfcd has the VRPs. `show routes`,
/// `show neighbor`, `show rpki` and the start line tell it.
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn invalid_routes_are_held_and_not_used_by_default() {
    let opts = Opts {
        fib_install: true,
        routes_after_vrps: true,
        ..Opts::enforcing(None)
    };
    let s = Setup::start("i", 21, &opts, &FIRST);
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(ESTABLISH, &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    s.wait_for_used(Duration::from_secs(20), &used);
    // RFC 6811 §2: held in the Adj-RIB-In, but no candidate.
    let at = s.routes_at("192.0.2.128/25");
    assert!(
        at.len() == 1
            && at[0].starts_with("!192.0.2.128/25 ")
            && at[0].ends_with(&format!(
                " invalid   {BIRD_AS} via {} held by enforcement",
                s.lab.b_addr
            )),
        "{at:?}"
    );
    let body = s.http("/v1/routes?family=ipv4&held=1");
    assert!(
        body.matches("\"held\":\"enforcement\"").count() == 2
            && body.contains("\"prefix\":\"198.51.100.0/24\"")
            && !body.contains("\"held\":null"),
        "{body}"
    );
    // Counted as received, and as held.
    let b = s.lab.b_addr.to_string();
    let (out, ok) = s.ctl(&["show", "neighbor", &b]);
    assert!(
        ok && out.contains("ipv4-unicast received 4 held 2 "),
        "{out}"
    );
    let body = s.http(&format!("/v1/neighbors/{b}"));
    assert!(body.contains("\"received\":4,\"held\":2,"), "{body}");
    // The relay has had two routes and no withdrawal: the Invalid ones
    // never reached it.
    assert_eq!(s.relay_imports(), (2, 0), "{}", s.report());
    // Where the operator turns validation on, the enforcement shows.
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.starts_with("mode external\nenforcement drop-invalid\n"),
        "{out}"
    );
    let start = s.last_line("bgpfcd starting");
    assert!(
        start.ends_with(" rpki=external enforcement=drop-invalid"),
        "{start}"
    );
}

/// Issue #59's acceptance, and #52's: "Creating, modifying and deleting a
/// ROA in the lab each flip the state of an already-installed route and
/// produce the correct advertisement or withdrawal, with no BGP UPDATE
/// received." The cache's new VRPs create a ROA (203.0.113.0/24 goes from
/// `not-found` to `valid`), change one (192.0.2.0/24, now for another AS,
/// from `valid` to `invalid`), delete one (198.51.100.0/24, from `invalid`
/// to `not-found`) and authorise the /25 (from `invalid` to `valid`).
/// bgpfcd validates those routes again (RFC 6811 §4) and, with the
/// default `drop-invalid`, withdraws 192.0.2.0/24 from the relay and the
/// kernel, and advertises and installs the two it had held. Each route
/// that changed state is logged with its states and what became of it,
/// and kept for `show rpki transitions` (issue #59: "An operator needs to
/// see that a prefix went Valid → Invalid at a specific time"). With the
/// old VRPs back, everything moves back.
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn a_roa_created_changed_and_deleted_moves_installed_routes_without_an_update() {
    let opts = Opts {
        fib_install: true,
        ..Opts::enforcing(None)
    };
    let s = Setup::start("o", 22, &opts, &FIRST);
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(ESTABLISH, &used);
    s.wait_for_used(Duration::from_secs(20), &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    let updates = s.updates_from_bird();
    let sessions = s.count("session established");
    assert!(s.route_lines().is_empty(), "{}", s.report());

    s.caches[0].set_vrps(&SECOND);
    let (used, held) = split_invalid(&FLIPPED);
    s.wait_for_states(CHANGE, &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    s.wait_for_used(Duration::from_secs(20), &used);
    // No UPDATE came from BIRD, and no session was reset.
    assert_eq!(s.updates_from_bird(), updates, "{}", s.report());
    assert_eq!(s.count("session established"), sessions, "{}", s.report());
    // One line per route that changed state, in prefix order, after the
    // summary line, which counts them.
    let moved = s.moved(&[
        ("192.0.2.0/24", "valid->invalid held by enforcement"),
        ("192.0.2.128/25", "invalid->valid best"),
        ("198.51.100.0/24", "invalid->not-found best"),
        ("203.0.113.0/24", "not-found->valid best"),
    ]);
    assert_eq!(s.route_lines(), moved, "{}", s.report());
    let summary = s.last_line("rib: validation states changed");
    assert!(
        summary.contains(" changed=4 ")
            && summary.ends_with(" held=1 released=2 logged=4 unlogged=0"),
        "{summary}"
    );
    assert_eq!(
        s.transitions(),
        (
            moved.clone(),
            "4 kept (most recent 1024); 0 not recorded".to_owned()
        ),
        "{}",
        s.report()
    );
    assert_eq!(
        s.http_transitions(),
        (moved.clone(), "0".to_owned()),
        "{}",
        s.http("/v1/rpki/transitions")
    );

    // The VRPs as they were: 192.0.2.0/24 is Valid again, and advertised
    // and installed again; the others move back too.
    s.caches[0].set_vrps(&FIRST);
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(CHANGE, &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    s.wait_for_used(Duration::from_secs(20), &used);
    assert_eq!(s.updates_from_bird(), updates, "{}", s.report());
    assert_eq!(s.count("session established"), sessions, "{}", s.report());
    let back = s.moved(&[
        ("192.0.2.0/24", "invalid->valid best"),
        ("192.0.2.128/25", "valid->invalid held by enforcement"),
        ("198.51.100.0/24", "not-found->invalid held by enforcement"),
        ("203.0.113.0/24", "valid->not-found best"),
    ]);
    let all: Vec<String> = moved.into_iter().chain(back).collect();
    assert_eq!(s.route_lines(), all, "{}", s.report());
    let summary = s.last_line("rib: validation states changed");
    assert!(
        summary.ends_with(" held=2 released=1 logged=4 unlogged=0"),
        "{summary}"
    );
    assert_eq!(
        s.transitions(),
        (all, "8 kept (most recent 1024); 0 not recorded".to_owned()),
        "{}",
        s.report()
    );
}
