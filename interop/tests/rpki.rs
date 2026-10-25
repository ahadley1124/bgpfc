//! Route origin validation in `bgpfcd` (RFC 6811) with VRPs over RTR
//! (RFC 8210) from `StayRTR`, an independent RTR cache, for routes from
//! BIRD 2 (AGENTS.md §5, `interop/` row). These scenarios test the RTR
//! transport and the states it gives the routes, so their `rpki` blocks
//! say `enforcement off;` (RFC 8481 §5, "Set State, Don't Act"): every
//! route is accepted and relayed whatever its state, and the state moves
//! nothing but itself. Without it the default, `drop-invalid`, would hold
//! the Invalid routes back.
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
use std::path::PathBuf;
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
    /// Whether a second BIRD, in C, takes the routes from bgpfcd.
    relay: bool,
}

impl Opts {
    /// `caches` with `mode external`, nothing else.
    fn external(caches: Caches) -> Opts {
        Opts {
            caches,
            backup: None,
            unanswered: false,
            mode: "external",
            relay: false,
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
        let relay = opts.relay.then(|| {
            let ns_c = lab.add_c();
            Bird::start(
                &lab,
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
                    statics: Vec::new(),
                    channel: String::new(),
                    protocol: String::new(),
                },
            )
        });
        let bird = Bird::start(
            &lab,
            &lab.b.clone(),
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
                protocol: String::new(),
            },
        );
        let socket = lab.dir.join("ctl.sock");
        let mut bgpfcd_opts =
            BgpfcdOpts::single(BGPFC_AS, lab.a_addr, NeighborOpts::new(lab.b_addr, BIRD_AS));
        if opts.relay {
            // RFC 4271 §9.2.1.1 pacing, shortened from the 30 s EBGP
            // default so that the routes reach the relay quickly.
            let mut to_relay = NeighborOpts::new(lab.c_addr, RELAY_AS);
            to_relay.advertisement_interval = Some(1);
            bgpfcd_opts.neighbors.push(to_relay);
            bgpfcd_opts.listen.push(lab.a2_addr.into());
        }
        let unanswered = opts.unanswered.then(|| lab.blackhole());
        bgpfcd_opts.extra = format!(
            "control {{ socket {}; http {{ listen {HTTP}; }} }}\n{}",
            socket.display(),
            rpki_block(opts.mode, binds, unanswered)
        );
        let bgpfcd = start_bgpfcd(&lab, &ns_a, &bgpfcd_opts);
        Setup {
            caches,
            stub,
            bgpfcd,
            bird,
            relay,
            socket,
            unanswered,
            lab,
        }
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

    /// Everything a failed assertion needs.
    fn report(&self) -> String {
        let mut caches: Vec<String> = self.caches.iter().map(|c| c.daemon.log_text()).collect();
        caches.extend(self.stub.iter().map(|s| s.daemon.log_text()));
        format!(
            "{:?}\n--- bgpfcd ---\n{}\n--- cache ---\n{}\n--- bird ---\n{}",
            self.states(),
            self.bgpfcd.log_text(),
            caches.join("\n--- cache ---\n"),
            self.bird.daemon.log_text()
        )
    }
}

/// The `rpki` block for the caches at `binds`, in that order of
/// preference, after the one at `unanswered` if there is one, with
/// `enforcement off`: the states are shown and acted on by nothing.
fn rpki_block(mode: &str, binds: &[&str], unanswered: Option<Ipv4Addr>) -> String {
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
    // The shortest back-off, so that a cache that comes back is found
    // within a second or two.
    format!("rpki {{ mode {mode}; enforcement off;{entries} backoff 1 1; }}")
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
        relay: true,
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
        ok && out == "mode disabled\ncache 127.0.0.1:3323 preference 0\n",
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
