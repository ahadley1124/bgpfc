//! Route origin validation in `bgpfcd` (RFC 6811) with VRPs over RTR
//! (RFC 8210) from `StayRTR`, an independent RTR cache, for routes from
//! BIRD 2 (AGENTS.md §5, `interop/` row). Nothing acts on the states yet
//! (AGENTS.md §9, step 13), so every route is accepted and relayed
//! whatever its state.
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird`, `birdc`,
//! `curl` and `stayrtr` on `PATH`, and a built `bgpfcd`. CI runs them with
//! `--include-ignored` under sudo.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, Lab, NeighborOpts, StayRtr, start_bgpfcd, wait_for,
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

/// The states without validation (issue #52).
const DISABLED: [(&str, &str); 4] = [
    ("192.0.2.0/24", "disabled"),
    ("192.0.2.128/25", "disabled"),
    ("198.51.100.0/24", "disabled"),
    ("203.0.113.0/24", "disabled"),
];

/// What a scenario runs.
struct Opts {
    /// This many `StayRTR` caches, at the first [`CACHES`], in that order
    /// of preference.
    caches: usize,
    /// The `mode` of the `rpki` block.
    mode: &'static str,
    /// Whether a second BIRD, in C, takes the routes from bgpfcd.
    relay: bool,
}

/// BIRD in B sends its routes to bgpfcd in A, which validates them with
/// the VRPs of the caches beside it, and may pass them on to a second
/// BIRD in C.
struct Setup {
    /// The `StayRTR` caches, in order of preference.
    caches: Vec<StayRtr>,
    bgpfcd: Daemon,
    bird: Bird,
    relay: Option<Bird>,
    socket: PathBuf,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl Setup {
    /// Start what `opts` asks for, every cache serving `vrps`.
    fn start(tag: &str, subnet: u8, opts: &Opts, vrps: &[(&str, u8, u32)]) -> Setup {
        let mut lab = Lab::new(tag, subnet);
        let ns_a = lab.a.clone();
        let binds = &CACHES[..opts.caches];
        let caches = binds
            .iter()
            .map(|bind| StayRtr::start(&lab, &ns_a, bind, vrps))
            .collect();
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
        let mut entries = String::new();
        for (preference, bind) in binds.iter().enumerate() {
            let port = bind.rsplit(':').next().unwrap_or(bind);
            let _ = write!(
                entries,
                " cache 127.0.0.1 port {port} preference {preference};"
            );
        }
        // The shortest back-off, so that a cache that comes back is found
        // within a second or two.
        bgpfcd_opts.extra = format!(
            "control {{ socket {}; http {{ listen {HTTP}; }} }}\n\
             rpki {{ mode {};{entries} backoff 1 1; }}",
            socket.display(),
            opts.mode
        );
        let bgpfcd = start_bgpfcd(&lab, &ns_a, &bgpfcd_opts);
        Setup {
            caches,
            bgpfcd,
            bird,
            relay,
            socket,
            lab,
        }
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

    /// How many UPDATEs bgpfcd has taken from BIRD.
    fn updates_from_bird(&self) -> usize {
        self.count(&format!("msg=\"rib: update\" peer={} ", self.lab.b_addr))
    }

    /// Everything a failed assertion needs.
    fn report(&self) -> String {
        let caches: Vec<String> = self.caches.iter().map(|c| c.daemon.log_text()).collect();
        format!(
            "{:?}\n--- bgpfcd ---\n{}\n--- cache ---\n{}\n--- bird ---\n{}",
            self.states(),
            self.bgpfcd.log_text(),
            caches.join("\n--- cache ---\n"),
            self.bird.daemon.log_text()
        )
    }
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
        caches: 1,
        mode: "external",
        relay: true,
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
    s.caches[0].set_vrps(&SECOND);
    s.wait_for_states(CHANGE, &FLIPPED);
    s.wait_for_log(Duration::ZERO, "changed=4");
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

/// With `mode disabled` every route reads `disabled`, and bgpfcd never
/// connects to the cache the block still lists.
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn with_mode_disabled_no_cache_is_asked() {
    let opts = Opts {
        caches: 1,
        mode: "disabled",
        relay: false,
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

/// The preferred of two caches goes away for good: bgpfcd warns, keeps
/// its VRPs (RFC 8210 §10) and moves to the other cache, whose full set
/// replaces them. Then a reload to `mode disabled` and back.
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn the_vrps_outlive_their_cache_and_follow_a_reload() {
    let opts = Opts {
        caches: 2,
        mode: "external",
        relay: false,
    };
    let mut s = Setup::start("w", 19, &opts, &FIRST);
    s.wait_for_states(ESTABLISH, &VALIDATED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.contains("cache 127.0.0.1:3323 preference 0, in use")
            && out.contains("cache 127.0.0.1:3324 preference 1\n"),
        "{out}"
    );
    // A warning, and the VRPs stay in use while bgpfcd tries the cache
    // again and then the other one, whose full set replaces them (an info
    // line when in sync again).
    s.caches[0].daemon.kill();
    s.wait_for_log(
        RECONNECT,
        "WARN  msg=\"rtr lost the cache; serving the last data while reconnecting\"",
    );
    s.wait_for_states(Duration::ZERO, &VALIDATED);
    s.wait_for_log(RECONNECT, "INFO  msg=\"rtr cache reachable again\"");
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.contains("cache 127.0.0.1:3324 preference 1, in use")
            && out.contains("state idle, connected"),
        "{out}"
    );
    // The same VRPs from the other cache: no state changed.
    s.wait_for_states(Duration::ZERO, &VALIDATED);

    // A reload to `mode disabled` turns validation off for every route,
    // and one back to `mode external` brings the states back.
    let cfg_path = s.lab.dir.join(format!("bgpfcd-{}.conf", s.lab.a));
    let external = fs::read_to_string(&cfg_path).unwrap();
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
