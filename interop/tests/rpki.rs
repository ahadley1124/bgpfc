//! Route origin validation in `bgpfcd` (RFC 6811) with VRPs from
//! `StayRTR`, an independent RTR cache (RFC 8210), for routes from BIRD 2
//! (AGENTS.md §5, `interop/` row).
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird`, `birdc`
//! and `stayrtr` on `PATH`, and a built `bgpfcd`. CI runs them with
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
const ESTABLISH: Duration = Duration::from_secs(40);
/// The caches: RFC 8210 §9, unprotected TCP, so they run on the router's
/// own loopback.
const CACHES: [&str; 2] = ["127.0.0.1:3323", "127.0.0.1:3324"];

/// VRPs for two of BIRD's three routes, all of which it originates: one
/// for its AS, one for another.
const FIRST: [(&str, u8, u32); 2] = [
    ("192.0.2.0/24", 24, BIRD_AS),
    ("198.51.100.0/24", 24, 64_999),
];

/// [`FIRST`] and one for the third route.
const SECOND: [(&str, u8, u32); 3] = [
    ("192.0.2.0/24", 24, BIRD_AS),
    ("198.51.100.0/24", 24, 64_999),
    ("203.0.113.0/24", 24, BIRD_AS),
];

/// BIRD in B sends its routes to bgpfcd in A, which validates them with
/// the VRPs of one or more `StayRTR` caches beside it.
struct Setup {
    /// In order of preference.
    caches: Vec<StayRtr>,
    bgpfcd: Daemon,
    bird: Bird,
    socket: PathBuf,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl Setup {
    /// `caches` of the [`CACHES`], all serving `vrps`.
    fn start(tag: &str, subnet: u8, caches: usize, vrps: &[(&str, u8, u32)]) -> Setup {
        let lab = Lab::new(tag, subnet);
        let ns_a = lab.a.clone();
        let caches: Vec<StayRtr> = CACHES[..caches]
            .iter()
            .map(|bind| StayRtr::start(&lab, &ns_a, bind, vrps))
            .collect();
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
                statics: ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
                    .map(str::to_owned)
                    .to_vec(),
                channel: String::new(),
                protocol: String::new(),
            },
        );
        let socket = lab.dir.join("ctl.sock");
        let mut opts =
            BgpfcdOpts::single(BGPFC_AS, lab.a_addr, NeighborOpts::new(lab.b_addr, BIRD_AS));
        let mut entries = String::new();
        for (preference, bind) in CACHES[..caches.len()].iter().enumerate() {
            let port = bind.rsplit(':').next().unwrap_or(bind);
            let _ = write!(
                entries,
                " cache 127.0.0.1 port {port} preference {preference};"
            );
        }
        opts.extra = format!(
            "control {{ socket {}; }}\nrpki {{ mode external;{entries} }}",
            socket.display()
        );
        let bgpfcd = start_bgpfcd(&lab, &ns_a, &opts);
        Setup {
            caches,
            bgpfcd,
            bird,
            socket,
            lab,
        }
    }

    fn ctl(&self, args: &[&str]) -> (String, bool) {
        interop::bgpfcctl(&self.socket, args)
    }

    /// What `show routes` says about each route: its prefix and its
    /// validation state.
    fn states(&self) -> Vec<(String, String)> {
        let (out, _) = self.ctl(&["show", "routes"]);
        out.lines()
            .skip(1)
            .filter_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                Some((
                    words.first()?.trim_start_matches('*').to_owned(),
                    (*words.get(5)?).to_owned(),
                ))
            })
            .collect()
    }

    /// Wait up to `timeout` for the routes to have `states`.
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
    }

    /// Wait up to `timeout` for bgpfcd to log `line`.
    fn wait_for_log(&self, timeout: Duration, line: &str) {
        assert!(
            wait_for(timeout, || self.bgpfcd.log_text().contains(line)),
            "no `{line}`:\n{}",
            self.report()
        );
    }

    /// Everything a failed assertion needs.
    fn report(&self) -> String {
        let caches: Vec<String> = self.caches.iter().map(|c| c.daemon.log_text()).collect();
        format!(
            "{:?}\n--- bgpfcd ---\n{}\n--- stayrtr ---\n{}\n--- bird ---\n{}",
            self.states(),
            self.bgpfcd.log_text(),
            caches.join("\n--- stayrtr ---\n"),
            self.bird.daemon.log_text()
        )
    }
}

/// The states with [`FIRST`]: RFC 6811 §2 Matched, Covered but not
/// Matched, not Covered.
const VALIDATED: [(&str, &str); 3] = [
    ("192.0.2.0/24", "valid"),
    ("198.51.100.0/24", "invalid"),
    ("203.0.113.0/24", "not-found"),
];

/// The states with [`SECOND`].
const UPDATED: [(&str, &str); 3] = [
    ("192.0.2.0/24", "valid"),
    ("198.51.100.0/24", "invalid"),
    ("203.0.113.0/24", "valid"),
];

#[test]
#[ignore = "needs root, bird, stayrtr and iproute2"]
fn routes_are_validated_against_the_vrps_of_stayrtr() {
    let s = Setup::start("v", 15, 1, &FIRST);
    s.wait_for_states(ESTABLISH, &VALIDATED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    for line in [
        "mode external",
        "cache 127.0.0.1:3323 preference 0, in use",
        "state idle, connected, version 1",
        "vrps ipv4 2 ipv6 0",
    ] {
        assert!(ok && out.contains(line), "{line}:\n{out}");
    }
    let (out, ok) = s.ctl(&["show", "rpki", "validate", "198.51.100.0/24", "AS65001"]);
    assert!(
        ok && out.contains("198.51.100.0/24 origin AS65001: invalid")
            && out.contains("  198.51.100.0/24-24 AS64999\n"),
        "{out}"
    );
    // A new VRP: StayRTR sends a Serial Notify, bgpfcd asks for the
    // changes (RFC 8210 §8.2), and the route it covers is validated again
    // (RFC 6811 §4).
    s.caches[0].set_vrps(&SECOND);
    s.wait_for_states(Duration::from_secs(20), &UPDATED);
    s.wait_for_log(Duration::ZERO, "changes=not-found->valid:1");
    assert_eq!(
        s.bgpfcd.log_text().matches("session established").count(),
        1,
        "{}",
        s.report()
    );
}

#[test]
#[ignore = "needs root, bird, stayrtr and iproute2"]
fn the_vrps_outlive_their_cache_and_follow_a_reload() {
    let mut s = Setup::start("w", 16, 2, &SECOND);
    s.wait_for_states(ESTABLISH, &UPDATED);
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.contains("cache 127.0.0.1:3323 preference 0, in use")
            && out.contains("cache 127.0.0.1:3324 preference 1\n"),
        "{out}"
    );
    // The preferred cache goes away: a warning, and its VRPs stay in use
    // (RFC 8210 §10) while bgpfcd tries it again and then the other cache,
    // whose full set replaces them (an info line when in sync again).
    // NOTE(interop): a second cache, because one StayRTR restarted would
    // not do. It comes back with a new Session ID and closes the
    // connection on the Serial Query bgpfcd resumes with (RFC 8210 §8.1),
    // without the Error Report §5.1 requires, so bgpfcd, like BIRD 2.14,
    // keeps its VRPs and asks again until they expire (§6).
    s.caches[0].daemon.kill();
    s.wait_for_log(
        Duration::from_secs(10),
        "WARN  msg=\"rtr lost the cache; serving the last data while reconnecting\"",
    );
    s.wait_for_states(Duration::ZERO, &UPDATED);
    s.wait_for_log(
        Duration::from_secs(30),
        "INFO  msg=\"rtr cache reachable again\"",
    );
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(
        ok && out.contains("cache 127.0.0.1:3324 preference 1, in use")
            && out.contains("state idle, connected"),
        "{out}"
    );
    // The same VRPs from the other cache: no state changed.
    s.wait_for_states(Duration::ZERO, &UPDATED);

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
    s.wait_for_states(
        Duration::from_secs(10),
        &[
            ("192.0.2.0/24", "disabled"),
            ("198.51.100.0/24", "disabled"),
            ("203.0.113.0/24", "disabled"),
        ],
    );
    let (out, ok) = s.ctl(&["show", "rpki"]);
    assert!(ok && out.starts_with("mode disabled\n"), "{out}");
    fs::write(&cfg_path, &external).unwrap();
    let (out, ok) = s.ctl(&["reload"]);
    assert!(ok && out.contains("rpki: rtr client started"), "{out}");
    s.wait_for_states(Duration::from_secs(20), &UPDATED);
    // None of this touched the BGP session.
    assert_eq!(
        s.bgpfcd.log_text().matches("session established").count(),
        1,
        "{}",
        s.report()
    );
}
