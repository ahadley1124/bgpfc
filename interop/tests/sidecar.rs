//! The Routinator sidecar of `bgpfcd` (AGENTS.md §9 step 14) with BIRD 2
//! as the neighbor whose routes are validated. A script stands in for
//! Routinator (`StubRoutinator`): it answers `--version` and as `server`
//! becomes this crate's `rtr-stub`, a cache of RFC 8210, on the address
//! `bgpfcd` hands it. No real Routinator takes part (AGENTS.md §5,
//! `bgpfc-sidecar` row); the supervision, the command line and the
//! loopback RTR wiring are what is under test, and the validation that
//! follows from the VRPs is the same as with any other cache.
//!
//! The scenario: the cache's listener comes up eight seconds after the
//! child starts, as Routinator's does after its first validation run, so every
//! route is `disabled` until `bgpfcd`'s client finds it; with `invalid
//! drop` the Invalid routes then leave the candidates; a child killed from
//! outside is restarted, and its cache, a new session of the same VRPs,
//! brings the client back in sync without moving a route; a reload that
//! changes the `routinator` block runs a new child that serves other VRPs,
//! and the routes move with no UPDATE from BIRD; and a shutdown leaves no
//! child.
//!
//! The test is `#[ignore]`: it needs root, `iproute2`, `bird` and `birdc`
//! on `PATH`, and a built `bgpfcd`. CI runs it with `--include-ignored`
//! under sudo.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, Lab, NeighborOpts, StubRoutinator, start_bgpfcd, wait_for,
};

const BGPFC_AS: u32 = 65_000;
const BIRD_AS: u32 = 65_001;
const ESTABLISH: Duration = Duration::from_secs(40);
/// How long bgpfcd may take to find a cache that comes up late: the
/// stub's eight seconds, and a client that retries after one to a few
/// seconds more, up to the 30 s of a sidecar's default back-off.
const LATE: Duration = Duration::from_secs(60);
/// How long a restarted child, or a changed set of VRPs, may take to
/// reach the routes.
const CHANGE: Duration = Duration::from_secs(30);
/// The RTR address of the sidecar, inside bgpfcd's namespace.
const RTR: &str = "127.0.0.1:3323";

/// The routes BIRD originates.
const ROUTES: [&str; 4] = [
    "192.0.2.0/24",
    "192.0.2.128/25",
    "198.51.100.0/24",
    "203.0.113.0/24",
];

/// The VRPs the cache serves first: (prefix, max length, origin AS).
const FIRST: [(&str, u8, u32); 2] = [
    ("192.0.2.0/24", 24, BIRD_AS),
    ("198.51.100.0/24", 24, 64_999),
];

/// What `invalid drop` leaves of BIRD's routes with [`FIRST`]: the Valid
/// 192.0.2.0/24 and the not-found 203.0.113.0/24. The /25 is longer than
/// the VRP's max length and 198.51.100.0/24 is for another origin AS: both
/// are Invalid (RFC 6811 §2, RFC 9319 §3), and held, not used.
const KEPT: [(&str, &str); 2] = [("192.0.2.0/24", "valid"), ("203.0.113.0/24", "not-found")];

/// VRPs that change the state of every route: 192.0.2.0/24 now for another
/// AS, the /25 authorised, 198.51.100.0/24 gone, 203.0.113.0/24 new.
const SECOND: [(&str, u8, u32); 3] = [
    ("192.0.2.0/24", 24, 64_999),
    ("192.0.2.128/25", 25, BIRD_AS),
    ("203.0.113.0/24", 24, BIRD_AS),
];

/// What `invalid drop` leaves with [`SECOND`].
const FLIPPED: [(&str, &str); 3] = [
    ("192.0.2.128/25", "valid"),
    ("198.51.100.0/24", "not-found"),
    ("203.0.113.0/24", "valid"),
];

/// Every route, before the cache has sent anything (issue #52).
const DISABLED: [(&str, &str); 4] = [
    ("192.0.2.0/24", "disabled"),
    ("192.0.2.128/25", "disabled"),
    ("198.51.100.0/24", "disabled"),
    ("203.0.113.0/24", "disabled"),
];

/// bgpfcd's `rpki` block: a sidecar on [`RTR`] that restarts after a
/// second, and `invalid drop`. The client's back-off is the sidecar's
/// default.
fn rpki_block(stub: &StubRoutinator, refresh: u32) -> String {
    format!(
        "rpki {{ mode sidecar; invalid drop;\n\
         routinator {{ binary {}; repository-dir {}; rtr-listen {RTR};\n\
         refresh {refresh}; restart-backoff 1 1; }} }}\n",
        stub.binary.display(),
        stub.repository.display()
    )
}

struct Setup {
    stub: StubRoutinator,
    bgpfcd: Daemon,
    bird: Bird,
    socket: PathBuf,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl Setup {
    /// BIRD and a bgpfcd with a sidecar whose cache comes up `delay`
    /// seconds after the child starts, serving [`FIRST`].
    fn start(delay: u32) -> Setup {
        let lab = Lab::new("sc", 28);
        let ns_a = lab.a.clone();
        // A listener that comes up late, as Routinator's does, after the
        // session and BIRD's routes.
        let stub = StubRoutinator::new(&lab, delay, &FIRST);
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
        let mut opts =
            BgpfcdOpts::single(BGPFC_AS, lab.a_addr, NeighborOpts::new(lab.b_addr, BIRD_AS));
        opts.extra = format!(
            "control {{ socket {}; }}\n{}",
            socket.display(),
            rpki_block(&stub, 300)
        );
        let bgpfcd = start_bgpfcd(&lab, &ns_a, &opts);
        Setup {
            stub,
            bgpfcd,
            bird,
            socket,
            lab,
        }
    }

    fn config_path(&self) -> PathBuf {
        self.lab.dir.join(format!("bgpfcd-{}.conf", self.lab.a))
    }

    fn ctl(&self, args: &[&str]) -> (String, bool) {
        interop::bgpfcctl(&self.socket, args)
    }

    /// What `show routes` says about each route: its prefix and its
    /// validation state.
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

    /// Wait up to `timeout` for `show routes` to give exactly `states`.
    fn wait_for_states(&self, timeout: Duration, states: &[(&str, &str)]) {
        let want: Vec<(String, String)> = states
            .iter()
            .map(|(p, s)| ((*p).to_owned(), (*s).to_owned()))
            .collect();
        assert!(
            wait_for(timeout, || self.states() == want),
            "wanted {want:?}, have {:?}\n{}",
            self.states(),
            self.report()
        );
    }

    /// Wait up to `timeout` for `show rpki` to satisfy `done`.
    fn wait_for_rpki(&self, timeout: Duration, done: impl Fn(&str) -> bool) -> String {
        let mut out = String::new();
        assert!(
            wait_for(timeout, || {
                out = self.ctl(&["show", "rpki"]).0;
                done(&out)
            }),
            "{out}\n{}",
            self.report()
        );
        out
    }

    /// The child's process id, once `show rpki` has it running.
    fn child(&self) -> u32 {
        let out = self.wait_for_rpki(CHANGE, |out| out.contains("sidecar state running, pid "));
        pid_of(&out)
    }

    /// The process id of the running child, once it is not `old`.
    fn child_after(&self, old: u32) -> u32 {
        let out = self.wait_for_rpki(CHANGE, |out| {
            out.contains("sidecar state running, pid ") && pid_of(out) != old
        });
        pid_of(&out)
    }

    /// How many UPDATEs bgpfcd has taken from BIRD.
    fn updates_from_bird(&self) -> usize {
        self.bgpfcd
            .log_text()
            .matches(&format!("msg=\"rib: update\" peer={} ", self.lab.b_addr))
            .count()
    }

    fn report(&self) -> String {
        format!(
            "{:?}\n--- bgpfcd ---\n{}\n--- bird ---\n{}",
            self.states(),
            self.bgpfcd.log_text(),
            self.bird.daemon.log_text()
        )
    }
}

/// The process id in `sidecar state running, pid N, up Ms`.
fn pid_of(shown: &str) -> u32 {
    let line = shown
        .lines()
        .find(|l| l.starts_with("sidecar state running, pid "))
        .unwrap_or_else(|| panic!("no running sidecar:\n{shown}"));
    line["sidecar state running, pid ".len()..]
        .split(',')
        .next()
        .and_then(|pid| pid.parse().ok())
        .unwrap_or_else(|| panic!("no process id in {line}"))
}

/// Whether process `pid` runs: it has a `/proc` entry and is not a zombie.
fn alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let (_, rest) = stat.rsplit_once(')')?;
            rest.trim_start().chars().next()
        })
        .is_some_and(|state| state != 'Z')
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn a_sidecar_serves_the_vrps_and_is_supervised() {
    let mut s = Setup::start(8);
    // The child runs at once and the cache is not there yet: BIRD's routes
    // arrive and nobody has validated them.
    s.wait_for_states(ESTABLISH, &DISABLED);
    let first = s.child();
    let shown = s.wait_for_rpki(CHANGE, |out| out.contains("sidecar state running"));
    for line in [
        "mode sidecar",
        "invalid drop",
        "sidecar restarts 0 failures 0",
        "vrps none yet: every route is disabled",
    ] {
        assert!(shown.contains(line), "{line}:\n{shown}");
    }
    assert!(
        shown.contains(&format!(
            "sidecar routinator 0.15.2 {}, rtr {RTR}",
            s.stub.binary.display()
        )),
        "{shown}"
    );

    // The cache comes up, the client finds it on the sidecar's address, and
    // `invalid drop` keeps the Invalid routes out of the candidates.
    s.wait_for_states(LATE, &KEPT);
    let shown = s.wait_for_rpki(CHANGE, |out| {
        out.contains("state idle, connected, version 1")
            && out.contains(&format!("vrps ipv4 2 ipv6 0 from {RTR}"))
            && out.contains("failures 0")
    });
    assert!(shown.contains("session-id 1 "), "{shown}");
    // Routinator's command line is in the log, as the child's output.
    let log = s.bgpfcd.log_text();
    for arg in [
        "sidecar=routinator",
        &format!("--repository-dir={}", s.stub.repository.display()),
        "--no-rir-tals --tal=afrinic --tal=apnic --tal=lacnic --tal=ripe",
        &format!("server --rtr={RTR} --refresh=300"),
    ] {
        assert!(log.contains(arg), "no `{arg}`:\n{log}");
    }

    // The child is killed from outside. The supervisor starts another,
    // which is a new session of the cache (RFC 8210 §5.1): the client's
    // Serial Query for the old one is answered with a Cache Reset
    // (§8.3), and it loads the VRPs again. Nothing moves meanwhile: the
    // data stays in use (§6).
    let updates = s.updates_from_bird();
    let status = Command::new("kill")
        .args(["-KILL", &first.to_string()])
        .status()
        .expect("kill");
    assert!(status.success());
    assert_eq!(s.states(), KEPT.map(|(p, r)| (p.to_owned(), r.to_owned())));
    let second = s.child_after(first);
    s.wait_for_rpki(LATE, |out| {
        out.contains("sidecar restarts 1 ")
            && out.contains("state idle, connected, version 1")
            && out.contains("session-id 2 ")
    });
    assert!(!alive(first));
    s.wait_for_states(CHANGE, &KEPT);
    assert_eq!(s.updates_from_bird(), updates, "no UPDATE moved a route");

    // Other VRPs, and a reload that changes the block: a new child serves
    // them, and the routes move with no UPDATE from BIRD (RFC 6811 §4).
    s.stub.set_vrps(&SECOND);
    let path = s.config_path();
    let text = fs::read_to_string(&path).expect("config");
    assert!(text.contains("refresh 300;"), "{text}");
    fs::write(&path, text.replace("refresh 300;", "refresh 200;")).expect("config");
    let (out, ok) = s.ctl(&["reload"]);
    assert!(
        ok && out.contains("rpki: sidecar and rtr client restarted"),
        "{out}\n{}",
        s.report()
    );
    assert!(!alive(second), "the old child was stopped by the reload");
    s.wait_for_states(LATE, &FLIPPED);
    let third = s.child();
    assert_ne!(third, second);
    assert_eq!(s.updates_from_bird(), updates, "no UPDATE moved a route");

    // A shutdown stops the child along with the sessions.
    assert!(
        s.bgpfcd.terminate(Duration::from_secs(30)),
        "bgpfcd did not stop:\n{}",
        s.report()
    );
    assert!(!alive(third), "the child outlived the daemon");
    let log = s.bgpfcd.log_text();
    assert!(log.contains("msg=\"RPKI sidecar stopped\""), "{log}");
}
