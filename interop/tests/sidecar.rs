//! The Routinator sidecar of `bgpfcd` (AGENTS.md §9 step 14; issues #26,
//! #70, #71, #72): `rpki { mode sidecar; }` starts Routinator after the
//! privilege drop, wires the RTR client to it on loopback, supervises it,
//! and stops it, for routes from BIRD 2 (AGENTS.md §5, `interop/` row).
//!
//! Routinator itself never runs (AGENTS.md §5). A [`FakeRoutinator`]
//! stands in for it: a shell script that answers `--version` as Routinator
//! 0.15.2, records the arguments bgpfcd derives from the block, and then
//! becomes this crate's `rtr-stub` on the `--rtr` address, serving the VRPs
//! of `rpki.rs` under a new Session ID at each start, as a restarted
//! Routinator does (RFC 8210 §5.1, §8.3). bgpfcd runs as root with `--user
//! nobody`, as README's Option B: it refuses to run Routinator as root, and
//! Routinator is born as `nobody` with no capabilities.
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird`, `birdc`
//! and `curl` on `PATH`, and a built `bgpfcd`. CI runs them with
//! `--include-ignored` under sudo.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, FakeRoutinator, Lab, NOBODY, NeighborOpts, RtrStub,
    start_bgpfcd, wait_for,
};

const BGPFC_AS: u32 = 65_000;
const BIRD_AS: u32 = 65_001;
const ESTABLISH: Duration = Duration::from_secs(40);
/// bgpfcd's HTTP API, inside its namespace.
const HTTP: &str = "127.0.0.1:8179";

/// The routes BIRD originates, as in `rpki.rs`.
const ROUTES: [&str; 4] = [
    "192.0.2.0/24",
    "192.0.2.128/25",
    "198.51.100.0/24",
    "203.0.113.0/24",
];

/// The VRPs the fake Routinator serves, `rpki.rs`'s `FIRST`: (prefix, max
/// length, origin AS).
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

/// The states before the first full set, or without validation.
const DISABLED: [(&str, &str); 4] = [
    ("192.0.2.0/24", "disabled"),
    ("192.0.2.128/25", "disabled"),
    ("198.51.100.0/24", "disabled"),
    ("203.0.113.0/24", "disabled"),
];

/// The lines bgpfcd logs while it lost its cache: none of them may appear
/// when it stops the client before Routinator.
const LOST: [&str; 2] = [
    "msg=\"rtr lost the cache",
    "msg=\"rtr cache connection lost\"",
];

/// What a scenario runs.
struct Opts {
    /// Statements for the `rpki` block, after `mode sidecar`.
    rpki: &'static str,
    /// Statements for the `sidecar` block, after its binary and
    /// repository directory.
    sidecar: &'static str,
    /// The import policy for BIRD, `policy NAME { ... }`; `None` accepts
    /// everything.
    import: Option<&'static str>,
    /// Whether BIRD in B originates [`ROUTES`] to bgpfcd.
    bird: bool,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            rpki: "",
            sidecar: "",
            import: None,
            bird: true,
        }
    }
}

/// bgpfcd in A, run with `--user nobody` and `rpki { mode sidecar; }`
/// with a [`FakeRoutinator`]; BIRD in B sends it [`ROUTES`].
struct Setup {
    fake: FakeRoutinator,
    bgpfcd: Daemon,
    bird: Option<Bird>,
    socket: PathBuf,
    /// When bgpfcd was started.
    started: Instant,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl Setup {
    /// Install the fake, let `prepare` set it up (a version, a delay,
    /// failing), then start BIRD and bgpfcd as `opts` says.
    fn start(tag: &str, subnet: u8, opts: &Opts, prepare: impl FnOnce(&FakeRoutinator)) -> Setup {
        let lab = Lab::new(tag, subnet);
        let fake = FakeRoutinator::install(&lab, &FIRST);
        prepare(&fake);
        let bird = opts.bird.then(|| start_bird(&lab));
        let socket = lab.dir.join("ctl.sock");
        let config = bgpfcd_opts(
            &lab,
            &socket,
            &fake.block(opts.rpki, opts.sidecar),
            opts,
            true,
        );
        let ns_a = lab.a.clone();
        let started = Instant::now();
        let bgpfcd = start_bgpfcd(&lab, &ns_a, &config);
        Setup {
            fake,
            bgpfcd,
            bird,
            socket,
            started,
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

    /// `show rpki`.
    fn rpki(&self) -> String {
        self.ctl(&["show", "rpki"]).0
    }

    /// Wait up to `timeout` for `show rpki` to have every line of `lines`;
    /// what it said.
    fn wait_for_rpki(&self, timeout: Duration, lines: &[&str]) -> String {
        let mut out = String::new();
        assert!(
            wait_for(timeout, || {
                out = self.rpki();
                lines.iter().all(|l| out.contains(l))
            }),
            "not {lines:?} in:\n{out}\n{}",
            self.report()
        );
        out
    }

    /// Where the sidecar serves RTR, as `show rpki` says: `sidecar rtr
    /// ADDR, ...`.
    fn rtr(&self) -> String {
        let out = self.rpki();
        out.lines()
            .find_map(|l| l.strip_prefix("sidecar rtr "))
            .and_then(|rest| rest.split(',').next())
            .unwrap_or_else(|| panic!("no sidecar rtr line:\n{out}"))
            .to_owned()
    }

    /// What `show routes` says about each route it uses: its prefix and
    /// validation state, sorted.
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

    /// Wait up to `timeout` for `show routes` to give the routes `states`.
    fn wait_for_states(&self, timeout: Duration, states: &[(&str, &str)]) {
        let want = pairs(states);
        assert!(
            wait_for(timeout, || self.states() == want),
            "not {want:?}\n{}",
            self.report()
        );
    }

    /// The prefixes `show fib` lists, installed or pending (the FIB is in
    /// dry-run here), sorted.
    fn fib(&self) -> Vec<String> {
        let (out, _) = self.ctl(&["show", "fib"]);
        let mut fib: Vec<String> = out
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().next())
            .map(str::to_owned)
            .collect();
        fib.sort();
        fib
    }

    /// The routes `show routes held` lists: prefix, validation state and
    /// what holds it, sorted.
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

    /// Wait up to five seconds for the fake to have been started `n`
    /// times, and no more.
    fn wait_for_starts(&self, n: usize) {
        assert!(
            wait_for(Duration::from_secs(5), || self.fake.invocations().len()
                >= n),
            "{}",
            self.report()
        );
        assert_eq!(self.fake.invocations().len(), n, "{}", self.report());
    }

    /// Where bgpfcd first logged `text`, as an offset into its log.
    fn first(&self, text: &str) -> Option<usize> {
        self.bgpfcd.log_text().find(text)
    }

    /// Everything a failed assertion needs.
    fn report(&self) -> String {
        let bird = self
            .bird
            .as_ref()
            .map_or(String::new(), |b| b.daemon.log_text());
        format!(
            "{:?}\n--- invocations ---\n{:?}\n--- bgpfcd ---\n{}\n--- bird ---\n{bird}",
            self.states(),
            self.fake.invocations(),
            self.bgpfcd.log_text(),
        )
    }
}

/// BIRD in B, which originates [`ROUTES`] and waits for bgpfcd to connect.
fn start_bird(lab: &Lab) -> Bird {
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
            protocol: String::new(),
        },
    )
}

/// bgpfcd's configuration: BIRD as its neighbor, the control socket and
/// the HTTP API, `rpki` as the `rpki` block and the import policy of
/// `opts`; started with `--user nobody` if `drop_root` says so.
fn bgpfcd_opts(lab: &Lab, socket: &Path, rpki: &str, opts: &Opts, drop_root: bool) -> BgpfcdOpts {
    let from_bird = NeighborOpts {
        import: opts.import.map_or_else(
            || "ANY".to_owned(),
            |p| p.split_whitespace().nth(1).unwrap_or_default().to_owned(),
        ),
        ..NeighborOpts::new(lab.b_addr, BIRD_AS)
    };
    let mut bgpfcd_opts = BgpfcdOpts::single(BGPFC_AS, lab.a_addr, from_bird);
    bgpfcd_opts.extra = format!(
        "control {{ socket {}; http {{ listen {HTTP}; }} }}\n{rpki}\n{}",
        socket.display(),
        opts.import.unwrap_or_default(),
    );
    if drop_root {
        bgpfcd_opts.args = vec!["--user".to_owned(), "nobody".to_owned()];
    }
    bgpfcd_opts
}

/// `states` as owned pairs, sorted.
fn pairs(states: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut p: Vec<(String, String)> = states
        .iter()
        .map(|(p, s)| ((*p).to_owned(), (*s).to_owned()))
        .collect();
    p.sort();
    p
}

/// The prefixes of `states`, sorted.
fn prefixes(states: &[(&str, &str)]) -> Vec<String> {
    let mut p: Vec<String> = states.iter().map(|(p, _)| (*p).to_owned()).collect();
    p.sort();
    p
}

/// Routes and their validation states: (prefix, state).
type States<'a> = Vec<(&'a str, &'a str)>;

/// `states` split into those of the routes `enforcement drop-invalid`
/// uses, which `show routes` lists, and those of the routes it holds: the
/// Invalid ones (RFC 6811 §5).
fn split_invalid<'a>(states: &[(&'a str, &'a str)]) -> (States<'a>, States<'a>) {
    states.iter().partition(|(_, rov)| *rov != "invalid")
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

/// Whether process `pid` is alive: there, and not a zombie. An orphan
/// that died waits as a zombie until whatever adopted it reaps it, which
/// a container's init may do late.
fn alive(pid: u32) -> bool {
    let state = proc_status(pid, "State");
    !state.is_empty() && !state.starts_with('Z')
}

/// The `Name:` line of `/proc/PID/status`, without its name.
fn proc_status(pid: u32, name: &str) -> String {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

impl Setup {
    /// RFC 8210 §9 and issue #71: the sidecar's RTR port is open on
    /// loopback, at `rtr`, and on no other address, so B is refused.
    fn assert_loopback_only(&self, rtr: &str, port: u16) {
        let mut ss = self.lab.exec(&self.lab.a, "ss");
        ss.args(["-ltnH"]);
        let listeners = String::from_utf8_lossy(&ss.output().expect("ss").stdout).into_owned();
        let on_port: Vec<&str> = listeners
            .lines()
            .filter_map(|l| l.split_whitespace().nth(3))
            .filter(|local| local.ends_with(&format!(":{port}")))
            .collect();
        assert_eq!(on_port, [rtr], "{listeners}");
        let mut curl = self.lab.exec(&self.lab.b, "curl");
        curl.args([
            "-s",
            "--max-time",
            "3",
            &format!("http://{}:{port}/", self.lab.a_addr),
        ]);
        // 7: "Failed to connect to host".
        assert_eq!(curl.status().expect("curl").code(), Some(7));
    }

    /// Stop bgpfcd with `SIGTERM` and check that it stopped the client
    /// before Routinator, whose process `pid` is, so that the client never
    /// reported the cache lost, and that Routinator was not started again
    /// and left nothing running (issue #70).
    fn stop_in_order(&mut self, pid: u32) {
        let starts = self.fake.invocations().len();
        assert!(
            self.bgpfcd.terminate(Duration::from_secs(20)),
            "{}",
            self.report()
        );
        let log = self.bgpfcd.log_text();
        let at = |text: &str| {
            log.find(text)
                .unwrap_or_else(|| panic!("no `{text}`:\n{log}"))
        };
        let shutting = at("msg=\"shutting down\"");
        let stopping = at("msg=\"stopping the RPKI sidecar\"");
        let stopped = at("msg=\"RPKI sidecar stopped\"");
        assert!(
            shutting < stopping && stopping < stopped && stopped < at("msg=\"bgpfcd stopped\""),
            "{log}"
        );
        for lost in LOST {
            assert!(!log[shutting..].contains(lost), "{lost}:\n{log}");
        }
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(self.fake.invocations().len(), starts, "{}", self.report());
        assert_eq!(self.fake.serving(), Vec::<u32>::new());
        assert!(!alive(pid), "{pid} still runs");
    }
}

/// Routinator, whose process `pid` is, was started after the privilege
/// drop: it runs as `nobody`, with no capability at all, neither
/// effective, permitted nor ambient (issue #70; m14 design §4.1).
fn assert_started_after_the_drop(pid: u32) {
    let nobody = format!("{NOBODY}\t{NOBODY}\t{NOBODY}\t{NOBODY}");
    assert_eq!(proc_status(pid, "Uid"), nobody);
    assert_eq!(proc_status(pid, "Gid"), nobody);
    for caps in ["CapEff", "CapPrm", "CapAmb"] {
        assert_eq!(proc_status(pid, caps), "0000000000000000", "{caps}");
    }
}

/// Issues #26, #71 and #72: `rpki { mode sidecar; }` with a few
/// Routinator settings starts Routinator with the arguments derived from
/// them, the escape hatches passed through verbatim, after the privilege
/// drop, so that it runs as `nobody` with no capabilities. The RTR client
/// connects to it on a loopback port bgpfcd picked, which no other host
/// can reach (RFC 8210 §9), with no cache configured; BIRD's routes are
/// validated with its VRPs, and the Invalid ones held by the default
/// `drop-invalid`. A `SIGTERM` stops the client, then Routinator, which is
/// not restarted (issue #70), and leaves no process behind.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn the_sidecar_is_started_wired_and_validates() {
    let opts = Opts {
        sidecar: "accept-arin-rpa yes; global-args \"--strict\"; server-args \"--rtr-tcp-keepalive=30\";",
        ..Opts::default()
    };
    let mut s = Setup::start("sa", 26, &opts, |_| {});
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(ESTABLISH, &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());

    // The arguments bgpfcd derived, on a port it picked: 0 in the block,
    // so an unprivileged one.
    let rtr = s.rtr();
    let port: u16 = rtr
        .strip_prefix("127.0.0.1:")
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("{rtr}"));
    assert!(port >= 1024, "{rtr}");
    let repository = format!("--repository-dir={}", s.fake.repository.display());
    let rtr_arg = format!("--rtr={rtr}");
    assert_eq!(
        s.fake.invocations(),
        [vec![
            repository.as_str(),
            "--no-rir-tals",
            "--tal=afrinic",
            "--tal=apnic",
            "--tal=arin",
            "--tal=lacnic",
            "--tal=ripe",
            "--strict",
            "server",
            rtr_arg.as_str(),
            "--refresh=600",
            "--rtr-tcp-keepalive=30",
        ]],
        "{}",
        s.report()
    );
    assert_eq!(s.fake.version_checks(), 1);

    let pid = s.fake.pid().expect("the fake's pid");
    assert_eq!(s.fake.serving(), [pid]);
    assert_started_after_the_drop(pid);

    let out = s.wait_for_rpki(
        Duration::ZERO,
        &[
            "mode sidecar\nenforcement drop-invalid\nvalidation active\n",
            &format!("sidecar running pid {pid} for "),
            &format!(", routinator 0.15.2 ({})\n", s.fake.binary.display()),
            &format!("sidecar rtr {rtr}, restarts 0, failures 0\n"),
            &format!("cache {rtr} (sidecar) preference 0, in use, current\n"),
            "state idle, connected, version 1",
            "vrps ipv4 2 ipv6 0",
        ],
    );
    assert!(!out.contains("sidecar not running"), "{out}");
    let body = s.http("/v1/rpki");
    assert!(
        body.contains("\"mode\":\"sidecar\"")
            && body.contains("\"validation\":\"active\"")
            && body.contains(&format!(
                "\"state\":\"running\",\"alarm\":false,\"pid\":{pid},"
            ))
            && body.contains(&format!("\"rtr\":\"{rtr}\""))
            && body.contains("\"version\":\"0.15.2\""),
        "{body}"
    );

    s.assert_loopback_only(&rtr, port);

    // Issue #71: the wait for the first full set is said, then its end.
    let waiting = s
        .first("WARN  msg=\"rpki: no validation data yet; routes are used unvalidated until the first full set\" mode=sidecar enforcement=drop-invalid hint=")
        .unwrap_or_else(|| panic!("no waiting line:\n{}", s.report()));
    let arrived = s
        .first(
            "INFO  msg=\"rpki: validation data arrived; routes are validated from now on\" waited=",
        )
        .unwrap_or_else(|| panic!("no arrival line:\n{}", s.report()));
    assert!(waiting < arrived, "{}", s.report());

    s.stop_in_order(pid);
}

/// Issues #60 and #72: a sidecar that cannot run stops the start, loudly
/// and before any neighbor starts, as an external cache that cannot be
/// found does. A Routinator of another release is refused after its
/// `--version` and never started; a missing binary is named; and bgpfcd
/// as root without `--user` refuses to run Routinator at all, before it
/// even asks the binary its version.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn a_bad_sidecar_stops_the_start() {
    let lab = Lab::new("sb", 27);
    let fake = FakeRoutinator::install(&lab, &FIRST);
    let socket = lab.dir.join("ctl.sock");
    let opts = Opts {
        bird: false,
        ..Opts::default()
    };
    let ns_a = lab.a.clone();
    let run = |block: &str, drop_root: bool| {
        let mut bgpfcd = start_bgpfcd(
            &lab,
            &ns_a,
            &bgpfcd_opts(&lab, &socket, block, &opts, drop_root),
        );
        let status = bgpfcd.wait(Duration::from_secs(15));
        let log = bgpfcd.log_text();
        assert_eq!(status.and_then(|s| s.code()), Some(1), "{log}");
        assert!(!log.contains("session established"), "{log}");
        log
    };

    // Another release: refused once `--version` has told it.
    fake.set_version("Routinator 0.14.1");
    let log = run(&fake.block("", ""), true);
    assert!(
        log.contains("ERROR msg=\"cannot start rpki\" error=\"rpki sidecar: Routinator 0.14.1 is not supported: bgpfcd drives Routinator 0.15.x and was tested with 0.15.2\""),
        "{log}"
    );
    assert_eq!(fake.version_checks(), 1);
    assert_eq!(fake.invocations(), Vec::<Vec<String>>::new());
    fake.set_version("Routinator 0.15.2");

    // A binary that is not there.
    let missing = lab.dir.join("missing").join("routinator");
    let block = fake.block("", "").replace(
        &format!("binary \"{}\"", fake.binary.display()),
        &format!("binary \"{}\"", missing.display()),
    );
    assert!(block.contains(missing.to_str().expect("path")), "{block}");
    let log = run(&block, true);
    assert!(
        log.contains("ERROR msg=\"cannot start rpki\" error=\"rpki sidecar: ")
            && log.contains(missing.to_str().expect("path")),
        "{log}"
    );

    // Root without `--user`: refused before anything runs.
    let log = run(&fake.block("", ""), false);
    assert!(
        log.contains("ERROR msg=\"mode sidecar would run Routinator as root\" hint="),
        "{log}"
    );
    assert_eq!(fake.version_checks(), 1);
    assert_eq!(fake.invocations(), Vec::<Vec<String>>::new());
}

/// Issue #70: "killing the parent with SIGKILL leaves no orphan". bgpfcd
/// gets no chance to stop Routinator; the parent-death signal its
/// supervisor thread set ends it (`PR_SET_PDEATHSIG`), and its RTR port is
/// free again.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn sigkill_of_bgpfcd_leaves_no_orphan() {
    let opts = Opts {
        bird: false,
        ..Opts::default()
    };
    let mut s = Setup::start("sc", 28, &opts, |_| {});
    s.wait_for_rpki(ESTABLISH, &["validation active\n", "state idle, connected"]);
    let rtr = s.rtr();
    let pid = s.fake.pid().expect("the fake's pid");
    assert_eq!(s.fake.serving(), [pid]);

    s.bgpfcd.kill();
    assert!(
        wait_for(Duration::from_secs(5), || s.fake.serving().is_empty()),
        "{:?} still serving\n{}",
        s.fake.serving(),
        s.report()
    );
    assert!(!alive(pid), "{pid} still runs");
    // The port can be bound again: a stub listens on it.
    let ns_a = s.lab.a.clone();
    let _stub = RtrStub::start(&s.lab, &ns_a, &rtr, 9, &FIRST);
}

/// Issues #26 and #70: "killing Routinator results in a restart". The
/// supervisor starts it again with the same arguments, on the same
/// address, so the RTR client's own reconnect finds it with no special
/// case (#71); the restarted Routinator has a new Session ID and answers
/// the old session's Serial Query with a Cache Reset, and the client loads
/// its data afresh (RFC 8210 §8.3). Meanwhile the client keeps the data it
/// had (RFC 8210 §10, §6): no route changes state at any moment.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn a_killed_routinator_is_restarted_and_bgpfcd_resyncs() {
    let mut s = Setup::start("sd", 29, &Opts::default(), |_| {});
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(ESTABLISH, &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    let rtr = s.rtr();
    let pid = s.fake.pid().expect("the fake's pid");
    let session = format!("session-id {} serial 1\n", pid % 65_535 + 1);
    s.wait_for_rpki(Duration::ZERO, &["state idle, connected", &session]);
    let reachable = s.count("msg=\"rtr cache reachable again\"");
    let revalidations = s.count("msg=\"rib: validation states changed\"");

    let killed = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .expect("kill");
    assert!(killed.success());
    // Sampled until the client is back in sync with the new Routinator:
    // the routes keep their states, from the data the client held.
    let want = pairs(&used);
    let mut samples = Vec::new();
    let resynced = wait_for(Duration::from_secs(20), || {
        samples.push(s.states());
        s.count("msg=\"rtr cache reachable again\"") > reachable
            && s.fake.pid().is_some_and(|p| p != pid)
            && s.rpki().contains("state idle, connected")
    });
    assert!(resynced, "{}", s.report());
    assert!(samples.iter().all(|states| *states == want), "{samples:?}");

    // Restarted once, with the same arguments, at once.
    let starts = s.fake.invocations();
    assert_eq!(starts.len(), 2, "{}", s.report());
    assert_eq!(starts[1], starts[0]);
    assert!(starts[1].contains(&format!("--rtr={rtr}")), "{starts:?}");
    let restarted = s.first("msg=\"restarting the RPKI sidecar\"");
    assert!(restarted.is_some(), "{}", s.report());

    let new_pid = s.fake.pid().expect("the new pid");
    let session = format!("session-id {} serial 1\n", new_pid % 65_535 + 1);
    s.wait_for_rpki(
        Duration::from_secs(10),
        &[
            &format!("sidecar running pid {new_pid} for "),
            &format!("sidecar rtr {rtr}, restarts 1, "),
            ", last exit: killed by signal 9 (SIGKILL)\n",
            &format!("cache {rtr} (sidecar) preference 0, in use, current\n"),
            "state idle, connected",
            &session,
            "vrps ipv4 2 ipv6 0",
        ],
    );
    s.wait_for_log(
        Duration::ZERO,
        "msg=\"rtr cache cannot update incrementally; reloading\"",
    );
    assert_eq!(s.fake.serving(), [new_pid]);
    // The same VRPs again: nothing was validated anew, nothing moved.
    s.wait_for_states(Duration::ZERO, &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    assert_eq!(
        s.count("msg=\"rib: validation states changed\""),
        revalidations,
        "{}",
        s.report()
    );
    assert_eq!(s.count("session established"), 1, "{}", s.report());
    stop_with_routinator(&mut s, new_pid);
}

/// Issue #70: "restarting the child during our own shutdown is a bug".
/// `SIGTERM` reaches bgpfcd and Routinator, whose process `pid` is, at the
/// same moment, as systemd's default `KillMode=control-group` sends it:
/// bgpfcd, which stops Routinator right at the start of its shutdown,
/// starts no other, even past the restart back-off.
fn stop_with_routinator(s: &mut Setup, pid: u32) {
    let starts = s.fake.invocations().len();
    let both = Command::new("kill")
        .args(["-TERM", &s.bgpfcd.pid().to_string(), &pid.to_string()])
        .status()
        .expect("kill");
    assert!(both.success());
    assert!(
        s.bgpfcd.wait(Duration::from_secs(20)).is_some(),
        "{}",
        s.report()
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(s.fake.invocations().len(), starts, "{}", s.report());
    assert_eq!(s.fake.serving(), Vec::<u32>::new());
    let log = s.bgpfcd.log_text();
    let shutting = log
        .find("msg=\"shutting down\"")
        .unwrap_or_else(|| panic!("no shutdown:\n{log}"));
    assert!(
        !log[shutting..].contains("msg=\"restarting the RPKI sidecar\""),
        "{log}"
    );
    assert!(log[shutting..].contains("msg=\"bgpfcd stopped\""), "{log}");
}

/// Issue #70: "a persistently failing binary backs off rather than
/// spinning", and "repeated restart failures must surface as an
/// operational error, not just a log line". A Routinator that exits at
/// every start is started again at most every two seconds, the cap of
/// `restart-backoff 1 2`; from the third failure in a row it is an alarm
/// in `show rpki`, `show status` and their JSON, and an error in the log.
/// bgpfcd keeps routing meanwhile, every route `disabled`. Once the binary
/// starts again, the alarm clears and the routes are validated.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn a_routinator_that_keeps_failing_backs_off_and_raises_the_alarm() {
    let opts = Opts {
        rpki: "backoff 1 2;",
        sidecar: "restart-backoff 1 2; failure-threshold 3;",
        ..Opts::default()
    };
    let s = Setup::start("se", 30, &opts, |fake| fake.set_failing(true));
    s.wait_for_states(ESTABLISH, &DISABLED);

    // Backing off at the cap, which jitter may halve: at least one start
    // every two seconds after the first three, at most one a second, and
    // nothing like a loop.
    let twelve = s.started + Duration::from_secs(12);
    std::thread::sleep(twelve.saturating_duration_since(Instant::now()));
    let starts = s.fake.invocations().len();
    assert!((4..=15).contains(&starts), "{starts}\n{}", s.report());

    let out = s.wait_for_rpki(
        Duration::from_secs(10),
        &[
            "validation waiting ",
            "sidecar FAILED after ",
            " failures in a row, next attempt in ",
            ", last exit: exited with status 1\n",
        ],
    );
    assert!(!out.contains("sidecar running"), "{out}");
    let mut status = String::new();
    assert!(
        wait_for(Duration::from_secs(10), || {
            status = s.ctl(&["show", "status"]).0;
            status.contains("\nalarm rpki sidecar failed: ")
        }),
        "{status}"
    );
    assert!(
        status.contains("neighbors 1 established 1\n")
            && status.contains("rpki sidecar, validation waiting\n")
            && status.contains(" failures in a row\n"),
        "{status}"
    );
    let mut body = String::new();
    assert!(
        wait_for(Duration::from_secs(10), || {
            body = s.http("/v1/rpki");
            body.contains("\"state\":\"failed\",\"alarm\":true,")
        }),
        "{body}"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            body = s.http("/v1/status");
            body.contains("\"alarms\":[\"rpki-sidecar-failed\"]")
        }),
        "{body}"
    );
    s.wait_for_log(
        Duration::ZERO,
        "ERROR msg=\"RPKI sidecar keeps failing; the validator is not running, retrying at the backoff cap\"",
    );
    // Still routing: the one session, its routes used as received.
    s.wait_for_states(Duration::ZERO, &DISABLED);
    assert_eq!(s.count("session established"), 1, "{}", s.report());

    // A binary that works again: the next attempt runs, the alarm goes,
    // and the routes are validated.
    s.fake.set_failing(false);
    s.wait_for_rpki(
        Duration::from_secs(20),
        &[
            "validation active\n",
            "sidecar running pid ",
            "state idle, connected",
        ],
    );
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(Duration::from_secs(10), &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    let status = s.ctl(&["show", "status"]).0;
    assert!(
        status.contains("rpki sidecar, validation active\n") && !status.contains("alarm"),
        "{status}"
    );
    let body = s.http("/v1/status");
    assert!(body.contains("\"alarms\":[]"), "{body}");
    assert_eq!(s.count("session established"), 1, "{}", s.report());
}

/// Issue #71: "cold start converges without hanging and without silently
/// disabling enforcement". Routinator listens only after its first
/// validation run, twenty seconds here. bgpfcd does not wait for it: the
/// session comes up and BIRD's routes are used, best and in the FIB, as
/// `disabled` (RFC 6811 §2: no route leaves route selection for its state
/// unless configured to), and `show rpki` and `show status` say that
/// validation waits, as the log does at warn. Once the fake listens, the
/// client (`backoff 1 5`) finds it, every route is validated (RFC 6811 §4)
/// and `drop-invalid` takes the Invalid ones out of route selection and
/// the FIB.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn a_cold_sidecar_converges_without_hanging() {
    let opts = Opts {
        rpki: "backoff 1 5;",
        ..Opts::default()
    };
    let s = Setup::start("sf", 31, &opts, |fake| fake.set_delay(20));
    s.wait_for_states(ESTABLISH, &DISABLED);
    // Before the fake listens: it has not written its pid yet.
    assert_eq!(s.fake.pid(), None, "{}", s.report());
    assert!(s.started.elapsed() < Duration::from_secs(20));
    let (routes, _) = s.ctl(&["show", "routes"]);
    assert_eq!(
        routes
            .lines()
            .skip(1)
            .filter(|l| l.starts_with('*'))
            .count(),
        4,
        "{routes}"
    );
    assert_eq!(s.fib(), prefixes(&DISABLED), "{}", s.report());
    s.wait_for_rpki(Duration::ZERO, &["validation waiting "]);
    let (status, _) = s.ctl(&["show", "status"]);
    assert!(
        status.contains("rpki sidecar, validation waiting\n"),
        "{status}"
    );

    // The fake listens after its delay; the client finds it within its
    // back-off.
    assert!(
        wait_for(Duration::from_secs(30), || s.fake.pid().is_some()),
        "{}",
        s.report()
    );
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(Duration::from_secs(15), &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    assert!(
        wait_for(Duration::from_secs(10), || s.fib() == prefixes(&used)),
        "{:?}\n{}",
        s.fib(),
        s.report()
    );
    s.wait_for_rpki(Duration::ZERO, &["validation active\n"]);

    let waiting = s
        .first("WARN  msg=\"rpki: no validation data yet; routes are used unvalidated until the first full set\"")
        .unwrap_or_else(|| panic!("no waiting line:\n{}", s.report()));
    let arrived =
        "INFO  msg=\"rpki: validation data arrived; routes are validated from now on\" waited=";
    let at = s
        .first(arrived)
        .unwrap_or_else(|| panic!("no arrival line:\n{}", s.report()));
    assert!(waiting < at, "{}", s.report());
    let log = s.bgpfcd.log_text();
    let waited: u64 = log[at + arrived.len()..]
        .split(['s', '\n'])
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no waited= in:\n{log}"));
    assert!((20..40).contains(&waited), "waited={waited}s\n{log}");
    assert_eq!(s.count("session established"), 1, "{}", s.report());
}

/// m14 design §3.2: an operator who wants routes held until the first
/// full set writes `match rpki disabled; action reject;` first in the
/// import policy, and needs nothing else. While Routinator runs its first
/// validation, every route is held by policy and none is used; with the
/// first full set the policy is asked again, the Valid and `NotFound`
/// routes are used and `drop-invalid` holds the Invalid ones.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn unvalidated_routes_can_be_held_until_the_first_full_set() {
    let opts = Opts {
        rpki: "backoff 1 5;",
        import: Some(
            "policy GUARD {
                 term unvalidated { match rpki disabled; action reject; }
                 term rest { action accept; }
             }",
        ),
        ..Opts::default()
    };
    let s = Setup::start("sg", 32, &opts, |fake| fake.set_delay(20));
    let all_held = held_by(&DISABLED, "policy");
    assert!(
        wait_for(ESTABLISH, || s.held() == all_held),
        "{:?}\n{}",
        s.held(),
        s.report()
    );
    assert_eq!(s.fake.pid(), None, "{}", s.report());
    assert_eq!(s.states(), Vec::<(String, String)>::new());
    assert_eq!(s.fib(), Vec::<String>::new());
    let (routes, _) = s.ctl(&["show", "routes", "held"]);
    assert!(!routes.lines().any(|l| l.starts_with('*')), "{routes}");

    assert!(
        wait_for(Duration::from_secs(30), || s.fake.pid().is_some()),
        "{}",
        s.report()
    );
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(Duration::from_secs(15), &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    assert!(
        wait_for(Duration::from_secs(10), || s.fib() == prefixes(&used)),
        "{:?}\n{}",
        s.fib(),
        s.report()
    );
}

/// The `rpki` block of a running [`Setup`] reloaded: the configuration
/// file it started with, its `rpki` block replaced.
struct Reloader<'a> {
    s: &'a Setup,
    config: String,
    first: String,
}

impl Reloader<'_> {
    /// Write the file with `block` as its `rpki` block, and reload.
    fn reload(&self, block: &str) -> (String, bool) {
        fs::write(
            self.s.config_path(),
            self.config.replace(&self.first, block),
        )
        .expect("config");
        self.s.ctl(&["reload"])
    }
}

/// m14 design §5.2: a reload restarts only what changed. `enforcement`
/// alone touches neither the client nor Routinator; a client setting
/// restarts the client alone; a sidecar setting restarts Routinator, and
/// the data the client held covers its validation run (RFC 8210 §10);
/// a Routinator of another release fails the reload before anything
/// changes (issue #72); and the mode moves to `external`, back to
/// `sidecar` and to `disabled`, starting and stopping Routinator, with
/// the states kept across each move until the mode is `disabled`. The BGP
/// session is never reset.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn a_reload_restarts_only_what_changed_and_switches_modes() {
    let s = Setup::start("sh", 33, &Opts::default(), |_| {});
    let (used, _) = split_invalid(&VALIDATED);
    s.wait_for_states(ESTABLISH, &used);
    s.wait_for_rpki(
        Duration::ZERO,
        &["validation active\n", "state idle, connected"],
    );
    let config = fs::read_to_string(s.config_path()).expect("config");
    let first = s.fake.block("", "");
    assert!(config.contains(&first), "{config}");
    let r = Reloader {
        s: &s,
        config,
        first,
    };
    let restarted = reload_within_the_sidecar(&r);
    reload_across_modes(&r, &restarted);
    assert_eq!(s.count("session established"), 1, "{}", s.report());
}

/// Steps (a) to (d) of the reload walk, within `mode sidecar`; the block
/// in use at the end, with `prefer-valid`, `backoff 1 3` and `refresh
/// 300`.
fn reload_within_the_sidecar(r: &Reloader) -> String {
    let s = r.s;
    let pid = s.fake.pid().expect("the fake's pid");
    let clients = s.count("msg=\"rpki: starting the rtr client\"");

    // (a) `enforcement` alone: the RIB judges the routes again, with
    // nothing restarted. prefer-valid holds nothing.
    let (out, ok) = r.reload(&s.fake.block("enforcement prefer-valid;", ""));
    assert!(ok && out.contains("rpki enforcement prefer-valid"), "{out}");
    assert!(!out.contains("rpki: "), "{out}");
    s.wait_for_states(Duration::from_secs(10), &VALIDATED);
    assert_eq!(s.fake.invocations().len(), 1, "{}", s.report());
    assert_eq!(s.fake.serving(), [pid]);
    assert_eq!(s.count("msg=\"rpki: starting the rtr client\""), clients);

    // (b) A client setting: the client restarts, Routinator goes on.
    let client = "enforcement prefer-valid; backoff 1 3;";
    let (out, ok) = r.reload(&s.fake.block(client, ""));
    assert!(ok && out.contains("rpki: rtr client restarted"), "{out}");
    assert_eq!(
        s.count("msg=\"rpki: starting the rtr client\""),
        clients + 1
    );
    assert_eq!(s.fake.invocations().len(), 1, "{}", s.report());
    assert_eq!(s.fake.serving(), [pid]);
    s.wait_for_rpki(Duration::from_secs(10), &["state idle, connected"]);
    s.wait_for_states(Duration::ZERO, &VALIDATED);

    // (c) A sidecar setting: Routinator restarts with it, and takes five
    // seconds to listen; the held data keeps every state meanwhile.
    s.fake.set_delay(5);
    let restarted = s.fake.block(client, "refresh 300;");
    let (out, ok) = r.reload(&restarted);
    assert!(ok && out.contains("rpki: sidecar restarted"), "{out}");
    assert!(!alive(pid), "{pid} still runs");
    // The supervisor thread starts the child a moment after the reload.
    s.wait_for_starts(2);
    let starts = s.fake.invocations();
    assert!(
        starts[1].contains(&"--refresh=300".to_owned()),
        "{starts:?}"
    );
    let want = pairs(&VALIDATED);
    let mut samples = Vec::new();
    assert!(
        wait_for(Duration::from_secs(20), || {
            samples.push(s.states());
            s.fake.pid().is_some_and(|p| p != pid)
        }),
        "{}",
        s.report()
    );
    assert!(samples.len() > 4, "{samples:?}");
    assert!(samples.iter().all(|states| *states == want), "{samples:?}");
    let pid = s.fake.pid().expect("the new pid");
    let session = format!("session-id {} serial 1\n", pid % 65_535 + 1);
    s.wait_for_rpki(
        Duration::from_secs(15),
        &["state idle, connected", &session, "validation active\n"],
    );
    s.wait_for_states(Duration::ZERO, &VALIDATED);

    // (d) A Routinator of another release: the preflight's `--version`
    // fails the reload, and the running one goes on. The script itself
    // is unchanged, so the running supervisor checks nothing.
    s.fake.set_version("Routinator 0.14.1");
    let (out, ok) = r.reload(&s.fake.block(client, "refresh 301;"));
    assert!(
        !ok && out.contains("Routinator 0.14.1 is not supported"),
        "{out}"
    );
    s.wait_for_log(Duration::ZERO, "reload failed; running configuration kept");
    assert_eq!(s.fake.serving(), [pid]);
    assert_eq!(s.fake.invocations().len(), 2, "{}", s.report());
    s.fake.set_version("Routinator 0.15.2");
    s.wait_for_states(Duration::ZERO, &VALIDATED);
    restarted
}

/// Steps (e) to (g) of the reload walk: to `mode external`, back to
/// `mode sidecar` with `sidecar`, the block (c) left, and to `mode
/// disabled`.
fn reload_across_modes(r: &Reloader, sidecar: &str) {
    let s = r.s;
    // (e) To `mode external`, with a cache that serves the same VRPs:
    // Routinator stops, and the states stay as they were.
    let ns_a = s.lab.a.clone();
    let stub = RtrStub::start(&s.lab, &ns_a, "127.0.0.1:3323", 9, &FIRST);
    let (out, ok) = r.reload(
        "rpki { mode external; enforcement prefer-valid; backoff 1 3; cache 127.0.0.1 port 3323; }",
    );
    assert!(
        ok && out.contains("rpki: rtr client restarted; sidecar stopped"),
        "{out}"
    );
    assert_eq!(s.fake.serving(), Vec::<u32>::new());
    s.wait_for_rpki(
        Duration::from_secs(10),
        &[
            "cache 127.0.0.1:3323 preference 0, in use, current\n",
            "session-id 9 serial 1\n",
        ],
    );
    assert!(!s.rpki().contains("sidecar"), "{}", s.rpki());
    s.wait_for_states(Duration::ZERO, &VALIDATED);

    // (f) Back to `mode sidecar`: Routinator starts, and the external
    // cache's data covers its validation run, so nothing waits.
    let warned = s.count("msg=\"rpki: no validation data yet");
    let (out, ok) = r.reload(sidecar);
    assert!(ok && out.contains("rpki: sidecar started"), "{out}");
    s.wait_for_starts(3);
    let want = pairs(&VALIDATED);
    let mut samples = Vec::new();
    assert!(
        wait_for(Duration::from_secs(20), || {
            let rpki = s.rpki();
            samples.push((s.states(), rpki.contains("validation waiting")));
            rpki.contains("(sidecar) preference 0, in use, current\n")
                && rpki.contains("state idle, connected")
        }),
        "{}",
        s.report()
    );
    assert!(
        samples
            .iter()
            .all(|(states, waiting)| *states == want && !waiting),
        "{samples:?}"
    );
    assert_eq!(s.count("msg=\"rpki: no validation data yet"), warned);
    drop(stub);

    // (g) To `mode disabled`: Routinator stops, and every route is
    // `disabled` again.
    let pid = s.fake.pid().expect("the pid");
    assert_eq!(s.fake.serving(), [pid]);
    let (out, ok) = r.reload(&sidecar.replace("mode sidecar", "mode disabled"));
    assert!(
        ok && out.contains("rpki: validation disabled; sidecar stopped"),
        "{out}"
    );
    assert_eq!(s.fake.serving(), Vec::<u32>::new());
    s.wait_for_states(Duration::from_secs(10), &DISABLED);
    s.wait_for_rpki(Duration::ZERO, &["mode disabled\n", "validation off\n"]);
    assert_eq!(s.fake.invocations().len(), 3, "{}", s.report());
}

/// Issue #71 and `docs/config.md`, "Reload": a Routinator replaced, by one
/// of another release, between a reload's preflight and its start cannot
/// start. Validation is then off while `mode sidecar` is configured: `show
/// status` raises `rpki-sidecar-not-running` rather than list no alarm, and
/// `show rpki` says `sidecar not running`. A reload of the same file checks
/// the block again: it fails while the binary is still of the other
/// release, and starts Routinator once it is fixed, which clears the alarm.
/// The BGP session is never reset.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn a_sidecar_a_reload_could_not_start_raises_an_alarm_until_one_does() {
    let s = Setup::start("si", 34, &Opts::default(), |_| {});
    let (used, held) = split_invalid(&VALIDATED);
    s.wait_for_states(ESTABLISH, &used);
    s.wait_for_rpki(
        Duration::ZERO,
        &["validation active\n", "state idle, connected"],
    );
    let config = fs::read_to_string(s.config_path()).expect("config");
    let first = s.fake.block("", "");
    let r = Reloader {
        s: &s,
        config,
        first,
    };

    // The preflight asks the next `--version`; the start, right after it,
    // finds another release.
    s.fake
        .switch_version(s.fake.version_checks() + 2, "Routinator 0.14.1");
    let changed = s.fake.block("", "refresh 300;");
    let (out, ok) = r.reload(&changed);
    assert!(
        ok && out.contains(
            "rpki: cannot start the sidecar (rpki sidecar: Routinator 0.14.1 is not supported"
        ) && out.contains("); validation disabled"),
        "{out}"
    );
    assert_eq!(s.fake.serving(), Vec::<u32>::new());
    s.wait_for_states(Duration::from_secs(10), &DISABLED);
    s.wait_for_rpki(
        Duration::ZERO,
        &[
            "mode sidecar\n",
            "validation off\n",
            "sidecar not running\n",
        ],
    );
    let status = s.ctl(&["show", "status"]).0;
    assert!(
        status.contains(
            "rpki sidecar, validation off\nalarm rpki sidecar not running: validation is off\n"
        ),
        "{status}"
    );
    let body = s.http("/v1/status");
    assert!(
        body.contains("\"alarms\":[\"rpki-sidecar-not-running\"]"),
        "{body}"
    );

    // The same file again: the block is checked again, and the reload
    // fails while the binary is of the other release.
    let (out, ok) = r.reload(&changed);
    assert!(
        !ok && out.contains("Routinator 0.14.1 is not supported"),
        "{out}"
    );
    assert_eq!(s.fake.serving(), Vec::<u32>::new());
    assert_eq!(s.fake.invocations().len(), 1, "{}", s.report());

    // Fixed: the same file starts it, and the alarm goes.
    s.fake.set_version("Routinator 0.15.2");
    let (out, ok) = r.reload(&changed);
    assert!(ok && out.contains("rpki: sidecar started"), "{out}");
    s.wait_for_rpki(
        Duration::from_secs(20),
        &[
            "validation active\n",
            "sidecar running pid ",
            "state idle, connected",
        ],
    );
    s.wait_for_states(Duration::from_secs(10), &used);
    assert_eq!(s.held(), held_by(&held, "enforcement"), "{}", s.report());
    let status = s.ctl(&["show", "status"]).0;
    assert!(
        status.contains("rpki sidecar, validation active\n") && !status.contains("alarm"),
        "{status}"
    );
    let starts = s.fake.invocations();
    assert_eq!(starts.len(), 2, "{}", s.report());
    assert!(
        starts[1].contains(&"--refresh=300".to_owned()),
        "{starts:?}"
    );
    assert_eq!(s.count("session established"), 1, "{}", s.report());
}
