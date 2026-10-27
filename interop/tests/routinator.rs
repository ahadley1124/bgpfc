//! The real Routinator as the sidecar of `bgpfcd` (AGENTS.md §5,
//! `interop/` row; README, "Routinator sidecar"): `rpki { mode sidecar; }`
//! with the Routinator 0.15 package's `/usr/bin/routinator`, where
//! `sidecar.rs` runs a fake. It shows what no fake can: that the release
//! bgpfcd accepts takes the command line bgpfcd derives, starts, serves
//! RTR where bgpfcd wires its client, and goes, with whatever it started,
//! when bgpfcd stops.
//!
//! No network is needed. Routinator validates a [`LocalRpki`], a
//! repository the test signs with `openssl` and publishes with `rsync` on
//! loopback in bgpfcd's namespace, which has no route off the lab. The
//! block also names every TAL Routinator bundles, so that each `--tal`
//! bgpfcd passes is one this Routinator knows (it exits on one it does
//! not); their repositories cannot be reached from the namespace, so each
//! of them fails at once and adds nothing.
//!
//! As in `sidecar.rs`, bgpfcd runs as root with `--user nobody` (README,
//! Option B), BIRD originates its routes, and the test is `#[ignore]`:
//! it needs root, `iproute2`, `bird`, `birdc`, `curl`, `openssl`, `rsync`,
//! a built `bgpfcd` and Routinator 0.15 at `/usr/bin/routinator`. CI
//! installs it from `packages.nlnetlabs.nl` (`.github/workflows/ci.yml`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, LOCAL_RPKI_BASE, Lab, LocalRpki, NOBODY, NeighborOpts,
    start_bgpfcd, wait_for,
};

const BGPFC_AS: u32 = 65_000;
const BIRD_AS: u32 = 65_001;
/// Routinator's first validation run takes about a second here; the rest
/// is the RTR client's back-off while Routinator does not listen yet.
const ESTABLISH: Duration = Duration::from_secs(60);
/// Where the Routinator package installs it, the default `binary`.
const ROUTINATOR: &str = "/usr/bin/routinator";

/// The routes BIRD originates, as in `rpki.rs` and `sidecar.rs`.
const ROUTES: [&str; 4] = [
    "192.0.2.0/24",
    "192.0.2.128/25",
    "198.51.100.0/24",
    "203.0.113.0/24",
];

/// The ROAs of the local repository, as the VRPs the fake of `sidecar.rs`
/// serves: (prefix, max length, origin AS).
const ROAS: [(&str, u8, u32); 2] = [
    ("192.0.2.0/24", 24, BIRD_AS),
    ("198.51.100.0/24", 24, 64_999),
];

/// What RFC 6811 §2 makes of BIRD's routes with [`ROAS`]: Matched;
/// Covered, but longer than the max length (RFC 9319 §3); Covered for
/// another origin AS; not Covered.
const VALIDATED: [(&str, &str); 4] = [
    ("192.0.2.0/24", "valid"),
    ("192.0.2.128/25", "invalid"),
    ("198.51.100.0/24", "invalid"),
    ("203.0.113.0/24", "not-found"),
];

/// Every TAL Routinator 0.15 bundles, as bgpfcd passes them for the block
/// of [`Run::start`]: the RIR TALs, ARIN's with its agreement accepted,
/// then the test beds the block names (`routinator --tal=list`).
const BUNDLED_TALS: [&str; 9] = [
    "afrinic",
    "apnic",
    "arin",
    "lacnic",
    "ripe",
    "apnic-testbed",
    "arin-ote",
    "ripe-pilot",
    "nlnetlabs-testbed",
];

/// What `routinator --version` says this Routinator is: `0.15.3`, say.
///
/// # Panics
/// If it is not installed or says something else.
fn routinator_version() -> String {
    let out = Command::new(ROUTINATOR)
        .arg("--version")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "running {ROUTINATOR} --version: {e}; install Routinator 0.15 from \
                 packages.nlnetlabs.nl"
            )
        });
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.split_whitespace()
        .nth(1)
        .filter(|_| text.starts_with("Routinator "))
        .unwrap_or_else(|| panic!("{ROUTINATOR} --version said {text:?}"))
        .to_owned()
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

/// Whether process `pid` is alive: there, and not a zombie.
fn alive(pid: u32) -> bool {
    let state = proc_status(pid, "State");
    !state.is_empty() && !state.starts_with('Z')
}

/// The processes of process group `pgid` that are alive, by the fifth
/// field of `/proc/PID/stat`, after the command in parentheses.
fn group(pgid: u32) -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| {
            fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(") ")
                    .and_then(|(_, rest)| rest.split_whitespace().nth(2)?.parse::<u32>().ok())
                    == Some(pgid)
            })
        })
        .filter(|&pid| alive(pid))
        .collect()
}

/// The command line of process `pid`, an argument each.
fn cmdline(pid: u32) -> Vec<String> {
    fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

/// The running Routinator, as `show rpki` names it.
struct Sidecar {
    /// Its process.
    pid: u32,
    /// Where it serves RTR: `127.0.0.1:PORT`.
    rtr: String,
    /// The port of `rtr`.
    port: u16,
}

/// bgpfcd in A, with `--user nobody` and the real Routinator as its
/// sidecar on a [`LocalRpki`] in A; BIRD in B sends it [`ROUTES`].
struct Run {
    bgpfcd: Daemon,
    _bird: Bird,
    rpki: LocalRpki,
    socket: PathBuf,
    /// Routinator's config file.
    config: PathBuf,
    /// The repository directory of the block.
    repository: PathBuf,
    /// The repository directory of the config file, which bgpfcd's
    /// command line replaces.
    ignored: PathBuf,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl Run {
    /// Publish the local repository, start BIRD, and start bgpfcd with a
    /// block that sets every option bgpfcd derives Routinator's command
    /// line from: the config file, the TALs (all nine bundled ones and a
    /// directory), the refresh, and both escape hatches.
    fn start() -> Run {
        let lab = Lab::new("rr", 37);
        let rpki = LocalRpki::publish(&lab, &lab.a, &ROAS);
        let bird = start_bird(&lab);
        // Routinator's directory belongs to nobody, so that bgpfcd,
        // dropped to nobody, can create the repository directory in it.
        let dir = lab.dir.join("real-routinator");
        fs::create_dir_all(&dir).expect("routinator dir");
        std::os::unix::fs::chown(&dir, Some(NOBODY), Some(NOBODY)).expect("chown routinator dir");
        // Routinator wants a config file to name a repository directory,
        // which the command line's replaces; and it takes the loopback
        // host name of the local repository only when allowed (manual
        // page, `--allow-dubious-hosts`).
        let ignored = dir.join("ignored-repository");
        let config = lab.dir.join("routinator.conf");
        fs::write(
            &config,
            format!(
                "repository-dir = \"{}\"\nallow-dubious-hosts = true\n",
                ignored.display()
            ),
        )
        .expect("routinator.conf");
        let repository = dir.join("repository");
        let socket = lab.dir.join("ctl.sock");
        let block = format!(
            "rpki {{ mode sidecar; sidecar {{ binary \"{ROUTINATOR}\"; repository-dir \"{}\"; \
             accept-arin-rpa yes; tals apnic-testbed arin-ote ripe-pilot nlnetlabs-testbed; \
             extra-tals-dir \"{}\"; refresh 60; config-file \"{}\"; global-args \"--strict\"; \
             server-args \"--rtr-tcp-keepalive=30\"; }} }}",
            repository.display(),
            rpki.tals.display(),
            config.display()
        );
        let mut opts =
            BgpfcdOpts::single(BGPFC_AS, lab.a_addr, NeighborOpts::new(lab.b_addr, BIRD_AS));
        opts.extra = format!("control {{ socket {}; }}\n{block}", socket.display());
        opts.args = vec!["--user".to_owned(), "nobody".to_owned()];
        let ns_a = lab.a.clone();
        let bgpfcd = start_bgpfcd(&lab, &ns_a, &opts);
        Run {
            bgpfcd,
            _bird: bird,
            rpki,
            socket,
            config,
            repository,
            ignored,
            lab,
        }
    }

    fn ctl(&self, args: &[&str]) -> String {
        interop::bgpfcctl(&self.socket, args).0
    }

    /// `ss` in A with `args`: its output.
    fn ss(&self, args: &[&str]) -> String {
        let mut cmd = self.lab.exec(&self.lab.a, "ss");
        cmd.args(args);
        String::from_utf8_lossy(&cmd.output().expect("ss").stdout).into_owned()
    }

    /// What `show routes` says about each route it uses: its prefix and
    /// validation state, sorted.
    fn states(&self) -> Vec<(String, String)> {
        let mut states: Vec<(String, String)> = self
            .ctl(&["show", "routes"])
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

    /// The routes `show routes held` lists: prefix, validation state and
    /// what holds it, sorted.
    fn held(&self) -> Vec<(String, String, String)> {
        let mut held: Vec<(String, String, String)> = self
            .ctl(&["show", "routes", "held"])
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

    /// Everything a failed assertion needs.
    fn report(&self) -> String {
        format!(
            "{}\n--- bgpfcd ---\n{}\n--- rsyncd ---\n{}",
            self.ctl(&["show", "rpki"]),
            self.bgpfcd.log_text(),
            self.rpki.rsyncd.log_text()
        )
    }

    /// Wait for the RTR client to sync with Routinator: the two VRPs of
    /// the local repository, over RTR version 1 (RFC 8210 §7), from the
    /// sidecar's address and nothing else. `show rpki` names the
    /// Routinator `version` says, which bgpfcd's version check accepted
    /// (issue #72).
    fn wait_for_sync(&self, version: &str) -> Sidecar {
        let mut out = String::new();
        assert!(
            wait_for(ESTABLISH, || {
                out = self.ctl(&["show", "rpki"]);
                out.contains("validation active\n")
                    && out.contains("state idle, connected, version 1")
                    && out.contains("vrps ipv4 2 ipv6 0")
            }),
            "{}",
            self.report()
        );
        let pid: u32 = out
            .lines()
            .find_map(|l| l.strip_prefix("sidecar running pid "))
            .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
            .unwrap_or_else(|| panic!("no running sidecar:\n{}", self.report()));
        let rtr = out
            .lines()
            .find_map(|l| l.strip_prefix("sidecar rtr "))
            .and_then(|rest| rest.split(',').next())
            .unwrap_or_else(|| panic!("no sidecar rtr line:\n{out}"))
            .to_owned();
        let port: u16 = rtr
            .strip_prefix("127.0.0.1:")
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("{rtr}"));
        for line in [
            "mode sidecar\nenforcement drop-invalid\nstartup accept\nvalidation active\n"
                .to_owned(),
            format!("sidecar running pid {pid} for "),
            format!(", routinator {version} ({ROUTINATOR})\n"),
            format!("sidecar rtr {rtr}, restarts 0, failures 0\n"),
            format!("cache {rtr} (sidecar) preference 0, in use, current\n"),
        ] {
            assert!(out.contains(&line), "no {line:?} in:\n{out}");
        }
        let found = format!(
            "INFO  msg=\"found a supported Routinator\" binary={ROUTINATOR} version={version} \
             rtr={rtr}\n"
        );
        assert!(self.bgpfcd.log_text().contains(&found), "{}", self.report());
        Sidecar { pid, rtr, port }
    }

    /// Issue #72: Routinator runs with the command line bgpfcd derived,
    /// and took every part of it: each bundled TAL by its name, the local
    /// one, the command line's repository directory over the config
    /// file's, and `rsync` from the local repository.
    fn assert_command_line_taken(&self, s: &Sidecar) {
        let mut expected = vec![
            ROUTINATOR.to_owned(),
            format!("--config={}", self.config.display()),
            format!("--repository-dir={}", self.repository.display()),
            "--no-rir-tals".to_owned(),
        ];
        expected.extend(BUNDLED_TALS.iter().map(|t| format!("--tal={t}")));
        expected.extend([
            format!("--extra-tals-dir={}", self.rpki.tals.display()),
            "--strict".to_owned(),
            "server".to_owned(),
            format!("--rtr={}", s.rtr),
            "--refresh=60".to_owned(),
            "--rtr-tcp-keepalive=30".to_owned(),
        ]);
        assert_eq!(cmdline(s.pid), expected, "{}", self.report());
        assert_eq!(
            fs::read_link(format!("/proc/{}/exe", s.pid))
                .ok()
                .as_deref(),
            Some(Path::new(ROUTINATOR))
        );
        // Routinator tried each bundled TAL and, with no route off the
        // lab, found no trust anchor, which it says on its standard
        // error, logged with `sidecar=routinator`; it knew every name.
        let log = self.bgpfcd.log_text();
        for tal in BUNDLED_TALS {
            let said = format!("No valid trust anchor for TAL {tal}\" sidecar=routinator");
            assert!(log.contains(&said), "no `{said}`:\n{log}");
        }
        assert!(!log.contains("Unknown TAL"), "{log}");
        // It fetched the trust anchor certificate and the publication
        // point of the local repository with `rsync`, into the command
        // line's repository directory, not the config file's: its cache
        // of rsync URIs, by host and path.
        let fetched = self.repository.join("rsync").join(
            LOCAL_RPKI_BASE
                .strip_prefix("rsync://")
                .expect("an rsync URI"),
        );
        for file in [
            "ta/ta.cer",
            "repo/ta.mft",
            "repo/ta.crl",
            "repo/roa-0.roa",
            "repo/roa-1.roa",
        ] {
            assert!(
                fetched.join(file).is_file(),
                "{file} not fetched into {}:\n{}",
                fetched.display(),
                self.report()
            );
        }
        assert!(!self.ignored.exists());
    }

    /// RFC 8210 §9 and issue #71: Routinator listens on the loopback port
    /// bgpfcd picked, and nowhere else, so B cannot connect to it; and
    /// bgpfcd's connection to it probes with TCP keep-alive while idle in
    /// sync.
    fn assert_wired_on_loopback(&self, s: &Sidecar) {
        assert!(s.port >= 1024, "{}", s.rtr);
        let listeners = self.ss(&["-ltnpH"]);
        let on_port: Vec<&str> = listeners
            .lines()
            .filter(|l| {
                l.split_whitespace()
                    .nth(3)
                    .is_some_and(|local| local.ends_with(&format!(":{}", s.port)))
            })
            .collect();
        assert_eq!(on_port.len(), 1, "{listeners}");
        assert_eq!(on_port[0].split_whitespace().nth(3), Some(s.rtr.as_str()));
        assert!(
            on_port[0].contains(&format!("(\"routinator\",pid={},", s.pid)),
            "{listeners}"
        );
        let mut curl = self.lab.exec(&self.lab.b, "curl");
        curl.args([
            "-s",
            "--max-time",
            "3",
            &format!("http://{}:{}/", self.lab.a_addr, s.port),
        ]);
        // 7: "Failed to connect to host".
        assert_eq!(curl.status().expect("curl").code(), Some(7));
        let dport = format!(":{}", s.port);
        let mut sockets = String::new();
        assert!(
            wait_for(Duration::from_secs(5), || {
                sockets = self.ss(&[
                    "-tnoH",
                    "state",
                    "established",
                    "(",
                    "dport",
                    "=",
                    &dport,
                    ")",
                ]);
                sockets.lines().count() == 1 && sockets.contains("timer:(keepalive,")
            }),
            "{sockets}"
        );
    }

    /// BIRD's routes, validated with Routinator's VRPs; the Invalid ones
    /// held by the default `drop-invalid` (RFC 6811 §5).
    fn assert_routes_validated(&self) {
        let (used, invalid): (Vec<_>, Vec<_>) =
            VALIDATED.iter().partition(|(_, s)| *s != "invalid");
        let mut want: Vec<(String, String)> = used
            .iter()
            .map(|(p, s)| ((*p).to_owned(), (*s).to_owned()))
            .collect();
        want.sort();
        assert!(
            wait_for(ESTABLISH, || self.states() == want),
            "not {want:?}: {:?}\n{}",
            self.states(),
            self.report()
        );
        let mut held: Vec<(String, String, String)> = invalid
            .iter()
            .map(|(p, s)| ((*p).to_owned(), (*s).to_owned(), "enforcement".to_owned()))
            .collect();
        held.sort();
        assert_eq!(self.held(), held, "{}", self.report());
    }

    /// Issue #70: a `SIGTERM` stops the client, which never reports the
    /// cache lost, then Routinator, which is not started again; neither it
    /// nor anything it started runs on, and its port is closed.
    fn stop(&mut self, s: &Sidecar) {
        assert!(
            self.bgpfcd.terminate(Duration::from_secs(30)),
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
        for lost in [
            "msg=\"rtr lost the cache",
            "msg=\"rtr cache connection lost\"",
        ] {
            assert!(!log[shutting..].contains(lost), "{lost}:\n{log}");
        }
        assert_eq!(
            log.matches("msg=\"rpki: starting the routinator sidecar\"")
                .count(),
            1,
            "{log}"
        );
        assert!(!alive(s.pid), "Routinator {} still runs", s.pid);
        assert_eq!(group(s.pid), Vec::<u32>::new(), "its process group runs on");
        let listeners = self.ss(&["-ltnH"]);
        assert!(!listeners.contains(&format!(":{} ", s.port)), "{listeners}");
    }
}

/// Issues #26, #70, #71 and #72 with the real Routinator: bgpfcd checks
/// its version and accepts it, starts it after the privilege drop with the
/// command line it derives from a block that sets every option it derives
/// one from, and Routinator takes all of it: it validates the local
/// repository, `--strict`, and serves RTR on the loopback port bgpfcd
/// picked, to nobody else. The RTR client, wired to it with no cache
/// configured, syncs over RTR version 1 with keep-alive on (RFC 8210 §7,
/// §9) and validates BIRD's routes with its VRPs; the Invalid ones are
/// held by the default `drop-invalid`. A `SIGTERM` stops the client,
/// then Routinator, which is not started again and leaves no process and
/// no listener behind.
#[test]
#[ignore = "needs root, routinator 0.15, openssl, rsync, bird, curl and iproute2"]
fn the_real_routinator_is_started_wired_and_validates() {
    let version = routinator_version();
    let mut run = Run::start();
    let sidecar = run.wait_for_sync(&version);
    run.assert_command_line_taken(&sidecar);
    // Issue #70: started after the privilege drop, as nobody with no
    // capability at all, neither effective, permitted nor ambient.
    let nobody = format!("{NOBODY}\t{NOBODY}\t{NOBODY}\t{NOBODY}");
    assert_eq!(proc_status(sidecar.pid, "Uid"), nobody);
    assert_eq!(proc_status(sidecar.pid, "Gid"), nobody);
    for caps in ["CapEff", "CapPrm", "CapAmb"] {
        assert_eq!(proc_status(sidecar.pid, caps), "0000000000000000", "{caps}");
    }
    run.assert_wired_on_loopback(&sidecar);
    run.assert_routes_validated();
    run.stop(&sidecar);
}
