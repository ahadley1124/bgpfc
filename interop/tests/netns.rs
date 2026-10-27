//! bgpfcd told which network namespace to run in (`netns` and `--netns`,
//! `docs/config.md`, "Network namespace"; AGENTS.md §5, `interop/` row):
//! started in the host's namespace, it joins the lab's namespace B itself,
//! and its BGP session with BIRD in A, the routes it installs, its HTTP
//! API, its RTR client and Routinator all are in B, as under `ip netns
//! exec`, while `bgpfcctl` reaches its control socket from the host.
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird`, `birdc`,
//! `curl`, `stayrtr` and `setpriv` on `PATH`, and a built `bgpfcd`. CI runs
//! them with `--include-ignored` under sudo.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, FakeRoutinator, Lab, NOBODY, NeighborOpts, StayRtr,
    bgpfcd_config, bgpfcd_path, start_bgpfcd, wait_for,
};

const BGPFC_AS: u32 = 65_000;
const BIRD_AS: u32 = 65_001;
const ESTABLISH: Duration = Duration::from_secs(40);
/// bgpfcd's HTTP API, in its namespace: a port nothing on the host serves.
const HTTP: &str = "127.0.0.1:18179";
/// The routes BIRD originates.
const ROUTES: [&str; 2] = ["192.0.2.0/24", "198.51.100.0/24"];
/// The VRPs of the RTR cache: (prefix, max length, origin AS).
const VRPS: [(&str, u8, u32); 2] = [
    ("192.0.2.0/24", 24, BIRD_AS),
    ("198.51.100.0/24", 24, 64_999),
];

/// Capability bits, `<linux/capability.h>`.
const CAP_NET_BIND_SERVICE: u64 = 1 << 10;
const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// The `setpriv(1)` options that run a program as `nobody`, with no
/// groups and no capabilities.
fn as_nobody() -> Vec<String> {
    vec![
        format!("--reuid={NOBODY}"),
        format!("--regid={NOBODY}"),
        "--clear-groups".to_owned(),
    ]
}

/// BIRD in A, which originates [`ROUTES`] and connects to bgpfcd in B:
/// the session can only come up through bgpfcd's listener in B.
fn start_bird(lab: &Lab) -> Bird {
    Bird::start(
        lab,
        &lab.a,
        &BirdOpts {
            local_as: BIRD_AS,
            local: lab.a_addr,
            local_port: 179,
            neighbor: lab.b_addr,
            neighbor_port: 179,
            remote_as: BGPFC_AS,
            hold_time: 30,
            passive: false,
            statics: ROUTES.map(str::to_owned).to_vec(),
            channel: String::new(),
            protocol: String::new(),
            export: String::new(),
        },
    )
}

/// bgpfcd, started from the host: listening on B's address only, which
/// the host does not have, with BIRD in A as a passive neighbor, routes
/// installed, `extra` in the file and `args` on the command line.
fn bgpfcd_opts(lab: &Lab, extra: &str, args: &[&str]) -> BgpfcdOpts {
    let mut bird = NeighborOpts::new(lab.a_addr, BIRD_AS);
    bird.passive = true;
    let mut opts = BgpfcdOpts::single(BGPFC_AS, lab.b_addr, bird);
    opts.extra = format!("fib {{ mode install; }}\n{extra}");
    opts.args = args.iter().map(|a| (*a).to_owned()).collect();
    opts.from_host = true;
    opts
}

/// `/run/netns/NAME`, the file `ip netns add` made for the lab's
/// namespace `name`.
fn run_netns(name: &str) -> PathBuf {
    Path::new("/run/netns").join(name)
}

/// The identity of a network namespace's file: device and inode.
fn ns_id(path: &Path) -> (u64, u64) {
    let m = fs::metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    (m.dev(), m.ino())
}

/// The network namespace process `pid` is in.
fn ns_of(pid: u32) -> (u64, u64) {
    ns_id(Path::new(&format!("/proc/{pid}/ns/net")))
}

/// The effective capabilities of process `pid` (`CapEff`, `proc(5)`).
fn cap_eff(pid: u32) -> u64 {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    let value = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .expect("CapEff");
    u64::from_str_radix(value.trim(), 16).expect("hex")
}

/// BIRD and bgpfcd report the session Established.
fn assert_established(lab: &Lab, bird: &Bird, bgpfcd: &Daemon) {
    let ok = wait_for(ESTABLISH, || {
        bird.peer_status(lab).contains("Established")
            && bgpfcd.log_text().contains("session established")
    });
    assert!(
        ok,
        "no session.\n--- birdc ---\n{}\n--- bird ---\n{}\n--- bgpfcd ---\n{}",
        bird.peer_status(lab),
        bird.daemon.log_text(),
        bgpfcd.log_text()
    );
}

/// bgpfcd's routes in namespace `ns`'s kernel table (protocol 186).
fn kernel_routes(lab: &Lab, ns: &str) -> String {
    Daemon::ip_in(lab, ns, &["route", "show", "proto", "186"])
}

/// Every one of [`ROUTES`] is installed in B, through BIRD in A, and none
/// of them in the host's table (protocol 186, bgpfcd's).
fn assert_installed_in_b(lab: &Lab, bgpfcd: &Daemon) {
    let ok = wait_for(Duration::from_secs(15), || {
        let r = kernel_routes(lab, &lab.b);
        ROUTES.iter().all(|p| r.contains(p))
    });
    let r = kernel_routes(lab, &lab.b);
    assert!(ok, "routes not installed in B:\n{r}\n{}", bgpfcd.log_text());
    assert!(r.contains(&format!("via {}", lab.a_addr)), "{r}");
    // The host may route these prefixes itself; none of its routes is
    // bgpfcd's.
    let host = Command::new("ip")
        .args(["route", "show", "proto", "186"])
        .output()
        .expect("ip route");
    let host = String::from_utf8_lossy(&host.stdout);
    for p in ROUTES {
        assert!(!host.contains(p), "{p} in the host's table:\n{host}");
    }
}

/// bgpfcd logged that it joined `path`, by name, and dropped
/// `CAP_SYS_ADMIN`, and is in that namespace now, without the capability.
fn assert_joined(bgpfcd: &Daemon, path: &Path) {
    let log = bgpfcd.log_text();
    assert!(
        log.contains(&format!(
            "msg=\"network namespace joined\" netns={}",
            path.display()
        )),
        "{log}"
    );
    assert!(
        log.contains("msg=\"capability dropped\" capability=CAP_SYS_ADMIN"),
        "{log}"
    );
    assert_eq!(ns_of(bgpfcd.pid()), ns_id(path), "{log}");
    assert_eq!(cap_eff(bgpfcd.pid()) & CAP_SYS_ADMIN, 0, "{log}");
}

/// `curl` of bgpfcd's HTTP API at `path`, inside namespace `ns` or, with
/// `None`, from the host.
fn curl(lab: &Lab, ns: Option<&str>, path: &str) -> Output {
    let mut cmd = match ns {
        Some(ns) => lab.exec(ns, "curl"),
        None => Command::new("curl"),
    };
    cmd.args(["-s", "--max-time", "5", &format!("http://{HTTP}{path}")])
        .output()
        .expect("curl")
}

/// Everything happens in B: started from the host with `--netns NAME`,
/// bgpfcd joins B, where BIRD connects to its listener, its routes go to
/// B's kernel table and not the host's, its HTTP API answers in B and not
/// on the host, and its RTR client reaches `StayRTR` in A; `bgpfcctl` works
/// from the host over the control socket; bgpfcd's process is in B and
/// holds no `CAP_SYS_ADMIN`.
#[test]
#[ignore = "needs root, bird, curl, stayrtr and iproute2"]
fn bgpfcd_joins_a_namespace_from_the_host() {
    let lab = Lab::new("na", 40);
    let cache_addr = format!("{}:3323", lab.a_addr);
    let _cache = StayRtr::start(&lab, &lab.a, &cache_addr, &VRPS);
    let bird = start_bird(&lab);
    let socket = lab.dir.join("ctl.sock");
    let extra = format!(
        "control {{ socket {}; http {{ listen {HTTP}; }} }}\n\
         rpki {{ mode external; enforcement off; cache {} port 3323; }}",
        socket.display(),
        lab.a_addr
    );
    let ns_b = lab.b.clone();
    let bgpfcd = start_bgpfcd(&lab, &ns_b, &bgpfcd_opts(&lab, &extra, &["--netns", &ns_b]));
    assert_established(&lab, &bird, &bgpfcd);
    assert_installed_in_b(&lab, &bgpfcd);
    assert_joined(&bgpfcd, &run_netns(&lab.b));
    let log = bgpfcd.log_text();
    assert!(
        log.contains(&format!("netns={}", run_netns(&lab.b).display())),
        "{log}"
    );

    // The control socket is a file: bgpfcctl reaches it from the host.
    let (out, ok) = interop::bgpfcctl(&socket, &["show", "neighbors"]);
    assert!(
        ok && out.contains(&lab.a_addr.to_string()) && out.contains("Established"),
        "{out}"
    );
    // The RTR client is connected to the cache in A, from B.
    let ok = wait_for(Duration::from_secs(20), || {
        let (out, _) = interop::bgpfcctl(&socket, &["show", "rpki"]);
        out.contains("state idle, connected") && out.contains("vrps ipv4 2 ipv6 0")
    });
    assert!(
        ok,
        "{}\n{}",
        interop::bgpfcctl(&socket, &["show", "rpki"]).0,
        bgpfcd.log_text()
    );
    // Validated with those VRPs: Valid and, as `enforcement off` uses it,
    // Invalid.
    let (out, _) = interop::bgpfcctl(&socket, &["show", "routes"]);
    for (prefix, state) in [("192.0.2.0/24", "valid"), ("198.51.100.0/24", "invalid")] {
        let listed = out.lines().any(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            words.first().map(|p| p.trim_start_matches('*')) == Some(prefix)
                && words.get(5) == Some(&state)
        });
        assert!(listed, "{prefix} {state}:\n{out}");
    }

    // The HTTP API listens on B's loopback, not on the host's.
    let inside = curl(&lab, Some(&lab.b), "/v1/neighbors");
    let body = String::from_utf8_lossy(&inside.stdout);
    assert!(
        inside.status.success() && body.contains(&lab.a_addr.to_string()),
        "{inside:?}"
    );
    let outside = curl(&lab, None, "/v1/neighbors");
    // curl(1): exit status 7, "Failed to connect to host".
    assert_eq!(outside.status.code(), Some(7), "{outside:?}");
}

/// The `netns` statement names the namespace as well, and a reload that
/// changes it leaves bgpfcd where it is until the next restart; then
/// `--netns` with an absolute path overrides a statement that names
/// another namespace.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn the_statement_and_an_absolute_path_name_the_namespace() {
    let lab = Lab::new("nb", 41);
    let bird = start_bird(&lab);
    let socket = lab.dir.join("ctl.sock");
    let control = format!("control {{ socket {}; }}", socket.display());
    let ns_b = lab.b.clone();
    let b = run_netns(&lab.b);

    // The statement, by name.
    let opts = bgpfcd_opts(&lab, &format!("{control}\nnetns {ns_b};"), &[]);
    let mut bgpfcd = start_bgpfcd(&lab, &ns_b, &opts);
    assert_established(&lab, &bird, &bgpfcd);
    assert_installed_in_b(&lab, &bgpfcd);
    assert_joined(&bgpfcd, &b);
    // A reload of a file that names A instead: noted for the next restart,
    // and bgpfcd stays in B, its session up.
    let file = lab.dir.join(format!("bgpfcd-{ns_b}.conf"));
    let text = fs::read_to_string(&file).unwrap();
    let a_text = text.replace(&format!("netns {ns_b};"), &format!("netns {};", lab.a));
    assert_ne!(a_text, text);
    fs::write(&file, &a_text).unwrap();
    let (out, ok) = interop::bgpfcctl(&socket, &["reload"]);
    assert!(
        ok && out.contains(&format!(
            "netns changed: takes effect at the next restart; bgpfcd stays in {}",
            b.display()
        )),
        "{out}\n{}",
        bgpfcd.log_text()
    );
    assert_eq!(ns_of(bgpfcd.pid()), ns_id(&b));
    assert!(
        bird.peer_status(&lab).contains("Established"),
        "{}",
        bird.peer_status(&lab)
    );
    assert!(
        bgpfcd.terminate(Duration::from_secs(15)),
        "{}",
        bgpfcd.log_text()
    );
    let _ = fs::remove_file(&socket);

    // The file names A, the flag B by its path: B wins. In A, bgpfcd could
    // not listen on B's address and would stop.
    let opts = bgpfcd_opts(
        &lab,
        &format!("{control}\nnetns {};", lab.a),
        &["--netns", b.to_str().expect("path")],
    );
    let bgpfcd = start_bgpfcd(&lab, &ns_b, &opts);
    assert_established(&lab, &bird, &bgpfcd);
    assert_installed_in_b(&lab, &bgpfcd);
    assert_joined(&bgpfcd, &b);
}

/// `bgpfcd -c FILE --check --netns ...` with `args` before it, run as
/// `setpriv` with `setpriv` options, or directly without.
fn check(bgpfcd: &Path, setpriv: &[String], file: &Path, netns: &str) -> Output {
    let mut cmd = if setpriv.is_empty() {
        Command::new(bgpfcd)
    } else {
        let mut cmd = Command::new("setpriv");
        cmd.args(setpriv).arg(bgpfcd);
        cmd
    };
    cmd.arg("-c")
        .arg(file)
        .args(["--check", "--netns", netns])
        .stdin(Stdio::null())
        .output()
        .expect("bgpfcd --check")
}

/// A copy of bgpfcd that `nobody` can run, wherever the build is.
fn bgpfcd_for_nobody(lab: &Lab) -> PathBuf {
    let copy = lab.dir.join("bgpfcd");
    fs::copy(bgpfcd_path(), &copy).expect("copy bgpfcd");
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).expect("bgpfcd mode");
    copy
}

/// `--check` opens the namespace, which needs no privilege, and joins
/// nothing; the start joins it only with `CAP_SYS_ADMIN`, and an
/// unprivileged user that has it, with the two capabilities bgpfcd needs
/// besides (README, "Run", Option A), joins, comes up, and keeps those
/// two after it gave up `CAP_SYS_ADMIN`.
#[test]
#[ignore = "needs root, bird, setpriv and iproute2"]
fn check_and_capabilities_stop_a_start_that_cannot_join() {
    let lab = Lab::new("nc", 42);
    let binary = bgpfcd_for_nobody(&lab);
    let ns_b = lab.b.clone();
    // No control socket: `nobody` may not create one in the lab's
    // directory.
    let opts = bgpfcd_opts(&lab, "", &[]);
    let file = bgpfcd_config(&lab, &ns_b, &opts);

    let out = check(&binary, &[], &file, "nope");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr.contains("/run/netns/nope"), "{stderr}");
    let out = check(&binary, &as_nobody(), &file, &ns_b);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout.contains(&format!("netns {}", run_netns(&ns_b).display())),
        "{stdout}"
    );

    // As nobody, without capabilities: no join, no start.
    let mut setpriv = Command::new("setpriv");
    setpriv
        .args(as_nobody())
        .arg(&binary)
        .arg("-c")
        .arg(&file)
        .args(["--netns", &ns_b]);
    let mut refused = Daemon::start(setpriv, lab.dir.join("bgpfcd-refused.log"));
    let status = refused.wait(Duration::from_secs(10));
    let log = refused.log_text();
    assert!(
        status.is_some_and(|s| s.code() == Some(1)),
        "{status:?}\n{log}"
    );
    assert!(
        log.contains("msg=\"cannot join network namespace\"") && log.contains("CAP_SYS_ADMIN"),
        "{log}"
    );

    // As nobody, with CAP_SYS_ADMIN and the two of Option A.
    let bird = start_bird(&lab);
    let caps = "+sys_admin,+net_admin,+net_bind_service";
    let mut setpriv = Command::new("setpriv");
    setpriv
        .args(as_nobody())
        .args([
            format!("--inh-caps={caps}"),
            format!("--ambient-caps={caps}"),
        ])
        .arg(&binary)
        .arg("-c")
        .arg(&file)
        .args(["--netns", &ns_b]);
    let bgpfcd = Daemon::start(setpriv, lab.dir.join("bgpfcd-capabilities.log"));
    assert_established(&lab, &bird, &bgpfcd);
    assert_installed_in_b(&lab, &bgpfcd);
    assert_joined(&bgpfcd, &run_netns(&ns_b));
    let eff = cap_eff(bgpfcd.pid());
    assert_eq!(
        eff & (CAP_NET_BIND_SERVICE | CAP_NET_ADMIN),
        CAP_NET_BIND_SERVICE | CAP_NET_ADMIN,
        "{eff:x}"
    );
}

/// With `mode sidecar`, Routinator is a child of bgpfcd in B: the fake's
/// process is in B, and the RTR client, in B too, is in sync with it over
/// B's loopback. bgpfcd runs as root with `--user nobody`, which the
/// sidecar needs: the join comes first, before the privilege drop.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn the_sidecar_runs_in_the_namespace() {
    let lab = Lab::new("nd", 43);
    let fake = FakeRoutinator::install(&lab, &VRPS);
    let bird = start_bird(&lab);
    let socket = lab.dir.join("ctl.sock");
    let extra = format!(
        "control {{ socket {}; }}\n{}",
        socket.display(),
        fake.block("enforcement off;", "")
    );
    let ns_b = lab.b.clone();
    let bgpfcd = start_bgpfcd(
        &lab,
        &ns_b,
        &bgpfcd_opts(&lab, &extra, &["--netns", &ns_b, "--user", "nobody"]),
    );
    assert_established(&lab, &bird, &bgpfcd);
    assert_joined(&bgpfcd, &run_netns(&ns_b));
    let ok = wait_for(Duration::from_secs(30), || {
        let (out, _) = interop::bgpfcctl(&socket, &["show", "rpki"]);
        out.contains("sidecar running pid")
            && out.contains("state idle, connected")
            && out.contains("vrps ipv4 2 ipv6 0")
    });
    assert!(
        ok,
        "{}\n{}",
        interop::bgpfcctl(&socket, &["show", "rpki"]).0,
        bgpfcd.log_text()
    );
    let pid = fake.pid().expect("the fake's pid");
    assert_eq!(ns_of(pid), ns_id(&run_netns(&ns_b)));
    assert_ne!(ns_of(pid), ns_id(Path::new("/proc/self/ns/net")));
    assert_eq!(cap_eff(pid), 0, "Routinator holds no capability");
}
