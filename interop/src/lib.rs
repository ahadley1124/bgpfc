//! Interoperability test harness. Drives BIRD, FRR and `GoBGP` in network
//! namespaces and peers them with `bgpfcd`. Nothing in this
//! crate is shipped (AGENTS.md §1.2).
//!
//! Needs root, `iproute2` and the daemon under test:
//!
//! ```sh
//! cargo build -p bgpfcd
//! sudo -E "$(command -v cargo)" test -p interop -- --include-ignored
//! ```
//!
//! Each scenario builds two namespaces joined by a veth pair, starts the
//! daemons inside them, and polls their state until a condition holds or
//! a deadline passes. Everything is torn down on drop, also on panic.
#![forbid(unsafe_code)]

use std::fs;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Run a command, panicking with its output on failure.
fn sh(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {cmd} {}: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "{cmd} {} failed: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Two network namespaces, `a` and `b`, on one /24 joined by a veth pair.
pub struct Lab {
    /// Namespace name of side A.
    pub a: String,
    /// Namespace name of side B.
    pub b: String,
    /// Address of side A.
    pub a_addr: Ipv4Addr,
    /// Address of side B.
    pub b_addr: Ipv4Addr,
    /// Scratch directory for configs, sockets and logs.
    pub dir: PathBuf,
    /// Namespace name of side C, once [`Lab::add_c`] created it.
    pub c: Option<String>,
    /// Address of side A on the link to C.
    pub a2_addr: Ipv4Addr,
    /// Address of side C.
    pub c_addr: Ipv4Addr,
    id: String,
}

impl Lab {
    /// Build the lab. `tag` makes names unique per test; `subnet` is the
    /// third octet of `10.99.<subnet>.0/24`.
    ///
    /// # Panics
    /// If `ip` fails: not root, or `iproute2` missing.
    #[must_use]
    pub fn new(tag: &str, subnet: u8) -> Lab {
        let id = format!("{tag}{}", std::process::id() % 10_000);
        let a = format!("bgpfc-{id}-a");
        let b = format!("bgpfc-{id}-b");
        let va = format!("v{id}a");
        let vb = format!("v{id}b");
        let dir = std::env::temp_dir().join(format!("bgpfc-interop-{id}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        let a_addr = Ipv4Addr::new(10, 99, subnet, 1);
        let b_addr = Ipv4Addr::new(10, 99, subnet, 2);
        sh("ip", &["netns", "add", &a]);
        sh("ip", &["netns", "add", &b]);
        sh(
            "ip",
            &["link", "add", &va, "type", "veth", "peer", "name", &vb],
        );
        sh("ip", &["link", "set", &va, "netns", &a]);
        sh("ip", &["link", "set", &vb, "netns", &b]);
        for (ns, dev, addr) in [(&a, &va, a_addr), (&b, &vb, b_addr)] {
            sh(
                "ip",
                &["-n", ns, "addr", "add", &format!("{addr}/24"), "dev", dev],
            );
            sh("ip", &["-n", ns, "link", "set", dev, "up"]);
            sh("ip", &["-n", ns, "link", "set", "lo", "up"]);
        }
        Lab {
            a,
            b,
            a_addr,
            b_addr,
            dir,
            c: None,
            a2_addr: Ipv4Addr::new(10, 98, subnet, 1),
            c_addr: Ipv4Addr::new(10, 98, subnet, 2),
            id,
        }
    }

    /// Add a third namespace `c`, joined to `a` by a second veth pair on
    /// `10.98.<subnet>.0/24`; the namespace name is returned and kept in
    /// `self.c`.
    ///
    /// # Panics
    /// If `ip` fails.
    pub fn add_c(&mut self) -> String {
        let c = format!("bgpfc-{}-c", self.id);
        let va = format!("v{}a2", self.id);
        let vc = format!("v{}c", self.id);
        sh("ip", &["netns", "add", &c]);
        sh(
            "ip",
            &["link", "add", &va, "type", "veth", "peer", "name", &vc],
        );
        sh("ip", &["link", "set", &va, "netns", &self.a]);
        sh("ip", &["link", "set", &vc, "netns", &c]);
        for (ns, dev, addr) in [(&self.a, &va, self.a2_addr), (&c, &vc, self.c_addr)] {
            sh(
                "ip",
                &["-n", ns, "addr", "add", &format!("{addr}/24"), "dev", dev],
            );
            sh("ip", &["-n", ns, "link", "set", dev, "up"]);
            sh("ip", &["-n", ns, "link", "set", "lo", "up"]);
        }
        self.c = Some(c.clone());
        c
    }

    /// A command that runs inside namespace `ns`.
    #[must_use]
    pub fn exec(&self, ns: &str, program: &str) -> Command {
        let mut c = Command::new("ip");
        c.args(["netns", "exec", ns, program]);
        c
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.a]).status();
        let _ = Command::new("ip").args(["netns", "del", &self.b]).status();
        if let Some(c) = &self.c {
            let _ = Command::new("ip").args(["netns", "del", c]).status();
        }
        // Keep the daemons' logs when a test fails: CI prints them.
        if std::thread::panicking() {
            eprintln!("lab logs kept in {}", self.dir.display());
        } else {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

/// A running process whose stderr goes to a file; killed on drop.
pub struct Daemon {
    child: Child,
    /// Where stderr is collected.
    pub log: PathBuf,
}

impl Daemon {
    fn start(mut cmd: Command, log: PathBuf) -> Daemon {
        let file = fs::File::create(&log).expect("log file");
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(file)
            .spawn()
            .unwrap_or_else(|e| panic!("spawning {cmd:?}: {e}"));
        Daemon { child, log }
    }

    /// Everything the process wrote to stderr so far.
    #[must_use]
    pub fn log_text(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Stop the process.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Send `SIGTERM` and wait up to `timeout` for the process to exit;
    /// whether it did.
    pub fn terminate(&mut self, timeout: Duration) -> bool {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// `ip` output from inside namespace `ns`.
    ///
    /// # Panics
    /// If `ip` cannot be run.
    #[must_use]
    pub fn ip_in(lab: &Lab, ns: &str, args: &[&str]) -> String {
        let mut cmd = lab.exec(ns, "ip");
        cmd.args(args);
        let out = cmd.output().expect("ip");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Whether the process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Path to the `bgpfcd` binary: `$BGPFCD`, else the one next to this test
/// binary's `target/<profile>/` directory, built on demand.
///
/// # Panics
/// If the binary cannot be located or built.
#[must_use]
pub fn bgpfcd_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        if let Ok(p) = std::env::var("BGPFCD") {
            return PathBuf::from(p);
        }
        let exe = std::env::current_exe().expect("current exe");
        // target/<profile>/deps/<test> -> target/<profile>
        let profile_dir = exe
            .parent()
            .and_then(Path::parent)
            .expect("target profile dir");
        let candidate = profile_dir.join("bgpfcd");
        if !candidate.exists() {
            let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .args(["build", "-p", "bgpfcd", "-q"])
                .status()
                .expect("cargo build -p bgpfcd");
            assert!(status.success(), "building bgpfcd");
        }
        candidate
    })
    .clone()
}

/// Path to the `bgpfcctl` binary next to `bgpfcd`.
///
/// # Panics
/// If the binary cannot be located or built.
#[must_use]
pub fn bgpfcctl_path() -> PathBuf {
    let candidate = bgpfcd_path().with_file_name("bgpfcctl");
    if !candidate.exists() {
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-p", "bgpfcctl", "-q"])
            .status()
            .expect("cargo build -p bgpfcctl");
        assert!(status.success(), "building bgpfcctl");
    }
    candidate
}

/// Run `bgpfcctl -s socket args...`; stdout and stderr, and whether it
/// succeeded.
///
/// # Panics
/// If the binary cannot be run.
#[must_use]
pub fn bgpfcctl(socket: &Path, args: &[&str]) -> (String, bool) {
    let out = Command::new(bgpfcctl_path())
        .arg("-s")
        .arg(socket)
        .args(args)
        .output()
        .expect("bgpfcctl");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (s, out.status.success())
}

/// One neighbor of a daemon under test.
#[derive(Clone, Debug)]
pub struct NeighborOpts {
    /// The peer's address.
    pub addr: IpAddr,
    /// The peer's TCP port.
    pub port: u16,
    /// The peer's AS.
    pub remote_as: u32,
    /// Hold time in seconds.
    pub hold_time: u16,
    /// Never initiate the TCP connection.
    pub passive: bool,
    /// Import policy name (`ANY`, accept-all, is always defined).
    pub import: String,
    /// Export policy name.
    pub export: String,
}

impl NeighborOpts {
    /// An active neighbor on port 179 with a 30 s hold time.
    #[must_use]
    pub fn new(addr: impl Into<IpAddr>, remote_as: u32) -> NeighborOpts {
        NeighborOpts {
            addr: addr.into(),
            port: 179,
            remote_as,
            hold_time: 30,
            passive: false,
            import: "ANY".to_owned(),
            export: "ANY".to_owned(),
        }
    }
}

/// Options for one `bgpfcd` under test.
pub struct BgpfcdOpts {
    /// Our AS.
    pub local_as: u32,
    /// Router ID.
    pub router_id: Ipv4Addr,
    /// Listen addresses (port 179 each).
    pub listen: Vec<IpAddr>,
    /// Neighbors.
    pub neighbors: Vec<NeighborOpts>,
    /// Extra configuration text: policies and prefix lists.
    pub extra: String,
}

impl BgpfcdOpts {
    /// A daemon listening on `router_id` with one neighbor.
    #[must_use]
    pub fn single(local_as: u32, router_id: Ipv4Addr, neighbor: NeighborOpts) -> BgpfcdOpts {
        BgpfcdOpts {
            local_as,
            router_id,
            listen: vec![IpAddr::V4(router_id)],
            neighbors: vec![neighbor],
            extra: String::new(),
        }
    }
}

/// Write a configuration and start `bgpfcd` in namespace `ns` with debug
/// logging. Both families are offered, and an accept-all policy is used
/// in both directions.
///
/// # Panics
/// If the config cannot be written or the process cannot be spawned.
#[must_use]
pub fn start_bgpfcd(lab: &Lab, ns: &str, opts: &BgpfcdOpts) -> Daemon {
    use std::fmt::Write as _;
    let cfg = lab.dir.join(format!("bgpfcd-{ns}.conf"));
    let mut text = format!(
        "router-id {};\nlocal-as {};\nlog {{ level debug; }}\n\
         policy ANY {{ term all {{ action accept; }} }}\n{}\n",
        opts.router_id, opts.local_as, opts.extra
    );
    for l in &opts.listen {
        let _ = writeln!(text, "listen {{ address {l}; port 179; }}");
    }
    for n in &opts.neighbors {
        let _ = writeln!(
            text,
            "neighbor {} {{ remote-as {}; port {}; hold-time {}; passive {}; import {}; export {}; }}",
            n.addr,
            n.remote_as,
            n.port,
            n.hold_time,
            if n.passive { "yes" } else { "no" },
            n.import,
            n.export
        );
    }
    fs::write(&cfg, text).expect("bgpfcd config");
    let mut cmd = lab.exec(ns, bgpfcd_path().to_str().expect("path"));
    cmd.args(["-c", cfg.to_str().expect("path")]);
    Daemon::start(cmd, lab.dir.join(format!("bgpfcd-{ns}.log")))
}

/// A BIRD 2 instance with one BGP neighbour and a few static routes.
pub struct Bird {
    /// The process.
    pub daemon: Daemon,
    socket: PathBuf,
    lab_ns: String,
}

/// Options for a BIRD instance.
pub struct BirdOpts {
    /// BIRD's AS.
    pub local_as: u32,
    /// BIRD's address and router ID.
    pub local: Ipv4Addr,
    /// The port BIRD listens on and connects from.
    pub local_port: u16,
    /// The peer's address.
    pub neighbor: Ipv4Addr,
    /// The peer's port.
    pub neighbor_port: u16,
    /// The peer's AS.
    pub remote_as: u32,
    /// Hold time in seconds.
    pub hold_time: u16,
    /// Only accept connections (BIRD `passive on`).
    pub passive: bool,
    /// IPv4 prefixes BIRD originates as blackhole statics.
    pub statics: Vec<String>,
}

impl Bird {
    /// Write a config and start BIRD in namespace `ns`.
    ///
    /// # Panics
    /// If the config cannot be written or `bird` cannot be spawned.
    #[must_use]
    pub fn start(lab: &Lab, ns: &str, opts: &BirdOpts) -> Bird {
        let cfg = lab.dir.join(format!("bird-{ns}.conf"));
        let socket = lab.dir.join(format!("bird-{ns}.ctl"));
        let mut statics = String::new();
        for p in &opts.statics {
            use std::fmt::Write as _;
            let _ = writeln!(statics, "    route {p} blackhole;");
        }
        let passive = if opts.passive {
            "    passive on;\n"
        } else {
            ""
        };
        fs::write(
            &cfg,
            format!(
                "log stderr all;\n\
                 router id {local};\n\
                 protocol device {{ }}\n\
                 protocol static {{\n    ipv4;\n{statics}}}\n\
                 protocol bgp peer {{\n\
                 \x20   local {local} port {local_port} as {local_as};\n\
                 \x20   neighbor {neighbor} port {neighbor_port} as {remote_as};\n\
                 \x20   hold time {hold};\n\
                 {passive}\
                 \x20   ipv4 {{ import all; export all; }};\n\
                 }}\n",
                local = opts.local,
                local_port = opts.local_port,
                local_as = opts.local_as,
                neighbor = opts.neighbor,
                neighbor_port = opts.neighbor_port,
                remote_as = opts.remote_as,
                hold = opts.hold_time,
            ),
        )
        .expect("bird config");
        let mut cmd = lab.exec(ns, "bird");
        cmd.args([
            "-f",
            "-c",
            cfg.to_str().expect("path"),
            "-s",
            socket.to_str().expect("path"),
        ]);
        let daemon = Daemon::start(cmd, lab.dir.join(format!("bird-{ns}.log")));
        Bird {
            daemon,
            socket,
            lab_ns: ns.to_owned(),
        }
    }

    /// Output of `birdc <args>`.
    ///
    /// # Panics
    /// If `birdc` cannot be run.
    #[must_use]
    pub fn birdc(&self, lab: &Lab, args: &[&str]) -> String {
        let mut cmd = lab.exec(&self.lab_ns, "birdc");
        cmd.args(["-s", self.socket.to_str().expect("path")]);
        cmd.args(args);
        let out = cmd.output().expect("birdc");
        let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&out.stderr));
        s
    }

    /// `show protocols all peer`.
    #[must_use]
    pub fn peer_status(&self, lab: &Lab) -> String {
        self.birdc(lab, &["show", "protocols", "all", "peer"])
    }
}

/// Poll `check` until it returns true or `timeout` passes.
pub fn wait_for(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if check() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Read a whole file, tolerating a missing one.
#[must_use]
pub fn read(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

/// Options shared by the FRR and `GoBGP` instances.
pub struct OtherOpts {
    /// The daemon's AS.
    pub local_as: u32,
    /// The daemon's address and router ID.
    pub local: Ipv4Addr,
    /// The peer's address.
    pub neighbor: Ipv4Addr,
    /// The peer's AS.
    pub remote_as: u32,
    /// IPv4 prefixes the daemon originates.
    pub networks: Vec<String>,
}

/// An FRR `bgpd` run on its own (no zebra, no kernel routes), driven
/// through `vtysh`.
pub struct Frr {
    /// The process.
    pub daemon: Daemon,
    vty_dir: PathBuf,
    lab_ns: String,
}

impl Frr {
    /// Write a config and start `bgpd` in namespace `ns`.
    ///
    /// # Panics
    /// If the config cannot be written or `bgpd` cannot be spawned.
    #[must_use]
    pub fn start(lab: &Lab, ns: &str, opts: &OtherOpts) -> Frr {
        let dir = lab.dir.join(format!("frr-{ns}"));
        fs::create_dir_all(&dir).expect("frr dir");
        let mut networks = String::new();
        for n in &opts.networks {
            use std::fmt::Write as _;
            let _ = writeln!(networks, "  network {n}");
        }
        let cfg = dir.join("bgpd.conf");
        fs::write(
            &cfg,
            format!(
                "hostname frr\nlog stdout\n\
                 router bgp {local_as}\n\
                 \x20bgp router-id {local}\n\
                 \x20no bgp ebgp-requires-policy\n\
                 \x20no bgp network import-check\n\
                 \x20neighbor {neighbor} remote-as {remote_as}\n\
                 \x20neighbor {neighbor} timers 10 30\n\
                 \x20address-family ipv4 unicast\n\
                 {networks}\
                 \x20 neighbor {neighbor} activate\n\
                 \x20exit-address-family\n",
                local_as = opts.local_as,
                local = opts.local,
                neighbor = opts.neighbor,
                remote_as = opts.remote_as,
            ),
        )
        .expect("frr config");
        // bgpd insists on its own user for the vty socket directory.
        let _ = Command::new("chown")
            .args(["-R", "frr:frr", dir.to_str().expect("path")])
            .status();
        // bgpd connects to any zebra it finds, and the zserv Unix socket is
        // not namespaced: on a host where FRR's zebra runs (the CI runner),
        // bgpd would learn the host's interfaces, find none for its own
        // address and reject every session with an FSM error. Point it at
        // a socket nobody listens on so it behaves as without zebra.
        let zebra = dir.join("zserv.api");
        let mut cmd = lab.exec(ns, "/usr/lib/frr/bgpd");
        cmd.args([
            "-z",
            zebra.to_str().expect("path"),
            "-f",
            cfg.to_str().expect("path"),
            "-i",
            dir.join("bgpd.pid").to_str().expect("path"),
            "-Z",
            "-n",
            "-S",
            "--vty_socket",
            dir.to_str().expect("path"),
            "--log",
            "stdout",
            "--log-level",
            "debug",
            "-l",
            &opts.local.to_string(),
        ]);
        let daemon = Daemon::start(cmd, lab.dir.join(format!("frr-{ns}.log")));
        Frr {
            daemon,
            vty_dir: dir,
            lab_ns: ns.to_owned(),
        }
    }

    /// Output of `vtysh -c COMMAND`.
    ///
    /// # Panics
    /// If `vtysh` cannot be run.
    #[must_use]
    pub fn vtysh(&self, lab: &Lab, command: &str) -> String {
        let mut cmd = lab.exec(&self.lab_ns, "vtysh");
        cmd.args([
            "--vty_socket",
            self.vty_dir.to_str().expect("path"),
            "-d",
            "bgpd",
            "-c",
            command,
        ]);
        let out = cmd.output().expect("vtysh");
        let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&out.stderr));
        s
    }

    /// `show bgp summary`.
    #[must_use]
    pub fn summary(&self, lab: &Lab) -> String {
        self.vtysh(lab, "show bgp summary")
    }
}

/// A `gobgpd` instance driven through the `gobgp` CLI (gRPC on
/// 127.0.0.1:50051 inside its namespace).
pub struct GoBgp {
    /// The process.
    pub daemon: Daemon,
    lab_ns: String,
}

impl GoBgp {
    /// Write a config and start `gobgpd` in namespace `ns`.
    ///
    /// # Panics
    /// If the config cannot be written or `gobgpd` cannot be spawned.
    #[must_use]
    pub fn start(lab: &Lab, ns: &str, opts: &OtherOpts) -> GoBgp {
        let cfg = lab.dir.join(format!("gobgpd-{ns}.toml"));
        fs::write(
            &cfg,
            format!(
                "[global.config]\n  as = {local_as}\n  router-id = \"{local}\"\n\
                 \x20 local-address-list = [\"{local}\"]\n\n\
                 [[neighbors]]\n  [neighbors.config]\n    neighbor-address = \"{neighbor}\"\n\
                 \x20   peer-as = {remote_as}\n  [neighbors.timers.config]\n    hold-time = 30\n\
                 \x20 [[neighbors.afi-safis]]\n    [neighbors.afi-safis.config]\n\
                 \x20     afi-safi-name = \"ipv4-unicast\"\n",
                local_as = opts.local_as,
                local = opts.local,
                neighbor = opts.neighbor,
                remote_as = opts.remote_as,
            ),
        )
        .expect("gobgpd config");
        let mut cmd = lab.exec(ns, "gobgpd");
        cmd.args([
            "-f",
            cfg.to_str().expect("path"),
            "-p",
            "-l",
            "debug",
            "--api-hosts",
            "127.0.0.1:50051",
            "--pprof-disable",
        ]);
        let daemon = Daemon::start(cmd, lab.dir.join(format!("gobgpd-{ns}.log")));
        let g = GoBgp {
            daemon,
            lab_ns: ns.to_owned(),
        };
        // The gRPC API comes up a moment after the process.
        assert!(
            wait_for(Duration::from_secs(10), || g
                .gobgp(lab, &["global"])
                .contains("AS:")),
            "gobgpd api not up:\n{}",
            g.daemon.log_text()
        );
        for n in &opts.networks {
            let _ = g.gobgp(lab, &["global", "rib", "add", n]);
        }
        g
    }

    /// Output of `gobgp ARGS`.
    ///
    /// # Panics
    /// If `gobgp` cannot be run.
    #[must_use]
    pub fn gobgp(&self, lab: &Lab, args: &[&str]) -> String {
        let mut cmd = lab.exec(&self.lab_ns, "gobgp");
        cmd.args(["-u", "127.0.0.1", "-p", "50051"]).args(args);
        let out = cmd.output().expect("gobgp");
        let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&out.stderr));
        s
    }

    /// `gobgp neighbor`.
    #[must_use]
    pub fn neighbors(&self, lab: &Lab) -> String {
        self.gobgp(lab, &["neighbor"])
    }
}
