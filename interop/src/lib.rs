//! Interoperability test harness. Drives BIRD, FRR and `GoBGP` in network
//! namespaces and peers them with `bgpfcd`, and serves it VRPs over RTR
//! from `StayRTR`, or from this crate's stub cache (`src/bin/rtr-stub.rs`)
//! where `StayRTR` cannot be used. For `rpki { mode sidecar; }` it stands
//! in a [`FakeRoutinator`] for Routinator, which is never run (AGENTS.md
//! §5). Nothing in this crate is shipped (AGENTS.md §1.2).
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
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
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
        // Whatever the umask: a bgpfcd that dropped to `nobody` reads its
        // configuration file here again at a reload.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("scratch dir mode");
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

    /// An address on the link between A and B where what A sends goes
    /// nowhere: A has a permanent neighbour entry for it with a MAC address
    /// nobody has, and B drops frames for that address. A connection to
    /// it from A hangs until it times out, as to a host that is gone.
    ///
    /// # Panics
    /// If `ip` fails.
    #[must_use]
    pub fn blackhole(&self) -> Ipv4Addr {
        let [a, b, c, _] = self.a_addr.octets();
        let addr = Ipv4Addr::new(a, b, c, 9);
        sh(
            "ip",
            &[
                "-n",
                &self.a,
                "neigh",
                "add",
                &addr.to_string(),
                "lladdr",
                "02:00:00:00:00:09",
                "dev",
                &format!("v{}a", self.id),
                "nud",
                "permanent",
            ],
        );
        addr
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

    /// The process ID. `ip netns exec` executes the program in its own
    /// place, so this is the daemon's, not `ip`'s.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait up to `timeout` for the process to exit by itself; how it
    /// exited, or `None` if it still runs.
    pub fn wait(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
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
    /// `advertisement-interval` in seconds; `None` keeps the RFC 4271 §10
    /// default (30 s external, 5 s internal).
    pub advertisement_interval: Option<u16>,
    /// More statements for the `neighbor` block, such as
    /// `extended-next-hop yes;` or `connect-retry-time 5;`.
    pub extra: String,
}

impl NeighborOpts {
    /// An active neighbor on port 179 with a 30 s hold time and the
    /// default advertisement interval.
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
            advertisement_interval: None,
            extra: String::new(),
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
    /// Further command-line arguments, such as `--user nobody`.
    pub args: Vec<String>,
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
            args: Vec::new(),
        }
    }
}

/// Write a configuration and start `bgpfcd` in namespace `ns` with debug
/// logging and the further arguments of `opts`. Both families are
/// offered, and an accept-all policy is used in both directions. The file
/// is readable by every user, as a bgpfcd started with `--user` reads it
/// again at a reload.
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
        let interval = n
            .advertisement_interval
            .map(|s| format!(" advertisement-interval {s};"))
            .unwrap_or_default();
        let _ = writeln!(
            text,
            "neighbor {} {{ remote-as {}; port {}; hold-time {}; passive {}; import {}; export {};{interval} {} }}",
            n.addr,
            n.remote_as,
            n.port,
            n.hold_time,
            if n.passive { "yes" } else { "no" },
            n.import,
            n.export,
            n.extra
        );
    }
    fs::write(&cfg, text).expect("bgpfcd config");
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o644)).expect("bgpfcd config mode");
    let mut cmd = lab.exec(ns, bgpfcd_path().to_str().expect("path"));
    cmd.args(["-c", cfg.to_str().expect("path")]);
    cmd.args(&opts.args);
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
    /// More options for the BGP `ipv4` channel, such as
    /// `extended next hop on;`.
    pub channel: String,
    /// More options for the BGP protocol itself, such as
    /// `error wait time 1, 2;`.
    pub protocol: String,
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
                 \x20   {protocol}\n\
                 \x20   ipv4 {{ import all; export all; {channel} }};\n\
                 }}\n",
                local = opts.local,
                local_port = opts.local_port,
                local_as = opts.local_as,
                neighbor = opts.neighbor,
                neighbor_port = opts.neighbor_port,
                remote_as = opts.remote_as,
                hold = opts.hold_time,
                channel = opts.channel,
                protocol = opts.protocol,
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

/// A `StayRTR` RPKI cache: an RTR server (RFC 8210) that serves the VRPs
/// of a JSON file, which the test rewrites to change them.
pub struct StayRtr {
    /// The process.
    pub daemon: Daemon,
    vrps: PathBuf,
}

impl StayRtr {
    /// Start `stayrtr` in namespace `ns`, listening on `bind` (such as
    /// `127.0.0.1:3323`) and serving `vrps`: (prefix, max length, origin
    /// AS). It reads the file again every second and tells its clients
    /// with a Serial Notify when the VRPs change. Its End of Data gives a
    /// Retry Interval of two seconds (RFC 8210 §6), so that a client in
    /// sync with it while a more preferred cache is configured looks for
    /// that cache again within seconds.
    ///
    /// # Panics
    /// If the file cannot be written or `stayrtr` cannot be spawned.
    #[must_use]
    pub fn start(lab: &Lab, ns: &str, bind: &str, vrps: &[(&str, u8, u32)]) -> StayRtr {
        let port = bind.rsplit(':').next().unwrap_or(bind);
        let path = lab.dir.join(format!("vrps-{ns}-{port}.json"));
        StayRtr::write(&path, vrps);
        let mut cmd = lab.exec(ns, "stayrtr");
        cmd.args([
            "-cache",
            path.to_str().expect("path"),
            "-bind",
            bind,
            // The file's metadata says when it was made; a test file is
            // never fresh.
            "-checktime=false",
            "-refresh",
            "1",
            "-rtr.retry",
            "2",
            // No metrics listener, so that several caches can share a
            // namespace.
            "-metrics.addr",
            "",
            // Every PDU received, for the tests to check what bgpfcd asked.
            "-loglevel",
            "debug",
        ]);
        let cache = StayRtr {
            daemon: Daemon::start(cmd, lab.dir.join(format!("stayrtr-{ns}-{port}.log"))),
            vrps: path,
        };
        assert!(
            wait_for(Duration::from_secs(10), || cache
                .daemon
                .log_text()
                .contains("Server started")),
            "stayrtr did not start:\n{}",
            cache.daemon.log_text()
        );
        cache
    }

    /// Serve `vrps` from now on.
    pub fn set_vrps(&self, vrps: &[(&str, u8, u32)]) {
        StayRtr::write(&self.vrps, vrps);
    }

    fn write(path: &Path, vrps: &[(&str, u8, u32)]) {
        let roas: Vec<String> = vrps
            .iter()
            .map(|(prefix, max_len, asn)| {
                format!(
                    "{{\"prefix\":\"{prefix}\",\"maxLength\":{max_len},\"asn\":\"AS{asn}\",\"ta\":\"test\"}}"
                )
            })
            .collect();
        // Written whole and renamed, so that stayrtr never reads half a file.
        let tmp = path.with_extension("tmp");
        fs::write(
            &tmp,
            format!(
                "{{\"metadata\":{{\"generated\":0}},\"roas\":[{}]}}",
                roas.join(",")
            ),
        )
        .expect("vrps file");
        fs::rename(&tmp, path).expect("vrps file");
    }
}

/// This crate's stub RTR cache, `rtr-stub` (`src/bin/rtr-stub.rs`): the
/// VRPs it is given, as serial 1 of a Session ID of the test's choosing,
/// and a Cache Reset for any other Serial Query (RFC 8210 §8.3). It stands
/// in for `StayRTR` where a cache must restart and bring `bgpfcd` back in
/// sync; see the binary's documentation.
pub struct RtrStub {
    /// The process.
    pub daemon: Daemon,
}

impl RtrStub {
    /// Start the stub in namespace `ns`, listening on `bind` (such as
    /// `127.0.0.1:3323`) and serving `vrps`, (prefix, max length, origin
    /// AS), under `session_id`. Its log is
    /// `rtr-stub-<ns>-<port>-<session_id>.log`, so a restart with another
    /// Session ID writes a log of its own.
    ///
    /// # Panics
    /// If the binary is missing or the stub does not start listening.
    #[must_use]
    pub fn start(
        lab: &Lab,
        ns: &str,
        bind: &str,
        session_id: u16,
        vrps: &[(&str, u8, u32)],
    ) -> RtrStub {
        let port = bind.rsplit(':').next().unwrap_or(bind);
        let mut cmd = lab.exec(ns, rtr_stub_path().to_str().expect("path"));
        cmd.arg(bind).arg(session_id.to_string());
        for (prefix, max_len, asn) in vrps {
            cmd.arg(format!("{prefix}-{max_len}-{asn}"));
        }
        let stub = RtrStub {
            daemon: Daemon::start(
                cmd,
                lab.dir
                    .join(format!("rtr-stub-{ns}-{port}-{session_id}.log")),
            ),
        };
        assert!(
            wait_for(Duration::from_secs(10), || stub
                .daemon
                .log_text()
                .contains("listening on")),
            "rtr-stub did not start:\n{}",
            stub.daemon.log_text()
        );
        stub
    }
}

/// The user a [`FakeRoutinator`] runs as, with `bgpfcd --user nobody`:
/// `nobody`, and its group, 65534 on Debian and Ubuntu.
pub const NOBODY: u32 = 65_534;

/// The fake Routinator: a shell script that answers `--version` from the
/// file `version`, records the arguments of every other start in
/// `invocations`, insists on `server` and `--rtr=ADDR:PORT` as bgpfcd
/// derives them, and then becomes this crate's `rtr-stub` on that address,
/// serving the VRPs of the file `vrps` under a new Session ID each time,
/// as a restarted Routinator does. `fail` makes every start exit 1 at once;
/// `delay` holds the start that many seconds before it listens, as
/// Routinator's first validation run does. Every `--version` adds a line
/// to `version-checks`. `@DIR@` is the directory of these files.
const FAKE_ROUTINATOR: &str = r#"#!/bin/sh
# A stand-in for Routinator 0.15 in bgpfc's interop tests; never shipped.
dir=@DIR@
case "$1" in --version|-V) echo "$*" >> "$dir/version-checks"; cat "$dir/version"; exit 0 ;; esac
{ printf 'start'; for a in "$@"; do printf ' %s' "$a"; done; echo; } >> "$dir/invocations"
rtr=; server=
for a in "$@"; do
  case "$a" in --rtr=*) rtr=${a#--rtr=} ;; server) server=1 ;; esac
done
[ -n "$server" ] && [ -n "$rtr" ] || { echo "fake routinator: expected server --rtr=ADDR:PORT" >&2; exit 2; }
[ -e "$dir/fail" ] && { echo "fake routinator: failing as asked" >&2; exit 1; }
delay=$(cat "$dir/delay" 2>/dev/null || echo 0)
[ "$delay" -gt 0 ] && sleep "$delay"   # Routinator listens after its first run
echo $$ > "$dir/pid"
# exec: the RTR server must be this very process, which carries the
# parent-death signal (prctl(2)); a new Session ID per start, as Routinator.
exec "$dir/rtr-stub" "$rtr" $(( $$ % 65535 + 1 )) $(cat "$dir/vrps")
"#;

/// A fake Routinator 0.15.2 for `rpki { mode sidecar; }` (AGENTS.md §5:
/// never a real Routinator), in the directory `routinator` of a lab: the
/// shell script of the private `FAKE_ROUTINATOR`, whose documentation says
/// what it does, and its own copy of `rtr-stub`, which a bgpfcd run as
/// `nobody` can execute whatever the permissions of the checkout. The
/// directory belongs to [`NOBODY`], so that the script can write its
/// records, and bgpfcd the repository directory, there.
pub struct FakeRoutinator {
    /// The directory of the script, its records and its controls.
    pub dir: PathBuf,
    /// The script, for the `binary` statement.
    pub binary: PathBuf,
    /// For the `repository-dir` statement; bgpfcd creates it.
    pub repository: PathBuf,
}

impl FakeRoutinator {
    /// Install a fake that reports version 0.15.2, serving `vrps`:
    /// (prefix, max length, origin AS).
    ///
    /// # Panics
    /// If a file cannot be written or `rtr-stub` is not built.
    #[must_use]
    pub fn install(lab: &Lab, vrps: &[(&str, u8, u32)]) -> FakeRoutinator {
        let dir = lab.dir.join("routinator");
        fs::create_dir_all(&dir).expect("fake routinator dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))
            .expect("fake routinator dir mode");
        std::os::unix::fs::chown(&dir, Some(NOBODY), Some(NOBODY))
            .expect("chown the fake routinator dir to nobody");
        let binary = dir.join("routinator");
        let dir_text = dir.to_str().expect("path");
        assert!(
            !dir_text.contains(|c: char| c.is_whitespace() || c == '\'' || c == '"'),
            "{dir_text}: the script takes the path unquoted"
        );
        fs::write(&binary, FAKE_ROUTINATOR.replace("@DIR@", dir_text)).expect("fake routinator");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))
            .expect("fake routinator mode");
        let stub = dir.join("rtr-stub");
        fs::copy(rtr_stub_path(), &stub).expect("copy rtr-stub");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("rtr-stub mode");
        let vrps: Vec<String> = vrps
            .iter()
            .map(|(prefix, max_len, asn)| format!("{prefix}-{max_len}-{asn}"))
            .collect();
        fs::write(dir.join("vrps"), vrps.join(" ")).expect("fake routinator vrps");
        let fake = FakeRoutinator {
            repository: dir.join("repository"),
            binary,
            dir,
        };
        fake.set_version("Routinator 0.15.2");
        fake
    }

    /// What `--version` prints from now on.
    ///
    /// # Panics
    /// If the file cannot be written.
    pub fn set_version(&self, line: &str) {
        fs::write(self.dir.join("version"), format!("{line}\n")).expect("fake routinator version");
    }

    /// Whether every start from now on fails at once, with exit status 1.
    ///
    /// # Panics
    /// If the marker cannot be written or removed.
    pub fn set_failing(&self, on: bool) {
        let marker = self.dir.join("fail");
        if on {
            fs::write(marker, "").expect("fake routinator fail marker");
        } else if marker.exists() {
            fs::remove_file(marker).expect("fake routinator fail marker");
        }
    }

    /// How many seconds every start from now on waits before it listens,
    /// as Routinator does until its first validation run ends.
    ///
    /// # Panics
    /// If the file cannot be written.
    pub fn set_delay(&self, secs: u32) {
        fs::write(self.dir.join("delay"), secs.to_string()).expect("fake routinator delay");
    }

    /// The arguments of every start other than `--version`, in order.
    #[must_use]
    pub fn invocations(&self) -> Vec<Vec<String>> {
        read(&self.dir.join("invocations"))
            .lines()
            .filter_map(|l| l.strip_prefix("start"))
            .map(|args| args.split_whitespace().map(str::to_owned).collect())
            .collect()
    }

    /// How often the fake was asked `--version`.
    #[must_use]
    pub fn version_checks(&self) -> usize {
        read(&self.dir.join("version-checks")).lines().count()
    }

    /// The process ID of the latest start that came to serve RTR: the
    /// script's own, which `exec` hands to `rtr-stub`.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        read(&self.dir.join("pid")).trim().parse().ok()
    }

    /// The processes that run this fake's `rtr-stub`, by their command
    /// lines: the fake Routinators serving RTR now.
    #[must_use]
    pub fn serving(&self) -> Vec<u32> {
        let stub = self.dir.join("rtr-stub");
        let stub = stub.as_os_str().as_bytes();
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut pids: Vec<u32> = entries
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                fs::read(format!("/proc/{pid}/cmdline"))
                    .is_ok_and(|c| c.split(|&b| b == 0).next() == Some(stub))
            })
            .collect();
        pids.sort_unstable();
        pids
    }

    /// An `rpki` block that runs this fake: `mode sidecar`, then
    /// `rpki_extra`, then a `sidecar` block with its binary and repository
    /// directory, then `sidecar_extra`.
    #[must_use]
    pub fn block(&self, rpki_extra: &str, sidecar_extra: &str) -> String {
        format!(
            "rpki {{ mode sidecar; {rpki_extra} sidecar {{ binary \"{}\"; repository-dir \"{}\"; {sidecar_extra} }} }}",
            self.binary.display(),
            self.repository.display()
        )
    }
}

/// Path to `rtr-stub`. Cargo builds a package's binaries for its
/// integration tests and puts them in `target/<profile>/`, beside the
/// `deps/` directory the test binary runs from.
fn rtr_stub_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let path = exe
        .parent()
        .and_then(Path::parent)
        .expect("target profile dir")
        .join("rtr-stub");
    assert!(
        path.exists(),
        "{} is missing; run the tests with `cargo test -p interop`",
        path.display()
    );
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fake keeps the contract the sidecar scenarios rely on: it
    /// answers `--version` from its file and records the question, refuses
    /// a start that is not `server --rtr=ADDR:PORT`, fails on demand, and
    /// otherwise becomes `rtr-stub` on that address in its own process, so
    /// that its recorded pid is the server's. Its `rpki` block passes
    /// `bgpfcd --check`, which does not run the binary.
    #[test]
    #[ignore = "needs root and iproute2"]
    fn the_fake_routinator_behaves_as_documented() {
        let lab = Lab::new("fr", 25);
        let fake = FakeRoutinator::install(&lab, &[("192.0.2.0/24", 24, 65_001)]);
        let run = |args: &[&str]| {
            Command::new(&fake.binary)
                .args(args)
                .output()
                .expect("fake routinator")
        };

        let out = run(&["--version"]);
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "Routinator 0.15.2\n");
        fake.set_version("Routinator 0.14.1");
        assert_eq!(
            String::from_utf8_lossy(&run(&["-V"]).stdout),
            "Routinator 0.14.1\n"
        );
        assert_eq!(fake.version_checks(), 2);
        assert_eq!(fake.invocations(), Vec::<Vec<String>>::new());

        let out = run(&["--strict", "server"]);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        fake.set_failing(true);
        let out = run(&["server", "--rtr=127.0.0.1:3323"]);
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("failing as asked"));
        fake.set_failing(false);
        assert_eq!(
            fake.invocations(),
            [
                vec!["--strict", "server"],
                vec!["server", "--rtr=127.0.0.1:3323"]
            ]
        );
        assert_eq!(fake.pid(), None);

        let mut cmd = lab.exec(&lab.a, fake.binary.to_str().expect("path"));
        cmd.args(["--no-rir-tals", "server", "--rtr=127.0.0.1:3323"]);
        let mut serving = Daemon::start(cmd, lab.dir.join("fake.log"));
        assert!(
            wait_for(Duration::from_secs(10), || serving
                .log_text()
                .contains("listening on 127.0.0.1:3323: session ")),
            "{}",
            serving.log_text()
        );
        assert!(
            serving.log_text().ends_with(", 1 VRPs\n"),
            "{}",
            serving.log_text()
        );
        assert_eq!(fake.pid(), Some(serving.pid()));
        assert_eq!(fake.serving(), [serving.pid()]);
        assert_eq!(fake.invocations().len(), 3);
        serving.kill();
        assert_eq!(fake.serving(), Vec::<u32>::new());

        let cfg = lab.dir.join("check.conf");
        fs::write(
            &cfg,
            format!(
                "router-id 192.0.2.1;\nlocal-as 65000;\n{}\n",
                fake.block("backoff 1 5;", "refresh 300;")
            ),
        )
        .expect("config");
        let out = Command::new(bgpfcd_path())
            .args(["--check", "-c", cfg.to_str().expect("path")])
            .output()
            .expect("bgpfcd --check");
        assert!(out.status.success(), "{out:?}");
        assert_eq!(fake.version_checks(), 2);
    }
}
