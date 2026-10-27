//! Interoperability test harness. Drives BIRD, FRR and `GoBGP` in network
//! namespaces and peers them with `bgpfcd`, and serves it VRPs over RTR
//! from `StayRTR`, or from this crate's stub cache (`src/bin/rtr-stub.rs`)
//! where `StayRTR` cannot be used. For `rpki { mode sidecar; }` most
//! scenarios stand in a [`FakeRoutinator`] for Routinator, which can be
//! made to fail, hang or change its version; one runs the real Routinator
//! 0.15 at `/usr/bin/routinator`, with no network, on a [`LocalRpki`] of
//! its own (AGENTS.md §5). Nothing in this crate is shipped (AGENTS.md
//! §1.2).
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

/// Whether every directory from `/` down to `dir` lets others through
/// (their mode has `o+x`), as a process that dropped to `nobody` needs to
/// reach anything below it.
fn others_can_reach(dir: &Path) -> bool {
    dir.canonicalize().is_ok_and(|dir| {
        dir.ancestors().all(|d| {
            fs::metadata(d).is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o001 != 0)
        })
    })
}

/// Where a [`Lab`] keeps its scratch directory: the system's temporary
/// directory if `nobody` can reach it, as a bgpfcd run with `--user nobody`
/// must, and otherwise `/tmp`, as when `TMPDIR` names a directory only root
/// may enter.
fn scratch_base() -> PathBuf {
    [std::env::temp_dir(), PathBuf::from("/tmp")]
        .into_iter()
        .find(|base| others_can_reach(base))
        .unwrap_or_else(|| {
            panic!(
                "neither TMPDIR nor /tmp lets nobody through; set TMPDIR to a directory every \
                 user can reach"
            )
        })
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
        let dir = scratch_base().join(format!("bgpfc-interop-{id}"));
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

    /// The interface of A on its link to B.
    #[must_use]
    pub fn a_link(&self) -> String {
        format!("v{}a", self.id)
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

    /// Make A a router between B and C, which are then two hops apart
    /// over loopback addresses, the lab of multihop sessions
    /// (`interop/tests/multihop.rs`; `S` is the lab's subnet):
    ///
    /// ```text
    ///  C                        A                           B
    ///  lo 10.255.S.3/32         10.98.S.1 -- 10.98.S.2 (C)   lo 10.255.S.2/32
    ///  lo 10.255.S.30/32        10.99.S.1 -- 10.99.S.2 (B)   10.255.S.3/32 via 10.99.S.1 proto static
    ///  10.255.S.2/32 and        ip_forward=1                 10.255.S.30/32 via 10.99.S.1 proto static
    ///  10.99.S.0/24 via         10.255.S.{2,3,30}/32 routes
    ///    10.98.S.1
    /// ```
    ///
    /// C's second loopback is a next hop apart from the session's
    /// address, so that its route can go while the session stays. C also
    /// reaches the link between A and B, so that it answers a connection
    /// from B's address there, as a router's neighbors would.
    ///
    /// # Panics
    /// If [`Lab::add_c`] was not called first, or `ip` fails.
    #[must_use]
    pub fn route_through_a(&self) -> Loopbacks {
        let c = self
            .c
            .as_deref()
            .expect("route_through_a needs add_c first");
        let subnet = self.a_addr.octets()[2];
        let lo = |host| Ipv4Addr::new(10, 255, subnet, host);
        let loopbacks = Loopbacks {
            b: lo(2),
            c: lo(3),
            c_next_hop: lo(30),
        };
        let host = |a: Ipv4Addr| format!("{a}/32");
        let (b_lo, c_los) = (loopbacks.b, [loopbacks.c, loopbacks.c_next_hop]);
        sh(
            "ip",
            &[
                "netns",
                "exec",
                &self.a,
                "sysctl",
                "-qw",
                "net.ipv4.ip_forward=1",
            ],
        );
        sh(
            "ip",
            &["-n", &self.b, "addr", "add", &host(b_lo), "dev", "lo"],
        );
        for a in c_los {
            sh("ip", &["-n", c, "addr", "add", &host(a), "dev", "lo"]);
            // B reaches C's loopbacks by static routes through A.
            sh(
                "ip",
                &[
                    "-n",
                    &self.b,
                    "route",
                    "add",
                    &host(a),
                    "via",
                    &self.a_addr.to_string(),
                    "proto",
                    "static",
                ],
            );
            sh(
                "ip",
                &[
                    "-n",
                    &self.a,
                    "route",
                    "add",
                    &host(a),
                    "via",
                    &self.c_addr.to_string(),
                ],
            );
        }
        let [x, y, z, _] = self.b_addr.octets();
        for to in [host(b_lo), format!("{}/24", Ipv4Addr::new(x, y, z, 0))] {
            sh(
                "ip",
                &[
                    "-n",
                    c,
                    "route",
                    "add",
                    &to,
                    "via",
                    &self.a2_addr.to_string(),
                ],
            );
        }
        sh(
            "ip",
            &[
                "-n",
                &self.a,
                "route",
                "add",
                &host(b_lo),
                "via",
                &self.b_addr.to_string(),
            ],
        );
        loopbacks
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

/// The loopback addresses of a lab routed through A
/// ([`Lab::route_through_a`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loopbacks {
    /// B's, `10.255.S.2`: bgpfcd's session address.
    pub b: Ipv4Addr,
    /// C's, `10.255.S.3`: its speaker's session address.
    pub c: Ipv4Addr,
    /// C's second, `10.255.S.30`: a next hop other than the session's.
    pub c_next_hop: Ipv4Addr,
}

/// A running process whose stderr goes to a file; killed on drop.
pub struct Daemon {
    child: Child,
    /// Where stderr is collected.
    pub log: PathBuf,
}

impl Daemon {
    /// Spawn `cmd` with no standard input or output and its standard
    /// error in the file `log`.
    ///
    /// # Panics
    /// If the log file cannot be created or the process cannot be
    /// spawned.
    #[must_use]
    pub fn start(mut cmd: Command, log: PathBuf) -> Daemon {
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

    /// The process ID. `ip netns exec` and `setpriv` execute the program
    /// in their own place, so this is the daemon's, not theirs.
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
    /// Start the binary in the host's namespace, not through
    /// `ip netns exec`: for a daemon that joins a namespace itself
    /// (`--netns`).
    pub from_host: bool,
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
            from_host: false,
        }
    }
}

/// Write the configuration of a `bgpfcd` for namespace `ns`,
/// `bgpfcd-<ns>.conf` in the lab's directory, with debug logging. Both
/// families are offered, and an accept-all policy is used in both
/// directions. The file is readable by every user, as a bgpfcd started
/// with `--user` reads it again at a reload. Its path is returned.
///
/// # Panics
/// If the file cannot be written.
#[must_use]
pub fn bgpfcd_config(lab: &Lab, ns: &str, opts: &BgpfcdOpts) -> PathBuf {
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
    cfg
}

/// Write a configuration ([`bgpfcd_config`]) and start `bgpfcd` in
/// namespace `ns`, or, with `opts.from_host`, in the host's namespace,
/// with the further arguments of `opts`. Its log is `bgpfcd-<ns>.log`.
///
/// # Panics
/// If the config cannot be written or the process cannot be spawned.
#[must_use]
pub fn start_bgpfcd(lab: &Lab, ns: &str, opts: &BgpfcdOpts) -> Daemon {
    let cfg = bgpfcd_config(lab, ns, opts);
    let mut cmd = if opts.from_host {
        Command::new(bgpfcd_path())
    } else {
        lab.exec(ns, bgpfcd_path().to_str().expect("path"))
    };
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
    /// What the `ipv4` channel exports: a filter, such as `filter {
    /// bgp_next_hop = 192.0.2.30; accept; }`; empty is `all`.
    pub export: String,
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
                 \x20   ipv4 {{ import all; export {export}; {channel} }};\n\
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
                export = if opts.export.is_empty() {
                    "all"
                } else {
                    &opts.export
                },
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
/// as a restarted Routinator does. `fail` makes every start exit 1 at once.
/// Otherwise each start leaves a child of its own running, in its process
/// group, as Routinator's `rsync` runs during a validation run: a `sleep`,
/// whose process ID goes to `children`. `delay` holds the start that many
/// seconds before it listens, as Routinator's first validation run does.
/// Every `--version` adds a line
/// to `version-checks`; from the one whose number `version-from` holds on,
/// it prints `version-later` instead of `version`. `@DIR@` is the
/// directory of these files.
const FAKE_ROUTINATOR: &str = r#"#!/bin/sh
# A stand-in for Routinator 0.15 in bgpfc's interop tests; never shipped.
dir=@DIR@
case "$1" in --version|-V)
  echo "$*" >> "$dir/version-checks"
  if [ -e "$dir/version-from" ] && [ "$(wc -l < "$dir/version-checks")" -ge "$(cat "$dir/version-from")" ]
  then cat "$dir/version-later"; else cat "$dir/version"; fi
  exit 0 ;;
esac
{ printf 'start'; for a in "$@"; do printf ' %s' "$a"; done; echo; } >> "$dir/invocations"
rtr=; server=
for a in "$@"; do
  case "$a" in --rtr=*) rtr=${a#--rtr=} ;; server) server=1 ;; esac
done
[ -n "$server" ] && [ -n "$rtr" ] || { echo "fake routinator: expected server --rtr=ADDR:PORT" >&2; exit 2; }
[ -e "$dir/fail" ] && { echo "fake routinator: failing as asked" >&2; exit 1; }
sleep @CHILD@ </dev/null >/dev/null 2>&1 &   # Routinator's rsync
echo $! >> "$dir/children"
delay=$(cat "$dir/delay" 2>/dev/null || echo 0)
[ "$delay" -gt 0 ] && sleep "$delay"   # Routinator listens after its first run
echo $$ > "$dir/pid"
# exec: the RTR server must be this very process, which carries the
# parent-death signal (prctl(2)); a new Session ID per start, as Routinator.
exec "$dir/rtr-stub" "$rtr" $(( $$ % 65535 + 1 )) $(cat "$dir/vrps")
"#;

/// How long the child each start of a [`FakeRoutinator`] leaves runs.
const CHILD_SECONDS: u32 = 300;

/// A fake Routinator 0.15.2 for `rpki { mode sidecar; }` (AGENTS.md §5:
/// never a real Routinator), in the directory `routinator` of a lab: the
/// shell script of the private `FAKE_ROUTINATOR`, whose documentation says
/// what it does, and its own copy of `rtr-stub`, which a bgpfcd run as
/// `nobody` can execute whatever the permissions of the checkout. The
/// directory belongs to [`NOBODY`], so that the script can write its
/// records, and bgpfcd the repository directory, there. 0.15.2 is a patch
/// release before the one bgpfcd is tested with, 0.15.3, and bgpfcd
/// accepts it as the same series.
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
        let script = FAKE_ROUTINATOR
            .replace("@DIR@", dir_text)
            .replace("@CHILD@", &CHILD_SECONDS.to_string());
        fs::write(&binary, script).expect("fake routinator");
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

    /// What `--version` prints from now on; it ends a switch that
    /// [`FakeRoutinator::switch_version`] set.
    ///
    /// # Panics
    /// If the file cannot be written.
    pub fn set_version(&self, line: &str) {
        let _ = fs::remove_file(self.dir.join("version-from"));
        fs::write(self.dir.join("version"), format!("{line}\n")).expect("fake routinator version");
    }

    /// What `--version` prints from the `check`-th question on, counting
    /// every one since [`FakeRoutinator::install`]: a binary replaced
    /// between two of bgpfcd's checks, such as a reload's preflight and
    /// the start that follows it.
    ///
    /// # Panics
    /// If a file cannot be written.
    pub fn switch_version(&self, check: usize, line: &str) {
        fs::write(self.dir.join("version-later"), format!("{line}\n"))
            .expect("fake routinator later version");
        fs::write(self.dir.join("version-from"), check.to_string())
            .expect("fake routinator version switch");
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

    /// The process IDs of the children its starts left, the stand-ins for
    /// Routinator's `rsync`, in order: dead ones too.
    #[must_use]
    pub fn children(&self) -> Vec<u32> {
        read(&self.dir.join("children"))
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    /// Kill the children that still run, as systemd kills what is left of
    /// a service's control group. A process ID is signalled only while it
    /// still runs the child's command, so not once another process has it.
    pub fn kill_children(&self) {
        let command = format!("sleep\0{CHILD_SECONDS}\0");
        for pid in self.children() {
            let running =
                fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| c == command.as_bytes());
            if running {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
            }
        }
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

impl Drop for FakeRoutinator {
    /// [`FakeRoutinator::kill_children`]: a test leaves no `sleep` behind,
    /// also one that fails.
    fn drop(&mut self) {
        self.kill_children();
    }
}

/// Where a [`LocalRpki`] publishes: an rsync module on the loopback
/// address of a lab namespace. Routinator refuses a host name that is an
/// IP address unless it may use "dubious" ones (manual page,
/// `--allow-dubious-hosts`).
pub const LOCAL_RPKI_BASE: &str = "rsync://127.0.0.1/rpki";

/// The certificate policy every resource certificate carries,
/// id-cp-ipAddr-asNumber (RFC 6484 §1.2; RFC 6487 §4.8.9).
const RPKI_POLICY: &str = "1.3.6.1.5.5.7.14.2";

/// The eContentType of a ROA, id-ct-routeOriginAuthz (RFC 9582 §3).
const CT_ROA: &str = "1.2.840.113549.1.9.16.1.24";

/// The eContentType of a manifest, id-ct-rpkiManifest (RFC 9286 §4.1).
const CT_MANIFEST: &str = "1.2.840.113549.1.9.16.1.26";

/// id-sha256 (RFC 5754 §2.2), the hash a manifest lists its files with
/// (RFC 7935 §2).
const ID_SHA256: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 1];

/// How long every certificate and CRL of a [`LocalRpki`] is valid, in
/// days: far beyond any test run.
const LOCAL_RPKI_DAYS: &str = "36500";

/// An RPKI repository of the test's own, for the real Routinator: one
/// trust anchor that holds every address and AS number, and a ROA for each
/// VRP a test asks for, signed with `openssl` when the test starts and
/// published by an `rsync` daemon on `127.0.0.1:873` in a lab namespace.
/// Routinator, given the trust anchor locator in [`LocalRpki::tals`] and
/// allowed the loopback host name ([`LOCAL_RPKI_BASE`]), validates it
/// without any network beyond that namespace.
///
/// The objects follow the profiles Routinator checks, in its `--strict`
/// mode too:
/// - the trust anchor certificate, self-signed, with the resources, key
///   usage, policy and Subject Information Access of a CA (RFC 6487
///   §4.8), the CRL it issues (RFC 6487 §5) and the trust anchor locator
///   that names it (RFC 8630 §2.2);
/// - a ROA for each VRP (RFC 9582), and a manifest of the CRL and the
///   ROAs (RFC 9286), each a CMS signed object (RFC 6488) with a
///   one-time-use EE certificate: the ROA's holds exactly its prefix
///   (RFC 9582 §5), the manifest's inherits every resource and is valid
///   from its thisUpdate to its nextUpdate (RFC 9286 §5.1);
/// - names that are a `CommonName` in a `PrintableString` (RFC 6487 §4.4,
///   §4.5), which `openssl` writes only when told to.
///
/// The repository lives in the lab's directory, `rpki/`: the published
/// tree in `public/`, the TAL in `tals/`, keys and requests in `work/`.
/// Every user may read all of it, since Routinator and the daemon run as
/// `nobody`; the keys sign nothing but this test's objects.
pub struct LocalRpki {
    /// The directory of the trust anchor locator, for the
    /// `extra-tals-dir` statement.
    pub tals: PathBuf,
    /// The `rsync` daemon that publishes the repository.
    pub rsyncd: Daemon,
}

impl LocalRpki {
    /// Build the repository with a ROA for each of `vrps`, (prefix, max
    /// length, origin AS), and publish it in namespace `ns`.
    ///
    /// # Panics
    /// If `openssl` or `rsync` is missing or fails, a prefix does not
    /// parse, or a file cannot be written.
    #[must_use]
    pub fn publish(lab: &Lab, ns: &str, vrps: &[(&str, u8, u32)]) -> LocalRpki {
        let root = lab.dir.join("rpki");
        let public = root.join("public");
        let point = public.join("repo");
        let tals = root.join("tals");
        let ca = Issuer {
            work: root.join("work"),
            serial: std::cell::Cell::new(1),
        };
        for dir in [&ca.work, &public.join("ta"), &point, &tals] {
            fs::create_dir_all(dir).expect("local rpki dir");
        }
        ca.trust_anchor(&public.join("ta").join("ta.cer"), &tals);
        ca.crl(&point.join("ta.crl"));
        let mut files = vec!["ta.crl".to_owned()];
        for (i, &(prefix, max_len, asn)) in vrps.iter().enumerate() {
            let file = format!("roa-{i}.roa");
            ca.roa(&point.join(&file), prefix, max_len, asn);
            files.push(file);
        }
        ca.manifest(&point, &files);
        // Whatever the umask: the daemon and Routinator run as nobody.
        sh("chmod", &["-R", "a+rX", root.to_str().expect("path")]);
        let rsyncd = serve_rsync(lab, ns, &root, &public);
        LocalRpki { tals, rsyncd }
    }
}

/// Start `rsync --daemon` in namespace `ns`, publishing `public` as the
/// module of [`LOCAL_RPKI_BASE`] to [`NOBODY`]'s reading, and wait until
/// it answers.
fn serve_rsync(lab: &Lab, ns: &str, root: &Path, public: &Path) -> Daemon {
    let config = root.join("rsyncd.conf");
    fs::write(
        &config,
        format!(
            "use chroot = no\nuid = {NOBODY}\ngid = {NOBODY}\n[rpki]\npath = {}\nread only = yes\n",
            public.display()
        ),
    )
    .expect("rsyncd.conf");
    let mut cmd = lab.exec(ns, "rsync");
    cmd.args([
        "--daemon",
        "--no-detach",
        "--address=127.0.0.1",
        "--port=873",
    ])
    .arg(format!("--config={}", config.display()))
    .arg(format!(
        "--log-file={}",
        lab.dir
            .join(format!("rsyncd-{ns}-connections.log"))
            .display()
    ));
    let daemon = Daemon::start(cmd, lab.dir.join(format!("rsyncd-{ns}.log")));
    let listing = format!("{LOCAL_RPKI_BASE}/repo/");
    assert!(
        wait_for(Duration::from_secs(10), || {
            let mut list = lab.exec(ns, "rsync");
            list.arg(&listing)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        }),
        "rsync --daemon did not serve {listing}:\n{}",
        daemon.log_text()
    );
    daemon
}

/// The trust anchor of a [`LocalRpki`], which signs everything in it,
/// working in `work`.
struct Issuer {
    work: PathBuf,
    /// The serial number the next certificate gets (RFC 6487 §4.2).
    serial: std::cell::Cell<u32>,
}

impl Issuer {
    /// Run `openssl` in the work directory; its standard output.
    fn openssl(&self, args: &[&str]) -> Vec<u8> {
        let out = Command::new("openssl")
            .current_dir(&self.work)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("running openssl {}: {e}", args.join(" ")));
        assert!(
            out.status.success(),
            "openssl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) {
        fs::write(self.work.join(name), contents).expect("local rpki work file");
    }

    fn next_serial(&self) -> String {
        let serial = self.serial.get();
        self.serial.set(serial + 1);
        serial.to_string()
    }

    /// A key pair `NAME.key` and a request `NAME.csr` for the subject
    /// `CN=bgpfc-interop-NAME`, in a `PrintableString` (RFC 6487 §4.5):
    /// `string_mask = default` picks it, where `openssl`'s own setting
    /// writes a `UTF8String`.
    fn request(&self, name: &str) {
        self.openssl(&["genrsa", "-out", &format!("{name}.key"), "2048"]);
        self.write(
            &format!("{name}.req"),
            format!(
                "[req]\ndistinguished_name = dn\nstring_mask = default\nprompt = no\n\
                 [dn]\nCN = bgpfc-interop-{name}\n"
            ),
        );
        self.openssl(&[
            "req",
            "-new",
            "-key",
            &format!("{name}.key"),
            "-config",
            &format!("{name}.req"),
            "-out",
            &format!("{name}.csr"),
        ]);
    }

    /// The self-signed trust anchor certificate `ta.pem`, published as
    /// `cer` in DER, and the trust anchor locator that names it, in
    /// `tals/bgpfc-interop.tal` (RFC 8630 §2.2: its URI, an empty line,
    /// and its subjectPublicKeyInfo in base64).
    fn trust_anchor(&self, cer: &Path, tals: &Path) {
        self.request("ta");
        // RFC 6487 §4.8: the extensions of a CA certificate. A
        // self-signed one MAY leave out the Authority Key Identifier
        // (§4.8.3) and MUST leave out CRL Distribution Points and
        // Authority Information Access (§4.8.6, §4.8.7). Every address and
        // AS number, as an RIR's trust anchor holds them (§4.8.10,
        // §4.8.11).
        self.write(
            "ta.ext",
            format!(
                "[ext]\n\
                 basicConstraints = critical, CA:true\n\
                 keyUsage = critical, keyCertSign, cRLSign\n\
                 subjectKeyIdentifier = hash\n\
                 subjectInfoAccess = caRepository;URI:{LOCAL_RPKI_BASE}/repo/, \
                 rpkiManifest;URI:{LOCAL_RPKI_BASE}/repo/ta.mft\n\
                 certificatePolicies = critical, {RPKI_POLICY}\n\
                 sbgp-ipAddrBlock = critical, IPv4:0.0.0.0/0, IPv6:::/0\n\
                 sbgp-autonomousSysNum = critical, AS:0-4294967295\n"
            ),
        );
        let serial = self.next_serial();
        self.openssl(&[
            "x509",
            "-req",
            "-in",
            "ta.csr",
            "-signkey",
            "ta.key",
            "-set_serial",
            &serial,
            "-days",
            LOCAL_RPKI_DAYS,
            "-sha256",
            "-extfile",
            "ta.ext",
            "-extensions",
            "ext",
            "-out",
            "ta.pem",
        ]);
        let cer = cer.to_str().expect("path");
        self.openssl(&["x509", "-in", "ta.pem", "-outform", "DER", "-out", cer]);
        self.openssl(&[
            "pkey", "-in", "ta.key", "-pubout", "-outform", "DER", "-out", "ta.spki",
        ]);
        let spki = self.openssl(&["base64", "-A", "-in", "ta.spki"]);
        let spki = String::from_utf8(spki).expect("base64 is ASCII");
        fs::write(
            tals.join("bgpfc-interop.tal"),
            format!("{LOCAL_RPKI_BASE}/ta/ta.cer\n\n{}\n", spki.trim()),
        )
        .expect("trust anchor locator");
    }

    /// The trust anchor's CRL, empty, in DER at `out` (RFC 6487 §5: a
    /// version 2 CRL with the Authority Key Identifier and a CRL number).
    fn crl(&self, out: &Path) {
        let work = self.work.display();
        self.write(
            "ca.cnf",
            format!(
                "[ca]\ndefault_ca = ta\n[ta]\ndatabase = {work}/index.txt\n\
                 crlnumber = {work}/crlnumber\ndefault_md = sha256\n\
                 default_crl_days = {LOCAL_RPKI_DAYS}\ncrl_extensions = crl_ext\n\
                 [crl_ext]\nauthorityKeyIdentifier = keyid:always\n"
            ),
        );
        self.write("index.txt", "");
        self.write("crlnumber", "01\n");
        self.openssl(&[
            "ca",
            "-gencrl",
            "-config",
            "ca.cnf",
            "-keyfile",
            "ta.key",
            "-cert",
            "ta.pem",
            "-out",
            "ta.crl.pem",
        ]);
        let out = out.to_str().expect("path");
        self.openssl(&["crl", "-in", "ta.crl.pem", "-outform", "DER", "-out", out]);
    }

    /// A one-time-use EE certificate `NAME.pem` for the signed object
    /// published as `file`, with `resources` as its RFC 3779 extensions;
    /// its validity, `(notBefore, notAfter)` as `GeneralizedTime`.
    fn end_entity(&self, name: &str, file: &str, resources: &str) -> (String, String) {
        self.request(name);
        // RFC 6487 §4.8: the extensions of an EE certificate, which signs
        // the one object its Subject Information Access names (§4.8.8.2).
        self.write(
            &format!("{name}.ext"),
            format!(
                "[ext]\n\
                 keyUsage = critical, digitalSignature\n\
                 subjectKeyIdentifier = hash\n\
                 authorityKeyIdentifier = keyid:always\n\
                 crlDistributionPoints = URI:{LOCAL_RPKI_BASE}/repo/ta.crl\n\
                 authorityInfoAccess = caIssuers;URI:{LOCAL_RPKI_BASE}/ta/ta.cer\n\
                 subjectInfoAccess = signedObject;URI:{LOCAL_RPKI_BASE}/repo/{file}\n\
                 certificatePolicies = critical, {RPKI_POLICY}\n\
                 {resources}"
            ),
        );
        let serial = self.next_serial();
        self.openssl(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            "ta.pem",
            "-CAkey",
            "ta.key",
            "-set_serial",
            &serial,
            "-days",
            LOCAL_RPKI_DAYS,
            "-sha256",
            "-extfile",
            &format!("{name}.ext"),
            "-extensions",
            "ext",
            "-out",
            &format!("{name}.pem"),
        ]);
        let dates = self.openssl(&[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-noout",
            "-startdate",
            "-enddate",
            "-dateopt",
            "iso_8601",
        ]);
        let dates = String::from_utf8_lossy(&dates).into_owned();
        let date = |field: &str| -> String {
            let iso = dates
                .lines()
                .find_map(|l| l.strip_prefix(field))
                .unwrap_or_else(|| panic!("no {field} in {dates}"));
            // `2026-10-27 05:00:06Z` as `20261027050006Z`.
            iso.chars().filter(|c| !"-: ".contains(*c)).collect()
        };
        (date("notBefore="), date("notAfter="))
    }

    /// Sign `content` with `NAME.pem` as a CMS signed object of
    /// `content_type`, in DER at `out` (RFC 6488 §2): the EE certificate
    /// included, the signer named by its Subject Key Identifier
    /// (§2.1.6.2, `-keyid`), SHA-256, and no signed attribute beyond
    /// content type, message digest and signing time (§2.1.6.4,
    /// `-nosmimecap`).
    fn sign(&self, name: &str, content_type: &str, content: &[u8], out: &Path) {
        let econtent = format!("{name}.econtent");
        self.write(&econtent, content);
        self.openssl(&[
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-in",
            &econtent,
            "-econtent_type",
            content_type,
            "-signer",
            &format!("{name}.pem"),
            "-inkey",
            &format!("{name}.key"),
            "-md",
            "sha256",
            "-keyid",
            "-nosmimecap",
            "-outform",
            "DER",
            "-out",
            out.to_str().expect("path"),
        ]);
    }

    /// A ROA at `out` for `asn` to originate `prefix` up to `max_len`
    /// (RFC 9582). Its EE certificate holds exactly that prefix, neither
    /// `inherit` nor AS numbers (RFC 9582 §5).
    fn roa(&self, out: &Path, prefix: &str, max_len: u8, asn: u32) {
        let (addr, len) = parse_prefix(prefix);
        let family = if addr.is_ipv4() { "IPv4" } else { "IPv6" };
        let name = out
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("roa file name");
        let file = out
            .file_name()
            .and_then(|s| s.to_str())
            .expect("roa file name");
        self.end_entity(
            name,
            file,
            &format!("sbgp-ipAddrBlock = critical, {family}:{prefix}\n"),
        );
        self.sign(name, CT_ROA, &roa_econtent(asn, addr, len, max_len), out);
    }

    /// The manifest `ta.mft` in the publication point `point`, listing
    /// `files` there with their SHA-256 hashes (RFC 9286 §4.2.1). Its EE
    /// certificate inherits the trust anchor's resources, and its
    /// validity is the manifest's thisUpdate to nextUpdate (RFC 9286
    /// §5.1).
    fn manifest(&self, point: &Path, files: &[String]) {
        let (this_update, next_update) = self.end_entity(
            "mft",
            "ta.mft",
            "sbgp-ipAddrBlock = critical, IPv4:inherit, IPv6:inherit\n\
             sbgp-autonomousSysNum = critical, AS:inherit\n",
        );
        let hashes: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|file| {
                let path = point.join(file);
                let hash =
                    self.openssl(&["dgst", "-sha256", "-binary", path.to_str().expect("path")]);
                (file.clone(), hash)
            })
            .collect();
        let content = manifest_econtent(1, &this_update, &next_update, &hashes);
        self.sign("mft", CT_MANIFEST, &content, &point.join("ta.mft"));
    }
}

/// `ADDRESS/LENGTH` as an address and a length.
///
/// # Panics
/// If it does not parse.
fn parse_prefix(prefix: &str) -> (IpAddr, u8) {
    prefix
        .split_once('/')
        .and_then(|(addr, len)| Some((addr.parse().ok()?, len.parse().ok()?)))
        .unwrap_or_else(|| panic!("{prefix} is not a prefix"))
}

/// The DER encoding (X.690 §8.1, §10.1) of a value: its tag, its length
/// in the definite form, the shortest one, and its contents.
fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(u8::try_from(len).expect("below 0x80"));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let count = u8::try_from(bytes.len() - skip).expect("at most 8 length octets");
        out.push(0x80 | count);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

/// A SEQUENCE of `items`, each already encoded.
fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &items.concat())
}

/// A non-negative INTEGER (X.690 §8.3): the fewest octets of two's
/// complement, with a leading zero octet where the top bit is set.
fn der_uint(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(7);
    let mut contents = bytes[skip..].to_vec();
    if contents[0] & 0x80 != 0 {
        contents.insert(0, 0);
    }
    der(0x02, &contents)
}

/// An OBJECT IDENTIFIER (X.690 §8.19): the first two arcs in one
/// subidentifier, each subidentifier in base 128, high bit set on all
/// octets but its last.
fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut contents = Vec::new();
    let first = arcs[0] * 40 + arcs[1];
    for arc in std::iter::once(first).chain(arcs[2..].iter().copied()) {
        let mut septets = vec![u8::try_from(arc & 0x7f).expect("seven bits")];
        let mut rest = arc >> 7;
        while rest > 0 {
            septets.push(0x80 | u8::try_from(rest & 0x7f).expect("seven bits"));
            rest >>= 7;
        }
        contents.extend(septets.iter().rev());
    }
    der(0x06, &contents)
}

/// A BIT STRING of `bits`, the last `unused` bits of which are not part
/// of it (X.690 §8.6).
fn der_bits(unused: u8, bits: &[u8]) -> Vec<u8> {
    let mut contents = vec![unused];
    contents.extend_from_slice(bits);
    der(0x03, &contents)
}

/// An IP prefix as RFC 3779 §2.1.1 encodes it: a BIT STRING of the
/// constant most-significant bits, the unused ones zero.
fn der_prefix(addr: IpAddr, len: u8) -> Vec<u8> {
    let octets = match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let used = usize::from(len).div_ceil(8);
    let unused = u8::try_from(used * 8 - usize::from(len)).expect("fewer than 8");
    let mut bits = octets[..used].to_vec();
    if let Some(last) = bits.last_mut() {
        *last &= 0xff << unused;
    }
    der_bits(unused, &bits)
}

/// The eContent of a ROA (RFC 9582 §4) for `asn` to originate the prefix
/// `addr/len` up to `max_len`.
fn roa_econtent(asn: u32, addr: IpAddr, len: u8, max_len: u8) -> Vec<u8> {
    // RFC 9582 §4.3.1: the AFI, 1 for IPv4 and 2 for IPv6.
    let afi: &[u8] = if addr.is_ipv4() { &[0, 1] } else { &[0, 2] };
    let mut address = vec![der_prefix(addr, len)];
    // RFC 9582 §4.3.2.2: maxLength SHOULD NOT be encoded when it is the
    // prefix length.
    if max_len != len {
        address.push(der_uint(u64::from(max_len)));
    }
    let family = der_sequence(&[der(0x04, afi), der_sequence(&[der_sequence(&address)])]);
    // RFC 9582 §4.1: version 0, the DEFAULT, which DER leaves out
    // (X.690 §11.5).
    der_sequence(&[der_uint(u64::from(asn)), der_sequence(&[family])])
}

/// The eContent of a manifest (RFC 9286 §4.2): `number`, the two times as
/// `GeneralizedTime`, SHA-256, and each file's name with its hash.
fn manifest_econtent(
    number: u64,
    this_update: &str,
    next_update: &str,
    files: &[(String, Vec<u8>)],
) -> Vec<u8> {
    let list: Vec<Vec<u8>> = files
        .iter()
        .map(|(name, hash)| der_sequence(&[der(0x16, name.as_bytes()), der_bits(0, hash)]))
        .collect();
    // RFC 9286 §4.2.1: version 0, the DEFAULT, left out (X.690 §11.5).
    der_sequence(&[
        der_uint(number),
        der(0x18, this_update.as_bytes()),
        der(0x18, next_update.as_bytes()),
        der_oid(&ID_SHA256),
        der_sequence(&list),
    ])
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
        // A switch from the fourth question on, which `set_version` ends.
        fake.switch_version(4, "Routinator 0.13.0");
        assert_eq!(
            String::from_utf8_lossy(&run(&["--version"]).stdout),
            "Routinator 0.14.1\n"
        );
        for _ in 0..2 {
            assert_eq!(
                String::from_utf8_lossy(&run(&["--version"]).stdout),
                "Routinator 0.13.0\n"
            );
        }
        fake.set_version("Routinator 0.14.1");
        assert_eq!(
            String::from_utf8_lossy(&run(&["--version"]).stdout),
            "Routinator 0.14.1\n"
        );
        assert_eq!(fake.version_checks(), 6);

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
        // One child, in the server's process group, which a kill of the
        // server alone leaves running.
        let children = fake.children();
        assert_eq!(children.len(), 1, "{children:?}");
        let alive = |pid: u32| {
            fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(") ")
                    .is_some_and(|(_, rest)| !rest.starts_with('Z'))
            })
        };
        assert!(alive(children[0]));
        serving.kill();
        assert_eq!(fake.serving(), Vec::<u32>::new());
        assert!(alive(children[0]));
        fake.kill_children();
        assert!(wait_for(Duration::from_secs(5), || !alive(children[0])));

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
        assert_eq!(fake.version_checks(), 6);
    }

    /// The DER a [`LocalRpki`] writes: RFC 3779 §2.1.1's prefixes, both
    /// forms of length (X.690 §8.1.3), integers with and without a
    /// leading zero (§8.3), `id-sha256` as certificates carry it, and a
    /// ROA's eContent laid out as RFC 9582 §4 defines it.
    #[test]
    fn der_is_written_as_the_rfcs_lay_it_out() {
        let prefix = |p: &str| {
            let (addr, len) = parse_prefix(p);
            der_prefix(addr, len)
        };
        assert_eq!(
            prefix("10.5.0.4/32"),
            [0x03, 0x05, 0x00, 0x0a, 0x05, 0x00, 0x04]
        );
        assert_eq!(prefix("10.5.0.0/23"), [0x03, 0x04, 0x01, 0x0a, 0x05, 0x00]);
        assert_eq!(
            prefix("2001:0:200:3::1/128"),
            [
                0x03, 0x11, 0x00, 0x20, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01
            ]
        );
        assert_eq!(
            prefix("2001:0:200::/39"),
            [0x03, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02]
        );
        // Host bits past the length are left out, as DER wants them zero.
        assert_eq!(prefix("10.5.1.255/23"), prefix("10.5.0.0/23"));
        assert_eq!(prefix("0.0.0.0/0"), [0x03, 0x01, 0x00]);

        assert_eq!(der(0x04, &[7; 3]), [0x04, 0x03, 7, 7, 7]);
        assert_eq!(der(0x04, &[0; 127])[..2], [0x04, 0x7f]);
        assert_eq!(der(0x04, &[0; 128])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(der(0x04, &[0; 300])[..4], [0x04, 0x82, 0x01, 0x2c]);

        assert_eq!(der_uint(0), [0x02, 0x01, 0x00]);
        assert_eq!(der_uint(127), [0x02, 0x01, 0x7f]);
        assert_eq!(der_uint(128), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(der_uint(65_001), [0x02, 0x03, 0x00, 0xfd, 0xe9]);
        assert_eq!(
            der_uint(u64::from(u32::MAX)),
            [0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff]
        );

        assert_eq!(
            der_oid(&ID_SHA256),
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
            ]
        );

        let (addr, len) = parse_prefix("192.0.2.0/24");
        let address = [0x30, 0x06, 0x03, 0x04, 0x00, 0xc0, 0x00, 0x02];
        let addresses = [&[0x30, 0x08][..], &address].concat();
        let family = [&[0x30, 0x0e, 0x04, 0x02, 0x00, 0x01][..], &addresses].concat();
        let blocks = [&[0x30, 0x10][..], &family].concat();
        let as_id = [0x02, 0x03, 0x00, 0xfd, 0xe9];
        let roa = [&[0x30, 0x17][..], &as_id, &blocks].concat();
        assert_eq!(roa_econtent(65_001, addr, len, 24), roa);
        // A longer maxLength follows the address in its SEQUENCE.
        let longer = roa_econtent(65_001, addr, len, 26);
        assert_eq!(longer.len(), roa.len() + 3);
        assert!(longer.windows(11).any(|w| w
            == [
                0x30, 0x09, 0x03, 0x04, 0x00, 0xc0, 0x00, 0x02, 0x02, 0x01, 26
            ]));
    }

    /// The repository a [`LocalRpki`] publishes is valid to the real
    /// Routinator, in its strict mode, from inside a lab namespace and
    /// with no other network: `routinator vrps` gives back the VRPs it was
    /// built from, IPv6 and a longer maxLength included.
    #[test]
    #[ignore = "needs root, iproute2, openssl, rsync and routinator 0.15"]
    fn the_local_rpki_is_valid_to_routinator() {
        let lab = Lab::new("lr", 38);
        let vrps = [
            ("192.0.2.0/24", 24, 65_001),
            ("198.51.100.0/24", 26, 64_999),
            ("2001:db8::/32", 48, 65_002),
        ];
        let rpki = LocalRpki::publish(&lab, &lab.a, &vrps);
        let cache = lab.dir.join("routinator-cache");
        let mut cmd = lab.exec(&lab.a, "timeout");
        cmd.env("HOME", &lab.dir)
            .args(["60", "/usr/bin/routinator", "--strict", "--no-rir-tals"])
            .arg(format!("--repository-dir={}", cache.display()))
            .arg(format!("--extra-tals-dir={}", rpki.tals.display()))
            .args(["--allow-dubious-hosts", "vrps"]);
        let out = cmd.output().expect("routinator vrps");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut got: Vec<&str> = stdout.lines().skip(1).collect();
        got.sort_unstable();
        assert_eq!(
            got,
            [
                "AS64999,198.51.100.0/24,26,bgpfc-interop",
                "AS65001,192.0.2.0/24,24,bgpfc-interop",
                "AS65002,2001:db8::/32,48,bgpfc-interop",
            ],
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
