//! Interoperability test harness. Drives BIRD (and later FRR and `GoBGP`)
//! in network namespaces and peers them with `bgpfcd`. Nothing in this
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
use std::net::Ipv4Addr;
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
        }
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
        let _ = fs::remove_dir_all(&self.dir);
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

/// Options for one `bgpfcd` under test.
pub struct BgpfcdOpts {
    /// Our AS.
    pub local_as: u32,
    /// Router ID (also the listen address).
    pub router_id: Ipv4Addr,
    /// The peer's address.
    pub neighbor: Ipv4Addr,
    /// The peer's AS.
    pub remote_as: u32,
    /// Hold time in seconds.
    pub hold_time: u16,
    /// Never initiate the TCP connection.
    pub passive: bool,
}

/// Start `bgpfcd` in namespace `ns` with debug logging.
///
/// # Panics
/// If the process cannot be spawned.
#[must_use]
pub fn start_bgpfcd(lab: &Lab, ns: &str, opts: &BgpfcdOpts) -> Daemon {
    let mut cmd = lab.exec(ns, bgpfcd_path().to_str().expect("path"));
    cmd.args([
        "--local-as",
        &opts.local_as.to_string(),
        "--router-id",
        &opts.router_id.to_string(),
        "--listen",
        &format!("{}:179", opts.router_id),
        "--log-level",
        "debug",
        "--neighbor",
        &opts.neighbor.to_string(),
        "--remote-as",
        &opts.remote_as.to_string(),
        "--hold-time",
        &opts.hold_time.to_string(),
    ]);
    if opts.passive {
        cmd.arg("--passive");
    }
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
    /// The peer's address.
    pub neighbor: Ipv4Addr,
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
                 \x20   local {local} as {local_as};\n\
                 \x20   neighbor {neighbor} as {remote_as};\n\
                 \x20   hold time {hold};\n\
                 {passive}\
                 \x20   ipv4 {{ import all; export all; }};\n\
                 }}\n",
                local = opts.local,
                local_as = opts.local_as,
                neighbor = opts.neighbor,
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
