//! Interoperability test harness. Drives BIRD, FRR and `GoBGP` in network
//! namespaces and peers them with `bgpfcd`, and serves it VRPs over RTR
//! from `StayRTR`, or from this crate's stub cache (`src/bin/rtr-stub.rs`)
//! where `StayRTR` cannot be used. Nothing in this crate is shipped
//! (AGENTS.md §1.2).
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

    /// Give both ends of each link an IPv6 address: `2001:db8:9::1` and
    /// `2001:db8:9::2` on the link from A to B, `2001:db8:8::1` and
    /// `2001:db8:8::2` on the one to C, if there is one, all /64. Whether
    /// the kernel took them: a host that boots with `ipv6.disable=1` has no
    /// IPv6 to give.
    #[must_use]
    pub fn add_ipv6(&self) -> bool {
        let mut links = vec![
            (&self.a, format!("v{}a", self.id), "2001:db8:9::1/64"),
            (&self.b, format!("v{}b", self.id), "2001:db8:9::2/64"),
        ];
        if let Some(c) = &self.c {
            links.push((&self.a, format!("v{}a2", self.id), "2001:db8:8::1/64"));
            links.push((c, format!("v{}c", self.id), "2001:db8:8::2/64"));
        }
        links.iter().all(|(ns, dev, addr)| {
            // No duplicate address detection: the address is usable at once.
            Command::new("ip")
                .args(["-n", ns, "addr", "add", addr, "dev", dev, "nodad"])
                .output()
                .is_ok_and(|o| o.status.success())
        })
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

    /// Another address of A's on the link, `10.99.<subnet>.<host>`, for a
    /// second speaker in A to bind to and connect from.
    ///
    /// # Panics
    /// If `ip` fails.
    #[must_use]
    pub fn add_a_addr(&self, host: u8) -> Ipv4Addr {
        let [a, b, c, _] = self.a_addr.octets();
        let addr = Ipv4Addr::new(a, b, c, host);
        sh(
            "ip",
            &[
                "-n",
                &self.a,
                "addr",
                "add",
                &format!("{addr}/24"),
                "dev",
                &format!("v{}a", self.id),
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
        Bird::start_with(lab, ns, opts, "")
    }

    /// [`Bird::start`] with `extra` appended to the configuration: more
    /// protocols, such as a second `static` one whose import filter gives
    /// its routes other attributes than the first's.
    ///
    /// # Panics
    /// If the config cannot be written or `bird` cannot be spawned.
    #[must_use]
    pub fn start_with(lab: &Lab, ns: &str, opts: &BirdOpts, extra: &str) -> Bird {
        Bird::start_named(lab, ns, ns, opts, extra)
    }

    /// [`Bird::start_with`] for a second BIRD process in a namespace that
    /// has one: its files are named after `name` instead of the namespace,
    /// which must differ from the other's. BIRD takes only one BGP protocol
    /// per neighbor address, so a speaker that peers with one address
    /// twice needs two processes.
    ///
    /// # Panics
    /// If the config cannot be written or `bird` cannot be spawned.
    #[must_use]
    pub fn start_named(lab: &Lab, ns: &str, name: &str, opts: &BirdOpts, extra: &str) -> Bird {
        Bird::launch(lab, ns, name, opts, extra, false)
    }

    /// [`Bird::start_with`] for a BIRD that comes back from a graceful
    /// restart (`birdc graceful restart`, then this): `bird -R` applies the
    /// recovery, so that its BGP speaks as a Restarting Speaker (RFC 4724
    /// §4.1): the Restart State and Forwarding State bits are set, and it
    /// waits for End-of-RIB markers before it selects routes.
    ///
    /// # Panics
    /// If the config cannot be written or `bird` cannot be spawned.
    #[must_use]
    pub fn start_recovering(lab: &Lab, ns: &str, opts: &BirdOpts, extra: &str) -> Bird {
        Bird::launch(lab, ns, ns, opts, extra, true)
    }

    fn launch(
        lab: &Lab,
        ns: &str,
        name: &str,
        opts: &BirdOpts,
        extra: &str,
        recover: bool,
    ) -> Bird {
        let cfg = lab.dir.join(format!("bird-{name}.conf"));
        let socket = lab.dir.join(format!("bird-{name}.ctl"));
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
                 }}\n\
                 {extra}\n",
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
        if recover {
            cmd.arg("-R");
        }
        let daemon = Daemon::start(cmd, lab.dir.join(format!("bird-{name}.log")));
        Bird {
            daemon,
            socket,
            lab_ns: ns.to_owned(),
        }
    }

    /// A BIRD in namespace `ns` (the lab's C) that originates
    /// `192.0.2.0/24` three times, as the `static` protocols `short`,
    /// `long` and `longest` whose import filters give the routes AS paths
    /// of one, two and three more hops than the first, and sends bgpfcd
    /// all three under `add paths tx` (RFC 7911 §5). It is passive, in AS
    /// `local_as`, and peers with the lab's A (AS 65000) at `a2_addr`.
    ///
    /// # Panics
    /// If the config cannot be written or `bird` cannot be spawned.
    #[must_use]
    pub fn three_paths(lab: &Lab, ns: &str, local_as: u32) -> Bird {
        Bird::three_paths_with(lab, ns, local_as, "")
    }

    /// [`Bird::three_paths`] with `protocol` added to the BGP protocol,
    /// such as `local role provider;` (RFC 9234).
    ///
    /// # Panics
    /// If the config cannot be written or `bird` cannot be spawned.
    #[must_use]
    pub fn three_paths_with(lab: &Lab, ns: &str, local_as: u32, protocol: &str) -> Bird {
        const THREE: &str = "\
            protocol static short {\n    ipv4 { import all; };\n    route 192.0.2.0/24 blackhole;\n}\n\
            protocol static long {\n    ipv4 { import filter { bgp_path.prepend(64999); accept; }; };\n\
            \x20   route 192.0.2.0/24 blackhole;\n}\n\
            protocol static longest {\n    ipv4 { import filter {\n\
            \x20       bgp_path.prepend(64998); bgp_path.prepend(64999); accept; }; };\n\
            \x20   route 192.0.2.0/24 blackhole;\n}\n";
        Bird::start_with(
            lab,
            ns,
            &BirdOpts {
                local_as,
                local: lab.c_addr,
                local_port: 179,
                neighbor: lab.a2_addr,
                neighbor_port: 179,
                remote_as: 65_000,
                hold_time: 30,
                passive: true,
                statics: Vec::new(),
                channel: "add paths tx;".to_owned(),
                protocol: protocol.to_owned(),
            },
            THREE,
        )
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
        Frr::start_with(lab, ns, opts, "", "")
    }

    /// [`Frr::start`] with lines added to `router bgp` (`global`, such as
    /// more `neighbor` statements) and to its `address-family ipv4
    /// unicast` (`family`, such as `  neighbor X addpath-tx-all-paths`):
    /// complete lines, ending in a newline, indented by one space and by
    /// two as the rest of those blocks are.
    ///
    /// # Panics
    /// If the config cannot be written or `bgpd` cannot be spawned.
    #[must_use]
    pub fn start_with(lab: &Lab, ns: &str, opts: &OtherOpts, global: &str, family: &str) -> Frr {
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
                 {global}\
                 \x20address-family ipv4 unicast\n\
                 {networks}\
                 \x20 neighbor {neighbor} activate\n\
                 {family}\
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
