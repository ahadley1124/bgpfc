//! Graceful Restart (RFC 4724, RFC 8538) between `bgpfcd` and BIRD 2 and
//! FRR (AGENTS.md §5, `interop/` row), in both directions: a peer that
//! restarts while `bgpfcd` keeps its routes as a Receiving Speaker, and
//! `bgpfcd` restarting in install mode while the peer keeps its routes and
//! the kernel keeps the routes `bgpfcd` installed.
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird` or FRR's
//! `bgpd`, and a built `bgpfcd`. CI runs them with `--include-ignored`
//! under sudo. A scenario that installs IPv6 routes needs IPv6 in the
//! kernel; where the host has none (it boots with `ipv6.disable=1`) it says
//! so and returns, and the IPv6 routes that travel over an IPv4 session
//! without being installed are tried all the same.

use std::path::Path;
use std::time::{Duration, Instant};

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, Frr, Lab, NeighborOpts, OtherOpts, bgpfcctl, start_bgpfcd,
    wait_for,
};

const BGPFC_AS: u32 = 65_000;
const PEER_AS: u32 = 65_001;
const FEEDER_AS: u32 = 65_003;
const ESTABLISH: Duration = Duration::from_secs(40);
/// Long enough for a restarted daemon to reconnect and exchange its table.
const RECOVER: Duration = Duration::from_secs(60);

/// What a peer originates.
const V4_ROUTES: [&str; 3] = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];

/// `bgpfcctl` against the daemon of the lab, which has `control` in its
/// configuration.
fn ctl(socket: &Path, args: &[&str]) -> String {
    bgpfcctl(socket, args).0
}

/// The lines of `show routes` for `family` (`ipv4` or `ipv6`), without the
/// header.
fn routes(socket: &Path, family: &str) -> Vec<String> {
    ctl(socket, &["show", "routes", family])
        .lines()
        .skip(1)
        .map(str::to_owned)
        .collect()
}

/// The prefixes `show routes` lists, and how many of them are stale.
fn prefixes(socket: &Path, family: &str) -> Vec<String> {
    routes(socket, family)
        .iter()
        .filter_map(|l| l.trim_start_matches('*').split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn stale(socket: &Path, family: &str) -> usize {
    routes(socket, family)
        .iter()
        .filter(|l| l.ends_with(" stale"))
        .count()
}

fn detail(socket: &Path, peer: impl std::fmt::Display) -> String {
    ctl(socket, &["show", "neighbor", &peer.to_string()])
}

/// A BIRD for the Restarting Speaker side of a scenario: it speaks
/// Graceful Restart fully, and originates `statics`.
fn bird_opts(lab: &Lab, protocol: &str, statics: &[&str]) -> BirdOpts {
    BirdOpts {
        local_as: PEER_AS,
        local: lab.b_addr,
        local_port: 179,
        neighbor: lab.a_addr,
        neighbor_port: 179,
        remote_as: BGPFC_AS,
        hold_time: 30,
        // bgpfcd connects; BIRD is there to be connected to.
        passive: true,
        statics: statics.iter().map(|s| (*s).to_owned()).collect(),
        channel: String::new(),
        protocol: protocol.to_owned(),
    }
}

/// bgpfcd with one graceful neighbor, the peer under test in B.
fn bgpfcd_opts(lab: &Lab, socket: &Path, neighbor: &str, extra: &str) -> BgpfcdOpts {
    let mut n = NeighborOpts::new(lab.b_addr, PEER_AS);
    // The reconnect after a restart is what a test waits for.
    n.extra = format!("connect-retry-time 5; graceful-restart yes; {neighbor}");
    let mut o = BgpfcdOpts::single(BGPFC_AS, lab.a_addr, n);
    o.extra = format!("control {{ socket {}; }}\n{extra}", socket.display());
    o
}

fn established(lab: &Lab, bird: &Bird, bgpfcd: &Daemon) {
    let ok = wait_for(ESTABLISH, || {
        bird.peer_status(lab).contains("Established")
            && bgpfcd.log_text().contains("session established")
    });
    assert!(
        ok,
        "no session.\n--- bird ---\n{}\n--- birdc ---\n{}\n--- bgpfcd ---\n{}",
        bird.daemon.log_text(),
        bird.peer_status(lab),
        bgpfcd.log_text()
    );
}

/// The IPv6 statics of `BIRD`, and its IPv6 channel over the IPv4 session:
/// the next hop is configured, so the host's kernel need not have IPv6.
const BIRD_V6_CHANNEL: &str = "ipv6 { import all; export all; next hop address 2001:db8:9::2; };";
const BIRD_V6_STATICS: &str = "protocol static statics6 {\n    ipv6;\n\
    \x20   route 2001:db8:1::/48 blackhole;\n    route 2001:db8:2::/48 blackhole;\n}\n";

// ---------------------------------------------------------------------
// A peer restarts; bgpfcd is the Receiving Speaker (RFC 4724 §4.2).
// ---------------------------------------------------------------------

/// BIRD restarts gracefully (`birdc graceful restart`, then `bird -R`),
/// dropping one of its routes meanwhile and keeping the others, in both
/// families: bgpfcd keeps all of them as stale ones while BIRD is away
/// (the TCP connection failed, RFC 4724 §4.2), BIRD's capability then has
/// the Restart State bit and the Forwarding State bit of both families,
/// the routes it sends again replace the stale ones and its End-of-RIB of
/// each family removes the one it did not.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn bgpfcd_keeps_the_routes_of_a_bird_that_restarts_gracefully() {
    let lab = Lab::new("ga", 21);
    let socket = lab.dir.join("ctl.sock");
    let protocol = format!("graceful restart on; {BIRD_V6_CHANNEL}");
    let first = bird_opts(&lab, &protocol, &V4_ROUTES);
    let mut bird = Bird::start_with(&lab, &lab.b.clone(), &first, BIRD_V6_STATICS);
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &bgpfcd_opts(&lab, &socket, "", ""));
    established(&lab, &bird, &bgpfcd);
    assert!(
        wait_for(Duration::from_secs(10), || {
            routes(&socket, "ipv4").len() == 3 && routes(&socket, "ipv6").len() == 2
        }),
        "{}",
        bgpfcd.log_text()
    );
    // RFC 4724 §4: the End-of-RIB marker of each family.
    let log = bgpfcd.log_text();
    assert!(
        log.contains("end-of-rib\" peer=") && log.contains("family=ipv6-unicast"),
        "{log}"
    );
    let d = detail(&socket, lab.b_addr);
    assert!(
        d.contains("restart-time 120s notification no restarting no"),
        "{d}"
    );
    assert_eq!(stale(&socket, "ipv4") + stale(&socket, "ipv6"), 0);

    // BIRD goes: no NOTIFICATION, the connection ends. The routes stay,
    // marked stale, and so does what bgpfcd tells others of them.
    let out = bird.birdc(&lab, &["graceful", "restart"]);
    assert!(out.contains("Graceful restart requested"), "{out}");
    assert!(
        wait_for(Duration::from_secs(10), || !bird.daemon.is_running()),
        "{}",
        bird.daemon.log_text()
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            stale(&socket, "ipv4") == 3 && stale(&socket, "ipv6") == 2
        }),
        "{}\n{}",
        ctl(&socket, &["show", "routes"]),
        bgpfcd.log_text()
    );
    let d = detail(&socket, lab.b_addr);
    assert!(
        d.contains("stale routes ipv4-unicast=3,ipv6-unicast=2; awaiting end-of-rib")
            && d.contains("session due back in"),
        "{d}"
    );

    // BIRD comes back in recovery, without one of its routes of each
    // family. Its routes are never gone from bgpfcd's tables meanwhile.
    let second = bird_opts(&lab, &protocol, &V4_ROUTES[..2]);
    let extra = BIRD_V6_STATICS.replace("    route 2001:db8:2::/48 blackhole;\n", "");
    bird.daemon.kill();
    let _bird = Bird::start_recovering(&lab, &lab.b.clone(), &second, &extra);
    let mut least = usize::MAX;
    let ok = wait_for(RECOVER, || {
        least = least.min(routes(&socket, "ipv4").len());
        stale(&socket, "ipv4") == 0
            && stale(&socket, "ipv6") == 0
            && routes(&socket, "ipv4").len() == 2
            && routes(&socket, "ipv6").len() == 1
            && detail(&socket, lab.b_addr).contains("Established")
    });
    assert!(
        ok,
        "{}\n{}\n{}",
        ctl(&socket, &["show", "routes"]),
        detail(&socket, lab.b_addr),
        bgpfcd.log_text()
    );
    assert!(least >= 2, "routes went and came back: {least}");
    // RFC 4724 §3: BIRD restarted and preserved its forwarding state.
    let d = detail(&socket, lab.b_addr);
    assert!(
        d.contains("restarting yes forwarding ipv4-unicast,ipv6-unicast without none"),
        "{d}"
    );
    // The one it did not send again went at its End-of-RIB (§4.2), and
    // nothing before it.
    let log = bgpfcd.log_text();
    assert!(
        log.contains("stale routes removed\" peer=")
            && log.contains("why=end-of-rib")
            && !log.contains("why=\"restart timer\""),
        "{log}"
    );
    assert_eq!(
        prefixes(&socket, "ipv4"),
        ["192.0.2.0/24", "198.51.100.0/24"]
    );
    assert_eq!(prefixes(&socket, "ipv6"), ["2001:db8:1::/48"]);
}

/// A BIRD that crashes and starts afresh has no forwarding state to speak
/// of: its capability lacks the Forwarding State bit, and bgpfcd removes the
/// routes it kept at once, before any End-of-RIB (RFC 4724 §4.2).
#[test]
#[ignore = "needs root, bird and iproute2"]
fn a_bird_that_restarts_without_forwarding_state_loses_its_routes_at_once() {
    let lab = Lab::new("gb", 22);
    let socket = lab.dir.join("ctl.sock");
    let opts = bird_opts(&lab, "graceful restart on;", &V4_ROUTES);
    let mut bird = Bird::start(&lab, &lab.b.clone(), &opts);
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &bgpfcd_opts(&lab, &socket, "", ""));
    established(&lab, &bird, &bgpfcd);
    assert!(wait_for(Duration::from_secs(10), || routes(
        &socket, "ipv4"
    )
    .len()
        == 3));
    // A crash: SIGKILL, and the kernel ends the connection.
    bird.daemon.kill();
    assert!(
        wait_for(Duration::from_secs(10), || stale(&socket, "ipv4") == 3),
        "{}",
        bgpfcd.log_text()
    );
    // It starts again, without recovery: it has no routes of its own to
    // offer yet (a static that is not there), and no preserved state.
    let _bird = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, "graceful restart on;", &[]),
    );
    assert!(
        wait_for(RECOVER, || routes(&socket, "ipv4").is_empty()),
        "{}\n{}",
        ctl(&socket, &["show", "routes"]),
        bgpfcd.log_text()
    );
    let log = bgpfcd.log_text();
    assert!(
        log.contains("why=\"no forwarding state\"") && !log.contains("why=\"restart timer\""),
        "{log}"
    );
}

/// A BIRD that does not come back in the Restart Time it advertised loses
/// its routes then (RFC 4724 §4.2).
#[test]
#[ignore = "needs root, bird and iproute2"]
fn the_restart_time_ends_the_wait_for_a_bird_that_does_not_return() {
    let lab = Lab::new("gc", 23);
    let socket = lab.dir.join("ctl.sock");
    let opts = bird_opts(
        &lab,
        "graceful restart on; graceful restart time 6;",
        &V4_ROUTES,
    );
    let mut bird = Bird::start(&lab, &lab.b.clone(), &opts);
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &bgpfcd_opts(&lab, &socket, "", ""));
    established(&lab, &bird, &bgpfcd);
    assert!(wait_for(Duration::from_secs(10), || routes(
        &socket, "ipv4"
    )
    .len()
        == 3));
    let d = detail(&socket, lab.b_addr);
    assert!(d.contains("neighbor restart-time 6s"), "{d}");
    bird.daemon.kill();
    let gone = Instant::now();
    assert!(wait_for(Duration::from_secs(5), || stale(&socket, "ipv4") == 3));
    assert!(
        wait_for(Duration::from_secs(20), || routes(&socket, "ipv4")
            .is_empty()),
        "{}",
        bgpfcd.log_text()
    );
    assert!(
        gone.elapsed() >= Duration::from_secs(5),
        "{:?}",
        gone.elapsed()
    );
    let log = bgpfcd.log_text();
    assert!(log.contains("why=\"restart timer\""), "{log}");
}

// ---------------------------------------------------------------------
// bgpfcd restarts in install mode; the peer is the Receiving Speaker and
// the kernel keeps the routes (RFC 4724 §4.1, AGENTS.md §3, "FIB").
// ---------------------------------------------------------------------

/// The routes of the triangle: B, the peer that keeps bgpfcd's routes,
/// originates `B_ROUTES`; C, a BIRD that feeds bgpfcd, originates the others.
const B_V4: &str = "100.64.1.0/24";
const B_V6: &str = "2001:db8:b::/48";
const C_V4_KEPT: &str = "192.0.2.0/24";
const C_V4_DROPPED: &str = "198.51.100.0/24";
const C_V6_KEPT: &str = "2001:db8:1::/48";
const C_V6_DROPPED: &str = "2001:db8:2::/48";

/// The peer under test, B.
enum Peer {
    Bird(Bird),
    Frr(Frr),
}

impl Peer {
    /// Whether B's table has a route to `prefix`.
    fn has(&self, lab: &Lab, prefix: &str) -> bool {
        match self {
            Peer::Bird(b) => b.birdc(lab, &["show", "route", prefix]).contains(prefix),
            Peer::Frr(f) => {
                let family = if prefix.contains(':') { "ipv6" } else { "ipv4" };
                f.vtysh(lab, &format!("show bgp {family} unicast {prefix}"))
                    .contains("BGP routing table entry")
            }
        }
    }

    /// What B says of the capability bgpfcd sent.
    fn status(&self, lab: &Lab) -> String {
        match self {
            Peer::Bird(b) => b.peer_status(lab),
            Peer::Frr(f) => f.vtysh(lab, &format!("show bgp neighbors {}", lab.a_addr)),
        }
    }

    fn established(&self, lab: &Lab) -> bool {
        match self {
            Peer::Bird(b) => b.peer_status(lab).contains("Established"),
            Peer::Frr(f) => f
                .vtysh(lab, &format!("show bgp neighbors {}", lab.a_addr))
                .contains("BGP state = Established"),
        }
    }

    fn log(&self) -> String {
        match self {
            Peer::Bird(b) => b.daemon.log_text(),
            Peer::Frr(f) => f.daemon.log_text(),
        }
    }
}

/// The prefixes of our protocol number in the kernel of A.
fn kernel(lab: &Lab, v6: bool) -> std::collections::BTreeSet<String> {
    let args: &[&str] = if v6 {
        &["-6", "route", "show", "proto", "186"]
    } else {
        &["route", "show", "proto", "186"]
    };
    Daemon::ip_in(lab, &lab.a, args)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// `ip monitor route` in A: what happens to the routes of the kernel, from
/// now on, in order.
struct Monitor {
    child: std::process::Child,
    path: std::path::PathBuf,
}

impl Monitor {
    fn start(lab: &Lab) -> Monitor {
        let path = lab.dir.join("route-monitor.txt");
        let out = std::fs::File::create(&path).expect("monitor file");
        let child = lab
            .exec(&lab.a, "ip")
            .args(["monitor", "route"])
            .stdout(std::process::Stdio::from(out))
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("ip monitor");
        Monitor { child, path }
    }

    fn text(&self) -> String {
        interop::read(&self.path)
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bgpfcd_install_opts(lab: &Lab, socket: &Path) -> BgpfcdOpts {
    let neighbor = |addr, asn| NeighborOpts {
        extra: "connect-retry-time 5; graceful-restart yes; restart-time 60;".to_owned(),
        ..NeighborOpts::new(addr, asn)
    };
    BgpfcdOpts {
        local_as: BGPFC_AS,
        router_id: lab.a_addr,
        listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
        neighbors: vec![
            neighbor(lab.b_addr, PEER_AS),
            neighbor(lab.c_addr, FEEDER_AS),
        ],
        extra: format!(
            "fib {{ mode install; }}\ncontrol {{ socket {} ; }}",
            socket.display()
        ),
    }
}

/// B, C and bgpfcd in install mode, for `bgpfcd_restarts_in_install_mode`.
struct Triangle {
    /// The routes in the kernel of A before the crash, and after the
    /// restart: those C keeps sending, and B's own.
    all_v4: Vec<&'static str>,
    kept_v4: Vec<&'static str>,
    all_v6: Vec<&'static str>,
    kept_v6: Vec<&'static str>,
    v6: bool,
    opts: BgpfcdOpts,
    bgpfcd: Daemon,
    peer: Peer,
    bird_c: Bird,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl Triangle {
    /// Start them all. `None` where `v6` asks for IPv6 and the kernel has
    /// none to give.
    fn start(speaker: &str, v6: bool) -> Option<Triangle> {
        let mut lab = Lab::new(
            if speaker == "bird" { "gd" } else { "ge" },
            if v6 { 25 } else { 24 },
        );
        let ns_c = lab.add_c();
        if v6 && !lab.add_ipv6() {
            eprintln!("skipped: this kernel has no IPv6, so no IPv6 route can be installed");
            return None;
        }
        let socket = lab.dir.join("ctl.sock");

        // C, the feeder. c2 (and c6b) are protocols of their own, to take
        // away.
        let mut c_extra =
            format!("protocol static c2 {{\n    ipv4;\n    route {C_V4_DROPPED} blackhole;\n}}\n");
        let mut c_protocol = "graceful restart on;".to_owned();
        if v6 {
            c_protocol
                .push_str("ipv6 { import all; export all; next hop address 2001:db8:8::2; };");
            c_extra.push_str(&static_v6("c6a", C_V6_KEPT));
            c_extra.push_str(&static_v6("c6b", C_V6_DROPPED));
        }
        let bird_c = Bird::start_with(
            &lab,
            &ns_c,
            &BirdOpts {
                local_as: FEEDER_AS,
                local: lab.c_addr,
                local_port: 179,
                neighbor: lab.a2_addr,
                neighbor_port: 179,
                remote_as: BGPFC_AS,
                hold_time: 30,
                passive: true,
                statics: vec![C_V4_KEPT.to_owned()],
                channel: String::new(),
                protocol: c_protocol,
            },
            &c_extra,
        );

        // B, the peer that keeps what bgpfcd sends it.
        let peer = if speaker == "bird" {
            let mut protocol = "graceful restart on; graceful restart time 60;".to_owned();
            let mut extra = String::new();
            if v6 {
                protocol
                    .push_str("ipv6 { import all; export all; next hop address 2001:db8:9::2; };");
                extra = static_v6("b6", B_V6);
            }
            Peer::Bird(Bird::start_with(
                &lab,
                &lab.b.clone(),
                &bird_opts(&lab, &protocol, &[B_V4]),
                &extra,
            ))
        } else {
            // FRR originates nothing here: it sets the Restart State bit
            // for as long as its own startup lasts, and RFC 4724 §4.1 has
            // bgpfcd not wait for the End-of-RIB of such a neighbor, so a
            // route learned from it may come after route selection, and be
            // removed from the kernel and installed again.
            let global = " bgp graceful-restart\n bgp graceful-restart restart-time 60\n";
            Peer::Frr(Frr::start_with(
                &lab,
                &lab.b.clone(),
                &frr_opts(&lab, &[]),
                global,
                "",
            ))
        };

        let opts = bgpfcd_install_opts(&lab, &socket);
        let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &opts);
        let b_v4: Vec<&str> = if speaker == "bird" {
            vec![B_V4]
        } else {
            Vec::new()
        };
        let kept_v4: Vec<&str> = b_v4.iter().copied().chain([C_V4_KEPT]).collect();
        let all_v4: Vec<&str> = kept_v4.iter().copied().chain([C_V4_DROPPED]).collect();
        let (kept_v6, all_v6) = if v6 {
            (vec![B_V6, C_V6_KEPT], vec![B_V6, C_V6_KEPT, C_V6_DROPPED])
        } else {
            (Vec::new(), Vec::new())
        };
        Some(Triangle {
            all_v4,
            kept_v4,
            all_v6,
            kept_v6,
            v6,
            opts,
            bgpfcd,
            peer,
            bird_c,
            lab,
        })
    }

    /// Whether the kernel of A has exactly these routes of bgpfcd's.
    fn kernel_is(&self, v4: &[&str], v6: &[&str]) -> bool {
        let want = |routes: &[&str]| -> std::collections::BTreeSet<String> {
            routes.iter().map(|s| (*s).to_owned()).collect()
        };
        kernel(&self.lab, false) == want(v4) && (!self.v6 || kernel(&self.lab, true) == want(v6))
    }

    fn state(&self) -> String {
        format!(
            "kernel {:?} {:?}\n--- bgpfcd ---\n{}\n--- peer ---\n{}",
            kernel(&self.lab, false),
            kernel(&self.lab, true),
            self.bgpfcd.log_text(),
            self.peer.log()
        )
    }

    /// Everything is up and bgpfcd has installed what it learned, and told
    /// B what it learned of C.
    fn converge(&self) {
        let ok = wait_for(ESTABLISH + RECOVER, || {
            self.peer.established(&self.lab)
                && self.bird_c.peer_status(&self.lab).contains("Established")
                && self.kernel_is(&self.all_v4, &self.all_v6)
        });
        assert!(ok, "not converged: {}", self.state());
        let ok = wait_for(Duration::from_secs(20), || {
            [C_V4_KEPT, C_V4_DROPPED]
                .iter()
                .chain(self.all_v6.iter().skip(1))
                .all(|p| self.peer.has(&self.lab, p))
        });
        assert!(ok, "{}", self.peer.status(&self.lab));
        let log = self.bgpfcd.log_text();
        assert!(
            !log.contains("restarted with forwarding state kept"),
            "{log}"
        );
    }

    /// bgpfcd crashes, and C stops sending two routes bgpfcd cannot hear of
    /// being gone. For a few seconds the kernel keeps all its routes, and B
    /// all it was told.
    fn crash(&mut self) -> Monitor {
        let monitor = Monitor::start(&self.lab);
        self.bgpfcd.kill();
        let down = Instant::now();
        let _ = self.bird_c.birdc(&self.lab, &["disable", "c2"]);
        if self.v6 {
            let _ = self.bird_c.birdc(&self.lab, &["disable", "c6b"]);
        }
        let mut gaps = Vec::new();
        while down.elapsed() < Duration::from_secs(3) {
            if !self.kernel_is(&self.all_v4, &self.all_v6) {
                gaps.push(format!("kernel at {:?}", down.elapsed()));
            }
            for p in [C_V4_KEPT, C_V4_DROPPED] {
                if !self.peer.has(&self.lab, p) {
                    gaps.push(format!("{p} in B at {:?}", down.elapsed()));
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(gaps.is_empty(), "{gaps:?}\n{}", self.peer.status(&self.lab));
        monitor
    }

    /// bgpfcd starts again: it finds its routes in the kernel, and says it
    /// has restarted (R bit) with forwarding state for the families (F
    /// bit). Until it has its routes again, no route that is to stay is
    /// ever gone, from the kernel or from B.
    fn restart(&mut self) {
        let started = Instant::now();
        self.bgpfcd = start_bgpfcd(&self.lab, &self.lab.a.clone(), &self.opts);
        let mut gaps = Vec::new();
        let ok = wait_for(RECOVER, || {
            if !self.peer.has(&self.lab, C_V4_KEPT) {
                gaps.push(format!("{C_V4_KEPT} in B at {:?}", started.elapsed()));
            }
            let v4 = kernel(&self.lab, false);
            if !self.kept_v4.iter().all(|p| v4.contains(*p)) {
                gaps.push(format!("kernel at {:?}: {v4:?}", started.elapsed()));
            }
            self.kernel_is(&self.kept_v4, &self.kept_v6) && !self.peer.has(&self.lab, C_V4_DROPPED)
        });
        assert!(ok, "no recovery: {}", self.state());
        assert!(gaps.is_empty(), "{gaps:?}\n{}", self.bgpfcd.log_text());
    }
}

/// An IPv6 static protocol named `name` for `prefix`.
fn static_v6(name: &str, prefix: &str) -> String {
    format!("protocol static {name} {{\n    ipv6;\n    route {prefix} blackhole;\n}}\n")
}

/// B keeps what bgpfcd told it while bgpfcd restarts, and the kernel keeps
/// what bgpfcd installed, all the way (RFC 4724 §4.1): with `v6`, in both
/// families. A route C stops sending meanwhile goes at the end, from the
/// kernel when bgpfcd's route selection ends, from B at bgpfcd's End-of-RIB.
fn bgpfcd_restarts_in_install_mode(speaker: &str, v6: bool) {
    let Some(mut t) = Triangle::start(speaker, v6) else {
        return;
    };
    t.converge();
    let monitor = t.crash();
    t.restart();
    let log = t.bgpfcd.log_text();
    assert!(
        log.contains("restarted with forwarding state kept, deferring route selection"),
        "{log}"
    );
    assert!(log.contains("graceful restart finished"), "{log}");
    // The routes to stay were not deleted from the kernel, nor replaced:
    // only the one C stopped sending was removed (AGENTS.md §3, "FIB").
    let events = monitor.text();
    for p in t.kept_v4.iter().chain(&t.kept_v6) {
        assert!(
            !events
                .lines()
                .any(|l| l.contains("Deleted") && l.contains(p)),
            "{p} was deleted:\n{events}"
        );
    }
    assert!(
        events
            .lines()
            .any(|l| l.contains("Deleted") && l.contains(C_V4_DROPPED)),
        "{events}"
    );
    // B hears of the removal when bgpfcd's End-of-RIB comes (§4.2), not
    // before.
    assert!(!t.peer.has(&t.lab, C_V4_DROPPED) && t.peer.has(&t.lab, C_V4_KEPT));
    if v6 {
        assert!(!t.peer.has(&t.lab, C_V6_DROPPED) && t.peer.has(&t.lab, C_V6_KEPT));
    }
    // RFC 4724 §3: B saw the Restart State bit and the Forwarding State bit
    // of the families that have routes installed.
    let status = t.peer.status(&t.lab);
    if let Peer::Bird(_) = t.peer {
        assert!(status.contains("Restart recovery"), "{status}");
        assert!(status.contains("AF preserved: ipv4"), "{status}");
    }
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn bird_keeps_the_routes_of_a_bgpfcd_that_restarts_and_the_kernel_keeps_its_own() {
    bgpfcd_restarts_in_install_mode("bird", false);
}

#[test]
#[ignore = "needs root, bird and iproute2, and IPv6 in the kernel"]
fn bird_keeps_the_ipv6_routes_of_a_bgpfcd_that_restarts_too() {
    bgpfcd_restarts_in_install_mode("bird", true);
}

#[test]
#[ignore = "needs root, bird, frr and iproute2"]
fn frr_keeps_the_routes_of_a_bgpfcd_that_restarts_and_the_kernel_keeps_its_own() {
    bgpfcd_restarts_in_install_mode("frr", false);
}

// ---------------------------------------------------------------------
// FRR
// ---------------------------------------------------------------------

/// FRR with `bgp graceful-restart` and `preserve-fw-state`, which is what
/// makes it set the Forwarding State bit without zebra; it originates
/// `networks`.
fn frr_opts(lab: &Lab, networks: &[&str]) -> OtherOpts {
    OtherOpts {
        local_as: PEER_AS,
        local: lab.b_addr,
        neighbor: lab.a_addr,
        remote_as: BGPFC_AS,
        networks: networks.iter().map(|s| (*s).to_owned()).collect(),
    }
}

const FRR_GLOBAL: &str = " bgp graceful-restart\n bgp graceful-restart restart-time 120\n bgp graceful-restart preserve-fw-state\n";

/// An FRR that restarts after a crash, with its forwarding state
/// preserved, and one route fewer: bgpfcd keeps the three routes as stale
/// ones until FRR is back, and the End-of-RIB removes the one that FRR
/// did not send again (RFC 4724 §4.2).
#[test]
#[ignore = "needs root, frr and iproute2"]
fn bgpfcd_keeps_the_routes_of_an_frr_that_restarts() {
    let lab = Lab::new("gf", 26);
    let socket = lab.dir.join("ctl.sock");
    let mut frr = Frr::start_with(
        &lab,
        &lab.b.clone(),
        &frr_opts(&lab, &V4_ROUTES),
        FRR_GLOBAL,
        "",
    );
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &bgpfcd_opts(&lab, &socket, "", ""));
    assert!(
        wait_for(ESTABLISH, || {
            routes(&socket, "ipv4").len() == 3 && bgpfcd.log_text().contains("session established")
        }),
        "{}\n{}",
        frr.daemon.log_text(),
        bgpfcd.log_text()
    );
    // FRR's capability: the Graceful Notification bit too, and the Restart
    // Time of its configuration.
    let d = detail(&socket, lab.b_addr);
    assert!(d.contains("restart-time 120s notification yes"), "{d}");

    frr.daemon.kill();
    assert!(
        wait_for(Duration::from_secs(10), || stale(&socket, "ipv4") == 3),
        "{}",
        bgpfcd.log_text()
    );
    let _frr = Frr::start_with(
        &lab,
        &lab.b.clone(),
        &frr_opts(&lab, &V4_ROUTES[..2]),
        FRR_GLOBAL,
        "",
    );
    let mut least = usize::MAX;
    let ok = wait_for(RECOVER, || {
        least = least.min(routes(&socket, "ipv4").len());
        stale(&socket, "ipv4") == 0
            && routes(&socket, "ipv4").len() == 2
            && detail(&socket, lab.b_addr).contains("Established")
    });
    assert!(
        ok,
        "{}\n{}\n{}",
        ctl(&socket, &["show", "routes"]),
        detail(&socket, lab.b_addr),
        bgpfcd.log_text()
    );
    assert!(least >= 2, "routes went and came back: {least}");
    let d = detail(&socket, lab.b_addr);
    assert!(d.contains("forwarding ipv4-unicast"), "{d}");
    let log = bgpfcd.log_text();
    assert!(log.contains("why=end-of-rib"), "{log}");
    assert_eq!(
        prefixes(&socket, "ipv4"),
        ["192.0.2.0/24", "198.51.100.0/24"]
    );
}

/// FRR in B with two routes of its own, a BIRD in C with two, and bgpfcd.
struct FrrPair {
    frr: Frr,
    bgpfcd: Daemon,
    socket: std::path::PathBuf,
    _bird_c: Bird,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl FrrPair {
    fn start() -> FrrPair {
        let mut lab = Lab::new("gg", 27);
        let ns_c = lab.add_c();
        let socket = lab.dir.join("ctl.sock");
        let bird_c = Bird::start(
            &lab,
            &ns_c,
            &BirdOpts {
                local_as: FEEDER_AS,
                local: lab.c_addr,
                local_port: 179,
                neighbor: lab.a2_addr,
                neighbor_port: 179,
                remote_as: BGPFC_AS,
                hold_time: 30,
                passive: true,
                statics: vec![C_V4_KEPT.to_owned(), C_V4_DROPPED.to_owned()],
                channel: String::new(),
                protocol: String::new(),
            },
        );
        let networks = ["100.64.1.0/24", "100.64.2.0/24"];
        let frr = Frr::start_with(
            &lab,
            &lab.b.clone(),
            &frr_opts(&lab, &networks),
            FRR_GLOBAL,
            "",
        );
        let neighbor = |addr, asn| NeighborOpts {
            extra: "connect-retry-time 5; graceful-restart yes;".to_owned(),
            ..NeighborOpts::new(addr, asn)
        };
        let bgpfcd = start_bgpfcd(
            &lab,
            &lab.a.clone(),
            &BgpfcdOpts {
                local_as: BGPFC_AS,
                router_id: lab.a_addr,
                listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
                neighbors: vec![
                    neighbor(lab.b_addr, PEER_AS),
                    neighbor(lab.c_addr, FEEDER_AS),
                ],
                extra: format!("control {{ socket {} ; }}", socket.display()),
            },
        );
        let pair = FrrPair {
            frr,
            bgpfcd,
            socket,
            _bird_c: bird_c,
            lab,
        };
        let ok = wait_for(ESTABLISH, || {
            routes(&pair.socket, "ipv4").len() == 4
                && pair.at_frr(C_V4_KEPT)
                && pair.at_frr(C_V4_DROPPED)
        });
        assert!(
            ok,
            "{}\n{}",
            pair.frr.daemon.log_text(),
            pair.bgpfcd.log_text()
        );
        pair
    }

    /// Whether FRR has a route to `prefix`.
    fn at_frr(&self, prefix: &str) -> bool {
        self.frr
            .vtysh(&self.lab, &format!("show bgp ipv4 unicast {prefix}"))
            .contains("BGP routing table entry")
    }

    fn sessions(&self) -> usize {
        self.bgpfcd
            .log_text()
            .matches("session established")
            .count()
    }

    /// Ask bgpfcd to clear its session with FRR.
    fn clear(&self, how: &[&str]) {
        let mut args = vec!["clear", "neighbor"];
        let b = self.lab.b_addr.to_string();
        args.push(&b);
        args.extend(how);
        let (out, ok) = bgpfcctl(&self.socket, &args);
        assert!(ok, "{out}");
    }

    /// The session is back and all four routes with it, FRR having its
    /// two of C's.
    fn recovered(&self, sessions_before: usize) -> bool {
        self.sessions() > sessions_before
            && stale(&self.socket, "ipv4") == 0
            && routes(&self.socket, "ipv4").len() == 4
            && self.at_frr(C_V4_KEPT)
            && self.at_frr(C_V4_DROPPED)
    }

    fn state(&self) -> String {
        format!(
            "{}\n{}\n{}",
            ctl(&self.socket, &["show", "routes"]),
            self.frr.daemon.log_text(),
            self.bgpfcd.log_text()
        )
    }
}

/// Both bgpfcd and FRR sent the Graceful Notification bit (RFC 8538 §2),
/// so a reset that bgpfcd asks for with the Administrative Reset keeps the
/// routes of both sides, and a Hard Reset (§3) does not.
#[test]
#[ignore = "needs root, bird, frr and iproute2"]
fn a_graceful_reset_keeps_the_routes_of_both_sides_and_a_hard_reset_deletes_them() {
    let p = FrrPair::start();

    // RFC 8538 §4: a NOTIFICATION that is no Hard Reset, sent by bgpfcd,
    // starts the Graceful Restart procedures on both sides.
    let before = p.sessions();
    p.clear(&[]);
    assert!(
        wait_for(Duration::from_secs(10), || stale(&p.socket, "ipv4") == 2),
        "{}",
        p.state()
    );
    assert!(
        p.at_frr(C_V4_KEPT) && p.at_frr(C_V4_DROPPED),
        "FRR dropped our routes"
    );
    let mut gone = false;
    let ok = wait_for(RECOVER, || {
        gone |= !p.at_frr(C_V4_KEPT) || routes(&p.socket, "ipv4").len() < 4;
        p.recovered(before)
    });
    assert!(ok, "{}", p.state());
    assert!(!gone, "a route was gone during the graceful reset");

    // RFC 8538 §3.2: the Hard Reset ends the session as RFC 4271 has it.
    // The routes of both sides go at once, and come back with the session.
    let before = p.sessions();
    p.clear(&["hard-reset"]);
    assert!(
        wait_for(Duration::from_secs(10), || {
            routes(&p.socket, "ipv4").len() == 2 && stale(&p.socket, "ipv4") == 0
        }),
        "{}",
        p.state()
    );
    assert!(
        wait_for(Duration::from_secs(10), || !p.at_frr(C_V4_KEPT)
            && !p.at_frr(C_V4_DROPPED)),
        "FRR kept our routes after a Hard Reset:\n{}",
        p.frr.daemon.log_text()
    );
    assert!(wait_for(RECOVER, || p.recovered(before)), "{}", p.state());
}
