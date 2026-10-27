//! Multihop eBGP (`multihop` and `local-address`, `docs/config.md`,
//! "Neighbors"; AGENTS.md §5, `interop/` row), in a lab where A routes
//! between bgpfcd in B and BIRD in C, two hops apart over loopback
//! addresses ([`Lab::route_through_a`]), while BIRD in A peers with
//! bgpfcd directly.
//!
//! bgpfcd sends an external neighbor TTL 1 unless it has `multihop`: a
//! neighbor two hops away then never comes up, and the log and `show
//! neighbor` say why; with `multihop` the SYN gets through, and with
//! `local-address` the session runs from the loopback BIRD knows it by.
//! The directly connected session keeps working with TTL 1.
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird` and
//! `birdc` on `PATH`, and a built `bgpfcd` and `bgpfcctl`. CI runs them
//! with `--include-ignored` under sudo.

use std::path::PathBuf;
use std::time::Duration;

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, Lab, Loopbacks, NeighborOpts, bgpfcd_config, start_bgpfcd,
    wait_for,
};

const BGPFC_AS: u32 = 65_002;
const BIRD_A_AS: u32 = 65_001;
const BIRD_C_AS: u32 = 65_003;
const ESTABLISH: Duration = Duration::from_secs(40);
/// How long a session that must not come up is watched: three of the
/// neighbor's `connect-retry-time`s.
const NO_SESSION: Duration = Duration::from_secs(15);
/// What BIRD in C originates.
const C_ROUTE: &str = "203.0.113.0/24";
/// What bgpfcd logs when TTL 1 does not reach a neighbor.
const HINT: &str = "hint=\"external neighbor: more than one hop away needs multihop\"";

/// The routed lab with BIRD in A and in C and bgpfcd in B. The daemons
/// are stopped before the lab goes (fields drop in order).
struct Routed {
    bird_a: Bird,
    bird_c: Bird,
    bgpfcd: Daemon,
    socket: PathBuf,
    opts: BgpfcdOpts,
    lo: Loopbacks,
    lab: Lab,
}

impl Routed {
    /// Build the lab and start the three daemons, with `to_c` in bgpfcd's
    /// neighbor block for C. BIRD in C is passive, so a session with it
    /// is one bgpfcd opened; the FIB stays in dry-run.
    fn start(tag: &str, subnet: u8, to_c: &str) -> Routed {
        let mut lab = Lab::new(tag, subnet);
        let ns_c = lab.add_c();
        let lo = lab.route_through_a();
        let bird_a = Bird::start(
            &lab,
            &lab.a.clone(),
            &BirdOpts {
                local_as: BIRD_A_AS,
                local: lab.a_addr,
                local_port: 179,
                neighbor: lab.b_addr,
                neighbor_port: 179,
                remote_as: BGPFC_AS,
                hold_time: 30,
                passive: true,
                statics: Vec::new(),
                channel: String::new(),
                protocol: String::new(),
                export: String::new(),
            },
        );
        // BIRD's next hop is C's second loopback, not the session's
        // address (design finding 6: BIRD sets it on a multihop session).
        let bird_c = Bird::start(
            &lab,
            &ns_c,
            &BirdOpts {
                local_as: BIRD_C_AS,
                local: lo.c,
                local_port: 179,
                neighbor: lo.b,
                neighbor_port: 179,
                remote_as: BGPFC_AS,
                hold_time: 30,
                passive: true,
                statics: vec![C_ROUTE.to_owned()],
                channel: String::new(),
                protocol: "multihop;".to_owned(),
                export: format!("filter {{ bgp_next_hop = {}; accept; }}", lo.c_next_hop),
            },
        );
        let socket = lab.dir.join("ctl.sock");
        let opts = BgpfcdOpts {
            local_as: BGPFC_AS,
            router_id: lo.b,
            listen: vec![lab.b_addr.into(), lo.b.into()],
            neighbors: vec![
                NeighborOpts {
                    advertisement_interval: Some(0),
                    ..NeighborOpts::new(lab.a_addr, BIRD_A_AS)
                },
                to_c_neighbor(lo, to_c),
            ],
            extra: format!("control {{ socket {}; }}", socket.display()),
            args: Vec::new(),
            from_host: false,
        };
        let bgpfcd = start_bgpfcd(&lab, &lab.b.clone(), &opts);
        Routed {
            bird_a,
            bird_c,
            bgpfcd,
            socket,
            opts,
            lo,
            lab,
        }
    }

    fn ctl(&self, args: &[&str]) -> (String, bool) {
        interop::bgpfcctl(&self.socket, args)
    }

    /// `show neighbor` for C.
    fn neighbor_c(&self) -> String {
        self.ctl(&["show", "neighbor", &self.lo.c.to_string()]).0
    }

    /// Rewrite bgpfcd's neighbor block for C with `to_c` and reload: a
    /// change of `multihop` or `local-address` resets that neighbor alone
    /// (design.md 1.6).
    fn reload_c(&mut self, to_c: &str) {
        self.opts.neighbors[1] = to_c_neighbor(self.lo, to_c);
        let _ = bgpfcd_config(&self.lab, &self.lab.b, &self.opts);
        let (out, ok) = self.ctl(&["reload"]);
        assert!(ok && out.contains("reset 1 "), "{out}");
    }

    /// Everything the daemons logged, for a failed assertion.
    fn report(&self) -> String {
        format!(
            "--- show neighbor C ---\n{}\n--- bird C ---\n{}\n--- bird A ---\n{}\n--- bgpfcd ---\n{}",
            self.neighbor_c(),
            self.bird_c.daemon.log_text(),
            self.bird_a.daemon.log_text(),
            self.bgpfcd.log_text()
        )
    }

    /// No session with C comes up while [`NO_SESSION`] passes.
    fn assert_no_session_with_c(&self) {
        let up = wait_for(NO_SESSION, || {
            self.neighbor_c().contains("state Established")
                || self.bird_c.peer_status(&self.lab).contains("Established")
        });
        assert!(!up, "a session with C:\n{}", self.report());
    }
}

/// bgpfcd's neighbor C, with a short `connect-retry-time` so that its
/// attempts come every few seconds, and `extra`.
fn to_c_neighbor(lo: Loopbacks, extra: &str) -> NeighborOpts {
    NeighborOpts {
        extra: format!("connect-retry-time 5; {extra}"),
        ..NeighborOpts::new(lo.c, BIRD_C_AS)
    }
}

/// An external neighbor two hops away: without `multihop` bgpfcd's SYN
/// dies at the router, and the log and `show neighbor` say so; with
/// `multihop 2` it reaches BIRD, which refuses a connection from an
/// address it does not know (design finding 5); with `local-address` too
/// the session comes up, from the loopback. Each reload resets the
/// neighbor, and the direct session with A stays up throughout.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn ebgp_multihop_needs_multihop_and_binds_local_address() {
    let mut s = Routed::start("mh", 50, "");
    let c = s.lo.c.to_string();
    let b_lo = s.lo.b.to_string();
    let a = s.lab.a_addr.to_string();

    // (i) TTL 1: A answers the SYN with a Time Exceeded, and the connect
    // fails at once (design finding 1).
    let refused = format!(
        "WARN  msg=\"connect failed\" peer={c} error=\"No route to host (os error 113)\" ttl=1 {HINT}"
    );
    let ok = wait_for(Duration::from_secs(10), || {
        s.bgpfcd.log_text().contains(&refused)
    });
    assert!(ok, "{refused}\n{}", s.report());
    s.assert_no_session_with_c();
    let n = s.neighbor_c();
    assert!(n.contains("  ttl 1\n"), "{n}");
    assert!(
        n.contains("  last error No route to host (os error 113) ("),
        "{n}"
    );
    // Folded: one warning, the repeats at debug.
    let log = s.bgpfcd.log_text();
    assert_eq!(log.matches(&refused).count(), 1, "{log}");
    assert!(
        log.matches(&format!("DEBUG msg=\"connect failed\" peer={c} "))
            .count()
            >= 1,
        "{log}"
    );

    // (ii) TTL 2 reaches C, from the address of B's interface, which BIRD
    // does not know its neighbor by.
    s.reload_c("multihop 2;");
    let ok = wait_for(Duration::from_secs(15), || {
        s.bird_c
            .daemon
            .log_text()
            .contains("Unexpected connect from unknown address")
    });
    assert!(ok, "{}", s.report());
    s.assert_no_session_with_c();
    assert!(s.neighbor_c().contains("  ttl 2\n"), "{}", s.report());

    // (iii) Bound to the loopback BIRD knows: the session comes up, and
    // BIRD, passive, proves the bind.
    s.reload_c(&format!("multihop 2; local-address {b_lo};"));
    let ok = wait_for(ESTABLISH, || {
        s.neighbor_c().contains("state Established")
            && s.bird_c.peer_status(&s.lab).contains("Established")
    });
    assert!(ok, "{}", s.report());
    let n = s.neighbor_c();
    assert!(n.contains(&format!("  local address {b_lo}\n")), "{n}");
    assert!(n.contains("  ttl 2\n"), "{n}");
    assert!(!n.contains("last error"), "{n}");
    // Its route arrived (whether it can be used is next-hop resolution's
    // business, not this test's).
    let ok = wait_for(Duration::from_secs(10), || {
        s.neighbor_c().contains("routes received 1 ")
    });
    assert!(ok, "{}", s.report());

    // The direct session with A was up all along, with TTL 1, through the
    // three reloads that reset C.
    let (n, _) = s.ctl(&["show", "neighbor", &a]);
    assert!(n.contains("state Established"), "{n}");
    assert!(n.contains("  ttl 1\n"), "{n}");
    assert!(s.bird_a.peer_status(&s.lab).contains("Established"));
    let log = s.bgpfcd.log_text();
    assert_eq!(
        log.matches(&format!("msg=\"session established\" peer={a} "))
            .count(),
        1,
        "{log}"
    );
}
