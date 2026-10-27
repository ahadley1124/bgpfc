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
//! The next hop BIRD in C gives its route is a loopback of C that B
//! reaches by a static route through A: bgpfcd resolves it in B's kernel
//! table (RFC 4271 §9.1.2, `docs/config.md`, "Route selection") and
//! installs the route through A's address, the immediate gateway; when
//! the static route goes the route is held, leaves the kernel and is
//! withdrawn from A, and it comes back with the static route. An internal
//! session over the loopbacks resolves the same way, with the system's
//! TTL.
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
    /// BIRD in C's AS.
    c_as: u32,
    lab: Lab,
}

/// How a [`Routed`] lab is set up.
struct Setup {
    /// BIRD in C's AS: [`BIRD_C_AS`] for an external session with
    /// bgpfcd, [`BGPFC_AS`] for an internal one, which BIRD runs multihop
    /// by default.
    c_as: u32,
    /// More statements for bgpfcd's neighbor block for C, given the
    /// lab's loopbacks.
    to_c: fn(Loopbacks) -> String,
    /// Whether bgpfcd installs its routes (`fib { mode install; }`), or
    /// keeps the FIB in dry-run.
    install: bool,
}

impl Routed {
    /// Build the lab and start the three daemons as `setup` says. BIRD in
    /// C is passive, so a session with it is one bgpfcd opened.
    fn start(tag: &str, subnet: u8, setup: &Setup) -> Routed {
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
        // BIRD runs an internal session multihop unless told otherwise.
        let bird_c = Bird::start(
            &lab,
            &ns_c,
            &BirdOpts {
                local_as: setup.c_as,
                local: lo.c,
                local_port: 179,
                neighbor: lo.b,
                neighbor_port: 179,
                remote_as: BGPFC_AS,
                hold_time: 30,
                passive: true,
                statics: vec![C_ROUTE.to_owned()],
                channel: String::new(),
                protocol: if setup.c_as == BGPFC_AS {
                    String::new()
                } else {
                    "multihop;".to_owned()
                },
                export: format!("filter {{ bgp_next_hop = {}; accept; }}", lo.c_next_hop),
            },
        );
        let socket = lab.dir.join("ctl.sock");
        let fib = if setup.install {
            "fib { mode install; }"
        } else {
            ""
        };
        let opts = BgpfcdOpts {
            local_as: BGPFC_AS,
            router_id: lo.b,
            listen: vec![lab.b_addr.into(), lo.b.into()],
            neighbors: vec![
                NeighborOpts {
                    advertisement_interval: Some(0),
                    ..NeighborOpts::new(lab.a_addr, BIRD_A_AS)
                },
                to_c_neighbor(lo, setup.c_as, &(setup.to_c)(lo)),
            ],
            extra: format!("control {{ socket {}; }} {fib}", socket.display()),
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
            c_as: setup.c_as,
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
        self.opts.neighbors[1] = to_c_neighbor(self.lo, self.c_as, to_c);
        let _ = bgpfcd_config(&self.lab, &self.lab.b, &self.opts);
        let (out, ok) = self.ctl(&["reload"]);
        assert!(ok && out.contains("reset 1 "), "{out}");
    }

    /// The sessions with A and with C are Established on both ends.
    fn wait_established(&self) -> bool {
        let a = self.lab.a_addr.to_string();
        wait_for(ESTABLISH, || {
            self.neighbor_c().contains("state Established")
                && self.bird_c.peer_status(&self.lab).contains("Established")
                && self
                    .ctl(&["show", "neighbor", &a])
                    .0
                    .contains("state Established")
                && self.bird_a.peer_status(&self.lab).contains("Established")
        })
    }

    /// B's kernel route to C's route, as `ip route show proto 186` prints
    /// it, or an empty string.
    fn installed(&self) -> String {
        Daemon::ip_in(&self.lab, &self.lab.b, &["route", "show", "proto", "186"])
            .lines()
            .find(|l| l.starts_with(&format!("{C_ROUTE} ")))
            .unwrap_or_default()
            .to_owned()
    }

    /// The fields of the line of `show nexthops` for C's second loopback.
    fn next_hop(&self) -> Vec<String> {
        let c_next_hop = self.lo.c_next_hop.to_string();
        self.ctl(&["show", "nexthops"])
            .0
            .lines()
            .map(|l| l.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
            .find(|f| f.first() == Some(&c_next_hop))
            .unwrap_or_default()
    }

    /// Whether BIRD in A has C's route, which only bgpfcd sends it.
    fn a_has_route(&self) -> bool {
        self.bird_a
            .birdc(&self.lab, &["show", "route", C_ROUTE])
            .contains(C_ROUTE)
    }

    /// Everything the daemons logged, for a failed assertion.
    fn report(&self) -> String {
        format!(
            "--- show neighbor C ---\n{}\n--- show nexthops ---\n{}\n--- show routes {C_ROUTE} \
             ---\n{}\n--- ip route in B ---\n{}\n--- bird C ---\n{}\n--- bird A ---\n{}\n--- \
             bgpfcd ---\n{}",
            self.neighbor_c(),
            self.ctl(&["show", "nexthops"]).0,
            self.ctl(&["show", "routes", C_ROUTE]).0,
            Daemon::ip_in(&self.lab, &self.lab.b, &["route", "show"]),
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

/// bgpfcd's neighbor C in AS `c_as`, with a short `connect-retry-time`
/// so that its attempts come every few seconds, and `extra`.
fn to_c_neighbor(lo: Loopbacks, c_as: u32, extra: &str) -> NeighborOpts {
    NeighborOpts {
        extra: format!("connect-retry-time 5; {extra}"),
        ..NeighborOpts::new(lo.c, c_as)
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
    let mut s = Routed::start(
        "mh",
        50,
        &Setup {
            c_as: BIRD_C_AS,
            to_c: |_| String::new(),
            install: false,
        },
    );
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

impl Routed {
    /// Run `ip args` in B, which must succeed.
    fn ip_in_b(&self, args: &[&str]) {
        let out = self
            .lab
            .exec(&self.lab.b, "ip")
            .args(args)
            .output()
            .expect("ip");
        assert!(
            out.status.success(),
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The `rib: next hops changed` lines bgpfcd logged in `log`.
    fn next_hops_changed(log: &str) -> Vec<&str> {
        log.lines()
            .filter(|l| l.contains("msg=\"rib: next hops changed\""))
            .collect()
    }
}

/// What the routed lab of [`routes_install_via_the_resolved_gateway_and_follow_it`]
/// expects of C's route and its next hop, C's second loopback.
struct Expect {
    /// The beginning of the kernel's line for the route installed through
    /// A on B's link to it.
    via: String,
    /// The fields of `show nexthops` for the next hop resolved through
    /// the static route to it.
    resolved: Vec<String>,
}

impl Routed {
    /// What C's route installed and its next hop resolved look like.
    fn expect(&self) -> Expect {
        let a = self.lab.a_addr.to_string();
        let next_hop = self.lo.c_next_hop.to_string();
        Expect {
            via: format!("{C_ROUTE} via {a} dev {} ", self.lab.b_link()),
            resolved: [
                next_hop.as_str(),
                "resolved",
                &a,
                &self.lab.b_link(),
                &format!("{next_hop}/32"),
                "1",
            ]
            .map(str::to_owned)
            .to_vec(),
        }
    }

    /// A static route with the destination and metric of C's route, there
    /// before bgpfcd installs it, stays (AGENTS.md §3: never touch a route
    /// of another protocol): bgpfcd's is left out, with a failure line,
    /// and `show fib` lists it pending; once the static route goes, it is
    /// installed.
    fn assert_another_programs_route_stays(&self, e: &Expect) {
        let a = self.lab.a_addr.to_string();
        let next_hop = format!("{}/32", self.lo.c_next_hop);
        self.ip_in_b(&["route", "del", &next_hop]);
        let gone = wait_for(Duration::from_secs(10), || self.installed().is_empty());
        assert!(gone, "{}", self.report());
        let static_route = [C_ROUTE, "via", &a, "proto", "static", "metric", "20"];
        self.ip_in_b(&[&["route", "add"][..], &static_route].concat());
        let before = self.bgpfcd.log_text().len();
        self.ip_in_b(&["route", "add", &next_hop, "via", &a, "proto", "static"]);
        let refused = "another route has this destination and metric";
        let ok = wait_for(Duration::from_secs(10), || {
            self.bgpfcd.log_text()[before..].contains(refused)
        });
        assert!(ok, "{}", self.report());
        let kernel = Daemon::ip_in(&self.lab, &self.lab.b, &["route", "show", C_ROUTE]);
        assert!(
            kernel.contains("proto static") && !kernel.contains("proto bgp"),
            "{kernel}"
        );
        let fib = self.ctl(&["show", "fib"]).0;
        assert!(
            fib.lines()
                .any(|l| l.starts_with(&format!("{C_ROUTE} ")) && l.ends_with(" pending")),
            "{fib}"
        );
        self.ip_in_b(&[&["route", "del"][..], &static_route].concat());
        self.assert_in_use(e);
    }

    /// C's route is the best, installed through A, which has it from
    /// bgpfcd, and its next hop resolves through the static route.
    fn assert_in_use(&self, e: &Expect) {
        let ok = wait_for(Duration::from_secs(10), || {
            self.installed().starts_with(&e.via) && self.a_has_route()
        });
        assert!(ok, "{}\n{}", e.via, self.report());
        assert!(self.installed().contains(" metric 20"), "{}", self.report());
        assert_eq!(self.next_hop(), e.resolved, "{}", self.report());
        let next_hop = format!(" {} ", self.lo.c_next_hop);
        assert!(
            self.ctl(&["show", "routes", C_ROUTE])
                .0
                .lines()
                .any(|l| l.starts_with(&format!("*{C_ROUTE} ")) && l.contains(&next_hop)),
            "{}",
            self.report()
        );
    }

    /// The static route to C's second loopback goes: the route is held
    /// for its next hop, leaves the kernel, and A is sent its withdrawal;
    /// bgpfcd logs one line for the next hop and none for the route at
    /// info.
    fn assert_held_when_the_next_hop_goes(&self) {
        let next_hop = self.lo.c_next_hop.to_string();
        let before = self.bgpfcd.log_text().len();
        self.ip_in_b(&["route", "del", &format!("{next_hop}/32")]);
        let held = format!(" via {} next hop unresolvable", self.lo.c);
        let ok = wait_for(Duration::from_secs(10), || {
            self.ctl(&["show", "routes", C_ROUTE])
                .0
                .lines()
                .any(|l| l.starts_with(&format!("!{C_ROUTE} ")) && l.ends_with(&held))
                && self.installed().is_empty()
                && !self.a_has_route()
        });
        assert!(ok, "{}", self.report());
        let unresolved = [next_hop.as_str(), "unresolved", "-", "-", "-", "1"];
        assert_eq!(
            self.next_hop(),
            unresolved.map(str::to_owned).to_vec(),
            "{}",
            self.report()
        );
        assert!(
            self.neighbor_c().contains("  routes received 1 held 1 "),
            "{}",
            self.report()
        );
        let log = self.bgpfcd.log_text();
        let after = log.get(before..).unwrap_or_default();
        let changed = Routed::next_hops_changed(after);
        assert_eq!(changed.len(), 1, "{after}");
        assert!(
            changed[0].contains(" INFO  ")
                && changed[0].contains(" resolved=0 unresolved=1 moved=0 held=1 released=0 ")
                && changed[0].ends_with(&format!("next_hops=\"{next_hop} unresolved\"")),
            "{}",
            changed[0]
        );
        // The route shows at info only in the FIB's folded line of
        // changes.
        let route_lines: Vec<&str> = after
            .lines()
            .filter(|l| l.contains(" INFO  ") && l.contains(C_ROUTE))
            .filter(|l| !l.contains("msg=\"fib: changes\""))
            .collect();
        assert!(route_lines.is_empty(), "{route_lines:#?}\n{after}");
    }

    /// The static route comes back, and so does the route: installed and
    /// sent to A again (A's advertisement interval is 0), with no UPDATE
    /// from C.
    fn assert_back_when_the_next_hop_returns(&self, e: &Expect) {
        let a = self.lab.a_addr.to_string();
        let next_hop = self.lo.c_next_hop.to_string();
        let before = self.bgpfcd.log_text().len();
        self.ip_in_b(&[
            "route",
            "add",
            &format!("{next_hop}/32"),
            "via",
            &a,
            "proto",
            "static",
        ]);
        self.assert_in_use(e);
        assert!(
            self.neighbor_c().contains("  routes received 1 held 0 "),
            "{}",
            self.report()
        );
        let log = self.bgpfcd.log_text();
        let after = log.get(before..).unwrap_or_default();
        let changed = Routed::next_hops_changed(after);
        assert_eq!(changed.len(), 1, "{after}");
        let back = format!("next_hops=\"{next_hop} via {a} dev {}\"", self.lab.b_link());
        assert!(
            changed[0].contains(" resolved=1 unresolved=0 moved=0 held=0 released=1 ")
                && changed[0].ends_with(&back),
            "{}",
            changed[0]
        );
    }
}

/// C's route has C's second loopback as its next hop, which B reaches by
/// a static route through A: bgpfcd resolves it there and installs the
/// route through A, the immediate gateway, on B's link to A (design.md
/// 6.3, 2). When the static route goes the next hop no longer resolves
/// (RFC 4271 §9.1.2): the route is held, leaves B's kernel and is
/// withdrawn from A, and bgpfcd logs one line for it, none for the route
/// at info. When the static route comes back, so does the route, with no
/// UPDATE from C. The session with C, over its other loopback, stays up
/// throughout.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn routes_install_via_the_resolved_gateway_and_follow_it() {
    let s = Routed::start(
        "mr",
        51,
        &Setup {
            c_as: BIRD_C_AS,
            to_c: |lo| format!("multihop 2; local-address {};", lo.b),
            install: true,
        },
    );
    assert!(s.wait_established(), "{}", s.report());
    let e = s.expect();
    // Through A, the gateway of the static route, not through C's
    // address, which no link of B reaches.
    s.assert_in_use(&e);
    s.assert_held_when_the_next_hop_goes();
    s.assert_back_when_the_next_hop_returns(&e);
    s.assert_another_programs_route_stays(&e);

    // The session with C was never touched: one session, still up.
    assert!(s.neighbor_c().contains("state Established"));
    assert!(s.bird_c.peer_status(&s.lab).contains("Established"));
    let log = s.bgpfcd.log_text();
    let c = s.lo.c;
    assert_eq!(
        log.matches(&format!("msg=\"session established\" peer={c} "))
            .count(),
        1,
        "{log}"
    );
}

/// An internal session over the loopbacks (design.md 6.3, 3): with no
/// `multihop` on either side bgpfcd keeps the system's TTL, which crosses
/// A, and the route resolves and installs as over the external one.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn ibgp_over_loopbacks_resolves_through_static_routes() {
    let s = Routed::start(
        "mi",
        52,
        &Setup {
            c_as: BGPFC_AS,
            to_c: |lo| format!("local-address {};", lo.b),
            install: true,
        },
    );
    assert!(s.wait_established(), "{}", s.report());
    let n = s.neighbor_c();
    assert!(n.contains("  ttl system default\n"), "{n}");
    assert!(n.contains(&format!("  local address {}\n", s.lo.b)), "{n}");
    s.assert_in_use(&s.expect());
}
