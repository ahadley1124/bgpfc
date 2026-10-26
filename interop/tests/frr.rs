//! Sessions between `bgpfcd` and FRR `bgpd` (AGENTS.md §5, `interop/`
//! row): session up, prefixes both ways, withdraw, route refresh, a
//! four-octet AS, and several paths per prefix with ADD-PATH (RFC 7911) in
//! both directions. Every test is `#[ignore]`: needs root, `iproute2`, FRR
//! and BIRD.

use std::time::Duration;

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Frr, Lab, NeighborOpts, OtherOpts, start_bgpfcd, wait_for,
};

const BGPFC_AS: u32 = 65_000;
/// A four-octet AS (RFC 6793), beyond the two-octet range.
const FRR_AS: u32 = 4_200_000_001;
const BIRD_AS: u32 = 65_002;
const ESTABLISH: Duration = Duration::from_secs(40);

#[test]
#[ignore = "needs root, frr, bird and iproute2"]
fn frr_session_prefixes_both_ways_withdraw_and_refresh() {
    let mut lab = Lab::new("f", 11);
    let ns_c = lab.add_c();
    // FRR in B originates one prefix; BIRD in C originates another;
    // bgpfcd relays between them.
    let frr = Frr::start(
        &lab,
        &lab.b.clone(),
        &OtherOpts {
            local_as: FRR_AS,
            local: lab.b_addr,
            neighbor: lab.a_addr,
            remote_as: BGPFC_AS,
            networks: vec!["192.0.2.0/24".to_owned()],
        },
    );
    let bird = Bird::start(
        &lab,
        &ns_c,
        &BirdOpts {
            local_as: BIRD_AS,
            local: lab.c_addr,
            local_port: 179,
            neighbor: lab.a2_addr,
            neighbor_port: 179,
            remote_as: BGPFC_AS,
            hold_time: 30,
            passive: true,
            statics: vec!["203.0.113.0/24".to_owned()],
            channel: String::new(),
            protocol: String::new(),
        },
    );
    let bgpfcd = start_bgpfcd(
        &lab,
        &lab.a.clone(),
        &BgpfcdOpts {
            local_as: BGPFC_AS,
            router_id: lab.a_addr,
            listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
            neighbors: vec![
                NeighborOpts::new(lab.b_addr, FRR_AS),
                NeighborOpts::new(lab.c_addr, BIRD_AS),
            ],
            extra: String::new(),
        },
    );
    let ok = wait_for(ESTABLISH, || {
        frr.summary(&lab).contains(" 65000 ")
            && bgpfcd.log_text().matches("session established").count() == 2
    });
    assert!(
        ok,
        "frr:\n{}\nbgpfcd:\n{}",
        frr.summary(&lab),
        bgpfcd.log_text()
    );
    assert!(
        bgpfcd.log_text().contains("remote_as=AS4200000001"),
        "{}",
        bgpfcd.log_text()
    );

    // FRR's prefix reaches BIRD with our AS prepended and the four-octet
    // AS intact; BIRD's prefix reaches FRR.
    let ok = wait_for(Duration::from_secs(15), || {
        bird.birdc(&lab, &["show", "route", "all"])
            .contains("192.0.2.0/24")
            && frr
                .vtysh(&lab, "show bgp ipv4 unicast")
                .contains("203.0.113.0/24")
    });
    let routes = bird.birdc(&lab, &["show", "route", "all"]);
    assert!(
        ok,
        "bird:\n{routes}\nfrr:\n{}\n{}",
        frr.vtysh(&lab, "show bgp ipv4 unicast"),
        bgpfcd.log_text()
    );
    assert!(routes.contains("BGP.as_path: 65000 4200000001"), "{routes}");
    let frr_routes = frr.vtysh(&lab, "show bgp ipv4 unicast 203.0.113.0/24");
    assert!(frr_routes.contains("65000 65002"), "{frr_routes}");

    // Withdraw on FRR: gone from BIRD.
    let _ = frr.vtysh(&lab, "configure terminal\nrouter bgp 4200000001\naddress-family ipv4 unicast\nno network 192.0.2.0/24");
    let ok = wait_for(Duration::from_secs(15), || {
        !bird
            .birdc(&lab, &["show", "route"])
            .contains("192.0.2.0/24")
    });
    assert!(ok, "withdraw not relayed:\n{}", bgpfcd.log_text());

    // FRR asks for a refresh: bgpfcd re-sends.
    let _ = frr.vtysh(&lab, "clear bgp ipv4 unicast * soft in");
    let ok = wait_for(Duration::from_secs(10), || {
        bgpfcd.log_text().contains("rib: route refresh")
    });
    assert!(ok, "no route refresh seen:\n{}", bgpfcd.log_text());
    let ok = wait_for(Duration::from_secs(10), || {
        frr.vtysh(&lab, "show bgp ipv4 unicast")
            .contains("203.0.113.0/24")
    });
    assert!(ok, "{}", frr.vtysh(&lab, "show bgp ipv4 unicast"));
}

/// The AS of the BIRD in C that sends several paths in the ADD-PATH tests.
const BIRD_C_AS: u32 = 65_002;
/// FRR's AS in the ADD-PATH tests.
const FRR_ADD_PATH_AS: u32 = 65_003;

/// The AS paths FRR lists for a prefix in `show bgp ipv4 unicast PREFIX`,
/// in FRR's order: the lines made of AS numbers alone.
fn frr_as_paths(out: &str) -> Vec<String> {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit() || c == ' '))
        .map(str::to_owned)
        .collect()
}

/// RFC 7911 §5 with FRR as the receiver. BIRD in C sends bgpfcd three paths
/// to one prefix (`add paths tx`; `add-path receive`); bgpfcd sends them to
/// FRR in B (`add-path send all`), which takes them with no configuration:
/// FRR advertises the Receive half of the capability unless told not to.
#[test]
#[ignore = "needs root, frr, bird and iproute2"]
fn frr_takes_several_paths_from_bgpfcd() {
    let mut lab = Lab::new("pf", 22);
    let ns_c = lab.add_c();
    let frr = Frr::start(
        &lab,
        &lab.b.clone(),
        &OtherOpts {
            local_as: FRR_ADD_PATH_AS,
            local: lab.b_addr,
            neighbor: lab.a_addr,
            remote_as: BGPFC_AS,
            networks: Vec::new(),
        },
    );
    let bird = Bird::three_paths(&lab, &ns_c, BIRD_C_AS);
    let socket = lab.dir.join("ctl.sock");
    let to_frr = NeighborOpts {
        advertisement_interval: Some(1),
        extra: "add-path send ipv4-unicast all;".to_owned(),
        ..NeighborOpts::new(lab.b_addr, FRR_ADD_PATH_AS)
    };
    let to_bird = NeighborOpts {
        extra: "add-path receive ipv4-unicast yes;".to_owned(),
        ..NeighborOpts::new(lab.c_addr, BIRD_C_AS)
    };
    let bgpfcd = start_bgpfcd(
        &lab,
        &lab.a.clone(),
        &BgpfcdOpts {
            local_as: BGPFC_AS,
            router_id: lab.a_addr,
            listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
            neighbors: vec![to_frr, to_bird],
            extra: format!("control {{ socket {}; }}", socket.display()),
        },
    );
    let ok = wait_for(ESTABLISH, || {
        bgpfcd.log_text().matches("session established").count() == 2
    });
    assert!(ok, "{}", bgpfcd.log_text());

    let paths = || frr_as_paths(&frr.vtysh(&lab, "show bgp ipv4 unicast 192.0.2.0/24"));
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    let three = vec![
        "65000 65002".to_owned(),
        "65000 65002 64999".to_owned(),
        "65000 65002 64999 64998".to_owned(),
    ];
    let ok = wait_for(Duration::from_secs(30), || {
        sorted(paths()) == sorted(three.clone())
    });
    assert!(
        ok,
        "{:?}\n{}\n{}",
        paths(),
        frr.vtysh(&lab, "show bgp ipv4 unicast 192.0.2.0/24"),
        bgpfcd.log_text()
    );
    let (out, ok) = interop::bgpfcctl(&socket, &["show", "neighbor", &lab.b_addr.to_string()]);
    assert!(
        ok && out.contains("add-path receive none send ipv4-unicast=all"),
        "{out}"
    );

    // A withdrawn path goes by its identifier; the other two stay.
    let _ = bird.birdc(&lab, &["disable", "short"]);
    let two = vec![
        "65000 65002 64999".to_owned(),
        "65000 65002 64999 64998".to_owned(),
    ];
    let ok = wait_for(Duration::from_secs(30), || {
        sorted(paths()) == sorted(two.clone())
    });
    assert!(ok, "{:?}\n{}", paths(), bgpfcd.log_text());
}

/// FRR in B with two BIRD feeders in A that originate `198.51.100.0/24`,
/// bgpfcd, and BIRD in C that takes the paths.
struct SenderLab {
    frr: Frr,
    feeders: [Bird; 2],
    bird: Bird,
    bgpfcd: interop::Daemon,
    socket: std::path::PathBuf,
    /// Last, so that the namespaces go after the daemons in them.
    lab: Lab,
}

impl SenderLab {
    const FEEDER_1_AS: u32 = 65_010;
    const FEEDER_2_AS: u32 = 65_011;

    /// Start them all and wait for bgpfcd's two sessions.
    fn start(tag: &str, subnet: u8) -> SenderLab {
        let mut lab = Lab::new(tag, subnet);
        let ns_c = lab.add_c();
        // BIRD cannot peer with an address of its own namespace, so the
        // feeders sit in A, on addresses of their own, and connect to FRR;
        // FRR without zebra does not connect out.
        let (f1, f2) = (lab.add_a_addr(12), lab.add_a_addr(13));
        // Two BIRD processes, one session each to FRR (BIRD takes one
        // protocol per neighbor address); the second one's route is given
        // a longer AS path, so that the two differ.
        let feeder = |name: &str, local, local_as, statics: &[&str], extra: &str| {
            Bird::start_named(
                &lab,
                &lab.a.clone(),
                name,
                &BirdOpts {
                    local_as,
                    local,
                    local_port: 179,
                    neighbor: lab.b_addr,
                    neighbor_port: 179,
                    remote_as: FRR_ADD_PATH_AS,
                    hold_time: 30,
                    passive: false,
                    statics: statics.iter().map(|s| (*s).to_owned()).collect(),
                    channel: String::new(),
                    // The feeder's address alone: bgpfcd has 179 on A's.
                    protocol: "strict bind yes;".to_owned(),
                },
                extra,
            )
        };
        let feeders = [
            feeder("f1", f1, Self::FEEDER_1_AS, &["198.51.100.0/24"], ""),
            feeder(
                "f2",
                f2,
                Self::FEEDER_2_AS,
                &[],
                "protocol static longer {\n    ipv4 { import filter { bgp_path.prepend(64999); accept; }; };\n\
                 \x20   route 198.51.100.0/24 blackhole;\n}\n",
            ),
        ];
        let frr = Self::start_frr(&lab, f1, f2);
        let bird = Bird::start(
            &lab,
            &ns_c,
            &BirdOpts {
                local_as: BIRD_C_AS,
                local: lab.c_addr,
                local_port: 179,
                neighbor: lab.a2_addr,
                neighbor_port: 179,
                remote_as: BGPFC_AS,
                hold_time: 30,
                passive: true,
                statics: Vec::new(),
                channel: "add paths rx;".to_owned(),
                protocol: String::new(),
            },
        );
        let socket = lab.dir.join("ctl.sock");
        let to_frr = NeighborOpts {
            extra: "add-path receive ipv4-unicast yes;".to_owned(),
            ..NeighborOpts::new(lab.b_addr, FRR_ADD_PATH_AS)
        };
        let to_bird = NeighborOpts {
            advertisement_interval: Some(1),
            extra: "add-path send ipv4-unicast all;".to_owned(),
            ..NeighborOpts::new(lab.c_addr, BIRD_C_AS)
        };
        let bgpfcd = start_bgpfcd(
            &lab,
            &lab.a.clone(),
            &BgpfcdOpts {
                local_as: BGPFC_AS,
                router_id: lab.a_addr,
                listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
                neighbors: vec![to_frr, to_bird],
                extra: format!("control {{ socket {}; }}", socket.display()),
            },
        );
        let ok = wait_for(ESTABLISH, || {
            bgpfcd.log_text().matches("session established").count() == 2
        });
        assert!(ok, "{}", bgpfcd.log_text());
        SenderLab {
            frr,
            feeders,
            bird,
            bgpfcd,
            socket,
            lab,
        }
    }

    /// FRR in B, with the feeders at `f1` and `f2` as passive neighbors
    /// and bgpfcd's neighbor sent every path.
    fn start_frr(lab: &Lab, f1: std::net::Ipv4Addr, f2: std::net::Ipv4Addr) -> Frr {
        Frr::start_with(
            lab,
            &lab.b.clone(),
            &OtherOpts {
                local_as: FRR_ADD_PATH_AS,
                local: lab.b_addr,
                neighbor: lab.a_addr,
                remote_as: BGPFC_AS,
                networks: Vec::new(),
            },
            &format!(
                " neighbor {f1} remote-as {}\n neighbor {f1} timers 10 30\n\
             \x20neighbor {f1} passive\n\
             \x20neighbor {f2} remote-as {}\n neighbor {f2} timers 10 30\n\
             \x20neighbor {f2} passive\n",
                Self::FEEDER_1_AS,
                Self::FEEDER_2_AS
            ),
            &format!(
                "  neighbor {f1} activate\n  neighbor {f2} activate\n\
             \x20 neighbor {} addpath-tx-all-paths\n",
                lab.a_addr
            ),
        )
    }

    fn ctl(&self, args: &[&str]) -> (String, bool) {
        interop::bgpfcctl(&self.socket, args)
    }

    /// bgpfcd's candidate routes to the prefix.
    fn candidates(&self) -> String {
        self.ctl(&["show", "routes", "198.51.100.0/24"]).0
    }

    /// The AS paths BIRD in C has for the prefix, sorted.
    fn paths_c(&self) -> Vec<String> {
        let out = self
            .bird
            .birdc(&self.lab, &["show", "route", "all", "198.51.100.0/24"]);
        let mut v: Vec<String> = out
            .lines()
            .filter_map(|l| l.trim().strip_prefix("BGP.as_path: "))
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    }

    /// Wait until BIRD in C has exactly the paths `want`.
    fn wait_for_paths_c(&self, want: &[&str]) {
        let mut want: Vec<String> = want.iter().map(|p| (*p).to_owned()).collect();
        want.sort();
        let ok = wait_for(Duration::from_secs(60), || self.paths_c() == want);
        assert!(
            ok,
            "wanted {want:?}, has {:?}\n{}\n{}",
            self.paths_c(),
            self.frr
                .vtysh(&self.lab, "show bgp ipv4 unicast 198.51.100.0/24"),
            self.bgpfcd.log_text()
        );
    }
}

/// RFC 7911 §5 with FRR as the sender. FRR in B learns `198.51.100.0/24`
/// from two BIRD speakers in A beside bgpfcd and sends bgpfcd both under
/// `addpath-tx-all-paths`; bgpfcd keeps both (`add-path receive`) and sends
/// them to BIRD in C (`add-path send all`, `add paths rx`). A feeder that
/// goes away takes its path away from C by the identifier bgpfcd gave it.
#[test]
#[ignore = "needs root, frr, bird and iproute2"]
fn frr_sends_several_paths_to_bgpfcd() {
    let t = SenderLab::start("ph", 24);

    // FRR -> bgpfcd: two paths from one neighbor, each with its identifier.
    let ok = wait_for(Duration::from_secs(60), || {
        t.candidates().matches(" id ").count() == 2
    });
    assert!(
        ok,
        "{}\n--- frr ---\n{}\n{}\n--- feeders ---\n{}\n{}",
        t.candidates(),
        t.frr.summary(&t.lab),
        t.frr.vtysh(&t.lab, "show bgp ipv4 unicast 198.51.100.0/24"),
        t.feeders[0].birdc(&t.lab, &["show", "protocols", "all"]),
        t.bgpfcd.log_text()
    );
    assert_eq!(t.candidates().matches("*198.51.100.0/24").count(), 1);
    let (fib, ok) = t.ctl(&["show", "fib"]);
    assert!(ok && fib.matches("198.51.100.0/24").count() == 1, "{fib}");

    // bgpfcd -> BIRD: both, our AS and FRR's in front.
    t.wait_for_paths_c(&["65000 65003 65010", "65000 65003 65011 64999"]);

    // One feeder goes away: FRR withdraws its path from bgpfcd, which
    // withdraws it from BIRD by the identifier it gave it.
    let _ = t.feeders[1].birdc(&t.lab, &["disable", "peer"]);
    t.wait_for_paths_c(&["65000 65003 65010"]);
    let ok = wait_for(Duration::from_secs(10), || {
        t.candidates().matches(" id ").count() == 1
    });
    assert!(ok, "{}", t.candidates());
}
