//! Sessions between `bgpfcd` and BIRD 2 (AGENTS.md §5, `interop/` row).
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird` and
//! `birdc` on `PATH`, and a built `bgpfcd`. CI runs them with
//! `--include-ignored` under sudo.

use std::time::Duration;

use interop::{BgpfcdOpts, Bird, BirdOpts, Lab, NeighborOpts, start_bgpfcd, wait_for};

const BGPFC_AS: u32 = 65_000;
const BIRD_AS: u32 = 65_001;
const ESTABLISH: Duration = Duration::from_secs(40);

fn bird_opts(lab: &Lab, passive: bool, statics: &[&str]) -> BirdOpts {
    BirdOpts {
        local_as: BIRD_AS,
        local: lab.b_addr,
        local_port: 179,
        neighbor: lab.a_addr,
        neighbor_port: 179,
        remote_as: BGPFC_AS,
        hold_time: 30,
        passive,
        statics: statics.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn bgpfcd_opts(lab: &Lab, passive: bool) -> BgpfcdOpts {
    let mut n = NeighborOpts::new(lab.b_addr, BIRD_AS);
    n.passive = passive;
    BgpfcdOpts::single(BGPFC_AS, lab.a_addr, n)
}

/// Both sides report Established, and BIRD's statics reach bgpfcd's RIB.
fn assert_established(lab: &Lab, bird: &Bird, bgpfcd: &interop::Daemon) {
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

#[test]
#[ignore = "needs root, bird and iproute2"]
fn session_with_bird_bgpfcd_connects() {
    let lab = Lab::new("c", 1);
    // BIRD passive: only bgpfcd's outgoing connection can succeed.
    let bird = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, true, &["192.0.2.0/24", "198.51.100.0/24"]),
    );
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &bgpfcd_opts(&lab, false));
    assert_established(&lab, &bird, &bgpfcd);
    // RFC 4271 §4.2: BIRD offered 30, we offered 30.
    assert!(
        bgpfcd.log_text().contains("hold=30s"),
        "{}",
        bgpfcd.log_text()
    );
    // BIRD's two statics arrive as UPDATEs.
    let ok = wait_for(Duration::from_secs(10), || {
        let log = bgpfcd.log_text();
        log.contains("prefix=192.0.2.0/24") && log.contains("prefix=198.51.100.0/24")
    });
    assert!(ok, "statics not received:\n{}", bgpfcd.log_text());
    // BIRD sees our capabilities.
    let status = bird.peer_status(&lab);
    assert!(status.contains("Neighbor AS:      65000"), "{status}");
    assert!(status.contains("ipv4"), "{status}");
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn session_with_bird_bird_connects() {
    let lab = Lab::new("p", 2);
    // bgpfcd passive: BIRD must connect to us.
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &bgpfcd_opts(&lab, true));
    let bird = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, false, &["192.0.2.0/24"]),
    );
    assert_established(&lab, &bird, &bgpfcd);
    let log = bgpfcd.log_text();
    // RFC 4271 §8.2.2: passive start goes to Active and the incoming
    // connection (event 17) carries it to OpenSent.
    assert!(log.contains("from=Idle to=Active event=1"), "{log}");
    assert!(log.contains("from=Active to=OpenSent event=17"), "{log}");
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn session_survives_simultaneous_connect() {
    let lab = Lab::new("x", 3);
    // Both sides active at once: RFC 4271 §6.8 must leave exactly one
    // session, whichever way the collision is resolved.
    let bird = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, false, &["192.0.2.0/24"]),
    );
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &bgpfcd_opts(&lab, false));
    assert_established(&lab, &bird, &bgpfcd);
    // Stay up for a while: no flapping.
    std::thread::sleep(Duration::from_secs(5));
    let status = bird.peer_status(&lab);
    assert!(status.contains("Established"), "{status}");
    let log = bgpfcd.log_text();
    assert_eq!(
        log.matches("session established").count(),
        1,
        "session flapped:\n{log}"
    );
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn bird_shutdown_sends_cease_and_bgpfcd_retries() {
    let lab = Lab::new("s", 4);
    let mut bird = Bird::start(&lab, &lab.b.clone(), &bird_opts(&lab, true, &[]));
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &bgpfcd_opts(&lab, false));
    assert_established(&lab, &bird, &bgpfcd);
    // `birdc down` makes BIRD send Cease / Administrative Shutdown.
    let _ = bird.birdc(&lab, &["down"]);
    let ok = wait_for(Duration::from_secs(10), || {
        let log = bgpfcd.log_text();
        log.contains("notification received")
            && log.contains("Cease/Administrative Shutdown")
            && log.contains("session down")
    });
    assert!(ok, "cease not seen:\n{}", bgpfcd.log_text());
    bird.daemon.kill();
    // bgpfcd keeps retrying on its own (IdleHoldTimer, then Connect).
    let ok = wait_for(Duration::from_secs(30), || {
        bgpfcd.log_text().contains("from=Idle to=Connect event=13")
    });
    assert!(ok, "no automatic restart:\n{}", bgpfcd.log_text());
}

/// BIRD B's statics go through bgpfcd to a second BIRD on A's loopback:
/// update generation, withdraw and route refresh (AGENTS.md §5, interop
/// row: "prefixes exchanged both ways, withdraw, route refresh").
#[test]
#[ignore = "needs root, bird and iproute2"]
fn routes_are_relayed_withdrawn_and_refreshed() {
    const BIRD2_AS: u32 = 65_002;
    let mut lab = Lab::new("r", 5);
    let ns_c = lab.add_c();
    let bird_b = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, true, &["192.0.2.0/24", "198.51.100.0/24"]),
    );
    // A second BIRD in namespace C, receiving only.
    let mut bird2 = Bird::start(
        &lab,
        &ns_c,
        &BirdOpts {
            local_as: BIRD2_AS,
            local: lab.c_addr,
            local_port: 179,
            neighbor: lab.a2_addr,
            neighbor_port: 179,
            remote_as: BGPFC_AS,
            hold_time: 30,
            passive: true,
            statics: Vec::new(),
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
                NeighborOpts::new(lab.b_addr, BIRD_AS),
                NeighborOpts::new(lab.c_addr, BIRD2_AS),
            ],
        },
    );
    assert_established(&lab, &bird_b, &bgpfcd);
    let ok = wait_for(ESTABLISH, || {
        bird2.peer_status(&lab).contains("Established")
    });
    assert!(
        ok,
        "bird2:\n{}\n{}",
        bird2.peer_status(&lab),
        bgpfcd.log_text()
    );

    // Both statics reach BIRD 2 with our AS prepended and our address as
    // next hop (RFC 4271 §5.1.2, §5.1.3).
    let ok = wait_for(Duration::from_secs(15), || {
        let routes = bird2.birdc(&lab, &["show", "route", "all"]);
        routes.contains("192.0.2.0/24") && routes.contains("198.51.100.0/24")
    });
    let routes = bird2.birdc(&lab, &["show", "route", "all"]);
    assert!(ok, "routes not relayed:\n{routes}\n{}", bgpfcd.log_text());
    assert!(routes.contains("BGP.as_path: 65000 65001"), "{routes}");
    assert!(
        routes.contains(&format!("BGP.next_hop: {}", lab.a2_addr)),
        "{routes}"
    );
    let log = bgpfcd.log_text();
    assert!(
        log.contains(&format!("prefix=192.0.2.0/24 next_hop={}", lab.b_addr)),
        "{log}"
    );

    // Withdraw: disabling BIRD B's static protocol withdraws both.
    let _ = bird_b.birdc(&lab, &["disable", "static1"]);
    let ok = wait_for(Duration::from_secs(15), || {
        !bird2
            .birdc(&lab, &["show", "route"])
            .contains("192.0.2.0/24")
    });
    assert!(ok, "withdraw not relayed:\n{}", bgpfcd.log_text());
    assert!(
        bgpfcd.log_text().contains("fib: delete"),
        "{}",
        bgpfcd.log_text()
    );

    // Route refresh: BIRD 2 asks for the Adj-RIB-Out again (RFC 2918).
    let _ = bird_b.birdc(&lab, &["enable", "static1"]);
    let ok = wait_for(Duration::from_secs(15), || {
        bird2
            .birdc(&lab, &["show", "route"])
            .contains("192.0.2.0/24")
    });
    assert!(ok, "re-announce not relayed:\n{}", bgpfcd.log_text());
    let _ = bird2.birdc(&lab, &["reload", "in", "peer"]);
    let ok = wait_for(Duration::from_secs(10), || {
        bgpfcd.log_text().contains("rib: route refresh")
    });
    assert!(ok, "no route refresh seen:\n{}", bgpfcd.log_text());
    let routes = bird2.birdc(&lab, &["show", "route"]);
    assert!(routes.contains("192.0.2.0/24"), "{routes}");
    bird2.daemon.kill();
}
