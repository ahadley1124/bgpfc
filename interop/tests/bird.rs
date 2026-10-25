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
        channel: String::new(),
        protocol: String::new(),
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
            channel: String::new(),
            protocol: String::new(),
        },
    );
    // The scenario re-announces the statics seconds after the first
    // advertisement; with the 30 s EBGP default of RFC 4271 §10 that
    // re-announcement would be held past the 15 s wait (§9.2.1.1). An
    // explicit 1 s interval keeps the test quick and still paced; the
    // default itself is unchanged.
    let mut to_bird2 = NeighborOpts::new(lab.c_addr, BIRD2_AS);
    to_bird2.advertisement_interval = Some(1);
    let bgpfcd = start_bgpfcd(
        &lab,
        &lab.a.clone(),
        &BgpfcdOpts {
            local_as: BGPFC_AS,
            router_id: lab.a_addr,
            listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
            neighbors: vec![NeighborOpts::new(lab.b_addr, BIRD_AS), to_bird2],
            extra: String::new(),
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
        log.contains(&format!("prefix=192.0.2.0/24 gateway={}", lab.b_addr)),
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
        bgpfcd.log_text().contains("op=delete"),
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

/// Import and export policies shape what BIRD 2 receives: one static is
/// rejected on import by prefix list, the other gets a prepended AS path
/// and a community on export.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn export_policy_filters_and_sets() {
    const BIRD2_AS: u32 = 65_002;
    let mut lab = Lab::new("f", 6);
    let ns_c = lab.add_c();
    let bird_b = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, true, &["192.0.2.0/24", "198.51.100.0/24"]),
    );
    let bird2 = Bird::start(
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
            channel: String::new(),
            protocol: String::new(),
        },
    );
    let mut to_bird2 = NeighborOpts::new(lab.c_addr, BIRD2_AS);
    to_bird2.export = "OUT".to_owned();
    let mut from_bird_b = NeighborOpts::new(lab.b_addr, BIRD_AS);
    from_bird_b.import = "IN".to_owned();
    let bgpfcd = start_bgpfcd(
        &lab,
        &lab.a.clone(),
        &BgpfcdOpts {
            local_as: BGPFC_AS,
            router_id: lab.a_addr,
            listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
            neighbors: vec![from_bird_b, to_bird2],
            extra: "prefix-list DROP { 198.51.100.0/24; }
                    policy IN {
                        term drop { match prefix-list DROP; action reject; }
                        term rest { match as-path \"^65001$\"; set local-pref 150; action accept; }
                    }
                    policy OUT {
                        term tag { set community add 65000:42; set as-path prepend 65000; action accept; }
                    }"
            .to_owned(),
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
    let ok = wait_for(Duration::from_secs(15), || {
        bird2
            .birdc(&lab, &["show", "route", "all"])
            .contains("192.0.2.0/24")
    });
    let routes = bird2.birdc(&lab, &["show", "route", "all"]);
    assert!(ok, "route not relayed:\n{routes}\n{}", bgpfcd.log_text());
    // Rejected on import: never reaches BIRD 2, nor the FIB.
    assert!(!routes.contains("198.51.100.0/24"), "{routes}");
    assert!(
        !bgpfcd.log_text().contains("prefix=198.51.100.0/24 gateway"),
        "{}",
        bgpfcd.log_text()
    );
    // Export set actions, then our AS prepended by the session rules.
    assert!(
        routes.contains("BGP.as_path: 65000 65000 65001"),
        "{routes}"
    );
    assert!(routes.contains("(65000,42)"), "{routes}");
}

/// Install mode: relayed routes land in the kernel table of bgpfcd's
/// namespace with our protocol number, leave with the withdraw, and are
/// all removed on SIGTERM, which also sends BIRD a Cease.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn fib_install_and_clean_shutdown() {
    let lab = Lab::new("k", 7);
    let bird = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, true, &["192.0.2.0/24", "198.51.100.0/24"]),
    );
    let mut opts = bgpfcd_opts(&lab, false);
    opts.extra = "fib { mode install; }".to_owned();
    let mut bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &opts);
    assert_established(&lab, &bird, &bgpfcd);
    let ns_a = lab.a.clone();
    let routes = |lab: &Lab| interop::Daemon::ip_in(lab, &ns_a, &["route", "show", "proto", "186"]);
    let ok = wait_for(Duration::from_secs(15), || {
        let r = routes(&lab);
        r.contains("192.0.2.0/24") && r.contains("198.51.100.0/24")
    });
    let r = routes(&lab);
    assert!(ok, "routes not installed:\n{r}\n{}", bgpfcd.log_text());
    assert!(r.contains(&format!("via {}", lab.b_addr)), "{r}");
    assert!(r.contains("metric 20"), "{r}");
    assert!(
        bgpfcd.log_text().contains("fib: applied"),
        "{}",
        bgpfcd.log_text()
    );

    // Withdraw one: only the other stays.
    let _ = bird.birdc(&lab, &["disable", "static1"]);
    let ok = wait_for(Duration::from_secs(15), || {
        !routes(&lab).contains("192.0.2.0/24")
    });
    assert!(
        ok,
        "route not removed:\n{}\n{}",
        routes(&lab),
        bgpfcd.log_text()
    );
    let _ = bird.birdc(&lab, &["enable", "static1"]);
    let ok = wait_for(Duration::from_secs(15), || {
        routes(&lab).contains("192.0.2.0/24")
    });
    assert!(ok, "route not reinstalled:\n{}", bgpfcd.log_text());

    // SIGTERM: Cease to BIRD, routes gone, process exits.
    assert!(
        bgpfcd.terminate(Duration::from_secs(10)),
        "did not exit:\n{}",
        bgpfcd.log_text()
    );
    let r = routes(&lab);
    assert!(
        r.trim().is_empty(),
        "routes left behind:\n{r}\n{}",
        bgpfcd.log_text()
    );
    let ok = wait_for(Duration::from_secs(10), || {
        let s = bird.peer_status(&lab);
        s.contains("Received: Cease") || !s.contains("Established")
    });
    assert!(ok, "bird still up:\n{}", bird.peer_status(&lab));
    assert!(
        bird.daemon
            .log_text()
            .contains("Received: Administrative shutdown"),
        "{}",
        bird.daemon.log_text()
    );
}

/// The control plane end to end: bgpfcctl over the Unix socket, the HTTP
/// API with curl inside the namespace, a soft reset that makes BIRD send
/// its routes again, a FIB mode switch, and a reload that changes an
/// import policy.
#[test]
#[ignore = "needs root, bird, curl and iproute2"]
fn control_plane_commands() {
    use std::fs;
    let lab = Lab::new("m", 8);
    let bird = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, true, &["192.0.2.0/24", "198.51.100.0/24"]),
    );
    let socket = lab.dir.join("ctl.sock");
    let token_file = lab.dir.join("token");
    fs::write(&token_file, "s3cret\n").unwrap();
    let mut opts = bgpfcd_opts(&lab, false);
    opts.extra = format!(
        "control {{ socket {}; http {{ listen 127.0.0.1:8179; writes yes; token-file {}; }} }}",
        socket.display(),
        token_file.display()
    );
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &opts);
    assert_established(&lab, &bird, &bgpfcd);
    let ctl = |args: &[&str]| interop::bgpfcctl(&socket, args);

    let (out, ok) = ctl(&["show", "neighbors"]);
    assert!(ok && out.contains("Established"), "{out}");
    let (out, ok) = ctl(&["show", "neighbor", &lab.b_addr.to_string()]);
    assert!(ok && out.contains("route-refresh=true"), "{out}");
    let ok = wait_for(Duration::from_secs(10), || {
        ctl(&["show", "routes"]).0.contains("192.0.2.0/24")
    });
    assert!(ok, "{}", ctl(&["show", "routes"]).0);
    let (out, ok) = ctl(&["show", "routes", "192.0.2.0/24"]);
    assert!(
        ok && out.contains("*192.0.2.0/24") && out.contains("65001"),
        "{out}"
    );
    // No validation source: the route is not validated (issue #52).
    assert!(out.contains(" disabled "), "{out}");
    let (out, ok) = ctl(&["show", "fib"]);
    assert!(ok && out.starts_with("mode dry-run"), "{out}");
    let (out, ok) = ctl(&["show", "status"]);
    assert!(ok && out.contains("established 1"), "{out}");
    let (out, ok) = ctl(&["bogus"]);
    assert!(!ok && out.contains("unknown command"), "{out}");

    // HTTP, from inside the namespace.
    let curl = |args: &[&str]| {
        let mut cmd = lab.exec(&lab.a, "curl");
        cmd.args(["-s", "-i", "--max-time", "5"]).args(args);
        let out = cmd.output().expect("curl");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let r = curl(&["http://127.0.0.1:8179/v1/status"]);
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    let auth = "Authorization: Bearer s3cret";
    let r = curl(&["-H", auth, "http://127.0.0.1:8179/v1/status"]);
    assert!(
        r.starts_with("HTTP/1.1 200") && r.contains("\"established\":1"),
        "{r}"
    );
    let r = curl(&["-H", auth, "http://127.0.0.1:8179/v1/neighbors"]);
    assert!(r.contains("\"state\":\"Established\""), "{r}");
    let r = curl(&["-H", auth, "http://127.0.0.1:8179/v1/routes?family=ipv4"]);
    assert!(
        r.contains("\"prefix\":\"192.0.2.0/24\"")
            && r.contains("\"as_path\":[65001]")
            && r.contains("\"rov\":\"disabled\""),
        "{r}"
    );
    let r = curl(&["-H", auth, "http://127.0.0.1:8179/v1/nope"]);
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");

    // Soft reset: a ROUTE-REFRESH goes to BIRD, which answers with its
    // routes again.
    let before = bgpfcd.log_text().matches("rib: update").count();
    let (out, ok) = ctl(&["clear", "neighbor", &lab.b_addr.to_string(), "soft"]);
    assert!(ok, "{out}");
    let ok = wait_for(Duration::from_secs(10), || {
        let log = bgpfcd.log_text();
        log.contains("route refresh sent") && log.matches("rib: update").count() > before
    });
    assert!(ok, "no refresh:\n{}", bgpfcd.log_text());

    // FIB mode switch over HTTP: routes get installed.
    let r = curl(&[
        "-X",
        "POST",
        "-H",
        auth,
        "http://127.0.0.1:8179/v1/fib/mode/install",
    ]);
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let ns_a = lab.a.clone();
    let ok = wait_for(Duration::from_secs(10), || {
        interop::Daemon::ip_in(&lab, &ns_a, &["route", "show", "proto", "186"])
            .contains("192.0.2.0/24")
    });
    assert!(ok, "{}", bgpfcd.log_text());
    let (out, ok) = ctl(&["show", "fib"]);
    assert!(ok && out.contains("installed"), "{out}");
}

/// Reload with a policy change, refusal of a broken file, and a hard
/// reset carrying a shutdown communication.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn control_plane_reload_and_reset() {
    use std::fs;
    let lab = Lab::new("n", 9);
    let bird = Bird::start(
        &lab,
        &lab.b.clone(),
        &bird_opts(&lab, true, &["192.0.2.0/24", "198.51.100.0/24"]),
    );
    let socket = lab.dir.join("ctl.sock");
    let mut opts = bgpfcd_opts(&lab, false);
    opts.extra = format!(
        "control {{ socket {}; }} fib {{ mode install; }}",
        socket.display()
    );
    // The hard reset below reconnects at once (RFC 4271 §8.2.2 Idle,
    // ManualStart), often before the passive BIRD has finished closing the
    // old session; BIRD then resets the new connection, and bgpfcd waits
    // ConnectRetryTime in Active before it tries again. Keep that wait
    // well inside the test's, as `extended_next_hop_with_bird` does.
    opts.neighbors[0].extra = "connect-retry-time 5;".to_owned();
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &opts);
    assert_established(&lab, &bird, &bgpfcd);
    let ctl = |args: &[&str]| interop::bgpfcctl(&socket, args);
    let ns_a = lab.a.clone();
    let ok = wait_for(Duration::from_secs(10), || {
        interop::Daemon::ip_in(&lab, &ns_a, &["route", "show", "proto", "186"])
            .contains("198.51.100.0/24")
    });
    assert!(ok, "{}", bgpfcd.log_text());

    // Reload with an import policy that drops one prefix: it leaves the
    // RIB and the kernel without a session reset.
    let cfg_path = lab.dir.join(format!("bgpfcd-{}.conf", lab.a));
    let cfg = fs::read_to_string(&cfg_path).unwrap();
    let cfg = cfg.replace(
        "policy ANY { term all { action accept; } }",
        "policy ANY { term drop { match prefix 198.51.100.0/24; action reject; } term all { action accept; } }",
    );
    fs::write(&cfg_path, cfg).unwrap();
    let (out, ok) = ctl(&["reload"]);
    assert!(ok && out.contains("policy 1"), "{out}");
    let ok = wait_for(Duration::from_secs(10), || {
        !ctl(&["show", "routes"]).0.contains("198.51.100.0/24")
            && !interop::Daemon::ip_in(&lab, &ns_a, &["route", "show", "proto", "186"])
                .contains("198.51.100.0/24")
    });
    assert!(ok, "{}\n{}", ctl(&["show", "routes"]).0, bgpfcd.log_text());
    assert_eq!(bgpfcd.log_text().matches("session established").count(), 1);
    // A broken file is refused and the running configuration kept.
    fs::write(&cfg_path, "router-id 192.0.2.1;").unwrap();
    let (out, ok) = ctl(&["reload"]);
    assert!(!ok && out.contains("local-as"), "{out}");
    let (out, ok) = ctl(&["show", "status"]);
    assert!(ok && out.contains("established 1"), "{out}");

    // Hard reset with a shutdown communication reaches BIRD.
    let (out, ok) = ctl(&["clear", "neighbor", &lab.b_addr.to_string(), "maintenance"]);
    assert!(ok, "{out}");
    let ok = wait_for(Duration::from_secs(10), || {
        bird.daemon.log_text().contains("maintenance")
    });
    assert!(ok, "no communication seen:\n{}", bird.daemon.log_text());
    let ok = wait_for(ESTABLISH, || {
        bgpfcd.log_text().matches("session established").count() >= 2
    });
    assert!(ok, "no reconnect:\n{}", bgpfcd.log_text());
}

/// RFC 8950 with BIRD on both sides of bgpfcd, over IPv4 sessions. The
/// test hosts may run without IPv6 (one boots with `ipv6.disable=1`), so
/// the IPv6 next hop is BIRD's configured `next hop address`, not a session
/// address. BIRD in B (external) originates 192.0.2.0/24 with the IPv6 next
/// hop; bgpfcd passes it unchanged to BIRD in C (internal, §5), and sends
/// C's 203.0.113.0/24 to B with its own IPv4 address on that session (§5).
/// A reload then turns the capability off towards C: the session resets
/// and C no longer gets the route (§4).
#[test]
#[ignore = "needs root, bird and iproute2"]
fn extended_next_hop_with_bird() {
    let mut lab = Lab::new("e", 13);
    let (bird_b, bird_c, bgpfcd, socket) = start_extended_next_hop_lab(&mut lab);
    let ctl = |args: &[&str]| interop::bgpfcctl(&socket, args);
    let ok = wait_for(ESTABLISH, || {
        bgpfcd.log_text().matches("session established").count() == 2
    });
    assert!(ok, "{}", bgpfcd.log_text());
    // RFC 8950 §4: both sides list <1, 1, 2> on both sessions, so IPv6
    // next hops may go either way.
    let ok = wait_for(Duration::from_secs(5), || {
        bgpfcd
            .log_text()
            .matches("extended_next_hop_send=ipv4-unicast")
            .count()
            == 2
    });
    assert!(ok, "{}", bgpfcd.log_text());
    for addr in [lab.b_addr, lab.c_addr] {
        let (out, ok) = ctl(&["show", "neighbor", &addr.to_string()]);
        assert!(
            ok && out.contains("extended-next-hop receive ipv4-unicast send ipv4-unicast"),
            "{out}"
        );
    }
    let status = bird_b.peer_status(&lab);
    assert!(status.contains("IPv6 nexthop: ipv4"), "{status}");

    // RFC 8950 §3: BIRD's IPv6 next hop is decoded and kept in the RIB,
    // and the FIB (dry-run here) is asked for an IPv4 route via it.
    let ok = wait_for(Duration::from_secs(15), || {
        ctl(&["show", "routes", "192.0.2.0/24"])
            .0
            .contains("2001:db8::1")
    });
    assert!(ok, "{}\n{}", ctl(&["show", "routes"]).0, bgpfcd.log_text());
    let (out, ok) = ctl(&["show", "fib"]);
    assert!(ok && out.contains("2001:db8::1"), "{out}");

    // §5: passed on unchanged to the internal peer, encoding included.
    let route_c = || bird_c.birdc(&lab, &["show", "route", "all", "192.0.2.0/24"]);
    let ok = wait_for(Duration::from_secs(15), || {
        route_c().contains("BGP.next_hop: 2001:db8::1")
    });
    assert!(ok, "{}\n{}", route_c(), bgpfcd.log_text());
    assert!(route_c().contains("BGP.as_path: 65001"), "{}", route_c());

    // §5: our own next hop towards B is of the session's protocol, IPv4.
    // The 30 s RFC 4271 §10 interval may hold it behind C's first route.
    let route_b = || bird_b.birdc(&lab, &["show", "route", "all", "203.0.113.0/24"]);
    let ok = wait_for(Duration::from_secs(40), || {
        route_b().contains(&format!("BGP.next_hop: {}", lab.a_addr))
    });
    assert!(ok, "{}\n{}", route_b(), bgpfcd.log_text());

    assert_extended_next_hop_off_towards_c(&lab, &bird_c, &bgpfcd, &socket);
}

/// B, C and bgpfcd for `extended_next_hop_with_bird`, all three with
/// RFC 8950 on, and bgpfcd's control socket.
fn start_extended_next_hop_lab(lab: &mut Lab) -> (Bird, Bird, interop::Daemon, std::path::PathBuf) {
    let ns_c = lab.add_c();
    let bird_b = Bird::start(
        lab,
        &lab.b.clone(),
        &BirdOpts {
            channel: "extended next hop on; next hop address 2001:db8::1;".to_owned(),
            protocol: String::new(),
            ..bird_opts(lab, true, &["192.0.2.0/24"])
        },
    );
    let bird_c = Bird::start(
        lab,
        &ns_c,
        &BirdOpts {
            local_as: BGPFC_AS,
            local: lab.c_addr,
            local_port: 179,
            neighbor: lab.a2_addr,
            neighbor_port: 179,
            remote_as: BGPFC_AS,
            hold_time: 30,
            passive: true,
            statics: vec!["203.0.113.0/24".to_owned()],
            channel: "extended next hop on;".to_owned(),
            protocol: String::new(),
        },
    );
    let socket = lab.dir.join("ctl.sock");
    let to_b = NeighborOpts {
        extra: "extended-next-hop yes;".to_owned(),
        ..NeighborOpts::new(lab.b_addr, BIRD_AS)
    };
    // A short ConnectRetryTime, so that the reset in the test reconnects
    // quickly even if BIRD refuses the first attempt.
    let to_c = NeighborOpts {
        extra: "connect-retry-time 5; extended-next-hop yes;".to_owned(),
        ..NeighborOpts::new(lab.c_addr, BGPFC_AS)
    };
    let bgpfcd = start_bgpfcd(
        lab,
        &lab.a.clone(),
        &BgpfcdOpts {
            local_as: BGPFC_AS,
            router_id: lab.a_addr,
            listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
            neighbors: vec![to_b, to_c],
            extra: format!("control {{ socket {}; }}", socket.display()),
        },
    );
    (bird_b, bird_c, bgpfcd, socket)
}

/// Reload bgpfcd with `extended-next-hop` off towards C: the session resets
/// (the OPEN changes), comes back without the capability, and C loses the
/// route with the IPv6 next hop while bgpfcd keeps it (RFC 8950 §4, §5).
fn assert_extended_next_hop_off_towards_c(
    lab: &Lab,
    bird_c: &Bird,
    bgpfcd: &interop::Daemon,
    socket: &std::path::Path,
) {
    use std::fs;
    let ctl = |args: &[&str]| interop::bgpfcctl(socket, args);
    let cfg_path = lab.dir.join(format!("bgpfcd-{}.conf", lab.a));
    let cfg = fs::read_to_string(&cfg_path).unwrap().replace(
        "connect-retry-time 5; extended-next-hop yes;",
        "connect-retry-time 5;",
    );
    fs::write(&cfg_path, cfg).unwrap();
    let (out, ok) = ctl(&["reload"]);
    assert!(ok && out.contains("reset 1"), "{out}");
    let ok = wait_for(ESTABLISH, || {
        bgpfcd.log_text().matches("session established").count() >= 3
    });
    assert!(ok, "no reconnect:\n{}", bgpfcd.log_text());
    let c = lab.c_addr.to_string();
    let ok = wait_for(Duration::from_secs(15), || {
        let (out, _) = ctl(&["show", "neighbor", &c]);
        out.contains("Established") && out.contains("routes received 1 advertised 0")
    });
    let (out, _) = ctl(&["show", "neighbor", &c]);
    assert!(ok, "{out}\n{}", bgpfcd.log_text());
    assert!(!out.contains("extended-next-hop"), "{out}");
    let route_c = || bird_c.birdc(lab, &["show", "route", "all", "192.0.2.0/24"]);
    let ok = wait_for(Duration::from_secs(10), || {
        !route_c().contains("192.0.2.0/24")
    });
    assert!(ok, "{}\n{}", route_c(), bgpfcd.log_text());
    let (out, _) = ctl(&["show", "routes", "192.0.2.0/24"]);
    assert!(out.contains("2001:db8::1"), "{out}");
}

/// RFC 4271 §6.7 and RFC 4486 §4 against BIRD: BIRD sends three routes to
/// a neighbor whose `maximum-prefix` is two. bgpfcd ends the session with
/// Cease / Maximum Number of Prefixes Reached carrying AFI 1, SAFI 1 and
/// the limit, keeps none of BIRD's routes, retries once (`restart-limit
/// 1`) and then stays Idle. A reload raising the limit applies without a
/// reset, and `bgpfcctl clear neighbor` is the manual start that brings
/// the session back for good.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn prefix_limit_and_restart_limit_with_bird() {
    use std::fs;
    let lab = Lab::new("l", 14);
    let mut b = bird_opts(
        &lab,
        true,
        &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
    );
    // BIRD refuses connections for its `error wait time` (60 s at first)
    // after a session ends in an error; keep its retries quick.
    b.protocol = "error wait time 1, 2;".to_owned();
    let bird = Bird::start(&lab, &lab.b.clone(), &b);
    let socket = lab.dir.join("ctl.sock");
    let mut opts = bgpfcd_opts(&lab, false);
    opts.neighbors[0].extra =
        "connect-retry-time 5; maximum-prefix ipv4-unicast 2; restart-limit 1;".to_owned();
    opts.extra = format!("control {{ socket {}; }}", socket.display());
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &opts);
    let ctl = |args: &[&str]| interop::bgpfcctl(&socket, args);
    let b_addr = lab.b_addr.to_string();

    // Over the limit: the Cease, logged on both sides.
    let ok = wait_for(ESTABLISH, || {
        bgpfcd.log_text().contains("maximum prefixes reached")
    });
    assert!(ok, "no prefix limit:\n{}", bgpfcd.log_text());
    let log = bgpfcd.log_text();
    assert!(log.contains("family=ipv4-unicast limit=2"), "{log}");
    assert!(
        log.contains("Cease/Maximum Number of Prefixes Reached"),
        "{log}"
    );
    // RFC 4486 §4 Figure 1 as BIRD logs the data: AFI, SAFI, upper bound.
    let ok = wait_for(Duration::from_secs(10), || {
        bird.daemon
            .log_text()
            .contains("Received: Maximum number of prefixes reached: 00010100000002")
    });
    assert!(ok, "bird log:\n{}", bird.daemon.log_text());

    // RFC 4486 §4: one automatic retry, which fails the same way, then no
    // more until the operator acts.
    let ok = wait_for(Duration::from_secs(60), || {
        bgpfcd.log_text().contains("restart limit reached")
    });
    assert!(ok, "no restart limit:\n{}", bgpfcd.log_text());
    let log = bgpfcd.log_text();
    assert_eq!(log.matches("maximum prefixes reached").count(), 2, "{log}");
    assert!(log.contains("damped_failures=2 restart_limit=1"), "{log}");
    let (out, ok) = ctl(&["show", "neighbor", &b_addr]);
    assert!(ok && out.contains("state Idle"), "{out}");
    assert!(out.contains("restart limit reached"), "{out}");
    let (out, _) = ctl(&["show", "routes"]);
    assert!(!out.contains("192.0.2.0/24"), "{out}");
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(
        bgpfcd.log_text().matches("session established").count(),
        2,
        "{}",
        bgpfcd.log_text()
    );

    // A higher limit applies without a reset; the clear starts the peer.
    let cfg_path = lab.dir.join(format!("bgpfcd-{}.conf", lab.a));
    let cfg = fs::read_to_string(&cfg_path).unwrap().replace(
        "maximum-prefix ipv4-unicast 2;",
        "maximum-prefix ipv4-unicast 10;",
    );
    fs::write(&cfg_path, cfg).unwrap();
    let (out, ok) = ctl(&["reload"]);
    assert!(
        ok && out.contains("reset 0") && out.contains("limit 1"),
        "{out}"
    );
    let (out, ok) = ctl(&["clear", "neighbor", &b_addr]);
    assert!(ok, "{out}");
    let ok = wait_for(ESTABLISH, || {
        let (out, _) = ctl(&["show", "neighbor", &b_addr]);
        out.contains("ipv4-unicast received 3 advertised 0 maximum-prefix 10")
    });
    let (out, _) = ctl(&["show", "neighbor", &b_addr]);
    assert!(ok, "{out}\n{}", bgpfcd.log_text());
    assert!(!out.contains("restart limit reached"), "{out}");
    let (out, _) = ctl(&["show", "routes"]);
    assert!(out.contains("203.0.113.0/24"), "{out}");
}
