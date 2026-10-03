//! Sessions between `bgpfcd` and `GoBGP` (AGENTS.md §5, `interop/` row):
//! session up, prefixes both ways, withdraw, route refresh. Every test is
//! `#[ignore]`: needs root, `iproute2`, `gobgpd` and BIRD.

use std::time::Duration;

use interop::{
    BgpfcdOpts, Bird, BirdOpts, GoBgp, Lab, NeighborOpts, OtherOpts, start_bgpfcd, wait_for,
};

const BGPFC_AS: u32 = 65_000;
const GOBGP_AS: u32 = 65_003;
const BIRD_AS: u32 = 65_002;
const ESTABLISH: Duration = Duration::from_secs(40);

#[test]
#[ignore = "needs root, gobgpd, bird and iproute2"]
fn gobgp_session_prefixes_both_ways_withdraw_and_refresh() {
    let mut lab = Lab::new("g", 12);
    let ns_c = lab.add_c();
    let gobgp = GoBgp::start(
        &lab,
        &lab.b.clone(),
        &OtherOpts {
            local_as: GOBGP_AS,
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
        },
    );
    let socket = lab.dir.join("ctl.sock");
    let bgpfcd = start_bgpfcd(
        &lab,
        &lab.a.clone(),
        &BgpfcdOpts {
            local_as: BGPFC_AS,
            router_id: lab.a_addr,
            listen: vec![lab.a_addr.into(), lab.a2_addr.into()],
            neighbors: vec![
                NeighborOpts::new(lab.b_addr, GOBGP_AS),
                NeighborOpts::new(lab.c_addr, BIRD_AS),
            ],
            extra: format!("control {{ socket {}; }}", socket.display()),
        },
    );
    let ok = wait_for(ESTABLISH, || {
        gobgp.neighbors(&lab).contains("Establ")
            && bgpfcd.log_text().matches("session established").count() == 2
    });
    assert!(
        ok,
        "gobgp:\n{}\nbgpfcd:\n{}",
        gobgp.neighbors(&lab),
        bgpfcd.log_text()
    );

    let ok = wait_for(Duration::from_secs(15), || {
        bird.birdc(&lab, &["show", "route", "all"])
            .contains("192.0.2.0/24")
            && gobgp
                .gobgp(&lab, &["global", "rib"])
                .contains("203.0.113.0/24")
    });
    let routes = bird.birdc(&lab, &["show", "route", "all"]);
    assert!(
        ok,
        "bird:\n{routes}\ngobgp:\n{}\n{}",
        gobgp.gobgp(&lab, &["global", "rib"]),
        bgpfcd.log_text()
    );
    assert!(routes.contains("BGP.as_path: 65000 65003"), "{routes}");
    let g = gobgp.gobgp(&lab, &["global", "rib"]);
    assert!(g.contains("65000 65002"), "{g}");

    // Withdraw on GoBGP: gone from BIRD.
    let _ = gobgp.gobgp(&lab, &["global", "rib", "del", "192.0.2.0/24"]);
    let ok = wait_for(Duration::from_secs(15), || {
        !bird
            .birdc(&lab, &["show", "route"])
            .contains("192.0.2.0/24")
    });
    assert!(ok, "withdraw not relayed:\n{}", bgpfcd.log_text());

    check_soft_clear(&lab, &gobgp, &bird, &bgpfcd, &socket);
}

/// `GoBGP`'s `softresetin` re-applies policy from its own Adj-RIB-In and sends
/// nothing, so the refresh is tested the other way round: a soft clear on
/// `bgpfcd` sends ROUTE-REFRESH (RFC 2918 §4), `GoBGP` counts it and answers
/// with its routes again.
fn check_soft_clear(
    lab: &Lab,
    gobgp: &GoBgp,
    bird: &Bird,
    bgpfcd: &interop::Daemon,
    socket: &std::path::Path,
) {
    // Give GoBGP something to re-send first.
    let _ = gobgp.gobgp(lab, &["global", "rib", "add", "192.0.2.0/24"]);
    let ok = wait_for(Duration::from_secs(15), || {
        bird.birdc(lab, &["show", "route"]).contains("192.0.2.0/24")
    });
    assert!(ok, "re-add not relayed:\n{}", bgpfcd.log_text());
    let before = bgpfcd.log_text().matches("rib: update").count();
    let (out, ok) = interop::bgpfcctl(
        socket,
        &["clear", "neighbor", &lab.b_addr.to_string(), "soft"],
    );
    assert!(ok, "{out}");
    let ok = wait_for(Duration::from_secs(10), || {
        let n = gobgp.gobgp(lab, &["neighbor", &lab.a_addr.to_string()]);
        let refreshed = n
            .lines()
            .find(|l| l.trim_start().starts_with("Route Refresh:"))
            .and_then(|l| l.split_whitespace().nth(3))
            .is_some_and(|rcvd| rcvd != "0");
        refreshed && bgpfcd.log_text().matches("rib: update").count() > before
    });
    assert!(
        ok,
        "refresh not seen:\n{}\n{}",
        gobgp.gobgp(lab, &["neighbor", &lab.a_addr.to_string()]),
        bgpfcd.log_text()
    );
}
