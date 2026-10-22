//! Sessions between `bgpfcd` and FRR `bgpd` (AGENTS.md §5, `interop/`
//! row): session up, prefixes both ways, withdraw, route refresh, and a
//! four-octet AS. Every test is `#[ignore]`: needs root, `iproute2`, FRR
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
