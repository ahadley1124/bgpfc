//! Enhanced Route Refresh (RFC 7313) between `bgpfcd` and BIRD 2.14
//! (AGENTS.md §5, `interop/` row): the capability is negotiated, and a route
//! refresh in either direction, in both families, is bracketed by a `BoRR`
//! and an `EoRR` that the other side takes, with every route still there at
//! its end. Where either side leaves the capability out, BIRD sends and
//! takes plain refreshes.
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird` and `birdc`
//! on `PATH`, and a built `bgpfcd`. CI runs them with `--include-ignored`
//! under sudo.
//!
//! bgpfcd is in AS 65000, the BIRD that is the party to the refreshes in
//! AS 65001 (B), and a second BIRD in AS 65002 (C) feeds bgpfcd a route
//! that it passes on to B, so that its answer to a request is not empty.

use std::path::Path;
use std::time::Duration;

use interop::{
    BgpfcdOpts, Bird, BirdOpts, Daemon, Lab, NeighborOpts, bgpfcctl, start_bgpfcd, wait_for,
};

const BGPFC_AS: u32 = 65_000;
const B_AS: u32 = 65_001;
const C_AS: u32 = 65_002;
const ESTABLISH: Duration = Duration::from_secs(40);
const SETTLE: Duration = Duration::from_secs(15);

/// What B originates, and what C does.
const B_ROUTES: [&str; 3] = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];
const C_ROUTE: &str = "100.64.0.0/10";

/// B's IPv6 channel over the IPv4 session, and its statics: the next hop is
/// configured, so the host's kernel need not have IPv6.
const BIRD_V6_CHANNEL: &str = "ipv6 { import all; export all; next hop address 2001:db8:9::2; };";
const BIRD_V6_STATICS: &str = "protocol static statics6 {\n    ipv6;\n\
    \x20   route 2001:db8:1::/48 blackhole;\n    route 2001:db8:2::/48 blackhole;\n}\n";

fn ctl(socket: &Path, args: &[&str]) -> String {
    bgpfcctl(socket, args).0
}

/// How many routes `show routes` lists for `family` (`ipv4` or `ipv6`), and
/// how many of those are stale.
fn listed(socket: &Path, family: &str) -> (usize, usize) {
    let out = ctl(socket, &["show", "routes", family]);
    let lines: Vec<&str> = out.lines().skip(1).collect();
    (
        lines.len(),
        lines.iter().filter(|l| l.ends_with(" stale")).count(),
    )
}

fn count(log: &str, needle: &str) -> usize {
    log.matches(needle).count()
}

/// A running lab.
struct Setup {
    lab: Lab,
    bird: Bird,
    _bird_c: Bird,
    bgpfcd: Daemon,
    socket: std::path::PathBuf,
}

impl Setup {
    /// bgpfcd with `neighbor` among the statements of B's block, and
    /// `bird` among those of BIRD's protocol towards bgpfcd.
    fn start(tag: &str, subnet: u8, neighbor: &str, bird: &str) -> Setup {
        let mut lab = Lab::new(tag, subnet);
        let ns_c = lab.add_c();
        let bird_b = Bird::start_with(
            &lab,
            &lab.b.clone(),
            &BirdOpts {
                local_as: B_AS,
                local: lab.b_addr,
                local_port: 179,
                neighbor: lab.a_addr,
                neighbor_port: 179,
                remote_as: BGPFC_AS,
                hold_time: 30,
                // bgpfcd connects; BIRD is there to be connected to.
                passive: true,
                statics: B_ROUTES.iter().map(|s| (*s).to_owned()).collect(),
                channel: String::new(),
                // What BIRD does with each ROUTE-REFRESH it gets and sends
                // shows in its log.
                protocol: format!("debug all; {BIRD_V6_CHANNEL} {bird}"),
            },
            BIRD_V6_STATICS,
        );
        let bird_c = Bird::start(
            &lab,
            &ns_c,
            &BirdOpts {
                local_as: C_AS,
                local: lab.c_addr,
                local_port: 179,
                neighbor: lab.a2_addr,
                neighbor_port: 179,
                remote_as: BGPFC_AS,
                hold_time: 30,
                passive: true,
                statics: vec![C_ROUTE.to_owned()],
                channel: String::new(),
                protocol: String::new(),
            },
        );
        let socket = lab.dir.join("ctl.sock");
        let neighbor_block = |addr, asn, extra: &str| NeighborOpts {
            // A short interval, so that a route that arrives behind another
            // is not held for the RFC 4271 §10 default of 30 s.
            advertisement_interval: Some(1),
            extra: format!("connect-retry-time 5; {extra}"),
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
                    neighbor_block(lab.b_addr, B_AS, neighbor),
                    neighbor_block(lab.c_addr, C_AS, ""),
                ],
                extra: format!("control {{ socket {}; }}", socket.display()),
            },
        );
        let s = Setup {
            lab,
            bird: bird_b,
            _bird_c: bird_c,
            bgpfcd,
            socket,
        };
        s.wait_up();
        s
    }

    /// Both sessions are up and B's three and two routes, and C's, are in
    /// bgpfcd's tables.
    fn wait_up(&self) {
        let ok = wait_for(ESTABLISH, || {
            self.bird.peer_status(&self.lab).contains("Established")
                && listed(&self.socket, "ipv4").0 == B_ROUTES.len() + 1
                && listed(&self.socket, "ipv6").0 == 2
        });
        assert!(
            ok,
            "no sessions.\n--- bird ---\n{}\n--- birdc ---\n{}\n--- bgpfcd ---\n{}",
            self.bird.daemon.log_text(),
            self.bird.peer_status(&self.lab),
            self.bgpfcd.log_text()
        );
    }

    fn bird_log(&self) -> String {
        self.bird.daemon.log_text()
    }

    /// How often BIRD (`bird`) or bgpfcd has logged `needle`.
    fn logged(&self, bird: bool, needle: &str) -> usize {
        let log = if bird {
            self.bird_log()
        } else {
            self.bgpfcd.log_text()
        };
        count(&log, needle)
    }

    fn neighbor(&self) -> String {
        ctl(
            &self.socket,
            &["show", "neighbor", &self.lab.b_addr.to_string()],
        )
    }

    /// Wait until `needle` has been logged `n` times more than `before` by
    /// BIRD (`bird`) or bgpfcd.
    fn wait_more(&self, bird: bool, needle: &str, before: usize, n: usize) {
        let log = || {
            if bird {
                self.bird_log()
            } else {
                self.bgpfcd.log_text()
            }
        };
        let ok = wait_for(SETTLE, || count(&log(), needle) >= before + n);
        assert!(
            ok,
            "{n} more of {needle:?} in the {} log expected.\n--- bird ---\n{}\n--- bgpfcd ---\n{}",
            if bird { "bird" } else { "bgpfcd" },
            self.bird_log(),
            self.bgpfcd.log_text()
        );
    }

    /// Nothing was lost: the session is up as it was, no route is stale,
    /// and the tables hold what they did.
    fn assert_intact(&self) {
        let status = self.bird.peer_status(&self.lab);
        assert!(status.contains("Established"), "{status}");
        assert_eq!(
            count(&self.bgpfcd.log_text(), "session established"),
            2,
            "a session flapped:\n{}",
            self.bgpfcd.log_text()
        );
        assert_eq!(listed(&self.socket, "ipv4"), (B_ROUTES.len() + 1, 0));
        assert_eq!(listed(&self.socket, "ipv6"), (2, 0));
        // BIRD kept what bgpfcd had sent it, C's route.
        let table = self.bird.birdc(&self.lab, &["show", "route"]);
        assert!(table.contains(C_ROUTE), "{table}");
    }
}

/// A refresh in either direction is a `BoRR`, the routes and an `EoRR`, for
/// each family, and neither side loses a route to it.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn bgpfcd_and_bird_bracket_route_refreshes_both_ways() {
    let s = Setup::start("er", 41, "", "");
    // RFC 7313 §3.1: both advertised capability 70.
    let status = s.bird.peer_status(&s.lab);
    assert_eq!(count(&status, "Enhanced refresh"), 2, "{status}");
    let detail = s.neighbor();
    assert!(detail.contains("enhanced-route-refresh=true"), "{detail}");
    // BIRD's End-of-RIB came for each of its two families (RFC 4724 §2); C
    // has the one.
    assert_eq!(
        s.bgpfcd
            .log_text()
            .lines()
            .filter(|l| l.contains("rib: end-of-rib") && l.contains(&s.lab.b_addr.to_string()))
            .count(),
        2
    );

    // BIRD asks for bgpfcd's routes (`reload in`): RFC 7313 §4, a BoRR, the
    // Adj-RIB-Out and an EoRR, in each family. BIRD takes them.
    let begins = s.logged(true, "Got BEGIN-OF-RR");
    let ends = s.logged(true, "Got END-OF-RR");
    let out = s.bird.birdc(&s.lab, &["reload", "in", "peer"]);
    assert!(out.contains("reloading"), "{out}");
    s.wait_more(true, "Got BEGIN-OF-RR", begins, 2);
    s.wait_more(true, "Got END-OF-RR", ends, 2);
    assert!(
        !s.bird_log().contains("unknown subtype"),
        "{}",
        s.bird_log()
    );
    s.assert_intact();

    // BIRD refreshes on its own (`reload out`): a BoRR and an EoRR around
    // its table. bgpfcd marks the family's routes stale at the BoRR, and
    // the routes it is sent replace them.
    let begun = s.logged(false, "rib: route refresh begins");
    let ended = s.logged(false, "rib: route refresh ends");
    let purged = s.logged(false, "why=end-of-refresh");
    let out = s.bird.birdc(&s.lab, &["reload", "out", "peer"]);
    assert!(out.contains("reloading"), "{out}");
    s.wait_more(false, "rib: route refresh begins", begun, 2);
    s.wait_more(false, "rib: route refresh ends", ended, 2);
    s.wait_more(false, "why=end-of-refresh", purged, 2);
    let log = s.bgpfcd.log_text();
    assert!(
        log.contains("family=ipv4-unicast stale_routes=3")
            && log.contains("family=ipv6-unicast stale_routes=2"),
        "{log}"
    );
    // Everything was sent again, so the EoRR removed nothing.
    assert_eq!(
        count(&log, "routes=0 why=end-of-refresh"),
        count(&log, "why=end-of-refresh"),
        "{log}"
    );
    s.assert_intact();

    // bgpfcd asks for BIRD's routes and sends its own again (`clear
    // neighbor ... soft`): the request is an ordinary one (§4), BIRD
    // answers with a BoRR, its routes and an EoRR, and takes ours in
    // brackets.
    let begun = s.logged(false, "rib: route refresh begins");
    let ended = s.logged(false, "rib: route refresh ends");
    let (bird_begins, bird_ends) = (
        s.logged(true, "Got BEGIN-OF-RR"),
        s.logged(true, "Got END-OF-RR"),
    );
    let requests = s.logged(true, "Got ROUTE-REFRESH");
    let out = ctl(
        &s.socket,
        &["clear", "neighbor", &s.lab.b_addr.to_string(), "soft"],
    );
    assert!(out.contains("soft reset"), "{out}");
    s.wait_more(true, "Got ROUTE-REFRESH", requests, 2);
    s.wait_more(false, "rib: route refresh begins", begun, 2);
    s.wait_more(false, "rib: route refresh ends", ended, 2);
    s.wait_more(true, "Got BEGIN-OF-RR", bird_begins, 2);
    s.wait_more(true, "Got END-OF-RR", bird_ends, 2);
    s.assert_intact();
    // And no NOTIFICATION anywhere.
    assert!(
        !s.bgpfcd.log_text().contains("notification"),
        "{}",
        s.bgpfcd.log_text()
    );
}

/// `enhanced-refresh no`: bgpfcd does not advertise the capability, so BIRD
/// has no use for the subtypes, sends its refreshes plain, and gets ours
/// plain.
#[test]
#[ignore = "needs root, bird and iproute2"]
fn without_the_capability_bird_sends_and_takes_plain_refreshes() {
    let s = Setup::start("en", 42, "enhanced-refresh no;", "");
    let status = s.bird.peer_status(&s.lab);
    // Only BIRD's own side of the list has it.
    assert_eq!(count(&status, "Enhanced refresh"), 1, "{status}");
    let detail = s.neighbor();
    assert!(detail.contains("enhanced-route-refresh=false"), "{detail}");
    let updates = s.logged(false, "rib: update");
    let out = s.bird.birdc(&s.lab, &["reload", "out", "peer"]);
    assert!(out.contains("reloading"), "{out}");
    s.wait_more(false, "rib: update", updates, 1);
    let out = s.bird.birdc(&s.lab, &["reload", "in", "peer"]);
    assert!(out.contains("reloading"), "{out}");
    s.wait_more(false, "rib: route refresh\" peer=", 0, 2);
    let out = ctl(
        &s.socket,
        &["clear", "neighbor", &s.lab.b_addr.to_string(), "soft"],
    );
    assert!(out.contains("soft reset"), "{out}");
    s.wait_more(true, "Got ROUTE-REFRESH", 0, 2);
    std::thread::sleep(Duration::from_secs(1));
    // RFC 7313 §4: BIRD applies the procedures to a peer it received the
    // capability from; this one sent none. No brackets either way.
    let log = s.bird_log();
    assert!(
        !log.contains("BEGIN-OF-RR") && !log.contains("END-OF-RR"),
        "{log}"
    );
    let log = s.bgpfcd.log_text();
    assert!(!log.contains("route refresh begins"), "{log}");
    assert_eq!(count(&log, "session established"), 2, "{log}");
    assert_eq!(listed(&s.socket, "ipv4"), (B_ROUTES.len() + 1, 0));
}

/// With Graceful Restart too: BIRD sends its End-of-RIB first, and a
/// refresh of its own after that is taken (RFC 7313 §4).
#[test]
#[ignore = "needs root, bird and iproute2"]
fn a_refresh_after_the_end_of_rib_of_a_graceful_restart_peer_is_taken() {
    let s = Setup::start("eg", 43, "graceful-restart yes;", "graceful restart on;");
    let status = s.bird.peer_status(&s.lab);
    assert_eq!(count(&status, "Enhanced refresh"), 2, "{status}");
    assert_eq!(count(&status, "Graceful restart"), 2, "{status}");
    let begun = s.logged(false, "rib: route refresh begins");
    let ended = s.logged(false, "rib: route refresh ends");
    let out = s.bird.birdc(&s.lab, &["reload", "out", "peer"]);
    assert!(out.contains("reloading"), "{out}");
    s.wait_more(false, "rib: route refresh ends", ended, 2);
    let log = s.bgpfcd.log_text();
    assert_eq!(count(&log, "rib: route refresh begins"), begun + 2, "{log}");
    assert!(!log.contains("route refresh message ignored"), "{log}");
    assert_eq!(listed(&s.socket, "ipv4"), (B_ROUTES.len() + 1, 0));
    assert_eq!(listed(&s.socket, "ipv6"), (2, 0));
}

/// FRR 8.4 advertises the capability by default. It sends its `BoRR` only
/// after it has sent its End-of-RIB (RFC 7313 §4), which it does to a peer
/// with Graceful Restart, so both sides have it on here. bgpfcd, with the
/// End-of-RIB in, takes the `BoRR`, the routes and the `EoRR` that answer its
/// request, and FRR takes the brackets bgpfcd puts around its table.
#[test]
#[ignore = "needs root, frr and iproute2"]
fn frr_answers_a_request_in_brackets_after_its_end_of_rib() {
    use interop::{Frr, OtherOpts};
    /// A four-octet AS (RFC 6793), beyond the two-octet range.
    const FRR_AS: u32 = 4_200_000_001;
    let lab = Lab::new("ef", 44);
    let socket = lab.dir.join("ctl.sock");
    let frr = Frr::start_with(
        &lab,
        &lab.b.clone(),
        &OtherOpts {
            local_as: FRR_AS,
            local: lab.b_addr,
            neighbor: lab.a_addr,
            remote_as: BGPFC_AS,
            networks: B_ROUTES.iter().map(|s| (*s).to_owned()).collect(),
        },
        " bgp graceful-restart\n",
        "",
    );
    let mut n = NeighborOpts::new(lab.b_addr, FRR_AS);
    n.extra = "connect-retry-time 5; graceful-restart yes;".to_owned();
    let mut o = BgpfcdOpts::single(BGPFC_AS, lab.a_addr, n);
    o.extra = format!("control {{ socket {}; }}\n", socket.display());
    let bgpfcd = start_bgpfcd(&lab, &lab.a.clone(), &o);
    let ok = wait_for(ESTABLISH, || {
        bgpfcd.log_text().contains("rib: end-of-rib") && listed(&socket, "ipv4").0 == 3
    });
    assert!(
        ok,
        "frr:\n{}\nbgpfcd:\n{}",
        frr.summary(&lab),
        bgpfcd.log_text()
    );
    // RFC 7313 §3.1: FRR and bgpfcd advertised capability 70.
    let neighbor = frr.vtysh(&lab, "show bgp neighbor");
    assert!(
        neighbor.contains("Enhanced Route Refresh: advertised and received"),
        "{neighbor}"
    );
    let detail = ctl(&socket, &["show", "neighbor", &lab.b_addr.to_string()]);
    assert!(detail.contains("enhanced-route-refresh=true"), "{detail}");

    // bgpfcd asks FRR for its routes (`clear neighbor ... soft`): FRR
    // answers with a BoRR, its routes and an EoRR, all of which replace what
    // bgpfcd had.
    let log = |needle: &str| count(&bgpfcd.log_text(), needle);
    let (begun, ended) = (
        log("rib: route refresh begins"),
        log("rib: route refresh ends"),
    );
    let out = ctl(
        &socket,
        &["clear", "neighbor", &lab.b_addr.to_string(), "soft"],
    );
    assert!(out.contains("soft reset"), "{out}");
    let ok = wait_for(SETTLE, || {
        log("rib: route refresh begins") > begun && log("rib: route refresh ends") > ended
    });
    assert!(ok, "no brackets from FRR:\n{}", bgpfcd.log_text());
    let text = bgpfcd.log_text();
    assert!(
        text.contains("family=ipv4-unicast stale_routes=3")
            && text.contains("routes=0 why=end-of-refresh"),
        "{text}"
    );
    assert!(!text.contains("route refresh message ignored"), "{text}");
    assert_eq!(listed(&socket, "ipv4"), (3, 0));
    // FRR took the brackets bgpfcd put around its (empty) table: the
    // session is still up and no route went.
    let neighbor = frr.vtysh(&lab, "show bgp neighbor");
    assert!(neighbor.contains("BGP state = Established"), "{neighbor}");
    assert!(
        neighbor.contains("Notifications:          0          0"),
        "{neighbor}"
    );
}
