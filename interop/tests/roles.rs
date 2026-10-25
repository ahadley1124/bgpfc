//! BGP Roles and Only to Customer (RFC 9234) between `bgpfcd` and BIRD 2.14,
//! whose `local role` and `require roles` implement the same RFC
//! (AGENTS.md §5, `interop/` row).
//!
//! Every test is `#[ignore]`: it needs root, `iproute2`, `bird` and `birdc`
//! on `PATH`, and a built `bgpfcd`. CI runs them with `--include-ignored`
//! under sudo.
//!
//! bgpfcd is in AS 65000, BIRD in B in AS 65001 and, where there is one,
//! BIRD in C in AS 65002. The `role` of a side is the Role bgpfcd has on
//! the session to it; BIRD's `local role` is the one BIRD has.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use interop::{BgpfcdOpts, Bird, BirdOpts, Daemon, Lab, NeighborOpts, start_bgpfcd, wait_for};

const BGPFC_AS: u32 = 65_000;
const B_AS: u32 = 65_001;
const C_AS: u32 = 65_002;
const ESTABLISH: Duration = Duration::from_secs(40);

/// One BIRD and the session bgpfcd has to it.
#[derive(Clone, Default)]
struct Side {
    /// bgpfcd's statements for the neighbor, such as `role customer;`.
    ours: &'static str,
    /// BIRD's statements for the protocol, such as `local role provider;`.
    theirs: &'static str,
    /// Prefixes BIRD originates.
    statics: &'static [&'static str],
    /// More for BIRD's `ipv4` channel, such as an export filter.
    channel: &'static str,
}

/// A running lab: bgpfcd, BIRD in B, BIRD in C if asked for, and bgpfcd's
/// control socket.
struct Setup {
    lab: Lab,
    bird_b: Bird,
    bird_c: Option<Bird>,
    bgpfcd: Daemon,
    socket: PathBuf,
}

impl Setup {
    fn start(tag: &str, subnet: u8, b: &Side, c: Option<&Side>) -> Setup {
        let mut lab = Lab::new(tag, subnet);
        let ns_c = c.map(|_| lab.add_c());
        let bird_b = Bird::start(
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
                passive: true,
                statics: b.statics.iter().map(|s| (*s).to_owned()).collect(),
                channel: b.channel.to_owned(),
                protocol: b.theirs.to_owned(),
            },
        );
        let bird_c = c.zip(ns_c.as_ref()).map(|(c, ns)| {
            Bird::start(
                &lab,
                ns,
                &BirdOpts {
                    local_as: C_AS,
                    local: lab.c_addr,
                    local_port: 179,
                    neighbor: lab.a2_addr,
                    neighbor_port: 179,
                    remote_as: BGPFC_AS,
                    hold_time: 30,
                    passive: true,
                    statics: c.statics.iter().map(|s| (*s).to_owned()).collect(),
                    channel: c.channel.to_owned(),
                    protocol: c.theirs.to_owned(),
                },
            )
        });
        let socket = lab.dir.join("ctl.sock");
        // A short interval, so that a route that arrives behind another is
        // not held for the RFC 4271 §10 default of 30 s.
        let neighbor = |addr, asn, side: &Side| NeighborOpts {
            advertisement_interval: Some(1),
            extra: format!("connect-retry-time 5; {}", side.ours),
            ..NeighborOpts::new(addr, asn)
        };
        let mut neighbors = vec![neighbor(lab.b_addr, B_AS, b)];
        if let Some(c) = c {
            neighbors.push(neighbor(lab.c_addr, C_AS, c));
        }
        let bgpfcd = start_bgpfcd(
            &lab,
            &lab.a.clone(),
            &BgpfcdOpts {
                local_as: BGPFC_AS,
                router_id: lab.a_addr,
                listen: if ns_c.is_some() {
                    vec![lab.a_addr.into(), lab.a2_addr.into()]
                } else {
                    vec![lab.a_addr.into()]
                },
                neighbors,
                extra: format!("control {{ socket {}; }}", socket.display()),
            },
        );
        Setup {
            lab,
            bird_b,
            bird_c,
            bgpfcd,
            socket,
        }
    }

    fn ctl(&self, args: &[&str]) -> String {
        interop::bgpfcctl(&self.socket, args).0
    }

    /// `show neighbor` for the neighbor in B (`b`) or in C.
    fn neighbor(&self, in_b: bool) -> String {
        let addr = if in_b {
            self.lab.b_addr
        } else {
            self.lab.c_addr
        };
        self.ctl(&["show", "neighbor", &addr.to_string()])
    }

    /// Wait for bgpfcd to have `n` sessions established, and BIRD in B
    /// (and in C) to say so too.
    fn established(&self, n: usize) {
        let ok = wait_for(ESTABLISH, || {
            self.bgpfcd
                .log_text()
                .matches("session established")
                .count()
                >= n
                && self.bird_b.peer_status(&self.lab).contains("Established")
                && self
                    .bird_c
                    .as_ref()
                    .is_none_or(|c| c.peer_status(&self.lab).contains("Established"))
        });
        assert!(ok, "{}", self.report());
    }

    /// Everything worth reading when a test fails.
    fn report(&self) -> String {
        format!(
            "--- bgpfcd ---\n{}\n--- bgpfcd routes ---\n{}\n--- bird b ---\n{}\n{}\n--- bird c ---\n{}",
            self.bgpfcd.log_text(),
            self.ctl(&["show", "routes"]),
            self.bird_b.daemon.log_text(),
            self.bird_b.peer_status(&self.lab),
            self.bird_c
                .as_ref()
                .map_or(String::new(), |c| c.daemon.log_text()),
        )
    }

    /// Wait until `check` holds for the text of `bgpfcctl show routes`.
    fn wait_routes(&self, what: &str, check: impl Fn(&str) -> bool) -> String {
        let ok = wait_for(Duration::from_secs(20), || {
            check(&self.ctl(&["show", "routes"]))
        });
        let routes = self.ctl(&["show", "routes"]);
        assert!(ok, "{what}:\n{routes}\n{}", self.report());
        routes
    }
}

/// The line of `show routes` for `prefix`.
fn line<'a>(routes: &'a str, prefix: &str) -> &'a str {
    routes
        .lines()
        .find(|l| l.contains(&format!("{prefix} ")) || l.contains(&format!("{prefix}  ")))
        .unwrap_or_else(|| panic!("no route to {prefix}:\n{routes}"))
}

/// BIRD's `show route all` for `prefix`.
fn bird_route(bird: &Bird, lab: &Lab, prefix: &str) -> String {
    bird.birdc(lab, &["show", "route", "all", prefix])
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn provider_and_customer_routes_carry_the_attribute() {
    // bgpfcd is a customer of the BIRD in B and the provider of the BIRD
    // in C: RFC 9234 §4.2 Table 2 pairs each with the other's Role.
    let s = Setup::start(
        "rp",
        20,
        &Side {
            ours: "role customer;",
            theirs: "local role provider;",
            statics: &["192.0.2.0/24"],
            channel: "",
        },
        Some(&Side {
            ours: "role provider;",
            theirs: "local role customer;",
            statics: &["198.51.100.0/24"],
            channel: "",
        }),
    );
    s.established(2);
    let bird_c = s.bird_c.as_ref().unwrap();

    // RFC 9234 §4.1: each side sent its Role, and bgpfcd reports both.
    let b = s.neighbor(true);
    assert!(b.contains("role customer (neighbor sent provider)"), "{b}");
    let c = s.neighbor(false);
    assert!(c.contains("role provider (neighbor sent customer)"), "{c}");
    let status = s.bird_b.peer_status(&s.lab);
    assert!(
        status.contains("Role:") && status.contains("provider"),
        "{status}"
    );

    // RFC 9234 §5 ingress: the route from the provider has the attribute,
    // with the provider's AS (BIRD set it on its way out, as bgpfcd would
    // have on the way in); the customer's has none.
    let routes = s.wait_routes("both routes", |r| {
        r.contains("192.0.2.0/24") && r.contains("198.51.100.0/24")
    });
    assert!(
        line(&routes, "192.0.2.0/24").ends_with("otc 65001"),
        "{routes}"
    );
    assert!(
        !line(&routes, "198.51.100.0/24").contains("otc"),
        "{routes}"
    );

    // RFC 9234 §5 egress: the provider's route reaches the customer with
    // the attribute; the customer's reaches the provider without one.
    let ok = wait_for(Duration::from_secs(20), || {
        bird_route(bird_c, &s.lab, "192.0.2.0/24").contains("192.0.2.0/24")
    });
    let at_c = bird_route(bird_c, &s.lab, "192.0.2.0/24");
    assert!(ok, "{at_c}\n{}", s.report());
    assert!(at_c.contains("BGP.otc: 65001"), "{at_c}");
    let ok = wait_for(Duration::from_secs(20), || {
        bird_route(&s.bird_b, &s.lab, "198.51.100.0/24").contains("198.51.100.0/24")
    });
    let at_b = bird_route(&s.bird_b, &s.lab, "198.51.100.0/24");
    assert!(ok, "{at_b}\n{}", s.report());
    assert!(!at_b.contains("otc"), "{at_b}");
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn a_customer_does_not_give_one_provider_the_routes_of_another() {
    // RFC 9234 §5 egress 2, the leak of RFC 7908 §3.1: bgpfcd, a customer
    // of both BIRDs, must not pass the route of one to the other.
    let provider = |prefix: &'static [&'static str]| Side {
        ours: "role customer;",
        theirs: "local role provider;",
        statics: prefix,
        channel: "",
    };
    let s = Setup::start(
        "tp",
        21,
        &provider(&["192.0.2.0/24"]),
        Some(&provider(&["198.51.100.0/24"])),
    );
    s.established(2);
    let routes = s.wait_routes("both routes", |r| {
        r.contains("192.0.2.0/24") && r.contains("198.51.100.0/24")
    });
    assert!(
        line(&routes, "192.0.2.0/24").ends_with("otc 65001"),
        "{routes}"
    );
    assert!(
        line(&routes, "198.51.100.0/24").ends_with("otc 65002"),
        "{routes}"
    );
    // Long enough for the 1 s interval and BIRD's processing.
    std::thread::sleep(Duration::from_secs(6));
    let bird_c = s.bird_c.as_ref().unwrap();
    let at_c = bird_c.birdc(&s.lab, &["show", "route"]);
    let at_b = s.bird_b.birdc(&s.lab, &["show", "route"]);
    assert!(!at_c.contains("192.0.2.0/24"), "{at_c}");
    assert!(!at_b.contains("198.51.100.0/24"), "{at_b}");
    for in_b in [true, false] {
        let n = s.neighbor(in_b);
        assert!(n.contains("routes received 1 advertised 0"), "{n}");
    }
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn roles_that_do_not_correspond_refuse_the_session() {
    // RFC 9234 §4.2: Provider with Provider is not in Table 2. Both sides
    // answer with OPEN Message Error / Role Mismatch (subcode 11), and the
    // session never comes up.
    let s = Setup::start(
        "mm",
        22,
        &Side {
            ours: "role provider;",
            theirs: "local role provider;",
            statics: &["192.0.2.0/24"],
            channel: "",
        },
        None,
    );
    let ok = wait_for(Duration::from_secs(30), || {
        let log = s.bgpfcd.log_text();
        log.contains("sending notification") && log.contains("Role Mismatch")
    });
    assert!(ok, "{}", s.report());
    let ok = wait_for(Duration::from_secs(10), || {
        s.bird_b.daemon.log_text().contains("Role mismatch")
    });
    assert!(ok, "{}", s.report());
    // Not once in 10 s more, and no route.
    std::thread::sleep(Duration::from_secs(10));
    assert!(!s.bgpfcd.log_text().contains("session established"));
    assert!(!s.bird_b.peer_status(&s.lab).contains("Established"));
    assert!(!s.ctl(&["show", "routes"]).contains("192.0.2.0/24"));
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn strict_mode_needs_the_neighbors_capability() {
    // RFC 9234 §4.2: BIRD sends no Role. Without strict mode bgpfcd goes
    // on, with its own Role; with it, the connection is rejected with
    // Role Mismatch, until a reload turns it off.
    let s = Setup::start(
        "st",
        23,
        &Side {
            ours: "role customer; role-strict yes;",
            // BIRD waits out an error before it takes the next connection.
            theirs: "error wait time 1, 2;",
            statics: &["192.0.2.0/24"],
            channel: "",
        },
        None,
    );
    let ok = wait_for(Duration::from_secs(30), || {
        let log = s.bgpfcd.log_text();
        log.contains("sending notification") && log.contains("Role Mismatch")
    });
    assert!(ok, "{}", s.report());
    assert!(!s.bgpfcd.log_text().contains("session established"));

    let cfg_path = s.lab.dir.join(format!("bgpfcd-{}.conf", s.lab.a));
    let cfg = fs::read_to_string(&cfg_path)
        .unwrap()
        .replace("role customer; role-strict yes;", "role customer;");
    fs::write(&cfg_path, cfg).unwrap();
    let out = s.ctl(&["reload"]);
    assert!(out.contains("reset 1"), "{out}");
    s.established(1);
    // RFC 9234 §4.2: "The locally configured BGP Role is used for the
    // procedures described in Section 5": the route has the attribute
    // though BIRD sent none.
    let routes = s.wait_routes("the route", |r| r.contains("192.0.2.0/24"));
    assert!(
        line(&routes, "192.0.2.0/24").ends_with("otc 65001"),
        "{routes}"
    );
    let n = s.neighbor(true);
    assert!(n.contains("role customer (neighbor sent none)"), "{n}");
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn bird_requiring_roles_refuses_a_neighbor_with_none() {
    // The other way: BIRD's `require roles yes` is the strict mode of
    // RFC 9234 §4.2, and bgpfcd has no Role to send.
    let s = Setup::start(
        "rq",
        24,
        &Side {
            ours: "",
            theirs: "local role provider; require roles yes;",
            statics: &["192.0.2.0/24"],
            channel: "",
        },
        None,
    );
    let ok = wait_for(Duration::from_secs(30), || {
        let log = s.bgpfcd.log_text();
        log.contains("notification received") && log.contains("Role Mismatch")
    });
    assert!(ok, "{}", s.report());
    assert!(!s.bgpfcd.log_text().contains("session established"));
}

#[test]
#[ignore = "needs root, bird and iproute2"]
fn leaks_are_dropped_and_the_rest_is_marked() {
    // BIRD has no Role, so nothing stops it sending the attribute: bgpfcd
    // has the Peer Role on the session (RFC 9234 §5 ingress 2, 3). A route
    // with BIRD's own AS in it is as a peer sends it, one with another
    // AS is a route leak, and one with none gets BIRD's AS.
    let s = Setup::start(
        "lk",
        25,
        &Side {
            ours: "role peer;",
            theirs: "",
            statics: &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
            channel: "export filter {
                if net = 192.0.2.0/24 then bgp_otc = 65001;
                if net = 198.51.100.0/24 then bgp_otc = 65099;
                accept;
            };",
        },
        None,
    );
    s.established(1);
    let routes = s.wait_routes("two routes", |r| {
        r.contains("192.0.2.0/24") && r.contains("203.0.113.0/24")
    });
    assert!(
        line(&routes, "192.0.2.0/24").ends_with("otc 65001"),
        "{routes}"
    );
    assert!(
        line(&routes, "203.0.113.0/24").ends_with("otc 65001"),
        "{routes}"
    );
    // The leak is reported, and kept out of the RIB and the count.
    let ok = wait_for(Duration::from_secs(10), || {
        let log = s.bgpfcd.log_text();
        log.contains("route leak") && log.contains("otc=65099")
    });
    assert!(ok, "{}", s.report());
    assert!(!routes.contains("198.51.100.0/24"), "{routes}");
    let n = s.neighbor(true);
    assert!(n.contains("routes received 2"), "{n}");
    // The session goes on.
    assert!(n.contains("Established"), "{n}");
}
