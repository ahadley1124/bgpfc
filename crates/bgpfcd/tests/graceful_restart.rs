//! Graceful Restart (RFC 4724, RFC 8538) between the daemon as a process
//! and two stub speakers on localhost, where no privilege is needed. Stub A
//! has the capability, and restarts its session in the ways the RFCs
//! tell: it is reset gracefully (the Graceful Notification bit), it
//! loses its TCP connection, it comes back without the Forwarding State
//! bit, and it is sent a Hard Reset. Stub B has none, and is told only
//! what a speaker without the capability would be: a route is withdrawn
//! when the daemon deletes it, never earlier.
//!
//! The daemon connects to the stubs, which listen on 127.0.0.1 and
//! 127.0.0.3, and listens on 127.0.0.2 itself: any address of 127.0.0.0/8
//! is loopback on Linux, and a connection to one of them comes from
//! 127.0.0.1, which is how stub A reaches the daemon as its neighbor.

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufReader, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_bench::speaker::{SessionError, read_message};
use bgpfc_control::proto::{Request, Response};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::capability::{Capability, GracefulRestart, GracefulRestartFamily};
use bgpfc_wire::error::{CeaseSubcode, ErrorCode};
use bgpfc_wire::header::{MessageType, frame};
use bgpfc_wire::keepalive::KEEPALIVE;
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RestartTime, RouterId};
use bgpfc_wire::update::{DecodeContext, EncodeContext, PeerKind, UpdateMessage};

const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const TIMEOUT: Duration = Duration::from_secs(30);

/// A next hop that is not loopback: the daemon ignores routes through one
/// (RFC 4271 §6.3, RFC 7606 §7.11).
const NEXT_HOP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bgpfcd-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn prefix(s: &str) -> Prefix {
    s.parse().unwrap()
}

/// The daemon, killed when the test ends.
struct Daemon {
    child: Child,
    dir: PathBuf,
    /// The port it listens on, at 127.0.0.2.
    listen_port: u16,
    /// The ports of the stubs A and B.
    ports: (u16, u16),
}

impl Daemon {
    /// The configuration: neighbor A (127.0.0.1, `graceful-restart yes`),
    /// unless `without_a`, and neighbor B (127.0.0.3, nothing special), on
    /// the stubs' ports.
    fn config(dir: &Path, listen_port: u16, ports: (u16, u16), without_a: bool) -> String {
        let (port_a, port_b) = ports;
        let a = if without_a {
            String::new()
        } else {
            format!(
                "neighbor 127.0.0.1 {{ remote-as 65001; port {port_a}; families ipv4-unicast;\n\
                   import ANY; export ANY; advertisement-interval 0;\n\
                   graceful-restart yes; restart-time 90; stale-time 60; }}\n"
            )
        };
        format!(
            "router-id 192.0.2.1;\nlocal-as 65000;\nlog {{ level warn; }}\n\
             listen {{ address 127.0.0.2; port {listen_port}; }}\n\
             fib {{ mode dry-run; }}\ncontrol {{ socket {}; }}\n\
             policy ANY {{ term all {{ action accept; }} }}\n{a}\
             neighbor 127.0.0.3 {{ remote-as 65002; port {port_b}; families ipv4-unicast;\n\
               import ANY; export ANY; advertisement-interval 0; }}\n",
            dir.join("ctl.sock").display()
        )
    }

    /// Start it on the stubs' ports.
    fn start(dir: &Path, port_a: u16, port_b: u16) -> Daemon {
        let conf = dir.join("bgpfcd.conf");
        let listen = TcpListener::bind("127.0.0.2:0").unwrap();
        let listen_port = listen.local_addr().unwrap().port();
        drop(listen);
        let ports = (port_a, port_b);
        fs::write(&conf, Daemon::config(dir, listen_port, ports, false)).unwrap();
        let log = fs::File::create(dir.join("bgpfcd.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_bgpfcd"))
            .arg("-c")
            .arg(&conf)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        Daemon {
            child,
            dir: dir.to_owned(),
            listen_port,
            ports,
        }
    }

    /// Remove neighbor A from the configuration file and reload.
    fn remove_a(&self) {
        let conf = self.dir.join("bgpfcd.conf");
        fs::write(
            &conf,
            Daemon::config(&self.dir, self.listen_port, self.ports, true),
        )
        .unwrap();
        self.ask("reload");
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.join("bgpfcd.log")).unwrap_or_default()
    }

    /// Ask the control socket, retrying until it is there.
    fn ask(&self, command: &str) -> Vec<String> {
        let socket = self.dir.join("ctl.sock");
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Ok(mut s) = UnixStream::connect(&socket) {
                let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
                s.write_all(Request::format(&words).as_bytes()).unwrap();
                let r = Response::read_from(&mut BufReader::new(s)).unwrap();
                assert_eq!(r.status, Ok(()), "{command}: {:?}", r.lines);
                return r.lines;
            }
            assert!(
                Instant::now() < deadline,
                "no control socket:\n{}",
                self.log()
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// `ask` until `done` holds of the answer.
    fn wait_for(&self, command: &str, done: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let answer = self.ask(command).join("\n");
            if done(&answer) {
                return answer;
            }
            assert!(
                Instant::now() < deadline,
                "{command}: no answer as expected, last:\n{answer}\n{}",
                self.log()
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// What a stub says of Graceful Restart in its OPEN.
#[derive(Clone, Copy)]
struct Gr {
    /// The Restart Time, seconds.
    restart_time: u16,
    /// The Forwarding State bit of IPv4 unicast.
    forwarding: bool,
}

/// What a stub read.
#[derive(Debug, Default)]
struct Read {
    announced: BTreeSet<Prefix>,
    withdrawn: BTreeSet<Prefix>,
    /// The families the End-of-RIB markers were for.
    end_of_rib: Vec<AddressFamily>,
}

/// A speaker the daemon connects to.
struct Stub {
    stream: TcpStream,
    /// The OPEN the daemon sent.
    theirs: OpenMessage,
}

impl Stub {
    /// Wait for the daemon to connect and bring the session up. `gr` is
    /// the capability to advertise, if any.
    fn accept(
        listener: &TcpListener,
        asn: u32,
        router_id: u32,
        gr: Option<Gr>,
        d: &Daemon,
    ) -> Stub {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + TIMEOUT;
        let stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("the daemon never connected: {e}\n{}", d.log()),
            }
        };
        Stub::open(stream, asn, router_id, gr, d)
    }

    /// Bring the session up over `stream`, which is ours or the daemon's.
    fn open(mut stream: TcpStream, asn: u32, router_id: u32, gr: Option<Gr>, d: &Daemon) -> Stub {
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut caps = vec![Capability::Multiprotocol(V4)];
        caps.extend(gr.map(|gr| {
            Capability::GracefulRestart(GracefulRestart {
                restarting: false,
                notification: true,
                restart_time: RestartTime::new(gr.restart_time).unwrap(),
                families: vec![GracefulRestartFamily {
                    family: V4,
                    forwarding: gr.forwarding,
                }],
            })
        }));
        let open = OpenMessage::new(
            Asn(asn),
            HoldTime::new(90).unwrap(),
            RouterId::new(router_id).unwrap(),
            caps,
        );
        stream
            .write_all(&frame(MessageType::Open, &open.encode().unwrap()).unwrap())
            .unwrap();
        stream.write_all(&KEEPALIVE).unwrap();
        let (kind, body) = read_message(&mut stream, false).unwrap();
        assert_eq!(kind, MessageType::Open, "{}", d.log());
        let theirs = OpenMessage::decode(&body).unwrap();
        Stub { stream, theirs }
    }

    /// The Graceful Restart capability the daemon advertised.
    fn gr_cap(&self) -> Option<&GracefulRestart> {
        bgpfc_wire::capability::graceful_restart(&self.theirs.capabilities)
    }

    /// Send an UPDATE announcing `prefixes` along `path`.
    fn announce(&mut self, prefixes: &[&str], path: &[u32]) {
        let hops: Vec<Asn> = path.iter().map(|a| Asn(*a)).collect();
        self.send(&UpdateMessage {
            nlri: prefixes.iter().map(|p| prefix(p)).collect(),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&hops)),
                PathAttribute::NextHop(NEXT_HOP),
            ],
            ..UpdateMessage::default()
        });
    }

    /// Send the End-of-RIB marker of IPv4 unicast (RFC 4724 §2).
    fn end_of_rib(&mut self) {
        self.send(&UpdateMessage::end_of_rib(V4));
    }

    fn send(&mut self, message: &UpdateMessage) {
        let body = message
            .encode(&EncodeContext {
                four_octet_as: true,
                extended_next_hop: false,
                add_path: bgpfc_wire::update::AddPathFamilies::NONE,
            })
            .unwrap();
        self.stream
            .write_all(&frame(MessageType::Update, &body).unwrap())
            .unwrap();
    }

    /// Read until `done` holds of what was read so far, or a NOTIFICATION
    /// or the end of the connection comes (`Err`). KEEPALIVEs are skipped.
    fn read_until(
        &mut self,
        d: &Daemon,
        done: impl Fn(&Read) -> bool,
    ) -> Result<Read, Option<NotificationMessage>> {
        let ctx = DecodeContext {
            four_octet_as: true,
            peer: PeerKind::External,
            allow_as_set: false,
            extended_next_hop: false,
            add_path: bgpfc_wire::update::AddPathFamilies::NONE,
        };
        let mut read = Read::default();
        while !done(&read) {
            match read_message(&mut self.stream, false) {
                Ok((MessageType::Keepalive, _)) => {}
                Ok((MessageType::Update, body)) => {
                    let u = UpdateMessage::decode(&body, &ctx).unwrap();
                    if let Some(family) = u.message.end_of_rib_family() {
                        read.end_of_rib.push(family);
                    }
                    read.withdrawn.extend(u.message.withdrawn.iter().copied());
                    read.announced.extend(u.message.nlri.iter().copied());
                }
                Ok((MessageType::Notification, body)) => {
                    return Err(Some(NotificationMessage::decode(&body).unwrap()));
                }
                Ok((other, _)) => panic!("unexpected {other:?}\n{}", d.log()),
                Err(SessionError::Io(_)) => return Err(None),
                Err(e) => panic!("{e}\n{}", d.log()),
            }
        }
        Ok(read)
    }

    /// Whether anything arrives in `wait`: an UPDATE, a NOTIFICATION or the
    /// end of the connection. KEEPALIVEs do not count.
    fn is_quiet_for(&mut self, wait: Duration) -> bool {
        self.stream.set_read_timeout(Some(wait)).unwrap();
        let deadline = Instant::now() + wait;
        let quiet = loop {
            match read_message(&mut self.stream, false) {
                Ok((MessageType::Keepalive, _)) => {}
                Err(SessionError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break true;
                }
                // An UPDATE, a NOTIFICATION, the end of the connection.
                _ => break false,
            }
            if Instant::now() >= deadline {
                break true;
            }
        };
        self.stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        quiet
    }
}

/// The two stubs' listeners, and the daemon pointed at them.
fn lab(name: &str) -> (Daemon, TcpListener, TcpListener) {
    let dir = scratch(name);
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.3:0").unwrap();
    let ports = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    (Daemon::start(&dir, ports.0, ports.1), a, b)
}

/// Both stubs up; A has sent `routes` and its End-of-RIB, and B has them.
fn established(
    d: &Daemon,
    la: &TcpListener,
    lb: &TcpListener,
    gr: Gr,
    routes: &[&str],
) -> (Stub, Stub) {
    let mut b = Stub::accept(lb, 65_002, 0xc000_0202, None, d);
    let mut a = Stub::accept(la, 65_001, 0xc000_0201, Some(gr), d);
    a.announce(routes, &[65_001]);
    a.end_of_rib();
    let want: BTreeSet<Prefix> = routes.iter().map(|p| prefix(p)).collect();
    let got = b
        .read_until(d, |r| r.announced == want)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.announced, want);
    (a, b)
}

const ROUTES: [&str; 3] = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];

#[test]
fn the_initial_update_ends_with_end_of_rib_and_a_reset_keeps_the_routes_as_stale() {
    let (d, la, lb) = lab("gr-reset");
    // B has a route of its own before A comes up.
    let mut b = Stub::accept(&lb, 65_002, 0xc000_0202, None, &d);
    b.announce(&["100.64.0.0/10"], &[65_002]);
    d.wait_for("show routes", |r| r.contains("100.64.0.0/10"));
    let mut a = Stub::accept(
        &la,
        65_001,
        0xc000_0201,
        Some(Gr {
            restart_time: 90,
            forwarding: true,
        }),
        &d,
    );
    // RFC 4724 §3, RFC 8538 §2: the daemon advertised the capability with
    // the N bit and the Restart Time of its neighbor block, and a tuple for
    // IPv4 unicast; it has not restarted, and no forwarding state is
    // claimed in dry-run mode.
    let cap = a.gr_cap().expect("the capability is advertised");
    assert!(!cap.restarting && cap.notification);
    assert_eq!(cap.restart_time.secs(), 90);
    assert_eq!(cap.families.len(), 1);
    assert!(!cap.families[0].forwarding, "dry-run installs nothing");
    // RFC 4724 §4: the table, then the marker that ends the initial update.
    let first = a
        .read_until(&d, |r| !r.end_of_rib.is_empty())
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(first.announced, BTreeSet::from([prefix("100.64.0.0/10")]));
    assert_eq!(first.end_of_rib, vec![V4]);
    // B has no capability, so it is sent no marker.
    assert!(b.is_quiet_for(Duration::from_millis(300)));

    a.announce(&ROUTES, &[65_001]);
    a.end_of_rib();
    let want: BTreeSet<Prefix> = ROUTES.iter().map(|p| prefix(p)).collect();
    let got = b
        .read_until(&d, |r| r.announced.len() >= want.len())
        .unwrap();
    assert!(got.announced.is_superset(&want) && got.end_of_rib.is_empty());
    let detail = d.wait_for("show neighbor 127.0.0.1", |r| {
        r.contains("graceful-restart neighbor restart-time 90s notification yes")
    });
    assert!(
        detail.contains("forwarding ipv4-unicast without none"),
        "{detail}"
    );
    assert!(!detail.contains("stale routes"), "{detail}");

    // RFC 8538 §4: both sides set the N bit, so a graceful reset keeps the
    // routes of both as stale ones. The daemon's NOTIFICATION is the
    // ordinary Administrative Reset.
    d.ask("clear neighbor 127.0.0.1");
    let n = a
        .read_until(&d, |_| false)
        .unwrap_err()
        .expect("a NOTIFICATION");
    assert_eq!(
        (n.code, n.subcode),
        (ErrorCode::Cease, CeaseSubcode::AdministrativeReset as u8)
    );
    let routes = d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
    assert!(routes.contains("192.0.2.0/24"), "{routes}");
    let detail = d.ask("show neighbor 127.0.0.1").join("\n");
    assert!(
        detail.contains("stale routes ipv4-unicast=3; awaiting end-of-rib ipv4-unicast"),
        "{detail}"
    );
    // The routes are still in use, so B is told nothing.
    assert!(b.is_quiet_for(Duration::from_secs(1)), "{}", d.log());

    // The neighbor is back, with the Forwarding State bit. It sends two of
    // the three routes again, and its End-of-RIB.
    let mut a = Stub::accept(
        &la,
        65_001,
        0xc000_0201,
        Some(Gr {
            restart_time: 90,
            forwarding: true,
        }),
        &d,
    );
    let first = a
        .read_until(&d, |r| !r.end_of_rib.is_empty())
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(first.end_of_rib, vec![V4]);
    a.announce(&[ROUTES[0], ROUTES[1]], &[65_001]);
    // Replaced, not deleted: before the marker all three are in the table
    // and none is withdrawn from B.
    d.wait_for("show routes", |r| r.matches(" stale").count() == 1);
    assert!(b.is_quiet_for(Duration::from_millis(500)));
    a.end_of_rib();
    // RFC 4724 §4.2: what it did not send again goes at its End-of-RIB.
    let got = b
        .read_until(&d, |r| !r.withdrawn.is_empty())
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn, BTreeSet::from([prefix(ROUTES[2])]));
    let routes = d.ask("show routes").join("\n");
    assert!(
        !routes.contains(" stale") && !routes.contains(ROUTES[2]),
        "{routes}"
    );
    let detail = d.ask("show neighbor 127.0.0.1").join("\n");
    assert!(!detail.contains("stale routes"), "{detail}");
}

#[test]
fn a_neighbor_back_without_forwarding_state_loses_its_routes_at_once() {
    let (d, la, lb) = lab("gr-no-forwarding");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (_a, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    d.ask("clear neighbor 127.0.0.1");
    d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
    assert!(b.is_quiet_for(Duration::from_millis(500)));
    // RFC 4724 §4.2: no Forwarding State bit, so "MUST immediately remove
    // all the stale routes" for the family, End-of-RIB or not.
    let _a = Stub::accept(
        &la,
        65_001,
        0xc000_0201,
        Some(Gr {
            restart_time: 90,
            forwarding: false,
        }),
        &d,
    );
    let got = b
        .read_until(&d, |r| r.withdrawn.len() == 3)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(
        got.withdrawn,
        ROUTES.iter().map(|p| prefix(p)).collect::<BTreeSet<_>>()
    );
    assert!(!d.ask("show routes").join("\n").contains(" stale"));
}

#[test]
fn a_neighbor_that_comes_back_without_the_capability_loses_its_routes_at_once() {
    let (d, la, lb) = lab("gr-no-capability");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (_a, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    d.ask("clear neighbor 127.0.0.1");
    d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
    // RFC 4724 §4.2: "if the Graceful Restart Capability is not received in
    // the re-established session at all".
    let _a = Stub::accept(&la, 65_001, 0xc000_0201, None, &d);
    let got = b
        .read_until(&d, |r| r.withdrawn.len() == 3)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn.len(), 3);
}

#[test]
fn a_hard_reset_deletes_the_routes_of_both_sides_at_once() {
    let (d, la, lb) = lab("gr-hard-reset");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (mut a, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    d.ask("clear neighbor 127.0.0.1 hard-reset");
    // RFC 8538 §3, §5.2: Cease / Hard Reset, with the Administrative Reset
    // in its data.
    let n = a
        .read_until(&d, |_| false)
        .unwrap_err()
        .expect("a NOTIFICATION");
    assert!(n.is_hard_reset(), "{n}");
    assert_eq!(
        n.hard_reset_inner().map(|i| (i.code, i.subcode)),
        Some((ErrorCode::Cease, CeaseSubcode::AdministrativeReset as u8))
    );
    // Not kept: B hears of the withdrawals, and nothing is stale.
    let got = b
        .read_until(&d, |r| r.withdrawn.len() == 3)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn.len(), 3);
    assert!(!d.ask("show routes").join("\n").contains("stale"));
}

#[test]
fn a_hard_reset_from_the_neighbor_deletes_its_routes_at_once() {
    let (d, la, lb) = lab("gr-hard-reset-in");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (mut a, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    // RFC 8538 §3.2: "the speaker MUST terminate the BGP session following
    // the standard procedures in [RFC4271]": the routes go, N bit or not.
    let inner = NotificationMessage::cease(CeaseSubcode::AdministrativeShutdown);
    let hard = NotificationMessage::hard_reset(&inner);
    a.stream
        .write_all(&frame(MessageType::Notification, &hard.encode(false).unwrap()).unwrap())
        .unwrap();
    let got = b
        .read_until(&d, |r| r.withdrawn.len() == 3)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn.len(), 3);
    assert!(!d.ask("show routes").join("\n").contains("stale"));
}

#[test]
fn a_notification_from_the_neighbor_keeps_its_routes_as_stale() {
    let (d, la, lb) = lab("gr-notification-in");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (mut a, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    // RFC 8538 §4: with the N bit exchanged, "a BGP NOTIFICATION message
    // other than a Hard Reset" is followed by the Receiving Speaker
    // procedures.
    let cease = NotificationMessage::cease(CeaseSubcode::AdministrativeReset);
    a.stream
        .write_all(&frame(MessageType::Notification, &cease.encode(false).unwrap()).unwrap())
        .unwrap();
    d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
    assert!(b.is_quiet_for(Duration::from_secs(1)), "{}", d.log());
}

#[test]
fn the_restart_time_ends_the_wait_for_a_neighbor_that_does_not_come_back() {
    let (d, la, lb) = lab("gr-restart-timer");
    // RFC 4724 §3: the neighbor says its session needs two seconds to
    // come back.
    let gr = Gr {
        restart_time: 2,
        forwarding: true,
    };
    let (a, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    // RFC 4724 §4.2: a TCP failure keeps the routes.
    let lost = Instant::now();
    drop(a);
    d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
    let detail = d.ask("show neighbor 127.0.0.1").join("\n");
    assert!(detail.contains("session due back in"), "{detail}");
    // "If the session does not get re-established within the Restart Time
    // that the peer advertised previously, the Receiving Speaker MUST
    // delete all the stale routes."
    let got = b
        .read_until(&d, |r| r.withdrawn.len() == 3)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn.len(), 3);
    assert!(
        lost.elapsed() >= Duration::from_secs(2),
        "deleted after {:?}",
        lost.elapsed()
    );
    assert!(!d.ask("show routes").join("\n").contains("stale"));
}

#[test]
fn a_connection_from_the_neighbor_replaces_the_established_session_and_keeps_its_routes() {
    let (d, la, lb) = lab("gr-takeover");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (mut old, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    // RFC 4724 §4.2: the neighbor restarted and the daemon has not noticed
    // the old connection end. The neighbor connects to the daemon, from
    // 127.0.0.1: "the previous TCP session MUST be closed, and the new one
    // retained", with no NOTIFICATION sent on the old one.
    let new = TcpStream::connect(("127.0.0.2", d.listen_port)).unwrap();
    let mut a = Stub::open(new, 65_001, 0xc000_0201, Some(gr), &d);
    assert!(a.gr_cap().is_some());
    assert_eq!(
        old.read_until(&d, |_| false).unwrap_err(),
        None,
        "the old connection is closed without a NOTIFICATION"
    );
    // The routes were kept, and are replaced by what the new session sends.
    d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
    assert!(b.is_quiet_for(Duration::from_millis(500)), "{}", d.log());
    a.announce(&[ROUTES[0]], &[65_001]);
    a.end_of_rib();
    let got = b
        .read_until(&d, |r| r.withdrawn.len() == 2)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(
        got.withdrawn,
        BTreeSet::from([prefix(ROUTES[1]), prefix(ROUTES[2])])
    );
    assert!(!d.ask("show routes").join("\n").contains("stale"));
}

#[test]
fn the_stale_routes_of_a_neighbor_that_is_removed_go_at_once() {
    let (d, la, lb) = lab("gr-removed");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (a, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    drop(a);
    d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
    assert!(b.is_quiet_for(Duration::from_millis(500)));
    // RFC 4724 §4.2 keeps the routes for a neighbor that is coming back;
    // one that is no longer configured is not.
    d.remove_a();
    let got = b
        .read_until(&d, |r| r.withdrawn.len() == 3)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn.len(), 3);
    assert!(!d.ask("show routes").join("\n").contains(" stale"));
}

/// Whether the daemon has connected to `listener` since it was last asked.
fn connected(listener: &TcpListener) -> bool {
    listener.set_nonblocking(true).unwrap();
    listener.accept().is_ok()
}

#[test]
fn a_hard_reset_waits_for_the_neighbor_to_close_before_the_connection_is_closed() {
    let (d, la, lb) = lab("gr-linger");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (mut a, _b) = established(&d, &la, &lb, gr, &ROUTES);
    d.ask("clear neighbor 127.0.0.1 hard-reset");
    let n = a
        .read_until(&d, |_| false)
        .unwrap_err()
        .expect("a NOTIFICATION");
    assert!(n.is_hard_reset(), "{n}");
    // RFC 4724 §4.2: a neighbor that reads the end of the connection along
    // with the NOTIFICATION may take it for a failure of the transport and
    // keep the routes the Hard Reset (RFC 8538 §3.2) is there to delete. The
    // daemon closes after the neighbor has, and connects again after that:
    // the neighbor has then dealt with the old session (RFC 4271 §6.8).
    assert!(
        a.is_quiet_for(Duration::from_millis(700)),
        "the daemon closed first:\n{}",
        d.log()
    );
    assert!(!connected(&la), "the daemon connected too early");
    let closed = Instant::now();
    drop(a);
    let a = Stub::accept(
        &la,
        65_001,
        0xc000_0201,
        Some(Gr {
            restart_time: 90,
            forwarding: true,
        }),
        &d,
    );
    assert!(
        closed.elapsed() < Duration::from_secs(2),
        "the daemon waited out its limit: {:?}",
        closed.elapsed()
    );
    drop(a);
}

#[test]
fn a_neighbor_that_does_not_close_after_the_notification_is_closed_by_the_daemon() {
    let (d, la, lb) = lab("gr-linger-limit");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (mut a, _b) = established(&d, &la, &lb, gr, &ROUTES);
    d.ask("clear neighbor 127.0.0.1");
    let n = a
        .read_until(&d, |_| false)
        .unwrap_err()
        .expect("a NOTIFICATION");
    assert!(!n.is_hard_reset(), "{n}");
    // The wait is bounded: a neighbor that never closes does not hold the
    // daemon off for good.
    let waited = Instant::now();
    assert_eq!(a.read_until(&d, |_| false).unwrap_err(), None);
    let waited = waited.elapsed();
    assert!(waited >= Duration::from_secs(1), "closed after {waited:?}");
    assert!(waited < Duration::from_secs(10), "closed after {waited:?}");
    let _a = Stub::accept(
        &la,
        65_001,
        0xc000_0201,
        Some(Gr {
            restart_time: 90,
            forwarding: true,
        }),
        &d,
    );
}

#[test]
fn a_neighbor_without_graceful_restart_sees_the_connection_close_at_once() {
    let (d, la, lb) = lab("gr-no-linger");
    let gr = Gr {
        restart_time: 90,
        forwarding: true,
    };
    let (_a, mut b) = established(&d, &la, &lb, gr, &ROUTES);
    d.ask("clear neighbor 127.0.0.3");
    b.read_until(&d, |_| false)
        .unwrap_err()
        .expect("a NOTIFICATION");
    // Without the capability there is no difference between a NOTIFICATION
    // and a failure of the transport to tell (RFC 4724 §4.2), and the
    // connection is closed as RFC 4271 §4.5 has it.
    let waited = Instant::now();
    assert_eq!(b.read_until(&d, |_| false).unwrap_err(), None);
    assert!(
        waited.elapsed() < Duration::from_secs(1),
        "{:?}",
        waited.elapsed()
    );
}
