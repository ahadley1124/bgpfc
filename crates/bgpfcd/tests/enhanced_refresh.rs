//! Enhanced Route Refresh (RFC 7313) between the daemon as a process and two
//! stub speakers on localhost, where no privilege is needed. Stub A has the
//! capability: it begins and ends route refreshes of its own, asks for ours,
//! and sends a message of the wrong length. Stub B has none, and is told
//! only what a speaker without it would be.
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
use bgpfc_wire::error::ErrorCode;
use bgpfc_wire::header::{MessageType, frame};
use bgpfc_wire::keepalive::KEEPALIVE;
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::route_refresh::{RefreshSubtype, RouteRefreshMessage};
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RestartTime, RouterId};
use bgpfc_wire::update::{DecodeContext, EncodeContext, PeerKind, UpdateMessage};

const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const TIMEOUT: Duration = Duration::from_secs(30);
const BORR: RefreshSubtype = RefreshSubtype::BeginOfRefresh;
const EORR: RefreshSubtype = RefreshSubtype::EndOfRefresh;
const REQUEST: RefreshSubtype = RefreshSubtype::Request;

/// A next hop that is not loopback: the daemon ignores routes through one
/// (RFC 4271 §6.3, RFC 7606 §7.11).
const NEXT_HOP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

const ROUTES: [&str; 3] = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bgpfcd-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn prefix(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn set(prefixes: &[&str]) -> BTreeSet<Prefix> {
    prefixes.iter().map(|p| prefix(p)).collect()
}

/// The daemon, killed when the test ends.
struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Daemon {
    /// The configuration: neighbor A (127.0.0.1) with `a_extra` statements,
    /// and neighbor B (127.0.0.3, nothing special), on the stubs' ports.
    fn config(dir: &Path, listen_port: u16, ports: (u16, u16), a_extra: &str) -> String {
        let (port_a, port_b) = ports;
        format!(
            "router-id 192.0.2.1;\nlocal-as 65000;\nlog {{ level warn; }}\n\
             listen {{ address 127.0.0.2; port {listen_port}; }}\n\
             fib {{ mode dry-run; }}\ncontrol {{ socket {}; }}\n\
             policy ANY {{ term all {{ action accept; }} }}\n\
             neighbor 127.0.0.1 {{ remote-as 65001; port {port_a}; families ipv4-unicast;\n\
               import ANY; export ANY; advertisement-interval 0; {a_extra} }}\n\
             neighbor 127.0.0.3 {{ remote-as 65002; port {port_b}; families ipv4-unicast;\n\
               import ANY; export ANY; advertisement-interval 0; }}\n",
            dir.join("ctl.sock").display()
        )
    }

    /// Start it on the stubs' ports. The port it listens on is one that was
    /// free a moment ago; another process can take it in between, and the
    /// daemon is then started again on another.
    fn start(dir: &Path, ports: (u16, u16), a_extra: &str) -> Daemon {
        let conf = dir.join("bgpfcd.conf");
        for _ in 0..8 {
            let listen = TcpListener::bind("127.0.0.2:0").unwrap();
            let listen_port = listen.local_addr().unwrap().port();
            drop(listen);
            fs::write(&conf, Daemon::config(dir, listen_port, ports, a_extra)).unwrap();
            let log = fs::File::create(dir.join("bgpfcd.log")).unwrap();
            let mut child = Command::new(env!("CARGO_BIN_EXE_bgpfcd"))
                .arg("-c")
                .arg(&conf)
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap();
            let socket = dir.join("ctl.sock");
            let deadline = Instant::now() + TIMEOUT;
            while !socket.exists() && Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            if socket.exists() {
                return Daemon {
                    child,
                    dir: dir.to_owned(),
                };
            }
            let _ = child.kill();
            let _ = child.wait();
            let log = fs::read_to_string(dir.join("bgpfcd.log")).unwrap_or_default();
            assert!(
                log.contains("Address already in use"),
                "the daemon did not start:\n{log}"
            );
        }
        panic!("no port to listen on was free in 8 tries");
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

/// What a stub read, in the order it came.
#[derive(Debug, Default)]
struct Read {
    announced: BTreeSet<Prefix>,
    withdrawn: BTreeSet<Prefix>,
    end_of_rib: Vec<AddressFamily>,
    /// Each ROUTE-REFRESH by its subtype, and each UPDATE as `None`.
    order: Vec<Option<RefreshSubtype>>,
}

impl Read {
    fn refreshes(&self) -> Vec<RefreshSubtype> {
        self.order.iter().flatten().copied().collect()
    }
}

/// A speaker the daemon connects to.
struct Stub {
    stream: TcpStream,
    /// The OPEN the daemon sent.
    theirs: OpenMessage,
}

/// The capabilities a stub advertises besides IPv4 unicast.
fn err() -> Vec<Capability> {
    vec![Capability::RouteRefresh, Capability::EnhancedRouteRefresh]
}

impl Stub {
    /// Wait for the daemon to connect and bring the session up, advertising
    /// IPv4 unicast and `caps`.
    fn accept(
        listener: &TcpListener,
        asn: u32,
        router_id: u32,
        caps: Vec<Capability>,
        d: &Daemon,
    ) -> Stub {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + TIMEOUT;
        let mut stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("the daemon never connected: {e}\n{}", d.log()),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut all = vec![Capability::Multiprotocol(V4)];
        all.extend(caps);
        let open = OpenMessage::new(
            Asn(asn),
            HoldTime::new(90).unwrap(),
            RouterId::new(router_id).unwrap(),
            all,
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

    /// Send a ROUTE-REFRESH of `subtype` for IPv4 unicast.
    fn refresh(&mut self, subtype: RefreshSubtype) {
        self.stream
            .write_all(
                &RouteRefreshMessage {
                    family: V4,
                    subtype,
                }
                .frame(),
            )
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
                    read.order.push(None);
                }
                Ok((MessageType::RouteRefresh, body)) => {
                    let m = RouteRefreshMessage::decode(&body, true).unwrap();
                    assert_eq!(m.family, V4);
                    read.order.push(Some(m.subtype));
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

    /// Whether nothing but KEEPALIVEs arrives in `wait`.
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

/// The two stubs' listeners, and the daemon pointed at them with `a_extra`
/// in A's block.
fn lab(name: &str, a_extra: &str) -> (Daemon, TcpListener, TcpListener) {
    let dir = scratch(name);
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.3:0").unwrap();
    let ports = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    (Daemon::start(&dir, ports, a_extra), a, b)
}

/// Both stubs up; A, with `caps`, has sent `routes` and B has them.
fn established(
    d: &Daemon,
    la: &TcpListener,
    lb: &TcpListener,
    caps: Vec<Capability>,
    routes: &[&str],
) -> (Stub, Stub) {
    let mut b = Stub::accept(lb, 65_002, 0xc000_0202, vec![], d);
    let mut a = Stub::accept(la, 65_001, 0xc000_0201, caps, d);
    a.announce(routes, &[65_001]);
    let got = b
        .read_until(d, |r| r.announced == set(routes))
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.announced, set(routes));
    (a, b)
}

#[test]
fn the_capability_is_advertised_unless_turned_off_and_used_when_both_have_it() {
    let (d, la, lb) = lab("err-capability", "");
    let a = Stub::accept(&la, 65_001, 0xc000_0201, err(), &d);
    // RFC 7313 §3.1, §4: the daemon advertised it once.
    assert_eq!(
        a.theirs
            .capabilities
            .iter()
            .filter(|c| **c == Capability::EnhancedRouteRefresh)
            .count(),
        1
    );
    let detail = d.wait_for("show neighbor 127.0.0.1", |r| r.contains("capabilities"));
    assert!(detail.contains("enhanced-route-refresh=true"), "{detail}");
    // A neighbor that did not advertise it is told so.
    let _b = Stub::accept(&lb, 65_002, 0xc000_0202, vec![Capability::RouteRefresh], &d);
    let detail = d.wait_for("show neighbor 127.0.0.3", |r| r.contains("capabilities"));
    assert!(detail.contains("enhanced-route-refresh=false"), "{detail}");
    drop((a, d));

    // `enhanced-refresh no` advertises nothing, whatever the neighbor does.
    let (d, la, _lb) = lab("err-capability-off", "enhanced-refresh no;");
    let a = Stub::accept(&la, 65_001, 0xc000_0201, err(), &d);
    assert!(
        !a.theirs
            .capabilities
            .contains(&Capability::EnhancedRouteRefresh)
    );
    let detail = d.wait_for("show neighbor 127.0.0.1", |r| r.contains("capabilities"));
    assert!(detail.contains("enhanced-route-refresh=false"), "{detail}");
}

#[test]
fn a_refresh_the_peer_makes_removes_the_routes_it_does_not_send_again() {
    let (d, la, lb) = lab("err-peer-refresh", "");
    let (mut a, mut b) = established(&d, &la, &lb, err(), &ROUTES);
    // RFC 7313 §4: at the BoRR all three are stale, and the daemon's other
    // neighbors hear nothing, for no best path changes.
    a.refresh(BORR);
    let detail = d.wait_for("show neighbor 127.0.0.1", |r| {
        r.contains("route refresh under way")
    });
    assert!(
        detail.contains("route refresh under way for ipv4-unicast: 3 stale routes, stale timer"),
        "{detail}"
    );
    d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
    assert!(b.is_quiet_for(Duration::from_millis(300)));
    // Two of them again: replaced, and still nothing for B.
    a.announce(&[ROUTES[0], ROUTES[1]], &[65_001]);
    d.wait_for("show routes", |r| r.matches(" stale").count() == 1);
    assert!(b.is_quiet_for(Duration::from_millis(300)));
    // The EoRR: the third goes, and B is told.
    a.refresh(EORR);
    let got = b
        .read_until(&d, |r| !r.withdrawn.is_empty())
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn, set(&[ROUTES[2]]));
    let routes = d.wait_for("show routes", |r| !r.contains(ROUTES[2]));
    assert!(!routes.contains(" stale"), "{routes}");
    let detail = d.ask("show neighbor 127.0.0.1").join("\n");
    assert!(!detail.contains("route refresh under way"), "{detail}");
    // The session was untouched.
    assert!(detail.contains("state Established"), "{detail}");
}

#[test]
fn a_refresh_that_is_never_ended_is_cut_off_by_the_stale_time() {
    let (d, la, lb) = lab("err-stale-time", "refresh-stale-time 1;");
    let (mut a, mut b) = established(&d, &la, &lb, err(), &ROUTES);
    a.refresh(BORR);
    // RFC 7313 §4: "an implementation MAY impose a locally configurable
    // upper bound": the routes go with no EoRR, after the second the
    // neighbor's block says.
    let got = b
        .read_until(&d, |r| r.withdrawn.len() == ROUTES.len())
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn, set(&ROUTES));
    let detail = d.ask("show neighbor 127.0.0.1").join("\n");
    assert!(!detail.contains("route refresh under way"), "{detail}");
    // An EoRR after that is one without a BoRR, ignored and logged.
    a.refresh(EORR);
    let log = d.wait_for("show neighbor 127.0.0.1", |_| d.log().contains("ignored"));
    assert!(log.contains("state Established"), "{log}");
    assert!(d.log().contains("EoRR without a BoRR"), "{}", d.log());
}

#[test]
fn a_refresh_the_peer_asks_for_is_a_borr_the_table_and_an_eorr() {
    let (d, la, lb) = lab("err-our-refresh", "");
    let mut b = Stub::accept(&lb, 65_002, 0xc000_0202, vec![], &d);
    b.announce(&ROUTES, &[65_002]);
    d.wait_for("show routes", |r| r.contains(ROUTES[2]));
    let mut a = Stub::accept(&la, 65_001, 0xc000_0201, err(), &d);
    // The initial update is no route refresh: no BoRR.
    let first = a
        .read_until(&d, |r| r.announced.len() == ROUTES.len())
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(first.refreshes(), vec![]);
    // RFC 7313 §4: a normal request is answered with a BoRR, the whole
    // Adj-RIB-Out and an EoRR, in that order.
    a.refresh(REQUEST);
    let got = a
        .read_until(&d, |r| r.refreshes().len() == 2)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.refreshes(), vec![BORR, EORR]);
    assert_eq!(got.order.first(), Some(&Some(BORR)));
    assert_eq!(got.order.last(), Some(&Some(EORR)));
    assert_eq!(got.announced, set(&ROUTES));
    assert!(got.order.len() >= 3);
    // Nothing is sent after the EoRR unless something changes.
    assert!(a.is_quiet_for(Duration::from_millis(300)));
}

#[test]
fn a_soft_reset_asks_for_the_routes_and_sends_ours_in_brackets() {
    let (d, la, lb) = lab("err-soft", "");
    let (mut a, mut b) = established(&d, &la, &lb, err(), &ROUTES);
    // Our own table to A, which the initial update sent.
    b.announce(&["100.64.0.0/10"], &[65_002]);
    a.read_until(&d, |r| r.announced.contains(&prefix("100.64.0.0/10")))
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    d.ask("clear neighbor 127.0.0.1 soft");
    // RFC 2918 §4: a request for A's routes, and our Adj-RIB-Out sent
    // again, which with RFC 7313 §4 is bracketed. The request has the
    // subtype 0 (§4: "a normal route refresh request").
    let got = a
        .read_until(&d, |r| r.refreshes().len() >= 3)
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    let refreshes = got.refreshes();
    assert!(refreshes.contains(&REQUEST), "{refreshes:?}");
    let begin = refreshes.iter().position(|s| *s == BORR).unwrap();
    let end = refreshes.iter().position(|s| *s == EORR).unwrap();
    assert!(begin < end, "{refreshes:?}");
    // A answers with a refresh of its own, leaving two of its three routes,
    // and the third goes.
    a.refresh(BORR);
    a.announce(&[ROUTES[0], ROUTES[1]], &[65_001]);
    a.refresh(EORR);
    let got = b
        .read_until(&d, |r| !r.withdrawn.is_empty())
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(got.withdrawn, set(&[ROUTES[2]]));
}

#[test]
fn a_borr_or_eorr_of_the_wrong_length_ends_the_session_with_a_route_refresh_error() {
    let (d, la, lb) = lab("err-length", "");
    let (mut a, _b) = established(&d, &la, &lb, err(), &ROUTES);
    // RFC 7313 §5: a BoRR with a fifth octet.
    let body = [0, 1, 1, 1, 0];
    a.stream
        .write_all(&frame(MessageType::RouteRefresh, &body).unwrap())
        .unwrap();
    let n = a
        .read_until(&d, |_| false)
        .unwrap_err()
        .expect("a NOTIFICATION");
    assert_eq!((n.code, n.subcode), (ErrorCode::RouteRefresh, 1));
    // "The Data field of the NOTIFICATION message MUST contain the complete
    // ROUTE-REFRESH message."
    assert_eq!(n.data, frame(MessageType::RouteRefresh, &body).unwrap());
    // The session is gone and its routes with it.
    d.wait_for("show routes", |r| !r.contains(ROUTES[0]));
}

#[test]
fn without_the_capability_the_message_subtype_is_ignored() {
    let (d, la, lb) = lab("err-plain", "");
    let mut b = Stub::accept(&lb, 65_002, 0xc000_0202, vec![], &d);
    b.announce(&["100.64.0.0/10"], &[65_002]);
    d.wait_for("show routes", |r| r.contains("100.64.0.0/10"));
    let mut a = Stub::accept(&la, 65_001, 0xc000_0201, vec![Capability::RouteRefresh], &d);
    a.read_until(&d, |r| r.announced.contains(&prefix("100.64.0.0/10")))
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    a.announce(&ROUTES, &[65_001]);
    let detail = d.wait_for("show neighbor 127.0.0.1", |r| r.contains("capabilities"));
    assert!(detail.contains("enhanced-route-refresh=false"), "{detail}");
    // RFC 2918 §3: a BoRR is a request to a speaker that ignores the
    // Reserved octet: our table is sent again, with no brackets, and
    // nothing is marked stale.
    a.refresh(BORR);
    let got = a
        .read_until(&d, |r| r.announced.contains(&prefix("100.64.0.0/10")))
        .unwrap_or_else(|e| panic!("{e:?}\n{}", d.log()));
    assert_eq!(
        got.refreshes(),
        vec![],
        "no brackets without the capability"
    );
    let routes = d.ask("show routes").join("\n");
    assert!(!routes.contains(" stale"), "{routes}");
    // And the wrong length is the header error it always was.
    let body = [0, 1, 1, 1, 0];
    a.stream
        .write_all(&frame(MessageType::RouteRefresh, &body).unwrap())
        .unwrap();
    let n = a
        .read_until(&d, |_| false)
        .unwrap_err()
        .expect("a NOTIFICATION");
    assert_eq!((n.code, n.subcode), (ErrorCode::MessageHeader, 2));
}

#[test]
fn a_borr_before_the_end_of_rib_of_a_graceful_restart_peer_is_ignored() {
    let (d, la, lb) = lab("err-gr", "graceful-restart yes;");
    let mut caps = err();
    caps.push(Capability::GracefulRestart(GracefulRestart {
        restarting: false,
        notification: true,
        restart_time: RestartTime::new(90).unwrap(),
        families: vec![GracefulRestartFamily {
            family: V4,
            forwarding: false,
        }],
    }));
    let (mut a, _b) = established(&d, &la, &lb, caps, &ROUTES);
    // RFC 7313 §4: it must be ignored, and an error logged.
    a.refresh(BORR);
    d.wait_for("show neighbor 127.0.0.1", |_| {
        d.log().contains("BoRR before the end-of-rib")
    });
    let routes = d.ask("show routes").join("\n");
    assert!(!routes.contains(" stale"), "{routes}");
    // Its End-of-RIB, and then a BoRR counts.
    a.end_of_rib();
    a.refresh(BORR);
    d.wait_for("show routes", |r| r.matches(" stale").count() == 3);
}
