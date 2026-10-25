//! ADD-PATH (RFC 7911) between the daemon as a process and two stub
//! speakers on localhost, where no privilege is needed. Stub A sends the
//! daemon several paths to one prefix, each under a Path Identifier of its
//! own (§3); stub B is sent them, each under an identifier of the daemon's,
//! and told by that identifier which one is withdrawn (§5). A peer that
//! did not advertise the Receive half is sent one path without identifiers,
//! as RFC 4271 has it (§5).
//!
//! The daemon connects to the stubs, which listen on 127.0.0.2 and
//! 127.0.0.3: any address of 127.0.0.0/8 is loopback on Linux.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_bench::speaker::read_message;
use bgpfc_control::proto::{Request, Response};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::capability::{AddPathMode, AddPathTuple, Capability};
use bgpfc_wire::header::{MessageType, frame};
use bgpfc_wire::keepalive::KEEPALIVE;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, PathId, RouterId};
use bgpfc_wire::update::{
    AddPathFamilies, DecodeContext, EncodeContext, PathIds, PeerKind, UpdateMessage,
};

const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const TIMEOUT: Duration = Duration::from_secs(20);

/// A next hop that is not loopback: the daemon ignores routes through one
/// (RFC 4271 §6.3, RFC 7606 §7.11).
const NEXT_HOP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

/// A directory of its own for one test, under the system's temporary
/// directory.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bgpfcd-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn prefix() -> Prefix {
    "198.51.100.0/24".parse().unwrap()
}

/// The daemon, killed when the test ends.
struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Daemon {
    /// Start it with neighbor A (127.0.0.2, receives paths from it) and
    /// neighbor B (127.0.0.3, is sent them) on the stubs' ports.
    fn start(dir: &Path, port_a: u16, port_b: u16) -> Daemon {
        let conf = dir.join("bgpfcd.conf");
        let listen = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_port = listen.local_addr().unwrap().port();
        drop(listen);
        fs::write(
            &conf,
            format!(
                "router-id 192.0.2.1;\nlocal-as 65000;\nlog {{ level warn; }}\n\
                 listen {{ address 127.0.0.1; port {listen_port}; }}\n\
                 fib {{ mode dry-run; }}\ncontrol {{ socket {}; }}\n\
                 policy ANY {{ term all {{ action accept; }} }}\n\
                 neighbor 127.0.0.2 {{ remote-as 65001; port {port_a}; families ipv4-unicast;\n\
                   import ANY; export ANY; advertisement-interval 0;\n\
                   add-path receive ipv4-unicast yes; }}\n\
                 neighbor 127.0.0.3 {{ remote-as 65002; port {port_b}; families ipv4-unicast;\n\
                   import ANY; export ANY; advertisement-interval 0;\n\
                   add-path send ipv4-unicast all; }}\n",
                dir.join("ctl.sock").display()
            ),
        )
        .unwrap();
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
        }
    }

    /// What the daemon has logged, for a failing test to show.
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

/// What an UPDATE did to one path.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    /// Announced under this identifier (none without ADD-PATH), along
    /// this AS path.
    Announce(Option<u32>, Vec<u32>),
    /// Withdrawn under this identifier.
    Withdraw(Option<u32>),
}

/// A speaker the daemon connects to.
struct Stub {
    stream: TcpStream,
    /// The families whose UPDATEs carry Path Identifiers between us and the
    /// daemon, in the one direction this stub uses.
    paths: AddPathFamilies,
}

impl Stub {
    /// Wait for the daemon to connect and bring the session up, with
    /// `mode` advertised for IPv4 unicast, if any.
    fn accept(
        listener: &TcpListener,
        asn: u32,
        router_id: u32,
        mode: Option<AddPathMode>,
        daemon: &Daemon,
    ) -> Stub {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + TIMEOUT;
        let mut stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("the daemon never connected: {e}\n{}", daemon.log()),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut caps = vec![Capability::Multiprotocol(V4)];
        caps.extend(mode.map(|mode| Capability::AddPath(vec![AddPathTuple { family: V4, mode }])));
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
        assert_eq!(kind, MessageType::Open, "{}", daemon.log());
        let theirs = OpenMessage::decode(&body).unwrap();
        // RFC 7911 §5: identifiers are in use in a direction where one side
        // can send and the other receive. Each stub uses one direction, so
        // one flag says how its UPDATEs are encoded or decoded.
        let (daemon_receives, daemon_sends) =
            bgpfc_wire::capability::add_path_abilities(&theirs.capabilities, V4);
        let paths = match mode {
            Some(m) if (m.sends() && daemon_receives) || (m.receives() && daemon_sends) => {
                AddPathFamilies::of(&[V4])
            }
            _ => AddPathFamilies::NONE,
        };
        Stub { stream, paths }
    }

    /// Send an UPDATE announcing the prefix along `path` under `id`.
    fn announce(&mut self, id: u32, path: &[u32], next_hop: Ipv4Addr) {
        let hops: Vec<Asn> = path.iter().map(|a| Asn(*a)).collect();
        let message = UpdateMessage {
            nlri: vec![prefix()],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&hops)),
                PathAttribute::NextHop(next_hop),
            ],
            path_ids: Some(Box::new(PathIds {
                nlri: vec![PathId(id)],
                ..PathIds::default()
            })),
            ..UpdateMessage::default()
        };
        self.send(&message);
    }

    /// Send an UPDATE withdrawing the path `id` of the prefix.
    fn withdraw(&mut self, id: u32) {
        let message = UpdateMessage {
            withdrawn: vec![prefix()],
            path_ids: Some(Box::new(PathIds {
                withdrawn: vec![PathId(id)],
                ..PathIds::default()
            })),
            ..UpdateMessage::default()
        };
        self.send(&message);
    }

    fn send(&mut self, message: &UpdateMessage) {
        let body = message
            .encode(&EncodeContext {
                four_octet_as: true,
                extended_next_hop: false,
                add_path: self.paths,
            })
            .unwrap();
        self.stream
            .write_all(&frame(MessageType::Update, &body).unwrap())
            .unwrap();
    }

    /// The paths announced or withdrawn by the next `n` UPDATEs' worth of
    /// events, KEEPALIVEs skipped.
    fn events(&mut self, n: usize, daemon: &Daemon) -> Vec<Event> {
        let ctx = DecodeContext {
            four_octet_as: true,
            peer: PeerKind::External,
            allow_as_set: false,
            extended_next_hop: false,
            add_path: self.paths,
        };
        let mut out = Vec::new();
        while out.len() < n {
            let (kind, body) = read_message(&mut self.stream, false)
                .unwrap_or_else(|e| panic!("{e}\n{}", daemon.log()));
            match kind {
                MessageType::Keepalive => {}
                MessageType::Update => {
                    let d = UpdateMessage::decode(&body, &ctx).unwrap();
                    // The daemon's address on a loopback session is a
                    // loopback next hop, which this decoder (RFC 7606
                    // §7.11, Invalid NEXT_HOP, subcode 8) flags; nothing
                    // else may be wrong with the message.
                    assert!(
                        d.treated_as_withdraw
                            .as_ref()
                            .is_none_or(|e| e.subcode == 8)
                            && d.disabled.is_empty(),
                        "{d:?}"
                    );
                    out.extend(events_of(&d.message));
                }
                other => panic!("unexpected {other:?}\n{}", daemon.log()),
            }
        }
        out
    }
}

/// The events of one UPDATE: its withdrawals, then its announcements.
fn events_of(m: &UpdateMessage) -> Vec<Event> {
    let ids = m.path_ids.as_deref();
    let id =
        |list: fn(&PathIds) -> &[PathId], i: usize| ids.and_then(|p| list(p).get(i)).map(|p| p.0);
    let path: Vec<u32> = m
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p.asns().map(|a| a.0).collect()),
            _ => None,
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for (i, p) in m.withdrawn.iter().enumerate() {
        assert_eq!(*p, prefix());
        out.push(Event::Withdraw(id(|p| &p.withdrawn, i)));
    }
    for (i, p) in m.nlri.iter().enumerate() {
        assert_eq!(*p, prefix());
        out.push(Event::Announce(id(|p| &p.nlri, i), path.clone()));
    }
    out
}

/// The two stubs' listeners, and the daemon pointed at them.
fn lab(name: &str) -> (Daemon, TcpListener, TcpListener) {
    let dir = scratch(name);
    let a = TcpListener::bind("127.0.0.2:0").unwrap();
    let b = TcpListener::bind("127.0.0.3:0").unwrap();
    let ports = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    (Daemon::start(&dir, ports.0, ports.1), a, b)
}

#[test]
fn several_paths_in_and_out_each_under_its_own_identifier() {
    let (daemon, la, lb) = lab("add-path-both");
    // A sends paths (Send), B takes them (Receive).
    let mut a = Stub::accept(&la, 65_001, 0xc000_0201, Some(AddPathMode::Send), &daemon);
    let mut b = Stub::accept(
        &lb,
        65_002,
        0xc000_0202,
        Some(AddPathMode::Receive),
        &daemon,
    );
    assert!(
        !a.paths.is_empty() && !b.paths.is_empty(),
        "{}",
        daemon.log()
    );

    // RFC 7911 §3: two paths to one prefix, told apart by identifier.
    a.announce(11, &[65_001], NEXT_HOP);
    a.announce(12, &[65_001, 64_999], NEXT_HOP);
    let got = b.events(2, &daemon);
    // RFC 7911 §5: re-advertised under identifiers of the daemon's, not
    // the ones A used, one for each path.
    let ids: BTreeMap<Vec<u32>, u32> = got
        .iter()
        .map(|e| match e {
            Event::Announce(Some(id), path) => (path.clone(), *id),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        ids.keys().cloned().collect::<Vec<_>>(),
        vec![vec![65_000, 65_001], vec![65_000, 65_001, 64_999]],
        "{got:?}"
    );
    assert_ne!(
        ids[&vec![65_000, 65_001]],
        ids[&vec![65_000, 65_001, 64_999]]
    );

    // The control plane shows the identifiers each path came with.
    let routes = daemon.wait_for("show routes 198.51.100.0/24", |r| {
        r.contains("id 11") && r.contains("id 12")
    });
    assert_eq!(routes.matches('*').count(), 1, "{routes}");
    // B is advertised both, and told so.
    let detail = daemon.wait_for("show neighbor 127.0.0.3", |r| {
        r.contains("ipv4-unicast received 0 advertised 2")
    });
    assert!(
        detail.contains("add-path receive none send ipv4-unicast=all"),
        "{detail}"
    );
    let detail = daemon.ask("show neighbor 127.0.0.2").join("\n");
    assert!(
        detail.contains("add-path receive ipv4-unicast send none"),
        "{detail}"
    );

    // RFC 7911 §5: a withdrawal for an identifier never announced is not
    // an error, the session stays and nothing is withdrawn.
    a.withdraw(99);
    // The withdrawal of one path names the identifier the daemon gave it.
    a.withdraw(11);
    assert_eq!(
        b.events(1, &daemon),
        vec![Event::Withdraw(Some(ids[&vec![65_000, 65_001]]))],
        "{}",
        daemon.log()
    );
    a.withdraw(12);
    assert_eq!(
        b.events(1, &daemon),
        vec![Event::Withdraw(Some(ids[&vec![65_000, 65_001, 64_999]]))],
        "{}",
        daemon.log()
    );
    daemon.wait_for("show routes 198.51.100.0/24", |r| {
        !r.contains("198.51.100.0/24")
    });
}

#[test]
fn a_peer_that_did_not_ask_for_paths_gets_the_best_one_alone() {
    let (daemon, la, lb) = lab("add-path-plain");
    let mut a = Stub::accept(&la, 65_001, 0xc000_0201, Some(AddPathMode::Send), &daemon);
    // B advertises nothing: `add-path send` is configured, but RFC 7911 §5
    // wants the peer's Receive too, and without it the encoding is
    // RFC 4271's.
    let mut b = Stub::accept(&lb, 65_002, 0xc000_0202, None, &daemon);
    assert!(!a.paths.is_empty() && b.paths.is_empty());

    a.announce(11, &[65_001, 64_999], NEXT_HOP);
    assert_eq!(
        b.events(1, &daemon),
        vec![Event::Announce(None, vec![65_000, 65_001, 64_999])]
    );
    // A shorter path takes over: one announcement replaces the route.
    a.announce(12, &[65_001], NEXT_HOP);
    assert_eq!(
        b.events(1, &daemon),
        vec![Event::Announce(None, vec![65_000, 65_001])]
    );
    // Withdrawing the best one falls back to the other, with no withdrawal.
    a.withdraw(12);
    assert_eq!(
        b.events(1, &daemon),
        vec![Event::Announce(None, vec![65_000, 65_001, 64_999])]
    );
    let detail = daemon.ask("show neighbor 127.0.0.3").join("\n");
    assert!(!detail.contains("add-path"), "{detail}");
    // The other direction is in use all the same.
    let detail = daemon.ask("show neighbor 127.0.0.2").join("\n");
    assert!(
        detail.contains("add-path receive ipv4-unicast send none"),
        "{detail}"
    );
    a.withdraw(11);
    assert_eq!(b.events(1, &daemon), vec![Event::Withdraw(None)]);
}
