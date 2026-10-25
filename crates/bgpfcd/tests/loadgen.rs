//! The load generator against the daemon over localhost
//! (`docs/PROFILING.md`): a 10 000-prefix synthetic table must end up in
//! the RIB exactly, and the report lines must parse; with two peers, the
//! table one sends reaches the other and no session resets.
//!
//! Needs a profiling build and free localhost ports (127.0.0.1 and
//! 127.0.0.2):
//!
//! ```sh
//! cargo test -p bgpfcd --features profiling -- --ignored
//! ```
#![cfg(feature = "profiling")]

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use bgpfc_bench::scenario::{Plan, Scenario, Source, run};
use bgpfc_bench::speaker::{Endpoint, SpeakerOpts};
use bgpfc_control::proto::{Request, Response};
use bgpfc_prof::report::{get, get_u64};
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};

const PREFIXES: usize = 10_000;

/// Prefixes, twenty to an attribute set and so about to an UPDATE: enough
/// UPDATEs to fill the RIB's queue (1024) and a peer's (256).
const TWO_PEER_PREFIXES: usize = 100_000;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn ask(socket: &Path, command: &str) -> Vec<String> {
    let mut s = UnixStream::connect(socket).unwrap();
    let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
    s.write_all(Request::format(&words).as_bytes()).unwrap();
    let r = Response::read_from(&mut BufReader::new(s)).unwrap();
    assert_eq!(r.status, Ok(()), "{command}: {:?}", r.lines);
    r.lines
}

/// `ask`, retried until `done` holds of the answer (the socket may not be
/// there yet).
fn wait_for(socket: &Path, command: &str, done: impl Fn(&str) -> bool) -> String {
    for _ in 0..600 {
        if UnixStream::connect(socket).is_ok() {
            let answer = ask(socket, command).join("\n");
            if done(&answer) {
                return answer;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("{command}: no answer as expected");
}

/// Start bgpfcd in `dir`, listening on `port` with 127.0.0.1 as a passive
/// neighbor and `more` appended to the configuration; its report lines
/// arrive on the receiver.
fn start_daemon(dir: &Path, port: u16, more: &str) -> (Child, Receiver<String>) {
    let conf = dir.join("bgpfcd.conf");
    std::fs::write(
        &conf,
        format!(
            "router-id 192.0.2.1;\nlocal-as 65000;\nlog {{ level warn; }}\n\
             listen {{ address 127.0.0.1; port {port}; }}\nfib {{ mode dry-run; }}\n\
             control {{ socket {}; }}\npolicy ANY {{ term all {{ action accept; }} }}\n\
             neighbor 127.0.0.1 {{ remote-as 65001; passive yes; import ANY; export ANY; }}\n\
             {more}",
            dir.join("ctl.sock").display()
        ),
    )
    .unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_bgpfcd"))
        .arg("-c")
        .arg(&conf)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let stderr = daemon.stderr.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("msg=\"profile\"") && tx.send(line).is_err() {
                return;
            }
        }
    });
    (daemon, rx)
}

/// The next report line of `event`.
fn next(rx: &Receiver<String>, event: &str) -> String {
    loop {
        let line = rx
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("no {event} report"));
        if get(&line, "event") == Some(event) {
            return line;
        }
    }
}

/// A synthetic table of [`PREFIXES`] for the daemon on `port`, the session
/// held until the daemon stops.
fn plan(port: u16) -> Plan {
    Plan {
        endpoint: Endpoint::Connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        speaker: SpeakerOpts {
            asn: Asn(65_001),
            router_id: RouterId::from(Ipv4Addr::new(192, 0, 2, 254)),
            hold_time: HoldTime::new(90).unwrap(),
            families: vec![AddressFamily::IPV4_UNICAST],
            extended: false,
        },
        source: Source::Synthetic {
            prefixes: PREFIXES,
            attr_sets: 500,
            seed: 7,
            next_hops: vec![Ipv4Addr::new(192, 0, 2, 9)],
        },
        scenario: Scenario::Load,
        seed: 7,
        hold: Some(Duration::from_secs(120)),
        timeout: Duration::from_secs(30),
    }
}

#[test]
#[ignore = "starts bgpfcd on a localhost port; run with --features profiling -- --ignored"]
fn a_synthetic_table_fills_the_rib_exactly() {
    let dir = std::env::temp_dir().join(format!("bgpfcd-loadgen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let (mut daemon, rx) = start_daemon(&dir, port, "");
    let loadgen = thread::spawn(move || {
        let mut out = Vec::new();
        run(&plan(port), &mut out).map(|()| String::from_utf8(out).unwrap())
    });

    let load = next(&rx, "table_load");
    assert_eq!(get(&load, "end"), Some("eor"), "{load}");
    assert_eq!(get_u64(&load, "prefixes"), Some(PREFIXES as u64), "{load}");
    for key in [
        "load_us",
        "bytes_per_prefix",
        "live",
        "peak",
        "allocs",
        "hwm_kb",
    ] {
        assert!(
            get_u64(&load, key).is_some_and(|v| v > 0),
            "{key} in {load}"
        );
    }
    let dup = next(&rx, "duplication");
    assert_eq!(get_u64(&dup, "routes"), Some(PREFIXES as u64), "{dup}");
    assert_eq!(get_u64(&dup, "attr_sets"), get_u64(&dup, "attr_values"));

    // The RIB holds the table exactly, as the stats line and the neighbor
    // summary both say.
    let socket = dir.join("ctl.sock");
    let lines = ask(&socket, "stats");
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_eq!(
        get_u64(line, "rib_prefixes"),
        Some(PREFIXES as u64),
        "{line}"
    );
    assert_eq!(get_u64(line, "adj_rib_in"), Some(PREFIXES as u64), "{line}");
    assert_eq!(get_u64(line, "prefixes_announced"), Some(PREFIXES as u64));
    assert_eq!(get_u64(line, "rib_insert.count"), Some(PREFIXES as u64));
    assert_eq!(
        get_u64(line, "updates_rx"),
        get_u64(line, "msg_parse_update.count")
    );
    let neighbors = ask(&socket, "show neighbors").join("\n");
    assert!(neighbors.contains(&PREFIXES.to_string()), "{neighbors}");

    let killed = Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let shutdown = next(&rx, "shutdown");
    assert!(get_u64(&shutdown, "live").is_some(), "{shutdown}");
    assert!(daemon.wait().unwrap().success());

    let out = loadgen.join().unwrap().unwrap();
    assert!(out.contains("phase=load"), "{out}");
    assert!(out.contains("event=closed by=peer"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two peers send the same table, the second first. Each route of the
/// first replaces the second's as the best (lower peer address, RFC 4271
/// §9.1.2.2 g), so the RIB withdraws it from the first peer while that
/// peer is still sending. Enough UPDATEs to fill the RIB's queue and then
/// the peer's: the withdrawals must not wait in the input queue the
/// peer's own UPDATEs fill, where they found no room and reset the
/// session (Cease, Out of Resources).
#[test]
#[ignore = "starts bgpfcd on localhost ports; run with --features profiling -- --ignored"]
fn a_table_reaches_a_second_peer_and_no_session_resets() {
    let dir = std::env::temp_dir().join(format!("bgpfcd-two-peers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let listener = TcpListener::bind("127.0.0.2:0").unwrap();
    let second = format!(
        "neighbor 127.0.0.2 {{ remote-as 65001; port {}; connect-retry-time 1; \
         import ANY; export ANY; }}\n",
        listener.local_addr().unwrap().port()
    );
    let (mut daemon, rx) = start_daemon(&dir, port, &second);
    let table = |mut p: Plan| {
        if let Source::Synthetic {
            prefixes,
            attr_sets,
            ..
        } = &mut p.source
        {
            *prefixes = TWO_PEER_PREFIXES;
            *attr_sets = TWO_PEER_PREFIXES / 20;
        }
        p
    };
    let mut b = table(plan(port));
    b.endpoint = Endpoint::Listen(listener);
    b.hold = None;
    let b = thread::spawn(move || {
        let mut out = Vec::new();
        run(&b, &mut out).map(|()| String::from_utf8(out).unwrap())
    });
    let load = next(&rx, "table_load");
    assert_eq!(get(&load, "peer"), Some("127.0.0.2"), "{load}");
    let a = thread::spawn(move || {
        let mut out = Vec::new();
        run(&table(plan(port)), &mut out).map(|()| String::from_utf8(out).unwrap())
    });

    let load = next(&rx, "table_load");
    assert_eq!(get(&load, "peer"), Some("127.0.0.1"), "{load}");
    assert_eq!(get_u64(&load, "prefixes"), Some(TWO_PEER_PREFIXES as u64));
    let socket = dir.join("ctl.sock");
    wait_for(&socket, "show neighbor 127.0.0.2", |a| {
        a.contains(&format!("advertised {TWO_PEER_PREFIXES}"))
    });
    wait_for(&socket, "show neighbor 127.0.0.1", |a| {
        a.contains("advertised 0")
    });
    let neighbors = ask(&socket, "show neighbors").join("\n");
    assert_eq!(neighbors.matches("Established").count(), 2, "{neighbors}");

    let killed = Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    assert!(daemon.wait().unwrap().success());
    for out in [a.join().unwrap().unwrap(), b.join().unwrap().unwrap()] {
        assert!(
            out.contains("notification=Cease/Administrative_Shutdown"),
            "{out}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
