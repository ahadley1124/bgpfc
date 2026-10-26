//! The Routinator sidecar (AGENTS.md §9 step 14) in the daemon as a process,
//! where no privilege is needed. A shell script stands in for Routinator,
//! never the real one (AGENTS.md §5, `bgpfc-sidecar` row): it answers
//! `--version` as the supported release and otherwise exits, hangs or
//! ignores `SIGTERM`, as each test needs. A cache of this file stands in
//! for the RTR listener Routinator would open, on the port the block names.
//!
//! What the tests show: the stub runs with the command line the settings
//! derive, the RTR client reads from the port it serves on, the state is in
//! `show rpki` and the HTTP API, a reload moves the child only when its
//! block changes and fails before stopping anything when the new binary
//! would not start, a child that ignores `SIGTERM` is killed, one that
//! exits is restarted and then reported failed, and the child never
//! outlives the daemon, even when the daemon is killed.
//!
//! The daemon listens on 127.0.0.2, and the stubs' RTR cache on 127.0.0.1:
//! any address of 127.0.0.0/8 is loopback on Linux.

use std::fs;
use std::io::{BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_control::proto::{Request, Response};
use bgpfc_rpki::Vrp;
use bgpfc_rtr::{Framer, Intervals, Pdu};
use bgpfc_wire::types::Asn;

/// How long a test waits for something to happen.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A directory for one test, removed when the test ends.
struct Scratch(PathBuf);

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("bgpfcd-sidecar-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

impl Scratch {
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// An executable `#!/bin/sh` script. Another process writes it: were
    /// this one to hold it open for writing while a parallel test forks,
    /// the forked child would hold it too until it executes, and running
    /// the script meanwhile would fail with `ETXTBSY`.
    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.join(name);
        let status = Command::new("/bin/sh")
            .args([
                "-c",
                "printf '%s' \"$1\" > \"$2\" && chmod 755 \"$2\"",
                "sh",
            ])
            .arg(format!("#!/bin/sh\n{body}\n"))
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success(), "writing {}", path.display());
        path
    }

    /// A Routinator that reports `version`, and otherwise runs `body`.
    fn routinator_of(&self, name: &str, version: &str, body: &str) -> PathBuf {
        self.script(
            name,
            &format!(
                "if [ \"$1\" = --version ]; then echo 'Routinator {version}'; exit 0; fi\n{body}"
            ),
        )
    }

    /// A Routinator of the supported release that runs `body`.
    fn routinator(&self, name: &str, body: &str) -> PathBuf {
        self.routinator_of(name, "0.15.2", body)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Poll `probe` until it returns something.
fn wait_until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(found) = probe() {
            return found;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(25));
    }
}

/// Whether process `pid` is running. A zombie is not: it has exited, and
/// whoever is meant to reap it has not yet.
fn alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            // The state is the field after the command name, which is
            // parenthesised and may itself contain parentheses.
            let (_, rest) = stat.rsplit_once(')')?;
            rest.trim_start().chars().next()
        })
        .is_some_and(|state| state != 'Z')
}

fn kill(signal: &str, pid: u32) {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill {signal} {pid}");
}

fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
    Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
}

/// An RTR cache (RFC 8210) on the loopback that serves the same VRPs to
/// every connection: all of them to a Reset Query, and "nothing changed" to
/// a Serial Query.
struct Cache {
    port: u16,
}

impl Cache {
    fn start(vrps: Vec<Vrp>) -> Cache {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let vrps = Arc::new(vrps);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let vrps = Arc::clone(&vrps);
                thread::spawn(move || serve(stream, &vrps));
            }
        });
        Cache { port }
    }

    /// A port nothing listens on.
    fn closed_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}

/// The cache's Session ID and the one serial it serves.
const SESSION: u16 = 9;
const SERIAL: u32 = 1;

fn serve(mut stream: TcpStream, vrps: &[Vrp]) {
    let mut framer = Framer::new();
    let mut buf = [0; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => framer.feed(&buf[..n]),
        }
        while let Ok(Some(pdu)) = framer.next_pdu() {
            let (version, all) = match pdu {
                Pdu::ResetQuery { version } => (version, true),
                Pdu::SerialQuery { version, .. } => (version, false),
                _ => continue,
            };
            let mut out = Pdu::CacheResponse {
                version,
                session_id: SESSION,
            }
            .encode();
            if all {
                for &vrp in vrps {
                    Pdu::Prefix {
                        version,
                        announce: true,
                        vrp,
                    }
                    .encode_into(&mut out);
                }
            }
            Pdu::EndOfData {
                session_id: SESSION,
                serial: SERIAL,
                intervals: Some(Intervals::DEFAULT),
            }
            .encode_into(&mut out);
            if stream.write_all(&out).is_err() {
                return;
            }
        }
    }
}

/// An `rpki` block that runs `binary` as a sidecar serving RTR on `port`,
/// with `rpki` more statements for the block and `routinator` for the
/// `routinator` block. It states `invalid drop`, which acts on nothing
/// without a BGP neighbor.
fn sidecar_block(dir: &Scratch, binary: &Path, port: u16, rpki: &str, routinator: &str) -> String {
    format!(
        "rpki {{ mode sidecar; invalid drop; {rpki}\n\
         routinator {{ binary {}; repository-dir {}; rtr-listen 127.0.0.1:{port}; {routinator} }} }}\n",
        binary.display(),
        dir.join("repo").display()
    )
}

/// The daemon, killed when the test ends.
struct Daemon {
    child: Child,
    dir: PathBuf,
    listen_port: u16,
    http_port: u16,
}

/// The configuration file around an `rpki` block.
fn config_text(dir: &Path, listen_port: u16, http_port: u16, rpki: &str) -> String {
    format!(
        "router-id 192.0.2.1;\nlocal-as 65000;\nlog {{ level info; }}\n\
         listen {{ address 127.0.0.2; port {listen_port}; }}\n\
         fib {{ mode dry-run; }}\n\
         control {{ socket {}; http {{ listen 127.0.0.1:{http_port}; }} }}\n{rpki}",
        dir.join("ctl.sock").display()
    )
}

fn free_port(address: &str) -> u16 {
    TcpListener::bind((address, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn bgpfcd(conf: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bgpfcd"));
    cmd.arg("-c").arg(conf);
    cmd
}

impl Daemon {
    /// Start it with `rpki` as its `rpki` block. The ports it listens on
    /// are ones that were free a moment ago: another test or process can
    /// take one in between, and the daemon then exits with "Address already
    /// in use" before it opens its control socket; it is started again on
    /// others.
    fn start(dir: &Scratch, rpki: &str) -> Daemon {
        let conf = dir.join("bgpfcd.conf");
        for _ in 0..8 {
            let (listen_port, http_port) = (free_port("127.0.0.2"), free_port("127.0.0.1"));
            fs::write(&conf, config_text(&dir.0, listen_port, http_port, rpki)).unwrap();
            let log = fs::File::create(dir.join("bgpfcd.log")).unwrap();
            let child = bgpfcd(&conf)
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap();
            let mut daemon = Daemon {
                child,
                dir: dir.0.clone(),
                listen_port,
                http_port,
            };
            // The control socket is opened after the listeners.
            let socket = dir.join("ctl.sock");
            let deadline = Instant::now() + TIMEOUT;
            while !socket.exists() && Instant::now() < deadline {
                if daemon.exited() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            if socket.exists() && !daemon.exited() {
                return daemon;
            }
            let log = daemon.log();
            assert!(
                log.contains("Address already in use"),
                "the daemon did not start:\n{log}"
            );
            let _ = daemon.child.kill();
            let _ = daemon.child.wait();
            // The stale socket of the failed attempt is not this one.
            let _ = fs::remove_file(socket);
        }
        panic!("no ports to listen on were free in 8 tries");
    }

    fn exited(&mut self) -> bool {
        self.child.try_wait().unwrap().is_some()
    }

    /// Replace the `rpki` block of the configuration file.
    fn rewrite(&self, rpki: &str) {
        fs::write(
            self.dir.join("bgpfcd.conf"),
            config_text(&self.dir, self.listen_port, self.http_port, rpki),
        )
        .unwrap();
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.join("bgpfcd.log")).unwrap_or_default()
    }

    /// The control socket's answer to `command`, error or not.
    fn request(&self, command: &str) -> Response {
        let socket = self.dir.join("ctl.sock");
        let mut stream = UnixStream::connect(&socket)
            .unwrap_or_else(|e| panic!("{command}: {e}\n{}", self.log()));
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        stream
            .write_all(Request::format(&words).as_bytes())
            .unwrap();
        Response::read_from(&mut BufReader::new(stream)).unwrap()
    }

    /// The control socket's answer to `command`, which must succeed.
    fn ask(&self, command: &str) -> String {
        let r = self.request(command);
        assert_eq!(r.status, Ok(()), "{command}: {:?}\n{}", r.lines, self.log());
        r.lines.join("\n")
    }

    /// `ask` until `done` holds of the answer.
    fn wait_for(&self, command: &str, done: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let answer = self.ask(command);
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

    /// Wait until `show rpki` shows the sidecar running, and return the
    /// child's process id.
    fn sidecar_pid(&self) -> u32 {
        let shown = self.wait_for("show rpki", |r| r.contains("sidecar state running, pid "));
        pid_of(&shown)
    }

    /// An HTTP GET of `path` on the API, the body of the answer.
    fn http_get(&self, path: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", self.http_port)).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        answer
            .split_once("\r\n\r\n")
            .map_or_else(String::new, |(_, body)| body.to_owned())
    }

    /// `SIGTERM` the daemon and wait for it to exit.
    fn terminate(&mut self) -> ExitStatus {
        kill("-TERM", self.child.id());
        wait_until("the daemon to exit", || self.child.try_wait().unwrap())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The process id in a `sidecar state running, pid N, up Ms` line.
fn pid_of(shown: &str) -> u32 {
    let line = shown
        .lines()
        .find(|l| l.starts_with("sidecar state running, pid "))
        .unwrap_or_else(|| panic!("no running sidecar in:\n{shown}"));
    line["sidecar state running, pid ".len()..]
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// What `show rpki` says once the client has the VRPs from the cache at
/// `port`.
fn loaded(port: u16) -> impl Fn(&str) -> bool {
    move |shown| shown.contains(&format!("from 127.0.0.1:{port}"))
}

#[test]
fn the_daemon_runs_the_sidecar_and_reads_its_vrps_from_the_port() {
    let dir = scratch("wiring");
    let argv_file = dir.join("argv");
    let stub = dir.routinator(
        "routinator",
        &format!("echo \"$@\" > '{}'\nexec sleep 300", argv_file.display()),
    );
    let cache = Cache::start(vec![vrp("192.0.2.0/24", 24, 64_496)]);
    let mut daemon = Daemon::start(&dir, &sidecar_block(&dir, &stub, cache.port, "", ""));

    // The cache here is not the child, so the client can have its VRPs
    // before the supervisor has started the stub: wait for both.
    let has_vrps = loaded(cache.port);
    let shown = daemon.wait_for("show rpki", |r| {
        has_vrps(r) && r.contains("sidecar state running, pid ")
    });
    let pid = pid_of(&shown);
    assert!(shown.contains("mode sidecar\ninvalid drop\n"), "{shown}");
    assert!(
        shown.contains(&format!(
            "sidecar routinator 0.15.2 {}, rtr 127.0.0.1:{}",
            stub.display(),
            cache.port
        )),
        "{shown}"
    );
    assert!(shown.contains("sidecar restarts 0 failures 0"), "{shown}");
    assert!(shown.contains("vrps ipv4 1 ipv6 0 from"), "{shown}");
    // The client read from the sidecar's port, and the VRPs are the ones the
    // RIB validates with.
    assert!(
        daemon
            .ask("show rpki validate 192.0.2.0/24 64496")
            .starts_with("192.0.2.0/24 origin AS64496: valid"),
    );

    // Routinator got the command line the settings derive, serving where
    // the client connects.
    let argv = wait_until("the stub to run", || fs::read_to_string(&argv_file).ok());
    assert_eq!(
        argv.trim(),
        format!(
            "--repository-dir={} --no-rir-tals --tal=afrinic --tal=apnic --tal=lacnic \
             --tal=ripe server --rtr=127.0.0.1:{} --refresh=600",
            dir.join("repo").display(),
            cache.port
        )
    );

    // The HTTP API has it too.
    let json = daemon.http_get("/v1/rpki");
    assert!(
        json.contains(&format!(
            "\"sidecar\":{{\"state\":\"running\",\"failed\":false,\"pid\":{pid},"
        )),
        "{json}"
    );
    assert!(
        json.contains(&format!(
            "\"rtr\":{{\"host\":\"127.0.0.1\",\"port\":{}}}",
            cache.port
        )),
        "{json}"
    );
    assert!(json.contains("\"version\":\"0.15.2\""), "{json}");

    // A clean shutdown stops the child, and the daemon says so.
    assert!(alive(pid));
    let status = daemon.terminate();
    assert!(status.success(), "{status}\n{}", daemon.log());
    assert!(!alive(pid), "the child outlived the daemon");
    let log = daemon.log();
    assert!(log.contains("msg=\"RPKI sidecar stopped\""), "{log}");
    assert!(log.contains("msg=\"bgpfcd stopped\""), "{log}");
}

#[test]
fn a_killed_daemon_takes_the_child_with_it() {
    // PR_SET_PDEATHSIG fires when the thread that spawned the child exits,
    // and the thread that spawns it lives as long as the daemon: no
    // shutdown code runs here, and the child still goes.
    let dir = scratch("killed");
    let stub = dir.routinator("routinator", "exec sleep 300");
    let mut daemon = Daemon::start(
        &dir,
        &sidecar_block(&dir, &stub, Cache::closed_port(), "", ""),
    );
    let pid = daemon.sidecar_pid();
    assert!(alive(pid));
    daemon.child.kill().unwrap();
    daemon.child.wait().unwrap();
    wait_until("the child to die with the daemon", || {
        (!alive(pid)).then_some(())
    });
}

#[test]
fn a_child_that_ignores_sigterm_is_killed_when_the_daemon_stops() {
    let dir = scratch("ignores-term");
    let stub = dir.routinator("routinator", "trap '' TERM\nexec sleep 300");
    let mut daemon = Daemon::start(
        &dir,
        &sidecar_block(&dir, &stub, Cache::closed_port(), "", "stop-timeout 1;"),
    );
    let pid = daemon.sidecar_pid();
    // Let the stub get to its `exec`, which keeps the ignored signal.
    thread::sleep(Duration::from_millis(300));
    let stopping = Instant::now();
    let status = daemon.terminate();
    let took = stopping.elapsed();
    assert!(status.success(), "{status}\n{}", daemon.log());
    // A second for the signal that was ignored, not an hour, and not a
    // child left behind.
    assert!(took >= Duration::from_millis(900), "stopped after {took:?}");
    assert!(took < Duration::from_secs(10), "stopped after {took:?}");
    assert!(!alive(pid));
    let log = daemon.log();
    assert!(
        log.contains("msg=\"RPKI sidecar did not stop in time; killing it\""),
        "{log}"
    );
}

#[test]
fn a_child_that_exits_is_restarted_and_then_reported_failed() {
    let dir = scratch("exits");
    let stub = dir.routinator("routinator", "echo 'bad RPKI object' >&2\nexit 1");
    let mut daemon = Daemon::start(
        &dir,
        &sidecar_block(
            &dir,
            &stub,
            Cache::closed_port(),
            "",
            "restart-backoff 1 1; failure-threshold 2;",
        ),
    );
    // The alarm: failed twice in a row, retrying at the cap.
    let shown = daemon.wait_for("show rpki", |r| {
        r.contains("sidecar state failed, next attempt in ") && r.contains("sidecar last exit")
    });
    assert!(
        shown.contains("sidecar last exit exited with status 1"),
        "{shown}"
    );
    // It does not give up, and the daemon goes on.
    let shown = daemon.wait_for("show rpki", |r| {
        r.lines()
            .find_map(|l| l.strip_prefix("sidecar restarts "))
            .and_then(|l| l.split(' ').next()?.parse::<u32>().ok())
            .is_some_and(|restarts| restarts >= 3)
    });
    assert!(shown.contains("mode sidecar"), "{shown}");
    let json = daemon.http_get("/v1/rpki");
    assert!(
        json.contains("\"last_exit\":\"exited with status 1\""),
        "{json}"
    );
    // What it printed is in the log, as the child's.
    let log = daemon.log();
    assert!(
        log.contains("msg=\"bad RPKI object\"") && log.contains("sidecar=routinator"),
        "{log}"
    );
    assert!(log.contains("RPKI sidecar keeps failing"), "{log}");
    let status = daemon.terminate();
    assert!(status.success(), "{status}\n{}", daemon.log());
}

#[test]
fn a_child_that_never_serves_leaves_every_route_disabled() {
    // Routinator opens its RTR listener only after its first validation
    // run; until then the client's attempts are refused, nothing is
    // validated, and the sidecar is simply running.
    let dir = scratch("silent");
    let stub = dir.routinator("routinator", "exec sleep 300");
    let daemon = Daemon::start(
        &dir,
        &sidecar_block(&dir, &stub, Cache::closed_port(), "backoff 1 1;", ""),
    );
    let pid = daemon.sidecar_pid();
    let shown = daemon.wait_for("show rpki", |r| {
        r.lines()
            .find_map(|l| l.strip_prefix("failures "))
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|failures| failures > 0)
    });
    assert!(
        shown.contains("vrps none yet: every route is disabled"),
        "{shown}"
    );
    assert!(shown.contains("sidecar state running"), "{shown}");
    assert_eq!(
        daemon
            .ask("show rpki validate 192.0.2.0/24 64496")
            .lines()
            .next(),
        Some("192.0.2.0/24 origin AS64496: disabled")
    );
    assert!(alive(pid), "the child is left alone");
}

#[test]
fn a_reload_moves_the_child_only_when_its_block_changes() {
    let dir = scratch("reload");
    let stub = dir.routinator("routinator", "exec sleep 300");
    let cache = Cache::start(vec![vrp("192.0.2.0/24", 24, 64_496)]);
    let port = cache.port;
    let block = |binary: &Path, rpki: &str, routinator: &str| {
        sidecar_block(&dir, binary, port, rpki, routinator)
    };
    let mut daemon = Daemon::start(&dir, &block(&stub, "", "refresh 300;"));
    daemon.wait_for("show rpki", loaded(port));
    let first = daemon.sidecar_pid();

    // A setting of the client alone: the client restarts, the child stays.
    daemon.rewrite(&block(&stub, "version 0;", "refresh 300;"));
    let summary = daemon.ask("reload");
    assert!(summary.contains("rpki: rtr client restarted"), "{summary}");
    assert_eq!(daemon.sidecar_pid(), first, "the same child");
    daemon.wait_for("show rpki", loaded(port));

    // A setting of the sidecar's: the old child is gone before the new one
    // runs, and the client reads from the new one.
    daemon.rewrite(&block(&stub, "version 0;", "refresh 200;"));
    let summary = daemon.ask("reload");
    assert!(
        summary.contains("rpki: sidecar and rtr client restarted"),
        "{summary}"
    );
    assert!(!alive(first), "the old child was stopped");
    let second = daemon.sidecar_pid();
    assert_ne!(second, first);
    daemon.wait_for("show rpki", loaded(port));

    // The action for Invalid routes is the RIB's: child and client alone.
    daemon.rewrite(
        &block(&stub, "version 0;", "refresh 200;").replace("invalid drop", "invalid prefer-valid"),
    );
    let summary = daemon.ask("reload");
    assert!(
        summary.contains("invalid routes: prefer-valid"),
        "{summary}"
    );
    assert!(
        !summary.contains("sidecar") && !summary.contains("rtr client"),
        "{summary}"
    );
    assert_eq!(daemon.sidecar_pid(), second);
    assert!(daemon.ask("show rpki").contains("invalid prefer-valid"));

    // A binary that is not a supported Routinator fails the reload with the
    // reason, before the running child is touched.
    let old = dir.routinator_of("old", "0.14.2", "exec sleep 300");
    daemon.rewrite(&block(&old, "version 0;", "refresh 200;"));
    let failed = daemon.request("reload");
    let error = failed.status.unwrap_err();
    assert!(
        error.contains("rpki routinator: Routinator 0.14.2 is not supported"),
        "{error}"
    );
    assert_eq!(daemon.sidecar_pid(), second, "the child was not touched");
    // Nor does a setting the sidecar crate refuses.
    daemon.rewrite(&block(&stub, "version 0;", "tal nonesuch;"));
    let error = daemon.request("reload").status.unwrap_err();
    assert!(error.contains("nonesuch"), "{error}");
    assert_eq!(daemon.sidecar_pid(), second);
    assert!(
        daemon.ask("show rpki").contains("invalid prefer-valid"),
        "the old configuration runs"
    );

    // Off: the child goes and every route is disabled again.
    daemon.rewrite("rpki { mode disabled; }\n");
    let summary = daemon.ask("reload");
    assert!(
        summary.contains("rpki: sidecar stopped, validation disabled"),
        "{summary}"
    );
    assert!(!alive(second));
    let shown = daemon.ask("show rpki");
    assert!(!shown.contains("sidecar"), "{shown}");
    assert_eq!(
        daemon
            .ask("show rpki validate 192.0.2.0/24 64496")
            .lines()
            .next(),
        Some("192.0.2.0/24 origin AS64496: disabled")
    );

    // On again: a new child, and the VRPs.
    daemon.rewrite(&block(&stub, "", "refresh 300;"));
    let summary = daemon.ask("reload");
    assert!(
        summary.contains("rpki: sidecar and rtr client started"),
        "{summary}"
    );
    let third = daemon.sidecar_pid();
    daemon.wait_for("show rpki", loaded(port));
    let status = daemon.terminate();
    assert!(status.success(), "{status}\n{}", daemon.log());
    assert!(!alive(third));
}

/// The daemon that exits at start: its status and what it printed.
fn exits_at_start(dir: &Scratch, rpki: &str, check: bool) -> (ExitStatus, String) {
    let conf = dir.join("bgpfcd.conf");
    fs::write(
        &conf,
        config_text(&dir.0, free_port("127.0.0.2"), free_port("127.0.0.1"), rpki),
    )
    .unwrap();
    let mut cmd = bgpfcd(&conf);
    if check {
        cmd.arg("--check");
    }
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let status = wait_until("the daemon to exit", || child.try_wait().unwrap());
    (status, reader.join().unwrap())
}

#[test]
fn a_sidecar_that_cannot_run_stops_the_start() {
    let dir = scratch("refused");
    let port = Cache::closed_port();
    // A release the command line was not written for.
    let old = dir.routinator_of("old", "0.14.2", "exec sleep 300");
    let (status, stderr) = exits_at_start(&dir, &sidecar_block(&dir, &old, port, "", ""), false);
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("msg=\"cannot start\" error=\"cannot start the routinator sidecar: Routinator 0.14.2 is not supported"),
        "{stderr}"
    );
    // The start left no control socket behind.
    assert!(!dir.join("ctl.sock").exists());

    // A binary that is not there.
    let missing = dir.join("missing");
    let (status, stderr) =
        exits_at_start(&dir, &sidecar_block(&dir, &missing, port, "", ""), false);
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("cannot start the routinator sidecar: "),
        "{stderr}"
    );
}

/// A binary that hangs when asked its version would hang the start for
/// ever. It is killed after ten seconds, with whatever it started, and the
/// start fails naming it. (The sidecar crate's tests cover the kill with a
/// shorter timeout; this takes the ten seconds the daemon allows.)
#[test]
fn a_binary_that_hangs_at_its_version_check_stops_the_start() {
    let dir = scratch("hangs");
    let started = dir.join("started");
    let hung = dir.script(
        "routinator",
        &format!("touch '{}'\nexec sleep 300", started.display()),
    );
    let before = Instant::now();
    let (status, stderr) = exits_at_start(
        &dir,
        &sidecar_block(&dir, &hung, Cache::closed_port(), "", ""),
        false,
    );
    let took = before.elapsed();
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(started.exists(), "the stub ran");
    assert!(took >= Duration::from_secs(9), "gave up after {took:?}");
    assert!(
        stderr.contains("did not finish within 10s and was killed"),
        "{stderr}"
    );
}

#[test]
fn check_judges_the_block_without_running_the_binary() {
    let dir = scratch("check");
    let port = Cache::closed_port();
    let missing = dir.join("missing");
    // The binary is not run, nor looked for: `--check` judges the file alone.
    let (status, stderr) = exits_at_start(&dir, &sidecar_block(&dir, &missing, port, "", ""), true);
    assert!(status.success(), "{stderr}");

    // What the parser sees, with its position.
    let (status, stderr) = exits_at_start(
        &dir,
        &sidecar_block(&dir, &missing, port, "", "rtr-listen 192.0.2.1:3323;"),
        true,
    );
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("rtr-listen address 192.0.2.1:3323 is not a loopback address"),
        "{stderr}"
    );
    let (status, stderr) = exits_at_start(
        &dir,
        "rpki { mode sidecar; invalid drop; cache 127.0.0.1;\n\
         routinator { binary /usr/bin/routinator; repository-dir /var/lib/rpki; } }\n",
        true,
    );
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("`cache` is not used with `mode sidecar`"),
        "{stderr}"
    );

    // What only the sidecar crate knows.
    for (statement, reason) in [
        ("tal nonesuch;", "nonesuch"),
        ("tal arin;", "ARIN"),
        ("server-arg --rtr=0.0.0.0:3323;", "--rtr"),
    ] {
        let (status, stderr) = exits_at_start(
            &dir,
            &sidecar_block(&dir, &missing, port, "", statement),
            true,
        );
        assert_eq!(status.code(), Some(1), "{statement}: {stderr}");
        assert!(
            stderr.contains("rpki routinator: "),
            "{statement}: {stderr}"
        );
        assert!(stderr.contains(reason), "{statement}: {stderr}");
    }
    // RFC 8481 §5: no action on the state unless the operator names it.
    let (status, stderr) = exits_at_start(
        &dir,
        "rpki { mode sidecar;\n\
         routinator { binary /usr/bin/routinator; repository-dir /var/lib/rpki; } }\n",
        true,
    );
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("`mode sidecar` needs an `invalid` statement"),
        "{stderr}"
    );
}
