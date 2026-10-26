//! Route origin validation from RPKI caches (AGENTS.md §9 steps 12 and
//! 14): the `rpki` block run as the RTR client of `bgpfc-rtr`, feeding the
//! RIB thread, and, with `mode sidecar`, the Routinator that the client
//! reads from.
//!
//! With `mode external` the coordinator starts a [`Client`] whose sink
//! hands every [`ValidationChange`] to the RIB thread as a
//! [`RibMsg::Validation`] on the RIB's bounded channel. Like an UPDATE, a
//! change waits behind what is queued: the client cannot outrun the RIB
//! (AGENTS.md §3, "Backpressure"), and the RIB applies the changes in the
//! order the client published them (RFC 6811 §4). The RIB starts with no
//! source, every route `disabled`, and the client's first full set
//! replaces that for every route.
//!
//! With `mode sidecar` the coordinator first starts a [`Sidecar`]: it
//! checks and runs Routinator as a child process and restarts it when it
//! fails (see `bgpfc-sidecar`). The client's one cache is the sidecar's
//! RTR listener on the loopback, whatever port the sidecar picked, so the
//! RTR side is the same as for an external cache. The [`Sidecar`] owns the
//! thread that spawns every child. That thread lives until the sidecar is
//! stopped, which only this struct does: at a reload that replaces the
//! sidecar, after its child is gone, and at shutdown. The child's
//! parent-death signal fires when the thread that spawned it exits, so
//! it ends the child only when nothing is left to stop it, which is when
//! the daemon is gone. The daemon starts the sidecar from the main thread
//! after it dropped root, as the sidecar's documentation asks.
//!
//! A reload that changes the block stops the client and starts another
//! with the new settings, which keeps the data the old one published until
//! a cache sends a full set, or until it expires (RFC 8210 §10, §6; see
//! [`Client::start_holding`]): the routes keep their states meanwhile, and
//! a new set validates again only the routes it judges differently. A
//! change to the `routinator` block, or to or from `mode sidecar`, also
//! stops the old sidecar and starts another, after the new settings and
//! binary have been checked ([`check_reload`]) so that a typo fails the
//! reload before anything is stopped. A change to `mode disabled` sends
//! [`ValidationChange::disabled`] instead, so that every route is
//! `disabled` again. A reload that leaves the block alone leaves the
//! client and the sidecar alone.
//!
//! Stopping the client, at a reload or at shutdown, joins its thread,
//! which a stop wakes from its sleep, its reads and writes, and its wait
//! for a connection attempt (see [`Client::stop`]): a cache that does not
//! answer holds up neither. The thread may still be waiting for room on
//! the RIB channel; the RIB thread makes that room, as it runs until the
//! process exits, and waits for nothing that waits for the client. At
//! shutdown the coordinator sends the Ceases and then stops the client
//! ([`Rpki::begin_stop`]), so that the sidecar's exit is not reported as a
//! lost cache, and asks the sidecar to stop at the same time, so that it
//! stops while the FIB cleanup, which needs neither, goes on;
//! [`Rpki::stop`] then waits for the child last.
//!
//! The client logs through `bgpfc_log`, so the daemon's `log { level }`
//! applies to it: a lost cache is a warning, its return an info line,
//! expired data an error.
//!
//! Implements: RFC 8210 §6 (the Expire Interval cap and the reconnect
//! back-off configured), §7 (the version offered first), §9 (unprotected
//! TCP to the configured port, 323 by default; to the sidecar only on the
//! loopback), §10 (the cache list with preferences; the data kept across a
//! new cache list); RFC 6811 §4 (each change of the VRPs reaches the RIB,
//! which validates the affected routes again).

use std::ffi::OsString;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;

use bgpfc_config::ast::{self, RpkiMode};
use bgpfc_rpki::{RpkiError, ValidationChange, ValidationSink};
use bgpfc_rtr::Version;
use bgpfc_rtr::client::{self, Backoff, Cache, Client, Held, Status};
use bgpfc_rtr::session;
use bgpfc_sidecar::{BackoffConfig, Sidecar, SidecarConfig, SidecarError, TalConfig};
use bgpfc_wire::types::RouterId;

use crate::messages::{RibMsg, SidecarReport};

/// Look up every cache of an external `rpki` block, so that a name that
/// does not resolve stops the daemon at start with an error naming it,
/// rather than leaving every route unvalidated without a word (issue
/// #60).
///
/// It is done where the daemon runs, not when the file is checked:
/// `bgpfcd --check` judges the file alone, wherever it runs, and the
/// configuration crate does no I/O. The client looks each name up again
/// at every connection attempt, so a cache that moves is followed.
///
/// # Errors
/// Every cache that has no address, with the reason.
pub(crate) fn resolve(rpki: &ast::Rpki) -> Result<(), String> {
    if rpki.mode != RpkiMode::External {
        return Ok(());
    }
    let failures: Vec<String> = rpki
        .caches
        .iter()
        .filter_map(|c| match (c.host.as_str(), c.port).to_socket_addrs() {
            Ok(mut addrs) => addrs
                .next()
                .is_none()
                .then(|| format!("{}: no address", c.host)),
            Err(e) => Some(format!("{}: {e}", c.host)),
        })
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("cannot resolve rpki cache {}", failures.join("; ")))
    }
}

/// The sidecar's settings for the `routinator` block of `mode sidecar`,
/// checked by [`SidecarConfig::validate`].
///
/// The configuration crate checks what one statement shows, with its
/// position. This is the rest, which only the sidecar crate knows: the
/// names of the TALs Routinator bundles, ARIN's agreement, the arguments
/// bgpfcd reserves. It touches no file and starts nothing, so `bgpfcd
/// --check` can run it ([`validate`]).
///
/// # Errors
/// The first setting the sidecar refuses.
pub(crate) fn sidecar_config(r: &ast::Routinator) -> Result<SidecarConfig, SidecarError> {
    let mut c = SidecarConfig::new(&r.binary, &r.repository_dir);
    c.rtr_listen = r.rtr_listen;
    c.tals = TalConfig {
        rir_tals: r.rir_tals,
        bundled: r.tals.clone(),
        extra_dir: r.tal_dir.clone(),
    };
    c.accept_arin_rpa = r.accept_arin_rpa;
    c.refresh = r.refresh;
    c.config_file.clone_from(&r.config_file);
    c.extra_global_args = r.global_args.iter().map(OsString::from).collect();
    c.extra_server_args = r.server_args.iter().map(OsString::from).collect();
    c.backoff = BackoffConfig {
        initial: r.restart_backoff_initial,
        cap: r.restart_backoff_cap,
        stable: r.stable_after,
    };
    c.stop_timeout = r.stop_timeout;
    c.failure_threshold = r.failure_threshold;
    c.validate()?;
    Ok(c)
}

/// What the sidecar crate makes of the `routinator` block, if `rpki` runs
/// one; the file alone, no binary is run.
///
/// # Errors
/// The setting at fault, named as the block names it.
pub(crate) fn validate(rpki: &ast::Rpki) -> Result<(), String> {
    match rpki.sidecar() {
        Some(r) => sidecar_config(r)
            .map(drop)
            .map_err(|e| format!("rpki routinator: {e}")),
        None => Ok(()),
    }
}

/// Before a reload changes anything: if `new` asks for another sidecar
/// than `old` runs, check that it would start, by running its binary's
/// `--version`. A reload then fails with the running configuration and
/// the running sidecar as they were, instead of with no sidecar.
///
/// # Errors
/// The setting or the binary at fault.
pub(crate) fn check_reload(old: &ast::Rpki, new: &ast::Rpki) -> Result<(), String> {
    let Some(r) = new.sidecar() else {
        return Ok(());
    };
    if old.sidecar() == Some(r) {
        return Ok(());
    }
    let config = sidecar_config(r).map_err(|e| format!("rpki routinator: {e}"))?;
    bgpfc_sidecar::check_binary(&config)
        .map(drop)
        .map_err(|e| format!("rpki routinator: {e}"))
}

/// The client's configuration for `rpki`, or `None` in a mode without a
/// client. `sidecar` is where the running sidecar serves RTR: the one
/// cache of `mode sidecar`.
pub(crate) fn client_config(
    rpki: &ast::Rpki,
    router_id: RouterId,
    sidecar: Option<SocketAddr>,
) -> Option<client::Config> {
    let caches = match (rpki.mode, sidecar) {
        (RpkiMode::External, _) => rpki
            .caches
            .iter()
            .map(|c| Cache {
                host: c.host.clone(),
                port: c.port,
                preference: c.preference,
            })
            .collect(),
        // RFC 8210 §9: unprotected TCP, to a cache on this host.
        (RpkiMode::Sidecar, Some(rtr)) => vec![Cache {
            host: rtr.ip().to_string(),
            port: rtr.port(),
            preference: 0,
        }],
        (RpkiMode::Sidecar, None) | (RpkiMode::Disabled, _) => return None,
    };
    let mut config = client::Config::new(caches);
    config.connect_timeout = rpki.connect_timeout;
    config.backoff = Backoff {
        min: rpki.backoff_min,
        max: rpki.backoff_max,
    };
    // The jitter spreads the reconnects of routers that lost a cache at
    // the same moment. The BGP Identifier differs between routers (RFC
    // 6286 §2.1) and stays the same across restarts, so a router's
    // schedule can be reproduced.
    config.jitter_seed = u64::from(router_id.to_u32());
    config.session = session::Config {
        // RFC 8210 §7: offer version 1 and fall back, unless pinned to 0.
        version: if rpki.version == 0 {
            Version::V0
        } else {
            Version::V1
        },
        max_expire: rpki.max_expire,
        response_timeout: rpki.response_timeout,
        reply_timeout: rpki.reply_timeout,
        max_vrps: usize::try_from(rpki.max_vrps).unwrap_or(usize::MAX),
    };
    Some(config)
}

/// Where the client publishes: the RIB thread's bounded channel. A send
/// waits while the channel is full, and fails once the RIB thread is
/// gone, which stops the client.
fn sink(rib: SyncSender<RibMsg>) -> impl ValidationSink {
    move |change: ValidationChange| {
        rib.send(RibMsg::Validation(change))
            .map_err(|_| RpkiError::SinkClosed)
    }
}

/// The running `rpki` block: the sidecar and the RTR client, if its mode
/// has them.
#[derive(Debug)]
pub(crate) struct Rpki {
    rib: SyncSender<RibMsg>,
    router_id: RouterId,
    /// The Routinator child, in `mode sidecar`. Declared before the
    /// client so that the client, which reads from it, is dropped first.
    sidecar: Option<Supervised>,
    client: Option<Client>,
}

/// A running sidecar, with the binary it was started from: the configured
/// path of the block that started it, which a failed reload may since have
/// moved on from.
#[derive(Debug)]
struct Supervised {
    sidecar: Sidecar,
    binary: PathBuf,
}

impl Rpki {
    /// Start what `config` asks for, publishing to `rib`. The caller has
    /// checked with [`resolve`] that the caches can be found and with
    /// [`validate`] that the sidecar's settings are usable.
    ///
    /// # Errors
    /// The sidecar could not be started (its binary is not a supported
    /// Routinator, say), or the client thread could not be spawned.
    pub(crate) fn start(
        config: &ast::Rpki,
        router_id: RouterId,
        rib: SyncSender<RibMsg>,
    ) -> Result<Rpki, String> {
        let mut rpki = Rpki {
            rib,
            router_id,
            sidecar: None,
            client: None,
        };
        rpki.sidecar = Rpki::start_sidecar(config)?;
        match rpki.spawn(config, None) {
            Ok(client) => rpki.client = client,
            Err(e) => {
                rpki.stop();
                return Err(format!("cannot start the rtr client: {e}"));
            }
        }
        Ok(rpki)
    }

    /// The sidecar `config` asks for, started: its settings and binary are
    /// checked, a free RTR port is picked if none is named, and the
    /// supervisor thread starts Routinator.
    fn start_sidecar(config: &ast::Rpki) -> Result<Option<Supervised>, String> {
        let Some(r) = config.sidecar() else {
            return Ok(None);
        };
        let c = sidecar_config(r).map_err(|e| format!("rpki routinator: {e}"))?;
        bgpfc_log::info!(
            "rpki: starting the routinator sidecar",
            binary = r.binary.display(),
            repository_dir = r.repository_dir.display()
        );
        Sidecar::start(c)
            .map(|sidecar| {
                Some(Supervised {
                    sidecar,
                    binary: r.binary.clone(),
                })
            })
            .map_err(|e| format!("cannot start the routinator sidecar: {e}"))
    }

    /// A client for `config`, holding `held`, if its mode runs one.
    fn spawn(&self, config: &ast::Rpki, held: Option<Held>) -> io::Result<Option<Client>> {
        let rtr = self.sidecar.as_ref().map(|s| s.sidecar.rtr_addr());
        let Some(client_config) = client_config(config, self.router_id, rtr) else {
            return Ok(None);
        };
        bgpfc_log::info!(
            "rpki: starting the rtr client",
            caches = client_config
                .caches
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            version = config.version,
            held_vrps = held.as_ref().map_or(0, |h| h.vrps.len())
        );
        let client = Client::start_holding(client_config, sink(self.rib.clone()), held)?;
        Ok(Some(client))
    }

    /// Apply `new`, the block of a reloaded configuration, in place of
    /// `old`, the running one; what was done, for the reload's summary.
    /// The caller has checked with [`resolve`] that the new caches can be
    /// found, and with [`validate`] and [`check_reload`] that a new
    /// sidecar would start.
    ///
    /// # Errors
    /// The new sidecar or the new client thread could not be started.
    /// Validation is then off, as with `mode disabled`, since nothing
    /// would expire the data the old client left in the RIB.
    pub(crate) fn reconfigure(
        &mut self,
        old: &ast::Rpki,
        new: &ast::Rpki,
    ) -> Result<&'static str, String> {
        if old.same_as(new) {
            return Ok("rpki unchanged");
        }
        let ran = self.client.is_some();
        // The sidecar moves only when its own block does, or the mode
        // changes to or from it; the client's settings alone leave it be.
        let sidecar_change = (old.sidecar() != new.sidecar())
            .then(|| (old.sidecar().is_some(), new.sidecar().is_some()));
        let held = self.stop_client();
        if sidecar_change.is_some() {
            // The old child goes first: it holds the repository directory
            // and perhaps the RTR port the new one asks for.
            self.stop_sidecar();
            match Rpki::start_sidecar(new) {
                Ok(sidecar) => self.sidecar = sidecar,
                Err(e) => {
                    self.disable();
                    return Err(format!("rpki: {e}; validation disabled"));
                }
            }
        }
        match self.spawn(new, held) {
            Ok(Some(client)) => {
                self.client = Some(client);
                Ok(match sidecar_change {
                    Some((true, true)) => "rpki: sidecar and rtr client restarted",
                    Some((false, true)) => "rpki: sidecar and rtr client started",
                    Some((true, false)) => "rpki: sidecar stopped, rtr client restarted",
                    // The client's settings moved on their own; a change
                    // of sidecar always has one on a side.
                    Some((false, false)) | None => {
                        if ran {
                            "rpki: rtr client restarted"
                        } else {
                            "rpki: rtr client started"
                        }
                    }
                })
            }
            Ok(None) if ran => {
                self.disable();
                Ok(if sidecar_change.is_some_and(|(had, _)| had) {
                    "rpki: sidecar stopped, validation disabled"
                } else {
                    "rpki: validation disabled"
                })
            }
            Ok(None) => Ok("rpki: validation stays disabled"),
            Err(e) => {
                self.disable();
                Err(format!(
                    "rpki: cannot start the rtr client ({e}); validation disabled"
                ))
            }
        }
    }

    /// Stop the client, if one runs, and return what it published.
    fn stop_client(&mut self) -> Option<Held> {
        let mut client = self.client.take()?;
        client.stop();
        // Read once the thread has ended: it publishes nothing after.
        client.status().held()
    }

    /// Stop the sidecar, if one runs, and wait until its child is gone.
    fn stop_sidecar(&mut self) {
        if let Some(running) = self.sidecar.take() {
            bgpfc_log::info!("rpki: stopping the routinator sidecar");
            running.sidecar.stop();
        }
    }

    /// Turn validation off in the RIB: every route `disabled`.
    fn disable(&self) {
        bgpfc_log::info!("rpki: validation disabled; every route is disabled again");
        // A RIB thread that is gone has no routes to tell.
        let _ = self
            .rib
            .send(RibMsg::Validation(ValidationChange::disabled()));
    }

    /// The first move of a shutdown: stop the client, so that the end of
    /// its cache is not reported as a lost one, and ask the sidecar to
    /// stop without waiting, so that it stops while the sessions close.
    /// [`stop`](Self::stop) waits for it.
    pub(crate) fn begin_stop(&mut self) {
        self.stop_client();
        if let Some(running) = &self.sidecar {
            running.sidecar.request_stop();
        }
    }

    /// Stop the client and the sidecar for good, at shutdown. It returns
    /// once the client thread has ended and the child is gone; see the
    /// module documentation.
    pub(crate) fn stop(&mut self) {
        self.stop_client();
        self.stop_sidecar();
    }

    /// The client's status, if one runs.
    pub(crate) fn status(&self) -> Option<Status> {
        self.client.as_ref().map(Client::status)
    }

    /// The sidecar's status, if one runs.
    pub(crate) fn sidecar_report(&self) -> Option<SidecarReport> {
        self.sidecar.as_ref().map(|s| SidecarReport {
            status: s.sidecar.status(),
            version: s.sidecar.version(),
            binary: s.binary.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{ErrorKind, Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::thread;
    use std::time::{Duration, Instant};

    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use bgpfc_config::Config;
    use bgpfc_rpki::{AffectedPrefixes, RouteOrigin, RovState, Vrp};
    use bgpfc_rtr::{Framer, Intervals, Pdu};
    use bgpfc_wire::types::Asn;

    const WAIT: Duration = Duration::from_secs(10);
    const SID: u16 = 7;

    fn config(rpki: &str) -> Config {
        bgpfc_config::parse_str("t", &format!("router-id 192.0.2.1; local-as 65000; {rpki}"))
            .unwrap()
    }

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
    }

    fn rov(change: &ValidationChange, prefix: &str, asn: u32) -> RovState {
        change
            .source
            .rov(prefix.parse().unwrap(), RouteOrigin::As(Asn(asn)))
    }

    /// The next validation change on the RIB channel.
    fn next_change(rx: &Receiver<RibMsg>) -> ValidationChange {
        match rx.recv_timeout(WAIT) {
            Ok(RibMsg::Validation(change)) => change,
            other => panic!("expected a validation change, got {other:?}"),
        }
    }

    fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// An RTR cache on the loopback that answers Reset Queries.
    struct StubCache {
        listener: TcpListener,
    }

    impl StubCache {
        fn new() -> StubCache {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            StubCache { listener }
        }

        fn port(&self) -> u16 {
            self.listener.local_addr().unwrap().port()
        }

        /// The block of a daemon that uses this cache alone.
        fn block(&self) -> String {
            format!(
                "rpki {{ mode external; invalid policy; cache 127.0.0.1 port {}; }}",
                self.port()
            )
        }

        /// Take the client's next connection and its first query.
        fn accept(&self) -> (TcpStream, Pdu) {
            let deadline = Instant::now() + WAIT;
            let mut stream = loop {
                match self.listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "the client did not connect");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            let mut framer = Framer::new();
            let query = loop {
                if let Some(pdu) = framer.next_pdu().unwrap() {
                    break pdu;
                }
                let mut buf = [0; 64];
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "the client closed the connection");
                framer.feed(&buf[..n]);
            };
            (stream, query)
        }

        /// Take the client's next connection and answer its Reset Query
        /// with `vrps` (RFC 8210 §8.1).
        fn serve(&self, vrps: &[Vrp]) -> TcpStream {
            let (mut stream, query) = self.accept();
            assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
            let version = query.version();
            let mut out = Pdu::CacheResponse {
                version,
                session_id: SID,
            }
            .encode();
            for &vrp in vrps {
                Pdu::Prefix {
                    version,
                    announce: true,
                    vrp,
                }
                .encode_into(&mut out);
            }
            Pdu::EndOfData {
                session_id: SID,
                serial: 1,
                intervals: Some(Intervals::DEFAULT),
            }
            .encode_into(&mut out);
            stream.write_all(&out).unwrap();
            stream
        }
    }

    /// Whether the client closed `conn`.
    fn closed(conn: &mut TcpStream) -> bool {
        let mut buf = [0; 16];
        match conn.read(&mut buf) {
            Ok(n) => n == 0,
            Err(e) => e.kind() == ErrorKind::ConnectionReset,
        }
    }

    #[test]
    fn the_client_is_configured_from_the_block() {
        let router_id = RouterId::new(0xC000_0201).unwrap();
        let cfg = config(
            "rpki {
                mode external; invalid policy;
                cache rtr.example.net port 3323 preference 10;
                cache 127.0.0.1;
                version 0; connect-timeout 5; response-timeout 30; reply-timeout 600;
                max-expire 3600; max-vrps 1000; backoff 2 300;
            }",
        );
        let c = client_config(&cfg.rpki, router_id, None).unwrap();
        assert_eq!(
            c.caches,
            [
                Cache {
                    host: "rtr.example.net".to_owned(),
                    port: 3323,
                    preference: 10
                },
                Cache::new("127.0.0.1"),
            ]
        );
        assert_eq!(c.connect_timeout, Duration::from_secs(5));
        assert_eq!(
            c.backoff,
            Backoff {
                min: Duration::from_secs(2),
                max: Duration::from_secs(300)
            }
        );
        assert_eq!(c.jitter_seed, 0xC000_0201);
        assert_eq!(
            c.session,
            session::Config {
                version: Version::V0,
                max_expire: Duration::from_secs(3_600),
                response_timeout: Duration::from_secs(30),
                reply_timeout: Duration::from_secs(600),
                max_vrps: 1_000,
            }
        );
        // The block's defaults are the client's.
        let cfg = config("rpki { mode external; invalid policy; cache 192.0.2.10; }");
        let c = client_config(&cfg.rpki, router_id, None).unwrap();
        let defaults = client::Config::new(vec![Cache::new("192.0.2.10")]);
        assert_eq!(c.caches, defaults.caches);
        assert_eq!(c.connect_timeout, defaults.connect_timeout);
        assert_eq!(c.backoff, defaults.backoff);
        assert_eq!(c.session, defaults.session);
        assert_eq!(ast::Rpki::DEFAULT_PORT, client::DEFAULT_PORT);
        assert_eq!(ast::Rpki::MIN_EXPIRE, session::Config::MIN_EXPIRE);
        assert_eq!(ast::Rpki::MAX_EXPIRE, session::Config::MAX_EXPIRE);
        // No client without the block, or with `mode disabled`.
        assert!(client_config(&config("").rpki, router_id, None).is_none());
        let disabled = config("rpki { mode disabled; cache 192.0.2.10; }");
        assert!(client_config(&disabled.rpki, router_id, None).is_none());
    }

    #[test]
    fn caches_that_cannot_be_found_are_named() {
        let ok = config(
            "rpki { mode external; invalid policy; cache 127.0.0.1; cache ::1; cache localhost; }",
        );
        assert_eq!(resolve(&ok.rpki), Ok(()));
        // RFC 2606 §2: `.invalid` never resolves.
        let bad = config(
            "rpki { mode external; invalid policy; cache 127.0.0.1; cache rtr.invalid;
             cache other.invalid preference 1; }",
        );
        let e = resolve(&bad.rpki).unwrap_err();
        assert!(
            e.starts_with("cannot resolve rpki cache rtr.invalid: "),
            "{e}"
        );
        assert!(e.contains("; other.invalid: "), "{e}");
        assert!(!e.contains("127.0.0.1"), "{e}");
        // Nothing is looked up for a mode without a client.
        let off = config("rpki { mode disabled; cache rtr.invalid; }");
        assert_eq!(resolve(&off.rpki), Ok(()));
    }

    #[test]
    fn the_cache_s_data_reaches_the_rib_channel() {
        let cache = StubCache::new();
        let cfg = config(&cache.block());
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        // The first set replaces the RIB's lack of a source: every route.
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_497), RovState::Invalid);
        assert_eq!(rov(&change, "198.51.100.0/24", 64_496), RovState::NotFound);
        eventually("the client in sync", || {
            rpki.status().is_some_and(|s| s.synced_at.is_some())
        });
        assert_eq!(rpki.status().unwrap().vrps_ipv4, 1);
        rpki.stop();
        assert!(rpki.status().is_none());
        assert!(closed(&mut conn), "no client is left");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn without_a_client_nothing_is_published() {
        let (tx, rx) = sync_channel(4);
        let cfg = config("rpki { mode disabled; cache 127.0.0.1; }");
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        assert!(rpki.status().is_none());
        rpki.stop();
        assert!(rx.try_recv().is_err());
    }

    /// A client in sync with `cache`, which sent `vrps`, and the RIB
    /// channel it publishes to.
    fn in_sync(cache: &StubCache, vrps: &[Vrp]) -> (Rpki, Receiver<RibMsg>, TcpStream) {
        let cfg = config(&cache.block());
        let (tx, rx) = sync_channel(4);
        let rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let conn = cache.serve(vrps);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        (rpki, rx, conn)
    }

    #[test]
    fn an_unchanged_block_leaves_the_client_alone() {
        let cache = StubCache::new();
        let (mut rpki, rx, mut conn) = in_sync(&cache, &[vrp("192.0.2.0/24", 24, 64_496)]);
        let cfg = config(&cache.block());
        assert_eq!(rpki.reconfigure(&cfg.rpki, &cfg.rpki), Ok("rpki unchanged"));
        // The same session goes on: no new connection, nothing published.
        conn.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0; 16];
        let quiet = conn.read(&mut buf).unwrap_err().kind();
        assert!(
            matches!(quiet, ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "{quiet:?}"
        );
        assert_eq!(
            cache.listener.accept().map_err(|e| e.kind()).err(),
            Some(ErrorKind::WouldBlock)
        );
        assert!(rx.try_recv().is_err());
        assert!(rpki.status().is_some_and(|s| s.connected));
        rpki.stop();
    }

    #[test]
    fn a_respelled_cache_leaves_the_client_alone() {
        // The parser takes a name in another case, or with its final dot,
        // for the same cache; so does a reload.
        let cache = StubCache::new();
        let named = |host: &str| {
            config(&format!(
                "rpki {{ mode external; invalid policy; cache {host} port {}; }}",
                cache.port()
            ))
        };
        let (old, new) = (named("localhost"), named("LocalHost."));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&old.rpki, old.router_id, tx).unwrap();
        let _conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        assert_eq!(rpki.reconfigure(&old.rpki, &new.rpki), Ok("rpki unchanged"));
        thread::sleep(Duration::from_millis(200));
        assert_eq!(
            cache.listener.accept().map_err(|e| e.kind()).err(),
            Some(ErrorKind::WouldBlock),
            "no new connection"
        );
        assert!(rx.try_recv().is_err());
        assert!(rpki.status().is_some_and(|s| s.connected));
        rpki.stop();
    }

    #[test]
    fn a_new_cache_list_keeps_the_old_data_until_a_full_set() {
        let first = StubCache::new();
        let (a, b, c) = (
            vrp("192.0.2.0/24", 24, 64_496),
            vrp("198.51.100.0/24", 24, 64_497),
            vrp("203.0.113.0/24", 24, 64_498),
        );
        let (mut rpki, rx, mut old_conn) = in_sync(&first, &[a, b]);
        let second = StubCache::new();
        let (old, new) = (config(&first.block()), config(&second.block()));
        assert_eq!(
            rpki.reconfigure(&old.rpki, &new.rpki),
            Ok("rpki: rtr client restarted")
        );
        assert!(closed(&mut old_conn), "the old client is gone");
        // RFC 8210 §10: until the new cache has sent a full set, the old
        // data stays in use; the RIB hears nothing.
        let (mut conn, query) = second.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        let held = rpki.status().unwrap();
        assert_eq!(held.vrps.as_deref().map(bgpfc_rpki::VrpSet::len), Some(2));
        assert!(held.expires_at.is_some());
        assert!(rx.try_recv().is_err());
        // The new cache's set replaces it, and only the routes the two
        // sets disagree on are validated again.
        let version = query.version();
        let mut out = Pdu::CacheResponse {
            version,
            session_id: SID,
        }
        .encode();
        for vrp in [a, c] {
            Pdu::Prefix {
                version,
                announce: true,
                vrp,
            }
            .encode_into(&mut out);
        }
        Pdu::EndOfData {
            session_id: SID,
            serial: 1,
            intervals: Some(Intervals::DEFAULT),
        }
        .encode_into(&mut out);
        conn.write_all(&out).unwrap();
        let change = next_change(&rx);
        let p = |s: &str| s.parse().unwrap();
        assert!(!change.affected.covers(p("192.0.2.0/24")));
        assert!(change.affected.covers(p("198.51.100.0/24")));
        assert!(change.affected.covers(p("203.0.113.0/24")));
        assert_eq!(rov(&change, "198.51.100.0/24", 64_497), RovState::NotFound);
        assert_eq!(rov(&change, "203.0.113.0/24", 64_498), RovState::Valid);
        rpki.stop();
    }

    #[test]
    fn switching_to_disabled_sends_the_disabled_change() {
        let cache = StubCache::new();
        let (mut rpki, rx, mut conn) = in_sync(&cache, &[vrp("192.0.2.0/24", 24, 64_496)]);
        let (old, new) = (
            config(&cache.block()),
            config(&format!(
                "rpki {{ mode disabled; cache 127.0.0.1 port {}; }}",
                cache.port()
            )),
        );
        assert_eq!(
            rpki.reconfigure(&old.rpki, &new.rpki),
            Ok("rpki: validation disabled")
        );
        assert!(rpki.status().is_none());
        assert!(closed(&mut conn));
        // ValidationChange::disabled: no source, for every route.
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Disabled);
        assert!(rx.try_recv().is_err());
        // From disabled to disabled nothing is sent; back to external
        // starts a client, whose first set is for every route again.
        assert_eq!(
            rpki.reconfigure(&new.rpki, &config("").rpki),
            Ok("rpki: validation stays disabled")
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(
            rpki.reconfigure(&new.rpki, &old.rpki),
            Ok("rpki: rtr client started")
        );
        let _conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        rpki.stop();
    }

    #[test]
    fn stopping_waits_for_a_full_rib_channel_to_drain() {
        // The client publishes while the RIB thread is busy and its
        // channel full: stopping it waits for the RIB to make room, and
        // the change is delivered, not lost.
        let cache = StubCache::new();
        let cfg = config(&cache.block());
        let (tx, rx) = sync_channel(1);
        tx.send(RibMsg::PeerDown {
            peer: "192.0.2.2".parse().unwrap(),
            retain: None,
        })
        .unwrap();
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        // The RIB thread drains the channel a while later.
        let rib = thread::spawn(move || {
            thread::sleep(Duration::from_secs(1));
            let mut messages = Vec::new();
            while let Ok(m) = rx.recv_timeout(Duration::from_secs(2)) {
                messages.push(m);
            }
            messages
        });
        // Long enough for the client to read the reply and wait to publish.
        thread::sleep(Duration::from_millis(500));
        let stopping = Instant::now();
        rpki.stop();
        assert!(stopping.elapsed() >= Duration::from_millis(300));
        assert!(closed(&mut conn));
        let messages = rib.join().unwrap();
        assert!(
            matches!(messages[0], RibMsg::PeerDown { .. }),
            "{messages:?}"
        );
        assert!(
            matches!(&messages[1..], [RibMsg::Validation(_)]),
            "{messages:?}"
        );
    }

    /// A port where a connection attempt hangs until its timeout, like one
    /// to a cache whose host is gone: a listener that never accepts, with
    /// its accept queue full, so that the kernel drops a new SYN.
    fn unanswered() -> (TcpListener, Vec<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut queued = Vec::new();
        loop {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                Ok(stream) => queued.push(stream),
                Err(e) if e.kind() == ErrorKind::TimedOut => return (listener, queued),
                Err(e) => panic!("filling the accept queue: {e}"),
            }
            assert!(queued.len() < 4_096, "the accept queue never filled");
        }
    }

    #[test]
    fn a_cache_that_never_answers_holds_up_neither_reload_nor_stop() {
        let (listener, _queued) = unanswered();
        let hanging = config(&format!(
            "rpki {{ mode external; invalid policy; cache 127.0.0.1 port {};
             connect-timeout 30; response-timeout 60; }}",
            listener.local_addr().unwrap().port()
        ));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&hanging.rpki, hanging.router_id, tx).unwrap();
        let connecting = |rpki: &Rpki| {
            rpki.status()
                .is_some_and(|s| s.state == bgpfc_rtr::session::State::Connecting)
        };
        eventually("the attempt", || connecting(&rpki));
        thread::sleep(Duration::from_millis(100));
        // A reload to another cache while the attempt lasts: the old client
        // stops at once, and the new one takes over.
        let cache = StubCache::new();
        let working = config(&cache.block());
        let reloading = Instant::now();
        assert_eq!(
            rpki.reconfigure(&hanging.rpki, &working.rpki),
            Ok("rpki: rtr client restarted")
        );
        assert!(
            reloading.elapsed() < Duration::from_secs(2),
            "{:?}",
            reloading.elapsed()
        );
        let _conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        // Back to the cache that never answers, then shutdown during the
        // attempt.
        assert_eq!(
            rpki.reconfigure(&working.rpki, &hanging.rpki),
            Ok("rpki: rtr client restarted")
        );
        eventually("the attempt", || connecting(&rpki));
        thread::sleep(Duration::from_millis(100));
        let stopping = Instant::now();
        rpki.stop();
        assert!(
            stopping.elapsed() < Duration::from_secs(2),
            "{:?}",
            stopping.elapsed()
        );
        assert!(rpki.status().is_none());
        assert!(rx.try_recv().is_err());
    }

    // The sidecar. A shell script stands in for Routinator: it answers
    // `--version` as the supported release and otherwise sleeps, and the
    // `StubCache` of this module stands in for the RTR listener Routinator
    // would open, on the port the block names.

    /// A directory for one test, removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("bgpfcd-rpki-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }

        /// An executable `#!/bin/sh` script, written by another process so
        /// that no forked child of a parallel test holds it open for
        /// writing when it is run (`ETXTBSY`).
        fn script(&self, name: &str, body: &str) -> std::path::PathBuf {
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
            assert!(status.success());
            path
        }

        /// A Routinator 0.15.2 that runs `body` unless asked its version.
        fn routinator(&self, name: &str, body: &str) -> std::path::PathBuf {
            self.script(
                name,
                &format!(
                    "if [ \"$1\" = --version ]; then echo 'Routinator 0.15.2'; exit 0; fi\n{body}"
                ),
            )
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// An `rpki` block that runs `binary` as a sidecar serving on `rtr`
    /// (port 0 to have one picked), with `block` more statements for the
    /// block and `routinator` for the `routinator` block.
    fn sidecar_block(
        dir: &Scratch,
        binary: &Path,
        rtr: &str,
        block: &str,
        routinator: &str,
    ) -> String {
        format!(
            "rpki {{ mode sidecar; invalid policy; {block}
             routinator {{ binary {}; repository-dir {}; rtr-listen {rtr}; {routinator} }} }}",
            binary.display(),
            dir.join("repo").display()
        )
    }

    fn sidecar_pid(rpki: &Rpki) -> Option<u32> {
        rpki.sidecar_report().and_then(|r| r.status.pid)
    }

    fn running_pid(rpki: &Rpki) -> u32 {
        let mut pid = None;
        eventually("the sidecar running", || {
            pid = sidecar_pid(rpki);
            pid.is_some()
        });
        pid.unwrap()
    }

    fn gone(pid: u32) -> bool {
        !Path::new(&format!("/proc/{pid}")).exists()
    }

    #[test]
    fn the_sidecars_defaults_are_the_blocks() {
        // The configuration crate cannot name the sidecar crate's
        // settings, so the defaults are written twice; here they are the
        // same.
        let routinator = ast::Routinator::new("/usr/bin/routinator", "/var/lib/rpki");
        assert_eq!(
            sidecar_config(&routinator).unwrap(),
            SidecarConfig::new("/usr/bin/routinator", "/var/lib/rpki")
        );
        // Every statement reaches the sidecar.
        let cfg = config(
            "rpki { mode sidecar; invalid drop; routinator {
                binary /opt/routinator; repository-dir /srv/rpki; rtr-listen [::1]:3323;
                rir-tals no; tal ripe; tal ripe-pilot; tal-dir /etc/tals; accept-arin-rpa yes;
                refresh 120; config-file /etc/routinator.conf;
                global-arg --strict; server-arg --http=127.0.0.1:8323; server-arg --rrdp-timeout=9;
                restart-backoff 2 90; stable-after 600; stop-timeout 20; failure-threshold 3;
            } }",
        );
        let c = sidecar_config(cfg.rpki.sidecar().unwrap()).unwrap();
        assert_eq!(c.binary, Path::new("/opt/routinator"));
        assert_eq!(c.repository_dir, Path::new("/srv/rpki"));
        assert_eq!(c.rtr_listen, "[::1]:3323".parse().unwrap());
        assert!(!c.tals.rir_tals);
        assert_eq!(c.tals.bundled, ["ripe", "ripe-pilot"]);
        assert_eq!(c.tals.extra_dir.as_deref(), Some(Path::new("/etc/tals")));
        assert!(c.accept_arin_rpa);
        assert_eq!(c.refresh, Duration::from_secs(120));
        assert_eq!(
            c.config_file.as_deref(),
            Some(Path::new("/etc/routinator.conf"))
        );
        assert_eq!(c.extra_global_args, [OsString::from("--strict")]);
        assert_eq!(
            c.extra_server_args,
            [
                OsString::from("--http=127.0.0.1:8323"),
                OsString::from("--rrdp-timeout=9")
            ]
        );
        assert_eq!(
            c.backoff,
            BackoffConfig {
                initial: Duration::from_secs(2),
                cap: Duration::from_secs(90),
                stable: Duration::from_secs(600)
            }
        );
        assert_eq!(c.stop_timeout, Duration::from_secs(20));
        assert_eq!(c.failure_threshold, 3);
    }

    #[test]
    fn the_sidecar_crate_judges_what_the_parser_cannot() {
        let block = |routinator: &str| {
            config(&format!(
                "rpki {{ mode sidecar; invalid drop; routinator {{ binary /usr/bin/routinator;
                 repository-dir /var/lib/rpki; {routinator} }} }}"
            ))
        };
        assert_eq!(validate(&block("").rpki), Ok(()));
        let unknown = validate(&block("tal nonesuch;").rpki).unwrap_err();
        assert!(
            unknown.starts_with("rpki routinator: ") && unknown.contains("nonesuch"),
            "{unknown}"
        );
        // ARIN's TAL needs the agreement accepted.
        let arin = validate(&block("tal arin;").rpki).unwrap_err();
        assert!(arin.contains("ARIN"), "{arin}");
        assert_eq!(
            validate(&block("tal arin; accept-arin-rpa yes;").rpki),
            Ok(())
        );
        // Options bgpfcd sets itself.
        let reserved = validate(&block("server-arg --rtr=0.0.0.0:3323;").rpki).unwrap_err();
        assert!(reserved.contains("--rtr"), "{reserved}");
        // A block that is not in use is not judged: `mode disabled` keeps
        // it, and the sidecar crate has nothing to say until it runs.
        let off = config(
            "rpki { mode disabled; routinator { binary /usr/bin/routinator;
             repository-dir /var/lib/rpki; tal nonesuch; } }",
        );
        assert_eq!(validate(&off.rpki), Ok(()));
        assert_eq!(validate(&config("").rpki), Ok(()));
    }

    #[test]
    fn the_sidecar_is_the_clients_one_cache() {
        let router_id = RouterId::new(0xC000_0201).unwrap();
        let cfg = config(
            "rpki { mode sidecar; invalid drop; version 0; backoff 2 20;
             routinator { binary /usr/bin/routinator; repository-dir /var/lib/rpki; } }",
        );
        for (rtr, host, port) in [
            ("127.0.0.1:3323", "127.0.0.1", 3323),
            ("[::1]:41000", "::1", 41_000),
        ] {
            let c = client_config(&cfg.rpki, router_id, Some(rtr.parse().unwrap())).unwrap();
            assert_eq!(
                c.caches,
                [Cache {
                    host: host.to_owned(),
                    port,
                    preference: 0
                }]
            );
            // The rest of the block is the client's, as for an external cache.
            assert_eq!(c.session.version, Version::V0);
            assert_eq!(
                c.backoff,
                Backoff {
                    min: Duration::from_secs(2),
                    max: Duration::from_secs(20)
                }
            );
        }
        // No sidecar, no cache.
        assert!(client_config(&cfg.rpki, router_id, None).is_none());
        // A sidecar waits less than a remote cache between attempts.
        let defaults = config(
            "rpki { mode sidecar; invalid drop;
             routinator { binary /usr/bin/routinator; repository-dir /var/lib/rpki; } }",
        );
        let c = client_config(
            &defaults.rpki,
            router_id,
            Some("127.0.0.1:1".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(c.backoff.max, ast::Rpki::DEFAULT_SIDECAR_BACKOFF_MAX);
    }

    #[test]
    fn the_client_follows_the_sidecar_through_reloads_and_shutdown() {
        let dir = Scratch::new("follow");
        let binary = dir.routinator("routinator", "exec sleep 300");
        let cache = StubCache::new();
        let rtr = format!("127.0.0.1:{}", cache.port());
        let block = |block: &str, routinator: &str| {
            config(&sidecar_block(&dir, &binary, &rtr, block, routinator))
        };
        let first = block("", "");
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&first.rpki, first.router_id, tx).unwrap();
        let pid = running_pid(&rpki);
        // The client connects to the port the sidecar serves on.
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        let report = rpki.sidecar_report().unwrap();
        assert_eq!(report.status.rtr, rtr.parse().unwrap());
        assert_eq!(report.version.to_string(), "0.15.2");
        assert_eq!(report.binary, binary);
        eventually("the client in sync", || {
            rpki.status().is_some_and(|s| s.synced_at.is_some())
        });

        // A setting of the client alone leaves the sidecar be.
        let slower = block("version 0;", "");
        assert_eq!(
            rpki.reconfigure(&first.rpki, &slower.rpki),
            Ok("rpki: rtr client restarted")
        );
        assert_eq!(sidecar_pid(&rpki), Some(pid), "the same child");
        assert!(closed(&mut conn));
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);

        // A setting of the sidecar's stops the child and starts another,
        // waiting for the first to be gone.
        let refresh = block("version 0;", "refresh 300;");
        assert_eq!(
            rpki.reconfigure(&slower.rpki, &refresh.rpki),
            Ok("rpki: sidecar and rtr client restarted")
        );
        assert!(closed(&mut conn));
        assert!(gone(pid), "the old child was reaped before the new started");
        let second = running_pid(&rpki);
        assert_ne!(second, pid);
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);

        // To `mode external` and back.
        let external = config(&cache.block());
        assert_eq!(
            rpki.reconfigure(&refresh.rpki, &external.rpki),
            Ok("rpki: sidecar stopped, rtr client restarted")
        );
        assert!(closed(&mut conn));
        assert!(gone(second));
        assert!(rpki.sidecar_report().is_none());
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        assert_eq!(
            rpki.reconfigure(&external.rpki, &first.rpki),
            Ok("rpki: sidecar and rtr client started")
        );
        assert!(closed(&mut conn));
        let third = running_pid(&rpki);
        let conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);

        // To `mode disabled`: the child goes, and every route is disabled.
        let disabled = config(&format!(
            "rpki {{ mode disabled; routinator {{ binary {}; repository-dir {}; }} }}",
            binary.display(),
            dir.join("repo").display()
        ));
        assert_eq!(
            rpki.reconfigure(&first.rpki, &disabled.rpki),
            Ok("rpki: sidecar stopped, validation disabled")
        );
        assert!(gone(third));
        drop(conn);

        // Shutdown, in its two moves, leaves no child.
        assert_eq!(
            rpki.reconfigure(&disabled.rpki, &first.rpki),
            Ok("rpki: sidecar and rtr client started")
        );
        let fourth = running_pid(&rpki);
        let _conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        rpki.begin_stop();
        rpki.stop();
        assert!(gone(fourth));
        assert!(rpki.sidecar_report().is_none() && rpki.status().is_none());
    }

    #[test]
    fn a_picked_port_is_the_ports_the_client_connects_to() {
        let dir = Scratch::new("picked");
        let binary = dir.routinator("routinator", "exec sleep 300");
        let cfg = config(&sidecar_block(&dir, &binary, "127.0.0.1:0", "", ""));
        let (tx, _rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let rtr = rpki.sidecar_report().unwrap().status.rtr;
        assert_ne!(rtr.port(), 0);
        eventually("the client to try", || {
            rpki.status()
                .is_some_and(|s| s.cache.port == rtr.port() && s.cache.host == "127.0.0.1")
        });
        rpki.stop();
    }

    #[test]
    fn a_sidecar_that_would_not_start_fails_the_start_and_the_reload() {
        let dir = Scratch::new("refused");
        let good = dir.routinator("routinator", "exec sleep 300");
        let old = dir.script("old", "echo 'Routinator 0.14.2'");
        let rtr = "127.0.0.1:0";
        let block = |binary: &Path| config(&sidecar_block(&dir, binary, rtr, "", ""));
        // At start: an old release is refused with the reason, and nothing
        // is left running.
        let (tx, _rx) = sync_channel(4);
        let e = Rpki::start(&block(&old).rpki, block(&old).router_id, tx.clone()).unwrap_err();
        assert!(
            e.starts_with(
                "cannot start the routinator sidecar: Routinator 0.14.2 is not supported"
            ),
            "{e}"
        );
        let missing = dir.join("missing");
        let e =
            Rpki::start(&block(&missing).rpki, block(&missing).router_id, tx.clone()).unwrap_err();
        assert!(
            e.starts_with("cannot start the routinator sidecar: "),
            "{e}"
        );

        // At a reload, `check_reload` says so while the old sidecar runs,
        // and costs nothing when there is nothing to check.
        let running = block(&good);
        let mut rpki = Rpki::start(&running.rpki, running.router_id, tx).unwrap();
        let pid = running_pid(&rpki);
        let e = check_reload(&running.rpki, &block(&old).rpki).unwrap_err();
        assert!(
            e.starts_with("rpki routinator: Routinator 0.14.2 is not supported"),
            "{e}"
        );
        let e = check_reload(&running.rpki, &block(&missing).rpki).unwrap_err();
        assert!(e.starts_with("rpki routinator: "), "{e}");
        assert_eq!(check_reload(&running.rpki, &running.rpki), Ok(()));
        assert_eq!(check_reload(&running.rpki, &config("").rpki), Ok(()));
        let external = config("rpki { mode external; invalid policy; cache 127.0.0.1; }");
        assert_eq!(check_reload(&running.rpki, &external.rpki), Ok(()));
        // A binary that passes is run for its version, and nothing else.
        let other = dir.routinator("other", "exit 3");
        assert_eq!(check_reload(&running.rpki, &block(&other).rpki), Ok(()));
        assert_eq!(
            sidecar_pid(&rpki),
            Some(pid),
            "the old sidecar was not touched"
        );
        rpki.stop();
        assert!(gone(pid));
    }
}
