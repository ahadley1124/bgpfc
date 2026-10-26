//! Route origin validation from RPKI caches (AGENTS.md §9 steps 12 and
//! 14): the `rpki` block run as the RTR client of `bgpfc-rtr`, feeding the
//! RIB thread, and with `mode sidecar` Routinator run by `bgpfc-sidecar`
//! as that client's one cache (issues #26, #70-#72).
//!
//! With `mode external` or `mode sidecar` the coordinator starts a
//! [`Client`] whose sink hands every [`ValidationChange`] to the RIB
//! thread as a [`RibMsg::Validation`] on the RIB's bounded channel. Like
//! an UPDATE, a change waits behind what is queued: the client cannot
//! outrun the RIB (AGENTS.md §3, "Backpressure"), and the RIB applies the
//! changes in the order the client published them (RFC 6811 §4). The RIB
//! starts with no source, every route `disabled`, and the client's first
//! full set replaces that for every route.
//!
//! With `mode sidecar`, [`Rpki::start`] first creates Routinator's
//! repository directory and starts a [`Sidecar`]: it checks the binary's
//! version, picks the RTR port when the block leaves it to bgpfcd, and
//! supervises Routinator from a thread of its own, which spawns every
//! child (`PR_SET_PDEATHSIG` follows the spawning thread). Then the client
//! starts with [`Sidecar::rtr_addr`] as its one cache, on loopback (RFC
//! 8210 §9; issue #71: no operator configuration names it). That address
//! stays the same for the life of the `Sidecar`, across every restart of
//! Routinator, so the client's own reconnect finds a restarted Routinator
//! with no special case (issue #71), and the data it holds stays in use
//! meanwhile (RFC 8210 §10, §6). The coordinator starts the block after
//! the privilege drop, so that Routinator, which fetches and parses data
//! from the internet, is born with the service user's credentials and no
//! capabilities (m14 design §4.1).
//!
//! A reload that changes the block stops the client and starts another
//! with the new settings, which keeps the data the old one published until
//! a cache sends a full set, or until it expires (RFC 8210 §10, §6; see
//! [`Client::start_holding`]): the routes keep their states meanwhile, and
//! a new set validates again only the routes it judges differently. A
//! change to `mode disabled` sends [`ValidationChange::disabled`] instead,
//! so that every route is `disabled` again. A reload that leaves the block
//! alone leaves the client alone. Routinator is restarted only when its
//! own settings change, since each start costs a validation run before it
//! listens again, and the held data covers that gap; it is started and
//! stopped as the mode comes to `sidecar` and leaves it (m14 design §5.2).
//! [`preflight`] checks before anything changes what a start of
//! Routinator would refuse, so that a reload onto a binary that would not
//! start fails and the running one goes on.
//!
//! Stopping the client, at a reload or at shutdown, joins its thread,
//! which a stop wakes from its sleep, its reads and writes, and its wait
//! for a connection attempt (see [`Client::stop`]): a cache that does not
//! answer holds up neither. The thread may still be waiting for room on
//! the RIB channel; the RIB thread makes that room, as it runs until the
//! process exits, and waits for nothing that waits for the client. At
//! shutdown the coordinator stops the block last, after the Ceases and
//! the FIB cleanup, which do not need it: the client first, so that it
//! neither warns about the cache it loses nor publishes to a RIB whose FIB
//! is gone, then Routinator (`SIGTERM`, `SIGKILL` after `stop-timeout`;
//! the supervisor restarts nothing during a requested stop, issue #70).
//!
//! The client and the sidecar log through `bgpfc_log`, so the daemon's
//! `log { level }` applies to them: a lost cache is a warning, its return
//! an info line, expired data an error; Routinator's standard error is
//! logged at warn, and a sidecar that keeps failing at error.
//!
//! Implements: RFC 8210 §6 (the Expire Interval cap and the reconnect
//! back-off configured), §7 (the version offered first), §9 (unprotected
//! TCP to the configured port, 323 by default; the sidecar's RTR on
//! loopback only), §10 (the cache list with preferences; the data kept
//! across a new cache list, and across a restart of Routinator); RFC 6811
//! §4 (each change of the VRPs reaches the RIB, which validates the
//! affected routes again).

use std::ffi::OsString;
use std::fs::DirBuilder;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use bgpfc_config::ast::{self, RpkiMode};
use bgpfc_config::{ConfigError, Pos};
use bgpfc_rpki::{RpkiError, ValidationChange, ValidationSink};
use bgpfc_rtr::Version;
use bgpfc_rtr::client::{self, Backoff, Cache, Client, Held, Status};
use bgpfc_rtr::session;
use bgpfc_sidecar::{BackoffConfig, Sidecar, SidecarConfig, TalConfig};
use bgpfc_wire::types::RouterId;

use crate::messages::{RibMsg, RpkiReport, SidecarReport};
use crate::privileges;

/// The checks of the `rpki` block that need more than the configuration
/// crate knows, as the hook of [`bgpfc_config::parse_file_with`]: their
/// errors are reported with the file's own, at their positions in it, by
/// `bgpfcd --check`, at start and at a reload. They judge the file alone,
/// like the configuration crate, and run nothing.
///
/// With `mode sidecar`, the `sidecar` block as Routinator would take it
/// ([`SidecarConfig::validate`]): TAL names, the ARIN agreement, settings
/// that leave no trust anchor, and the options the escape hatches may not
/// carry (issue #72). That is Routinator knowledge, which lives in
/// `bgpfc-sidecar` alone. The error, `rpki sidecar: ...`, is reported at
/// the `sidecar` block, or at the `mode` statement without one. With
/// another mode the block is only read, so that turning validation off
/// stays a one-word change (issue #60). Nothing runs here: the binary's
/// version is checked when the sidecar starts, where bgpfcd runs, not
/// wherever `--check` does.
pub(crate) fn check_config(config: &bgpfc_config::Config) -> Vec<ConfigError> {
    let rpki = &config.rpki;
    if rpki.mode != RpkiMode::Sidecar {
        return Vec::new();
    }
    match sidecar_config(&rpki.sidecar).validate() {
        Ok(()) => Vec::new(),
        Err(e) => {
            // The configuration crate places every `mode sidecar` block;
            // the start of the file stands in for a hand-built one.
            let pos = rpki.sidecar.pos.unwrap_or(Pos { line: 1, col: 1 });
            vec![ConfigError::new(pos, format!("rpki sidecar: {e}"))]
        }
    }
}

/// The `sidecar` block as the sidecar crate takes it. Pure.
///
/// The block's durations are whole seconds, so they meet the crate's
/// floors below a second ([`SidecarConfig::MIN_BACKOFF`],
/// [`SidecarConfig::MIN_BACKOFF_CAP`]) by construction; the configuration
/// crate's bounds are the crate's others.
pub(crate) fn sidecar_config(s: &ast::RpkiSidecar) -> SidecarConfig {
    // Destructured, so that a new setting cannot be left out.
    let ast::RpkiSidecar {
        pos: _,
        binary,
        repository_dir,
        rtr_listen,
        rir_tals,
        tals,
        extra_tals_dir,
        accept_arin_rpa,
        refresh,
        config_file,
        global_args,
        server_args,
        restart_initial,
        restart_cap,
        stable_after,
        stop_timeout,
        failure_threshold,
    } = s;
    SidecarConfig {
        binary: binary.clone(),
        rtr_listen: *rtr_listen,
        repository_dir: repository_dir.clone(),
        tals: TalConfig {
            rir_tals: *rir_tals,
            bundled: tals.clone(),
            extra_dir: extra_tals_dir.clone(),
        },
        accept_arin_rpa: *accept_arin_rpa,
        refresh: *refresh,
        config_file: config_file.clone(),
        extra_global_args: global_args.iter().map(OsString::from).collect(),
        extra_server_args: server_args.iter().map(OsString::from).collect(),
        backoff: BackoffConfig {
            initial: *restart_initial,
            cap: *restart_cap,
            stable: *stable_after,
        },
        stop_timeout: *stop_timeout,
        failure_threshold: *failure_threshold,
    }
}

/// What a reload checks before it changes anything, so that a reload that
/// would fail fails with the running configuration kept (m14 design
/// §5.1). A block that has not changed ([`ast::Rpki::same_as`]) needs
/// nothing. Otherwise:
///
/// - With `mode external`, every cache can be found, as [`resolve`]
///   checks at start (issue #60).
/// - When Routinator will start, because the mode becomes `sidecar` or
///   the `sidecar` block changes: bgpfcd is not root, since root now means
///   that no `--user` dropped it ([`privileges::sidecar_as_root`]); the
///   repository directory can be created; and [`Sidecar::check`] passes,
///   the settings and the binary's `--version` (issue #72). Without this,
///   a reload onto a Routinator that cannot start would stop the running
///   one first, and only then fail. A change to the client's settings
///   alone starts no Routinator and checks none of this.
///
/// # Errors
/// What fails, for the reload's error.
pub(crate) fn preflight(old: &ast::Rpki, new: &ast::Rpki) -> Result<(), String> {
    preflight_as(old, new, bgpfc_sys::is_root())
}

/// [`preflight`] for a bgpfcd that is `root` or not.
fn preflight_as(old: &ast::Rpki, new: &ast::Rpki, root: bool) -> Result<(), String> {
    if old.same_as(new) {
        return Ok(());
    }
    match new.mode {
        RpkiMode::Disabled => Ok(()),
        RpkiMode::External => resolve(new),
        RpkiMode::Sidecar if old.mode == RpkiMode::Sidecar && old.sidecar.same_as(&new.sidecar) => {
            Ok(())
        }
        RpkiMode::Sidecar => {
            if let Some(refused) = privileges::sidecar_as_root(root, None, new.mode) {
                return Err(format!("{refused}: {}", privileges::SIDECAR_AS_ROOT_HINT));
            }
            create_repository_dir(&new.sidecar.repository_dir)?;
            Sidecar::check(&sidecar_config(&new.sidecar))
                .map_err(|e| format!("rpki sidecar: {e}"))?;
            Ok(())
        }
    }
}

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

/// The client's configuration for `rpki`, or `None` in a mode without a
/// client. `sidecar` is where the running sidecar serves RTR, which with
/// `mode sidecar` is the client's one cache, at preference 0 (issue #71:
/// wired without operator configuration); `mode external` lists its
/// caches itself.
pub(crate) fn client_config(
    rpki: &ast::Rpki,
    router_id: RouterId,
    sidecar: Option<SocketAddr>,
) -> Option<client::Config> {
    let caches = match rpki.mode {
        RpkiMode::Disabled => return None,
        RpkiMode::External => rpki
            .caches
            .iter()
            .map(|c| Cache {
                host: c.host.clone(),
                port: c.port,
                preference: c.preference,
            })
            .collect(),
        RpkiMode::Sidecar => {
            let Some(addr) = sidecar else {
                debug_assert!(false, "mode sidecar without the sidecar's address");
                return None;
            };
            // An address, so the client's lookup cannot fail; and on
            // loopback, as the configuration crate and the sidecar crate
            // both insist (RFC 8210 §9).
            vec![Cache {
                host: addr.ip().to_string(),
                port: addr.port(),
                preference: 0,
            }]
        }
    };
    let mut config = client::Config::new(caches);
    config.connect_timeout = rpki.connect_timeout;
    // With `mode sidecar` the block's default is `1 30` rather than
    // `1 600` (`ast::Rpki::default_backoff`), so that the client finds
    // Routinator soon after its first validation run lets it listen.
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

/// Create Routinator's repository directory, with the parents it lacks,
/// as the user bgpfcd runs as: `0750`, for Routinator and bgpfcd's group
/// alone. One that exists is left as it is.
///
/// # Errors
/// The directory could not be created, naming it.
fn create_repository_dir(path: &Path) -> Result<(), String> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(path)
        .map_err(|e| {
            format!(
                "cannot create the rpki repository directory {}: {e}",
                path.display()
            )
        })
}

/// Start Routinator as `s` says: its repository directory, then
/// [`Sidecar::start`], which checks the binary's version (issue #72: a
/// mismatch is reported at startup), picks the RTR port if `s` leaves it
/// to bgpfcd, and starts supervising.
///
/// # Errors
/// What failed, for `cannot start rpki` or a reload's notes.
fn start_sidecar(s: &ast::RpkiSidecar) -> Result<Sidecar, String> {
    create_repository_dir(&s.repository_dir)?;
    bgpfc_log::info!(
        "rpki: starting the routinator sidecar",
        binary = s.binary.display(),
        repository_dir = s.repository_dir.display(),
        rtr_listen = s.rtr_listen
    );
    Sidecar::start(sidecar_config(s)).map_err(|e| format!("rpki sidecar: {e}"))
}

/// Where the client publishes: the RIB thread's bounded channel. A send
/// waits while the channel is full, and fails once the RIB thread is
/// gone, which stops the client. The first change ends the wait for
/// validation data, if routes were waiting, and says so (issue #71: the
/// startup window is not silent; m14 design §3.3).
fn sink(rib: SyncSender<RibMsg>, waiting: Arc<Mutex<Option<Instant>>>) -> impl ValidationSink {
    move |change: ValidationChange| {
        let since = lock(&waiting).take();
        if let Some(since) = since {
            // The RIB's `rib: validation states changed` line follows,
            // and the client's `rtr validation data committed`, with the
            // number of VRPs, came just before.
            bgpfc_log::info!(
                "rpki: validation data arrived; routes are validated from now on",
                waited = format!("{}s", since.elapsed().as_secs())
            );
        }
        rib.send(RibMsg::Validation(change))
            .map_err(|_| RpkiError::SinkClosed)
    }
}

/// The lock, also after a panic elsewhere: nothing that holds it can
/// panic halfway through an update.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The running `rpki` block: the RTR client, if its mode has one, and
/// Routinator, with `mode sidecar`.
#[derive(Debug)]
pub(crate) struct Rpki {
    rib: SyncSender<RibMsg>,
    router_id: RouterId,
    client: Option<Client>,
    /// Routinator, supervised; the client's one cache.
    sidecar: Option<Sidecar>,
    /// Since when every route has waited for the first full set, unused
    /// for validation: set when a client starts with no data to hold,
    /// cleared by the first change it publishes, or when validation is
    /// disabled (m14 design §3.3).
    waiting: Arc<Mutex<Option<Instant>>>,
}

impl Rpki {
    /// Start what `config` asks for, publishing to `rib`: with `mode
    /// sidecar`, the repository directory and Routinator, then the client
    /// at Routinator's address. The caller has checked with [`resolve`]
    /// that external caches can be found, and calls this after the
    /// privilege drop, so that Routinator runs as the service user (m14
    /// design §4.1).
    ///
    /// # Errors
    /// What could not be started, for `cannot start rpki`: the repository
    /// directory, Routinator (a binary that is missing, fails or reports
    /// another release), or the client thread. A sidecar already started
    /// is stopped again.
    pub(crate) fn start(
        config: &ast::Rpki,
        router_id: RouterId,
        rib: SyncSender<RibMsg>,
    ) -> Result<Rpki, String> {
        let mut rpki = Rpki {
            rib,
            router_id,
            client: None,
            sidecar: None,
            waiting: Arc::default(),
        };
        if config.mode == RpkiMode::Sidecar {
            rpki.sidecar = Some(start_sidecar(&config.sidecar)?);
        }
        // On an error `rpki` is dropped, and with it the sidecar, which
        // stops it.
        rpki.client = rpki
            .spawn_client(config, None)
            .map_err(|e| format!("cannot start the rtr client: {e}"))?;
        Ok(rpki)
    }

    /// A client for `config`, holding `held`, if its mode runs one; with
    /// `mode sidecar`, at the running sidecar's address. A client with no
    /// data to hold leaves the routes waiting for its first full set.
    fn spawn_client(&self, config: &ast::Rpki, held: Option<Held>) -> io::Result<Option<Client>> {
        let sidecar = self.sidecar.as_ref().map(Sidecar::rtr_addr);
        let Some(client_config) = client_config(config, self.router_id, sidecar) else {
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
        if held.is_none() {
            self.wait_for_data(config);
        }
        let sink = sink(self.rib.clone(), Arc::clone(&self.waiting));
        let client = Client::start_holding(client_config, sink, held)?;
        Ok(Some(client))
    }

    /// Note that the routes wait for the first full set, from now unless
    /// they waited already, and say so (issue #71). Until it arrives every
    /// route is `disabled`, used as received: RFC 6811 §2 lets no route
    /// leave route selection for its state without configuration, and the
    /// import-policy term `match rpki disabled; action reject;` is that
    /// configuration for those who want routes held instead (m14 design
    /// §3.2). With the sidecar the wait is Routinator's first validation
    /// run, minutes from a cold repository, so it is a warning; an
    /// external cache answers within a moment, which is no news.
    fn wait_for_data(&self, config: &ast::Rpki) {
        const WAITING: &str =
            "rpki: no validation data yet; routes are used unvalidated until the first full set";
        lock(&self.waiting).get_or_insert_with(Instant::now);
        if config.mode == RpkiMode::Sidecar {
            bgpfc_log::warn!(
                WAITING,
                mode = config.mode,
                enforcement = config.enforcement,
                hint = "Routinator serves RTR once its first validation run ends: minutes from a cold cache"
            );
        } else {
            bgpfc_log::info!(
                WAITING,
                mode = config.mode,
                enforcement = config.enforcement
            );
        }
    }

    /// Apply `new`, the block of a reloaded configuration, in place of
    /// `old`, the running one; what was done, for the reload's summary.
    /// The caller has checked `new` with [`preflight`].
    ///
    /// A block that has not changed ([`ast::Rpki::same_as`]) changes
    /// nothing; an `enforcement` alone is no change here, as the RIB
    /// judges the routes again. Otherwise the client is restarted, holding
    /// the data the old one published until a cache sends a full set or
    /// the data expires (RFC 8210 §10, §6), and Routinator (m14 design
    /// §5.2):
    ///
    /// - is left running when only the client's settings change: the new
    ///   client connects to the same address;
    /// - is stopped and started again when its own settings change. Its
    ///   address may change with it; the held data covers the validation
    ///   run before it listens again;
    /// - is started when the mode becomes `sidecar`, from `external` with
    ///   the external cache's data held, from `disabled` with nothing to
    ///   hold, so that the routes wait for its first full set;
    /// - is stopped when the mode leaves `sidecar`, after the client.
    ///
    /// A Routinator that keeps failing is not restarted by a reload that
    /// leaves its block alone: its supervisor keeps retrying.
    ///
    /// # Errors
    /// Routinator or the client could not be started although the
    /// preflight passed, as when the binary changed in between. Validation
    /// is then off, as with `mode disabled`: with no client, nothing would
    /// expire the data the old one left in the RIB.
    pub(crate) fn reconfigure(
        &mut self,
        old: &ast::Rpki,
        new: &ast::Rpki,
    ) -> Result<&'static str, String> {
        if old.same_as(new) {
            return Ok("rpki unchanged");
        }
        let sidecar = new.mode == RpkiMode::Sidecar;
        let had_sidecar = self.sidecar.is_some();
        // Also when an earlier start failed and none runs.
        let starting = sidecar && (!had_sidecar || !old.sidecar.same_as(&new.sidecar));
        let ran = self.client.is_some();
        let held = self.stop_client();
        if starting || !sidecar {
            self.stop_sidecar();
        }
        if starting {
            match start_sidecar(&new.sidecar) {
                Ok(started) => self.sidecar = Some(started),
                Err(e) => {
                    self.disable();
                    bgpfc_log::error!("rpki: cannot start the sidecar", error = e);
                    return Err(format!(
                        "rpki: cannot start the sidecar ({e}); validation disabled"
                    ));
                }
            }
        }
        let stopped = had_sidecar && !sidecar;
        match self.spawn_client(new, held) {
            Ok(Some(client)) => {
                self.client = Some(client);
                Ok(match (starting, had_sidecar, stopped, ran) {
                    (true, true, _, _) => "rpki: sidecar restarted",
                    (true, false, _, _) => "rpki: sidecar started",
                    (false, _, true, true) => "rpki: rtr client restarted; sidecar stopped",
                    (false, _, true, false) => "rpki: rtr client started; sidecar stopped",
                    (false, _, false, true) => "rpki: rtr client restarted",
                    (false, _, false, false) => "rpki: rtr client started",
                })
            }
            Ok(None) if ran || stopped => {
                self.disable();
                Ok(if stopped {
                    "rpki: validation disabled; sidecar stopped"
                } else {
                    "rpki: validation disabled"
                })
            }
            Ok(None) => Ok("rpki: validation stays disabled"),
            Err(e) => {
                // A Routinator that no client reads is of no use.
                self.stop_sidecar();
                self.disable();
                bgpfc_log::error!("rpki: cannot start the rtr client", error = e);
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

    /// Stop Routinator, if it runs, and return once it is gone: `SIGTERM`,
    /// `SIGKILL` after `stop-timeout`, reaped with its process group, every
    /// thread joined. The sidecar logs the stop itself.
    fn stop_sidecar(&mut self) {
        if let Some(sidecar) = self.sidecar.take() {
            sidecar.stop();
        }
    }

    /// Turn validation off in the RIB: every route `disabled`, and no
    /// longer waiting for data.
    fn disable(&self) {
        *lock(&self.waiting) = None;
        bgpfc_log::info!("rpki: validation disabled; every route is disabled again");
        // A RIB thread that is gone has no routes to tell.
        let _ = self
            .rib
            .send(RibMsg::Validation(ValidationChange::disabled()));
    }

    /// Stop the block for good, at shutdown: the client first, then
    /// Routinator, so that the client neither warns about the cache it
    /// loses nor publishes what it would read from a Routinator on its way
    /// down (m14 design §4.3). It returns once both are gone; see the
    /// module documentation.
    pub(crate) fn stop(&mut self) {
        self.stop_client();
        self.stop_sidecar();
    }

    /// The client's status, if one runs.
    pub(crate) fn status(&self) -> Option<Status> {
        self.client.as_ref().map(Client::status)
    }

    /// What the control plane shows of the running block `config`: the
    /// client's status, since when the routes have waited for the first
    /// full set, and Routinator's status and version, read now rather than
    /// kept, since a restart after the binary was replaced may change the
    /// version (issue #70: a validator that is not running must be
    /// visible).
    pub(crate) fn report(&self, config: &ast::Rpki) -> RpkiReport {
        RpkiReport {
            config: config.clone(),
            status: self.status(),
            waiting_since: *lock(&self.waiting),
            // A sidecar runs only with `mode sidecar`, started from this
            // block's `sidecar` settings: a change to them restarts it.
            sidecar: self.sidecar.as_ref().map(|s| SidecarReport {
                status: s.status(),
                version: s.version(),
                binary: config.sidecar.binary.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::{ErrorKind, Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::thread;
    use std::time::{Duration, Instant};

    use bgpfc_config::Config;
    use bgpfc_rpki::{AffectedPrefixes, RouteOrigin, RovState, Vrp};
    use bgpfc_rtr::{Framer, Intervals, Pdu};
    use bgpfc_sidecar::{SidecarState, TESTED_VERSION};
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
                "rpki {{ mode external; cache 127.0.0.1 port {}; }}",
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
                mode external;
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
        let cfg = config("rpki { mode external; cache 192.0.2.10; }");
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
        let ok = config("rpki { mode external; cache 127.0.0.1; cache ::1; cache localhost; }");
        assert_eq!(resolve(&ok.rpki), Ok(()));
        // RFC 2606 §2: `.invalid` never resolves.
        let bad = config(
            "rpki { mode external; cache 127.0.0.1; cache rtr.invalid;
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

    /// The parse hook finds nothing in a file the sidecar crate accepts,
    /// so such a file loads as the configuration crate alone judges it.
    #[test]
    fn the_parse_hook_accepts_the_modes_bgpfcd_runs() {
        for rpki in [
            "",
            "rpki { mode disabled; }",
            "rpki { mode external; cache 192.0.2.10; }",
            "rpki { mode sidecar; }",
        ] {
            let errors = check_config(&config(rpki));
            assert!(errors.is_empty(), "{rpki}: {errors:?}");
        }
    }

    /// The golden file with every sidecar statement written out, read
    /// from the configuration crate's tests.
    const FULL_SIDECAR: &str = include_str!("../../bgpfc-config/tests/golden/rpki-sidecar.conf");
    /// The golden file with the one-line sidecar block.
    const DEFAULT_SIDECAR: &str =
        include_str!("../../bgpfc-config/tests/golden/rpki-sidecar-defaults.conf");

    #[test]
    fn the_sidecar_settings_lower_to_the_sidecar_crate() {
        let cfg = bgpfc_config::parse_str("rpki-sidecar.conf", FULL_SIDECAR).unwrap();
        let expected = SidecarConfig {
            binary: "/opt/routinator/bin/routinator".into(),
            rtr_listen: "[::1]:3323".parse().unwrap(),
            repository_dir: "/var/lib/bgpfc/rpki cache".into(),
            tals: TalConfig {
                rir_tals: false,
                bundled: vec!["ripe".to_owned(), "ripe-pilot".to_owned()],
                extra_dir: Some("/etc/bgpfc/tals".into()),
            },
            accept_arin_rpa: true,
            refresh: Duration::from_secs(300),
            config_file: Some("/etc/bgpfc/routinator.conf".into()),
            extra_global_args: vec![
                "--strict".into(),
                "--exceptions=/etc/bgpfc/slurm;local.json".into(),
            ],
            extra_server_args: vec![
                "--rtr-tcp-keepalive=30".into(),
                "--http=127.0.0.1:8323".into(),
            ],
            backoff: BackoffConfig {
                initial: Duration::from_secs(2),
                cap: Duration::from_secs(600),
                stable: Duration::from_mins(15),
            },
            stop_timeout: Duration::from_secs(20),
            failure_threshold: 3,
        };
        assert_eq!(sidecar_config(&cfg.rpki.sidecar), expected);
    }

    /// The defaults and bounds of the `sidecar` block are those of the
    /// sidecar crate (m14 design §1.2), as m12 checks the RTR client's.
    #[test]
    fn the_sidecar_defaults_are_the_sidecar_crates() {
        use bgpfc_config::ast::RpkiSidecar as S;
        assert_eq!(
            sidecar_config(&S::default()),
            SidecarConfig::new(S::DEFAULT_BINARY, S::DEFAULT_REPOSITORY_DIR)
        );
        let cfg = bgpfc_config::parse_str("defaults", DEFAULT_SIDECAR).unwrap();
        assert_eq!(
            sidecar_config(&cfg.rpki.sidecar),
            SidecarConfig::new(S::DEFAULT_BINARY, S::DEFAULT_REPOSITORY_DIR)
        );
        assert_eq!(S::DEFAULT_REFRESH, SidecarConfig::DEFAULT_REFRESH);
        assert_eq!(S::DEFAULT_STOP_TIMEOUT, SidecarConfig::DEFAULT_STOP_TIMEOUT);
        assert_eq!(
            S::DEFAULT_FAILURE_THRESHOLD,
            SidecarConfig::DEFAULT_FAILURE_THRESHOLD
        );
        let backoff = BackoffConfig::default();
        assert_eq!(S::DEFAULT_RESTART_INITIAL, backoff.initial);
        assert_eq!(S::DEFAULT_RESTART_CAP, backoff.cap);
        assert_eq!(S::DEFAULT_STABLE_AFTER, backoff.stable);
        // The bounds the language allows are the crate's: whole seconds
        // meet its sub-second floors, and the longest values are its own.
        assert_eq!(S::MAX_RESTART_BACKOFF, SidecarConfig::MAX_DELAY);
        assert_eq!(S::MAX_STOP_TIMEOUT, SidecarConfig::MAX_DELAY);
        assert_eq!(S::MAX_STABLE_AFTER, SidecarConfig::MAX_STABLE);
        assert!(Duration::from_secs(1) >= SidecarConfig::MIN_BACKOFF);
        assert!(Duration::from_secs(1) >= SidecarConfig::MIN_BACKOFF_CAP);
        assert_eq!(S::MAX_REFRESH, Duration::from_secs(7_199));
        // So the extremes the language accepts pass the crate's checks,
        // and one second past the longest refresh does not.
        let extremes = [
            "refresh 1; restart-backoff 1 1; stable-after 1; stop-timeout 1; \
             failure-threshold 1;",
            "refresh 7199; restart-backoff 3600 3600; stable-after 86400; \
             stop-timeout 3600; failure-threshold 4294967295;",
        ];
        for settings in extremes {
            let cfg = config(&format!(
                "rpki {{ mode sidecar; sidecar {{ {settings} }} }}"
            ));
            assert_eq!(sidecar_config(&cfg.rpki.sidecar).validate(), Ok(()));
        }
        let mut past = sidecar_config(&S::default());
        past.refresh = S::MAX_REFRESH + Duration::from_secs(1);
        assert!(past.validate().is_err());
    }

    #[test]
    fn every_sidecar_block_the_parser_accepts_passes_validate() {
        for (name, text) in [
            ("rpki-sidecar.conf", FULL_SIDECAR),
            ("rpki-sidecar-defaults.conf", DEFAULT_SIDECAR),
        ] {
            let cfg = bgpfc_config::parse_str_with(name, text, &check_config);
            assert!(cfg.is_ok(), "{name}: {}", cfg.unwrap_err());
        }
    }

    /// Issue #72: what only Routinator's rules refuse is reported at the
    /// `sidecar` block, with the file's position and caret, as any other
    /// error; under `mode disabled` the same block is only read.
    #[test]
    fn routinator_rules_are_reported_at_the_sidecar_block() {
        let cases = [
            (
                "tals ripe-ncc;",
                "rpki sidecar: Routinator 0.15 bundles no TAL named \"ripe-ncc\"; it knows \
                 afrinic, apnic, arin, lacnic, ripe, apnic-testbed, arin-ote, ripe-pilot, \
                 nlnetlabs-testbed",
            ),
            (
                "tals arin;",
                "rpki sidecar: the ARIN TAL is listed, but ARIN's Relying Party Agreement \
                 has not been accepted",
            ),
            (
                "rir-tals no;",
                "rpki sidecar: no trust anchors: enable the RIR TALs, name a bundled TAL or \
                 give an extra TAL directory",
            ),
            (
                "global-args \"-d\";",
                "rpki sidecar: extra Routinator argument \"-d\" is not allowed: a detached \
                 Routinator leaves bgpfcd's supervision",
            ),
            (
                "server-args \"--rtr=0.0.0.0:323\";",
                "rpki sidecar: extra Routinator argument \"--rtr=0.0.0.0:323\" is not \
                 allowed: bgpfcd passes --rtr; RTR is served on the configured loopback \
                 address only",
            ),
        ];
        let head = "router-id 192.0.2.1;\nlocal-as 65000;\n";
        for (statement, message) in cases {
            let block = format!("  sidecar {{ {statement} }}");
            let text = format!("{head}rpki {{\n  mode sidecar;\n{block}\n}}\n");
            let errors = bgpfc_config::parse_str_with("t", &text, &check_config).unwrap_err();
            assert_eq!(
                errors.to_string(),
                format!("t:5:3: {message}\n  {block}\n    ^"),
                "{statement}"
            );
            let disabled = text.replace("mode sidecar", "mode disabled");
            let cfg = bgpfc_config::parse_str_with("t", &disabled, &check_config);
            assert!(cfg.is_ok(), "{statement}: {}", cfg.unwrap_err());
        }
        // Without a block, at the mode, which is all there is to point to.
        let config = bgpfc_config::Config {
            rpki: ast::Rpki {
                sidecar: ast::RpkiSidecar {
                    pos: Some(Pos { line: 3, col: 8 }),
                    rir_tals: false,
                    ..ast::RpkiSidecar::default()
                },
                ..ast::Rpki::defaults(RpkiMode::Sidecar)
            },
            ..config("")
        };
        let errors = check_config(&config);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].pos, Pos { line: 3, col: 8 });
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
                "rpki {{ mode external; cache {host} port {}; }}",
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
            "rpki {{ mode external; cache 127.0.0.1 port {};
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

    /// A directory of its own for one test, under the system's temporary
    /// directory, removed afterwards.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let name = format!("bgpfcd-rpki-{tag}-{}-{n}", std::process::id());
            let path = std::env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Scratch(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        /// An executable `#!/bin/sh` script `name` running `body`.
        ///
        /// Another process writes it, as bgpfc-sidecar's tests do: were
        /// this process to hold it open for writing while a parallel test
        /// forks, the forked child would hold it too until it executes,
        /// and running the script meanwhile would fail with `ETXTBSY`.
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

        /// A stub Routinator, never the real one (AGENTS.md §5): it
        /// answers `--version` with `Routinator {version}` and otherwise
        /// runs `body`.
        fn routinator(&self, version: &str, body: &str) -> PathBuf {
            let version =
                format!("if [ \"$1\" = --version ]; then echo 'Routinator {version}'; exit 0; fi");
            self.script("routinator", &format!("{version}\n{body}"))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The release the sidecar crate drives, as `--version` prints it.
    fn tested() -> String {
        TESTED_VERSION.to_string()
    }

    /// A block that runs `binary` with its repository in `repository`,
    /// serving RTR on 127.0.0.1 at `port`, or at one picked at start for 0.
    fn sidecar_block(binary: &Path, repository: &Path, port: u16) -> String {
        sidecar_block_with(binary, repository, port, "", "")
    }

    /// [`sidecar_block`] with more statements: `rpki` in the `rpki` block,
    /// `sidecar` in the `sidecar` block.
    fn sidecar_block_with(
        binary: &Path,
        repository: &Path,
        port: u16,
        rpki: &str,
        sidecar: &str,
    ) -> String {
        format!(
            "rpki {{ mode sidecar; {rpki} sidecar {{ binary \"{}\"; repository-dir \"{}\"; \
             rtr-listen 127.0.0.1 port {port}; {sidecar} }} }}",
            binary.display(),
            repository.display()
        )
    }

    /// Routinator's process id, once it runs.
    fn routinator_pid(rpki: &Rpki) -> u32 {
        let sidecar = rpki.sidecar.as_ref().expect("a sidecar");
        let deadline = Instant::now() + WAIT;
        loop {
            if let SidecarState::Running { pid, .. } = sidecar.status().state {
                return pid;
            }
            assert!(Instant::now() < deadline, "routinator did not start");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Whether process `pid` exists, if only as a zombie.
    fn alive(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Since when the routes have waited for the first full set.
    fn waiting(rpki: &Rpki) -> Option<Instant> {
        *lock(&rpki.waiting)
    }

    /// Issue #71, m14 design §3.3: a client that starts with no data
    /// leaves the routes waiting until its first full set; one that takes
    /// data over does not; disabling validation ends the wait.
    #[test]
    fn validation_waits_for_the_first_full_set() {
        let first = StubCache::new();
        let cfg = config(&first.block());
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let since = waiting(&rpki).expect("waiting from the start");
        let report = rpki.report(&cfg.rpki);
        assert_eq!(report.waiting_since, Some(since));
        assert!(report.sidecar.is_none(), "an external cache has no sidecar");
        // Until the cache answers, nothing ends the wait.
        let (mut conn, query) = first.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        assert_eq!(waiting(&rpki), Some(since));
        drop(conn);
        let _conn = first.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        next_change(&rx);
        assert_eq!(waiting(&rpki), None);

        // A new cache list: the new client holds the old data, which stays
        // in use until the new cache answers, so nothing waits.
        let second = StubCache::new();
        let moved = config(&second.block());
        assert_eq!(
            rpki.reconfigure(&cfg.rpki, &moved.rpki),
            Ok("rpki: rtr client restarted")
        );
        let (mut taken_over, _) = second.accept();
        assert_eq!(waiting(&rpki), None);

        // Back from `mode disabled` there is nothing to hold: the routes
        // wait again, and disabling ends that.
        let off = config("rpki { mode disabled; }");
        assert_eq!(
            rpki.reconfigure(&moved.rpki, &off.rpki),
            Ok("rpki: validation disabled")
        );
        assert!(closed(&mut taken_over));
        next_change(&rx);
        assert_eq!(
            rpki.reconfigure(&off.rpki, &moved.rpki),
            Ok("rpki: rtr client started")
        );
        assert!(waiting(&rpki).is_some());
        conn = second.accept().0;
        assert_eq!(
            rpki.reconfigure(&moved.rpki, &off.rpki),
            Ok("rpki: validation disabled")
        );
        assert!(closed(&mut conn));
        assert_eq!(waiting(&rpki), None);
        rpki.stop();
    }

    /// Issue #71: with `mode sidecar` the client's one cache is the
    /// sidecar's loopback address, with the block's client settings and
    /// the sidecar's own back-off default.
    #[test]
    fn the_client_uses_the_sidecar_alone() {
        let router_id = RouterId::new(0xC000_0201).unwrap();
        let cfg = config(
            "rpki { mode sidecar; version 0; connect-timeout 5; response-timeout 30;
             reply-timeout 600; max-expire 3600; max-vrps 1000; }",
        );
        let addr: SocketAddr = "127.0.0.1:3323".parse().unwrap();
        let c = client_config(&cfg.rpki, router_id, Some(addr)).unwrap();
        let sidecar = Cache {
            host: "127.0.0.1".to_owned(),
            port: 3323,
            preference: 0,
        };
        assert_eq!(c.caches, [sidecar]);
        // m14 design §3.4: `1 30`, so that the client finds Routinator
        // soon after it starts to listen.
        let backoff = Backoff {
            min: Duration::from_secs(1),
            max: Duration::from_secs(30),
        };
        assert_eq!(c.backoff, backoff);
        assert_eq!(c.connect_timeout, Duration::from_secs(5));
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
        let v6 = client_config(&cfg.rpki, router_id, Some("[::1]:3323".parse().unwrap())).unwrap();
        assert_eq!(v6.caches[0].host, "::1");
        assert_eq!(v6.caches[0].to_string(), "[::1]:3323");
        // A written back-off is the block's.
        let written = config("rpki { mode sidecar; backoff 2 5; }");
        let c = client_config(&written.rpki, router_id, Some(addr)).unwrap();
        assert_eq!(c.backoff.min, Duration::from_secs(2));
        assert_eq!(c.backoff.max, Duration::from_secs(5));
        // Only `mode sidecar` uses the sidecar's address.
        let external = config("rpki { mode external; cache 192.0.2.10; }");
        let c = client_config(&external.rpki, router_id, Some(addr)).unwrap();
        assert_eq!(c.caches, [Cache::new("192.0.2.10")]);
        let disabled = config("rpki { mode disabled; }");
        assert!(client_config(&disabled.rpki, router_id, Some(addr)).is_none());
    }

    /// Issues #26 and #71: `mode sidecar` starts Routinator and wires the
    /// client to it with no cache written; the data it serves reaches the
    /// RIB; stopping ends the client, then Routinator. The stub sleeps,
    /// and the module's cache serves the port it was told to use (m14
    /// design §7.3), so this tests the wiring without an RTR server.
    #[test]
    fn the_sidecar_serves_the_rib() {
        let dir = Scratch::new("serves");
        let binary = dir.routinator(&tested(), "exec sleep 600");
        let cache = StubCache::new();
        let cfg = config(&sidecar_block(&binary, &dir.join("repo"), cache.port()));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let rtr = SocketAddr::from((Ipv4Addr::LOCALHOST, cache.port()));
        let sidecar = rpki.sidecar.as_ref().unwrap();
        assert_eq!(sidecar.rtr_addr(), rtr);
        assert_eq!(sidecar.status().rtr, rtr);
        assert_eq!(sidecar.version(), TESTED_VERSION);
        let pid = routinator_pid(&rpki);
        assert!(waiting(&rpki).is_some(), "routes wait for Routinator");
        // What the control plane shows (m14 design §4.6), read from the
        // sidecar at the request.
        let report = rpki.report(&cfg.rpki);
        assert_eq!(report.waiting_since, waiting(&rpki));
        let shown = report.sidecar.expect("the sidecar is reported");
        assert!(
            matches!(shown.status.state, SidecarState::Running { pid: p, .. } if p == pid),
            "{:?}",
            shown.status
        );
        assert_eq!(shown.status.rtr, rtr);
        assert_eq!(shown.version, TESTED_VERSION);
        assert_eq!(shown.binary, binary);

        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        let change = next_change(&rx);
        assert_eq!(waiting(&rpki), None);
        assert_eq!(rpki.report(&cfg.rpki).waiting_since, None);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_497), RovState::Invalid);
        eventually("the client in sync", || {
            rpki.status().is_some_and(|s| s.synced_at.is_some())
        });
        let status = rpki.status().unwrap();
        assert_eq!(status.cache.to_string(), rtr.to_string());
        assert_eq!(status.vrps_ipv4, 1);

        rpki.stop();
        assert!(closed(&mut conn), "no client is left");
        assert!(!alive(pid), "routinator is gone");
        assert!(rpki.sidecar.is_none());
        assert!(rpki.status().is_none());
        let report = rpki.report(&cfg.rpki);
        assert!(report.sidecar.is_none() && report.status.is_none());
        assert!(rx.try_recv().is_err());
    }

    /// m14 design §4.3: at shutdown the client lets go of Routinator
    /// before Routinator gets its `SIGTERM`.
    #[test]
    fn the_client_stops_before_routinator() {
        let dir = Scratch::new("order");
        let (ready, termed) = (dir.join("ready"), dir.join("termed"));
        // It marks the SIGTERM, then takes a second to exit: stopped
        // first, it would see the client connected all that second.
        let body = format!(
            "trap 'touch \"{}\"; sleep 1; exit 0' TERM\ntouch \"{}\"\nsleep 600 &\nwait",
            termed.display(),
            ready.display()
        );
        let binary = dir.routinator(&tested(), &body);
        let cache = StubCache::new();
        let cfg = config(&sidecar_block(&binary, &dir.join("repo"), cache.port()));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let pid = routinator_pid(&rpki);
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        next_change(&rx);
        // From here on the stub has its trap.
        eventually("the stub's trap", || ready.exists());
        conn.set_nonblocking(true).unwrap();
        let watcher = thread::spawn(move || {
            let deadline = Instant::now() + WAIT;
            while !termed.exists() {
                assert!(Instant::now() < deadline, "routinator got no SIGTERM");
                thread::sleep(Duration::from_millis(5));
            }
            let mut buf = [0; 16];
            match conn.read(&mut buf) {
                Ok(n) => n == 0,
                Err(e) => e.kind() == ErrorKind::ConnectionReset,
            }
        });
        rpki.stop();
        let client_gone = watcher.join().unwrap();
        assert!(
            client_gone,
            "routinator was stopped under a connected client"
        );
        assert!(!alive(pid));
    }

    /// Issue #72: a version mismatch is reported clearly at startup, and
    /// no server is started.
    #[test]
    fn a_routinator_of_another_release_stops_the_start() {
        let dir = Scratch::new("release");
        let served = dir.join("served");
        let body = format!("touch '{}'\nexec sleep 600", served.display());
        let binary = dir.routinator("0.14.1", &body);
        let cfg = config(&sidecar_block(&binary, &dir.join("repo"), 0));
        let (tx, rx) = sync_channel(4);
        let err = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap_err();
        assert!(
            err.starts_with("rpki sidecar: Routinator 0.14.1 is not supported: "),
            "{err}"
        );
        assert!(err.contains("0.15"), "{err}");
        assert!(!served.exists(), "a server was started");
        assert!(rx.try_recv().is_err());
    }

    /// Issue #60: a binary that is not there stops the start, naming it.
    #[test]
    fn a_missing_routinator_stops_the_start() {
        let dir = Scratch::new("missing");
        let binary = dir.join("routinator");
        let cfg = config(&sidecar_block(&binary, &dir.join("repo"), 0));
        let (tx, rx) = sync_channel(4);
        let err = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap_err();
        let expected = format!(
            "rpki sidecar: `{} --version` could not be started: ",
            binary.display()
        );
        assert!(err.starts_with(&expected), "{err}");
        assert!(rx.try_recv().is_err());
    }

    /// The repository directory is created with its parents, for
    /// Routinator and bgpfcd's group alone; one that cannot be created
    /// stops the start before Routinator runs at all.
    #[test]
    fn the_repository_directory_is_created() {
        let dir = Scratch::new("repository");
        let binary = dir.routinator(&tested(), "exec sleep 600");
        let repository = dir.join("state/bgpfc/rpki");
        let cfg = config(&sidecar_block(&binary, &repository, 0));
        let (tx, _rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let meta = fs::metadata(&repository).unwrap();
        assert!(meta.is_dir());
        let mode = meta.permissions().mode() & 0o777;
        // 0750, less what the umask takes away.
        assert_eq!(mode & !0o750, 0, "{mode:o}");
        // Port 0: one picked at start, on the configured address, which
        // the client uses.
        let rtr = rpki.sidecar.as_ref().unwrap().rtr_addr();
        assert_eq!(rtr.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(rtr.port(), 0);
        assert_eq!(rpki.status().unwrap().cache.port, rtr.port());
        rpki.stop();

        let ran = dir.join("ran");
        let body = format!("touch '{}'\necho 'Routinator {}'", ran.display(), tested());
        let marking = dir.script("marking", &body);
        fs::write(dir.join("file"), "").unwrap();
        let blocked = dir.join("file/rpki");
        let cfg = config(&sidecar_block(&marking, &blocked, 0));
        let (tx, rx) = sync_channel(4);
        let err = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap_err();
        let expected = format!(
            "cannot create the rpki repository directory {}: ",
            blocked.display()
        );
        assert!(err.starts_with(&expected), "{err}");
        assert!(!ran.exists(), "routinator ran");
        assert!(rx.try_recv().is_err());
    }

    /// A Routinator stub that sleeps, in sync through the module's cache,
    /// which served one VRP.
    struct Running {
        dir: Scratch,
        binary: PathBuf,
        cache: StubCache,
        cfg: Config,
        rpki: Rpki,
        rx: Receiver<RibMsg>,
        conn: TcpStream,
        pid: u32,
    }

    impl Running {
        fn new(tag: &str) -> Running {
            let dir = Scratch::new(tag);
            let binary = dir.routinator(&tested(), "exec sleep 600");
            let cache = StubCache::new();
            let cfg = config(&sidecar_block(&binary, &dir.join("repo"), cache.port()));
            let (tx, rx) = sync_channel(4);
            let rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
            let pid = routinator_pid(&rpki);
            let conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
            next_change(&rx);
            Running {
                dir,
                binary,
                cache,
                cfg,
                rpki,
                rx,
                conn,
                pid,
            }
        }

        /// The block, with `rpki` and `sidecar` statements added.
        fn with(&self, rpki: &str, sidecar: &str) -> Config {
            let repository = self.dir.join("repo");
            let block =
                sidecar_block_with(&self.binary, &repository, self.cache.port(), rpki, sidecar);
            config(&block)
        }

        /// The VRPs the client holds.
        fn vrps(&self) -> Option<usize> {
            self.rpki.status()?.vrps.map(|v| v.len())
        }
    }

    /// m14 design §5.2: a block that has not changed, written another way,
    /// or with another `enforcement`, which the RIB applies, touches
    /// neither Routinator nor the client.
    #[test]
    fn an_unchanged_block_leaves_the_sidecar_alone() {
        let mut r = Running::new("unchanged");
        let respelled = r.with(
            "enforcement prefer-valid; backoff 1 30;",
            "refresh 600; rir-tals yes;",
        );
        assert_eq!(preflight_as(&r.cfg.rpki, &respelled.rpki, true), Ok(()));
        let done = r.rpki.reconfigure(&r.cfg.rpki, &respelled.rpki);
        assert_eq!(done, Ok("rpki unchanged"));
        assert_eq!(routinator_pid(&r.rpki), r.pid);
        assert!(r.rpki.status().is_some_and(|s| s.connected));
        r.conn
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0; 16];
        assert!(r.conn.read(&mut buf).is_err(), "the session goes on");
        r.rpki.stop();
        assert!(!alive(r.pid));
    }

    /// A change to the client's settings alone restarts the client at the
    /// same address, holding its data, and leaves Routinator running; it
    /// needs no check of Routinator, not even as root.
    #[test]
    fn a_client_setting_leaves_the_sidecar_running() {
        let mut r = Running::new("client");
        let new = r.with("backoff 1 3;", "");
        assert_eq!(preflight_as(&r.cfg.rpki, &new.rpki, true), Ok(()));
        let done = r.rpki.reconfigure(&r.cfg.rpki, &new.rpki);
        assert_eq!(done, Ok("rpki: rtr client restarted"));
        assert!(closed(&mut r.conn), "the old client is gone");
        assert_eq!(routinator_pid(&r.rpki), r.pid, "the same routinator");
        let (_conn, query) = r.cache.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        assert_eq!(r.vrps(), Some(1), "the data is held");
        assert_eq!(waiting(&r.rpki), None);
        assert!(r.rx.try_recv().is_err());
        r.rpki.stop();
    }

    /// RFC 8210 §10: a change to the `sidecar` block restarts Routinator,
    /// and the client keeps the data in use until the new one has sent a
    /// full set.
    #[test]
    fn a_sidecar_setting_restarts_it_and_keeps_the_data() {
        let mut r = Running::new("restart");
        let new = r.with("", "refresh 300;");
        assert_eq!(preflight_as(&r.cfg.rpki, &new.rpki, false), Ok(()));
        let done = r.rpki.reconfigure(&r.cfg.rpki, &new.rpki);
        assert_eq!(done, Ok("rpki: sidecar restarted"));
        assert!(closed(&mut r.conn));
        assert!(!alive(r.pid), "the old routinator is gone");
        let pid = routinator_pid(&r.rpki);
        assert_ne!(pid, r.pid);
        assert_eq!(r.vrps(), Some(1), "the data is held");
        assert_eq!(waiting(&r.rpki), None);
        // The new client asks the new Routinator, at the same fixed port.
        let (_conn, query) = r.cache.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        assert!(r.rx.try_recv().is_err(), "nothing changed for the RIB");
        r.rpki.stop();
        assert!(!alive(pid));
    }

    /// From `mode external` the external cache's data stays in use until
    /// Routinator's first full set, so the routes never wait; that set
    /// validates again only the routes the two judge differently.
    #[test]
    fn switching_from_external_keeps_the_data_until_routinator_answers() {
        let external = StubCache::new();
        let (a, b) = (
            vrp("192.0.2.0/24", 24, 64_496),
            vrp("198.51.100.0/24", 24, 64_497),
        );
        let (mut rpki, rx, mut old_conn) = in_sync(&external, &[a]);
        let dir = Scratch::new("from-external");
        let binary = dir.routinator(&tested(), "exec sleep 600");
        let sidecar = StubCache::new();
        let old = config(&external.block());
        let new = config(&sidecar_block(&binary, &dir.join("repo"), sidecar.port()));
        assert_eq!(preflight_as(&old.rpki, &new.rpki, false), Ok(()));
        assert_eq!(
            rpki.reconfigure(&old.rpki, &new.rpki),
            Ok("rpki: sidecar started")
        );
        assert!(closed(&mut old_conn));
        let pid = routinator_pid(&rpki);
        let held = rpki.status().unwrap();
        assert_eq!(held.vrps.as_deref().map(bgpfc_rpki::VrpSet::len), Some(1));
        assert_eq!(waiting(&rpki), None, "no startup window");
        assert!(rx.try_recv().is_err());
        let _conn = sidecar.serve(&[a, b]);
        let change = next_change(&rx);
        let p = |s: &str| s.parse().unwrap();
        assert!(!change.affected.covers(p("192.0.2.0/24")));
        assert!(change.affected.covers(p("198.51.100.0/24")));
        rpki.stop();
        assert!(!alive(pid));
    }

    /// Leaving `mode sidecar` stops Routinator after the client: for
    /// `mode disabled` every route is `disabled` again; for `mode
    /// external` its data stays in use until an external cache answers.
    #[test]
    fn switching_to_disabled_stops_the_sidecar_and_disables() {
        let mut r = Running::new("to-disabled");
        let off = config("rpki { mode disabled; }");
        assert_eq!(preflight_as(&r.cfg.rpki, &off.rpki, true), Ok(()));
        assert_eq!(
            r.rpki.reconfigure(&r.cfg.rpki, &off.rpki),
            Ok("rpki: validation disabled; sidecar stopped")
        );
        assert!(closed(&mut r.conn));
        assert!(!alive(r.pid));
        assert!(r.rpki.sidecar.is_none() && r.rpki.status().is_none());
        let change = next_change(&r.rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Disabled);

        let mut r = Running::new("to-external");
        let external = StubCache::new();
        let new = config(&external.block());
        assert_eq!(
            r.rpki.reconfigure(&r.cfg.rpki, &new.rpki),
            Ok("rpki: rtr client restarted; sidecar stopped")
        );
        assert!(!alive(r.pid));
        assert!(r.rpki.sidecar.is_none());
        let (_conn, query) = external.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        assert_eq!(r.vrps(), Some(1), "the sidecar's data is held");
        assert!(r.rx.try_recv().is_err());
        r.rpki.stop();
    }

    /// Issue #72, m14 design §5.1: a Routinator that would not start fails
    /// the reload before anything changes, and the running one goes on.
    #[test]
    fn a_sidecar_that_fails_its_check_fails_the_reload_before_anything_changes() {
        let mut r = Running::new("preflight");
        let old_release = r.dir.script(
            "routinator-0.14",
            "if [ \"$1\" = --version ]; then echo 'Routinator 0.14.1'; exit 0; fi\nexec sleep 600",
        );
        let repository = r.dir.join("repo");
        let port = r.cache.port();
        let new = config(&sidecar_block(&old_release, &repository, port));
        let err = preflight_as(&r.cfg.rpki, &new.rpki, false).unwrap_err();
        assert!(
            err.starts_with("rpki sidecar: Routinator 0.14.1 is not supported: "),
            "{err}"
        );
        assert_eq!(routinator_pid(&r.rpki), r.pid, "the running one goes on");
        assert!(r.rpki.status().is_some_and(|s| s.connected));
        r.conn
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0; 16];
        assert!(r.conn.read(&mut buf).is_err(), "the client is untouched");

        // A missing binary, and settings Routinator refuses, likewise.
        let missing = config(&sidecar_block(&r.dir.join("missing"), &repository, port));
        let err = preflight_as(&r.cfg.rpki, &missing.rpki, false).unwrap_err();
        assert!(err.contains("--version` could not be started"), "{err}");
        let tal = r.with("", "tals arin;");
        let err = preflight_as(&r.cfg.rpki, &tal.rpki, false).unwrap_err();
        assert!(
            err.starts_with("rpki sidecar: the ARIN TAL is listed"),
            "{err}"
        );

        // Into `mode sidecar` as root: refused before anything runs, even
        // `--version`. Otherwise the repository directory is created.
        let ran = r.dir.join("ran");
        let body = format!("touch '{}'\necho 'Routinator {}'", ran.display(), tested());
        let marking = r.dir.script("marking", &body);
        let fresh = r.dir.join("fresh/rpki");
        let into = config(&sidecar_block(&marking, &fresh, 0));
        let off = config("rpki { mode disabled; }");
        let err = preflight_as(&off.rpki, &into.rpki, true).unwrap_err();
        assert_eq!(
            err,
            format!(
                "mode sidecar would run Routinator as root: {}",
                privileges::SIDECAR_AS_ROOT_HINT
            )
        );
        assert!(!ran.exists() && !fresh.exists());
        assert_eq!(preflight_as(&off.rpki, &into.rpki, false), Ok(()));
        assert!(ran.exists() && fresh.is_dir());
        assert!(r.rx.try_recv().is_err());
        r.rpki.stop();
    }

    /// The preflight checks only what the reload will start: new external
    /// caches are looked up, as at start; a block that has not changed, or
    /// one that turns validation off, needs nothing, not even as root.
    #[test]
    fn the_preflight_checks_what_will_start() {
        let external = config("rpki { mode external; cache 127.0.0.1; }");
        let bad = config("rpki { mode external; cache rtr.invalid; }");
        let err = preflight_as(&external.rpki, &bad.rpki, false).unwrap_err();
        assert!(
            err.starts_with("cannot resolve rpki cache rtr.invalid: "),
            "{err}"
        );
        assert_eq!(preflight_as(&bad.rpki, &bad.rpki, false), Ok(()));
        let sidecar = config("rpki { mode sidecar; }");
        let prefer = config("rpki { mode sidecar; enforcement prefer-valid; }");
        assert_eq!(preflight_as(&sidecar.rpki, &prefer.rpki, true), Ok(()));
        let off = config("rpki { mode disabled; }");
        assert_eq!(preflight_as(&sidecar.rpki, &off.rpki, true), Ok(()));
        assert_eq!(preflight_as(&sidecar.rpki, &external.rpki, true), Ok(()));
    }

    /// A Routinator that passed the preflight but cannot start, as when
    /// the binary went away in between, leaves validation off rather than
    /// the old data unexpired.
    #[test]
    fn a_sidecar_that_fails_to_start_after_the_preflight_disables_validation() {
        let mut r = Running::new("late");
        let missing = r.dir.join("missing");
        let new = config(&sidecar_block(&missing, &r.dir.join("repo"), 0));
        let err = r.rpki.reconfigure(&r.cfg.rpki, &new.rpki).unwrap_err();
        assert!(
            err.starts_with("rpki: cannot start the sidecar (rpki sidecar: "),
            "{err}"
        );
        assert!(err.ends_with("); validation disabled"), "{err}");
        assert!(closed(&mut r.conn));
        assert!(!alive(r.pid));
        assert!(r.rpki.sidecar.is_none() && r.rpki.status().is_none());
        let change = next_change(&r.rx);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Disabled);
        // A later reload with a block that works starts it again; the
        // routes then wait for its first full set.
        let back = r.with("", "");
        assert_eq!(
            r.rpki.reconfigure(&new.rpki, &back.rpki),
            Ok("rpki: sidecar started")
        );
        let pid = routinator_pid(&r.rpki);
        assert!(waiting(&r.rpki).is_some());
        r.rpki.stop();
        assert!(!alive(pid));
    }
}
