//! `bgpfcd`: the bgpfc BGP-4 routing daemon.
//!
//! Milestone 8 shape (AGENTS.md §3): the configuration file, listener
//! threads, one thread per neighbour driving its FSM, the RIB thread, the
//! FIB thread, the control threads, and a main thread (the coordinator)
//! that owns the configuration and the peer table and acts on signals
//! and reload requests.
#![forbid(unsafe_code)]

mod args;
mod control;
mod coordinator;
mod fib;
mod messages;
mod peer;
mod privileges;
mod reader;
mod rib;
mod wiring;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, RwLock};

use bgpfc_config::diff::{ConfigDiff, GlobalChange};
use bgpfc_wire::error::CeaseSubcode;

use crate::control::CoordMsg;
use crate::coordinator::PeerTable;
use crate::messages::{FibMsg, PeerInput, RibMsg};

/// Updates the RIB thread may have queued before peers block.
const RIB_QUEUE: usize = 1024;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let opts = match args::parse(&argv) {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("bgpfcd: {msg}");
            }
            eprint!("{}", args::USAGE);
            std::process::exit(2);
        }
    };
    let (config, engine) = load(&opts);
    if opts.check {
        println!(
            "{}: ok ({} neighbors, {} policies)",
            opts.config.display(),
            config.neighbors.len(),
            config.policies.len()
        );
        return;
    }
    bgpfc_log::init(config.log_level);
    bgpfc_log::info!(
        "bgpfcd starting",
        version = env!("CARGO_PKG_VERSION"),
        config = opts.config.display(),
        local_as = config.local_as,
        router_id = config.router_id,
        fib_mode = config.fib.mode
    );
    run(&opts, config, engine);
}

/// Parse, validate and compile the configuration file, with the command
/// line overrides applied; exits with the errors printed otherwise.
fn load(opts: &args::Args) -> (bgpfc_config::Config, bgpfc_policy::Engine) {
    let mut config = match bgpfc_config::parse_file(&opts.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    // Policies compile after validation: only AS-path regexes can fail.
    let engine = match bgpfc_policy::Engine::new(&config) {
        Ok(e) => e,
        Err(errors) => {
            for e in errors {
                eprintln!("{}:{e}", opts.config.display());
            }
            std::process::exit(1);
        }
    };
    if let Some(level) = opts.log_level {
        config.log_level = level;
    }
    if let Some(mode) = opts.fib {
        config.fib.mode = mode;
    }
    (config, engine)
}

/// Bring everything up in the order privileges require, then run the
/// coordinator loop.
fn run(opts: &args::Args, config: bgpfc_config::Config, engine: bgpfc_policy::Engine) {
    // Signals first, so every thread inherits the handlers (AGENTS.md §3).
    let signals = match bgpfc_sys::Signals::install() {
        Ok(s) => s,
        Err(e) => {
            bgpfc_log::error!("cannot install signal handlers", error = e);
            std::process::exit(1);
        }
    };
    privileges::check(&config, opts.user.as_deref());

    // The netlink socket and the listeners are opened while still
    // privileged (README, "Option B"); the FIB thread flushes stale
    // routes right away.
    let fib_tx = match fib::start(bgpfc_fib::Fib::new(
        fib::mode_of(config.fib.mode),
        config.fib.table,
        config.fib.protocol,
    )) {
        Ok(tx) => tx,
        Err(e) => {
            bgpfc_log::error!("cannot start the fib", error = e);
            std::process::exit(1);
        }
    };
    let (rib_tx, rib_rx) = sync_channel(RIB_QUEUE);
    let table: PeerTable = Arc::new(RwLock::new(HashMap::new()));
    let mut peers = Vec::new();
    for n in &config.neighbors {
        peers.push(prepare_peer(&config, n, &rib_tx, &table));
    }
    for addr in &config.listen {
        if let Err(e) = coordinator::listen(*addr, Arc::clone(&table)) {
            bgpfc_log::error!("cannot listen", address = addr, error = e);
            std::process::exit(1);
        }
    }
    let (coord_tx, coord_rx) = sync_channel::<CoordMsg>(16);
    start_control(
        &config,
        control::Ctx {
            peers: Arc::clone(&table),
            rib: rib_tx.clone(),
            fib: fib_tx.clone(),
            coord: coord_tx.clone(),
            local_as: config.local_as,
            router_id: config.router_id,
            writes: config.control.http.as_ref().is_some_and(|h| h.writes),
            token: read_token(&config),
        },
    );
    if let Some(user) = &opts.user {
        privileges::drop(user, opts.group.as_deref());
    }

    rib::spawn(
        config.local_as,
        Box::new(engine),
        rib_rx,
        Arc::clone(&table),
        fib_tx.clone(),
    );
    for peer in peers {
        peer.start();
    }
    forward_signals(signals, coord_tx);

    let mut coord = Coordinator {
        opts,
        config,
        table,
        rib_tx,
        fib_tx,
    };
    while let Ok(msg) = coord_rx.recv() {
        match msg {
            CoordMsg::Signal(bgpfc_sys::Signal::Hup) => match coord.reload() {
                Ok(summary) => bgpfc_log::info!("reloaded", summary = summary),
                Err(e) => bgpfc_log::error!("reload failed; running configuration kept", error = e),
            },
            CoordMsg::Signal(sig) => {
                bgpfc_log::info!("shutting down", signal = format!("{sig:?}"));
                coord.shutdown();
                return;
            }
            CoordMsg::Reload(reply) => {
                let r = coord.reload();
                match &r {
                    Ok(summary) => bgpfc_log::info!("reloaded", summary = summary),
                    Err(e) => {
                        bgpfc_log::error!("reload failed; running configuration kept", error = e);
                    }
                }
                let _ = reply.send(r);
            }
        }
    }
}

/// The bearer token from `token-file`, if configured; exits if the file
/// cannot be read.
fn read_token(config: &bgpfc_config::Config) -> Option<String> {
    let path = config.control.http.as_ref()?.token_file.as_ref()?;
    match std::fs::read_to_string(path) {
        Ok(t) => Some(t.trim().to_owned()),
        Err(e) => {
            bgpfc_log::error!("cannot read token file", path = path.display(), error = e);
            std::process::exit(1);
        }
    }
}

/// Bind the control socket and the HTTP API, if configured.
fn start_control(config: &bgpfc_config::Config, ctx: control::Ctx) {
    if let Some(path) = &config.control.socket
        && let Err(e) = control::serve_unix(path, ctx.clone())
    {
        bgpfc_log::error!(
            "cannot bind control socket",
            path = path.display(),
            error = e
        );
        std::process::exit(1);
    }
    if let Some(h) = &config.control.http
        && let Err(e) = control::serve_http(h.listen, ctx)
    {
        bgpfc_log::error!("cannot bind http api", address = h.listen, error = e);
        std::process::exit(1);
    }
}

/// Read the signal pipe on its own thread so the coordinator can wait on
/// one channel.
fn forward_signals(mut signals: bgpfc_sys::Signals, tx: SyncSender<CoordMsg>) {
    let _ = std::thread::Builder::new()
        .name("signals".to_owned())
        .spawn(move || {
            while let Ok(sig) = signals.wait() {
                if tx.send(CoordMsg::Signal(sig)).is_err() {
                    return;
                }
            }
        });
}

/// Build a peer's thread state and register its handle.
fn prepare_peer(
    config: &bgpfc_config::Config,
    n: &bgpfc_config::ast::Neighbor,
    rib_tx: &SyncSender<RibMsg>,
    table: &PeerTable,
) -> peer::Peer {
    let cfg = wiring::peer_config(config.local_as, config.router_id, n);
    bgpfc_log::info!(
        "neighbor configured",
        peer = cfg.addr,
        remote_as = cfg.fsm.remote_as,
        passive = cfg.fsm.passive,
        import = n.import,
        export = n.export
    );
    let (handle, peer) = peer::prepare(cfg, rib_tx.clone());
    if let Ok(mut t) = table.write() {
        t.insert(handle.addr, handle);
    }
    peer
}

/// The main thread's state: the running configuration and what reload
/// and shutdown need.
struct Coordinator<'a> {
    opts: &'a args::Args,
    config: bgpfc_config::Config,
    table: PeerTable,
    rib_tx: SyncSender<RibMsg>,
    fib_tx: SyncSender<FibMsg>,
}

impl Coordinator<'_> {
    fn stop_peer(&self, addr: IpAddr, subcode: CeaseSubcode) {
        let handle = self.table.write().ok().and_then(|mut t| t.remove(&addr));
        if let Some(h) = handle {
            let _ = h.tx.try_send(PeerInput::Stop(subcode));
        }
    }

    /// Re-read the configuration file and apply the difference
    /// (`docs/config.md`, "Reload"). On any error nothing changes.
    fn reload(&mut self) -> Result<String, String> {
        let (new, engine) = load_checked(self.opts)?;
        let diff = ConfigDiff::between(&self.config, &new);
        let mut notes = Vec::new();
        for g in &diff.global {
            match g {
                GlobalChange::Identity => {
                    return Err("router-id or local-as changed: restart the daemon".to_owned());
                }
                GlobalChange::Listen | GlobalChange::Control => {
                    notes.push(format!("{g:?} changed: takes effect at the next restart"));
                }
                GlobalChange::Log => bgpfc_log::init(new.log_level),
                GlobalChange::Fib => {
                    if new.fib.table != self.config.fib.table
                        || new.fib.protocol != self.config.fib.protocol
                    {
                        notes.push(
                            "fib table or protocol changed: takes effect at the next restart"
                                .to_owned(),
                        );
                    }
                    if new.fib.mode != self.config.fib.mode {
                        let (tx, rx) = sync_channel(1);
                        if self
                            .fib_tx
                            .send(FibMsg::SetMode(fib::mode_of(new.fib.mode), tx))
                            .is_ok()
                        {
                            let _ = rx.recv_timeout(std::time::Duration::from_secs(30));
                        }
                    }
                }
            }
        }
        // RFC 4486 §4: de-configured peers and peers whose session
        // parameters changed get the matching Cease subcode.
        for addr in &diff.removed {
            self.stop_peer(*addr, CeaseSubcode::PeerDeconfigured);
        }
        for addr in &diff.reset {
            self.stop_peer(*addr, CeaseSubcode::OtherConfigurationChange);
        }
        // Policies always follow the new file: the engine knows every
        // neighbor's policy names.
        let _ = self.rib_tx.send(RibMsg::SetPolicies {
            policies: messages::NewPolicies(Box::new(engine)),
            reexport: diff.policy_changed.clone(),
        });
        // Import policy changes need the peer's routes again (RFC 2918).
        if let Ok(t) = self.table.read() {
            for addr in &diff.policy_changed {
                if let Some(h) = t.get(addr) {
                    let _ = h.tx.try_send(PeerInput::RequestRoutes);
                }
            }
        }
        let mut started = Vec::new();
        for addr in diff.added.iter().chain(&diff.reset) {
            if let Some(n) = new.neighbor(*addr) {
                started.push(prepare_peer(&new, n, &self.rib_tx, &self.table));
            }
        }
        for p in started {
            p.start();
        }
        let summary = format!(
            "added {} removed {} reset {} policy {} unchanged {}{}",
            diff.added.len(),
            diff.removed.len(),
            diff.reset.len(),
            diff.policy_changed.len(),
            diff.unchanged.len(),
            if notes.is_empty() {
                String::new()
            } else {
                format!("; {}", notes.join("; "))
            }
        );
        self.config = new;
        Ok(summary)
    }

    /// Stop every session with a Cease (RFC 4486 §4 Administrative
    /// Shutdown) and remove our routes from the kernel.
    fn shutdown(&self) {
        if let Ok(t) = self.table.read() {
            for handle in t.values() {
                let _ = handle
                    .tx
                    .try_send(PeerInput::Stop(CeaseSubcode::AdministrativeShutdown));
            }
        }
        // Give the peer threads a moment to write their NOTIFICATIONs.
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (done_tx, done_rx) = sync_channel(1);
        if self.fib_tx.send(FibMsg::Shutdown(done_tx)).is_ok() {
            let _ = done_rx.recv_timeout(std::time::Duration::from_secs(10));
        }
        if let Some(path) = &self.config.control.socket {
            let _ = std::fs::remove_file(path);
        }
        bgpfc_log::info!("bgpfcd stopped");
    }
}

/// [`load`] without exiting: for reload, where the running configuration
/// must survive a bad file.
fn load_checked(opts: &args::Args) -> Result<(bgpfc_config::Config, bgpfc_policy::Engine), String> {
    let mut config = bgpfc_config::parse_file(&opts.config).map_err(|e| e.to_string())?;
    let engine = bgpfc_policy::Engine::new(&config).map_err(|errors| {
        errors
            .iter()
            .map(|e| format!("{}:{e}", opts.config.display()))
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    if let Some(level) = opts.log_level {
        config.log_level = level;
    }
    if let Some(mode) = opts.fib {
        config.fib.mode = mode;
    }
    Ok((config, engine))
}
