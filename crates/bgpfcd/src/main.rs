//! `bgpfcd`: the bgpfc BGP-4 routing daemon.
//!
//! Milestone 7 shape (AGENTS.md §3): the configuration file, listener
//! threads, one thread per neighbour driving its FSM, the RIB thread, the
//! FIB thread, and a main thread that waits for signals.
#![forbid(unsafe_code)]

mod args;
mod coordinator;
mod fib;
mod messages;
mod peer;
mod privileges;
mod reader;
mod rib;
mod wiring;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;

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
    run(&opts, &config, engine);
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

/// Bring everything up in the order privileges require, then wait for
/// signals.
fn run(opts: &args::Args, config: &bgpfc_config::Config, engine: bgpfc_policy::Engine) {
    // Signals first, so every thread inherits the handlers (AGENTS.md §3).
    let mut signals = match bgpfc_sys::Signals::install() {
        Ok(s) => s,
        Err(e) => {
            bgpfc_log::error!("cannot install signal handlers", error = e);
            std::process::exit(1);
        }
    };
    privileges::check(config, opts.user.as_deref());

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
    let mut table = HashMap::new();
    let mut peers = Vec::new();
    for n in &config.neighbors {
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
        table.insert(handle.addr, handle);
        peers.push(peer);
    }
    let table = Arc::new(table);
    for addr in &config.listen {
        if let Err(e) = coordinator::listen(*addr, Arc::clone(&table)) {
            bgpfc_log::error!("cannot listen", address = addr, error = e);
            std::process::exit(1);
        }
    }
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

    loop {
        match signals.wait() {
            Ok(bgpfc_sys::Signal::Hup) => {
                bgpfc_log::warn!("reload requested; reload arrives with the control plane");
            }
            Ok(sig) => {
                bgpfc_log::info!("shutting down", signal = format!("{sig:?}"));
                shutdown(&table, &fib_tx);
                return;
            }
            Err(e) => {
                bgpfc_log::error!("signal pipe failed", error = e);
                std::process::exit(1);
            }
        }
    }
}

/// Stop every session with a Cease (RFC 4486 §4 Administrative Shutdown)
/// and remove our routes from the kernel.
fn shutdown(
    table: &coordinator::PeerTable,
    fib_tx: &std::sync::mpsc::SyncSender<messages::FibMsg>,
) {
    for handle in table.values() {
        let _ = handle.tx.try_send(messages::PeerInput::Stop);
    }
    // Give the peer threads a moment to write their NOTIFICATIONs.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let (done_tx, done_rx) = sync_channel(1);
    if fib_tx.send(messages::FibMsg::Shutdown(done_tx)).is_ok() {
        let _ = done_rx.recv_timeout(std::time::Duration::from_secs(10));
    }
    bgpfc_log::info!("bgpfcd stopped");
}
