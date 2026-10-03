//! `bgpfcd`: the bgpfc BGP-4 routing daemon.
//!
//! Milestone 4 shape (AGENTS.md §3): the configuration file, listener
//! threads, one thread per neighbour driving its FSM, and a stand-in RIB
//! thread.
#![forbid(unsafe_code)]

mod args;
mod coordinator;
mod messages;
mod peer;
mod reader;
mod rib_stub;
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
    let mut config = match bgpfc_config::parse_file(&opts.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if opts.check {
        println!(
            "{}: ok ({} neighbors, {} policies)",
            opts.config.display(),
            config.neighbors.len(),
            config.policies.len()
        );
        return;
    }
    if let Some(level) = opts.log_level {
        config.log_level = level;
    }
    if let Some(mode) = opts.fib {
        config.fib.mode = mode;
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

    let (rib_tx, rib_rx) = sync_channel(RIB_QUEUE);
    rib_stub::spawn(rib_rx);

    let mut table = HashMap::new();
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
        let handle = peer::spawn(cfg, rib_tx.clone());
        table.insert(handle.addr, handle);
    }
    let table = Arc::new(table);
    for addr in config.listen {
        if let Err(e) = coordinator::listen(addr, Arc::clone(&table)) {
            bgpfc_log::error!("cannot listen", address = addr, error = e);
            std::process::exit(1);
        }
    }
    // Everything runs on its own threads; the main thread has nothing to do
    // until signal handling arrives with the control plane.
    loop {
        std::thread::park();
    }
}
