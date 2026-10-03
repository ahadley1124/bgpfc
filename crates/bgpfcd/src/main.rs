//! `bgpfcd`: the bgpfc BGP-4 routing daemon.
//!
//! Milestone 3 shape (AGENTS.md §3): listener threads, one thread per
//! neighbour driving its FSM, and a stand-in RIB thread. Configuration
//! comes from the command line until milestone 4.
#![forbid(unsafe_code)]

mod args;
mod coordinator;
mod messages;
mod peer;
mod reader;
mod rib_stub;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;

/// Updates the RIB thread may have queued before peers block.
const RIB_QUEUE: usize = 1024;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match args::parse(&argv) {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("bgpfcd: {msg}");
            }
            eprint!("{}", args::USAGE);
            std::process::exit(2);
        }
    };
    bgpfc_log::init(parsed.log_level);
    bgpfc_log::info!("bgpfcd starting", version = env!("CARGO_PKG_VERSION"));

    let (rib_tx, rib_rx) = sync_channel(RIB_QUEUE);
    rib_stub::spawn(rib_rx);

    let mut table = HashMap::new();
    for cfg in parsed.peers {
        bgpfc_log::info!(
            "neighbor configured",
            peer = cfg.addr,
            remote_as = cfg.fsm.remote_as,
            passive = cfg.fsm.passive
        );
        let handle = peer::spawn(cfg, rib_tx.clone());
        table.insert(handle.addr, handle);
    }
    let table = Arc::new(table);
    for addr in parsed.listen {
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
