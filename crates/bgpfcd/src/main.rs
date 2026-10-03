//! `bgpfcd`: the bgpfc BGP-4 routing daemon.
#![forbid(unsafe_code)]

fn main() {
    bgpfc_log::init(bgpfc_log::Level::Info);
    bgpfc_log::info!("bgpfcd starting", version = env!("CARGO_PKG_VERSION"));
}
