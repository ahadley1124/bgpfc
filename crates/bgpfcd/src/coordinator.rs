//! Listener threads and the peer table: an accepted connection is handed to
//! the peer thread for its source address, or closed if no such neighbour
//! is configured (AGENTS.md §3).
//!
//! Implements: RFC 4271 §8.2.1 (listen on port 179; unconfigured peers are
//! refused since `AcceptConnectionsUnconfiguredPeers` is not supported).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::mpsc::TrySendError;
use std::thread;

use crate::messages::PeerInput;
use crate::peer::PeerHandle;

/// The configured neighbours, by address.
pub(crate) type PeerTable = Arc<HashMap<IpAddr, PeerHandle>>;

/// Bind `addr` and serve it on a new thread.
///
/// # Errors
/// The bind error, so the daemon can refuse to start.
pub(crate) fn listen(addr: SocketAddr, peers: PeerTable) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    bgpfc_log::info!("listening", address = addr);
    thread::Builder::new()
        .name(format!("listen-{addr}"))
        .spawn(move || accept_loop(&listener, &peers))?;
    Ok(())
}

fn accept_loop(listener: &TcpListener, peers: &PeerTable) {
    loop {
        let (stream, from) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                bgpfc_log::warn!("accept failed", error = e);
                continue;
            }
        };
        let ip = canonical(from.ip());
        let Some(peer) = peers.get(&ip) else {
            bgpfc_log::debug!("connection from unconfigured address", from = from);
            drop(stream);
            continue;
        };
        bgpfc_log::debug!("incoming connection", peer = ip, from = from);
        match peer.tx.try_send(PeerInput::Incoming(stream)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                bgpfc_log::warn!("peer queue full, dropping connection", peer = ip);
            }
            Err(TrySendError::Disconnected(_)) => bgpfc_log::warn!("peer thread gone", peer = ip),
        }
    }
}

/// An IPv4 peer reaching a dual-stack listener shows up as `::ffff:a.b.c.d`;
/// the peer table is keyed by the plain IPv4 address.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_addresses_fold_to_ipv4() {
        assert_eq!(
            canonical("::ffff:192.0.2.1".parse().unwrap()),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            canonical("2001:db8::1".parse().unwrap()),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            canonical("10.0.0.1".parse().unwrap()),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
