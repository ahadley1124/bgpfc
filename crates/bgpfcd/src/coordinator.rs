//! Listener threads and the peer table: an accepted connection is handed to
//! the peer thread for its source address, or closed if no such neighbour
//! is configured (AGENTS.md §3).
//!
//! Implements: RFC 4271 §8.2.1 (listen on port 179; unconfigured peers are
//! refused since `AcceptConnectionsUnconfiguredPeers` is not supported).
//! A connection is given the neighbor's TTL before anything is sent on it,
//! and refused when the neighbor has a `local-address` and the connection
//! reached another of ours (`docs/config.md`, "Neighbors").

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::TrySendError;
use std::thread;

use crate::messages::PeerInput;
use crate::peer::PeerHandle;

/// The configured neighbours, by address.
/// The peer table is replaced on reload, so readers take a lock; nothing
/// holds it for longer than a lookup.
pub(crate) type PeerTable = Arc<std::sync::RwLock<HashMap<IpAddr, PeerHandle>>>;

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
        let peer = peers.read().ok().and_then(|t| t.get(&ip).cloned());
        let Some(peer) = peer else {
            bgpfc_log::debug!("connection from unconfigured address", from = from);
            drop(stream);
            continue;
        };
        bgpfc_log::debug!("incoming connection", peer = ip, from = from);
        if !admit(&stream, &peer) {
            drop(stream);
            continue;
        }
        match peer.tx.try_send(PeerInput::Incoming(stream)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                bgpfc_log::warn!("peer queue full, dropping connection", peer = ip);
            }
            Err(TrySendError::Disconnected(_)) => bgpfc_log::warn!("peer thread gone", peer = ip),
        }
    }
}

/// Whether a connection from `peer` may go to its thread, made ready for
/// it if so.
///
/// With a `local-address`, the connection must have reached that address:
/// one to another address of ours would run the session from there, and
/// end with that address's interface, which `local-address` is meant to
/// avoid (BIRD's `local` refuses it likewise). With a TTL, it is set
/// before anything is sent, so that the OPEN goes out with it; the SYN-ACK
/// has gone already, with the listener's TTL. A connection whose TTL
/// cannot be set is closed rather than left sending with another.
fn admit(stream: &TcpStream, peer: &PeerHandle) -> bool {
    if let Some(local) = peer.local {
        match stream.local_addr() {
            Ok(to) if canonical(to.ip()) == local => {}
            Ok(to) => {
                bgpfc_log::info!(
                    "connection to another local address, closing",
                    peer = peer.addr,
                    to = canonical(to.ip()),
                    local_address = local
                );
                return false;
            }
            Err(e) => {
                bgpfc_log::warn!(
                    "cannot read the local address, closing",
                    peer = peer.addr,
                    error = e
                );
                return false;
            }
        }
    }
    if let Some(ttl) = peer.ttl
        && let Err(e) = bgpfc_sys::set_ttl(stream, ttl)
    {
        bgpfc_log::warn!("cannot set the ttl, closing", peer = peer.addr, error = e);
        return false;
    }
    true
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

    use std::io::Read;
    use std::num::NonZeroU8;
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::time::Duration;

    use crate::messages::PeerInput;

    /// A listener on `at` serving a table with the one neighbor `peer`,
    /// whose thread is the queue returned.
    fn serve(
        at: &str,
        peer: IpAddr,
        set: impl FnOnce(&mut PeerHandle),
    ) -> (SocketAddr, Receiver<PeerInput>) {
        let (tx, rx) = sync_channel(4);
        let mut handle = PeerHandle::on(peer, tx);
        set(&mut handle);
        let table: PeerTable = Arc::new(std::sync::RwLock::new(HashMap::from([(peer, handle)])));
        let listener = TcpListener::bind(at).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || accept_loop(&listener, &table));
        (addr, rx)
    }

    fn incoming(rx: &Receiver<PeerInput>) -> TcpStream {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(PeerInput::Incoming(s)) => s,
            other => panic!("{other:?}"),
        }
    }

    /// The neighbor's TTL is on the connection before its thread sees it.
    #[test]
    fn accepted_connections_get_the_neighbors_ttl() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let (addr, rx) = serve("127.0.0.1:0", peer, |h| h.ttl = NonZeroU8::new(5));
        let _near = TcpStream::connect(addr).unwrap();
        assert_eq!(bgpfc_sys::ttl(&incoming(&rx)).unwrap(), 5);
        // Without one, the system's.
        let (addr, rx) = serve("127.0.0.1:0", peer, |_| {});
        let near = TcpStream::connect(addr).unwrap();
        let system = bgpfc_sys::ttl(&near).unwrap();
        assert_eq!(bgpfc_sys::ttl(&incoming(&rx)).unwrap(), system);
    }

    /// docs/config.md, "Neighbors": with a `local-address`, a connection
    /// to another address of ours is closed before its thread sees it.
    #[test]
    fn connections_to_another_local_address_are_refused() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        let (addr, rx) = serve("127.0.0.1:0", peer, |h| {
            h.local = Some(other);
            h.ttl = NonZeroU8::new(1);
        });
        let mut near = TcpStream::connect(addr).unwrap();
        near.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        // Closed: the neighbor reads the end of the stream.
        assert_eq!(near.read(&mut [0; 1]).unwrap(), 0);
        assert!(rx.try_recv().is_err());
        // The configured address is taken, with the neighbor's TTL.
        let (addr, rx) = serve("127.0.0.1:0", peer, |h| {
            h.local = Some(peer);
            h.ttl = NonZeroU8::new(1);
        });
        let _near = TcpStream::connect(addr).unwrap();
        let accepted = incoming(&rx);
        assert_eq!(accepted.local_addr().unwrap().ip(), peer);
        assert_eq!(bgpfc_sys::ttl(&accepted).unwrap(), 1);
    }

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
