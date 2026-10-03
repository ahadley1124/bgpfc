//! The RIB thread: the only owner of RIB state (AGENTS.md §3). It turns
//! peer messages into `bgpfc_rib::Rib` calls and delivers what comes out:
//! UPDATEs to peer threads, route changes to the FIB (logged until the FIB
//! thread arrives in milestone 7).

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, TrySendError};
use std::thread;

use bgpfc_fsm::Session;
use bgpfc_rib::{Output, PeerInfo, Rib};
use bgpfc_wire::types::Asn;

use crate::coordinator::PeerTable;
use crate::messages::{PeerInput, RibMsg};

/// Start the RIB thread.
pub(crate) fn spawn(local_as: Asn, rx: Receiver<RibMsg>, peers: PeerTable) {
    thread::Builder::new()
        .name("rib".to_owned())
        .spawn(move || run(local_as, &rx, &peers))
        .expect("spawning the rib thread");
}

fn run(local_as: Asn, rx: &Receiver<RibMsg>, peers: &PeerTable) {
    let mut rib = Rib::new(local_as);
    while let Ok(msg) = rx.recv() {
        let outputs = match msg {
            RibMsg::PeerUp {
                peer,
                local_addr,
                session,
            } => {
                bgpfc_log::info!(
                    "rib: peer up",
                    peer = peer,
                    local = local_addr,
                    families = session
                        .families
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                rib.peer_up(peer_info(peer, local_addr, &session))
            }
            RibMsg::Update { peer, update } => {
                let announced = update.announcements().count();
                let withdrawn = update.withdrawals().count();
                bgpfc_log::debug!(
                    "rib: update",
                    peer = peer,
                    announced = announced,
                    withdrawn = withdrawn
                );
                if bgpfc_log::enabled(bgpfc_log::Level::Trace) {
                    for (family, prefix) in update.announcements() {
                        bgpfc_log::trace!(
                            "rib: announce",
                            peer = peer,
                            family = family,
                            prefix = prefix
                        );
                    }
                    for (family, prefix) in update.withdrawals() {
                        bgpfc_log::trace!(
                            "rib: withdraw",
                            peer = peer,
                            family = family,
                            prefix = prefix
                        );
                    }
                }
                rib.update(peer, &update)
            }
            RibMsg::FamilyDisabled { peer, family } => {
                bgpfc_log::warn!("rib: family disabled", peer = peer, family = family);
                rib.family_disabled(peer, family)
            }
            RibMsg::RouteRefresh { peer, family } => {
                bgpfc_log::info!("rib: route refresh", peer = peer, family = family);
                rib.refresh(peer, family)
            }
            RibMsg::PeerDown { peer } => {
                let stats = rib.peer_stats(peer).unwrap_or_default();
                bgpfc_log::info!(
                    "rib: peer down",
                    peer = peer,
                    routes_deleted = stats.received.iter().map(|(_, n)| n).sum::<usize>()
                );
                rib.peer_down(peer)
            }
        };
        deliver(outputs, peers);
    }
}

fn peer_info(peer: IpAddr, local_addr: IpAddr, s: &Session) -> PeerInfo {
    PeerInfo {
        addr: peer,
        local_addr,
        remote_as: s.peer_as,
        router_id: s.peer_router_id,
        kind: s.peer,
        families: s.families.clone(),
        four_octet_as: s.four_octet_as,
        extended_messages: s.extended_messages,
    }
}

fn deliver(outputs: Vec<Output>, peers: &PeerTable) {
    for o in outputs {
        match o {
            Output::Fib(c) => match c.next_hop {
                // The FIB thread (milestone 7) will take these; until then
                // every mode is dry-run.
                Some(nh) => bgpfc_log::debug!(
                    "fib: route",
                    family = c.family,
                    prefix = c.prefix,
                    next_hop = nh
                ),
                None => bgpfc_log::debug!("fib: delete", family = c.family, prefix = c.prefix),
            },
            Output::Send { peer, messages } => {
                let Some(handle) = peers.get(&peer) else {
                    continue;
                };
                bgpfc_log::debug!("rib: send", peer = peer, messages = messages.len());
                match handle.tx.try_send(PeerInput::Send(messages)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        // AGENTS.md §3: never drop updates silently; the
                        // peer thread resets the session.
                        bgpfc_log::warn!("rib: peer queue full", peer = peer);
                        handle.overrun.store(true, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        bgpfc_log::warn!("rib: peer thread gone", peer = peer);
                    }
                }
            }
            Output::EncodeFailed { peer, error } => {
                bgpfc_log::error!("rib: cannot encode update", peer = peer, error = error);
            }
        }
    }
}
