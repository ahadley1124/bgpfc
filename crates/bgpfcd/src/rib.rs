//! The RIB thread: the only owner of RIB state (AGENTS.md §3). It turns
//! peer messages into `bgpfc_rib::Rib` calls and delivers what comes out:
//! UPDATEs to peer threads, route changes to the FIB (logged until the FIB
//! thread arrives in milestone 7).

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::thread;

use bgpfc_fsm::Session;
use bgpfc_rib::{Output, PeerInfo, Policies, Rib};
use bgpfc_wire::types::Asn;

use crate::coordinator::PeerTable;
use crate::messages::{FibMsg, PeerInput, RibMsg, RibQuery, RibReply, RouteReport};

/// Start the RIB thread.
pub(crate) fn spawn(
    local_as: Asn,
    policies: Box<dyn Policies>,
    rx: Receiver<RibMsg>,
    peers: PeerTable,
    fib: SyncSender<FibMsg>,
) {
    thread::Builder::new()
        .name("rib".to_owned())
        .spawn(move || run(local_as, policies, &rx, &peers, &fib))
        .expect("spawning the rib thread");
}

fn run(
    local_as: Asn,
    policies: Box<dyn Policies>,
    rx: &Receiver<RibMsg>,
    peers: &PeerTable,
    fib: &SyncSender<FibMsg>,
) {
    let mut rib = Rib::with_policies(local_as, policies);
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
                log_update(peer, &update);
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
            RibMsg::Query(q, reply) => {
                let _ = reply.send(answer(&rib, &q));
                Vec::new()
            }
            RibMsg::SetPolicies { policies, reexport } => {
                rib.set_policies(policies.0);
                let mut out = Vec::new();
                for peer in reexport {
                    let families: Vec<_> = rib
                        .peer(peer)
                        .map(|p| p.families.clone())
                        .unwrap_or_default();
                    for family in families {
                        bgpfc_log::info!("rib: re-export", peer = peer, family = family);
                        out.extend(rib.reexport(peer, family));
                    }
                }
                out
            }
            RibMsg::Resend { peer } => {
                let families: Vec<_> = rib
                    .peer(peer)
                    .map(|p| p.families.clone())
                    .unwrap_or_default();
                let mut out = Vec::new();
                for family in families {
                    bgpfc_log::info!("rib: resend", peer = peer, family = family);
                    out.extend(rib.refresh(peer, family));
                }
                out
            }
        };
        deliver(outputs, peers, fib);
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

fn deliver(outputs: Vec<Output>, peers: &PeerTable, fib: &SyncSender<FibMsg>) {
    for o in outputs {
        match o {
            Output::Fib(c) => {
                // A bounded channel: a slow kernel slows the RIB rather
                // than growing memory (AGENTS.md §3 backpressure).
                if fib.send(FibMsg::Change(c)).is_err() {
                    bgpfc_log::error!("fib thread gone");
                }
            }
            Output::Send { peer, messages } => {
                let handle = peers.read().ok().and_then(|t| t.get(&peer).cloned());
                let Some(handle) = handle else {
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

fn log_update(peer: IpAddr, update: &bgpfc_wire::update::DecodedUpdate) {
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
}

fn answer(rib: &Rib, q: &RibQuery) -> RibReply {
    match q {
        RibQuery::Peers => RibReply::Peers(
            rib.peers()
                .map(|p| (p.clone(), rib.peer_stats(p.addr).unwrap_or_default()))
                .collect(),
        ),
        RibQuery::Routes { family, prefix } => match prefix {
            Some(prefix) => {
                let best = rib
                    .loc_rib(*family)
                    .find(|(p, _)| p == prefix)
                    .map(|(_, b)| b.peer);
                RibReply::Routes(
                    rib.candidates(*family, *prefix)
                        .iter()
                        .map(|c| RouteReport {
                            prefix: *prefix,
                            peer: c.peer,
                            attrs: std::sync::Arc::clone(&c.attrs),
                            best: best == Some(c.peer),
                        })
                        .collect(),
                )
            }
            None => RibReply::Routes(
                rib.loc_rib(*family)
                    .map(|(prefix, b)| RouteReport {
                        prefix,
                        peer: b.peer,
                        attrs: std::sync::Arc::clone(&b.attrs),
                        best: true,
                    })
                    .collect(),
            ),
        },
    }
}
