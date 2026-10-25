//! The RIB thread: the only owner of RIB state (AGENTS.md §3). It turns
//! peer messages into `bgpfc_rib::Rib` calls and delivers what comes out:
//! UPDATEs to peer threads, route changes to the FIB (logged until the FIB
//! thread arrives in milestone 7).

use std::net::IpAddr;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread;

use bgpfc_fsm::Session;
use bgpfc_rib::{FibChange, Output, PeerInfo, Policies, Rib, Sink};
use bgpfc_wire::types::Asn;

use crate::coordinator::PeerTable;
use crate::messages::{FibMsg, PAGE, RibMsg, RibQuery, RibReply, RouteReport};
use crate::peer::SendError;

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
    let mut out = Deliver {
        peers,
        fib,
        changes: Vec::new(),
    };
    #[cfg(feature = "profiling")]
    let mut loads = crate::profiling::Loads::from_env();
    loop {
        #[cfg(not(feature = "profiling"))]
        let Ok(msg) = rx.recv() else {
            return;
        };
        #[cfg(feature = "profiling")]
        let Some(msg) = loads.recv(rx, &rib) else {
            return;
        };
        #[cfg(feature = "profiling")]
        let seen = loads.before(&msg);
        match msg {
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
                rib.peer_up(peer_info(peer, local_addr, &session), &mut out);
            }
            RibMsg::Update { peer, update, .. } => {
                log_update(peer, &update);
                rib.update(peer, &update, &mut out);
            }
            RibMsg::FamilyDisabled { peer, family } => {
                bgpfc_log::warn!("rib: family disabled", peer = peer, family = family);
                rib.family_disabled(peer, family, &mut out);
            }
            RibMsg::RouteRefresh { peer, family } => {
                bgpfc_log::info!("rib: route refresh", peer = peer, family = family);
                rib.refresh(peer, family, &mut out);
            }
            RibMsg::PeerDown { peer } => {
                let stats = rib.peer_stats(peer).unwrap_or_default();
                bgpfc_log::info!(
                    "rib: peer down",
                    peer = peer,
                    routes_deleted = stats.received.iter().map(|(_, n)| n).sum::<usize>()
                );
                rib.peer_down(peer, &mut out);
            }
            RibMsg::Query(q, reply) => {
                let _ = reply.send(answer(&rib, &q));
            }
            RibMsg::SetPolicies { policies, reexport } => {
                rib.set_policies(policies.0);
                for peer in reexport {
                    let families: Vec<_> = rib
                        .peer(peer)
                        .map(|p| p.families.clone())
                        .unwrap_or_default();
                    for family in families {
                        bgpfc_log::info!("rib: re-export", peer = peer, family = family);
                        rib.reexport(peer, family, &mut out);
                    }
                }
            }
            RibMsg::Resend { peer } => {
                let families: Vec<_> = rib
                    .peer(peer)
                    .map(|p| p.families.clone())
                    .unwrap_or_default();
                for family in families {
                    bgpfc_log::info!("rib: resend", peer = peer, family = family);
                    rib.refresh(peer, family, &mut out);
                }
            }
            RibMsg::FibMode(mode, reply) => {
                // Changes already made go first.
                out.flush();
                fib_mode(&rib, fib, mode, reply);
            }
        }
        out.flush();
        #[cfg(feature = "profiling")]
        loads.after(seen, &rib);
    }
}

/// Routes in one `FibMsg::Reconcile`.
const RECONCILE_BATCH: usize = 4096;

/// Switch the FIB's mode. Going to install, the FIB reconciles what is
/// installed against every route the RIB has (README, "FIB dry-run"),
/// which go to it in batches through the bounded queue rather than as one
/// table-sized list.
fn fib_mode(rib: &Rib, fib: &SyncSender<FibMsg>, mode: bgpfc_fib::Mode, reply: SyncSender<usize>) {
    let send = |msg| fib.send(msg).is_ok();
    let mut ok = send(FibMsg::SetMode(mode));
    if mode == bgpfc_fib::Mode::Install {
        let mut batch = Vec::with_capacity(RECONCILE_BATCH);
        for route in rib.fib_routes() {
            batch.push(route);
            if batch.len() == RECONCILE_BATCH {
                ok &= send(FibMsg::Reconcile(std::mem::take(&mut batch)));
                batch.reserve(RECONCILE_BATCH);
            }
        }
        ok &= send(FibMsg::Reconcile(batch));
    }
    ok &= send(FibMsg::ReconcileEnd(reply));
    if !ok {
        bgpfc_log::error!("fib thread gone");
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

/// FIB changes sent in one message at most: one per channel operation
/// costs the RIB thread more than the change itself.
pub(crate) const FIB_BATCH: usize = 256;

/// Hands RIB outputs to the FIB and peer threads as the RIB produces them;
/// FIB changes go in batches, sent when full and after each input.
struct Deliver<'a> {
    peers: &'a PeerTable,
    fib: &'a SyncSender<FibMsg>,
    changes: Vec<FibChange>,
}

impl Deliver<'_> {
    fn flush(&mut self) {
        if self.changes.is_empty() {
            return;
        }
        // The next input likely changes about as many destinations.
        let next = Vec::with_capacity(self.changes.len());
        let changes = std::mem::replace(&mut self.changes, next);
        // A bounded channel: a slow kernel slows the RIB rather than
        // growing memory (AGENTS.md §3 backpressure).
        if self.fib.send(FibMsg::Changes(changes)).is_err() {
            bgpfc_log::error!("fib thread gone");
        }
    }
}

impl Sink for Deliver<'_> {
    fn put(&mut self, output: Output) {
        match output {
            Output::Fib(c) => {
                self.changes.push(c);
                if self.changes.len() >= FIB_BATCH {
                    self.flush();
                }
            }
            Output::Send { peer, messages } => {
                let handle = self.peers.read().ok().and_then(|t| t.get(&peer).cloned());
                let Some(handle) = handle else {
                    return;
                };
                bgpfc_log::debug!("rib: send", peer = peer, messages = messages.len());
                match handle.send_updates(messages) {
                    Ok(()) => {}
                    Err(SendError::Overrun) => {
                        // AGENTS.md §3: never drop updates silently; the
                        // peer thread resets the session.
                        bgpfc_log::warn!("rib: peer outbox full", peer = peer);
                    }
                    Err(SendError::Gone) => {
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
    // Counting the prefixes costs more than the test.
    if !bgpfc_log::enabled(bgpfc_log::Level::Debug) {
        return;
    }
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
        RibQuery::Routes {
            family,
            prefix,
            after,
        } => match prefix {
            Some(prefix) => {
                let best = rib
                    .loc_rib(*family)
                    .find(|(p, _)| p == prefix)
                    .map(|(_, b)| b.peer);
                RibReply::Routes(
                    rib.candidates(*family, *prefix)
                        .map(|c| RouteReport {
                            prefix: *prefix,
                            peer: c.peer,
                            attrs: std::sync::Arc::clone(c.attrs),
                            best: best == Some(c.peer),
                        })
                        .collect(),
                )
            }
            None => RibReply::Routes(
                rib.loc_rib_after(*family, *after)
                    .take(PAGE)
                    .map(|(prefix, b)| RouteReport {
                        prefix,
                        peer: b.peer,
                        attrs: std::sync::Arc::clone(b.attrs),
                        best: true,
                    })
                    .collect(),
            ),
        },
        RibQuery::FibRoutes { after } => {
            RibReply::FibRoutes(rib.fib_routes_after(*after).take(PAGE).collect())
        }
    }
}
