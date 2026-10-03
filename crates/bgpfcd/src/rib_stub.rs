//! Stand-in for the RIB thread until milestone 5: consumes `RibMsg` and
//! logs what it would do, so sessions can be exercised end to end.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::Receiver;
use std::thread;

use crate::messages::RibMsg;

/// Start the stub on its own thread.
pub(crate) fn spawn(rx: Receiver<RibMsg>) {
    thread::Builder::new()
        .name("rib".to_owned())
        .spawn(move || run(&rx))
        .expect("spawning the rib thread");
}

fn run(rx: &Receiver<RibMsg>) {
    let mut routes: HashMap<IpAddr, usize> = HashMap::new();
    while let Ok(msg) = rx.recv() {
        match msg {
            RibMsg::PeerUp { peer, session } => {
                routes.insert(peer, 0);
                bgpfc_log::info!(
                    "rib: peer up",
                    peer = peer,
                    families = session
                        .families
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            RibMsg::Update { peer, update } => {
                let announced = update.announcements().count();
                let withdrawn = update.withdrawals().count();
                let n = routes.entry(peer).or_insert(0);
                *n = n.saturating_add(announced).saturating_sub(withdrawn);
                bgpfc_log::debug!(
                    "rib: update",
                    peer = peer,
                    announced = announced,
                    withdrawn = withdrawn,
                    total = *n
                );
                for (family, prefix) in update.announcements() {
                    bgpfc_log::debug!(
                        "rib: announce",
                        peer = peer,
                        family = family,
                        prefix = prefix
                    );
                }
                for (family, prefix) in update.withdrawals() {
                    bgpfc_log::debug!(
                        "rib: withdraw",
                        peer = peer,
                        family = family,
                        prefix = prefix
                    );
                }
            }
            RibMsg::FamilyDisabled { peer, family } => {
                bgpfc_log::warn!("rib: family disabled", peer = peer, family = family);
            }
            RibMsg::RouteRefresh { peer, family } => {
                bgpfc_log::info!("rib: route refresh requested", peer = peer, family = family);
            }
            RibMsg::PeerDown { peer } => {
                let n = routes.remove(&peer).unwrap_or(0);
                bgpfc_log::info!("rib: peer down", peer = peer, routes_deleted = n);
            }
        }
    }
}
