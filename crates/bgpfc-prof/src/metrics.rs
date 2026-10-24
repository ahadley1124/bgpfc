//! The named instruments, with the key each has on the report line
//! (`docs/PROFILING.md`, "Reading the report line").

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::counter::{Counter, Gauge};
use crate::hist::Histogram;

/// UPDATE messages received, before decoding (`updates_rx`).
pub static UPDATES_RECEIVED: Counter = Counter::new();
/// UPDATE messages written to peers (`updates_tx`).
pub static UPDATES_SENT: Counter = Counter::new();
/// Routes announced in UPDATEs received (`prefixes_announced`).
pub static PREFIXES_ANNOUNCED: Counter = Counter::new();
/// Routes withdrawn by UPDATEs received, treat-as-withdraw included
/// (`prefixes_withdrawn`).
pub static PREFIXES_WITHDRAWN: Counter = Counter::new();
/// Octets of BGP messages read, headers included (`bytes_rx`).
pub static BYTES_RECEIVED: Counter = Counter::new();
/// Octets of BGP messages written, headers included (`bytes_tx`).
pub static BYTES_SENT: Counter = Counter::new();
/// Decision process runs, one per destination (`best_path_runs`).
pub static BEST_PATH_RUNS: Counter = Counter::new();
/// Sessions that reached Established (`sessions_established`).
pub static SESSIONS_ESTABLISHED: Counter = Counter::new();
/// Sessions that left Established (`sessions_dropped`).
pub static SESSIONS_DROPPED: Counter = Counter::new();

/// Destinations in the Loc-RIB, all families (`rib_prefixes`).
pub static RIB_PREFIXES: Gauge = Gauge::new();
/// Routes in all Adj-RIBs-In (`adj_rib_in`).
pub static ADJ_RIB_IN: Gauge = Gauge::new();
/// Routes in all Adj-RIBs-Out (`adj_rib_out`).
pub static ADJ_RIB_OUT: Gauge = Gauge::new();

/// From the first OPEN sent or received on a connection to Established.
pub static FSM_OPEN_TO_ESTABLISHED: Histogram = Histogram::new();
/// One complete UPDATE decode (`UpdateMessage::decode`).
pub static MSG_PARSE_UPDATE: Histogram = Histogram::new();
/// The path attribute section of one UPDATE.
pub static ATTR_PARSE: Histogram = Histogram::new();
/// One announced route into the Adj-RIB-In, import policy included,
/// before the decision process.
pub static RIB_INSERT: Histogram = Histogram::new();
/// One withdrawn route out of the Adj-RIB-In.
pub static RIB_REMOVE: Histogram = Histogram::new();
/// One decision process run (RFC 4271 §9.1.2) for one destination.
pub static BEST_PATH: Histogram = Histogram::new();
/// Encoding one peer's batch of Adj-RIB-Out changes into UPDATEs.
pub static ADJ_RIB_OUT_BUILD: Histogram = Histogram::new();
/// Removing every route of a peer that went down, decision process and
/// Adj-RIB-Out updates included.
pub static RIB_PEER_DOWN: Histogram = Histogram::new();
/// The RIB thread's handling of one UPDATE: Adj-RIB-In, decision process,
/// Adj-RIB-Out, outputs handed to the FIB and peer threads.
pub static RIB_UPDATE: Histogram = Histogram::new();
/// One UPDATE from the start of its decode on the peer thread until the
/// RIB thread is done with it, the wait in the RIB queue included.
pub static UPDATE_TOTAL: Histogram = Histogram::new();

/// Every counter with its report key, in report order.
pub static COUNTERS: [(&str, &Counter); 9] = [
    ("updates_rx", &UPDATES_RECEIVED),
    ("updates_tx", &UPDATES_SENT),
    ("prefixes_announced", &PREFIXES_ANNOUNCED),
    ("prefixes_withdrawn", &PREFIXES_WITHDRAWN),
    ("bytes_rx", &BYTES_RECEIVED),
    ("bytes_tx", &BYTES_SENT),
    ("best_path_runs", &BEST_PATH_RUNS),
    ("sessions_established", &SESSIONS_ESTABLISHED),
    ("sessions_dropped", &SESSIONS_DROPPED),
];

/// Every gauge with its report key.
pub static GAUGES: [(&str, &Gauge); 3] = [
    ("rib_prefixes", &RIB_PREFIXES),
    ("adj_rib_in", &ADJ_RIB_IN),
    ("adj_rib_out", &ADJ_RIB_OUT),
];

/// Every histogram with its report key prefix.
pub static HISTOGRAMS: [(&str, &Histogram); 10] = [
    ("fsm_open_to_established", &FSM_OPEN_TO_ESTABLISHED),
    ("msg_parse_update", &MSG_PARSE_UPDATE),
    ("attr_parse", &ATTR_PARSE),
    ("rib_insert", &RIB_INSERT),
    ("rib_remove", &RIB_REMOVE),
    ("best_path", &BEST_PATH),
    ("adj_rib_out_build", &ADJ_RIB_OUT_BUILD),
    ("rib_peer_down", &RIB_PEER_DOWN),
    ("rib_update", &RIB_UPDATE),
    ("update_total", &UPDATE_TOTAL),
];

static START: OnceLock<Instant> = OnceLock::new();

/// Remember the process start for [`uptime`]; later calls do nothing.
pub fn mark_start() {
    START.get_or_init(Instant::now);
}

/// Time since [`mark_start`]; zero before it.
#[must_use]
pub fn uptime() -> Duration {
    START.get().map_or(Duration::ZERO, Instant::elapsed)
}
