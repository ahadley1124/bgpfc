//! What the RIB holds, for profiling builds (`docs/PROFILING.md`).

use std::collections::{BTreeMap, HashMap};

use crate::Rib;

/// Table sizes, cheap to compute: one addition per family and peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizes {
    /// Destinations of every family. Every destination held has a route,
    /// and so a best one: this is also the size of the Loc-RIB.
    pub destinations: usize,
    /// Routes in all Adj-RIBs-In.
    pub adj_rib_in: usize,
    /// Routes in all Adj-RIBs-Out.
    pub adj_rib_out: usize,
}

impl Rib {
    /// How many destinations and routes the RIB holds.
    #[must_use]
    pub fn sizes(&self) -> Sizes {
        Sizes {
            destinations: self.tables.values().map(BTreeMap::len).sum(),
            adj_rib_in: self
                .peers
                .values()
                .flat_map(|p| p.adj_in_count.values())
                .sum(),
            adj_rib_out: self
                .peers
                .values()
                .flat_map(|p| p.adj_out.values())
                .map(HashMap::len)
                .sum(),
        }
    }
}
