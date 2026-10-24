//! A counting global allocator for profiling builds (`docs/PROFILING.md`):
//! the system allocator, plus live and peak bytes and the number of
//! allocations and deallocations.
//!
//! Built only with the `profiling` feature. A binary opts in with
//! `#[global_allocator] static A: Counting = Counting::new();`; the default
//! build contains neither this module nor its counters.
//!
//! Implements: no RFC; instrumentation only.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicU64, AtomicUsize};

/// What the counters hold at one moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocStats {
    /// Bytes currently allocated.
    pub live: u64,
    /// The highest `live` since start or the last [`reset_peak`].
    pub peak: u64,
    /// Successful allocations; a successful `realloc` counts as one.
    pub allocs: u64,
    /// Deallocations.
    pub deallocs: u64,
}

/// The counters behind one [`Counting`].
///
/// Every update is `Relaxed`: the figures are statistics, nothing is
/// synchronised through them, and a reader may see the four fields from
/// slightly different moments. `live` cannot underflow: a block is freed
/// only after the allocation that produced it, and the modification order
/// of one atomic respects that.
#[derive(Debug)]
struct Counters {
    live: AtomicUsize,
    peak: AtomicUsize,
    allocs: AtomicU64,
    deallocs: AtomicU64,
}

impl Counters {
    const fn new() -> Counters {
        Counters {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            allocs: AtomicU64::new(0),
            deallocs: AtomicU64::new(0),
        }
    }

    fn allocated(&self, size: usize) {
        self.allocs.fetch_add(1, Relaxed);
        let live = self.live.fetch_add(size, Relaxed).wrapping_add(size);
        self.raise_peak(live);
    }

    fn freed(&self, size: usize) {
        self.deallocs.fetch_add(1, Relaxed);
        self.live.fetch_sub(size, Relaxed);
    }

    fn reallocated(&self, old: usize, new: usize) {
        self.allocs.fetch_add(1, Relaxed);
        if new >= old {
            let grow = new - old;
            let live = self.live.fetch_add(grow, Relaxed).wrapping_add(grow);
            self.raise_peak(live);
        } else {
            self.live.fetch_sub(old - new, Relaxed);
        }
    }

    fn raise_peak(&self, live: usize) {
        // Most allocations set no new peak; loading first keeps them from
        // writing a cache line every thread shares.
        if live > self.peak.load(Relaxed) {
            self.peak.fetch_max(live, Relaxed);
        }
    }

    fn snapshot(&self) -> AllocStats {
        AllocStats {
            live: self.live.load(Relaxed) as u64,
            peak: self.peak.load(Relaxed) as u64,
            allocs: self.allocs.load(Relaxed),
            deallocs: self.deallocs.load(Relaxed),
        }
    }

    fn reset_peak(&self) {
        self.peak.store(self.live.load(Relaxed), Relaxed);
    }
}

/// The counters [`Counting::new`] uses and [`stats`] reads.
static GLOBAL: Counters = Counters::new();

/// The system allocator with counters. Register it as the global
/// allocator and read the figures with [`stats`].
#[derive(Debug)]
pub struct Counting {
    counters: &'static Counters,
}

impl Counting {
    /// The allocator [`stats`] and [`reset_peak`] report on.
    #[must_use]
    pub const fn new() -> Counting {
        Counting { counters: &GLOBAL }
    }
}

impl Default for Counting {
    fn default() -> Self {
        Counting::new()
    }
}

#[allow(
    unsafe_code,
    reason = "GlobalAlloc is an unsafe trait; every call is forwarded to System"
)]
// SAFETY: each method passes its arguments to the same method of `System`
// unchanged and returns `System`'s result unchanged, so every guarantee
// `System` gives (and every obligation on the caller) carries over as is.
// The bookkeeping only touches atomics: it never allocates, never panics,
// never unwinds and never reads or writes the memory handed out. A null
// result is passed through and not counted.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `alloc`'s
        // contract (a non-zero size).
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.counters.allocated(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            self.counters.allocated(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` came from this allocator,
        // that is from `System`, with this `layout`.
        unsafe { System.dealloc(ptr, layout) };
        self.counters.freed(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller guarantees `ptr` came from `System` with
        // `layout` and that `new_size` is valid for it; forwarded unchanged.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        // On failure the old block is untouched, so nothing changes.
        if !new.is_null() {
            self.counters.reallocated(layout.size(), new_size);
        }
        new
    }
}

/// The counters of every [`Counting::new`] allocator, normally the one
/// registered as the global allocator.
#[must_use]
pub fn stats() -> AllocStats {
    GLOBAL.snapshot()
}

/// Set the peak to the current live bytes, to measure the peak of a phase.
pub fn reset_peak() {
    GLOBAL.reset_peak();
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "the tests drive the GlobalAlloc methods directly"
)]
mod tests {
    use super::*;

    /// An allocator with counters of its own (a `static` per test), so
    /// tests run in parallel without seeing each other.
    fn local(counters: &'static Counters) -> Counting {
        Counting { counters }
    }

    fn layout(size: usize) -> Layout {
        Layout::from_size_align(size, 8).unwrap()
    }

    #[test]
    fn alloc_and_dealloc_move_live_and_peak() {
        static C: Counters = Counters::new();
        let a = local(&C);
        // SAFETY: non-zero sizes; each block is freed once with the layout
        // it was allocated with.
        unsafe {
            let p = a.alloc(layout(100));
            assert!(!p.is_null());
            let z = a.alloc_zeroed(layout(50));
            assert!(!z.is_null());
            assert!(std::slice::from_raw_parts(z, 50).iter().all(|b| *b == 0));
            assert_eq!(
                a.counters.snapshot(),
                AllocStats {
                    live: 150,
                    peak: 150,
                    allocs: 2,
                    deallocs: 0
                }
            );
            a.dealloc(p, layout(100));
            assert_eq!(a.counters.snapshot().live, 50);
            a.dealloc(z, layout(50));
        }
        assert_eq!(
            a.counters.snapshot(),
            AllocStats {
                live: 0,
                peak: 150,
                allocs: 2,
                deallocs: 2
            }
        );
    }

    #[test]
    fn realloc_counts_one_allocation_and_the_size_delta() {
        static C: Counters = Counters::new();
        let a = local(&C);
        // SAFETY: `p` is always the live block and `old` its layout; it is
        // freed once at the end.
        unsafe {
            let p = a.alloc(layout(64));
            let p = a.realloc(p, layout(64), 256);
            assert!(!p.is_null());
            assert_eq!(
                a.counters.snapshot(),
                AllocStats {
                    live: 256,
                    peak: 256,
                    allocs: 2,
                    deallocs: 0
                }
            );
            let p = a.realloc(p, layout(256), 32);
            assert!(!p.is_null());
            assert_eq!(
                a.counters.snapshot(),
                AllocStats {
                    live: 32,
                    peak: 256,
                    allocs: 3,
                    deallocs: 0
                }
            );
            a.dealloc(p, layout(32));
        }
        assert_eq!(a.counters.snapshot().live, 0);
        assert_eq!(a.counters.snapshot().deallocs, 1);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri stops on an impossible allocation instead of returning null"
    )]
    fn failed_allocations_are_not_counted() {
        static C: Counters = Counters::new();
        let a = local(&C);
        let huge = layout(isize::MAX as usize / 2);
        // SAFETY: a valid, non-zero layout; a null result is not used, and
        // the small block is freed with its layout.
        unsafe {
            assert!(a.alloc(huge).is_null());
            assert!(a.alloc_zeroed(huge).is_null());
            let p = a.alloc(layout(16));
            assert!(a.realloc(p, layout(16), isize::MAX as usize / 2).is_null());
            assert_eq!(
                a.counters.snapshot(),
                AllocStats {
                    live: 16,
                    peak: 16,
                    allocs: 1,
                    deallocs: 0
                }
            );
            a.dealloc(p, layout(16));
        }
    }

    #[test]
    fn reset_peak_starts_from_live() {
        let c = Counters::new();
        c.allocated(1000);
        c.freed(1000);
        c.allocated(10);
        assert_eq!(c.snapshot().peak, 1000);
        c.reset_peak();
        assert_eq!(c.snapshot().peak, 10);
        c.allocated(5);
        assert_eq!(c.snapshot().peak, 15);
    }

    #[test]
    fn new_reports_through_stats() {
        let a = Counting::new();
        let before = stats().allocs;
        // SAFETY: a non-zero layout, freed once with the same layout.
        unsafe {
            let p = a.alloc(layout(8));
            a.dealloc(p, layout(8));
        }
        assert!(stats().allocs > before);
        reset_peak();
        assert!(stats().peak >= stats().live);
    }
}
