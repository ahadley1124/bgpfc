//! Process memory as the kernel sees it, from `/proc/self/status`.
//!
//! `VmRSS` is the resident set now and `VmHWM` its high-water mark. Next to
//! the counting allocator's live and peak bytes they show how much memory
//! the allocator holds beyond what the program uses (fragmentation, freed
//! pages not returned). Off Linux, or without `/proc`, every reader
//! returns `None`.

/// The resident set size in KiB.
#[must_use]
pub fn read_rss_kb() -> Option<u64> {
    memory().map(|m| m.rss_kb)
}

/// The resident set high-water mark in KiB.
#[must_use]
pub fn read_hwm_kb() -> Option<u64> {
    memory().map(|m| m.hwm_kb)
}

/// Both figures from one read of the status file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memory {
    /// `VmRSS`, KiB.
    pub rss_kb: u64,
    /// `VmHWM`, KiB.
    pub hwm_kb: u64,
}

/// Read `VmRSS` and `VmHWM`.
#[must_use]
pub fn memory() -> Option<Memory> {
    let status = read_status()?;
    Some(Memory {
        rss_kb: parse_status_kb(&status, "VmRSS")?,
        hwm_kb: parse_status_kb(&status, "VmHWM")?,
    })
}

#[cfg(target_os = "linux")]
fn read_status() -> Option<String> {
    std::fs::read_to_string("/proc/self/status").ok()
}

#[cfg(not(target_os = "linux"))]
fn read_status() -> Option<String> {
    None
}

/// The number on the `key:` line of a `/proc/<pid>/status` text, which
/// the kernel prints as `VmRSS:\t   12345 kB`.
#[must_use]
pub fn parse_status_kb(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tbgpfcd\nVmPeak:\t  300000 kB\nVmHWM:\t   81234 kB\n\
                          VmRSS:\t   79876 kB\nVmRSSFile:\t1 kB\nThreads:\t9\n";

    #[test]
    fn parses_the_status_lines() {
        assert_eq!(parse_status_kb(STATUS, "VmRSS"), Some(79_876));
        assert_eq!(parse_status_kb(STATUS, "VmHWM"), Some(81_234));
        assert_eq!(parse_status_kb(STATUS, "VmSwap"), None);
        assert_eq!(parse_status_kb("VmRSS:\tlots kB\n", "VmRSS"), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn reads_this_process() {
        let m = memory().unwrap();
        assert!(m.rss_kb > 0);
        assert!(m.hwm_kb >= m.rss_kb);
        assert!(read_rss_kb().is_some() && read_hwm_kb().is_some());
    }
}
