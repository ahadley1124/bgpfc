//! Effective capabilities from `/proc/self/status` (README, "Option A";
//! AGENTS.md §3: no FFI for this).

use std::fmt;

/// Capabilities the daemon cares about (`<linux/capability.h>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// `CAP_NET_BIND_SERVICE` (10): bind port 179.
    NetBindService,
    /// `CAP_NET_ADMIN` (12): change routes.
    NetAdmin,
}

impl Capability {
    const fn bit(self) -> u32 {
        match self {
            Capability::NetBindService => 10,
            Capability::NetAdmin => 12,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Capability::NetBindService => "CAP_NET_BIND_SERVICE",
            Capability::NetAdmin => "CAP_NET_ADMIN",
        })
    }
}

/// The effective capability set as a bit mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effective(u64);

impl Effective {
    /// Parse the `CapEff:` line of `/proc/<pid>/status` text.
    #[must_use]
    pub fn parse(status: &str) -> Option<Effective> {
        status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .map(Effective)
    }

    /// Read the current process's set.
    ///
    /// # Errors
    /// If `/proc/self/status` cannot be read or has no `CapEff` line.
    pub fn current() -> std::io::Result<Effective> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        Effective::parse(&status).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no CapEff in /proc/self/status",
            )
        })
    }

    /// Whether `cap` is effective.
    #[must_use]
    pub const fn has(self, cap: Capability) -> bool {
        self.0 & (1 << cap.bit()) != 0
    }

    /// Those of `needed` that are not effective.
    #[must_use]
    pub fn missing(self, needed: &[Capability]) -> Vec<Capability> {
        needed.iter().copied().filter(|c| !self.has(*c)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cap_eff() {
        let full = Effective::parse("Name:\tx\nCapEff:\t000001ffffffffff\n").unwrap();
        assert!(full.has(Capability::NetAdmin));
        assert!(full.has(Capability::NetBindService));
        assert_eq!(full.missing(&[Capability::NetAdmin]), vec![]);
        let none = Effective::parse("CapEff:\t0000000000000000\n").unwrap();
        assert_eq!(
            none.missing(&[Capability::NetBindService, Capability::NetAdmin]),
            vec![Capability::NetBindService, Capability::NetAdmin]
        );
        let bind_only = Effective::parse("CapEff: 0000000000000400").unwrap();
        assert!(bind_only.has(Capability::NetBindService));
        assert!(!bind_only.has(Capability::NetAdmin));
        assert_eq!(Capability::NetAdmin.to_string(), "CAP_NET_ADMIN");
        assert!(Effective::parse("CapInh: 0\n").is_none());
        assert!(Effective::parse("CapEff: zz\n").is_none());
    }

    #[cfg(not(miri))]
    #[test]
    fn current_process_has_a_set() {
        Effective::current().expect("readable");
    }
}
