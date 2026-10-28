//! Effective capabilities from `/proc/self/status` (README, "Option A";
//! AGENTS.md §3: no FFI for this), and dropping one from the calling
//! thread (`capget(2)`, `capset(2)`), which reading cannot do.

use std::fmt;
use std::io;

use crate::ffi;

/// Capabilities the daemon cares about (`<linux/capability.h>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// `CAP_NET_BIND_SERVICE` (10): bind port 179.
    NetBindService,
    /// `CAP_NET_ADMIN` (12): change routes.
    NetAdmin,
    /// `CAP_SYS_ADMIN` (21): join a network namespace (`setns(2)`).
    SysAdmin,
}

impl Capability {
    /// The capability's number, its bit in each set.
    pub(crate) const fn bit(self) -> u32 {
        match self {
            Capability::NetBindService => 10,
            Capability::NetAdmin => 12,
            Capability::SysAdmin => 21,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Capability::NetBindService => "CAP_NET_BIND_SERVICE",
            Capability::NetAdmin => "CAP_NET_ADMIN",
            Capability::SysAdmin => "CAP_SYS_ADMIN",
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

/// Remove `cap` from the calling thread's effective, permitted and
/// inheritable sets, for good: nothing in the thread, nor in a thread or a
/// program it starts later, gets it back, but by executing a program with
/// file capabilities or set-user-ID root, or by root executing a program
/// (`capabilities(7)`). The kernel keeps no capability ambient that is not
/// permitted, so this clears it from the ambient set too. Other threads
/// keep theirs: capabilities belong to a thread, so drop them on the one
/// that later spawns the others, before it does.
///
/// A capability the thread does not hold is no error: the sets are
/// written back as they were.
///
/// # Errors
/// The `capget(2)` or `capset(2)` failure.
#[allow(unsafe_code, reason = "capget and capset with borrowed structs")]
pub fn drop_capability(cap: Capability) -> io::Result<()> {
    let mut header = ffi::cap_user_header {
        version: ffi::LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut sets = [ffi::cap_user_data::default(); ffi::LINUX_CAPABILITY_U32S_3];
    // SAFETY: `header` and `sets` live on this frame for the whole call.
    // With version 3 the kernel writes LINUX_CAPABILITY_U32S_3 structs to
    // `sets`, which has room for exactly that many; with another version it
    // would only write the version it prefers into `header` and fail.
    if unsafe { ffi::capget(&raw mut header, sets.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let sets = without(sets, cap);
    // SAFETY: as above; `capset` reads LINUX_CAPABILITY_U32S_3 structs from
    // `sets`, which holds that many, and writes at most `header`'s version.
    if unsafe { ffi::capset(&raw mut header, sets.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `sets`, as `capget(2)` fills them, with `cap` cleared from all three.
fn without(
    mut sets: [ffi::cap_user_data; ffi::LINUX_CAPABILITY_U32S_3],
    cap: Capability,
) -> [ffi::cap_user_data; ffi::LINUX_CAPABILITY_U32S_3] {
    // Bits 0-31 are in the first struct, 32-63 in the second
    // (<linux/capability.h>, `CAP_TO_INDEX` and `CAP_TO_MASK`).
    let (index, mask) = ((cap.bit() / 32) as usize, 1u32 << (cap.bit() % 32));
    if let Some(set) = sets.get_mut(index) {
        set.effective &= !mask;
        set.permitted &= !mask;
        set.inheritable &= !mask;
    }
    sets
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
        assert_eq!(Capability::SysAdmin.to_string(), "CAP_SYS_ADMIN");
        assert!(full.has(Capability::SysAdmin));
        // bit 21 alone: 0x200000.
        let sys_admin = Effective::parse("CapEff:\t0000000000200000\n").unwrap();
        assert!(sys_admin.has(Capability::SysAdmin));
        assert!(!sys_admin.has(Capability::NetAdmin));
        assert!(Effective::parse("CapInh: 0\n").is_none());
        assert!(Effective::parse("CapEff: zz\n").is_none());
    }

    #[cfg(not(miri))]
    #[test]
    fn current_process_has_a_set() {
        Effective::current().expect("readable");
    }

    /// Only the capability's bit goes, from every set, and only in its
    /// word: what `capset(2)` is given (`CAP_TO_INDEX`, `CAP_TO_MASK`).
    #[test]
    fn without_clears_one_bit_of_each_set() {
        let all = ffi::cap_user_data {
            effective: u32::MAX,
            permitted: u32::MAX,
            inheritable: u32::MAX,
        };
        let high = ffi::cap_user_data {
            effective: 0x1ff,
            permitted: 0x1ff,
            inheritable: 0,
        };
        let [low, rest] = without([all, high], Capability::SysAdmin);
        let cleared = !(1u32 << 21);
        assert_eq!(
            low,
            ffi::cap_user_data {
                effective: cleared,
                permitted: cleared,
                inheritable: cleared,
            }
        );
        assert_eq!(rest, high);
        let [low, _] = without([all, high], Capability::NetBindService);
        assert_eq!(low.permitted, !(1u32 << 10));
        // A capability not held: nothing changes.
        let none = [ffi::cap_user_data::default(); ffi::LINUX_CAPABILITY_U32S_3];
        assert_eq!(without(none, Capability::NetAdmin), none);
    }

    /// The `CapEff` of the calling thread (`/proc/thread-self/status`):
    /// `/proc/self/status` is the main thread's.
    #[cfg(not(miri))]
    fn thread_effective() -> Effective {
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        Effective::parse(&status).unwrap()
    }

    /// A thread that drops `CAP_SYS_ADMIN` loses it, and the thread that
    /// spawned it keeps whatever it had. Without the capability, as an
    /// unprivileged user, the drop is a no-op that succeeds; as root, the
    /// spawned thread really loses it, and only that thread.
    #[cfg(not(miri))]
    #[test]
    fn dropping_a_capability_affects_the_calling_thread_alone() {
        let before = thread_effective();
        let after = std::thread::spawn(|| {
            drop_capability(Capability::SysAdmin).expect("drop CAP_SYS_ADMIN");
            // Twice: a capability not held is no error.
            drop_capability(Capability::SysAdmin).expect("drop it again");
            thread_effective()
        })
        .join()
        .unwrap();
        assert!(!after.has(Capability::SysAdmin), "{after:?}");
        // Nothing else went.
        assert_eq!(
            after.has(Capability::NetAdmin),
            before.has(Capability::NetAdmin)
        );
        assert_eq!(thread_effective(), before, "the test thread kept its set");
    }
}
