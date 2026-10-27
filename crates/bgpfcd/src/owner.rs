//! Who owns the other end of a TCP connection within this host, from the
//! kernel's socket tables, `/proc/net/tcp` and `/proc/net/tcp6` (`proc(5)`):
//! for each socket of the network namespace they give its local and remote
//! address, its state and the user that owns it.
//!
//! With `mode sidecar`, bgpfcd's RTR client connects to Routinator on a
//! loopback port, and RTR there is unprotected TCP (RFC 8210 §9): the
//! client would believe whatever answers. Routinator binds that port only
//! once its first validation run ends, minutes after a cold start and
//! again after each restart, and until then any process on the host may
//! bind it and serve VRPs of its own, which `drop-invalid` would act on.
//! Routinator is bgpfcd's child and may not switch users, so it runs as
//! bgpfcd's user; the client therefore uses a connection only if the
//! socket at its other end belongs to the user that owns its own end
//! ([`same_user`]). The kernel gives a socket the user of the process that
//! made it, and a connection a listener has yet to accept, or has
//! accepted, the user of the listener. So a process of another user that
//! took the port is refused, and its VRPs never reach the RIB (RFC 8210
//! §13: the router relies on the cache being one it trusts). A process of
//! bgpfcd's own user is not told apart: such a process can already change
//! Routinator's repository and configuration.
//!
//! Nor are users the tables cannot name. In a user namespace they give
//! every user the namespace does not map as the overflow user, 65534
//! (`from_kuid_munged` in the kernel), so a bgpfcd that runs as that user
//! there, or in a namespace with no user map, where it is that user
//! itself, passes a server of any unmapped user, root's included. That,
//! and a user other processes share, such as `nobody`, is why
//! COMPLIANCE.md has the RFC 8210 §9, §13 row `partial` with `mode
//! sidecar` (`docs/config.md`, "Who serves the sidecar's port"). Where
//! one of them applies ([`weaknesses`]: bgpfcd runs as the overflow user,
//! as `nobody`, or in a user namespace that is not the initial one),
//! bgpfcd warns at each start of Routinator ([`warn_if_weaker`]), and
//! `bgpfcd --check` does too, and goes on: the check still refuses every
//! user it can tell apart from bgpfcd's own.

use std::fs;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

/// The socket tables, IPv4 and IPv6. A kernel without IPv6 has no second.
const TABLES: [&str; 2] = ["/proc/net/tcp", "/proc/net/tcp6"];

/// How often the tables are read for a connection that is not in them
/// yet, and how long apart: the far end of a connection on this host is
/// there once the handshake is done, so this only covers a read that
/// raced the kernel.
const ATTEMPTS: u32 = 5;
const PAUSE: Duration = Duration::from_millis(10);

/// `TCP_TIME_WAIT` (`<net/tcp_states.h>`): what is left of a closed
/// connection, owned by no one (the table says user 0).
const TIME_WAIT: u8 = 0x06;

/// One line of a socket table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    local: SocketAddr,
    remote: SocketAddr,
    state: u8,
    uid: u32,
}

/// The entries of one table's text: every line after the header that
/// parses. The kernel writes the lines, so one that does not parse is
/// skipped rather than trusted.
fn entries(table: &str) -> impl Iterator<Item = Entry> + '_ {
    table.lines().skip(1).filter_map(entry)
}

/// `sl local_address rem_address st tx_queue:rx_queue tr:tm->when
/// retrnsmt uid ...`.
fn entry(line: &str) -> Option<Entry> {
    let mut fields = line.split_whitespace();
    let _slot = fields.next()?;
    let local = address(fields.next()?)?;
    let remote = address(fields.next()?)?;
    let state = u8::from_str_radix(fields.next()?, 16).ok()?;
    // tx_queue:rx_queue, tr:tm->when and retrnsmt come before the user.
    let uid = fields.nth(3)?.parse().ok()?;
    Some(Entry {
        local,
        remote,
        state,
        uid,
    })
}

/// `0100007F:0CEB`: the address as 32-bit words, each printed as the
/// number its four octets make in this host's byte order (eight hex
/// digits for IPv4, thirty-two for IPv6), then the port, in hex. An IPv6
/// address that maps an IPv4 one, as a dual-stack socket's are, is taken
/// as that IPv4 address.
fn address(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        let hex = ip.get(i * 8..i * 8 + 8)?;
        u32::from_str_radix(hex, 16).ok().map(u32::to_ne_bytes)
    };
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut octets = [0; 16];
            for (i, chunk) in octets.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *chunk = word(i)?;
            }
            Ipv6Addr::from(octets).to_canonical()
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Why a connection was refused.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// An end of the connection is not in the tables.
    Missing,
    /// The far end belongs to another user than the near end.
    OtherUser { near: u32, far: u32 },
}

/// The users of the two ends of the connection from `near` to `far`, as
/// `tables` give them, and whether they are the same.
fn judge(tables: &[String], near: SocketAddr, far: SocketAddr) -> Result<(), Refusal> {
    let canonical = |a: SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    let (near, far) = (canonical(near), canonical(far));
    let live = tables
        .iter()
        .flat_map(|t| entries(t))
        .filter(|e| e.state != TIME_WAIT);
    let (mut near_uid, mut far_uid) = (None, None);
    for e in live {
        if e.local == near && e.remote == far {
            near_uid = Some(e.uid);
        } else if e.local == far && e.remote == near {
            far_uid = Some(e.uid);
        }
    }
    match (near_uid, far_uid) {
        (Some(near), Some(far)) if near == far => Ok(()),
        (Some(near), Some(far)) => Err(Refusal::OtherUser { near, far }),
        _ => Err(Refusal::Missing),
    }
}

/// The socket tables' text, those this kernel has.
fn read_tables() -> io::Result<Vec<String>> {
    let mut tables = Vec::with_capacity(TABLES.len());
    for path in TABLES {
        match fs::read_to_string(path) {
            Ok(text) => tables.push(text),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io::Error::new(e.kind(), format!("reading {path}: {e}"))),
        }
    }
    Ok(tables)
}

/// Whether the socket at the other end of `stream`, a connection within
/// this host, belongs to the user that owns this end, as the kernel's
/// socket tables say (see the module documentation).
///
/// # Errors
/// [`ErrorKind::PermissionDenied`], naming both users, if it belongs to
/// another; [`ErrorKind::NotFound`] if an end is not in the tables, as for
/// a connection that leaves the host; or the error reading the tables.
pub(crate) fn same_user(stream: &TcpStream) -> io::Result<()> {
    let near = stream.local_addr()?;
    let far = stream.peer_addr()?;
    for attempt in 1..=ATTEMPTS {
        match judge(&read_tables()?, near, far) {
            Ok(()) => return Ok(()),
            Err(Refusal::OtherUser { near, far: owner }) => {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "{far} is served by uid {owner}, not by uid {near} as bgpfcd is: \
                         another process holds the port"
                    ),
                ));
            }
            Err(Refusal::Missing) if attempt < ATTEMPTS => thread::sleep(PAUSE),
            Err(Refusal::Missing) => {}
        }
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        format!("the connection to {far} is not in the kernel's socket tables"),
    ))
}

/// The overflow user of a kernel that does not say otherwise in
/// `/proc/sys/kernel/overflowuid`: `DEFAULT_OVERFLOWUID` in the kernel's
/// `include/linux/highuid.h`.
const DEFAULT_OVERFLOW_UID: u32 = 65534;

/// The kernel's overflow user, the user the socket tables give a socket
/// whose user the reader's user namespace does not map.
const OVERFLOW_UID: &str = "/proc/sys/kernel/overflowuid";

/// The user map of this process's user namespace (`user_namespaces(7)`).
const UID_MAP: &str = "/proc/self/uid_map";

/// The map of the initial user namespace: every user to itself, one line
/// `0 0 4294967295` (`user_namespaces(7)`).
const IDENTITY_MAP: [u32; 3] = [0, 0, u32::MAX];

/// Why [`same_user`] tells fewer servers apart where bgpfcd runs than
/// where it runs as a user of its own in the initial user namespace: the
/// reasons COMPLIANCE.md has the RFC 8210 §9, §13 row `partial` with
/// `mode sidecar` (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Weakness {
    /// bgpfcd runs as the overflow user, this uid, which the socket
    /// tables give every user the user namespace does not map: a server
    /// of any such user, root's included, passes for bgpfcd's own.
    OverflowUser(u32),
    /// bgpfcd runs as `nobody`, this uid, which other services share: a
    /// server any of them starts on the port passes for Routinator.
    Nobody(u32),
    /// bgpfcd runs in a user namespace whose map is not the identity: the
    /// tables show every user it does not map as the overflow user, so
    /// the check cannot tell those users apart.
    UserNamespace,
}

impl std::fmt::Display for Weakness {
    /// Why, in a sentence that stands alone.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Weakness::OverflowUser(uid) => write!(
                f,
                "uid {uid} is the overflow uid, which the kernel's socket tables give every \
                 user this user namespace does not map, so a server of any such user, root's \
                 included, passes for bgpfcd's own"
            ),
            Weakness::Nobody(uid) => write!(
                f,
                "uid {uid} is nobody's, which other services share, so a server any of them \
                 starts on the port passes for Routinator"
            ),
            Weakness::UserNamespace => f.write_str(
                "bgpfcd runs in a user namespace whose uid_map is not the identity, where the \
                 kernel's socket tables show every user it does not map as the overflow uid, \
                 so the check cannot tell those users apart",
            ),
        }
    }
}

/// What weakens [`same_user`] for a bgpfcd that runs as `uid`, given the
/// kernel's overflow user, `overflow`, the uid `nobody` has in the user
/// database, if it has one, and the text of `/proc/self/uid_map`, `None`
/// for a kernel without user namespaces. Pure.
pub(crate) fn weaknesses(
    uid: u32,
    overflow: u32,
    nobody: Option<u32>,
    uid_map: Option<&str>,
) -> Vec<Weakness> {
    let mut found = Vec::new();
    if uid == overflow {
        found.push(Weakness::OverflowUser(uid));
    }
    if nobody == Some(uid) {
        found.push(Weakness::Nobody(uid));
    }
    if uid_map.is_some_and(|map| !is_identity_map(map)) {
        found.push(Weakness::UserNamespace);
    }
    found
}

/// Whether `uid_map`, as `/proc/self/uid_map` gives it, maps every user
/// to itself: one line, `0 0 4294967295`, however it is padded. An empty
/// map, a namespace's before its map is written, maps no one.
fn is_identity_map(uid_map: &str) -> bool {
    let mut lines = uid_map.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next().map(|line| {
        line.split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
    });
    matches!(first, Some(Ok(fields)) if fields == IDENTITY_MAP) && lines.next().is_none()
}

/// The effective uid in the text of `/proc/self/status` (`proc(5)`:
/// `Uid:` real, effective, saved set, filesystem), as this process's user
/// namespace sees it.
pub(crate) fn effective_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The overflow user in the text of `/proc/sys/kernel/overflowuid`, or
/// the kernel's default without one.
fn overflow_uid(text: Option<&str>) -> u32 {
    text.and_then(|t| t.trim().parse().ok())
        .unwrap_or(DEFAULT_OVERFLOW_UID)
}

/// What weakens [`same_user`] here for a bgpfcd that runs as `uid`, or,
/// with `None`, as the user this process runs as now, from the kernel and
/// the user database; and the uid judged. A file that cannot be read
/// counts as saying nothing: no `uid_map` is the initial namespace, no
/// `nobody` no such user.
pub(crate) fn weaker_here(uid: Option<u32>) -> Option<(u32, Vec<Weakness>)> {
    let read = |path: &str| fs::read_to_string(path).ok();
    let uid = match uid {
        Some(uid) => uid,
        None => effective_uid(&read("/proc/self/status")?)?,
    };
    let passwd = read("/etc/passwd").unwrap_or_default();
    let nobody = bgpfc_sys::lookup_user(&passwd, "nobody").map(|id| id.uid);
    let found = weaknesses(
        uid,
        overflow_uid(read(OVERFLOW_UID).as_deref()),
        nobody,
        read(UID_MAP).as_deref(),
    );
    Some((uid, found))
}

/// The reasons the check is weaker, one sentence.
pub(crate) fn reasons(found: &[Weakness]) -> String {
    found
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// With `mode sidecar`, at each start of Routinator, a warning if the
/// owner check of its port is weaker where bgpfcd runs ([`weaker_here`]);
/// bgpfcd starts it all the same. Whether the check holds is the
/// operator's to judge, which the warning helps with: running bgpfcd as a
/// user of its own, in the initial user namespace, is the remedy.
pub(crate) fn warn_if_weaker() {
    let Some((uid, found)) = weaker_here(None) else {
        return;
    };
    if found.is_empty() {
        return;
    }
    bgpfc_log::warn!(
        "rpki sidecar: the owner check of Routinator's port is weaker here; starting anyway",
        uid = uid,
        reasons = reasons(&found),
        hint = "run bgpfcd as a user of its own in the initial user namespace (docs/config.md, \"Who serves the sidecar's port\")"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::TcpListener;

    /// The header of both tables.
    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when \
                          retrnsmt   uid  timeout inode";

    fn table(lines: &[&str]) -> String {
        let mut text = format!("{HEADER}\n");
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Lines as an x86-64 Linux 6.18 kernel wrote them: a listener on
    /// 127.0.0.1:40011 of root, and a connection to it from port 51000 of
    /// uid 65534, both ends; then an IPv6 one, `::1` port 3323 to port
    /// 51001.
    #[cfg(target_endian = "little")]
    const V4: [&str; 3] = [
        "   0: 0100007F:9C4B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3104 1 0000000019dd57d6 100 0 0 10 0",
        "   1: 0100007F:C738 0100007F:9C4B 01 00000000:00000000 00:00000000 00000000 65534        0 8211 1 00000000a3e1b2c4 20 4 30 10 -1",
        "   2: 0100007F:9C4B 0100007F:C738 01 00000000:00000000 00:00000000 00000000     0        0 8212 1 00000000b4f2c3d5 20 4 28 10 -1",
    ];
    #[cfg(target_endian = "little")]
    const V6: [&str; 2] = [
        "   0: 00000000000000000000000001000000:0CFB 00000000000000000000000001000000:C739 01 00000000:00000000 00:00000000 00000000 65534        0 9001 1 00000000c5a3d4e6 20 4 30 10 -1",
        "   1: 00000000000000000000000001000000:C739 00000000000000000000000001000000:0CFB 01 00000000:00000000 00:00000000 00000000 65534        0 9002 1 00000000d6b4e5f7 20 4 30 10 -1",
    ];

    #[test]
    #[cfg(target_endian = "little")]
    fn the_tables_parse_as_the_kernel_writes_them() {
        let v4: Vec<Entry> = entries(&table(&V4)).collect();
        assert_eq!(
            v4,
            [
                Entry {
                    local: addr("127.0.0.1:40011"),
                    remote: addr("0.0.0.0:0"),
                    state: 0x0A,
                    uid: 0,
                },
                Entry {
                    local: addr("127.0.0.1:51000"),
                    remote: addr("127.0.0.1:40011"),
                    state: 0x01,
                    uid: 65_534,
                },
                Entry {
                    local: addr("127.0.0.1:40011"),
                    remote: addr("127.0.0.1:51000"),
                    state: 0x01,
                    uid: 0,
                },
            ]
        );
        let v6: Vec<Entry> = entries(&table(&V6)).collect();
        assert_eq!(v6[0].local, addr("[::1]:3323"));
        assert_eq!(v6[0].remote, addr("[::1]:51001"));
        assert_eq!(v6[1].uid, 65_534);
        // An IPv4 address mapped into IPv6 is the IPv4 one.
        let mapped = "   0: 0000000000000000FFFF00000100007F:9C4B 0000000000000000FFFF00000100007F:C738 01 00000000:00000000 00:00000000 00000000  1000 0 1 1 0 20 4 30 10 -1";
        let e = entry(mapped).unwrap();
        assert_eq!(e.local, addr("127.0.0.1:40011"));
        assert_eq!(e.uid, 1_000);
    }

    /// Lines that are not the kernel's are skipped, never half read.
    #[test]
    fn lines_that_do_not_parse_are_skipped() {
        for line in [
            "",
            "   0:",
            "   0: 0100007F:9C4B",
            "   0: 0100007F 00000000:0000 0A 0:0 0:0 0 0 0 1",
            "   0: 0100007G:9C4B 00000000:0000 0A 0:0 0:0 0 0 0 1",
            "   0: 0100007F:9C4B 00000000:0000 0A 0:0 0:0 0 nobody 0 1",
            "   0: 0100007F0:9C4B 00000000:0000 0A 0:0 0:0 0 0 0 1",
            "   0: 0100007F:19C4B 00000000:0000 0A 0:0 0:0 0 0 0 1",
            "   0: \u{e9}\u{e9}\u{e9}\u{e9}:9C4B 00000000:0000 0A 0:0 0:0 0 0 0 1",
        ] {
            assert_eq!(entry(line), None, "{line:?}");
        }
        assert_eq!(entries("only a header").count(), 0);
    }

    /// The verdict on a connection from port 51000 to a server on 40011.
    #[test]
    #[cfg(target_endian = "little")]
    fn the_far_end_must_belong_to_the_near_end_s_user() {
        let (near, far) = (addr("127.0.0.1:51000"), addr("127.0.0.1:40011"));
        // A server of root for a client of nobody: refused.
        let tables = [table(&V4)];
        assert_eq!(
            judge(&tables, near, far),
            Err(Refusal::OtherUser {
                near: 65_534,
                far: 0
            })
        );
        // Both ends nobody's: used.
        let same = V4[2].replace(
            "00000000     0        0 8212",
            "00000000 65534        0 8212",
        );
        let tables = [table(&[V4[0], V4[1], &same])];
        assert_eq!(judge(&tables, near, far), Ok(()));
        // A far end missing, or left only as TIME_WAIT: refused.
        let tables = [table(&[V4[0], V4[1]])];
        assert_eq!(judge(&tables, near, far), Err(Refusal::Missing));
        let gone = same.replace(" 01 00000000", " 06 00000000");
        let tables = [table(&[V4[1], &gone])];
        assert_eq!(judge(&tables, near, far), Err(Refusal::Missing));
        // A far end in the IPv6 table, as a dual-stack listener's: found.
        let dual = "   0: 0000000000000000FFFF00000100007F:9C4B 0000000000000000FFFF00000100007F:C738 01 00000000:00000000 00:00000000 00000000  1000 0 1 1 0 20 4 30 10 -1";
        let tables = [table(&[V4[1]]), table(&[dual])];
        assert_eq!(
            judge(&tables, near, far),
            Err(Refusal::OtherUser {
                near: 65_534,
                far: 1_000
            })
        );
        // IPv6 on both ends.
        let tables = [table(&V6)];
        assert_eq!(
            judge(&tables, addr("[::1]:51001"), addr("[::1]:3323")),
            Ok(())
        );
    }

    /// A connection between two sockets of this process: the same user at
    /// both ends, already while the listener has yet to accept it, and
    /// after. A connection that left the host would not be in the tables.
    #[test]
    fn a_connection_of_this_process_passes() {
        let mut hosts = vec!["127.0.0.1:0"];
        if TcpListener::bind("[::1]:0").is_ok() {
            hosts.push("[::1]:0");
        }
        for host in hosts {
            let listener = TcpListener::bind(host).unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            assert_eq!(same_user(&stream).map_err(|e| e.to_string()), Ok(()));
            let (_accepted, _) = listener.accept().unwrap();
            assert_eq!(same_user(&stream).map_err(|e| e.to_string()), Ok(()));
        }
    }

    /// The initial user namespace's map, however the kernel pads it, and
    /// nothing else, maps every user to itself.
    #[test]
    fn only_the_initial_namespace_maps_every_user_to_itself() {
        assert!(is_identity_map("         0          0 4294967295\n"));
        assert!(is_identity_map("0 0 4294967295"));
        for other in [
            // A namespace whose map is not written yet, as `unshare -U`.
            "",
            "\n",
            // A rootless container's, and one that maps a single user.
            "         0     100000      65536\n",
            "         0       1000          1\n",
            "0 0 4294967295\n4294967295 1 1\n",
            "0 0 4294967294\n",
            "0 0\n",
            "a b c\n",
        ] {
            assert!(!is_identity_map(other), "{other:?}");
        }
    }

    /// `Uid:` real, effective, saved set, filesystem: the second.
    #[test]
    fn the_effective_uid_comes_from_the_status() {
        use std::os::unix::fs::MetadataExt as _;
        let status = "Name:\tbgpfcd\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t42\n\
                      Uid:\t0\t65534\t65534\t65534\nGid:\t0\t65534\t65534\t65534\n";
        assert_eq!(effective_uid(status), Some(65534));
        assert_eq!(effective_uid("Name:\tx\n"), None);
        assert_eq!(effective_uid("Uid:\t0\n"), None);
        assert_eq!(effective_uid("Uid:\t0\tx\t0\t0\n"), None);
        // This process's own, as the kernel writes it: the owner the
        // kernel gives its `/proc/self`.
        let status = fs::read_to_string("/proc/self/status").unwrap();
        assert_eq!(
            effective_uid(&status),
            Some(fs::metadata("/proc/self").unwrap().uid())
        );
    }

    /// The kernel's overflow user, its default 65534 when the file says
    /// nothing usable.
    #[test]
    fn the_overflow_uid_is_the_kernel_s() {
        assert_eq!(overflow_uid(Some("65534\n")), 65534);
        assert_eq!(overflow_uid(Some("4000\n")), 4000);
        assert_eq!(overflow_uid(None), 65534);
        assert_eq!(overflow_uid(Some("")), 65534);
        assert_eq!(overflow_uid(Some("-1\n")), 65534);
    }

    /// What weakens the check: being the overflow user, being `nobody`,
    /// and a user namespace; each alone, together, or none of them.
    #[test]
    fn what_weakens_the_owner_check() {
        use Weakness::{Nobody, OverflowUser, UserNamespace};
        const IDENTITY: Option<&str> = Some("         0          0 4294967295\n");
        // A user of its own in the initial namespace, root included.
        assert_eq!(weaknesses(998, 65534, Some(65534), IDENTITY), []);
        assert_eq!(weaknesses(0, 65534, Some(65534), IDENTITY), []);
        // `nobody`, the overflow user on most systems: both.
        assert_eq!(
            weaknesses(65534, 65534, Some(65534), IDENTITY),
            [OverflowUser(65534), Nobody(65534)]
        );
        // `nobody` that is not the overflow user, as uid 99 on older
        // systems, and the overflow user with no `nobody`.
        assert_eq!(weaknesses(99, 65534, Some(99), IDENTITY), [Nobody(99)]);
        assert_eq!(weaknesses(4000, 4000, None, IDENTITY), [OverflowUser(4000)]);
        // A rootless container's namespace, and one with no map at all,
        // where bgpfcd is the overflow user itself.
        assert_eq!(
            weaknesses(998, 65534, Some(65534), Some("0 100000 65536\n")),
            [UserNamespace]
        );
        assert_eq!(
            weaknesses(65534, 65534, None, Some("")),
            [OverflowUser(65534), UserNamespace]
        );
        // A kernel without user namespaces has only the initial one.
        assert_eq!(weaknesses(998, 65534, None, None), []);
    }

    /// The warning says why, a reason after the other, each standing
    /// alone.
    #[test]
    fn the_reasons_are_one_sentence() {
        assert_eq!(reasons(&[]), "");
        assert_eq!(
            reasons(&[Weakness::Nobody(99), Weakness::UserNamespace]),
            "uid 99 is nobody's, which other services share, so a server any of them starts \
             on the port passes for Routinator; bgpfcd runs in a user namespace whose uid_map \
             is not the identity, where the kernel's socket tables show every user it does not \
             map as the overflow uid, so the check cannot tell those users apart"
        );
        assert!(
            Weakness::OverflowUser(65534)
                .to_string()
                .starts_with("uid 65534 is the overflow uid, ")
        );
    }

    /// Here, as the kernel and the user database have it: as `nobody` the
    /// check is weaker wherever `nobody` exists; as this process's user,
    /// the judgment is that of the files read now.
    #[test]
    fn the_judgment_here_reads_the_kernel() {
        let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
        if let Some(nobody) = bgpfc_sys::lookup_user(&passwd, "nobody") {
            let (uid, found) = weaker_here(Some(nobody.uid)).unwrap();
            assert_eq!(uid, nobody.uid);
            assert!(found.contains(&Weakness::Nobody(nobody.uid)), "{found:?}");
        }
        let (uid, found) = weaker_here(None).unwrap();
        let overflow = overflow_uid(fs::read_to_string(OVERFLOW_UID).ok().as_deref());
        assert_eq!(
            found.contains(&Weakness::OverflowUser(uid)),
            uid == overflow
        );
        let map = fs::read_to_string(UID_MAP).ok();
        assert_eq!(
            found.contains(&Weakness::UserNamespace),
            map.is_some_and(|m| !is_identity_map(&m))
        );
    }
}
