//! Cross-item checks on a lowered configuration (AGENTS.md §3, "Config"):
//! references resolve, neighbors are unique, timers are consistent. (The
//! loopback-only HTTP listener is checked where the statement is lowered,
//! so the error can point at it.)
//!
//! Implements: RFC 9687 §4.4 (a fixed `SendHoldTime` exceeds the Hold
//! Time); RFC 4271 §10 (`KeepaliveTime` below the Hold Time); RFC 8950 §4
//! (`extended-next-hop` qualifies a configured family); RFC 4271 §6.7
//! (`maximum-prefix` bounds a configured family); RFC 6811 §3 (`set rpki`
//! only where the state is used: import). A neighbor's `local-address`
//! is an address of its family a session can run from.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use crate::ast::{Config, Match, Neighbor, SendHoldTime, SetAction};
use crate::error::{ConfigError, Pos};

/// Every problem found, or nothing.
pub(crate) fn validate(cfg: &Config) -> Vec<ConfigError> {
    let mut errors = Vec::new();
    let mut err = |pos, m: String| errors.push(ConfigError::new(pos, m));

    for policy in &cfg.policies {
        for term in &policy.terms {
            for m in &term.matches {
                if let Match::PrefixList(name) = m
                    && cfg.prefix_list(name).is_none()
                {
                    err(
                        term.pos,
                        format!(
                            "term `{}` in policy `{}` uses undefined prefix-list `{name}`",
                            term.name, policy.name
                        ),
                    );
                }
            }
        }
    }

    // The state a route is used with is set on import (RFC 6811 §3) and
    // travels no further: without RFC 8097, which is not implemented, no
    // attribute carries it to the neighbor. In an export policy `set rpki`
    // would do nothing, so say so rather than let it mislead.
    for policy in &cfg.policies {
        let Some(n) = cfg.neighbors.iter().find(|n| n.export == policy.name) else {
            continue;
        };
        for term in &policy.terms {
            if term.sets.iter().any(|s| matches!(s, SetAction::Rpki(_))) {
                err(
                    term.pos,
                    format!(
                        "term `{}` of policy `{}` sets the validation state, which only an \
                         import policy can do; `{}` is the export policy of neighbor {}",
                        term.name, policy.name, policy.name, n.addr
                    ),
                );
            }
        }
    }

    let mut seen = HashSet::new();
    for n in &cfg.neighbors {
        if !seen.insert(n.addr) {
            err(n.pos, format!("neighbor {} is defined twice", n.addr));
        }
        for (what, name) in [("import", &n.import), ("export", &n.export)] {
            if cfg.policy(name).is_none() {
                err(
                    n.pos,
                    format!("neighbor {} {what}s undefined policy `{name}`", n.addr),
                );
            }
        }
        neighbor(n, &mut err);
    }

    errors
}

/// The checks of one neighbor's own statements against each other.
fn neighbor(n: &Neighbor, err: &mut impl FnMut(Pos, String)) {
    let hold = Duration::from_secs(u64::from(n.hold_time.secs()));
    // RFC 4271 §10: a KeepaliveTime of at least the Hold Time would
    // let the peer's HoldTimer expire.
    if let Some(k) = n.keepalive_time
        && !n.hold_time.is_zero()
        && k >= hold
    {
        err(
            n.pos,
            format!(
                "neighbor {}: keepalive-time {}s must be below hold-time {}s",
                n.addr,
                k.as_secs(),
                hold.as_secs()
            ),
        );
    }
    // RFC 9687 §4.4: SendHoldTime must be greater than the Hold Time.
    if let SendHoldTime::Seconds(s) = n.send_hold_time
        && u64::from(s) <= hold.as_secs()
    {
        err(
            n.pos,
            format!(
                "neighbor {}: send-hold-time {s}s must exceed hold-time {}s (RFC 9687 §4.4)",
                n.addr,
                hold.as_secs()
            ),
        );
    }
    // RFC 8950 §4: the capability only says how a family's next hop
    // may be encoded; it cannot make the family usable, which is the
    // Multiprotocol capability's job (RFC 4760 §8).
    for family in &n.extended_next_hop {
        if !n.families.contains(family) {
            err(
                n.pos,
                format!(
                    "neighbor {}: extended-next-hop needs the {family} family (RFC 8950 §4)",
                    n.addr
                ),
            );
        }
    }
    // RFC 4760 §8: a family not configured is never negotiated, so a
    // limit on it could never apply; say so rather than ignore it.
    for (family, _) in &n.maximum_prefix {
        if !n.families.contains(family) {
            err(
                n.pos,
                format!(
                    "neighbor {}: maximum-prefix for {family}, which is not in its families",
                    n.addr
                ),
            );
        }
    }
    if let Some(local) = n.local_address
        && let Some(problem) = local_address_problem(n.addr, local)
    {
        err(n.pos, format!("neighbor {}: {problem}", n.addr));
    }
}

/// Why `local` cannot be the address a session with `neighbor` runs
/// from, if it cannot. A connection is bound to it before connecting, so
/// it must be a unicast address of the neighbor's family that a socket
/// can be bound to without an interface.
fn local_address_problem(neighbor: IpAddr, local: IpAddr) -> Option<String> {
    let family = |a: IpAddr| if a.is_ipv4() { "IPv4" } else { "IPv6" };
    if local.is_ipv4() != neighbor.is_ipv4() {
        return Some(format!(
            "local-address {local} is {}, the neighbor {}",
            family(local),
            family(neighbor)
        ));
    }
    if local.is_unspecified() {
        return Some(format!(
            "local-address {local} is unspecified; leave the statement out to let the kernel \
             choose"
        ));
    }
    if local.is_multicast() {
        return Some(format!("local-address {local} is a multicast address"));
    }
    if local == neighbor {
        return Some(format!(
            "local-address {local} is the neighbor's own address"
        ));
    }
    // Binding an IPv6 link-local address needs the interface it is on
    // (ipv6(7), `sin6_scope_id`), which an address in this file cannot
    // name.
    if let IpAddr::V6(v6) = local
        && v6.is_unicast_link_local()
    {
        return Some(format!(
            "local-address {local} is link-local, which needs an interface bgpfcd cannot be \
             given"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_address_is_a_unicast_address_of_the_neighbors_family() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for (neighbor, local) in [
            ("192.0.2.2", "192.0.2.1"),
            ("192.0.2.2", "127.0.0.1"),
            ("192.0.2.2", "169.254.0.1"),
            ("2001:db8::2", "2001:db8::1"),
            ("2001:db8::2", "fd00::1"),
            ("fe80::2", "2001:db8::1"),
        ] {
            assert_eq!(
                local_address_problem(ip(neighbor), ip(local)),
                None,
                "{neighbor} {local}"
            );
        }
        for (neighbor, local, problem) in [
            ("2001:db8::2", "192.0.2.1", "is IPv4, the neighbor IPv6"),
            ("192.0.2.2", "2001:db8::1", "is IPv6, the neighbor IPv4"),
            ("192.0.2.2", "0.0.0.0", "is unspecified"),
            ("2001:db8::2", "::", "is unspecified"),
            ("192.0.2.2", "224.0.0.5", "is a multicast address"),
            ("2001:db8::2", "ff02::2", "is a multicast address"),
            ("192.0.2.2", "192.0.2.2", "is the neighbor's own address"),
            ("2001:db8::2", "fe80::1", "is link-local"),
        ] {
            let got = local_address_problem(ip(neighbor), ip(local));
            assert!(
                got.as_deref().is_some_and(|g| g.contains(problem)),
                "{neighbor} {local}: {got:?}"
            );
        }
    }
}
