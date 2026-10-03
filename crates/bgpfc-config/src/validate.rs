//! Cross-item checks on a lowered configuration (AGENTS.md §3, "Config"):
//! references resolve, neighbors are unique, timers are consistent. (The
//! loopback-only HTTP listener is checked where the statement is lowered,
//! so the error can point at it.)
//!
//! Implements: RFC 9687 §4.4 (a fixed `SendHoldTime` exceeds the Hold
//! Time); RFC 4271 §10 (`KeepaliveTime` below the Hold Time).

use std::collections::HashSet;
use std::time::Duration;

use crate::ast::{Config, Match, SendHoldTime};
use crate::error::ConfigError;

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
    }

    errors
}
