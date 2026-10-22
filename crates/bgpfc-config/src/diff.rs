//! What changed between two configurations, so a reload can apply only
//! that (AGENTS.md §3, "Config": reset only the sessions whose session
//! parameters changed; policy-only changes re-evaluate routes).

use std::net::IpAddr;

use crate::ast::{Config, Neighbor};

/// The difference between an old and a new configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigDiff {
    /// Neighbors only the new configuration has: start them.
    pub added: Vec<IpAddr>,
    /// Neighbors only the old configuration has: stop them (Cease / Peer
    /// De-configured, RFC 4486 §4).
    pub removed: Vec<IpAddr>,
    /// Neighbors in both whose session parameters differ: reset them
    /// (Cease / Other Configuration Change, RFC 4486 §4).
    pub reset: Vec<IpAddr>,
    /// Neighbors in both, not reset, whose import or export policy (or
    /// anything those policies reference) changed: re-evaluate their
    /// routes, with route refresh where the peer supports it.
    pub policy_changed: Vec<IpAddr>,
    /// Neighbors in both with only a description change, or none.
    pub unchanged: Vec<IpAddr>,
    /// Which global settings changed.
    pub global: Vec<GlobalChange>,
}

/// A change outside the neighbor blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlobalChange {
    /// `router-id` or `local-as`: every session resets.
    Identity,
    /// The listen addresses.
    Listen,
    /// The `fib` block.
    Fib,
    /// The `log` block.
    Log,
    /// The `control` block.
    Control,
}

impl ConfigDiff {
    /// Compare `old` with `new`.
    #[must_use]
    pub fn between(old: &Config, new: &Config) -> ConfigDiff {
        let identity_changed = old.router_id != new.router_id || old.local_as != new.local_as;
        let mut d = ConfigDiff::default();
        for (changed, what) in [
            (identity_changed, GlobalChange::Identity),
            (old.listen != new.listen, GlobalChange::Listen),
            (old.fib != new.fib, GlobalChange::Fib),
            (old.log_level != new.log_level, GlobalChange::Log),
            (old.control != new.control, GlobalChange::Control),
        ] {
            if changed {
                d.global.push(what);
            }
        }
        for n in &old.neighbors {
            if new.neighbor(n.addr).is_none() {
                d.removed.push(n.addr);
            }
        }
        for n in &new.neighbors {
            let Some(o) = old.neighbor(n.addr) else {
                d.added.push(n.addr);
                continue;
            };
            if identity_changed || !o.same_session(n) {
                d.reset.push(n.addr);
            } else if policy_differs(old, o, new, n) {
                d.policy_changed.push(n.addr);
            } else {
                d.unchanged.push(n.addr);
            }
        }
        d
    }

    /// Whether anything at all differs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.reset.is_empty()
            && self.policy_changed.is_empty()
            && self.global.is_empty()
    }
}

/// Whether the import or export policy of a neighbor, including the
/// prefix lists they use, differs between the configurations.
fn policy_differs(old: &Config, o: &Neighbor, new: &Config, n: &Neighbor) -> bool {
    [(&o.import, &n.import), (&o.export, &n.export)]
        .into_iter()
        .any(|(a, b)| policy_fingerprint(old, a) != policy_fingerprint(new, b))
}

/// The policy's terms and every prefix list they reference, with
/// positions stripped so that moving text around is not a change.
fn policy_fingerprint(cfg: &Config, name: &str) -> String {
    use std::fmt::Write as _;
    let Some(p) = cfg.policy(name) else {
        return String::new();
    };
    let mut s = String::new();
    for t in &p.terms {
        let _ = write!(s, "{}|{:?}|{:?}|{:?};", t.name, t.matches, t.sets, t.action);
        for m in &t.matches {
            if let crate::ast::Match::PrefixList(l) = m {
                let entries = cfg.prefix_list(l).map(|p| &p.entries);
                let _ = write!(s, "{l}={entries:?};");
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "router-id 192.0.2.1; local-as 65000;
        listen { address ::; }
        prefix-list P { 10.0.0.0/8 le 24; }
        policy IN { term p { match prefix-list P; action reject; } term r { action accept; } }
        policy OUT { term all { action accept; } }
        neighbor 192.0.2.2 { remote-as 65001; description \"a\"; import IN; export OUT; }
        neighbor 192.0.2.3 { remote-as 65002; import IN; export OUT; }";

    fn cfg(text: &str) -> Config {
        crate::parse_str("t", text).unwrap()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn identical_and_cosmetic_changes_are_empty() {
        let a = cfg(BASE);
        assert!(ConfigDiff::between(&a, &a).is_empty());
        // Comments, whitespace and a description are not changes.
        let b = cfg(&format!("# comment\n\n{}", BASE.replace("\"a\"", "\"b\"")));
        let d = ConfigDiff::between(&a, &b);
        assert!(d.is_empty(), "{d:?}");
        assert_eq!(d.unchanged, vec![addr("192.0.2.2"), addr("192.0.2.3")]);
    }

    #[test]
    fn neighbor_changes_are_classified() {
        let a = cfg(BASE);
        let b = cfg(&BASE
            .replace("remote-as 65001;", "remote-as 65001; hold-time 30;")
            .replace("neighbor 192.0.2.3", "neighbor 192.0.2.4"));
        let d = ConfigDiff::between(&a, &b);
        assert_eq!(d.reset, vec![addr("192.0.2.2")]);
        assert_eq!(d.removed, vec![addr("192.0.2.3")]);
        assert_eq!(d.added, vec![addr("192.0.2.4")]);
        assert_eq!(d.global, vec![]);
        assert!(!d.is_empty());
    }

    #[test]
    fn policy_and_prefix_list_edits_are_policy_changes() {
        let base = cfg(BASE);
        let a = &base;
        // A different policy name for one neighbor.
        let b = cfg(&BASE.replace(
            "remote-as 65002; import IN;",
            "remote-as 65002; import OUT;",
        ));
        let d = ConfigDiff::between(a, &b);
        assert_eq!(d.policy_changed, vec![addr("192.0.2.3")]);
        assert_eq!(d.unchanged, vec![addr("192.0.2.2")]);
        assert_eq!(d.reset, Vec::<IpAddr>::new());
        // A prefix list edit reaches every neighbor whose policy uses it.
        let edited_list = cfg(&BASE.replace("le 24", "le 32"));
        let d = ConfigDiff::between(a, &edited_list);
        assert_eq!(d.policy_changed, vec![addr("192.0.2.2"), addr("192.0.2.3")]);
        // A term edit likewise.
        let e = cfg(&BASE.replace(
            "term r { action accept; }",
            "term r { set med 1; action accept; }",
        ));
        assert_eq!(
            ConfigDiff::between(a, &e).policy_changed,
            vec![addr("192.0.2.2"), addr("192.0.2.3")]
        );
    }

    #[test]
    fn global_changes() {
        let a = cfg(BASE);
        let b = cfg(&BASE
            .replace("local-as 65000", "local-as 65009")
            .replace("address ::;", "address ::; port 1179;"));
        let d = ConfigDiff::between(&a, &b);
        assert_eq!(d.global, vec![GlobalChange::Identity, GlobalChange::Listen]);
        // A new local AS resets every session.
        assert_eq!(d.reset.len(), 2);
        let c = cfg(&format!(
            "{BASE} log {{ level debug; }} fib {{ mode install; }} control {{ socket /x; }}"
        ));
        assert_eq!(
            ConfigDiff::between(&a, &c).global,
            vec![GlobalChange::Fib, GlobalChange::Log, GlobalChange::Control]
        );
    }
}
