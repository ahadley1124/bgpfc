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
    /// Neighbors in both, not reset, whose `advertisement-interval`
    /// changed: the RIB paces the running session with the new value
    /// (RFC 4271 §9.2.1.1), no reset needed. A neighbor may be here and
    /// in `policy_changed` too.
    pub interval_changed: Vec<IpAddr>,
    /// Neighbors in both, not reset, whose `maximum-prefix` limits
    /// changed: the RIB applies them to the running session (RFC 4271
    /// §6.7), which ends at once if it already holds more routes than a
    /// new limit allows. A neighbor may be in the lists above too.
    pub prefix_limit_changed: Vec<IpAddr>,
    /// Neighbors in both, not reset, that `add-path send` sends a different
    /// number of paths to for some family (RFC 7911 §5): the RIB applies it
    /// to the running session and sends what the change adds or takes
    /// away. A neighbor may be in the lists above too.
    pub add_path_send_changed: Vec<IpAddr>,
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
    /// The `rpki` block, an absent one counting as `mode disabled` with
    /// the defaults: the RTR client starts, stops or restarts. A block
    /// that only spells something differently, such as a default written
    /// out or a cache's host (see [`Rpki::same_as`](crate::ast::Rpki::same_as)),
    /// is no change.
    Rpki,
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
            (!old.rpki.same_as(&new.rpki), GlobalChange::Rpki),
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
                continue;
            }
            let policy = policy_differs(old, o, new, n);
            let interval = o.advertisement_interval != n.advertisement_interval;
            let limit = o.maximum_prefix != n.maximum_prefix;
            // `same_session` holds the families `add-path send` is on for
            // the same: only how many paths each sends can differ.
            let paths = o.add_path_send != n.add_path_send;
            if paths {
                d.add_path_send_changed.push(n.addr);
            }
            if policy {
                d.policy_changed.push(n.addr);
            }
            if interval {
                d.interval_changed.push(n.addr);
            }
            if limit {
                d.prefix_limit_changed.push(n.addr);
            }
            if !policy && !interval && !limit && !paths {
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
            && self.interval_changed.is_empty()
            && self.prefix_limit_changed.is_empty()
            && self.add_path_send_changed.is_empty()
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
        // RFC 8950 §4: extended-next-hop changes the OPEN, so it is a
        // session parameter.
        let c = cfg(&BASE.replace(
            "remote-as 65002;",
            "remote-as 65002; extended-next-hop yes;",
        ));
        assert_eq!(ConfigDiff::between(&a, &c).reset, vec![addr("192.0.2.3")]);
        // The RFC 4486 §4 restart limit is the FSM's, like the timers: a
        // change resets the session, which also starts a peer it stopped.
        let unbounded =
            cfg(&BASE.replace("remote-as 65002;", "remote-as 65002; restart-limit off;"));
        assert_eq!(
            ConfigDiff::between(&a, &unbounded).reset,
            vec![addr("192.0.2.3")]
        );
        // Spelling out the default is no change.
        let explicit = cfg(&BASE.replace("remote-as 65002;", "remote-as 65002; restart-limit 10;"));
        assert!(ConfigDiff::between(&a, &explicit).is_empty());
    }

    #[test]
    fn a_role_or_strict_mode_is_a_session_parameter() {
        // RFC 9234 §4.1, §4.2: the Role is in the OPEN and strict mode
        // decides whether the OPEN is acceptable, and the Only to Customer
        // procedures of §5 follow the Role, so a change resets the session.
        let a = cfg(BASE);
        let with = |text: &str| cfg(&BASE.replace("remote-as 65002;", text));
        let customer = with("remote-as 65002; role customer;");
        assert_eq!(
            ConfigDiff::between(&a, &customer).reset,
            vec![addr("192.0.2.3")]
        );
        let provider = with("remote-as 65002; role provider;");
        assert_eq!(
            ConfigDiff::between(&customer, &provider).reset,
            vec![addr("192.0.2.3")]
        );
        let strict = with("remote-as 65002; role customer; role-strict yes;");
        assert_eq!(
            ConfigDiff::between(&customer, &strict).reset,
            vec![addr("192.0.2.3")]
        );
        assert_eq!(
            ConfigDiff::between(&strict, &a).reset,
            vec![addr("192.0.2.3")]
        );
        // Spelling out the defaults is no change.
        let explicit = with("remote-as 65002; role customer; role-strict no;");
        assert!(ConfigDiff::between(&customer, &explicit).is_empty());
        // Strict mode with no Role is no setting at all, and an error.
        assert!(
            crate::parse_str(
                "t",
                &BASE.replace("remote-as 65002;", "remote-as 65002; role-strict yes;")
            )
            .is_err()
        );
        let off = with("remote-as 65002; role-strict no;");
        assert!(ConfigDiff::between(&a, &off).is_empty());
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
    fn advertisement_interval_changes_need_no_reset() {
        let a = cfg(BASE);
        // Set where it was the default, and alongside a policy change.
        let b = cfg(&BASE
            .replace(
                "description \"a\";",
                "description \"a\"; advertisement-interval 0;",
            )
            .replace(
                "remote-as 65002; import IN;",
                "remote-as 65002; advertisement-interval 5; import OUT;",
            ));
        let d = ConfigDiff::between(&a, &b);
        assert_eq!(
            d.interval_changed,
            vec![addr("192.0.2.2"), addr("192.0.2.3")]
        );
        assert_eq!(d.policy_changed, vec![addr("192.0.2.3")]);
        assert_eq!(d.reset, Vec::<IpAddr>::new());
        assert_eq!(d.unchanged, Vec::<IpAddr>::new());
        assert!(!d.is_empty());
        // The explicit default is still a change from "the default": the
        // daemon resolves both to the same value and does nothing.
        let c = cfg(&BASE.replace(
            "description \"a\";",
            "description \"a\"; advertisement-interval 30;",
        ));
        assert_eq!(
            ConfigDiff::between(&a, &c).interval_changed,
            vec![addr("192.0.2.2")]
        );
        assert!(ConfigDiff::between(&b, &b).is_empty());
    }

    #[test]
    fn prefix_limit_changes_need_no_reset() {
        let a = cfg(BASE);
        // RFC 4271 §6.7: a limit is the RIB's, not the session's.
        let b = cfg(&BASE.replace(
            "remote-as 65002;",
            "remote-as 65002; maximum-prefix ipv4-unicast 100;",
        ));
        let d = ConfigDiff::between(&a, &b);
        assert_eq!(d.prefix_limit_changed, vec![addr("192.0.2.3")]);
        assert_eq!(d.reset, Vec::<IpAddr>::new());
        assert_eq!(d.unchanged, vec![addr("192.0.2.2")]);
        assert!(!d.is_empty());
        // Raised, lowered or removed alike.
        let c = cfg(&BASE.replace(
            "remote-as 65002;",
            "remote-as 65002; maximum-prefix ipv4-unicast 50;",
        ));
        assert_eq!(
            ConfigDiff::between(&b, &c).prefix_limit_changed,
            vec![addr("192.0.2.3")]
        );
        assert_eq!(
            ConfigDiff::between(&c, &a).prefix_limit_changed,
            vec![addr("192.0.2.3")]
        );
        assert!(ConfigDiff::between(&c, &c).is_empty());
    }

    #[test]
    fn graceful_restart_is_a_session_parameter() {
        let a = cfg(BASE);
        let with = |extra: &str| {
            cfg(&BASE.replace("remote-as 65002;", &format!("remote-as 65002; {extra}")))
        };
        // RFC 4724 §3: the capability and its Restart Time are in the OPEN,
        // and the stale time is read when a session comes up, so turning
        // it on, or changing either time, resets the session.
        let on = with("graceful-restart yes;");
        let d = ConfigDiff::between(&a, &on);
        assert_eq!(d.reset, vec![addr("192.0.2.3")]);
        assert_eq!(d.unchanged, vec![addr("192.0.2.2")]);
        for other in [
            "graceful-restart yes; restart-time 60;",
            "graceful-restart yes; stale-time 90;",
        ] {
            let d = ConfigDiff::between(&on, &with(other));
            assert_eq!(d.reset, vec![addr("192.0.2.3")], "{other}");
        }
        // Back off, a reset again; `no` is the same as nothing, and the
        // defaults written out are the defaults.
        assert_eq!(ConfigDiff::between(&on, &a).reset, vec![addr("192.0.2.3")]);
        assert!(ConfigDiff::between(&a, &with("graceful-restart no;")).is_empty());
        assert!(
            ConfigDiff::between(
                &on,
                &with("graceful-restart yes; restart-time 120; stale-time 360;")
            )
            .is_empty()
        );
    }

    #[test]
    fn add_path_resets_for_a_family_but_not_for_how_many_paths() {
        let a = cfg(BASE);
        let with = |extra: &str| {
            cfg(&BASE.replace("remote-as 65002;", &format!("remote-as 65002; {extra}")))
        };
        // RFC 7911 §4: the capability is in the OPEN, so turning ADD-PATH
        // on or off for a family changes the session.
        for extra in [
            "add-path receive ipv4-unicast yes;",
            "add-path send ipv4-unicast 2;",
            "add-path send ipv4-unicast all;",
        ] {
            let d = ConfigDiff::between(&a, &with(extra));
            assert_eq!(d.reset, vec![addr("192.0.2.3")], "{extra}");
            assert_eq!(d.add_path_send_changed, Vec::<IpAddr>::new(), "{extra}");
            assert!(!d.is_empty());
        }
        // `no`, `off` and nothing are the same.
        for same in [
            "add-path receive ipv4-unicast no;",
            "add-path send ipv4-unicast off;",
        ] {
            assert!(ConfigDiff::between(&a, &with(same)).is_empty(), "{same}");
        }
        // Another family is another session.
        assert_eq!(
            ConfigDiff::between(
                &with("add-path send ipv4-unicast 2;"),
                &with("add-path send ipv6-unicast 2;")
            )
            .reset,
            vec![addr("192.0.2.3")]
        );
        // How many paths is the RIB's: no reset, a re-evaluation.
        let two = with("add-path send ipv4-unicast 2;");
        for (other, listed) in [
            ("add-path send ipv4-unicast 3;", true),
            ("add-path send ipv4-unicast all;", true),
            ("add-path send ipv4-unicast 2;", false),
        ] {
            let d = ConfigDiff::between(&two, &with(other));
            assert_eq!(d.reset, Vec::<IpAddr>::new(), "{other}");
            assert_eq!(
                d.add_path_send_changed,
                if listed {
                    vec![addr("192.0.2.3")]
                } else {
                    vec![]
                },
                "{other}"
            );
            assert_eq!(d.is_empty(), !listed, "{other}");
            if listed {
                assert_eq!(d.unchanged, vec![addr("192.0.2.2")]);
            }
        }
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

    #[test]
    fn rpki_changes_are_one_global_change() {
        let a = cfg(BASE);
        let with = |block: &str| cfg(&format!("{BASE} {block}"));
        let external = with("rpki { mode external; cache 192.0.2.10; }");
        let d = ConfigDiff::between(&a, &external);
        assert_eq!(d.global, vec![GlobalChange::Rpki]);
        // No neighbor is touched.
        assert_eq!(d.unchanged, vec![addr("192.0.2.2"), addr("192.0.2.3")]);
        assert!(d.reset.is_empty() && d.policy_changed.is_empty());
        assert!(!d.is_empty());
        // Spelling out a default, or moving the block, is no change: the
        // running client is left alone.
        for same in [
            "rpki { mode external; cache 192.0.2.10 port 323 preference 0; }",
            "rpki { mode external; version 1; max-expire 172800; cache 192.0.2.10; }",
            "rpki { mode external; backoff 1 600; connect-timeout 10; cache 192.0.2.10; }",
        ] {
            assert!(
                ConfigDiff::between(&external, &with(same)).is_empty(),
                "{same}"
            );
        }
        // Nor is respelling a cache as the parser reads it: the same
        // address, or the same name in another case or with its final dot.
        let named = with("rpki { mode external; cache rtr.example.net; cache 2001:db8::1; }");
        for same in [
            "rpki { mode external; cache RTR.Example.NET; cache 2001:db8::1; }",
            "rpki { mode external; cache rtr.example.net.; cache 2001:0db8:0::1; }",
            "rpki { mode external; cache rtr.example.net port 323; cache 2001:db8::1; }",
        ] {
            assert!(
                ConfigDiff::between(&named, &with(same)).is_empty(),
                "{same}"
            );
        }
        for other in [
            "rpki { mode external; cache rtr.example.org; cache 2001:db8::1; }",
            "rpki { mode external; cache rtr.example.net; cache 2001:db8::2; }",
            "rpki { mode external; cache rtr.example.net port 3323; cache 2001:db8::1; }",
            "rpki { mode external; cache 2001:db8::1; cache rtr.example.net; }",
        ] {
            assert_eq!(
                ConfigDiff::between(&named, &with(other)).global,
                vec![GlobalChange::Rpki],
                "{other}"
            );
        }
        let moved = cfg(&format!(
            "rpki {{ mode external; cache 192.0.2.10; }}\n# moved\n{BASE}"
        ));
        assert!(ConfigDiff::between(&external, &moved).is_empty());
        // No block is `mode disabled`.
        assert!(ConfigDiff::between(&a, &with("rpki { mode disabled; }")).is_empty());
        // Anything else is a change: the mode, a cache, the order of the
        // caches (it breaks ties of preference), a setting.
        for other in [
            "rpki { mode disabled; cache 192.0.2.10; }",
            "rpki { mode external; cache 192.0.2.10 port 3323; }",
            "rpki { mode external; cache 192.0.2.10 preference 1; }",
            "rpki { mode external; cache 192.0.2.10; cache 192.0.2.11; }",
            "rpki { mode external; cache 192.0.2.10; max-vrps 10; }",
        ] {
            assert_eq!(
                ConfigDiff::between(&external, &with(other)).global,
                vec![GlobalChange::Rpki],
                "{other}"
            );
        }
        let two = with("rpki { mode external; cache 192.0.2.10; cache 192.0.2.11; }");
        let swapped = with("rpki { mode external; cache 192.0.2.11; cache 192.0.2.10; }");
        assert_eq!(
            ConfigDiff::between(&two, &swapped).global,
            vec![GlobalChange::Rpki]
        );
    }
}
