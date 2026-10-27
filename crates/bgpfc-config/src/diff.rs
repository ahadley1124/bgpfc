//! What changed between two configurations, so a reload can apply only
//! that (AGENTS.md §3, "Config": reset only the sessions whose session
//! parameters changed; policy-only changes re-evaluate routes).

use std::net::IpAddr;

use crate::ast::Config;

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
    /// anything those policies reference) changed: the union of
    /// `import_changed` and `export_changed`, in file order.
    pub policy_changed: Vec<IpAddr>,
    /// Those of `policy_changed` whose import policy changed: the routes
    /// they sent are put through it again, from the Adj-RIB-In (RFC 4271
    /// §3: "retain the current version of the routes advertised to it"),
    /// with route refresh (RFC 2918) only for the families of what it did
    /// not keep.
    pub import_changed: Vec<IpAddr>,
    /// Those of `policy_changed` whose export policy changed: what they
    /// are sent is exported again from the Loc-RIB, with no route
    /// refresh.
    pub export_changed: Vec<IpAddr>,
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
    /// The `netns` statement: the network namespace bgpfcd joined at
    /// startup, whose sockets it holds, so the change waits for the next
    /// restart.
    Netns,
    /// The `rpki` block's mode, or the RTR client's or the sidecar's
    /// settings, an absent block counting as
    /// [`Rpki::implicit`](crate::ast::Rpki::implicit): the RTR client
    /// starts, stops or restarts, and with `mode sidecar` the sidecar too
    /// when its own settings changed. A block that only spells something
    /// differently, such as a default written out, a cache's host or a
    /// moved `sidecar` block, is no change, and nor are its `enforcement`,
    /// its `startup` and its `tcp-keepalive`, which neither uses as a
    /// setting of its own (see [`Rpki::same_as`](crate::ast::Rpki::same_as));
    /// those are [`GlobalChange::RpkiEnforcement`],
    /// [`GlobalChange::RpkiStartup`] and [`GlobalChange::RpkiKeepalive`].
    Rpki,
    /// The `rpki` block's `enforcement`, an absent block or statement
    /// counting as the default: every route is judged again under the new
    /// mode (RFC 6811 §5), with no restart of the RTR client. It may come
    /// with [`GlobalChange::Rpki`] in one reload.
    RpkiEnforcement,
    /// The `rpki` block's `startup`, an absent block or statement counting
    /// as the default: the routes not validated yet are held or used as
    /// it now says (RFC 6811 §2), with no restart of the RTR client. It
    /// acts only while validation waits for its first full set, and never
    /// with `mode disabled`. It may come with the other two in one reload.
    RpkiStartup,
    /// The `rpki` block's `tcp-keepalive`, an absent block or statement
    /// counting as the defaults: the RTR client's connection in use gets
    /// the new values at once, and so does every later one, with no new
    /// connection and no restart of the client (RFC 8210 §9). It may come
    /// with the others in one reload.
    RpkiKeepalive,
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
            (old.netns != new.netns, GlobalChange::Netns),
            (!old.rpki.same_as(&new.rpki), GlobalChange::Rpki),
            (
                old.rpki.enforcement != new.rpki.enforcement,
                GlobalChange::RpkiEnforcement,
            ),
            (
                old.rpki.startup != new.rpki.startup,
                GlobalChange::RpkiStartup,
            ),
            (
                old.rpki.tcp_keepalive != new.rpki.tcp_keepalive,
                GlobalChange::RpkiKeepalive,
            ),
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
            let import = policy_differs(old, &o.import, new, &n.import);
            let export = policy_differs(old, &o.export, new, &n.export);
            let policy = import || export;
            let interval = o.advertisement_interval != n.advertisement_interval;
            let limit = o.maximum_prefix != n.maximum_prefix;
            if policy {
                d.policy_changed.push(n.addr);
            }
            if import {
                d.import_changed.push(n.addr);
            }
            if export {
                d.export_changed.push(n.addr);
            }
            if interval {
                d.interval_changed.push(n.addr);
            }
            if limit {
                d.prefix_limit_changed.push(n.addr);
            }
            if !policy && !interval && !limit {
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
            && self.global.is_empty()
    }
}

/// Whether the policy a neighbor names `o` in `old` and `n` in `new`, its
/// import or its export policy, differs between the configurations,
/// prefix lists it uses included.
fn policy_differs(old: &Config, o: &str, new: &Config, n: &str) -> bool {
    policy_fingerprint(old, o) != policy_fingerprint(new, n)
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
    use std::time::Duration;

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
        assert_eq!(d.import_changed, vec![addr("192.0.2.3")]);
        assert_eq!(d.export_changed, Vec::<IpAddr>::new());
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
        // So is a term on the validation state (RFC 6811 §3), and a change
        // of the state it matches or sets.
        let rpki = |m: &str, s: &str| {
            cfg(&BASE.replace(
                "term r { action accept; }",
                &format!("term r {{ match rpki {m}; set rpki {s}; action accept; }}"),
            ))
        };
        let valid = rpki("invalid", "valid");
        assert_eq!(
            ConfigDiff::between(a, &valid).policy_changed,
            vec![addr("192.0.2.2"), addr("192.0.2.3")]
        );
        for other in [rpki("not-found", "valid"), rpki("invalid", "not-found")] {
            assert_eq!(
                ConfigDiff::between(&valid, &other).policy_changed,
                vec![addr("192.0.2.2"), addr("192.0.2.3")]
            );
        }
        assert!(ConfigDiff::between(&valid, &rpki("invalid", "valid")).is_empty());
    }

    #[test]
    fn import_and_export_changes_are_told_apart() {
        // A reload imports again only for the neighbors whose import
        // policy changed, and exports again only to those whose export
        // policy changed (RFC 4271 §3, RFC 2918): a change of one is not
        // a change of the other.
        let a = cfg(BASE);
        let both = |d: &ConfigDiff| {
            (
                d.policy_changed.clone(),
                d.import_changed.clone(),
                d.export_changed.clone(),
            )
        };
        let none = Vec::<IpAddr>::new();
        let n2 = addr("192.0.2.2");
        let n3 = addr("192.0.2.3");
        // The export policy's terms: every neighbor exports with it.
        let export = cfg(&BASE.replace(
            "policy OUT { term all { action accept; } }",
            "policy OUT { term all { set med 5; action accept; } }",
        ));
        assert_eq!(
            both(&ConfigDiff::between(&a, &export)),
            (vec![n2, n3], none.clone(), vec![n2, n3])
        );
        // The prefix list only the import policy uses.
        let list = cfg(&BASE.replace("le 24", "le 32"));
        assert_eq!(
            both(&ConfigDiff::between(&a, &list)),
            (vec![n2, n3], vec![n2, n3], none.clone())
        );
        // One neighbor's export policy named anew.
        let renamed = cfg(&BASE.replace(
            "remote-as 65002; import IN; export OUT;",
            "remote-as 65002; import IN; export IN;",
        ));
        assert_eq!(
            both(&ConfigDiff::between(&a, &renamed)),
            (vec![n3], none.clone(), vec![n3])
        );
        // A policy both use, for one neighbor: both change.
        let shared = cfg(&BASE
            .replace(
                "remote-as 65002; import IN; export OUT;",
                "remote-as 65002; import OUT; export OUT;",
            )
            .replace(
                "policy OUT { term all { action accept; } }",
                "policy OUT { term all { set med 5; action accept; } }",
            ));
        assert_eq!(
            both(&ConfigDiff::between(&a, &shared)),
            (vec![n2, n3], vec![n3], vec![n2, n3])
        );
        // A reset neighbor is in neither: its session starts again.
        let reset = cfg(&BASE
            .replace("le 24", "le 32")
            .replace("remote-as 65002;", "remote-as 65002; hold-time 30;"));
        let d = ConfigDiff::between(&a, &reset);
        assert_eq!(d.reset, vec![n3]);
        assert_eq!(both(&d), (vec![n2], vec![n2], none));
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

    /// A name and the path it stands for are the same namespace; adding,
    /// changing or removing the statement is a change.
    #[test]
    fn netns_changes_are_a_global_change() {
        let a = cfg(BASE);
        let blue = cfg(&format!("{BASE} netns blue;"));
        let path = cfg(&format!("{BASE} netns /run/netns/blue;"));
        let red = cfg(&format!("{BASE} netns red;"));
        assert!(ConfigDiff::between(&blue, &path).is_empty());
        for (old, new) in [(&a, &blue), (&blue, &red), (&path, &a)] {
            let d = ConfigDiff::between(old, new);
            assert_eq!(d.global, vec![GlobalChange::Netns]);
            // No session resets for it.
            assert!(d.reset.is_empty(), "{d:?}");
        }
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

    #[test]
    fn an_enforcement_change_is_not_an_rpki_client_change() {
        let with = |block: &str| cfg(&format!("{BASE} {block}"));
        let modes = ["drop-invalid", "prefer-valid", "off"];
        for from in modes {
            for to in modes {
                let a = with(&format!(
                    "rpki {{ mode external; enforcement {from}; cache 192.0.2.10; }}"
                ));
                let b = with(&format!(
                    "rpki {{ mode external; enforcement {to}; cache 192.0.2.10; }}"
                ));
                // The client keeps its sessions and its VRPs; the routes
                // are judged again under the new mode, and that is all.
                assert!(a.rpki.same_as(&b.rpki), "{from} -> {to}");
                let d = ConfigDiff::between(&a, &b);
                let expected = if from == to {
                    vec![]
                } else {
                    vec![GlobalChange::RpkiEnforcement]
                };
                assert_eq!(d.global, expected, "{from} -> {to}");
                assert_eq!(d.is_empty(), from == to);
                assert_eq!(a.rpki == b.rpki, from == to);
                // No neighbor is touched either.
                assert_eq!(d.unchanged, vec![addr("192.0.2.2"), addr("192.0.2.3")]);
            }
        }
        // With another change to the block, it is one client change, and
        // the enforcement change beside it.
        let a = with("rpki { mode external; enforcement off; cache 192.0.2.10; }");
        let b = with("rpki { mode external; cache 192.0.2.11; }");
        assert_eq!(
            ConfigDiff::between(&a, &b).global,
            vec![GlobalChange::Rpki, GlobalChange::RpkiEnforcement]
        );
        let c = with("rpki { mode external; enforcement off; cache 192.0.2.11; }");
        assert_eq!(ConfigDiff::between(&a, &c).global, vec![GlobalChange::Rpki]);
    }

    #[test]
    fn sidecar_settings_are_an_rpki_change() {
        let with = |block: &str| cfg(&format!("{BASE} {block}"));
        let sidecar = with("rpki { mode sidecar; }");
        for other in [
            "rpki { mode sidecar; sidecar { refresh 300; } }",
            "rpki { mode sidecar; sidecar { binary /opt/routinator/bin/routinator; } }",
            "rpki { mode sidecar; sidecar { rtr-listen 127.0.0.1 port 3323; } }",
            "rpki { mode sidecar; sidecar { global-args --strict; } }",
            "rpki { mode sidecar; sidecar { server-args --rtr-tcp-keepalive=30; } }",
            "rpki { mode sidecar; sidecar { restart-backoff 1 60; } }",
            "rpki { mode sidecar; sidecar { failure-threshold 3; } }",
            // A client setting: the client restarts, the sidecar does not
            // (the reload tells them apart by `RpkiSidecar::same_as`).
            "rpki { mode sidecar; max-vrps 10; }",
            // The modes on either side.
            "rpki { mode external; cache 127.0.0.1; }",
            "rpki { mode disabled; }",
        ] {
            let d = ConfigDiff::between(&sidecar, &with(other));
            assert_eq!(d.global, vec![GlobalChange::Rpki], "{other}");
            // No neighbor is touched.
            assert_eq!(d.unchanged, vec![addr("192.0.2.2"), addr("192.0.2.3")]);
        }
        // The enforcement alone neither restarts the sidecar nor the
        // client.
        let off = with("rpki { mode sidecar; enforcement off; }");
        assert!(sidecar.rpki.same_as(&off.rpki));
        assert_eq!(
            ConfigDiff::between(&sidecar, &off).global,
            vec![GlobalChange::RpkiEnforcement]
        );
        // Two words in another order are other arguments.
        assert_eq!(
            ConfigDiff::between(
                &with("rpki { mode sidecar; sidecar { global-args --strict -v; } }"),
                &with("rpki { mode sidecar; sidecar { global-args -v --strict; } }"),
            )
            .global,
            vec![GlobalChange::Rpki]
        );
    }

    #[test]
    fn a_respelled_or_moved_sidecar_block_is_no_change() {
        let with = |block: &str| cfg(&format!("{BASE} {block}"));
        let sidecar = with("rpki { mode sidecar; }");
        for same in [
            "rpki { mode sidecar; sidecar { } }",
            "rpki { mode sidecar; sidecar { rtr-listen 127.0.0.1 port 0; } }",
            "rpki { mode sidecar; sidecar { rtr-listen 127.0.0.1; } }",
            "rpki { mode sidecar; backoff 1 30; }",
            "rpki {
                mode sidecar;
                sidecar {
                    binary /usr/bin/routinator;
                    repository-dir /var/lib/bgpfc/rpki;
                    rir-tals yes;
                    accept-arin-rpa no;
                    refresh 600;
                    restart-backoff 1 300;
                    stable-after 300;
                    stop-timeout 10;
                    failure-threshold 5;
                }
            }",
        ] {
            let other = with(same);
            assert!(sidecar.rpki.same_as(&other.rpki), "{same}");
            assert!(ConfigDiff::between(&sidecar, &other).is_empty(), "{same}");
        }
        // The block before or after the mode, or the whole `rpki` block
        // elsewhere in the file: only the positions differ.
        let a = with("rpki { mode sidecar; sidecar { refresh 300; } }");
        let b = with("rpki { sidecar { refresh 300; } mode sidecar; }");
        let moved = cfg(&format!(
            "rpki {{\n  mode sidecar;\n  sidecar {{ refresh 300; }}\n}}\n{BASE}"
        ));
        for other in [&b, &moved] {
            assert_ne!(a.rpki.sidecar.pos, other.rpki.sidecar.pos);
            assert!(ConfigDiff::between(&a, other).is_empty());
        }
    }

    #[test]
    fn the_sidecar_backoff_default_follows_the_mode() {
        let with = |block: &str| cfg(&format!("{BASE} {block}"));
        let external = with("rpki { mode external; cache 127.0.0.1; }");
        let sidecar = with("rpki { mode sidecar; }");
        assert_eq!(external.rpki.backoff_max, Duration::from_secs(600));
        assert_eq!(sidecar.rpki.backoff_max, Duration::from_secs(30));
        assert_eq!(external.rpki.backoff_min, sidecar.rpki.backoff_min);
        assert_eq!(
            ConfigDiff::between(&external, &sidecar).global,
            vec![GlobalChange::Rpki]
        );
        // A `backoff` written out applies in every mode.
        let written = with("rpki { mode sidecar; backoff 1 600; }");
        assert_eq!(written.rpki.backoff_max, Duration::from_secs(600));
        assert!(!sidecar.rpki.same_as(&written.rpki));
    }

    #[test]
    fn a_startup_change_is_not_an_rpki_client_change() {
        let with = |block: &str| cfg(&format!("{BASE} {block}"));
        for mode in [
            "mode external; cache 192.0.2.10;",
            "mode sidecar;",
            "mode disabled;",
        ] {
            let implied = with(&format!("rpki {{ {mode} }}"));
            let accept = with(&format!("rpki {{ {mode} startup accept; }}"));
            let hold = with(&format!("rpki {{ {mode} startup hold; }}"));
            // The default written out is no change at all.
            assert_eq!(implied.rpki, accept.rpki, "{mode}");
            assert!(ConfigDiff::between(&implied, &accept).is_empty(), "{mode}");
            // The client keeps its sessions and its VRPs; the routes not
            // validated yet are held or used, and no neighbor is touched.
            for (a, b) in [(&accept, &hold), (&hold, &accept)] {
                assert!(a.rpki.same_as(&b.rpki), "{mode}");
                let d = ConfigDiff::between(a, b);
                assert_eq!(d.global, vec![GlobalChange::RpkiStartup], "{mode}");
                assert_eq!(d.unchanged, vec![addr("192.0.2.2"), addr("192.0.2.3")]);
            }
        }
        // With the other changes of the block, each is named.
        let a = with("rpki { mode external; cache 192.0.2.10; }");
        let b = with("rpki { mode external; enforcement off; startup hold; cache 192.0.2.11; }");
        assert_eq!(
            ConfigDiff::between(&a, &b).global,
            vec![
                GlobalChange::Rpki,
                GlobalChange::RpkiEnforcement,
                GlobalChange::RpkiStartup
            ]
        );
    }

    #[test]
    fn a_keepalive_change_is_not_an_rpki_client_change() {
        let with = |block: &str| cfg(&format!("{BASE} {block}"));
        for mode in [
            "mode external; cache 192.0.2.10;",
            "mode sidecar;",
            "mode disabled;",
        ] {
            let implied = with(&format!("rpki {{ {mode} }}"));
            let written = with(&format!(
                "rpki {{ {mode} tcp-keepalive count 6 interval 10 idle 60; }}"
            ));
            let partly = with(&format!("rpki {{ {mode} tcp-keepalive idle 60; }}"));
            // The defaults written out, whole or in part, are no change.
            assert_eq!(implied.rpki, written.rpki, "{mode}");
            assert!(ConfigDiff::between(&implied, &written).is_empty(), "{mode}");
            assert!(ConfigDiff::between(&implied, &partly).is_empty(), "{mode}");
            // Any one value is one, which keeps the client and touches no
            // neighbor.
            for other in ["idle 61", "interval 5", "count 3"] {
                let changed = with(&format!("rpki {{ {mode} tcp-keepalive {other}; }}"));
                for (a, b) in [(&implied, &changed), (&changed, &implied)] {
                    assert!(a.rpki.same_as(&b.rpki), "{mode} {other}");
                    let d = ConfigDiff::between(a, b);
                    assert_eq!(d.global, vec![GlobalChange::RpkiKeepalive], "{mode}");
                    assert_eq!(d.unchanged, vec![addr("192.0.2.2"), addr("192.0.2.3")]);
                }
            }
        }
        // With the other changes of the block, each is named.
        let a = with("rpki { mode external; cache 192.0.2.10; }");
        let b = with(
            "rpki { mode external; enforcement off; startup hold; cache 192.0.2.11;
             tcp-keepalive count 3; }",
        );
        assert_eq!(
            ConfigDiff::between(&a, &b).global,
            vec![
                GlobalChange::Rpki,
                GlobalChange::RpkiEnforcement,
                GlobalChange::RpkiStartup,
                GlobalChange::RpkiKeepalive
            ]
        );
    }

    #[test]
    fn writing_the_default_enforcement_is_no_change() {
        let with = |block: &str| cfg(&format!("{BASE} {block}"));
        let implied = with("rpki { mode external; cache 192.0.2.10; }");
        let written = with("rpki { mode external; enforcement drop-invalid; cache 192.0.2.10; }");
        assert_eq!(
            implied.rpki.enforcement,
            crate::ast::Rpki::DEFAULT_ENFORCEMENT
        );
        assert_eq!(implied.rpki, written.rpki);
        assert!(ConfigDiff::between(&implied, &written).is_empty());
        // No block at all has the default too, and `mode disabled` with it
        // written out is the same.
        let none = cfg(BASE);
        let disabled = with("rpki { mode disabled; enforcement drop-invalid; }");
        assert_eq!(none.rpki, disabled.rpki);
        assert!(ConfigDiff::between(&none, &disabled).is_empty());
        // Another mode written there is an enforcement change, which a
        // state import policy sets can feel, and still no client change.
        let off = with("rpki { mode disabled; enforcement off; }");
        assert_eq!(
            ConfigDiff::between(&none, &off).global,
            vec![GlobalChange::RpkiEnforcement]
        );
        assert_eq!(
            ConfigDiff::between(&off, &implied).global,
            vec![GlobalChange::Rpki, GlobalChange::RpkiEnforcement]
        );
    }
}
