//! Prefix matching with length bounds (`docs/config.md`, "Prefix entries").

use std::net::IpAddr;

use bgpfc_config::ast::PrefixEntry;
use bgpfc_wire::prefix::Prefix;

/// A compiled prefix entry: the covering prefix and the allowed length
/// range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixRule {
    prefix: Prefix,
    min_len: u8,
    max_len: u8,
}

impl PrefixRule {
    /// From a config entry: no bounds means the exact length; `le` alone
    /// allows the entry's length up to `le`; `ge` alone allows `ge` up to
    /// the address size.
    #[must_use]
    pub fn new(e: &PrefixEntry) -> PrefixRule {
        let own = e.prefix.prefix_len();
        let max = match e.prefix {
            Prefix::V4 { .. } => 32,
            Prefix::V6 { .. } => 128,
        };
        let (min_len, max_len) = match (e.ge, e.le) {
            (None, None) => (own, own),
            (Some(ge), None) => (ge, max),
            (None, Some(le)) => (own, le),
            (Some(ge), Some(le)) => (ge, le),
        };
        PrefixRule {
            prefix: e.prefix,
            min_len,
            max_len,
        }
    }

    /// Whether `p` lies inside the rule's prefix with an allowed length.
    #[must_use]
    pub fn matches(&self, p: Prefix) -> bool {
        let len = p.prefix_len();
        if len < self.min_len || len > self.max_len || len < self.prefix.prefix_len() {
            return false;
        }
        match (self.prefix.addr(), p.addr()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let bits = self.prefix.prefix_len();
                bits == 0 || (u32::from(a) ^ u32::from(b)) >> (32 - u32::from(bits)) == 0
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let bits = self.prefix.prefix_len();
                bits == 0 || (u128::from(a) ^ u128::from(b)) >> (128 - u32::from(bits)) == 0
            }
            _ => false,
        }
    }
}

/// A compiled prefix list: any rule matching is a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixList {
    rules: Vec<PrefixRule>,
}

impl PrefixList {
    /// Compile the entries.
    #[must_use]
    pub fn new(entries: &[PrefixEntry]) -> PrefixList {
        PrefixList {
            rules: entries.iter().map(PrefixRule::new).collect(),
        }
    }

    /// Whether any entry matches `p`.
    #[must_use]
    pub fn matches(&self, p: Prefix) -> bool {
        self.rules.iter().any(|r| r.matches(p))
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the list has no entries (and so matches nothing).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(s: &str, ge: Option<u8>, le: Option<u8>) -> PrefixEntry {
        PrefixEntry {
            prefix: s.parse().unwrap(),
            ge,
            le,
        }
    }

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn exact_and_bounded_matches() {
        let exact = PrefixRule::new(&entry("10.0.0.0/8", None, None));
        assert!(exact.matches(p("10.0.0.0/8")));
        assert!(!exact.matches(p("10.1.0.0/16")));
        assert!(!exact.matches(p("11.0.0.0/8")));
        let le = PrefixRule::new(&entry("10.0.0.0/8", None, Some(24)));
        assert!(le.matches(p("10.0.0.0/8")));
        assert!(le.matches(p("10.1.2.0/24")));
        assert!(!le.matches(p("10.1.2.0/25")));
        assert!(!le.matches(p("10.0.0.0/7")));
        let ge = PrefixRule::new(&entry("10.0.0.0/8", Some(24), None));
        assert!(!ge.matches(p("10.1.0.0/16")));
        assert!(ge.matches(p("10.1.2.3/32")));
        let both = PrefixRule::new(&entry("2001:db8::/32", Some(48), Some(64)));
        assert!(both.matches(p("2001:db8:1::/48")));
        assert!(both.matches(p("2001:db8:1:2::/64")));
        assert!(!both.matches(p("2001:db8::/32")));
        assert!(!both.matches(p("2001:db9:1::/48")));
        assert!(!both.matches(p("10.0.0.0/8")));
        let any = PrefixRule::new(&entry("0.0.0.0/0", None, Some(32)));
        assert!(any.matches(p("203.0.113.0/24")));
        assert!(!any.matches(p("2001:db8::/32")));
        let any6 = PrefixRule::new(&entry("::/0", Some(0), Some(128)));
        assert!(any6.matches(p("2001:db8::/32")));
    }

    #[test]
    fn list_is_any_of() {
        let list = PrefixList::new(&[
            entry("10.0.0.0/8", None, Some(32)),
            entry("192.168.0.0/16", None, Some(32)),
        ]);
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
        assert!(list.matches(p("192.168.1.0/24")));
        assert!(list.matches(p("10.9.9.9/32")));
        assert!(!list.matches(p("172.16.0.0/12")));
        assert!(PrefixList::new(&[]).is_empty());
    }
}
