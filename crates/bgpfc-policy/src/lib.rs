//! Routing policy (AGENTS.md §3, "Policy"): the AS-path regex engine and
//! prefix-list matching; term evaluation follows.
//!
//! Implements: `docs/config.md`, "Prefix entries" and "AS-path regular
//! expressions".
#![forbid(unsafe_code)]

pub mod prefix_list;
pub mod regex;

pub use prefix_list::{PrefixList, PrefixRule};
pub use regex::{AsPathRegex, RegexError};
