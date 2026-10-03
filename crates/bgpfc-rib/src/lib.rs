//! Adj-RIB-In, Loc-RIB, Adj-RIB-Out and the decision process
//! (AGENTS.md §3, "RIB thread").
//!
//! Implements: RFC 4271 §9.1.1 (degree of preference), §9.1.2 and
//! §9.1.2.2 (route selection and tie-breaking); RFC 4271 §5 and RFC 4760
//! §3 (attribute sets with the family's next hop).
#![forbid(unsafe_code)]

pub mod attrs;
pub mod decision;
pub mod peer;
#[cfg(test)]
mod tests;

pub use attrs::{Interner, PathAttrs};
pub use decision::Candidate;
pub use peer::PeerInfo;
