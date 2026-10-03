//! BGP-4 session state machine. Pure: `(State, Event, Instant) -> (State, Vec<Action>)`.
//!
//! Implements: RFC 4271 §8 (nothing yet).
#![forbid(unsafe_code)]
