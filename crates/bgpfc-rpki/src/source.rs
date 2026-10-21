//! Where the RIB gets validation verdicts from, and how whoever produces
//! them tells the RIB that they changed.
//!
//! The RIB owner thread holds the current source as
//! `Arc<dyn ValidationSource>` and asks it for the state of each route.
//! A producer, such as the RTR client thread, builds a new source and
//! sends it through a [`ValidationSink`] as a [`ValidationChange`]; the
//! RIB swaps it in and validates again only the routes the change
//! affects.
//!
//! Implements: RFC 6811 §2 (each route gets a validation state from a
//! lookup), §4 ("When a mapping is added or deleted, the implementation
//! MUST re-validate any affected prefixes and run the BGP decision process
//! if needed").

use std::fmt;
use std::sync::Arc;
use std::sync::mpsc::{Sender, SyncSender};

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::prefix::Prefix;

use crate::RpkiError;
use crate::affected::AffectedPrefixes;
use crate::origin::RouteOrigin;
use crate::set::VrpSet;
use crate::state::{AspaState, RovState};

/// A source of validation verdicts for routes (issue #56).
///
/// The trait says nothing about where verdicts come from. An RTR client
/// (RFC 8210) publishes [`VrpSet`] snapshots, [`NullSource`] stands for
/// validation turned off, and an in-process validator could implement it
/// as well. Verdicts are queried once per route on import and again on
/// every re-validation, so they must be cheap.
pub trait ValidationSource: Send + Sync {
    /// The route origin validation state of a route for `prefix` whose
    /// Route Origin ASN is `origin` (RFC 6811 §2; see
    /// [`RouteOrigin::from_as_path`]).
    fn rov(&self, prefix: Prefix, origin: RouteOrigin) -> RovState;

    /// The ASPA verdict for a route with `path`. ASPA is planned for
    /// v1.1.0; a source that does not implement it returns
    /// [`AspaState::Disabled`].
    fn aspa(&self, path: &AsPath) -> AspaState {
        let _ = path;
        AspaState::Disabled
    }
}

/// Validation turned off: every verdict is `Disabled`.
///
/// No thread, no socket, no data. This is the source the RIB uses when
/// RPKI is not configured, a normal state of the daemon and not an error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NullSource;

impl ValidationSource for NullSource {
    fn rov(&self, _prefix: Prefix, _origin: RouteOrigin) -> RovState {
        RovState::Disabled
    }

    fn aspa(&self, _path: &AsPath) -> AspaState {
        AspaState::Disabled
    }
}

/// A set of VRPs judges route origins (RFC 6811 §2) and nothing else: its
/// ASPA verdict is `Disabled`.
impl ValidationSource for VrpSet {
    fn rov(&self, prefix: Prefix, origin: RouteOrigin) -> RovState {
        self.validate(prefix, origin)
    }
}

/// A new validation source and the routes it may judge differently from
/// the source before it. A producer hands this to the RIB owner thread.
///
/// The consumer replaces its source with `source`, validates again every
/// route `affected` covers, and runs the decision process for those whose
/// state changed (RFC 6811 §4). Each change is relative to the one before
/// it, so changes must be applied in order. A consumer that has fallen
/// behind may apply a run of changes at once: the last `source`, and the
/// [`AffectedPrefixes::merge`] of every `affected`.
///
/// A producer must use [`AffectedPrefixes::All`] when the new source
/// judges by different rules from the old one, for example when switching
/// between [`NullSource`] and a [`VrpSet`].
#[derive(Clone)]
pub struct ValidationChange {
    /// The source to use from now on.
    pub source: Arc<dyn ValidationSource>,
    /// The routes whose verdict may differ from the previous source's.
    pub affected: AffectedPrefixes,
}

impl ValidationChange {
    /// Switch validation off: [`NullSource`], and every route affected.
    #[must_use]
    pub fn disabled() -> ValidationChange {
        ValidationChange {
            source: Arc::new(NullSource),
            affected: AffectedPrefixes::All,
        }
    }
}

impl fmt::Debug for ValidationChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidationChange")
            .field("affected", &self.affected)
            .finish_non_exhaustive()
    }
}

/// The producer's end of a subscription to validation changes.
///
/// A producer, such as the RTR client thread, is given a sink and calls
/// [`ValidationSink::publish`] once per change, in order. What is behind
/// the sink is the daemon's business; typically a closure that wraps the
/// change in a RIB channel message and sends it on a bounded channel, so
/// that `publish` blocks while the RIB thread is busy (backpressure,
/// AGENTS.md §3).
///
/// Implemented for closures `FnMut(ValidationChange) -> Result<(),
/// RpkiError>` and for both kinds of `mpsc` sender. A producer that wants
/// to store any of them holds a `Box<dyn ValidationSink>`.
pub trait ValidationSink: Send {
    /// Hand `change` to the consumer. May block.
    ///
    /// # Errors
    /// [`RpkiError::SinkClosed`] when the consumer has gone away; the
    /// producer should stop.
    fn publish(&mut self, change: ValidationChange) -> Result<(), RpkiError>;
}

impl<F> ValidationSink for F
where
    F: FnMut(ValidationChange) -> Result<(), RpkiError> + Send,
{
    fn publish(&mut self, change: ValidationChange) -> Result<(), RpkiError> {
        self(change)
    }
}

impl ValidationSink for Sender<ValidationChange> {
    fn publish(&mut self, change: ValidationChange) -> Result<(), RpkiError> {
        self.send(change).map_err(|_| RpkiError::SinkClosed)
    }
}

impl ValidationSink for SyncSender<ValidationChange> {
    fn publish(&mut self, change: ValidationChange) -> Result<(), RpkiError> {
        self.send(change).map_err(|_| RpkiError::SinkClosed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;

    use bgpfc_wire::as_path::{AsPathSegment, SegmentType};
    use bgpfc_wire::types::Asn;

    use super::*;
    use crate::vrp::Vrp;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(p(prefix), max_len, Asn(asn)).unwrap()
    }

    fn paths() -> Vec<AsPath> {
        vec![
            AsPath::empty(),
            AsPath::sequence(&[Asn(64_496), Asn(64_497)]),
            AsPath {
                segments: vec![AsPathSegment {
                    kind: SegmentType::Set,
                    asns: vec![Asn(64_496)],
                }],
            },
            AsPath {
                segments: vec![AsPathSegment {
                    kind: SegmentType::ConfedSequence,
                    asns: vec![Asn(65_100)],
                }],
            },
        ]
    }

    fn assert_send_sync<T: Send + Sync + ?Sized>() {}

    fn assert_send<T: Send + ?Sized>() {}

    #[test]
    fn sources_and_changes_cross_threads() {
        assert_send_sync::<NullSource>();
        assert_send_sync::<VrpSet>();
        assert_send_sync::<dyn ValidationSource>();
        assert_send_sync::<ValidationChange>();
        assert_send_sync::<AffectedPrefixes>();
        assert_send::<dyn ValidationSink>();
    }

    #[test]
    fn null_source_disables_everything() {
        let source: Arc<dyn ValidationSource> = Arc::new(NullSource);
        let origins = [
            RouteOrigin::None,
            RouteOrigin::As(Asn(0)),
            RouteOrigin::As(Asn(64_496)),
            RouteOrigin::As(Asn(4_200_000_000)),
        ];
        for prefix in [
            "0.0.0.0/0",
            "192.0.2.0/24",
            "192.0.2.1/32",
            "::/0",
            "2001:db8::/32",
            "2001:db8::1/128",
        ] {
            for origin in origins {
                assert_eq!(source.rov(p(prefix), origin), RovState::Disabled);
                assert_eq!(NullSource.rov(p(prefix), origin), RovState::Disabled);
            }
        }
        for path in paths() {
            assert_eq!(source.aspa(&path), AspaState::Disabled);
        }
        // Disabled is not NotFound (issue #52), even for the null source.
        assert_ne!(
            NullSource.rov(p("192.0.2.0/24"), RouteOrigin::None),
            RovState::NotFound
        );
    }

    #[test]
    fn vrp_set_as_a_source() {
        let set: VrpSet = [vrp("192.0.2.0/24", 24, 64_496)].into_iter().collect();
        let source: Arc<dyn ValidationSource> = Arc::new(set.clone());
        let by = |a| RouteOrigin::As(Asn(a));
        for (prefix, origin) in [
            ("192.0.2.0/24", by(64_496)),
            ("192.0.2.0/24", by(64_497)),
            ("192.0.2.0/25", by(64_496)),
            ("198.51.100.0/24", by(64_496)),
            ("192.0.2.0/24", RouteOrigin::None),
        ] {
            assert_eq!(
                source.rov(p(prefix), origin),
                set.validate(p(prefix), origin)
            );
        }
        assert_eq!(source.rov(p("192.0.2.0/24"), by(64_496)), RovState::Valid);
        for path in paths() {
            assert_eq!(source.aspa(&path), AspaState::Disabled);
        }
    }

    #[test]
    fn disabled_change() {
        let change = ValidationChange::disabled();
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(
            change.source.rov(p("192.0.2.0/24"), RouteOrigin::None),
            RovState::Disabled
        );
        let text = format!("{change:?}");
        assert!(
            text.starts_with("ValidationChange { affected: All"),
            "{text}"
        );
    }

    #[test]
    fn closure_sink() {
        let mut seen = Vec::new();
        {
            let mut sink = |change: ValidationChange| {
                seen.push(change.affected);
                Ok::<(), RpkiError>(())
            };
            sink.publish(ValidationChange::disabled()).unwrap();
            sink.publish(ValidationChange {
                source: Arc::new(VrpSet::new()),
                affected: AffectedPrefixes::none(),
            })
            .unwrap();
        }
        assert_eq!(seen, [AffectedPrefixes::All, AffectedPrefixes::none()]);

        let mut closed = |_: ValidationChange| Err::<(), _>(RpkiError::SinkClosed);
        assert_eq!(
            closed.publish(ValidationChange::disabled()).unwrap_err(),
            RpkiError::SinkClosed
        );
    }

    #[test]
    fn channel_sinks_deliver_in_order_across_threads() {
        let (tx, rx) = mpsc::channel();
        let mut sink: Box<dyn ValidationSink> = Box::new(tx);
        let producer = thread::spawn(move || {
            let set: VrpSet = [vrp("192.0.2.0/24", 24, 64_496)].into_iter().collect();
            sink.publish(ValidationChange {
                source: Arc::new(set),
                affected: AffectedPrefixes::All,
            })?;
            sink.publish(ValidationChange::disabled())
        });
        let first = rx.recv().unwrap();
        let second = rx.recv().unwrap();
        producer.join().unwrap().unwrap();
        let route = p("192.0.2.0/24");
        let origin = RouteOrigin::As(Asn(64_496));
        assert_eq!(first.source.rov(route, origin), RovState::Valid);
        assert_eq!(second.source.rov(route, origin), RovState::Disabled);

        // A bounded channel blocks the producer instead of queueing more.
        let (tx, rx) = mpsc::sync_channel(1);
        let mut sink = tx;
        sink.publish(ValidationChange::disabled()).unwrap();
        let producer = thread::spawn(move || sink.publish(ValidationChange::disabled()));
        assert_eq!(rx.recv().unwrap().affected, AffectedPrefixes::All);
        assert_eq!(rx.recv().unwrap().affected, AffectedPrefixes::All);
        producer.join().unwrap().unwrap();
    }

    #[test]
    fn a_gone_consumer_closes_the_sink() {
        let (tx, rx) = mpsc::channel();
        drop(rx);
        let mut sink = tx;
        assert_eq!(
            sink.publish(ValidationChange::disabled()),
            Err(RpkiError::SinkClosed)
        );
        let (tx, rx) = mpsc::sync_channel(4);
        drop(rx);
        let mut sink = tx;
        assert_eq!(
            sink.publish(ValidationChange::disabled()),
            Err(RpkiError::SinkClosed)
        );
        assert_eq!(
            RpkiError::SinkClosed.to_string(),
            "the consumer of validation changes has gone away"
        );
    }
}
