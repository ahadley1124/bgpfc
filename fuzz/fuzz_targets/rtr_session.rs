//! Whatever a cache sends, and however the transport and the clock
//! behave, the RTR client session must not panic, must commit only whole
//! replies, and must keep its timers in the future.
//!
//! The input is a script for the I/O shell around a `Session` and a
//! `Framer`. The first octet picks the configuration: bit 0 the version
//! offered (0 or 1), the next bits the configured expiry. Then each
//! command octet `c`, by `c % 8`:
//!
//! - 0: time passes, `next * 7` seconds, and the session ticks;
//! - 1: the transport connects;
//! - 2: the transport drops;
//! - 3 to 7: the next octet gives a length, and that many octets arrive
//!   from the cache, go through the framer, and each PDU it gives out goes
//!   to the session.
//!
//! The shell carries out the actions as `bgpfcd` would: `Negotiated` sets
//! the framer's version, `Close` drops the framer, and every PDU the
//! session sends must encode.
#![no_main]

use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_rpki::VrpSet;
use bgpfc_rtr::session::{Action, Config, Event};
use bgpfc_rtr::{Framer, Pdu, Received, Session, Version};
use libfuzzer_sys::fuzz_target;

/// The shell around a session.
struct Shell {
    session: Session,
    now: Instant,
    /// The framer of the open connection, if one is open.
    framer: Option<Framer>,
    /// What the RIB was last given.
    rib: Option<Arc<VrpSet>>,
    /// The octets of the PDU, or of the PDU in error, being stepped.
    received: Option<Vec<u8>>,
}

impl Shell {
    fn step(&mut self, event: Event<'_>) {
        // Issue #58: only End of Data commits a reply; anything else that
        // commits is a flush, which commits the empty set.
        let end_of_data = matches!(
            event,
            Event::Pdu(Received {
                pdu: Pdu::EndOfData { .. },
                ..
            })
        );
        for action in self.session.step(event, self.now) {
            match action {
                Action::Connect => {}
                Action::Send(pdu) => {
                    let octets = pdu.encode();
                    assert_eq!(Pdu::decode(&octets).as_ref(), Ok(&pdu));
                    // RFC 8210 §5.11: the PDU in error as it arrived.
                    if let Pdu::ErrorReport(report) = &pdu
                        && let Some(received) = &self.received
                    {
                        assert!(received.starts_with(report.erroneous_pdu()));
                    }
                }
                Action::Close => self.framer = None,
                Action::Negotiated(version) => {
                    if let Some(framer) = &mut self.framer {
                        framer.set_version(version);
                    }
                }
                Action::Downgrade(version) => assert_eq!(version, Version::V0),
                Action::Commit(commit) => {
                    assert!(end_of_data || commit.vrps.is_empty());
                    self.rib = Some(commit.vrps);
                }
                Action::Log(line) => line.write(&[]),
                // A shell with one cache stays with it (RFC 8210 §8.3, §8.4).
                Action::Fallback(_) => {}
            }
        }
        assert_eq!(self.session.vrps(), self.rib.as_ref());
        // Every timer due by now has run.
        if let Some(deadline) = self.session.next_deadline() {
            assert!(deadline > self.now);
        }
    }

    fn receive(&mut self, octets: &[u8]) {
        let Some(framer) = &mut self.framer else {
            return;
        };
        framer.feed(octets);
        loop {
            let Some(framer) = &mut self.framer else {
                return;
            };
            match framer.next_received() {
                Ok(Some(Received { pdu, octets })) => {
                    let octets = octets.to_vec();
                    self.received = Some(octets.clone());
                    self.step(Event::Pdu(Received {
                        pdu,
                        octets: &octets,
                    }));
                }
                Ok(None) => return,
                Err(error) => {
                    let erroneous_pdu = framer.erroneous_pdu().to_vec();
                    self.framer = None;
                    self.received = Some(erroneous_pdu.clone());
                    self.step(Event::DecodeError {
                        error,
                        erroneous_pdu: &erroneous_pdu,
                    });
                    self.received = None;
                    return;
                }
            }
            self.received = None;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&setup, mut script)) = data.split_first() else {
        return;
    };
    let config = Config {
        version: if setup & 1 == 0 {
            Version::V1
        } else {
            Version::V0
        },
        max_expire: Duration::from_secs(u64::from(setup >> 1) * 1_500),
        ..Config::default()
    };
    let now = Instant::now();
    let mut shell = Shell {
        session: Session::new(config, now),
        now,
        framer: None,
        rib: None,
        received: None,
    };
    shell.step(Event::Tick);
    while let Some((&command, rest)) = script.split_first() {
        script = rest;
        match command % 8 {
            0 => {
                let secs = script.first().map_or(0, |&n| u64::from(n) * 7);
                script = script.get(1..).unwrap_or_default();
                shell.now += Duration::from_secs(secs);
                shell.step(Event::Tick);
            }
            1 => {
                shell.framer = Some(Framer::new());
                shell.step(Event::Connected);
            }
            2 => {
                shell.framer = None;
                shell.step(Event::Disconnected);
            }
            _ => {
                let len = script.first().map_or(0, |&n| usize::from(n));
                let rest = script.get(1..).unwrap_or_default();
                let (octets, after) = rest.split_at(len.min(rest.len()));
                script = after;
                shell.receive(octets);
            }
        }
    }
});
