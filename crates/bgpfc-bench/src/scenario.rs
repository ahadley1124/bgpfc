//! What the load generator does once a session is up.
//!
//! Every scenario starts by sending the whole table followed by an
//! End-of-RIB marker per family (RFC 4724 §2), which ends the daemon's
//! table-load measurement. What follows depends on the scenario:
//!
//! - `load`: nothing; the session is held.
//! - `churn`: random announcements, withdrawals and re-announcements with
//!   new attributes at a fixed rate, then an End-of-RIB as a sync point.
//! - `withdraw-all`: every route withdrawn, then an End-of-RIB.
//! - `flap`: Cease, a pause, a new session and the whole table again,
//!   `cycles` times.
//!
//! Progress is printed as `loadgen key=value ...` lines.

use std::fmt;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_prof::Line;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn};

use crate::mrt::PeerRoutes;
use crate::pack::{PackError, Packer};
use crate::rng::Rng;
use crate::speaker::{Endpoint, Negotiated, Session, SessionError, SpeakerOpts};
use crate::synth::{SynthOpts, generate};
use crate::table::{Table, family_of};

/// What to do after the table is sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scenario {
    /// Hold the session.
    Load,
    /// `rate` UPDATEs a second for `duration`.
    Churn {
        /// UPDATE messages per second.
        rate: u64,
        /// How long.
        duration: Duration,
    },
    /// Withdraw every route.
    WithdrawAll,
    /// Reset and reload the session `cycles` times.
    Flap {
        /// How many resets.
        cycles: u32,
        /// Pause between the Cease and the new connection.
        gap: Duration,
    },
}

impl Scenario {
    /// The name on the command line and in results.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Scenario::Load => "load",
            Scenario::Churn { .. } => "churn",
            Scenario::WithdrawAll => "withdraw-all",
            Scenario::Flap { .. } => "flap",
        }
    }
}

/// Where the routes come from.
#[derive(Clone, Debug)]
pub enum Source {
    /// A generated IPv4 table ([`crate::synth`]).
    Synthetic {
        /// Number of prefixes.
        prefixes: usize,
        /// Number of attribute sets.
        attr_sets: usize,
        /// PRNG seed.
        seed: u64,
        /// Next hops to draw from.
        next_hops: Vec<Ipv4Addr>,
    },
    /// One peer's routes from an MRT file ([`crate::mrt`]).
    Mrt(PeerRoutes),
}

impl Source {
    /// The families the routes will need.
    #[must_use]
    pub fn families(&self) -> Vec<AddressFamily> {
        match self {
            Source::Synthetic { .. } => vec![AddressFamily::IPV4_UNICAST],
            Source::Mrt(r) => r.families(),
        }
    }

    /// The table to send on a session that negotiated `n`, from `local_as`.
    #[must_use]
    pub fn table(&self, local_as: Asn, n: &Negotiated) -> Table {
        match self {
            Source::Synthetic {
                prefixes,
                attr_sets,
                seed,
                next_hops,
            } => generate(&SynthOpts {
                prefixes: *prefixes,
                attr_sets: *attr_sets,
                seed: *seed,
                local_as,
                peer_as: n.peer_as,
                internal: n.peer_as == local_as,
                next_hops: next_hops.clone(),
            }),
            Source::Mrt(r) => r.table(local_as, n.peer_as),
        }
    }
}

/// A complete run.
#[derive(Debug)]
pub struct Plan {
    /// Connect or listen.
    pub endpoint: Endpoint,
    /// Our OPEN.
    pub speaker: SpeakerOpts,
    /// The routes.
    pub source: Source,
    /// What to do after the table.
    pub scenario: Scenario,
    /// Seed for churn.
    pub seed: u64,
    /// How long to keep the session after the scenario; `None` until the
    /// peer closes it.
    pub hold: Option<Duration>,
    /// How long to keep trying to set up a session.
    pub timeout: Duration,
}

/// Why a run failed.
#[derive(Debug)]
pub enum RunError {
    /// No session.
    Session(SessionError),
    /// The table could not be packed.
    Pack(PackError),
    /// Writing to the session or to the output failed.
    Io(io::Error),
    /// The table has a family the session did not negotiate.
    Family(AddressFamily),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Session(e) => write!(f, "session: {e}"),
            RunError::Pack(e) => write!(f, "packing: {e}"),
            RunError::Io(e) => write!(f, "{e}"),
            RunError::Family(fam) => write!(f, "the peer did not negotiate {fam}"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<SessionError> for RunError {
    fn from(e: SessionError) -> Self {
        RunError::Session(e)
    }
}

impl From<PackError> for RunError {
    fn from(e: PackError) -> Self {
        RunError::Pack(e)
    }
}

impl From<io::Error> for RunError {
    fn from(e: io::Error) -> Self {
        RunError::Io(e)
    }
}

/// What one phase sent and how long it took.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase {
    /// `load`, `churn`, `withdraw` or `reload`.
    pub name: &'static str,
    /// UPDATE messages, End-of-RIB markers included.
    pub updates: u64,
    /// Routes announced or withdrawn.
    pub prefixes: u64,
    /// Octets written.
    pub bytes: u64,
    /// From the first write to the last.
    pub took: Duration,
}

impl Phase {
    /// The phase as a `key=value` line.
    #[must_use]
    pub fn line(&self) -> Line {
        let mut l = Line::default();
        l.field("phase", self.name)
            .field("updates", self.updates)
            .field("prefixes", self.prefixes)
            .field("bytes", self.bytes)
            .field("ms", self.took.as_millis())
            .field("updates_per_s", per_second(self.updates, self.took))
            .field("prefixes_per_s", per_second(self.prefixes, self.took))
            .field("bytes_per_s", per_second(self.bytes, self.took));
        l
    }
}

/// `n` in `d`, per second.
#[must_use]
pub fn per_second(n: u64, d: Duration) -> u64 {
    let us = d.as_micros().max(1);
    u64::try_from(u128::from(n) * 1_000_000 / us).unwrap_or(u64::MAX)
}

fn say(out: &mut dyn Write, line: &Line) -> io::Result<()> {
    writeln!(out, "loadgen {line}")?;
    out.flush()
}

/// Run `plan`, printing progress to `out`.
///
/// # Errors
/// [`RunError`] when the session cannot be set up or breaks.
pub fn run(plan: &Plan, out: &mut dyn Write) -> Result<(), RunError> {
    let mut session = establish(plan, out, None)?;
    let built = Instant::now();
    let table = plan.source.table(plan.speaker.asn, &session.negotiated);
    let mut l = Line::default();
    l.field("event", "table")
        .field("routes", table.routes.len())
        .field("attr_sets", table.used_sets())
        .field("ms", built.elapsed().as_millis());
    say(out, &l)?;
    let mut cache = Packed::default();
    let phase = send_table(&session, &table, &mut cache, "load", out)?;
    say(out, &phase.line())?;

    match &plan.scenario {
        Scenario::Load => {}
        Scenario::Churn { rate, duration } => {
            let p = churn(&session, &table, *rate, *duration, plan.seed)?;
            say(out, &p.line())?;
        }
        Scenario::WithdrawAll => {
            let p = withdraw_all(&session, &table)?;
            say(out, &p.line())?;
        }
        Scenario::Flap { cycles, gap } => {
            for cycle in 1..=*cycles {
                session.close()?;
                let mut l = Line::default();
                l.field("event", "cease").field("cycle", cycle);
                say(out, &l)?;
                thread::sleep(*gap);
                session = establish(plan, out, Some(cycle))?;
                let p = send_table(&session, &table, &mut cache, "reload", out)?;
                let mut l = p.line();
                l.field("cycle", cycle);
                say(out, &l)?;
            }
        }
    }

    let closed = session.wait_closed(plan.hold);
    let mut l = Line::default();
    l.field("event", "closed")
        .field("by", if closed { "peer" } else { "us" })
        .opt("notification", session.notification())
        .field("updates_received", session.updates_received());
    if !closed {
        session.close()?;
    }
    say(out, &l)?;
    Ok(())
}

fn establish(plan: &Plan, out: &mut dyn Write, cycle: Option<u32>) -> Result<Session, RunError> {
    let started = Instant::now();
    let s = Session::establish(&plan.endpoint, &plan.speaker, plan.timeout)?;
    let n = &s.negotiated;
    for f in plan.source.families() {
        if !n.families.contains(&f) {
            return Err(RunError::Family(f));
        }
    }
    let mut l = Line::default();
    l.field("event", "established")
        .opt("cycle", cycle)
        .field("local", s.local)
        .field("peer_as", n.peer_as.0)
        .field("hold", n.hold_time)
        .field("four_octet_as", n.four_octet_as)
        .field("extended", n.extended)
        .field(
            "families",
            n.families
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
        .field("ms", started.elapsed().as_millis());
    say(out, &l)?;
    Ok(s)
}

/// The table's UPDATEs, packed once per negotiated encoding and reused by
/// `flap`.
#[derive(Default)]
struct Packed {
    key: Option<(bool, bool)>,
    messages: Vec<Vec<u8>>,
}

fn send_table(
    session: &Session,
    table: &Table,
    cache: &mut Packed,
    name: &'static str,
    out: &mut dyn Write,
) -> Result<Phase, RunError> {
    let n = &session.negotiated;
    let packer = Packer::new(n.four_octet_as, n.extended);
    let key = Some((n.four_octet_as, n.extended));
    if cache.key != key {
        let t = Instant::now();
        cache.messages = packer.table(table)?;
        cache.key = key;
        let mut l = Line::default();
        l.field("event", "packed")
            .field("messages", cache.messages.len())
            .field("max_len", packer.max_len())
            .field("ms", t.elapsed().as_millis());
        say(out, &l)?;
    }
    let start = Instant::now();
    let mut bytes = session.send(&cache.messages)?;
    let mut updates = cache.messages.len() as u64;
    bytes += end_of_rib(session, &packer, &table.families())?;
    updates += table.families().len() as u64;
    Ok(Phase {
        name,
        updates,
        prefixes: table.routes.len() as u64,
        bytes,
        took: start.elapsed(),
    })
}

fn end_of_rib(
    session: &Session,
    packer: &Packer,
    families: &[AddressFamily],
) -> Result<u64, RunError> {
    let markers = families
        .iter()
        .map(|f| packer.end_of_rib(*f))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(session.send(&markers)?)
}

/// Random changes at `rate` UPDATEs a second: a route that is up is
/// withdrawn or re-announced with another attribute set, one that is down
/// is announced again. One prefix per UPDATE, as route flaps arrive.
fn churn(
    session: &Session,
    table: &Table,
    rate: u64,
    duration: Duration,
    seed: u64,
) -> Result<Phase, RunError> {
    let n = &session.negotiated;
    let packer = Packer::new(n.four_octet_as, n.extended);
    // A seed of its own, so churn does not depend on how the table was made.
    let mut rng = Rng::new(seed ^ 0x6368_7572_6e00_0000);
    let mut state: Vec<Option<u32>> = table.routes.iter().map(|r| Some(r.set)).collect();
    let set_count = table.sets.len();
    let total = rate.saturating_mul(duration.as_secs()).max(1);
    let start = Instant::now();
    let (mut bytes, mut changes) = (0u64, 0u64);
    let mut batch = Vec::new();
    for i in 0..total {
        // Pace by schedule rather than by sleeping a fixed step, so the
        // rate holds however long a write takes.
        let due = start
            + Duration::from_nanos(
                u64::try_from(u128::from(i) * 1_000_000_000 / u128::from(rate.max(1)))
                    .unwrap_or(u64::MAX),
            );
        let now = Instant::now();
        if due > now {
            bytes += session.send(&batch)?;
            batch.clear();
            thread::sleep(due - now);
        }
        let k = rng.index(table.routes.len());
        let prefix = table.routes[k].prefix;
        let family = family_of(&prefix);
        match state[k] {
            Some(_) if rng.chance(500) => {
                packer.withdraw(family, &[prefix], &mut batch)?;
                state[k] = None;
            }
            current => {
                let mut set = rng.index(set_count);
                if set_count > 1 && current == u32::try_from(set).ok() {
                    set = (set + 1) % set_count;
                }
                packer.announce(family, &table.sets[set], &[prefix], &mut batch)?;
                state[k] = u32::try_from(set).ok();
            }
        }
        changes += 1;
    }
    bytes += session.send(&batch)?;
    bytes += end_of_rib(session, &packer, &table.families())?;
    Ok(Phase {
        name: "churn",
        updates: changes + table.families().len() as u64,
        prefixes: changes,
        bytes,
        took: start.elapsed(),
    })
}

fn withdraw_all(session: &Session, table: &Table) -> Result<Phase, RunError> {
    let n = &session.negotiated;
    let packer = Packer::new(n.four_octet_as, n.extended);
    let mut messages = Vec::new();
    for family in table.families() {
        let prefixes: Vec<Prefix> = table
            .routes
            .iter()
            .map(|r| r.prefix)
            .filter(|p| family_of(p) == family)
            .collect();
        packer.withdraw(family, &prefixes, &mut messages)?;
    }
    let start = Instant::now();
    let mut bytes = session.send(&messages)?;
    bytes += end_of_rib(session, &packer, &table.families())?;
    Ok(Phase {
        name: "withdraw",
        updates: (messages.len() + table.families().len()) as u64,
        prefixes: table.routes.len() as u64,
        bytes,
        took: start.elapsed(),
    })
}
