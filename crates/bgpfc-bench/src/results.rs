//! What one benchmark invocation records: the metrics of a run taken from
//! the daemon's report lines, and the CSV history in `bench/results.csv`
//! with its regression check against the previous comparable row.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::Path;

use bgpfc_prof::report::{get, get_u64};

use crate::stats::{change_bp, percent};

/// The CSV columns, in order.
pub const HEADER: &str = "timestamp,git_rev,dirty,scenario,prefixes,seed,params,runs,\
load_us,updates_per_s,peak_live_bytes,bytes_per_prefix,peak_rss_kb,residual_bytes";

/// The figures of one run, or the medians of several.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Table-load time, µs.
    pub load_us: Option<u64>,
    /// UPDATEs per second during the table load, as the daemon counted.
    pub updates_per_s: Option<u64>,
    /// Peak live heap bytes when the scenario ended.
    pub peak_live_bytes: Option<u64>,
    /// Live heap growth over the table load per prefix loaded.
    pub bytes_per_prefix: Option<u64>,
    /// Peak RSS when the scenario ended, KiB.
    pub peak_rss_kb: Option<u64>,
    /// Live bytes after the withdrawals or the last flap minus live bytes
    /// before the first load; `None` for scenarios that keep their routes.
    pub residual_bytes: Option<i64>,
}

/// What a scenario waits for before it counts as done: table loads, and
/// End-of-RIB sync points after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expect {
    /// `event=table_load` lines.
    pub table_loads: usize,
    /// `event=eor` lines.
    pub eors: usize,
}

impl Expect {
    /// What `scenario` produces; `cycles` matters for `flap` only.
    #[must_use]
    pub fn of(scenario: &str, cycles: u32) -> Expect {
        match scenario {
            "churn" | "withdraw-all" => Expect {
                table_loads: 1,
                eors: 1,
            },
            "flap" => Expect {
                table_loads: 1 + cycles as usize,
                eors: 0,
            },
            _ => Expect {
                table_loads: 1,
                eors: 0,
            },
        }
    }

    /// Whether `events` hold everything expected.
    #[must_use]
    pub fn met(&self, events: &[String]) -> bool {
        count(events, "table_load") >= self.table_loads && count(events, "eor") >= self.eors
    }
}

fn count(events: &[String], event: &str) -> usize {
    events
        .iter()
        .filter(|e| get(e, "event") == Some(event))
        .count()
}

/// The metrics of one run from the daemon's report lines up to the end of
/// the scenario (before shutdown).
#[must_use]
pub fn metrics(scenario: &str, events: &[String]) -> Metrics {
    let of = |name: &'static str| events.iter().filter(move |e| get(e, "event") == Some(name));
    let first_load = of("table_load").next();
    // The duplication line has no memory fields; the line before it does.
    let last = events.iter().rev().find(|e| get_u64(e, "peak").is_some());
    let mut m = Metrics {
        load_us: first_load.and_then(|e| get_u64(e, "load_us")),
        updates_per_s: first_load.and_then(|e| get_u64(e, "updates_per_s")),
        bytes_per_prefix: first_load.and_then(|e| get_u64(e, "bytes_per_prefix")),
        // Process-wide high-water marks, as of the scenario's last event.
        peak_live_bytes: last.and_then(|e| get_u64(e, "peak")),
        peak_rss_kb: last.and_then(|e| get_u64(e, "hwm_kb")),
        residual_bytes: None,
    };
    let before = first_load.and_then(|e| get_u64(e, "live_before"));
    let after = match scenario {
        "withdraw-all" => of("eor").next_back(),
        "flap" => of("peer_down").next_back(),
        _ => None,
    }
    .and_then(|e| get_u64(e, "live"));
    if let (Some(b), Some(a)) = (before, after) {
        m.residual_bytes = Some(i64::try_from(i128::from(a) - i128::from(b)).unwrap_or(i64::MAX));
    }
    m
}

/// The prefixes the first table load brought in.
#[must_use]
pub fn prefixes_loaded(events: &[String]) -> Option<u64> {
    events
        .iter()
        .find(|e| get(e, "event") == Some("table_load"))
        .and_then(|e| get_u64(e, "prefixes"))
}

/// One CSV row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub timestamp: String,
    /// `git rev-parse --short HEAD`, empty without git.
    pub git_rev: String,
    /// `1` with uncommitted changes, `0` without, empty without git.
    pub dirty: String,
    /// The scenario.
    pub scenario: String,
    /// Table size.
    pub prefixes: u64,
    /// PRNG seed.
    pub seed: u64,
    /// The other parameters that change the result, `key=value;...`.
    pub params: String,
    /// Number of runs summarised.
    pub runs: u32,
    /// Medians over the runs.
    pub metrics: Metrics,
}

/// The fields a row must share with an earlier one to be compared with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    /// The scenario.
    pub scenario: String,
    /// Table size.
    pub prefixes: u64,
    /// PRNG seed.
    pub seed: u64,
    /// The other parameters.
    pub params: String,
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

impl Row {
    /// The comparison key.
    #[must_use]
    pub fn key(&self) -> Key {
        Key {
            scenario: self.scenario.clone(),
            prefixes: self.prefixes,
            seed: self.seed,
            params: self.params.clone(),
        }
    }

    /// The row as a CSV line, without the newline.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let m = &self.metrics;
        let mut s = String::new();
        let _ = write!(
            s,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.timestamp,
            self.git_rev,
            self.dirty,
            self.scenario,
            self.prefixes,
            self.seed,
            self.params,
            self.runs,
            opt(m.load_us),
            opt(m.updates_per_s),
            opt(m.peak_live_bytes),
            opt(m.bytes_per_prefix),
            opt(m.peak_rss_kb),
            opt(m.residual_bytes),
        );
        s
    }

    /// Parse a CSV line; `None` for the header or a malformed line.
    #[must_use]
    pub fn parse(line: &str) -> Option<Row> {
        let f: Vec<&str> = line.trim_end().split(',').collect();
        if f.len() != 14 || f[0] == "timestamp" {
            return None;
        }
        let num = |s: &str| -> Option<Option<u64>> {
            if s.is_empty() {
                Some(None)
            } else {
                s.parse().ok().map(Some)
            }
        };
        Some(Row {
            timestamp: f[0].to_owned(),
            git_rev: f[1].to_owned(),
            dirty: f[2].to_owned(),
            scenario: f[3].to_owned(),
            prefixes: f[4].parse().ok()?,
            seed: f[5].parse().ok()?,
            params: f[6].to_owned(),
            runs: f[7].parse().ok()?,
            metrics: Metrics {
                load_us: num(f[8])?,
                updates_per_s: num(f[9])?,
                peak_live_bytes: num(f[10])?,
                bytes_per_prefix: num(f[11])?,
                peak_rss_kb: num(f[12])?,
                residual_bytes: if f[13].is_empty() {
                    None
                } else {
                    Some(f[13].parse().ok()?)
                },
            },
        })
    }
}

/// The last row of `path` with key `key`, if any.
///
/// # Errors
/// Reading the file, unless it does not exist.
pub fn previous(path: &Path, key: &Key) -> io::Result<Option<Row>> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(text
        .lines()
        .filter_map(Row::parse)
        .rfind(|r| r.key() == *key))
}

/// Append `row` to `path`, creating it (and its directory) with a header.
///
/// # Errors
/// Creating or writing the file.
pub fn append(path: &Path, row: &Row) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let new = !path.exists();
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    if new {
        writeln!(f, "{HEADER}")?;
    }
    writeln!(f, "{}", row.to_csv())
}

/// Which way a metric is better.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Better {
    Lower,
    Higher,
}

/// The change of every metric and the ones beyond the threshold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    /// One line per metric present in both rows.
    pub lines: Vec<String>,
    /// The metrics that regressed beyond the threshold.
    pub regressed: Vec<&'static str>,
}

/// Compare `new` with `old`. A time or memory metric regresses when it is
/// worse by more than `threshold_bp` basis points.
#[must_use]
pub fn compare(old: &Metrics, new: &Metrics, threshold_bp: i64) -> Comparison {
    let rows: [(&'static str, Option<u64>, Option<u64>, Better); 5] = [
        ("load_us", old.load_us, new.load_us, Better::Lower),
        (
            "updates_per_s",
            old.updates_per_s,
            new.updates_per_s,
            Better::Higher,
        ),
        (
            "peak_live_bytes",
            old.peak_live_bytes,
            new.peak_live_bytes,
            Better::Lower,
        ),
        (
            "bytes_per_prefix",
            old.bytes_per_prefix,
            new.bytes_per_prefix,
            Better::Lower,
        ),
        (
            "peak_rss_kb",
            old.peak_rss_kb,
            new.peak_rss_kb,
            Better::Lower,
        ),
    ];
    let mut c = Comparison::default();
    for (name, o, n, better) in rows {
        let (Some(o), Some(n)) = (o, n) else {
            continue;
        };
        let Some(bp) = change_bp(o, n) else {
            continue;
        };
        let worse = match better {
            Better::Lower => bp > threshold_bp,
            Better::Higher => bp < -threshold_bp,
        };
        c.lines.push(format!(
            "{name:18} {o:>14} -> {n:>14}  {:>9}{}",
            percent(bp),
            if worse { "  REGRESSION" } else { "" }
        ));
        if worse {
            c.regressed.push(name);
        }
    }
    // Shown but never a regression: the baseline may be near zero.
    if let (Some(o), Some(n)) = (old.residual_bytes, new.residual_bytes) {
        c.lines.push(format!(
            "{:18} {o:>14} -> {n:>14}  (not checked)",
            "residual_bytes"
        ));
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOAD: &str = "2026-10-24T12:00:00.000Z INFO  msg=\"profile\" event=table_load \
        uptime_ms=900 peer=127.0.0.1 end=eor prefixes=1000 updates=50 load_ms=12 \
        load_us=12345 updates_per_s=4050 prefixes_per_s=81000 live_before=500000 \
        bytes_per_prefix=300 live=800000 peak=810000 hwm_kb=9000";

    fn line(event: &str, rest: &str) -> String {
        format!("x INFO  msg=\"profile\" event={event} uptime_ms=1 {rest}")
    }

    #[test]
    fn metrics_per_scenario() {
        let load = vec![LOAD.to_owned(), line("duplication", "routes=1000")];
        let m = metrics("load", &load);
        assert_eq!(
            m,
            Metrics {
                load_us: Some(12_345),
                updates_per_s: Some(4050),
                peak_live_bytes: Some(810_000),
                bytes_per_prefix: Some(300),
                peak_rss_kb: Some(9000),
                residual_bytes: None,
            }
        );
        assert_eq!(prefixes_loaded(&load), Some(1000));
        let withdraw = vec![
            LOAD.to_owned(),
            line("eor", "live=520000 peak=820000 hwm_kb=9100"),
        ];
        let m = metrics("withdraw-all", &withdraw);
        assert_eq!(m.residual_bytes, Some(20_000));
        assert_eq!(m.peak_live_bytes, Some(820_000));
        assert_eq!(m.peak_rss_kb, Some(9100));
        let flap = vec![
            LOAD.to_owned(),
            line("peer_down", "live=700000 peak=820000 hwm_kb=9100"),
            LOAD.to_owned(),
            line("peer_down", "live=480000 peak=830000 hwm_kb=9200"),
        ];
        assert_eq!(metrics("flap", &flap).residual_bytes, Some(-20_000));
        assert!(Expect::of("flap", 1).met(&flap));
        assert!(!Expect::of("flap", 2).met(&flap));
        assert!(!Expect::of("churn", 0).met(&load));
        assert!(Expect::of("withdraw-all", 0).met(&withdraw));
    }

    fn row(load_us: u64, peak: u64) -> Row {
        Row {
            timestamp: "2026-10-24T12:00:00.000Z".to_owned(),
            git_rev: "abc1234".to_owned(),
            dirty: "0".to_owned(),
            scenario: "load".to_owned(),
            prefixes: 1_000_000,
            seed: 1,
            params: "attr_sets=50000;extended=false".to_owned(),
            runs: 5,
            metrics: Metrics {
                load_us: Some(load_us),
                updates_per_s: Some(40_000),
                peak_live_bytes: Some(peak),
                bytes_per_prefix: Some(380),
                peak_rss_kb: None,
                residual_bytes: Some(-3),
            },
        }
    }

    #[test]
    fn rows_round_trip_and_are_found_by_key() {
        let r = row(5_000_000, 400_000_000);
        assert_eq!(Row::parse(&r.to_csv()), Some(r.clone()));
        assert_eq!(Row::parse(HEADER), None);
        assert_eq!(Row::parse("a,b"), None);

        let dir = std::env::temp_dir().join(format!("bgpfc-results-{}", std::process::id()));
        let path = dir.join("sub").join("results.csv");
        assert_eq!(previous(&path, &r.key()).unwrap(), None);
        append(&path, &row(1, 1)).unwrap();
        append(&path, &r).unwrap();
        let mut other = row(9, 9);
        other.seed = 2;
        append(&path, &other).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(HEADER));
        assert_eq!(text.lines().count(), 4);
        assert_eq!(previous(&path, &r.key()).unwrap(), Some(r));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn regressions_beyond_the_threshold() {
        let old = row(5_000_000, 400_000_000).metrics;
        let same = compare(&old, &old, 1000);
        assert_eq!(same.regressed, Vec::<&str>::new());
        assert_eq!(same.lines.len(), 5);

        let mut slower = old;
        slower.load_us = Some(5_600_000);
        slower.updates_per_s = Some(30_000);
        slower.peak_live_bytes = Some(430_000_000);
        let c = compare(&old, &slower, 1000);
        assert_eq!(c.regressed, vec!["load_us", "updates_per_s"]);
        assert!(c.lines[0].contains("+12.00%") && c.lines[0].ends_with("REGRESSION"));
        // 7.5 % more memory is inside a 10 % threshold, not a 5 % one.
        assert_eq!(compare(&old, &slower, 500).regressed.len(), 3);
        // Faster and smaller is never a regression.
        let mut better = old;
        better.load_us = Some(1);
        better.updates_per_s = Some(1_000_000);
        assert_eq!(compare(&old, &better, 0).regressed, Vec::<&str>::new());
    }
}
