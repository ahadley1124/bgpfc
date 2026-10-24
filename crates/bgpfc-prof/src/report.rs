//! The report line: `key=value` pairs separated by single spaces, starting
//! with `event=`. Keys are fixed words; values are numbers, addresses and
//! words, never whitespace, so a line splits on spaces and each pair on
//! its first `=` (`docs/PROFILING.md`, "Reading the report line").

use std::fmt;

use crate::metrics;
use crate::procfs;

/// A report line being built.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line {
    pairs: Vec<(String, String)>,
}

impl Line {
    /// A line for `event`, with the uptime.
    #[must_use]
    pub fn new(event: &str) -> Line {
        let mut l = Line::default();
        l.field("event", event)
            .field("uptime_ms", metrics::uptime().as_millis());
        l
    }

    /// Append `key=value`. A value that would break the line's syntax has
    /// the offending characters replaced by `_`; an empty one becomes `-`.
    pub fn field(&mut self, key: &str, value: impl fmt::Display) -> &mut Line {
        self.pairs.push((key.to_owned(), clean(value.to_string())));
        self
    }

    /// Append `key=value` when there is a value.
    pub fn opt(&mut self, key: &str, value: Option<impl fmt::Display>) -> &mut Line {
        if let Some(v) = value {
            self.field(key, v);
        }
        self
    }

    /// Append `rss_kb` and `hwm_kb`, when `/proc` has them.
    pub fn process_memory(&mut self) -> &mut Line {
        let m = procfs::memory();
        self.opt("rss_kb", m.map(|m| m.rss_kb))
            .opt("hwm_kb", m.map(|m| m.hwm_kb))
    }

    /// Append every gauge.
    pub fn gauges(&mut self) -> &mut Line {
        for (k, g) in &metrics::GAUGES {
            self.field(k, g.get());
        }
        self
    }

    /// Append every counter.
    pub fn counters(&mut self) -> &mut Line {
        for (k, c) in &metrics::COUNTERS {
            self.field(k, c.get());
        }
        self
    }

    /// Append `<name>.count`, `.sum_ns`, `.max_ns`, `.p50_ns`, `.p90_ns`
    /// and `.p99_ns` for every histogram.
    pub fn histograms(&mut self) -> &mut Line {
        for (name, h) in &metrics::HISTOGRAMS {
            let s = h.snapshot();
            self.field(&format!("{name}.count"), s.count)
                .field(&format!("{name}.sum_ns"), s.sum)
                .field(&format!("{name}.max_ns"), s.max)
                .field(&format!("{name}.p50_ns"), s.quantile(500))
                .field(&format!("{name}.p90_ns"), s.quantile(900))
                .field(&format!("{name}.p99_ns"), s.quantile(990));
        }
        self
    }

    /// The pairs in order.
    pub fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The value of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (k, v)) in self.pairs().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{k}={v}")?;
        }
        Ok(())
    }
}

fn clean(v: String) -> String {
    if v.is_empty() {
        return "-".to_owned();
    }
    if v.chars().any(bad) {
        v.chars().map(|c| if bad(c) { '_' } else { c }).collect()
    } else {
        v
    }
}

fn bad(c: char) -> bool {
    c.is_whitespace() || c.is_control() || matches!(c, '=' | '"' | '\\')
}

/// The `key=value` pairs of a report line, also when it is embedded in a
/// log line (`... INFO  msg="profile" event=...`); words without `=` are
/// skipped.
pub fn fields(line: &str) -> impl Iterator<Item = (&str, &str)> {
    line.split_whitespace().filter_map(|w| w.split_once('='))
}

/// The value of `key` on `line`.
#[must_use]
pub fn get<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    fields(line).find(|(k, _)| *k == key).map(|(_, v)| v)
}

/// The value of `key` on `line` as a number.
#[must_use]
pub fn get_u64(line: &str, key: &str) -> Option<u64> {
    get(line, key)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_back() {
        let mut l = Line::new("table_load");
        l.field("peer", "192.0.2.1")
            .field("prefixes", 1_000_000)
            .opt("missing", None::<u64>)
            .opt("present", Some("x"));
        let text = l.to_string();
        assert!(text.starts_with("event=table_load uptime_ms="), "{text}");
        assert_eq!(get(&text, "peer"), Some("192.0.2.1"));
        assert_eq!(get_u64(&text, "prefixes"), Some(1_000_000));
        assert_eq!(get(&text, "missing"), None);
        assert_eq!(l.get("present"), Some("x"));
        let parsed: Vec<_> = fields(&text).collect();
        assert_eq!(parsed, l.pairs().collect::<Vec<_>>());
    }

    #[test]
    fn values_cannot_break_the_line() {
        let mut l = Line::default();
        l.field("a", "two words")
            .field("b", "x=y\"\\")
            .field("c", "");
        assert_eq!(l.to_string(), "a=two_words b=x_y__ c=-");
    }

    #[test]
    fn standard_sections_are_all_parseable() {
        crate::metrics::mark_start();
        crate::metrics::BEST_PATH_RUNS.add(3);
        crate::metrics::BEST_PATH.record(1500);
        let mut l = Line::new("stats");
        l.process_memory().gauges().counters().histograms();
        let text = l.to_string();
        let pairs: Vec<_> = fields(&text).collect();
        assert_eq!(pairs.len(), l.pairs().count(), "{text}");
        assert!(get_u64(&text, "best_path_runs").unwrap() >= 3);
        assert!(get_u64(&text, "best_path.count").unwrap() >= 1);
        assert!(get_u64(&text, "best_path.p99_ns").unwrap() >= 1024);
        for key in ["rib_prefixes", "updates_rx", "update_total.p50_ns"] {
            assert!(get_u64(&text, key).is_some(), "{key}");
        }
        #[cfg(target_os = "linux")]
        assert!(get_u64(&text, "rss_kb").is_some());
    }

    #[test]
    fn reads_fields_out_of_a_log_line() {
        let log = "2026-10-24T12:00:00.000Z INFO  msg=\"profile\" event=shutdown live=42";
        assert_eq!(get(log, "event"), Some("shutdown"));
        assert_eq!(get_u64(log, "live"), Some(42));
        assert_eq!(get(log, "msg"), Some("\"profile\""));
    }
}
