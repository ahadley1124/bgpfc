//! Leveled logger to stderr.
//!
//! One line per event, in this shape (AGENTS.md §3, "Logging"):
//!
//! ```text
//! 2026-10-03T12:34:56.789Z INFO  msg="session established" peer=198.51.100.1 hold=90
//! ```
//!
//! The timestamp is UTC with millisecond precision. The level is padded to
//! five columns. `msg` is always quoted; other values are quoted only when
//! they contain characters that would make the line ambiguous.
//!
//! Use the [`error!`], [`warn!`], [`info!`], [`debug!`] and [`trace!`]
//! macros. Every field value must implement [`fmt::Display`].
//!
//! ```
//! bgpfc_log::init(bgpfc_log::Level::Info);
//! bgpfc_log::info!("session established", peer = "198.51.100.1", hold = 90);
//! bgpfc_log::debug!("not printed at info level");
//! ```
//!
//! There is no `log` crate facade and no global allocator trickery: a single
//! atomic holds the active level and each line is written with one locked
//! write to stderr.
//!
//! Implements: no RFC; infrastructure only.
#![forbid(unsafe_code)]

use std::fmt;
use std::io::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Severity of a log line, most severe first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Level {
    /// The daemon cannot do something it was asked to do.
    Error = 1,
    /// Something unexpected that the daemon recovered from.
    Warn = 2,
    /// Normal operational events: sessions up and down, config reloads.
    Info = 3,
    /// Detail useful when diagnosing a problem: FSM transitions, policy decisions.
    Debug = 4,
    /// Everything, including per-message events.
    Trace = 5,
}

impl Level {
    /// Upper-case name padded to five columns, as printed on each line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    /// Parse a level name as written in the config file; case-insensitive.
    #[must_use]
    pub fn parse(name: &str) -> Option<Level> {
        match name.to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            "trace" => Some(Level::Trace),
            _ => None,
        }
    }

    const fn from_u8(v: u8) -> Option<Level> {
        match v {
            1 => Some(Level::Error),
            2 => Some(Level::Warn),
            3 => Some(Level::Info),
            4 => Some(Level::Debug),
            5 => Some(Level::Trace),
            _ => None,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str().trim_end())
    }
}

/// `0` means "nothing is logged" and is the state before [`init`] runs, so
/// that a library used from tests stays quiet unless the test opts in.
static MAX_LEVEL: AtomicU8 = AtomicU8::new(0);

/// Enable logging at `level` and below (towards [`Level::Error`]).
///
/// May be called again at any time, for example on a config reload.
pub fn init(level: Level) {
    MAX_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Disable all logging.
pub fn disable() {
    MAX_LEVEL.store(0, Ordering::Relaxed);
}

/// The active level, or `None` when logging is disabled.
#[must_use]
pub fn level() -> Option<Level> {
    Level::from_u8(MAX_LEVEL.load(Ordering::Relaxed))
}

/// Whether a line at `level` would be written.
#[must_use]
pub fn enabled(level: Level) -> bool {
    level as u8 <= MAX_LEVEL.load(Ordering::Relaxed)
}

/// A `key=value` pair on a log line.
pub type Field<'a> = (&'a str, &'a dyn fmt::Display);

/// Write one line. Called by the macros; prefer those.
///
/// The level check happens here as well as in the macro, so that a caller
/// building fields by hand still respects the active level.
pub fn log(level: Level, msg: &str, fields: &[Field<'_>]) {
    if !enabled(level) {
        return;
    }
    let line = format_line(SystemTime::now(), level, msg, fields);
    // A failed write to stderr (closed pipe, full disk) has nowhere to be
    // reported, and must never take the daemon down.
    let stderr = std::io::stderr();
    let mut out = stderr.lock();
    let _ = out.write_all(line.as_bytes());
}

/// Render a complete line, including the trailing newline. Pure, so that it
/// can be tested without touching stderr or the clock.
#[must_use]
pub fn format_line(now: SystemTime, level: Level, msg: &str, fields: &[Field<'_>]) -> String {
    let mut line = String::with_capacity(64 + msg.len() + fields.len() * 16);
    push_timestamp(&mut line, now);
    line.push(' ');
    line.push_str(level.as_str());
    line.push_str(" msg=");
    push_quoted(&mut line, msg);
    for (key, value) in fields {
        line.push(' ');
        line.push_str(key);
        line.push('=');
        push_value(&mut line, &value.to_string());
    }
    line.push('\n');
    line
}

/// Append `value`, quoting it only when needed.
fn push_value(out: &mut String, value: &str) {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| !c.is_whitespace() && !c.is_control() && !matches!(c, '"' | '\\' | '='));
    if plain {
        out.push_str(value);
    } else {
        push_quoted(out, value);
    }
}

/// Append `value` in double quotes, escaping `"`, `\` and control characters
/// so that the line can be split on whitespace and parsed back.
fn push_quoted(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = fmt::Write::write_fmt(out, format_args!("\\u{{{:04x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append `now` as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// std has no calendar support, so the civil date is computed by hand. Times
/// before the Unix epoch cannot occur on a correctly configured host and are
/// clamped to the epoch rather than handled.
fn push_timestamp(out: &mut String, now: SystemTime) {
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = since_epoch.as_secs();
    let millis = since_epoch.subsec_millis();
    let (year, month, day) = civil_from_days(secs / 86_400);
    let tod = secs % 86_400;
    let _ = fmt::Write::write_fmt(
        out,
        format_args!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
            tod / 3600,
            (tod / 60) % 60,
            tod % 60,
        ),
    );
}

/// Proleptic Gregorian date for a day count since 1970-01-01.
///
/// Howard Hinnant's `civil_from_days` algorithm, restricted to non-negative
/// day counts. Valid until year 2^31 or so, which is plenty.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, March-based [0, 365]
    let mp = (5 * doy + 2) / 153; // month, March-based [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[doc(hidden)]
#[macro_export]
macro_rules! __log_at {
    ($level:expr, $msg:expr $(, $key:ident = $value:expr)* $(,)?) => {
        if $crate::enabled($level) {
            $crate::log(
                $level,
                $msg,
                &[$((::core::stringify!($key), &$value as &dyn ::core::fmt::Display)),*],
            );
        }
    };
}

/// Log at [`Level::Error`]: `error!("msg", key = value, ...)`.
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::__log_at!($crate::Level::Error, $($arg)*) };
}

/// Log at [`Level::Warn`]: `warn!("msg", key = value, ...)`.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::__log_at!($crate::Level::Warn, $($arg)*) };
}

/// Log at [`Level::Info`]: `info!("msg", key = value, ...)`.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::__log_at!($crate::Level::Info, $($arg)*) };
}

/// Log at [`Level::Debug`]: `debug!("msg", key = value, ...)`.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::__log_at!($crate::Level::Debug, $($arg)*) };
}

/// Log at [`Level::Trace`]: `trace!("msg", key = value, ...)`.
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => { $crate::__log_at!($crate::Level::Trace, $($arg)*) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, millis: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(secs, millis * 1_000_000)
    }

    #[test]
    fn epoch_formats_as_1970() {
        let line = format_line(at(0, 0), Level::Info, "x", &[]);
        assert_eq!(line, "1970-01-01T00:00:00.000Z INFO  msg=\"x\"\n");
    }

    #[test]
    fn known_timestamps() {
        // 2026-10-03T12:34:56.789Z, the example in AGENTS.md.
        let line = format_line(at(1_791_030_896, 789), Level::Info, "m", &[]);
        assert!(line.starts_with("2026-10-03T12:34:56.789Z "), "{line}");
        // Leap day, last second of the day.
        let line = format_line(at(951_868_799, 0), Level::Info, "m", &[]);
        assert!(line.starts_with("2000-02-29T23:59:59.000Z "), "{line}");
        // First second of a non-leap century year.
        let line = format_line(at(4_102_444_800, 0), Level::Info, "m", &[]);
        assert!(line.starts_with("2100-01-01T00:00:00.000Z "), "{line}");
    }

    #[test]
    fn civil_from_days_matches_a_naive_calendar() {
        fn leap(y: u64) -> bool {
            (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
        }
        let (mut y, mut m, mut d) = (1970, 1, 1);
        for days in 0..(400 * 366) {
            assert_eq!(civil_from_days(days), (y, m, d), "day {days}");
            let dim = match m {
                2 if leap(y) => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            d += 1;
            if d > dim {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
    }

    #[test]
    fn levels_are_padded_to_five_columns() {
        for l in [
            Level::Error,
            Level::Warn,
            Level::Info,
            Level::Debug,
            Level::Trace,
        ] {
            assert_eq!(l.as_str().len(), 5);
        }
        let line = format_line(at(0, 0), Level::Warn, "m", &[]);
        assert!(line.contains("Z WARN  msg="), "{line}");
    }

    #[test]
    fn fields_are_appended_in_order() {
        let peer = "198.51.100.1";
        let hold = 90;
        let line = format_line(
            at(0, 0),
            Level::Info,
            "session established",
            &[("peer", &peer), ("hold", &hold)],
        );
        assert_eq!(
            line,
            "1970-01-01T00:00:00.000Z INFO  msg=\"session established\" peer=198.51.100.1 hold=90\n"
        );
    }

    #[test]
    fn values_are_quoted_only_when_needed() {
        let mut s = String::new();
        push_value(&mut s, "plain");
        assert_eq!(s, "plain");
        s.clear();
        push_value(&mut s, "");
        assert_eq!(s, "\"\"");
        s.clear();
        push_value(&mut s, "has space");
        assert_eq!(s, "\"has space\"");
        s.clear();
        push_value(&mut s, "a=b");
        assert_eq!(s, "\"a=b\"");
        s.clear();
        push_value(&mut s, "q\"uote\\back\nnl\u{1}");
        assert_eq!(s, "\"q\\\"uote\\\\back\\nnl\\u{0001}\"");
    }

    #[test]
    fn level_parse_and_display() {
        assert_eq!(Level::parse("INFO"), Some(Level::Info));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse("loud"), None);
        assert_eq!(Level::Warn.to_string(), "WARN");
        assert!(Level::Error < Level::Trace);
    }

    #[test]
    fn enabled_follows_the_active_level() {
        // Tests in this crate share the global level; serialise through this one test.
        disable();
        assert!(!enabled(Level::Error));
        assert_eq!(level(), None);
        init(Level::Warn);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Warn));
        assert!(!enabled(Level::Info));
        assert_eq!(level(), Some(Level::Warn));
        init(Level::Trace);
        assert!(enabled(Level::Trace));
        // The macros compile with and without fields and with a trailing comma.
        info!("plain");
        debug!("fields", a = 1, b = "two",);
        disable();
    }
}
