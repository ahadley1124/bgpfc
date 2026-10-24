//! `bgp_bench`: start a profiling `bgpfcd`, drive it with `bgp_loadgen`,
//! collect its report lines, repeat, and record the medians in
//! `bench/results.csv`, failing on a regression against the previous
//! comparable row (`docs/PROFILING.md`).
#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use bgpfc_bench::cli::Flags;
use bgpfc_bench::results::{self, Expect, Metrics, Row};
use bgpfc_bench::stats::{summarize, summarize_signed};

const USAGE: &str = "\
usage: bgp_bench [options]

  --scenario NAME     load | churn | withdraw-all | flap (default load)
  --runs N            runs to take the median of (default 5)
  --prefixes N        synthetic table size (default 1000000)
  --attr-sets N       distinct attribute sets (default 50000)
  --seed N            PRNG seed (default 1)
  --mrt FILE          replay an uncompressed TABLE_DUMP_V2 file instead
  --mrt-peer N        its peer index (default: the one with most routes)
  --rate N            churn: UPDATEs per second (default 1000)
  --duration SECS     churn: how long (default 10)
  --cycles N          flap: resets (default 3)
  --gap SECS          flap: pause before reconnecting (default 1)
  --extended          offer Extended Message (65535-octet UPDATEs)
  --spans on|off      span timing in the daemon (default on)
  --threshold PCT     a time or memory metric worse by more than this is a
                      regression: exit status 1 (default 10)
  --results FILE      CSV history (default bench/results.csv)
  --no-record         compare, but do not append a row
  --daemon PATH       bgpfcd built with --features profiling
                      (default: next to this program)
  --loadgen PATH      bgp_loadgen (default: next to this program)
  --port N            the daemon's listen port on 127.0.0.1 (default 11179)
  --timeout SECS      give up on a run after this long (default 900)
  --keep              keep each run's directory (config and logs)
";

#[derive(Debug)]
struct Opts {
    scenario: String,
    runs: u32,
    prefixes: u64,
    attr_sets: u64,
    seed: u64,
    mrt: Option<(PathBuf, Option<u16>)>,
    rate: u64,
    duration: u64,
    cycles: u32,
    gap: u64,
    extended: bool,
    /// `on` or `off`.
    spans: &'static str,
    threshold_bp: i64,
    results: PathBuf,
    record: bool,
    daemon: PathBuf,
    loadgen: PathBuf,
    port: u16,
    timeout: Duration,
    keep: bool,
}

fn main() {
    let mut flags = Flags::from_env();
    if flags.switch("-h") || flags.switch("--help") {
        print!("{USAGE}");
        return;
    }
    let opts = match parse(&mut flags) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("bgp_bench: {e}");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };
    match bench(&opts) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("bgp_bench: {e}");
            std::process::exit(2);
        }
    }
}

fn sibling(name: &str) -> PathBuf {
    std::env::current_exe().map_or_else(|_| PathBuf::from(name), |p| p.with_file_name(name))
}

fn parse(f: &mut Flags) -> Result<Opts, String> {
    let scenario = f.value("--scenario")?.unwrap_or_else(|| "load".to_owned());
    if !["load", "churn", "withdraw-all", "flap"].contains(&scenario.as_str()) {
        return Err(format!("unknown scenario {scenario}"));
    }
    let spans = match f.value("--spans")?.as_deref() {
        None | Some("on") => "on",
        Some("off") => "off",
        Some(v) => return Err(format!("--spans takes on or off, not {v}")),
    };
    let threshold: u32 = f.get_or("--threshold", 10)?;
    let mrt = f
        .get::<PathBuf>("--mrt")?
        .map(|p| Ok::<_, String>((p, f.get("--mrt-peer")?)))
        .transpose()?;
    let o = Opts {
        scenario,
        runs: f.get_or("--runs", 5u32)?.max(1),
        prefixes: f.get_or("--prefixes", 1_000_000)?,
        attr_sets: f.get_or("--attr-sets", 50_000)?,
        seed: f.get_or("--seed", 1)?,
        mrt,
        rate: f.get_or("--rate", 1000)?,
        duration: f.get_or("--duration", 10)?,
        cycles: f.get_or("--cycles", 3)?,
        gap: f.get_or("--gap", 1)?,
        extended: f.switch("--extended"),
        spans,
        threshold_bp: i64::from(threshold) * 100,
        results: f.get_or("--results", PathBuf::from("bench/results.csv"))?,
        record: !f.switch("--no-record"),
        daemon: f.get_or("--daemon", sibling("bgpfcd"))?,
        loadgen: f.get_or("--loadgen", sibling("bgp_loadgen"))?,
        port: f.get_or("--port", 11_179)?,
        timeout: Duration::from_secs(f.get_or("--timeout", 900)?),
        keep: f.switch("--keep"),
    };
    f.finish()?;
    for p in [&o.daemon, &o.loadgen] {
        if !p.exists() {
            return Err(format!(
                "{} not found; build with `cargo build --profile profiling --features profiling`",
                p.display()
            ));
        }
    }
    Ok(o)
}

/// The parameters besides scenario, size and seed that change the result.
fn params(o: &Opts) -> String {
    let mut p = match &o.mrt {
        Some((file, peer)) => format!(
            "mrt={};peer={}",
            file.file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
            peer.map_or_else(|| "auto".to_owned(), |p| p.to_string())
        ),
        None => format!("attr_sets={}", o.attr_sets),
    };
    let _ = write!(p, ";extended={};spans={}", o.extended, o.spans);
    let _ = match o.scenario.as_str() {
        "churn" => write!(p, ";rate={};duration={}", o.rate, o.duration),
        "flap" => write!(p, ";cycles={};gap={}", o.cycles, o.gap),
        _ => Ok(()),
    };
    // The CSV is comma-separated; keep the field one field.
    p.replace(',', "_")
}

/// Run everything; whether no metric regressed.
fn bench(o: &Opts) -> Result<bool, String> {
    let mut runs = Vec::new();
    let mut loaded = Vec::new();
    for n in 1..=o.runs {
        let (m, prefixes) = run_once(o, n)?;
        loaded.extend(prefixes);
        println!(
            "run {n}/{}: load_us={} updates_per_s={} bytes_per_prefix={} peak_live_bytes={} \
             peak_rss_kb={} residual_bytes={}",
            o.runs,
            show(m.load_us),
            show(m.updates_per_s),
            show(m.bytes_per_prefix),
            show(m.peak_live_bytes),
            show(m.peak_rss_kb),
            show(m.residual_bytes),
        );
        runs.push(m);
    }
    let medians = summary(&runs);
    let prefixes = if o.mrt.is_some() {
        // The file decides the size: what the daemon loaded.
        summarize(&loaded).map_or(0, |s| s.median)
    } else {
        o.prefixes
    };
    let row = Row {
        timestamp: timestamp(),
        git_rev: git(&["rev-parse", "--short", "HEAD"]).unwrap_or_default(),
        dirty: git(&["status", "--porcelain", "--untracked-files=no"])
            .map(|s| if s.is_empty() { "0" } else { "1" }.to_owned())
            .unwrap_or_default(),
        scenario: o.scenario.clone(),
        prefixes,
        seed: o.seed,
        params: params(o),
        runs: o.runs,
        metrics: medians,
    };
    let previous = results::previous(&o.results, &row.key())
        .map_err(|e| format!("{}: {e}", o.results.display()))?;
    if o.record {
        results::append(&o.results, &row).map_err(|e| format!("{}: {e}", o.results.display()))?;
        println!("recorded in {}", o.results.display());
    }
    let Some(previous) = previous else {
        println!(
            "no earlier row for scenario {} prefixes {} seed {} {}",
            row.scenario, row.prefixes, row.seed, row.params
        );
        return Ok(true);
    };
    println!(
        "against {} ({}{}), threshold {}:",
        previous.timestamp,
        if previous.git_rev.is_empty() {
            "no git"
        } else {
            &previous.git_rev
        },
        if previous.dirty == "1" { ", dirty" } else { "" },
        bgpfc_bench::stats::percent(o.threshold_bp)
    );
    let c = results::compare(&previous.metrics, &row.metrics, o.threshold_bp);
    for l in &c.lines {
        println!("  {l}");
    }
    if c.regressed.is_empty() {
        Ok(true)
    } else {
        println!("regressed: {}", c.regressed.join(", "));
        Ok(false)
    }
}

fn show<T: ToString>(v: Option<T>) -> String {
    v.map_or_else(|| "-".to_owned(), |v| v.to_string())
}

/// Medians of every metric, printed with min and max.
fn summary(runs: &[Metrics]) -> Metrics {
    fn col(runs: &[Metrics], f: impl Fn(&Metrics) -> Option<u64>) -> Vec<u64> {
        runs.iter().filter_map(f).collect()
    }
    println!(
        "{:18} {:>14} {:>14} {:>14}",
        "metric", "median", "min", "max"
    );
    let mut out = Metrics::default();
    let cols: [(&str, Vec<u64>, &mut Option<u64>); 5] = [
        ("load_us", col(runs, |m| m.load_us), &mut out.load_us),
        (
            "updates_per_s",
            col(runs, |m| m.updates_per_s),
            &mut out.updates_per_s,
        ),
        (
            "bytes_per_prefix",
            col(runs, |m| m.bytes_per_prefix),
            &mut out.bytes_per_prefix,
        ),
        (
            "peak_live_bytes",
            col(runs, |m| m.peak_live_bytes),
            &mut out.peak_live_bytes,
        ),
        (
            "peak_rss_kb",
            col(runs, |m| m.peak_rss_kb),
            &mut out.peak_rss_kb,
        ),
    ];
    for (name, values, slot) in cols {
        if let Some(s) = summarize(&values) {
            println!("{name:18} {:>14} {:>14} {:>14}", s.median, s.min, s.max);
            *slot = Some(s.median);
        }
    }
    let residuals: Vec<i64> = runs.iter().filter_map(|m| m.residual_bytes).collect();
    if let Some((median, min, max)) = summarize_signed(&residuals) {
        println!("{:18} {median:>14} {min:>14} {max:>14}", "residual_bytes");
        out.residual_bytes = Some(median);
    }
    out
}

fn timestamp() -> String {
    // The log line's own UTC timestamp: std has no calendar.
    bgpfc_log::format_line(SystemTime::now(), bgpfc_log::Level::Info, "", &[])
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

enum Msg {
    Daemon(String),
    DaemonGone,
    Loadgen(String),
    LoadgenGone,
}

/// Copy `from` line by line to `log` and send each line (profile lines
/// only, when `only_profile`), then `gone` at the end.
fn tee(
    from: impl std::io::Read + Send + 'static,
    log: PathBuf,
    tx: Sender<Msg>,
    wrap: fn(String) -> Msg,
    gone: Msg,
    only_profile: bool,
) {
    thread::spawn(move || {
        let mut file = fs::File::create(&log).ok();
        for line in BufReader::new(from).lines().map_while(Result::ok) {
            if let Some(f) = &mut file {
                let _ = writeln!(f, "{line}");
            }
            if (!only_profile || line.contains("msg=\"profile\"")) && tx.send(wrap(line)).is_err() {
                return;
            }
        }
        let _ = tx.send(gone);
    });
}

/// Copy `from` to `log`.
fn copy(mut from: impl std::io::Read + Send + 'static, log: PathBuf) {
    thread::spawn(move || {
        if let Ok(mut f) = fs::File::create(&log) {
            let _ = std::io::copy(&mut from, &mut f);
        }
    });
}

fn config(o: &Opts, dir: &Path) -> String {
    format!(
        "router-id 192.0.2.1;\nlocal-as 65000;\nlog {{ level warn; }}\n\
         listen {{ address 127.0.0.1; port {}; }}\nfib {{ mode dry-run; }}\n\
         control {{ socket {}; }}\npolicy ANY {{ term all {{ action accept; }} }}\n\
         neighbor 127.0.0.1 {{ remote-as 65001; passive yes; hold-time 90;\n    \
         families ipv4-unicast ipv6-unicast; import ANY; export ANY; }}\n",
        o.port,
        dir.join("ctl.sock").display()
    )
}

fn loadgen_args(o: &Opts) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "--connect".into(),
        format!("127.0.0.1:{}", o.port),
        "--scenario".into(),
        o.scenario.clone(),
        "--seed".into(),
        o.seed.to_string(),
    ];
    // Only what the scenario reads: bgp_loadgen refuses the rest.
    match o.scenario.as_str() {
        "churn" => a.extend([
            "--rate".into(),
            o.rate.to_string(),
            "--duration".into(),
            o.duration.to_string(),
        ]),
        "flap" => a.extend([
            "--cycles".into(),
            o.cycles.to_string(),
            "--gap".into(),
            o.gap.to_string(),
        ]),
        _ => {}
    }
    if let Some((file, peer)) = &o.mrt {
        a.push("--mrt".into());
        a.push(file.display().to_string());
        if let Some(p) = peer {
            a.push("--mrt-peer".into());
            a.push(p.to_string());
        }
    } else {
        a.extend(["--prefixes".into(), o.prefixes.to_string()]);
        a.extend(["--attr-sets".into(), o.attr_sets.to_string()]);
    }
    if o.extended {
        a.push("--extended".into());
    }
    a
}

/// One run: daemon up, loadgen through the scenario, daemon down; the
/// metrics from its report lines and the prefixes it loaded.
fn run_once(o: &Opts, n: u32) -> Result<(Metrics, Option<u64>), String> {
    let dir = std::env::temp_dir().join(format!("bgp-bench-{}-{n}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let conf = dir.join("bgpfcd.conf");
    fs::write(&conf, config(o, &dir)).map_err(|e| format!("{}: {e}", conf.display()))?;
    let (tx, rx) = mpsc::channel();

    let mut daemon = Command::new(&o.daemon)
        .arg("-c")
        .arg(&conf)
        .env("BGP_PROFILE_SPANS", if o.spans == "on" { "1" } else { "0" })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", o.daemon.display()))?;
    if let Some(err) = daemon.stderr.take() {
        tee(
            err,
            dir.join("bgpfcd.log"),
            tx.clone(),
            Msg::Daemon,
            Msg::DaemonGone,
            true,
        );
    }
    let mut loadgen = Command::new(&o.loadgen)
        .args(loadgen_args(o))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", o.loadgen.display()))?;
    if let Some(out) = loadgen.stdout.take() {
        tee(
            out,
            dir.join("loadgen.log"),
            tx,
            Msg::Loadgen,
            Msg::LoadgenGone,
            false,
        );
    }
    if let Some(err) = loadgen.stderr.take() {
        copy(err, dir.join("loadgen.err"));
    }

    let result = collect(o, &rx, &dir);
    // Shut the daemon down cleanly (its shutdown report goes to the log),
    // then the loadgen, which sees the Cease.
    let _ = Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status();
    let daemon_ok = wait(&mut daemon, Duration::from_secs(60));
    let _ = wait(&mut loadgen, Duration::from_secs(15));
    if result.is_ok() && !o.keep {
        let _ = fs::remove_dir_all(&dir);
    } else {
        eprintln!("bgp_bench: logs of run {n} kept in {}", dir.display());
    }
    if daemon_ok.is_none() {
        eprintln!("bgp_bench: bgpfcd did not stop on SIGTERM; killed");
    }
    result
}

/// Wait for the scenario's events.
fn collect(o: &Opts, rx: &Receiver<Msg>, dir: &Path) -> Result<(Metrics, Option<u64>), String> {
    let expect = Expect::of(&o.scenario, o.cycles);
    let deadline = Instant::now() + o.timeout;
    let mut events: Vec<String> = Vec::new();
    while !expect.met(&events) {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Msg::Daemon(line)) => events.push(line),
            Ok(Msg::Loadgen(line)) => {
                if line.contains("phase=") {
                    println!("  {line}");
                }
            }
            Ok(Msg::DaemonGone) => {
                return Err(format!(
                    "bgpfcd exited early; see {} (is it built with --features profiling?)",
                    dir.join("bgpfcd.log").display()
                ));
            }
            Ok(Msg::LoadgenGone) => {
                return Err(format!(
                    "bgp_loadgen exited early; see {}",
                    dir.join("loadgen.err").display()
                ));
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err(format!("no result within {:?}", o.timeout));
            }
            Err(RecvTimeoutError::Disconnected) => return Err("lost both processes".to_owned()),
        }
    }
    // The duplication line follows the table load immediately.
    while let Ok(Msg::Daemon(line)) = rx.recv_timeout(Duration::from_millis(500)) {
        events.push(line);
    }
    Ok((
        results::metrics(&o.scenario, &events),
        results::prefixes_loaded(&events),
    ))
}

fn wait(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(s)) = child.try_wait() {
            return Some(s);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}
