//! `bgp_loadgen`: a BGP speaker that loads `bgpfcd` with a synthetic or
//! MRT table and then runs a scenario (`docs/PROFILING.md`).
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::Duration;

use bgpfc_bench::cli::Flags;
use bgpfc_bench::mrt;
use bgpfc_bench::scenario::{Plan, Scenario, Source, run};
use bgpfc_bench::speaker::{Endpoint, SpeakerOpts};
use bgpfc_wire::types::{Asn, HoldTime, RouterId};

const USAGE: &str = "\
usage: bgp_loadgen (--connect ADDR:PORT | --listen ADDR:PORT) [options]

session:
  --connect ADDR:PORT   connect to the daemon (it has us as a passive neighbor)
  --listen ADDR:PORT    wait for the daemon to connect
  --asn N               our AS (default 65001)
  --router-id A.B.C.D   our BGP Identifier (default 192.0.2.254)
  --hold-time SECS      proposed Hold Time (default 90)
  --extended            offer Extended Message (RFC 8654): 65535-octet UPDATEs
  --timeout SECS        keep trying to set up a session this long (default 60)

table (synthetic unless --mrt):
  --prefixes N          IPv4 prefixes (default 1000000)
  --attr-sets N         distinct attribute sets / AS_PATHs (default 50000)
  --seed N              PRNG seed for the table and churn (default 1)
  --next-hop A,B,...    next hops to draw from (default 192.0.2.1-4)
  --mrt FILE            replay one peer of an uncompressed TABLE_DUMP_V2 file
  --mrt-peer N          its peer index (default: the one with most routes)
  --mrt-list            print the file's peers and route counts, then exit

scenario:
  --scenario NAME       load | churn | withdraw-all | flap (default load)
  --rate N              churn: UPDATEs per second (default 1000)
  --duration SECS       churn: how long (default 10)
  --cycles N            flap: how many resets (default 3)
  --gap SECS            flap: pause before reconnecting (default 1)
  --hold SECS           afterwards keep the session SECS seconds
                        (default: until the daemon closes it)
";

fn main() {
    let mut flags = Flags::from_env();
    if flags.switch("-h") || flags.switch("--help") {
        print!("{USAGE}");
        return;
    }
    match plan(&mut flags) {
        Ok(None) => {}
        Ok(Some(plan)) => {
            let stdout = std::io::stdout();
            if let Err(e) = run(&plan, &mut stdout.lock()) {
                eprintln!("bgp_loadgen: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("bgp_loadgen: {e}");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
}

fn secs(flags: &mut Flags, name: &str, default: u64) -> Result<Duration, String> {
    Ok(Duration::from_secs(flags.get_or(name, default)?))
}

/// The run the flags ask for; `None` when there is nothing to run.
fn plan(flags: &mut Flags) -> Result<Option<Plan>, String> {
    let connect: Option<SocketAddr> = flags.get("--connect")?;
    let listen: Option<SocketAddr> = flags.get("--listen")?;
    let mrt_file: Option<PathBuf> = flags.get("--mrt")?;
    let mrt_peer: Option<u16> = flags.get("--mrt-peer")?;
    if flags.switch("--mrt-list") {
        let path = mrt_file.ok_or("--mrt-list needs --mrt FILE")?;
        flags.finish()?;
        list_peers(&path)?;
        return Ok(None);
    }
    let seed = flags.get_or("--seed", 1u64)?;
    let source = match &mrt_file {
        Some(path) => {
            let routes =
                mrt::load_file(path, mrt_peer).map_err(|e| format!("{}: {e}", path.display()))?;
            println!(
                "loadgen event=mrt peer={} peer_as={} routes={} attr_sets={} skipped={}",
                routes.peer.addr,
                routes.peer.asn.0,
                routes.routes.len(),
                routes.sets.len(),
                routes.skipped
            );
            Source::Mrt(routes)
        }
        None => Source::Synthetic {
            prefixes: flags.get_or("--prefixes", 1_000_000usize)?,
            attr_sets: flags.get_or("--attr-sets", 50_000usize)?,
            seed,
            next_hops: match flags.value("--next-hop")? {
                Some(list) => list
                    .split(',')
                    .map(|a| a.parse().map_err(|_| format!("bad next hop {a}")))
                    .collect::<Result<Vec<Ipv4Addr>, _>>()?,
                None => (1..=4).map(|i| Ipv4Addr::new(192, 0, 2, i)).collect(),
            },
        },
    };
    let scenario = match flags.value("--scenario")?.as_deref().unwrap_or("load") {
        "load" => Scenario::Load,
        "churn" => Scenario::Churn {
            rate: flags.get_or("--rate", 1000u64)?.max(1),
            duration: secs(flags, "--duration", 10)?,
        },
        "withdraw-all" => Scenario::WithdrawAll,
        "flap" => Scenario::Flap {
            cycles: flags.get_or("--cycles", 3u32)?,
            gap: secs(flags, "--gap", 1)?,
        },
        other => return Err(format!("unknown scenario {other}")),
    };
    let endpoint = match (connect, listen) {
        (Some(a), None) => Endpoint::Connect(a),
        (None, Some(a)) => {
            Endpoint::Listen(TcpListener::bind(a).map_err(|e| format!("listen {a}: {e}"))?)
        }
        _ => return Err("give one of --connect and --listen".to_owned()),
    };
    let router_id: Ipv4Addr = flags.get_or("--router-id", Ipv4Addr::new(192, 0, 2, 254))?;
    let hold = flags.get_or("--hold-time", 90u16)?;
    let speaker = SpeakerOpts {
        asn: Asn(flags.get_or("--asn", 65_001u32)?),
        router_id: RouterId::new(u32::from(router_id))
            .ok_or("the router ID must not be 0.0.0.0")?,
        hold_time: HoldTime::new(hold).ok_or("the hold time is 0 or at least 3")?,
        families: source.families(),
        extended: flags.switch("--extended"),
    };
    let plan = Plan {
        endpoint,
        speaker,
        source,
        scenario,
        seed,
        hold: flags.get::<u64>("--hold")?.map(Duration::from_secs),
        timeout: secs(flags, "--timeout", 60)?,
    };
    flags.finish()?;
    Ok(Some(plan))
}

fn list_peers(path: &std::path::Path) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (index, counts) = mrt::peer_counts(std::io::BufReader::new(file))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    println!("collector {} view {:?}", index.collector, index.view);
    println!(
        "{:>5}  {:<40} {:>10} {:>9}",
        "index", "address", "as", "routes"
    );
    for (i, (p, n)) in index.peers.iter().zip(&counts).enumerate() {
        println!("{i:>5}  {:<40} {:>10} {n:>9}", p.addr, p.asn.0);
    }
    Ok(())
}
