//! Command-line arguments. A stop-gap until the configuration language of
//! milestone 4: enough to bring up sessions.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bgpfc_fsm::{Config, SendHoldTime};
use bgpfc_wire::capability::Capability;
use bgpfc_wire::types::{AddressFamily, Asn, HoldTime, RouterId};

use crate::peer::PeerConfig;

/// Usage text, also printed on a bad argument.
pub(crate) const USAGE: &str = "\
usage: bgpfcd --local-as AS --router-id A.B.C.D [options] --neighbor ADDR --remote-as AS [neighbor options] ...

options:
  --listen ADDR:PORT      listen address (repeatable; default [::]:179)
  --log-level LEVEL       error | warn | info | debug | trace (default info)
  --hold-time SECONDS     default hold time for all neighbors (default 90)

neighbor options (apply to the preceding --neighbor):
  --remote-as AS          the neighbor's AS (required)
  --port PORT             TCP port to connect to (default 179)
  --passive               never initiate the TCP connection
  --hold-time SECONDS     hold time for this neighbor
  --allow-as-set          accept AS_SET in UPDATEs (RFC 9774 override)
";

/// Parsed arguments.
#[derive(Debug)]
pub(crate) struct Args {
    /// Where to listen.
    pub(crate) listen: Vec<SocketAddr>,
    /// Log level.
    pub(crate) log_level: bgpfc_log::Level,
    /// Neighbours.
    pub(crate) peers: Vec<PeerConfig>,
}

/// Parse `argv[1..]`.
///
/// # Errors
/// A message to print, followed by [`USAGE`].
pub(crate) fn parse(args: &[String]) -> Result<Args, String> {
    let mut local_as = None;
    let mut router_id = None;
    let mut listen = Vec::new();
    let mut log_level = bgpfc_log::Level::Info;
    let mut hold_time = HoldTime::new(90).unwrap_or(HoldTime::ZERO);
    let mut neighbors: Vec<Neighbor> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = || {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        let mut used_value = true;
        match flag {
            "--local-as" => local_as = Some(parse_asn(&value()?)?),
            "--router-id" => {
                let ip: std::net::Ipv4Addr =
                    value()?.parse().map_err(|_| "bad --router-id".to_owned())?;
                router_id = Some(RouterId::new(u32::from(ip)).ok_or("router id must not be 0")?);
            }
            "--listen" => listen.push(
                value()?
                    .parse()
                    .map_err(|_| "bad --listen address".to_owned())?,
            ),
            "--log-level" => {
                log_level = bgpfc_log::Level::parse(&value()?).ok_or("bad --log-level")?;
            }
            "--hold-time" => {
                let secs: u16 = value()?.parse().map_err(|_| "bad --hold-time".to_owned())?;
                let h = HoldTime::new(secs).ok_or("hold time must be 0 or at least 3")?;
                match neighbors.last_mut() {
                    Some(n) => n.hold_time = Some(h),
                    None => hold_time = h,
                }
            }
            "--neighbor" => {
                let addr: IpAddr = value()?
                    .parse()
                    .map_err(|_| "bad --neighbor address".to_owned())?;
                neighbors.push(Neighbor {
                    addr,
                    remote_as: None,
                    port: 179,
                    passive: false,
                    hold_time: None,
                    allow_as_set: false,
                });
            }
            "--remote-as" => current(&mut neighbors, flag)?.remote_as = Some(parse_asn(&value()?)?),
            "--port" => {
                current(&mut neighbors, flag)?.port =
                    value()?.parse().map_err(|_| "bad --port".to_owned())?;
            }
            "--passive" => {
                current(&mut neighbors, flag)?.passive = true;
                used_value = false;
            }
            "--allow-as-set" => {
                current(&mut neighbors, flag)?.allow_as_set = true;
                used_value = false;
            }
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other}")),
        }
        i += if used_value { 2 } else { 1 };
    }
    let local_as = local_as.ok_or("--local-as is required")?;
    let router_id = router_id.ok_or("--router-id is required")?;
    if neighbors.is_empty() {
        return Err("at least one --neighbor is required".to_owned());
    }
    if listen.is_empty() {
        listen.push(
            "[::]:179"
                .parse()
                .map_err(|_| "default listen".to_owned())?,
        );
    }
    let peers = neighbors
        .into_iter()
        .map(|n| n.into_peer(local_as, router_id, hold_time))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Args {
        listen,
        log_level,
        peers,
    })
}

struct Neighbor {
    addr: IpAddr,
    remote_as: Option<Asn>,
    port: u16,
    passive: bool,
    hold_time: Option<HoldTime>,
    allow_as_set: bool,
}

impl Neighbor {
    fn into_peer(
        self,
        local_as: Asn,
        router_id: RouterId,
        hold_time: HoldTime,
    ) -> Result<PeerConfig, String> {
        let remote_as = self
            .remote_as
            .ok_or_else(|| format!("--neighbor {} needs --remote-as", self.addr))?;
        let mut fsm = Config::new(local_as, router_id, remote_as);
        fsm.hold_time = self.hold_time.unwrap_or(hold_time);
        fsm.passive = self.passive;
        fsm.send_hold_time = SendHoldTime::Default;
        fsm.capabilities = vec![
            Capability::Multiprotocol(AddressFamily::IPV4_UNICAST),
            Capability::Multiprotocol(AddressFamily::IPV6_UNICAST),
            Capability::RouteRefresh,
            Capability::ExtendedMessage,
        ];
        // RFC 4271 §10: jitter from something that differs per process.
        fsm.jitter_seed = jitter_seed(self.addr);
        Ok(PeerConfig {
            addr: self.addr,
            port: self.port,
            fsm,
            allow_as_set: self.allow_as_set,
        })
    }
}

fn current<'a>(neighbors: &'a mut [Neighbor], flag: &str) -> Result<&'a mut Neighbor, String> {
    neighbors
        .last_mut()
        .ok_or_else(|| format!("{flag} must follow --neighbor"))
}

/// Plain or `asdot`-free ASN; AS 0 is never valid (RFC 7607 §2).
fn parse_asn(s: &str) -> Result<Asn, String> {
    let n: u32 = s.parse().map_err(|_| format!("bad AS number {s}"))?;
    if n == 0 {
        return Err("AS 0 is reserved (RFC 7607)".to_owned());
    }
    Ok(Asn(n))
}

/// A seed that differs per process and per peer, from the clock and the
/// hasher's random keys; std has no RNG.
fn jitter_seed(addr: IpAddr) -> u64 {
    use std::hash::{BuildHasher, Hash, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    addr.hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos()
        .hash(&mut h);
    h.finish() | 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_a_full_command_line() {
        let a = parse(&argv(
            "--local-as 65000 --router-id 192.0.2.1 --listen 127.0.0.1:1179 --log-level debug \
             --hold-time 30 --neighbor 192.0.2.2 --remote-as 65001 --port 1179 --passive \
             --neighbor 2001:db8::2 --remote-as 4200000000 --hold-time 9 --allow-as-set",
        ))
        .unwrap();
        assert_eq!(a.listen, vec!["127.0.0.1:1179".parse().unwrap()]);
        assert_eq!(a.log_level, bgpfc_log::Level::Debug);
        assert_eq!(a.peers.len(), 2);
        let p = &a.peers[0];
        assert_eq!(p.addr, "192.0.2.2".parse::<IpAddr>().unwrap());
        assert_eq!(p.port, 1179);
        assert!(p.fsm.passive);
        assert_eq!(p.fsm.remote_as, Asn(65_001));
        assert_eq!(p.fsm.local_as, Asn(65_000));
        assert_eq!(p.fsm.hold_time.secs(), 30);
        assert!(!p.allow_as_set);
        let q = &a.peers[1];
        assert_eq!(q.fsm.remote_as, Asn(4_200_000_000));
        assert_eq!(q.fsm.hold_time.secs(), 9);
        assert!(q.allow_as_set);
        assert_eq!(q.port, 179);
        assert_ne!(p.fsm.jitter_seed, 0);
    }

    #[test]
    fn defaults_and_errors() {
        let a = parse(&argv(
            "--local-as 1 --router-id 1.1.1.1 --neighbor 10.0.0.1 --remote-as 2",
        ))
        .unwrap();
        assert_eq!(a.listen, vec!["[::]:179".parse().unwrap()]);
        assert_eq!(a.peers[0].fsm.hold_time.secs(), 90);
        for bad in [
            "--router-id 1.1.1.1 --neighbor 10.0.0.1 --remote-as 2",
            "--local-as 1 --neighbor 10.0.0.1 --remote-as 2",
            "--local-as 1 --router-id 1.1.1.1",
            "--local-as 1 --router-id 1.1.1.1 --neighbor 10.0.0.1",
            "--local-as 0 --router-id 1.1.1.1 --neighbor 10.0.0.1 --remote-as 2",
            "--local-as 1 --router-id 0.0.0.0 --neighbor 10.0.0.1 --remote-as 2",
            "--local-as 1 --router-id 1.1.1.1 --remote-as 2 --neighbor 10.0.0.1",
            "--local-as 1 --router-id 1.1.1.1 --neighbor 10.0.0.1 --remote-as 2 --hold-time 2",
            "--local-as 1 --router-id 1.1.1.1 --neighbor 10.0.0.1 --remote-as 2 --bogus",
            "--local-as",
        ] {
            assert!(parse(&argv(bad)).is_err(), "{bad}");
        }
    }
}
