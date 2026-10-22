//! `rtr-stub`: a minimal RPKI cache (RFC 8210) for the interop tests,
//! for the one scenario `StayRTR` cannot be used for: a cache that
//! restarts and brings the router back in sync.
//!
//! A cache that restarts starts a new session with a new Session ID
//! (RFC 8210 §5.1), and the router resumes with a Serial Query for the
//! old one (§8.1). `StayRTR` 0.5.1 closes the connection on that query
//! without a word, so the router never syncs with it again until its data
//! expires. This stub answers as RFC 8210 §8.3 has a cache that "cannot
//! supply an incremental update from the Serial Number specified by the
//! router" answer, for instance because it "has lost state": with a Cache
//! Reset, after which the router asks for everything with a Reset Query.
//! Routinator does the same.
//!
//! ```text
//! rtr-stub BIND SESSION-ID VRP...
//! ```
//!
//! `BIND` is the address and port to listen on, `SESSION-ID` the Session
//! ID of this run, and each `VRP` is written `PREFIX-MAXLEN-ASN`, such as
//! `192.0.2.0/24-24-65001`. The stub serves those VRPs as serial 1 of the
//! session to every router that connects, in the protocol version of the
//! router's query (RFC 8210 §7):
//!
//! - a Reset Query gets a Cache Response, a Prefix PDU per VRP and an End
//!   of Data (§8.1);
//! - a Serial Query for serial 1 of this session gets a Cache Response and
//!   an End of Data, since nothing changed (§8.2);
//! - any other Serial Query, such as one for the session of an earlier
//!   run, gets a Cache Reset (§8.3).
//!
//! Anything else ends the connection. Each query and its answer are
//! logged on stderr, one line each.
#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;

use bgpfc_rpki::Vrp;
use bgpfc_rtr::{Framer, Intervals, Pdu, Version};
use bgpfc_wire::types::Asn;

/// The one serial the stub serves.
const SERIAL: u32 = 1;

/// What every connection is served.
struct Data {
    session_id: u16,
    vrps: Vec<Vrp>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (bind, session_id, vrps) = match parse(&args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("rtr-stub: {e}\nusage: rtr-stub BIND SESSION-ID PREFIX-MAXLEN-ASN...");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(bind) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("rtr-stub: binding {bind}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "listening on {bind}: session {session_id} serial {SERIAL}, {} VRPs",
        vrps.len()
    );
    let data = Arc::new(Data { session_id, vrps });
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let data = Arc::clone(&data);
                thread::spawn(move || serve(stream, &data));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    ExitCode::SUCCESS
}

/// The arguments: where to listen, the Session ID and the VRPs.
fn parse(args: &[String]) -> Result<(&str, u16, Vec<Vrp>), String> {
    let [bind, session_id, vrps @ ..] = args else {
        return Err("too few arguments".to_owned());
    };
    let session_id = session_id
        .parse()
        .map_err(|e| format!("Session ID {session_id}: {e}"))?;
    let vrps = vrps
        .iter()
        .map(|arg| vrp(arg).ok_or_else(|| format!("bad VRP {arg}")))
        .collect::<Result<_, _>>()?;
    Ok((bind, session_id, vrps))
}

/// `PREFIX-MAXLEN-ASN` as a VRP.
fn vrp(arg: &str) -> Option<Vrp> {
    let mut parts = arg.rsplitn(3, '-');
    let asn = parts.next()?.parse().ok()?;
    let max_len = parts.next()?.parse().ok()?;
    let prefix = parts.next()?.parse().ok()?;
    Vrp::new(prefix, max_len, Asn(asn)).ok()
}

/// Answer the queries of one router until it closes the connection or
/// sends something that is not a query.
fn serve(mut stream: TcpStream, data: &Data) {
    let peer = stream
        .peer_addr()
        .map_or_else(|_| "?".to_owned(), |a| a.to_string());
    eprintln!("{peer}: connected");
    let mut framer = Framer::new();
    let mut buf = [0; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => {
                eprintln!("{peer}: closed by the router");
                return;
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("{peer}: {e}");
                return;
            }
        };
        framer.feed(&buf[..n]);
        loop {
            let pdu = match framer.next_pdu() {
                Ok(Some(pdu)) => pdu,
                Ok(None) => break,
                Err(e) => {
                    eprintln!("{peer}: {e}; closing");
                    return;
                }
            };
            let Some((answer, what)) = answer(&pdu, data) else {
                eprintln!("{peer}: {} PDU; closing", pdu.pdu_type());
                return;
            };
            eprintln!("{peer}: {}: {what}", describe(&pdu));
            if let Err(e) = stream.write_all(&answer) {
                eprintln!("{peer}: {e}");
                return;
            }
        }
    }
}

/// The octets that answer `query`, and what they are, for the log; `None`
/// for a PDU that is not a query.
fn answer(query: &Pdu, data: &Data) -> Option<(Vec<u8>, String)> {
    let version = query.version();
    let current = match *query {
        Pdu::ResetQuery { .. } => false,
        Pdu::SerialQuery {
            session_id, serial, ..
        } => {
            if session_id != data.session_id || serial != SERIAL {
                // RFC 8210 §8.3: "the cache replies with a Cache Reset to
                // tell the router that it cannot honor the request."
                return Some((
                    Pdu::CacheReset { version }.encode(),
                    "Cache Reset".to_owned(),
                ));
            }
            true
        }
        _ => return None,
    };
    let mut out = Pdu::CacheResponse {
        version,
        session_id: data.session_id,
    }
    .encode();
    // RFC 8210 §5.5: a reply to a Reset Query announces the whole data
    // set; one to a Serial Query, the changes since, of which there are
    // none.
    let vrps: &[Vrp] = if current { &[] } else { &data.vrps };
    for &vrp in vrps {
        Pdu::Prefix {
            version,
            announce: true,
            vrp,
        }
        .encode_into(&mut out);
    }
    Pdu::EndOfData {
        session_id: data.session_id,
        serial: SERIAL,
        // RFC 8210 §5.8: the intervals are in version 1 only.
        intervals: (version == Version::V1).then_some(Intervals::DEFAULT),
    }
    .encode_into(&mut out);
    Some((
        out,
        format!(
            "Cache Response, {} VRPs, End of Data session {} serial {SERIAL}",
            vrps.len(),
            data.session_id
        ),
    ))
}

/// A query for the log: its type and version, and for a Serial Query the
/// session and serial it asks about.
fn describe(query: &Pdu) -> String {
    let base = format!("{} v{}", query.pdu_type(), query.version());
    match query {
        Pdu::SerialQuery {
            session_id, serial, ..
        } => format!("{base} session {session_id} serial {serial}"),
        _ => base,
    }
}
