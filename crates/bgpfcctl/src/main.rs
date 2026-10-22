//! `bgpfcctl`: command-line client for `bgpfcd` over its Unix socket
//! (`docs/control.md`). The words on the command line are the request;
//! the daemon's body lines are printed as they are.
#![forbid(unsafe_code)]

use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;

use bgpfc_control::proto::{Request, Response};

/// The socket `contrib/bgpfc.conf` configures.
const DEFAULT_SOCKET: &str = "/run/bgpfc/bgpfc.sock";

const USAGE: &str = "\
usage: bgpfcctl [-s SOCKET] COMMAND...

  -s, --socket PATH   control socket (default /run/bgpfc/bgpfc.sock,
                      or $BGPFC_SOCKET)

commands:
  show neighbors
  show neighbor ADDR
  show routes [ipv4|ipv6] [PREFIX]
  show fib
  show status
  clear neighbor ADDR [soft] [MESSAGE]
  reload
  fib mode dry-run|install
";

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = std::env::var("BGPFC_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_owned());
    while let Some(first) = args.first() {
        match first.as_str() {
            "-s" | "--socket" => {
                if args.len() < 2 {
                    eprintln!("bgpfcctl: {first} needs a value");
                    std::process::exit(2);
                }
                socket.clone_from(&args[1]);
                args.drain(..2);
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return;
            }
            _ => break,
        }
    }
    if args.is_empty() {
        eprint!("{USAGE}");
        std::process::exit(2);
    }
    let response = match talk(&socket, &args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bgpfcctl: {socket}: {e}");
            std::process::exit(1);
        }
    };
    let out = std::io::stdout();
    let mut out = out.lock();
    for line in &response.lines {
        let _ = writeln!(out, "{line}");
    }
    if let Err(m) = response.status {
        eprintln!("bgpfcctl: {m}");
        std::process::exit(1);
    }
}

fn talk(socket: &str, words: &[String]) -> std::io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.write_all(Request::format(words).as_bytes())?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    Response::read_from(&mut reader)
}
