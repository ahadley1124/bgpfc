//! Connection reader thread: frames and decodes messages from one TCP
//! connection and hands them to the peer thread.
//!
//! Implements: RFC 4271 §4.1 framing via `bgpfc-wire`; RFC 8654 §4 (the
//! message size limit follows the negotiated Extended Message flag, which
//! the peer thread flips once the session is up).

use std::io::Read;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;

use bgpfc_wire::error::DecodeError;
use bgpfc_wire::header::{HEADER_LEN, Header, MessageType};
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::route_refresh::RouteRefreshMessage;

use crate::messages::{ConnId, Inbound, PeerInput};

/// Read messages from `stream` until it closes or a message cannot be
/// framed, sending each outcome to `tx`. Runs on its own thread; returns
/// when the connection ends or the peer thread is gone.
pub(crate) fn run(
    mut stream: TcpStream,
    conn: ConnId,
    extended: &AtomicBool,
    tx: &SyncSender<PeerInput>,
) {
    let mut header = [0u8; HEADER_LEN];
    let mut body = Vec::new();
    loop {
        if stream.read_exact(&mut header).is_err() {
            let _ = tx.send(PeerInput::Closed { conn });
            return;
        }
        let message = match Header::decode(&header, extended.load(Ordering::Relaxed)) {
            Ok(h) => {
                body.resize(h.body_len(), 0);
                if stream.read_exact(&mut body).is_err() {
                    let _ = tx.send(PeerInput::Closed { conn });
                    return;
                }
                decode(h.kind, &body)
            }
            Err(e) => Err(e),
        };
        let fatal = message.is_err();
        if tx.send(PeerInput::Message { conn, message }).is_err() {
            return;
        }
        if fatal {
            // The peer thread will send the NOTIFICATION and close; nothing
            // after a framing error can be trusted (RFC 4271 §6.1).
            return;
        }
    }
}

/// Decode a body into the typed message its header announced. UPDATEs are
/// left raw for the peer thread, which has the session context.
fn decode(kind: MessageType, body: &[u8]) -> Result<Inbound, DecodeError> {
    Ok(match kind {
        MessageType::Open => Inbound::Open(OpenMessage::decode(body)?),
        MessageType::Update => Inbound::Update(body.to_vec()),
        MessageType::Notification => {
            // The header's 21-octet minimum guarantees two octets.
            NotificationMessage::decode(body).map_or(Inbound::Keepalive, Inbound::Notification)
        }
        MessageType::Keepalive => Inbound::Keepalive,
        MessageType::RouteRefresh => Inbound::RouteRefresh(RouteRefreshMessage::decode(body)?),
    })
}
