#![allow(nonstandard_style)]

use std::net::{SocketAddrV4, TcpStream};
use std::io::{ Read, Write };
use std::thread;

mod connection;
mod structs;
mod impliments;
mod setup;

fn parse_header(input: [u8; 1024]) -> Result<structs::Header, &'static str> {
    let header = structs::Header::from_bytes(&input[0..19])?;
    Ok(header)
}

fn my_open_message() -> structs::openMessage {
    let header = structs::Header::new([255; 16], 0, 1);
    let version = 4;
    let my_asn = 65500;
    let hold_time = 300;
    let bgp_id: u32 = u32::from_be_bytes([10, 0, 1, 136]);
    let opt_param_len = 0;
    let opt_params = Vec::new();
    structs::openMessage::new(header, version, my_asn, hold_time, bgp_id, opt_param_len, opt_params)
}

fn init_peer(stream: &mut std::net::TcpStream) -> Result<&mut std::net::TcpStream, &'static str> {
    println!("Accepted connection from {}", stream.peer_addr().unwrap());
    let open_message = my_open_message();
    let open_message_bytes = open_message.to_bytes();
    #[cfg(debug_assertions)]
    println!("Sending open message: {:?}", open_message);
    if let Err(e) = stream.write_all(&open_message_bytes) {
        eprintln!("Failed to send open message: {}", e);
        return Err("Failed to send open message");
    } else {
        #[cfg(debug_assertions)]
        println!("Sent open message");
    }
    #[cfg(debug_assertions)]
    println!("Sent open message: {:?}", open_message);
    // Send keepalive message after sending open message
    let keepalive = structs::keepaliveMessage::new(open_message.header);
    let keepalive_bytes = keepalive.to_bytes();
    if let Err(e) = stream.write_all(&keepalive_bytes) {
        eprintln!("Failed to send keepalive: {}", e);
        return Err("Failed to send keepalive");
    } else {
        #[cfg(debug_assertions)]
        println!("Sent keepalive message");
    }
    stream.flush().unwrap();
    Ok(stream)
}

fn main() {
    // Load configuration
    let config = setup::json::main();
    let config = match config {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            return;
        }
    };
    let addr = SocketAddrV4::new("0.0.0.0".parse().unwrap(), 179);
    let listener = connection::bind_socket(addr).unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    //upon accepting a new connection, move it to a new thread
    let mut streams: Vec<TcpStream> = Vec::new();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                streams.push(stream.try_clone().unwrap());
                thread::spawn(move || {
                    if let Err(e) = init_peer(&mut stream) {
                        eprintln!("Failed to initialize peer: {}", e);
                    }
                    let mut buffer = vec![0; 1024];
                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                #[cfg(debug_assertions)]
                                println!("Received {} bytes", n);
                                //parse the header
                                let mut header_buf = [0u8; 1024];
                                header_buf[..n].copy_from_slice(&buffer[..n]);
                                match parse_header(header_buf) {
                                    Ok(header) => {
                                        #[cfg(debug_assertions)]
                                        println!("Parsed header: {:?}", header);
                                    }
                                    Err(e) => eprintln!("Failed to parse header: {}", e),
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to read from stream: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => eprintln!("Failed to accept connection: {}", e),
        }
    }
    // The following code is unreachable because of the infinite loop above.
    // If you want to support graceful shutdown, refactor the loop to break on some condition.
}

#[test]
fn test_open_message() {
    let mut open_message: [u8; 1024] = [0; 1024];
    let bytes: [u8; 29] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x1d, 0x01, 0x04, 0xff, 0xdc, 0xff, 0xdc,
        0x0a, 0x00, 0x01, 0x88, 0x00,
    ];
    open_message[..bytes.len()].copy_from_slice(&bytes);
    println!("open_message: {:?}", open_message);
    println!("open_message length: {}", open_message.len());
    let parsed_header = structs::Header::from_bytes(&open_message[0..19]).unwrap();
    println!("Parsed header: {:?}", parsed_header);
    let parsed_open_message = structs::openMessage::from_bytes(&open_message[..29]).unwrap();
    println!("Parsed open message: {:?}", parsed_open_message);
    assert_eq!(open_message, parsed_open_message.to_bytes());
}

#[test]
fn test_update_message() {
    let update_message: [u8; 41] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x0e, 0x40,
        0x01, 0x01, 0x00, 0x40, 0x02, 0x00, 0x40, 0x03,
        0x04, 0x0a, 0x00, 0x00, 0x01, 0x18, 0x17, 0xbe,
        0xd8,
    ];
    println!("update_message: {:?}", update_message);
    println!("update_message length: {}", update_message.len());
    let parsed_header = structs::Header::from_bytes(&update_message[0..19]).unwrap();
    println!("Parsed header: {:?}", parsed_header);
    let parsed_update_message = structs::updateMessage::from_bytes(&update_message[..]).unwrap();
    println!("Parsed update message: {:?}", parsed_update_message);
    assert_eq!(update_message.as_ref(), parsed_update_message.to_bytes().as_slice());
}
