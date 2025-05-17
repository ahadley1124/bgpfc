#![allow(nonstandard_style)]

use std::net::{SocketAddrV4, TcpStream};
use std::io::{ Read, Write };
use std::thread;
use std::collections::HashMap;

mod connection;
mod structs;
mod impliments;

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