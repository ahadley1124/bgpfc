#![allow(nonstandard_style)]

use std::net::{SocketAddrV4, TcpStream};
use std::io::{ Read, Write };
use std::thread;

mod config;
mod structs;
mod impliments;

fn main() {
    let socket: thread::JoinHandle<()> = socket();
    let mut stream = TcpStream::connect("127.0.0.1:179").unwrap();
    let message = b"Hello, BGP!";
    stream.write_all(message).unwrap();
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();
    println!("Received from server: {:?}", &buffer);
    socket.join().unwrap();
}

pub fn socket() -> std::thread::JoinHandle<()> {
    let socket_addr = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 179);
    thread::spawn(move || {
        let listener = std::net::TcpListener::bind(socket_addr).unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(_) => {
                            println!("Received data: {:?}", &buffer);
                            // Echo back the data
                            stream.write_all(&buffer).unwrap();
                        }
                        Err(e) => {
                            eprintln!("Failed to read from socket: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        }
    })
}