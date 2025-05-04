use std::net::SocketAddrV4;
use std::io::{ Read, Write };

mod connection;
mod structs;
mod impliments;

fn parse_header(input: &str) -> Result<structs::Header, &'static str> {
    let mut parts = input.split_whitespace();
    let marker: [u8; 16] = parts
        .next()
        .ok_or("Missing marker")?
        .as_bytes()
        .try_into()
        .map_err(|_| "Invalid marker length")?;
    let length: u16 = parts
        .next()
        .ok_or("Missing length")?
        .parse()
        .map_err(|_| "Invalid length")?;
    let message_type: u8 = parts
        .next()
        .ok_or("Missing message type")?
        .parse()
        .map_err(|_| "Invalid message type")?;

    Ok(structs::Header {
        marker,
        length,
        message_type,
    })
}

fn main() {
    let addr = SocketAddrV4::new("0.0.0.0".parse().unwrap(), 179);
    let listener = connection::bind_socket(addr).unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    // only listen for connections and print all the data received
    let (mut stream, _) = listener.accept().unwrap();
    println!("Accepted connection from {}", stream.peer_addr().unwrap());
    let mut buf = [0; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                println!("Received {} bytes: {:?}", n, &buf[..n]);
                println!("Message: {}", String::from_utf8_lossy(&buf[..n]));
                let header = parse_header(&String::from_utf8_lossy(&buf[..n]));
                match header {
                    Ok(ref header) => println!("Parsed header: {:?}", header),
                    Err(e) => eprintln!("Error parsing header: {}", e),
                }
                println!("Parsed header: {:?}", header);
                stream.write_all(&buf[..n]).unwrap();
            }
            Err(e) => {
                eprintln!("Error reading from stream: {}", e);
                break;
            }
        }
    }
}
