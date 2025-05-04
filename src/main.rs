use std::net::SocketAddrV4;
use std::io::{ Read, Write };

mod connection;
mod structs;
mod impliments;

fn parse_header(input: [u8; 1024]) -> Result<structs::Header, &'static str> {
    let header = structs::Header::from_bytes(&input[0..19])?;
    Ok(header)
}

fn main() {
    let addr = SocketAddrV4::new("0.0.0.0".parse().unwrap(), 179);
    let listener = connection::bind_socket(addr).unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    // only listen for connections and print all the data received
    let (mut stream, _) = listener.accept().unwrap();
    println!("Accepted connection from {}", stream.peer_addr().unwrap());
    let mut buf: [u8; 1024] = [0; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                println!("Received {} bytes: {:?}", n, &buf[..n]);
                println!("Message: {}", String::from_utf8_lossy(&buf[..n]));
                let header = parse_header(buf);
                match header {
                    Ok(ref header) => println!("Parsed header: {:?}", header),
                    Err(e) => eprintln!("Error parsing header: {}", e),
                }
                stream.write_all(&buf[..n]).unwrap();
            }
            Err(e) => {
                eprintln!("Error reading from stream: {}", e);
                break;
            }
        }
    }
}
