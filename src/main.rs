use std::net::SocketAddrV4;
use std::io::{ Read, Write };

mod connection;
mod structs;
mod impliments;

fn parse_header(input: [u8; 1024]) -> Result<structs::Header, &'static str> {
    let header = structs::Header::from_bytes(&input[0..19])?;
    Ok(header)
}

fn my_open_message() -> structs::openMessage {
    let header = structs::Header::new([0; 16], 0, 1);
    let version = 4;
    let my_asn = 65500;
    let hold_time = 300;
    let bgp_id: u32 = u32::from_be_bytes([10, 0, 1, 136]);
    let opt_param_len = 0;
    let opt_params = Vec::new();
    structs::openMessage::new(header, version, my_asn, hold_time, bgp_id, opt_param_len, opt_params)
}

fn main() {
    let addr = SocketAddrV4::new("0.0.0.0".parse().unwrap(), 179);
    let listener = connection::bind_socket(addr).unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    // only listen for connections and print all the data received
    let (mut stream, _) = listener.accept().unwrap();
    println!("Accepted connection from {}", stream.peer_addr().unwrap());
    let open_message = my_open_message();
    let open_message_bytes = open_message.to_bytes();
    println!("Sending open message: {:?}", open_message_bytes);
    stream.write_all(&open_message_bytes).unwrap();
    let mut buf: [u8; 1024] = [0; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                let current_time = std::time::SystemTime::now();
                println!("Received {} bytes: {:?}", n, &buf[..n]);
                println!("Message: {}", String::from_utf8_lossy(&buf[..n]));
                let header = parse_header(buf);
                match header {
                    Ok(ref header) => println!("Parsed header: {:?}", header),
                    Err(e) => eprintln!("Error parsing header: {}", e),
                }
                stream.write_all(&buf[..n]).unwrap();
                let elapsed = current_time.elapsed().unwrap();
                println!("Time elapsed: {:?}", elapsed);
            }
            Err(e) => {
                eprintln!("Error reading from stream: {}", e);
                break;
            }
        }
    }
}
