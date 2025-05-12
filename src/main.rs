#![allow(nonstandard_style)]

use std::net::SocketAddrV4;
use std::io::{ Read, Write };
use std::thread;

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

    let header = structs::Header::new([0; 16], 0, 1);

    //upon accepting a new connection, move it to a new thread
    loop {
        let (mut stream, _) = listener.accept().unwrap();
        println!("Accepted connection from {}", stream.peer_addr().unwrap());
        let open_message = my_open_message();
        let open_message_bytes = open_message.to_bytes();
        stream.write_all(&open_message_bytes).unwrap();

        thread::spawn(move || {
            let mut buf: [u8; 1024] = [0; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        break;
                    } // Connection closed
                    Ok(n) => {
                        let header = match parse_header(buf) {
                            Ok(header) => {
                                println!("Received header: {:?}", header);
                                header
                            }
                            Err(e) => {
                                eprintln!("Error parsing header: {}", e);
                                return;
                            }
                        };

                        match header.message_type {
                            1 => {
                                #[cfg(debug_assertions)]
                                println!("Received open message");
                                match structs::openMessage::from_bytes(&buf[19..n]) {
                                    Ok(open_message) => {
                                        #[cfg(debug_assertions)]
                                        println!("Received open message: {:?}", open_message);
                                        // Send keepalive after successful open message parse
                                        let keepalive = structs::keepaliveMessage::new(header);
                                        let keepalive_bytes = keepalive.to_bytes();
                                        if let Err(e) = stream.write_all(&keepalive_bytes) {
                                            eprintln!("Failed to send keepalive: {}", e);
                                        } else {
                                            #[cfg(debug_assertions)]
                                            println!("Sent keepalive message");
                                        }
                                    }
                                    Err(e) => eprintln!("Error parsing open message: {}", e),
                                }
                            }
                            2 => {
                                #[cfg(debug_assertions)]
                                println!("Received update message");
                                match structs::updateMessage::from_bytes(&buf[19..n]) {
                                    Ok(update_message) => {
                                        #[cfg(debug_assertions)]
                                        println!("Received update message: {:?}", update_message);
                                    }
                                    Err(e) => eprintln!("Error parsing update message: {}", e),
                                }
                            }
                            3 => {
                                #[cfg(debug_assertions)]
                                println!("Received notification message");
                                match structs::notificationMessage::from_bytes(&buf[19..n]) {
                                    Ok(notification_message) => {
                                        #[cfg(debug_assertions)]
                                        println!(
                                            "Received notification message: {:?}",
                                            notification_message
                                        );
                                    }
                                    Err(e) =>
                                        eprintln!("Error parsing notification message: {}", e),
                                }
                            }
                            4 => {
                                #[cfg(debug_assertions)]
                                println!("Received keepalive message");
                                match structs::keepaliveMessage::from_bytes(&buf[0..n]) {
                                    Ok(keepalive_message) => {
                                        #[cfg(debug_assertions)]
                                        println!(
                                            "Received keepalive message: {:?}",
                                            keepalive_message
                                        );
                                    }
                                    Err(e) => eprintln!("Error parsing keepalive message: {}", e),
                                }
                            }
                            _ => #[cfg(debug_assertions)]
                                println!("Unknown message type: {}", header.message_type),
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading from stream: {}", e);
                        break;
                    }
                }
            }
        });
    }
}

//fn main() {
//    let addr = SocketAddrV4::new("0.0.0.0".parse().unwrap(), 179);
//    let listener = connection::bind_socket(addr).unwrap();
//    println!("Listening on {}", listener.local_addr().unwrap());
//    // only listen for connections and print all the data received
//    let (mut stream, _) = listener.accept().unwrap();
//    println!("Accepted connection from {}", stream.peer_addr().unwrap());
//    let open_message = my_open_message();
//    let open_message_bytes = open_message.to_bytes();
//    stream.write_all(&open_message_bytes).unwrap();
//    let mut buf: [u8; 1024] = [0; 1024];
//    loop {
//        match stream.read(&mut buf) {
//            Ok(0) => {
//                break;
//            }
//            Ok(n) => {
//                let current_time = std::time::SystemTime::now();
//                let header = parse_header(buf);
//                // if the header is ok, unwrap it, else print the error
//                match header {
//                    Ok(_) => {
//                        continue;
//                    }
//                    Err(e) => {
//                        eprintln!("Error parsing header: {}", e);
//                    }
//                }
//                match header.clone().unwrap().message_type {
//                    1 => {
//                        println!("Received open message");
//                        let open_message = structs::openMessage::from_bytes(&buf[19..n]);
//                        match open_message {
//                            Ok(open_message) => {
//                                println!("Received open message: {:?}", open_message);
//                            }
//                            Err(e) => {
//                                eprintln!("Error parsing open message: {}", e);
//                            }
//                        }
//                    }
//                    2 => {
//                        println!("Received update message");
//                        let update_message = structs::updateMessage::from_bytes(&buf[19..n]);
//                        match update_message {
//                            Ok(update_message) => {
//                                println!("Received update message: {:?}", update_message);
//                            }
//                            Err(e) => {
//                                eprintln!("Error parsing update message: {}", e);
//                            }
//                        }
//                    }
//                    3 => {
//                        println!("Received notification message");
//                        let notification_message = structs::notificationMessage::from_bytes(&buf[19..n]);
//                        match notification_message {
//                            Ok(notification_message) => {
//                                println!("Received notification message: {:?}", notification_message);
//                            }
//                            Err(e) => {
//                                eprintln!("Error parsing notification message: {}", e);
//                            }
//                        }
//                    }
//                    4 => {
//                        println!("Received keepalive message");
//                        println!("Full buffer: {:?}", buf);
//                        println!("Buffer length: {}", n);
//                        let keepalive_message = structs::keepaliveMessage::from_bytes(&buf[0..n]);
//                        match keepalive_message {
//                            Ok(keepalive_message) => {
//                                println!("Received keepalive message: {:?}", keepalive_message);
//                            }
//                            Err(e) => {
//                                eprintln!("Error parsing keepalive message: {}", e);
//                            }
//                        }
//                    }
//                    _ => {
//                        println!("Unknown message type: {}", header.clone().unwrap().message_type);
//                    }
//
//                }
//                let elapsed = current_time.elapsed().unwrap();
//                println!("Time elapsed: {:?}", elapsed);
//            }
//            Err(e) => {
//                eprintln!("Error reading from stream: {}", e);
//                break;
//            }
//        }
//    }
//}
