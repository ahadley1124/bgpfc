use std::net::{SocketAddrV4, SocketAddrV6, SocketAddr, TcpStream, ToSocketAddrs, TcpListener};

pub fn bind_socket<T: ToSocketAddrs>(addr: T) -> std::io::Result<std::net::TcpListener> {
    let listener = TcpListener::bind(addr)?;
    Ok(listener)
}

pub fn connect_socket<T: ToSocketAddrs>(addr: T) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(addr)?;
    Ok(stream)
}

pub fn set_connection_parameters(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_ttl(64)?;
    Ok(())
}