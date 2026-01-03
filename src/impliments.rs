use std::net::IpAddr;

use crate::structs;

impl structs::config {
    pub fn new(asn: u32, router_id: IpAddr, neighbors: Vec<structs::neighbor>) -> Self {
        Self {
            asn,
            router_id,
            neighbors
        }
    }
}

impl structs::neighbor {
    pub fn new(ip: IpAddr, remote_asn: u32, description: String, hold_time: u16) -> Self {
        Self {
            ip,
            remote_asn,
            description,
            hold_time
        }
    }
    
}