use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

pub struct config {
    pub asn: u32,
    pub router_id: IpAddr,
    pub neighbors: Vec<neighbor>,
}

pub struct neighbor {
    pub ip: IpAddr,
    pub remote_asn: u32,
    pub description: String,
    pub hold_time: u16,
}

pub struct bgp_header {
    pub marker: [u8; 16],
    pub length: u16,
    pub msg_type: u8,
}

pub struct bgp_opt_param {
    pub param_type: u8,
    pub param_len: u8,
    pub param_value: Box<[u8]>,
}

pub struct bgp_open {
    pub header: bgp_header,
    pub version: u8,
    pub my_asn: u16,
    pub hold_time: u16,
    pub bgp_id: Ipv4Addr,
    pub opt_params_len: u8,
    pub opt_params: Vec<bgp_opt_param>,
}

pub struct bgp_prefix {
    pub prefix_len: u8,
    pub prefix: Vec<u8>,
}

pub struct bgp_path_attr {
    
}

pub struct bgp_update {
    pub header: bgp_header,
    pub withdrawn_routes_len: u16,
    pub withdrawn_routes: Vec<bgp_prefix>,
    pub path_attr_len: u16,
    pub path_attributes: Vec<bgp_path_attr>,
    pub nlri: Vec<bgp_prefix>,
}