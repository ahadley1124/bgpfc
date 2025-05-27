use std::net::IpAddr;
use serde::{Serialize, Deserialize};

pub struct Header {
    pub marker: [u8; 16],
    pub length: u16,
    pub message_type: u8,
}

pub struct BGPMessage {
    pub header: Header,
    pub message: Option<(openMessage, updateMessage, keepaliveMessage, notificationMessage)>,
}

pub struct openMessage {
    pub header: Header,
    pub version: u8,
    pub my_asn: u16,
    pub hold_time: u16,
    pub bgp_id: u32,
    pub opt_param_len: u8,
    pub opt_params: Vec<u8>,
}

pub struct updateMessage {
    pub header: Header,
    pub withdrawn_routes_len: u16,
    pub withdrawn_routes: Vec<u8>,
    pub total_path_attr_len: u16,
    pub path_attributes: Vec<u8>,
    pub nlri: Vec<u8>,
}

pub struct keepaliveMessage {
    pub header: Header,
    pub extra: Vec<u8>,
}

pub struct notificationMessage {
    pub header: Header,
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub my_asn: u16,
    pub hold_time: u16,
    pub bgp_id: IpAddr,
    pub networks: Vec<Networks>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Networks {
    pub prefix: IpAddr,
    pub mask: u8,
    pub next_hop: IpAddr,
    pub as_path: Vec<u16>,
    pub internal: bool,
    pub local_pref: u32,
    pub rpki_valid: Option<bool>,
    pub rpki_partial_valid: Option<bool>,
    pub rpki_invalid: Option<bool>,
}

pub struct RPKI_PDU {
    pub version: u8,
    pub PDU_type: u8,
    pub serial_number: u32,
    pub session_id: u32,
    pub length: u32,
    pub flags: u8,
    pub prefix_length: u8,
    pub max_length: u8,
    pub prefix: IpAddr,
    pub asn: u32,
    zero: u8,
}

pub struct RPKI_Serial_Notify {
    pub version: u8,
    pub PDU_type: u8,
    pub session_id: u32,
    pub length: u32,
    pub serial_number: u32,
}

pub struct RPKI_Serial_Query {
    pub version: u8,
    pub PDU_type: u8,
    pub session_id: u32,
    pub length: u32,
    pub serial_number: u32,
}

pub struct RPKI_Reset_Query {
    pub version: u8,
    pub PDU_type: u8,
    pub reserved: u16,
    pub length: u32,
}