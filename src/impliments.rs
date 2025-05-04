use std::fmt::{Debug, Display};

use crate::structs;

impl structs::Header {
    pub fn new(marker: [u8; 16], length: u16, message_type: u8) -> Self {
        Self {
            marker,
            length,
            message_type,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 19 {
            return Err("Invalid header length");
        }
        let marker = bytes[0..16].try_into().map_err(|_| "Invalid marker length")?;
        let length = u16::from_be_bytes([bytes[16], bytes[17]]);
        let message_type = bytes[18];
        Ok(Self {
            marker,
            length,
            message_type,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(19);
        bytes.extend_from_slice(&self.marker);
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.push(self.message_type);
        bytes
    }
}

impl Display for structs::Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Header {{ marker: {:?}, length: {}, message_type: {} }}", self.marker, self.length, self.message_type)
    }
}

impl Debug for structs::Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Header {{ marker: {:?}, length: {}, message_type: {} }}", self.marker, self.length, self.message_type)
    }
}

impl structs::openMessage {
    pub fn new(mut header: structs::Header, version: u8, my_asn: u16, hold_time: u16, bgp_id: u32, opt_param_len: u8, opt_params: Vec<u8>) -> Self {
        // calculate the length and update the header
        let length = 19 + 1 + 2 + 2 + 4 + 1 + opt_param_len as usize;
        header.length = length as u16; // update the header length
        Self {
            header,
            version,
            my_asn,
            hold_time,
            bgp_id,
            opt_param_len,
            opt_params,
        }
    }

    pub fn length(&self) -> usize {
        19 + 1 + 2 + 2 + 4 + 1 + self.opt_param_len as usize
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.push(self.version);
        bytes.extend_from_slice(&self.my_asn.to_be_bytes());
        bytes.extend_from_slice(&self.hold_time.to_be_bytes());
        bytes.extend_from_slice(&self.bgp_id.to_be_bytes());
        bytes.push(self.opt_param_len);
        bytes.extend_from_slice(&self.opt_params);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 19 {
            return Err("Invalid open message length");
        }
        let header = structs::Header::from_bytes(&bytes[0..19])?;
        let version = bytes[19];
        let my_asn = u16::from_be_bytes([bytes[20], bytes[21]]);
        let hold_time = u16::from_be_bytes([bytes[22], bytes[23]]);
        let bgp_id = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        let opt_param_len = bytes[28];
        let opt_params = bytes[29..].to_vec();
        Ok(Self {
            header,
            version,
            my_asn,
            hold_time,
            bgp_id,
            opt_param_len,
            opt_params,
        })
    }
}