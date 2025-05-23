use std::fmt::{Debug, Display};

use crate::structs;

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

    pub fn to_bytes(&self) -> [u8; 1024] {
        let mut bytes: [u8; 1024] = [0; 1024];
        bytes[0..19].copy_from_slice(&self.header.to_bytes());
        bytes[19] = self.version;
        bytes[20..22].copy_from_slice(&self.my_asn.to_be_bytes());
        bytes[22..24].copy_from_slice(&self.hold_time.to_be_bytes());
        bytes[24..28].copy_from_slice(&self.bgp_id.to_be_bytes());
        bytes[28] = self.opt_param_len;
        bytes[29..(29 + self.opt_param_len as usize)].copy_from_slice(&self.opt_params);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 29 {
            return Err("Invalid open message length");
        }
        let header = structs::Header::from_bytes(&bytes[0..19])?;
        let version = bytes[19];
        let asn_bytes = [bytes[20], bytes[21]];
        let my_asn = u16::from_be_bytes(asn_bytes);
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

impl Debug for structs::openMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenMessage {{ header: {:?}, version: {}, my_asn: {}, hold_time: {}, bgp_id: {}, opt_param_len: {}, opt_params: {:?} }}", self.header, self.version, self.my_asn, self.hold_time, self.bgp_id, self.opt_param_len, self.opt_params)
    }
}

impl Display for structs::openMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenMessage {{ header: {}, version: {}, my_asn: {}, hold_time: {}, bgp_id: {}, opt_param_len: {}, opt_params: {:?} }}", self.header, self.version, self.my_asn, self.hold_time, self.bgp_id, self.opt_param_len, self.opt_params)
    }
}
