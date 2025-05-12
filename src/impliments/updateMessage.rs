use std::fmt::{Debug, Display};

use crate::structs;

impl structs::updateMessage {
    pub fn new(mut header: structs::Header, withdrawn_routes_len: u16, withdrawn_routes: Vec<u8>, total_path_attr_len: u16, path_attributes: Vec<u8>, nlri: Vec<u8>) -> Self {
        // calculate the length and update the header
        let length = 19 + 2 + withdrawn_routes_len as usize + 2 + total_path_attr_len as usize + nlri.len();
        header.length = length as u16; // update the header length
        Self {
            header,
            withdrawn_routes_len,
            withdrawn_routes,
            total_path_attr_len,
            path_attributes,
            nlri,
        }
    }

    pub fn length(&self) -> usize {
        19 + 2 + self.withdrawn_routes_len as usize + 2 + self.total_path_attr_len as usize + self.nlri.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.withdrawn_routes_len.to_be_bytes());
        bytes.extend_from_slice(&self.withdrawn_routes);
        bytes.extend_from_slice(&self.total_path_attr_len.to_be_bytes());
        bytes.extend_from_slice(&self.path_attributes);
        bytes.extend_from_slice(&self.nlri);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 19 {
            return Err("Invalid update message length");
        }
        let header = structs::Header::from_bytes(&bytes[0..19])?;
        let withdrawn_routes_len = u16::from_be_bytes([bytes[19], bytes[20]]);
        let withdrawn_routes = bytes[21..(21 + withdrawn_routes_len as usize)].to_vec();
        let total_path_attr_len = u16::from_be_bytes([bytes[21 + withdrawn_routes_len as usize], bytes[22 + withdrawn_routes_len as usize]]);
        let path_attributes = bytes[(23 + withdrawn_routes_len as usize)..(23 + withdrawn_routes_len as usize + total_path_attr_len as usize)].to_vec();
        let nlri = bytes[(23 + withdrawn_routes_len as usize + total_path_attr_len as usize)..].to_vec();
        Ok(Self {
            header,
            withdrawn_routes_len,
            withdrawn_routes,
            total_path_attr_len,
            path_attributes,
            nlri,
        })
    }
}

impl Debug for structs::updateMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UpdateMessage {{ header: {:?}, withdrawn_routes_len: {}, withdrawn_routes: {:?}, total_path_attr_len: {}, path_attributes: {:?}, nlri: {:?} }}", self.header, self.withdrawn_routes_len, self.withdrawn_routes, self.total_path_attr_len, self.path_attributes, self.nlri)
    }
}

impl Display for structs::updateMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UpdateMessage {{ header: {}, withdrawn_routes_len: {}, withdrawn_routes: {:?}, total_path_attr_len: {}, path_attributes: {:?}, nlri: {:?} }}", self.header, self.withdrawn_routes_len, self.withdrawn_routes, self.total_path_attr_len, self.path_attributes, self.nlri)
    }
}
