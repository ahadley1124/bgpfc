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

impl Clone for structs::Header {
    fn clone(&self) -> Self {
        Self {
            marker: self.marker,
            length: self.length,
            message_type: self.message_type,
        }
    }
}
