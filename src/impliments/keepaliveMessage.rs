use std::fmt::{Debug, Display};

use crate::structs;

impl structs::keepaliveMessage {
    pub fn new(mut header: structs::Header) -> Self {
        // calculate the length and update the header
        let length = 19;
        header.length = length as u16; // update the header length
        Self {
            header,
            extra: Vec::new(),
        }
    }

    pub fn length(&self) -> usize {
        19
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.header.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<bool, &'static str> {
        // the rfc says that the keepalive message is 19 bytes long, but multiple different implementations have different lengths
        // so we will just check if the length is at least 19 bytes
        if bytes.len() >= 2 {
            return Err("Invalid keepalive message length");
        }
        Ok(true)
    }
}

impl Debug for structs::keepaliveMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeepaliveMessage {{ header: {:?} }}", self.header)
    }
}

impl Display for structs::keepaliveMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeepaliveMessage {{ header: {} }}", self.header)
    }
}