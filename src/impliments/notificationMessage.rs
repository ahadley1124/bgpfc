use std::fmt::{Debug, Display};

use crate::structs;

impl structs::notificationMessage {
    pub fn new(mut header: structs::Header, error_code: u8, error_subcode: u8, data: Vec<u8>) -> Self {
        // calculate the length and update the header
        let length = 19 + 1 + 1 + data.len();
        header.length = length as u16; // update the header length
        Self {
            header,
            error_code,
            error_subcode,
            data,
        }
    }

    pub fn length(&self) -> usize {
        19 + 1 + 1 + self.data.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.push(self.error_code);
        bytes.push(self.error_subcode);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() >= 21 {
            return Err("Invalid notification message length");
        }
        let header = structs::Header::from_bytes(&bytes[0..19])?;
        let error_code = bytes[19];
        let error_subcode = bytes[20];
        let data = bytes[21..].to_vec();
        Ok(Self {
            header,
            error_code,
            error_subcode,
            data,
        })
    }
}

impl Debug for structs::notificationMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NotificationMessage {{ header: {:?}, error_code: {}, error_subcode: {}, data: {:?} }}", self.header, self.error_code, self.error_subcode, self.data)
    }
}

impl Display for structs::notificationMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NotificationMessage {{ header: {}, error_code: {}, error_subcode: {}, data: {:?} }}", self.header, self.error_code, self.error_subcode, self.data)
    }
}
