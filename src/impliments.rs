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
        if bytes.len() < 19 {
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