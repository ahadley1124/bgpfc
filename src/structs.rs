pub struct Header {
    pub marker: [u8; 16],
    pub length: [u8; 2],
    pub message_type: u8,
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
}

pub struct notificationMessage {
    pub header: Header,
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}