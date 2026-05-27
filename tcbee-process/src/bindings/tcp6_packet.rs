use serde::Deserialize;
use ts_storage::{DataValue, IpTuple};

use crate::{bindings::event_indexer::EventIndexer, ip::ip_addr_from_16_bytes, reader::FromBuffer};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct Tcp6Packet {
    pub time: u64,
    pub saddr: [u8; 16usize],
    pub daddr: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub flags: u8,
    pub div: [u8; 4usize],
}

impl FromBuffer for Tcp6Packet {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        let try_deserialize = bincode::deserialize::<'_, Tcp6Packet>(buf);

        if try_deserialize.is_err() {
            Tcp6Packet::default()
        } else {
            try_deserialize.unwrap()
        }
    }
    const ENTRY_SIZE: usize = 64;
}

impl EventIndexer for Tcp6Packet {
    fn get_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(self.seq as i64),
            1 => DataValue::Int(self.ack as i64),
            2 => DataValue::Int(self.window as i64),
            3 => DataValue::Int(self.flags as i64),
            _ => panic!("Tried to access out of bounds index!"),
        }
    }
    fn get_default_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(0),
            1 => DataValue::Int(0),
            2 => DataValue::Int(0),
            3 => DataValue::Int(0),
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_field_name(&self, index: usize) -> &str {
        match index {
            0 => "SEQ_NUM",
            1 => "ACK_NUM",
            2 => "WINDOW",
            3 => "FLAGS",
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_ip_tuple(&self) -> IpTuple {
        let src = ip_addr_from_16_bytes(self.saddr);
        let dst = ip_addr_from_16_bytes(self.daddr);

        IpTuple {
            src,
            dst,
            sport: self.sport as i64,
            dport: self.dport as i64,
            l4proto: 6,
        }
    }
    fn get_max_index(&self) -> usize {
        3
    }
    fn get_timestamp(&self) -> f64 {
        self.time as f64
    }
    fn check_divider(&self) -> bool {
        self.div == 0xFFFFFFFFu32.to_be_bytes()
    }
    fn get_struct_length(&self) -> usize {
        64
    }
}
