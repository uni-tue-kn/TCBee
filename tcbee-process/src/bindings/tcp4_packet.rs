use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use ts_storage::{DataPoint, DataValue, IpTuple};

use crate::{bindings::event_indexer::EventIndexer, db_writer::DBOperation, reader::FromBuffer};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct Tcp4Packet {
    pub time: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub flags: u8,
    pub div: [u8; 4usize],
}

impl FromBuffer for Tcp4Packet {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        let try_deserialize = bincode::deserialize::<'_, Tcp4Packet>(buf);

        if try_deserialize.is_err() {
            Tcp4Packet::default()
        } else {
            try_deserialize.unwrap()
        }
    }
    const ENTRY_SIZE: usize = 35;
}

impl EventIndexer for Tcp4Packet {
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
        let src: IpAddr = IpAddr::V4(Ipv4Addr::from(self.saddr));
        let dst: IpAddr = IpAddr::V4(Ipv4Addr::from(self.daddr));

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

    fn get_struct_length(&self) -> usize {
        40
    }
    fn check_divider(&self) -> bool {
        self.div == 0xFFFFFFFFu32.to_be_bytes()
    }
}
