use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use ts_storage::{DataValue, IpTuple};

use crate::{bindings::event_indexer::EventIndexer, ip::ip_addr_from_16_bytes, reader::FromBuffer};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct CubicEvent {
    // Shared ID
    pub time: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16usize],
    pub dst_v6: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    // Cubic
    pub cnt: u32,
    pub last_max_cwnd: u32,
    pub last_cwnd: u32,
    pub last_time: u32,
    pub bic_origin_point: u32,
    pub bic_K: u32,
    pub delay_min: u32,
    pub epoch_start: u32,
    pub ack_cnt: u32,
    pub tcp_cwnd: u32,
    pub round_start: u32,
    pub end_seq: u32,
    pub last_ack: u32,
    pub curr_rtt: u32,
    pub div: [u8; 4usize],
}

pub fn unpack_ipv4_pair(packed: u64) -> (Ipv4Addr, Ipv4Addr) {
    let src = (packed >> 32) as u32;
    let dst = packed as u32;

    // If those u32s are in network byte order (big-endian):
    let src = Ipv4Addr::from(u32::from_be(src));
    let dst = Ipv4Addr::from(u32::from_be(dst));

    (src, dst)
}

impl FromBuffer for CubicEvent {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        let try_deserialize = bincode::deserialize::<'_, CubicEvent>(buf);

        if try_deserialize.is_err() {
            CubicEvent::default()
        } else {
            try_deserialize.unwrap()
        }
    }
    const ENTRY_SIZE: usize = 114;
}

impl EventIndexer for CubicEvent {
    fn get_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(self.cnt as i64),
            1 => DataValue::Int(self.last_max_cwnd as i64),
            2 => DataValue::Int(self.last_cwnd as i64),
            3 => DataValue::Int(self.last_time as i64),
            4 => DataValue::Int(self.bic_origin_point as i64),
            5 => DataValue::Int(self.bic_K as i64),
            6 => DataValue::Int(self.delay_min as i64),
            7 => DataValue::Int(self.epoch_start as i64),
            8 => DataValue::Int(self.ack_cnt as i64),
            9 => DataValue::Int(self.tcp_cwnd as i64),
            10 => DataValue::Int(self.round_start as i64),
            11 => DataValue::Int(self.end_seq as i64),
            12 => DataValue::Int(self.last_ack as i64),
            13 => DataValue::Int(self.curr_rtt as i64),
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_default_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(0),
            1 => DataValue::Int(0),
            2 => DataValue::Int(0),
            3 => DataValue::Int(0),
            4 => DataValue::Int(0),
            5 => DataValue::Int(0),
            6 => DataValue::Int(0),
            7 => DataValue::Int(0),
            8 => DataValue::Int(0),
            9 => DataValue::Int(0),
            10 => DataValue::Int(0),
            11 => DataValue::Int(0),
            12 => DataValue::Int(0),
            13 => DataValue::Int(0),
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_field_name(&self, index: usize) -> &str {
        match index {
            0 => "cnt",
            1 => "last_max_cwnd",
            2 => "last_cwnd",
            3 => "last_time",
            4 => "bic_origin_point",
            5 => "bic_K",
            6 => "delay_min",
            7 => "epoch_start",
            8 => "ack_cnt",
            9 => "tcp_cwnd",
            10 => "round_start",
            11 => "end_seq",
            12 => "last_ack",
            13 => "curr_rtt",
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_ip_tuple(&self) -> IpTuple {
        let src: IpAddr;
        let dst: IpAddr;

        if self.addr_v4 != 0 {
            let (parsed_src, parsed_dst) = unpack_ipv4_pair(self.addr_v4);
            src = IpAddr::V4(parsed_src);
            dst = IpAddr::V4(parsed_dst);
        } else {
            src = ip_addr_from_16_bytes(self.src_v6);
            dst = ip_addr_from_16_bytes(self.dst_v6);
        }

        IpTuple {
            src,
            dst,
            sport: self.sport as i64,
            dport: self.dport as i64,
            l4proto: 6,
        }
    }
    fn get_max_index(&self) -> usize {
        13
    }
    fn get_timestamp(&self) -> f64 {
        self.time as f64
    }
    fn check_divider(&self) -> bool {
        self.div == 0xFFFFFFFFu32.to_be_bytes()
    }
    fn get_struct_length(&self) -> usize {
        72
    }
}
