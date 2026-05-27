use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use ts_storage::{DataValue, IpTuple};

use crate::{bindings::event_indexer::EventIndexer, ip::ip_addr_from_16_bytes, reader::FromBuffer};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct BbrEvent {
    // Shared ID
    pub time: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16usize],
    pub dst_v6: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    // BBR
    pub min_rtt_us: u32,
    pub min_rtt_stamp: u32,
    pub probe_rtt_done_stamp: u32,
    pub rtt_cnt: u32,
    pub next_rtt_delivered: u32,
    pub cycle_mstamp: u64,
    pub lt_bw: u32,
    pub lt_last_delivered: u32,
    pub lt_last_stamp: u32,
    pub lt_last_lost: u32,
    pub prior_cwnd: u32,
    pub full_bw: u32,
    pub div: [u8; 4usize],
}

pub fn unpack_ipv4_pair(packed: u64) -> (Ipv4Addr, Ipv4Addr) {
    let src = (packed >> 32) as u32;
    let dst = packed as u32;

    let src = Ipv4Addr::from(u32::from_be(src));
    let dst = Ipv4Addr::from(u32::from_be(dst));

    (src, dst)
}

impl FromBuffer for BbrEvent {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        let try_deserialize = bincode::deserialize::<'_, BbrEvent>(buf);

        if try_deserialize.is_err() {
            BbrEvent::default()
        } else {
            try_deserialize.unwrap()
        }
    }
    const ENTRY_SIZE: usize = 110;
}

impl EventIndexer for BbrEvent {
    fn get_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(self.min_rtt_us as i64),
            1 => DataValue::Int(self.min_rtt_stamp as i64),
            2 => DataValue::Int(self.probe_rtt_done_stamp as i64),
            3 => DataValue::Int(self.rtt_cnt as i64),
            4 => DataValue::Int(self.next_rtt_delivered as i64),
            5 => DataValue::Int(self.cycle_mstamp as i64),
            6 => DataValue::Int(self.lt_bw as i64),
            7 => DataValue::Int(self.lt_last_delivered as i64),
            8 => DataValue::Int(self.lt_last_stamp as i64),
            9 => DataValue::Int(self.lt_last_lost as i64),
            10 => DataValue::Int(self.prior_cwnd as i64),
            11 => DataValue::Int(self.full_bw as i64),
            _ => panic!("Tried to access out of bounds index!"),
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
            _ => panic!("Tried to access out of bounds index!"),
        }
    }

    fn get_field_name(&self, index: usize) -> &str {
        match index {
            0 => "min_rtt_us",
            1 => "min_rtt_stamp",
            2 => "probe_rtt_done_stamp",
            3 => "rtt_cnt",
            4 => "next_rtt_delivered",
            5 => "cycle_mstamp",
            6 => "lt_bw",
            7 => "lt_last_delivered",
            8 => "lt_last_stamp",
            9 => "lt_last_lost",
            10 => "prior_cwnd",
            11 => "full_bw",
            _ => panic!("Tried to access out of bounds index!"),
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
        11
    }

    fn get_timestamp(&self) -> f64 {
        self.time as f64
    }

    fn check_divider(&self) -> bool {
        self.div == 0xFFFFFFFFu32.to_be_bytes()
    }

    fn get_struct_length(&self) -> usize {
        106
    }
}
