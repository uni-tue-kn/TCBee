use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use ts_storage::{DataValue, IpTuple};

use crate::{
    bindings::event_indexer::EventIndexer, flow_tracker::AF_INET, ip::ip_addr_from_16_bytes,
    reader::FromBuffer,
};
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, Deserialize)]
pub struct cwnd_trace_entry {
    pub time: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16usize],
    pub dst_v6: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub snd_cwnd: u32,
    pub div: [u8; 4usize],
}
impl EventIndexer for cwnd_trace_entry {
    fn get_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(self.snd_cwnd as i64),
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_default_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(0),
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_field_name(&self, index: usize) -> &str {
        match index {
            0 => "perf_snd_cwnd",
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_ip_tuple(&self) -> IpTuple {
        let src: IpAddr;
        let dst: IpAddr;

        //print!("Family: {}",self.family);

        if self.family == AF_INET {
            // TODO: check offsets
            let bytes = self.addr_v4.to_be_bytes();

            let mut srcbytes: [u8; 4] = bytes[0..4].try_into().unwrap();
            let mut dstbytes: [u8; 4] = bytes[4..8].try_into().unwrap();
            //srcbytes.reverse();

            srcbytes.reverse();
            dstbytes.reverse();
            src = IpAddr::V4(Ipv4Addr::from(srcbytes));
            dst = IpAddr::V4(Ipv4Addr::from(dstbytes));
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
        0
    }
    fn get_timestamp(&self) -> f64 {
        self.time as f64
    }
    fn check_divider(&self) -> bool {
        self.div == 0xFFFFFFFFu32.to_be_bytes()
    }
    fn get_struct_length(&self) -> usize {
        62
    }
}

impl FromBuffer for cwnd_trace_entry {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        //unsafe { *(buf.as_ptr() as *const sock_trace_entry) }

        let try_deserialize = bincode::deserialize::<'_, cwnd_trace_entry>(buf);

        if try_deserialize.is_err() {
            cwnd_trace_entry::default()
        } else {
            try_deserialize.unwrap()
        }
    }
    const ENTRY_SIZE: usize = 62;
}
