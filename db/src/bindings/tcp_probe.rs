use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use ts_storage::{DataValue, IpTuple};

use crate::{
    db_writer::DBOperation, flow_tracker::{EventIndexer, AF_INET}, reader::FromBuffer, shorten_to_ipv4, shorten_to_ipv6
};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct TcpProbe {
    pub time: u64,
    pub saddr: [u8; 28usize],
    pub daddr: [u8; 28usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub mark: u32,
    pub data_len: u16,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub snd_cwnd: u32,
    pub ssthresh: u32,
    pub snd_wnd: u32,
    pub srtt: u32,
    pub rcv_wnd: u32,
    pub sock_cookie: u64,
    pub div: [u8; 4usize],
}

impl FromBuffer for TcpProbe {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        let try_deserialize = bincode::deserialize::<'_, TcpProbe>(buf);

        if try_deserialize.is_err() {
            TcpProbe::default()
        } else {
            try_deserialize.unwrap()
        }
    }
    const ENTRY_SIZE: usize = 116;
}

impl EventIndexer for TcpProbe {
    fn get_field(&self, index: usize) -> Option<DataValue> {
        match index {
            0 => if self.mark > 0 {Some(DataValue::Int(self.mark as i64))} else {None},
            1 => if self.data_len > 0 {Some(DataValue::Int(self.data_len as i64))} else {None},
            2 => if self.snd_nxt > 0 {Some(DataValue::Int(self.snd_nxt as i64))} else {None},
            3 => if self.snd_una > 0 {Some(DataValue::Int(self.snd_una as i64))} else {None},
            4 => if self.snd_cwnd > 0 {Some(DataValue::Int(self.snd_cwnd as i64))} else {None},
            5 => if self.ssthresh > 0 {Some(DataValue::Int(self.ssthresh as i64))} else {None},
            6 => if self.snd_wnd > 0 {Some(DataValue::Int(self.snd_wnd as i64))} else {None},
            7 => if self.srtt > 0 {Some(DataValue::Int(self.srtt as i64))} else {None},
            8 => if self.rcv_wnd > 0 {Some(DataValue::Int(self.rcv_wnd as i64))} else {None},
            9 => if self.sock_cookie > 0 {Some(DataValue::Int(self.sock_cookie as i64))} else {None},
            _ => None, // TODO: better error handling
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
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_field_name(&self, index: usize) -> &str {
        match index {
            0 => "MARK",
            1 => "DATA_LEN",
            2 => "SND_NXT",
            3 => "SND_UNA",
            4 => "SND_CWND",
            5 => "SSTRESH",
            6 => "SND_WND",
            7 => "SRTT",
            8 => "RCV_WND",
            9 => "SOCK_COOKIE",
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_ip_tuple(&self) -> IpTuple {
        let src: IpAddr;
        let dst: IpAddr;
        
        if self.family == AF_INET {
            //IPv4
            src = IpAddr::V4(Ipv4Addr::from(shorten_to_ipv4(self.saddr)));
            dst = IpAddr::V4(Ipv4Addr::from(shorten_to_ipv4(self.daddr)));
        } else {
            src = IpAddr::V6(Ipv6Addr::from(shorten_to_ipv6(self.saddr)));
            dst = IpAddr::V6(Ipv6Addr::from(shorten_to_ipv6(self.daddr)));
        }
        IpTuple {
            src: src,
            dst: dst,
            sport: self.sport as i64,
            dport: self.dport as i64,
            l4proto: 6,
        }
    }
    fn get_max_index(&self) -> usize {
        9
    }
    fn get_timestamp(&self) -> f64 {
        self.time as f64
    }
    fn as_db_op(self) -> DBOperation {
        DBOperation::Probe(self)
    }
    fn get_struct_length(&self) -> usize {
        116
    }
}
