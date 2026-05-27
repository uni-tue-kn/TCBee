use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use ts_storage::{DataValue, IpTuple};

use crate::{
    bindings::event_indexer::EventIndexer, flow_tracker::AF_INET, ip::ip_addr_from_16_bytes,
    reader::FromBuffer,
};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, Deserialize)]
pub struct sock_trace_entry {
    pub time: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16usize],
    pub dst_v6: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    // SOCK Stats
    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    // INET_CONN Stats
    pub backoff: u8,
    pub rto: u32,
    // INET_CONN -> icsk_ack
    pub ato: u32,
    pub rcv_mss: u16,
    // TCP_SOCK Stats
    pub snd_cwnd: u32,
    pub bytes_acked: u64,
    pub snd_ssthresh: u32,
    pub total_retrans: u32,
    pub probes: u8,
    pub lost: u32,
    pub sacked_out: u32,
    pub retrans: u32,
    pub rcv_ssthresh: u32,
    pub rttvar: u32,
    pub advmss: u16,
    pub reordering: u32,
    pub rcv_rtt: u32,
    pub rcv_space: u32,
    pub bytes_received: u64,
    pub segs_out: u32,
    pub segs_in: u32,
    // TCP_SOCK -> tcp_options_received
    pub snd_wscale: u16,
    pub rcv_wscale: u16,
    pub div: [u8; 4usize],
}

impl FromBuffer for sock_trace_entry {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        //unsafe { *(buf.as_ptr() as *const sock_trace_entry) }

        let try_deserialize = bincode::deserialize::<'_, sock_trace_entry>(buf);

        if try_deserialize.is_err() {
            sock_trace_entry::default()
        } else {
            try_deserialize.unwrap()
        }
    }
    const ENTRY_SIZE: usize = 160;
}

impl EventIndexer for sock_trace_entry {
    fn get_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(self.pacing_rate as i64),
            1 => DataValue::Int(self.max_pacing_rate as i64),
            2 => DataValue::Int(self.backoff as i64),
            3 => DataValue::Int(self.rto as i64),
            4 => DataValue::Int(self.ato as i64),
            5 => DataValue::Int(self.rcv_mss as i64),
            6 => DataValue::Int(self.snd_cwnd as i64),
            7 => DataValue::Int(self.bytes_acked as i64),
            8 => DataValue::Int(self.snd_ssthresh as i64),
            9 => DataValue::Int(self.total_retrans as i64),
            10 => DataValue::Int(self.probes as i64),
            11 => DataValue::Int(self.lost as i64),
            12 => DataValue::Int(self.sacked_out as i64),
            13 => DataValue::Int(self.retrans as i64),
            14 => DataValue::Int(self.rcv_ssthresh as i64),
            15 => DataValue::Int(self.rttvar as i64),
            16 => DataValue::Int(self.advmss as i64),
            17 => DataValue::Int(self.reordering as i64),
            18 => DataValue::Int(self.rcv_rtt as i64),
            19 => DataValue::Int(self.rcv_space as i64),
            20 => DataValue::Int(self.bytes_received as i64),
            21 => DataValue::Int(self.segs_out as i64),
            22 => DataValue::Int(self.segs_in as i64),
            23 => DataValue::Int(self.snd_wscale as i64),
            24 => DataValue::Int(self.rcv_wscale as i64),
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
            14 => DataValue::Int(0),
            15 => DataValue::Int(0),
            16 => DataValue::Int(0),
            17 => DataValue::Int(0),
            18 => DataValue::Int(0),
            19 => DataValue::Int(0),
            20 => DataValue::Int(0),
            21 => DataValue::Int(0),
            22 => DataValue::Int(0),
            23 => DataValue::Int(0),
            24 => DataValue::Int(0),
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_field_name(&self, index: usize) -> &str {
        match index {
            0 => "pacing_rate",
            1 => "max_pacing_rate",
            2 => "backoff",
            3 => "rto",
            4 => "ato",
            5 => "rcv_mss",
            6 => "snd_cwnd",
            7 => "bytes_acked",
            8 => "snd_ssthresh",
            9 => "total_retrans",
            10 => "probes",
            11 => "lost",
            12 => "sacked_out",
            13 => "retrans",
            14 => "rcv_ssthresh",
            15 => "rttvar",
            16 => "advmss",
            17 => "reordering",
            18 => "rcv_rtt",
            19 => "rcv_space",
            20 => "bytes_received",
            21 => "segs_out",
            22 => "segs_in",
            23 => "snd_wscale",
            24 => "rcv_wscale",
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
        24
    }
    fn get_timestamp(&self) -> f64 {
        self.time as f64
    }
    fn check_divider(&self) -> bool {
        self.div == 0xFFFFFFFFu32.to_be_bytes()
    }
    fn get_struct_length(&self) -> usize {
        160
    }
}
