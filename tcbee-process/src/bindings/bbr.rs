use serde::Deserialize;
use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair},
};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[cfg_attr(feature = "fixture-gen", derive(serde::Serialize))]
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

event_schema! {
    BbrEvent => "bbr", 110 {
        min_rtt_us: U32,
        min_rtt_stamp: U32,
        probe_rtt_done_stamp: U32,
        rtt_cnt: U32,
        next_rtt_delivered: U32,
        cycle_mstamp: U64,
        lt_bw: U32,
        lt_last_delivered: U32,
        lt_last_stamp: U32,
        lt_last_lost: U32,
        prior_cwnd: U32,
        full_bw: U32,
    }
    {
        fn flow_key(&self) -> IpTuple {
            let (src, dst) = kernel_addr_pair(
                self.addr_v4 != 0,
                self.addr_v4,
                self.src_v6,
                self.dst_v6,
            );
            flow_tuple(src, dst, self.sport, self.dport)
        }
    }
}
