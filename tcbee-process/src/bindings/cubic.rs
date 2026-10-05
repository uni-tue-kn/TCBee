use serde::Deserialize;
use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair},
};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[cfg_attr(feature = "fixture-gen", derive(serde::Serialize))]
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

event_schema! {
    CubicEvent => "cubic", 114 {
        cnt: U32,
        last_max_cwnd: U32,
        last_cwnd: U32,
        last_time: U32,
        bic_origin_point: U32,
        bic_K: U32,
        delay_min: U32,
        epoch_start: U32,
        ack_cnt: U32,
        tcp_cwnd: U32,
        round_start: U32,
        end_seq: U32,
        last_ack: U32,
        curr_rtt: U32,
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
