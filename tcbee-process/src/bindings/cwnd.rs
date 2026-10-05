use serde::Deserialize;
use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair, AF_INET},
};
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, Deserialize)]
#[cfg_attr(feature = "fixture-gen", derive(serde::Serialize))]
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
event_schema! {
    cwnd_trace_entry => "cwnd", 62 {
        snd_cwnd => "perf_snd_cwnd": U32,
    }
    {
        fn flow_key(&self) -> IpTuple {
            let (src, dst) = kernel_addr_pair(
                self.family == AF_INET,
                self.addr_v4,
                self.src_v6,
                self.dst_v6,
            );
            flow_tuple(src, dst, self.sport, self.dport)
        }
    }
}
