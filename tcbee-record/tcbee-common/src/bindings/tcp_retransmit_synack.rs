#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};


use super::{__IncompleteArrayField, __u16, __u64, __u8, trace_entry };

#[repr(C)]
#[derive(Debug)]
pub struct trace_event_raw_tcp_retransmit_synack {
    pub ent: trace_entry,
    pub skaddr: *const ::aya_ebpf::cty::c_void,
    pub req: *const ::aya_ebpf::cty::c_void,
    pub sport: __u16,
    pub dport: __u16,
    pub family: __u16,
    pub saddr: [__u8; 4usize],
    pub daddr: [__u8; 4usize],
    pub saddr_v6: [__u8; 16usize],
    pub daddr_v6: [__u8; 16usize],
    pub __data: __IncompleteArrayField<::aya_ebpf::cty::c_char>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub struct tcp_retransmit_synack_entry {
    pub time: __u64,
    pub sport: __u16,
    pub dport: __u16,
    pub family: __u16,
    pub saddr: [__u8; 4usize],
    pub daddr: [__u8; 4usize],
    pub saddr_v6: [__u8; 16usize],
    pub daddr_v6: [__u8; 16usize],
}