#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

use super::{__u64, __u8, trace_entry};

#[repr(C)]
#[derive(Debug)]
// Event class tcp_event_skb. saddr and daddr hold a sockaddr_in or sockaddr_in6.
pub struct trace_event_raw_tcp_bad_csum {
    pub ent: trace_entry,
    pub skbaddr: __u64,
    pub saddr: [__u8; 28usize],
    pub daddr: [__u8; 28usize],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub struct tcp_bad_csum_entry {
    pub time: __u64,
    pub saddr: [__u8; 4usize],
    pub daddr: [__u8; 4usize],
}
