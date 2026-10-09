use serde::Deserialize;
use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair, AF_INET},
};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, Deserialize)]
#[cfg_attr(feature = "fixture-gen", derive(serde::Serialize))]
pub struct sock_trace_entry {
    pub time: u64,
    pub hook_seq: u64,
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

event_schema! {
    sock_trace_entry => "sock", 168 {
        pacing_rate: U64,
        max_pacing_rate: U64,
        backoff: U8,
        rto: U32,
        ato: U32,
        rcv_mss: U16,
        snd_cwnd: U32,
        bytes_acked: U64,
        snd_ssthresh: U32,
        total_retrans: U32,
        probes: U8,
        lost: U32,
        sacked_out: U32,
        retrans: U32,
        rcv_ssthresh: U32,
        rttvar: U32,
        advmss: U16,
        reordering: U32,
        rcv_rtt: U32,
        rcv_space: U32,
        bytes_received: U64,
        segs_out: U32,
        segs_in: U32,
        snd_wscale: U16,
        rcv_wscale: U16,
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
