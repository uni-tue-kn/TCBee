// Minimal hand-written bindings for the kernel's CUBIC congestion control state.
// Field offsets verified with `pahole` against the running kernel's BTF.

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "ebpf")]
use crate::kread::read_kernel;
#[cfg(feature = "ebpf")]
use aya_ebpf::helpers::generated::bpf_ktime_get_ns;
#[cfg(feature = "ebpf")]
use kernel_read_derive::KernelRead;

#[cfg(feature = "ebpf")]
use crate::bindings::tcp_sock::sock;

// ---- cubic / bictcp (size: 60) ----------------------------------------------
// All field offsets verified with pahole against running kernel BTF.

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cubic {
    pub cnt: u32,               //  0..4
    pub last_max_cwnd: u32,     //  4..8
    pub last_cwnd: u32,         //  8..12
    pub last_time: u32,         // 12..16
    pub bic_origin_point: u32,  // 16..20
    pub bic_K: u32,             // 20..24
    pub delay_min: u32,         // 24..28
    pub epoch_start: u32,       // 28..32
    pub ack_cnt: u32,           // 32..36
    pub tcp_cwnd: u32,          // 36..40
    pub _pad: [u8; 4],          // 40..44  (unused: u16, sample_cnt: u8, found: u8)
    pub round_start: u32,       // 44..48
    pub end_seq: u32,           // 48..52
    pub last_ack: u32,          // 52..56
    pub curr_rtt: u32,          // 56..60
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "ebpf", derive(KernelRead))]
#[cfg_attr(feature = "ebpf", kernel_read(ctx(sk: *const sock, cubic: *const cubic), default_src = "cubic"))]
pub struct cubic_trace_entry {
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
}
