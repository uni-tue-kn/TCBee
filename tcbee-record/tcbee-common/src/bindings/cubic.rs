// Minimal hand-written bindings for the kernel's CUBIC congestion control state.
// Field offsets verified with `pahole` against the running kernel's BTF.

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

pub use crate::records::cubic_trace_entry;
