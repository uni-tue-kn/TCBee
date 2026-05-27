// Minimal hand-written bindings for the kernel's BBR congestion control state.
// Field offsets verified with `pahole` against the running kernel's BTF.
// Only fields read by the eBPF probe are named; bitfield regions are collapsed
// to opaque padding since we do not access individual bits.

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

// ---- minmax (used inside bbr) -----------------------------------------------

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct minmax_sample {
    pub t: u32,
    pub v: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct minmax {
    pub s: [minmax_sample; 3], //  0..24
}

// ---- bbr (size: 68) ---------------------------------------------------------
// Accessed field offsets (from pahole):
//   min_rtt_us              @  0  (u32)
//   min_rtt_stamp           @  4  (u32)
//   probe_rtt_done_stamp    @  8  (u32)
//   bw (minmax)             @ 12  (24 bytes)
//   rtt_cnt                 @ 36  (u32)
//   next_rtt_delivered      @ 40  (u32)
//   cycle_mstamp            @ 44  (u64) -- 4-byte aligned in kernel
//   _bitfield_1             @ 52  (u32, bitfields not accessed)
//   lt_bw                   @ 56  (u32)
//   lt_last_delivered       @ 60  (u32) -- wait, recheck
//   ...

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bbr {
    pub min_rtt_us: u32,            //  0..4
    pub min_rtt_stamp: u32,         //  4..8
    pub probe_rtt_done_stamp: u32,  //  8..12
    pub bw: minmax,                 // 12..36
    pub rtt_cnt: u32,               // 36..40
    pub next_rtt_delivered: u32,    // 40..44
    pub cycle_mstamp: u64,          // 44..52 (u64, 4-byte aligned here)
    pub _bitfield_1: [u8; 4],       // 52..56 (mode, flags — not accessed)
    pub lt_bw: u32,                 // 56..60
    pub lt_last_delivered: u32,     // 60..64
    pub lt_last_stamp: u32,         // 64..68  (wait — recheck against pahole)
    pub lt_last_lost: u32,          // 68..72
    pub _bitfield_2: [u8; 4],       // 72..76 (pacing_gain etc — not accessed)
    pub prior_cwnd: u32,            // 76..80
    pub full_bw: u32,               // 80..84
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "ebpf", derive(KernelRead))]
#[cfg_attr(feature = "ebpf", kernel_read(ctx(sk: *const sock, bbr: *const bbr), default_src = "bbr"))]
pub struct bbr_trace_entry {
    // Shared ID
    pub time: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16usize],
    pub dst_v6: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    // General
    pub min_rtt_us: u32,
    pub min_rtt_stamp: u32,
    pub probe_rtt_done_stamp: u32,
    //pub bw: minmax_trace,
    pub rtt_cnt: u32,
    pub next_rtt_delivered: u32,
    pub cycle_mstamp: u64,
    //pub bitfield1: u32,
    pub lt_bw: u32,
    pub lt_last_delivered: u32,
    pub lt_last_stamp: u32,
    pub lt_last_lost: u32,
    // pub bitfield2: u32,
    pub prior_cwnd: u32,
    pub full_bw: u32,
}
