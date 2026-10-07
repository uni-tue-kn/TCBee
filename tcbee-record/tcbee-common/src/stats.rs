//! Layout of the `STATS` per-CPU counter array shared by the eBPF programs and userspace.
//!
//! Every ring buffer owns three consecutive u64 slots. A probe invocation that passes the
//! filter increments exactly one of `STAT_HANDLED` (record submitted), `STAT_DROPPED`
//! (ring buffer full) or `STAT_ERROR` (kernel read failed). The number of invocations
//! is their sum.

pub const RB_TCP4_EGRESS: u32 = 0;
pub const RB_TCP4_INGRESS: u32 = 1;
pub const RB_TCP6_EGRESS: u32 = 2;
pub const RB_TCP6_INGRESS: u32 = 3;
pub const RB_SOCK_SEND: u32 = 4;
pub const RB_SOCK_RECV: u32 = 5;
pub const RB_CWND_SEND: u32 = 6;
pub const RB_CWND_RECV: u32 = 7;
pub const RB_TCP_PROBE: u32 = 8;
pub const RB_RETRANSMIT_SYNACK: u32 = 9;
pub const RB_BAD_CSUM: u32 = 10;
pub const RB_CUBIC: u32 = 11;
pub const RB_BBR: u32 = 12;
pub const RB_COUNT: u32 = 13;

pub const STAT_HANDLED: u32 = 0;
pub const STAT_DROPPED: u32 = 1;
pub const STAT_ERROR: u32 = 2;
pub const STATS_PER_RB: u32 = 3;
pub const STATS_LEN: u32 = RB_COUNT * STATS_PER_RB;

/// Slots whose sum is the number of probe invocations of a ring buffer
pub const fn invocation_slots(rb: u32) -> [u32; 3] {
    [slot(rb, STAT_HANDLED), slot(rb, STAT_DROPPED), slot(rb, STAT_ERROR)]
}

#[inline(always)]
pub const fn slot(rb: u32, stat: u32) -> u32 {
    rb * STATS_PER_RB + stat
}

/// Ring buffer map names and the `--ringbuf-size` group they belong to, indexed by `RB_*`.
pub const RINGBUFS: [(&str, &str); RB_COUNT as usize] = [
    ("TCP4_PACKETS_EGRESS", "tcp4"),
    ("TCP4_PACKETS_INGRESS", "tcp4"),
    ("TCP6_PACKETS_EGRESS", "tcp6"),
    ("TCP6_PACKETS_INGRESS", "tcp6"),
    ("TCP_SEND_SOCK_EVENTS", "sock"),
    ("TCP_RECV_SOCK_EVENTS", "sock"),
    ("TCP_SEND_CWND_EVENTS", "cwnd"),
    ("TCP_RECEIVE_CWND_EVENTS", "cwnd"),
    ("TCP_PROBE_QUEUE", "tcp_probe"),
    ("TCP_RETRANSMIT_SYNACK_QUEUE", "synack"),
    ("TCP_BAD_CSUM_QUEUE", "bad_csum"),
    ("CUBIC_EVENTS", "cubic"),
    ("BBR_EVENTS", "bbr"),
];
