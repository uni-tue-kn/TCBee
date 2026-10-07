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

/// A ring buffer map of the eBPF object: an array with one ring buffer per CPU
pub struct RingBuf {
    /// Map name (the kernel shows the first 15 characters)
    pub map: &'static str,
    /// `--ringbuf-size` group
    pub group: &'static str,
    /// Default size of each CPU's ring buffer in bytes. A flow's events mostly land on one
    /// or two CPUs, so a ring has to absorb a writer stall at a single CPU's event rate.
    pub size_per_cpu: u32,
}

const fn rb(map: &'static str, group: &'static str, mib: u32) -> RingBuf {
    RingBuf {
        map,
        group,
        size_per_cpu: mib << 20,
    }
}

/// All ring buffer maps, indexed by `RB_*`. IPv6 rings are smaller as they stay empty in
/// most recordings.
pub const RINGBUFS: [RingBuf; RB_COUNT as usize] = [
    rb("TCP4_PACKETS_EGRESS", "tcp4", 16),
    rb("TCP4_PACKETS_INGRESS", "tcp4", 16),
    rb("TCP6_PACKETS_EGRESS", "tcp6", 4),
    rb("TCP6_PACKETS_INGRESS", "tcp6", 4),
    rb("TCP_SEND_SOCK_EVENTS", "sock", 16),
    rb("TCP_RECV_SOCK_EVENTS", "sock", 16),
    rb("TCP_SEND_CWND_EVENTS", "cwnd", 8),
    rb("TCP_RECEIVE_CWND_EVENTS", "cwnd", 8),
    rb("TCP_PROBE_QUEUE", "tcp_probe", 4),
    rb("TCP_RETRANSMIT_SYNACK_QUEUE", "synack", 1),
    rb("TCP_BAD_CSUM_QUEUE", "bad_csum", 1),
    rb("CUBIC_EVENTS", "cubic", 8),
    rb("BBR_EVENTS", "bbr", 8),
];
