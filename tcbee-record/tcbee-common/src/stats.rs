//! Layout of the `STATS` per-CPU counter array shared by the eBPF programs and userspace.
//!
//! Every ring buffer owns three consecutive u64 slots. A probe invocation that passes the
//! filter increments exactly one of `STAT_HANDLED` (record submitted), `STAT_DROPPED`
//! (ring buffer full), `STAT_ERROR` (kernel read failed) or, in on-change mode, the ring's
//! suppressed slot (watched fields unchanged, no record). The number of invocations is their
//! sum. The suppressed slots and the state error slot follow the per-ring slots, so the
//! layout of the first `RB_COUNT * STATS_PER_RB` slots does not depend on the mode.

use tcbee_trace::TraceFile;

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
pub const RB_MPTCP_PM: u32 = 13;
pub const RB_TCP_EVENTS: u32 = 14;
pub const RB_COUNT: u32 = 15;

pub const STAT_HANDLED: u32 = 0;
pub const STAT_DROPPED: u32 = 1;
pub const STAT_ERROR: u32 = 2;
pub const STATS_PER_RB: u32 = 3;
/// First of the `RB_COUNT` suppressed slots, one per ring buffer
pub const STATS_SUPPRESSED_BASE: u32 = RB_COUNT * STATS_PER_RB;
/// On-change runs that found no socket storage and wrote a full record
pub const STATS_STATE_ERR: u32 = STATS_SUPPRESSED_BASE + RB_COUNT;
pub const STATS_LEN: u32 = STATS_STATE_ERR + 1;

/// Slots whose sum is the number of probe invocations of a ring buffer
pub const fn invocation_slots(rb: u32) -> [u32; 4] {
    [
        slot(rb, STAT_HANDLED),
        slot(rb, STAT_DROPPED),
        slot(rb, STAT_ERROR),
        suppressed_slot(rb),
    ]
}

/// Slot of the runs an on-change probe of this ring buffer suppressed
pub const fn suppressed_slot(rb: u32) -> u32 {
    STATS_SUPPRESSED_BASE + rb
}

#[inline(always)]
pub const fn slot(rb: u32, stat: u32) -> u32 {
    rb * STATS_PER_RB + stat
}

/// A ring buffer map of the eBPF object: an array with one ring buffer per CPU
pub struct RingBuf {
    /// Map name (the kernel shows the first 15 characters)
    pub map: &'static str,
    /// Trace file its records are written to
    pub file: TraceFile,
    /// `--ringbuf-size` group
    pub group: &'static str,
    /// Default size of each CPU's ring buffer in bytes. A flow's events mostly land on one
    /// or two CPUs, so a ring has to absorb a writer stall at a single CPU's event rate.
    pub size_per_cpu: u32,
}

const fn rb(map: &'static str, file: TraceFile, group: &'static str, mib: u32) -> RingBuf {
    RingBuf {
        map,
        file,
        group,
        size_per_cpu: mib << 20,
    }
}

/// All ring buffer maps, indexed by `RB_*`. IPv6 rings are smaller as they stay empty in
/// most recordings. `tests/c_mirror.rs` checks the ids and map names against the eBPF sources.
pub const RINGBUFS: [RingBuf; RB_COUNT as usize] = [
    rb("TCP4_PACKETS_EGRESS", TraceFile::Tcp4Send, "tcp4", 16),
    rb("TCP4_PACKETS_INGRESS", TraceFile::Tcp4Receive, "tcp4", 16),
    rb("TCP6_PACKETS_EGRESS", TraceFile::Tcp6Send, "tcp6", 4),
    rb("TCP6_PACKETS_INGRESS", TraceFile::Tcp6Receive, "tcp6", 4),
    rb("TCP_SEND_SOCK_EVENTS", TraceFile::SendSock, "sock", 16),
    rb("TCP_RECV_SOCK_EVENTS", TraceFile::RecvSock, "sock", 16),
    rb("TCP_SEND_CWND_EVENTS", TraceFile::SendCwnd, "cwnd", 8),
    rb("TCP_RECEIVE_CWND_EVENTS", TraceFile::RecvCwnd, "cwnd", 8),
    rb("TCP_PROBE_QUEUE", TraceFile::TcpProbe, "tcp_probe", 4),
    rb(
        "TCP_RETRANSMIT_SYNACK_QUEUE",
        TraceFile::TcpRetransmitSynack,
        "synack",
        1,
    ),
    rb("TCP_BAD_CSUM_QUEUE", TraceFile::TcpBadCsum, "bad_csum", 1),
    rb("CUBIC_EVENTS", TraceFile::Cubic, "cubic", 8),
    rb("BBR_EVENTS", TraceFile::Bbr, "bbr", 8),
    rb("MPTCP_PM_EVENTS", TraceFile::MptcpPm, "mptcp_pm", 1),
    rb("TCP_EVENTS", TraceFile::TcpEvents, "tcp_events", 4),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appended_slots_follow_the_per_ring_slots() {
        // The first RB_COUNT * STATS_PER_RB slots keep their layout in every mode
        assert_eq!(slot(RB_TCP_EVENTS, STAT_ERROR), RB_COUNT * STATS_PER_RB - 1);
        assert_eq!(suppressed_slot(0), RB_COUNT * STATS_PER_RB);
        assert_eq!(suppressed_slot(RB_TCP_EVENTS) + 1, STATS_STATE_ERR);
        assert_eq!(RB_TCP_EVENTS, RB_COUNT - 1);
        assert_eq!(STATS_LEN, 61);
        let all: Vec<u32> = (0..RB_COUNT).flat_map(invocation_slots).collect();
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "a slot counts for two rings");
        assert!(!all.contains(&STATS_STATE_ERR));
    }
}
