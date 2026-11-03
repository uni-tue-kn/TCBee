//! Which writer CPU drains which ring buffer. The hook of a ring decides how often it gets
//! records: the per-packet hooks come in pairs of ingress and egress rings, the rare hooks
//! (timers, events) get a few records per connection.

use tcbee_common::stats::*;

/// The rings of one hook pair, or all rings of the rare hooks
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum HookGroup {
    /// Header records at the TC hooks, IPv4 and IPv6, received and sent
    HeadersTc,
    /// Header records at the driver hooks (XDP, net_dev_start_xmit)
    HeadersDriver,
    /// Socket records per sent and received segment
    Sock,
    /// Congestion window records per sent and received segment
    Cwnd,
    /// Congestion control internals, per ACK
    Cc,
    /// tcp_probe, at every received segment
    TcpProbe,
    /// Timers, socket and TCP events, SYN-ACK retransmissions, bad checksums, MPTCP path
    /// manager events, flow owners
    Rare,
}

impl HookGroup {
    /// The per-packet groups
    const PER_PACKET: [HookGroup; 6] = [
        HookGroup::HeadersTc,
        HookGroup::HeadersDriver,
        HookGroup::Sock,
        HookGroup::Cwnd,
        HookGroup::Cc,
        HookGroup::TcpProbe,
    ];

    /// The group of ring buffer `rb` (an index into `RINGBUFS`)
    pub(crate) const fn of(rb: u32) -> HookGroup {
        match rb {
            RB_TCP4_EGRESS | RB_TCP4_INGRESS | RB_TCP6_EGRESS | RB_TCP6_INGRESS => {
                HookGroup::HeadersTc
            }
            RB_TCP4_DRIVER_INGRESS
            | RB_TCP6_DRIVER_INGRESS
            | RB_TCP4_DRIVER_EGRESS
            | RB_TCP6_DRIVER_EGRESS => HookGroup::HeadersDriver,
            RB_SOCK_SEND | RB_SOCK_RECV | RB_SOCK_INGRESS => HookGroup::Sock,
            RB_CWND_SEND | RB_CWND_RECV => HookGroup::Cwnd,
            RB_CUBIC | RB_BBR | RB_RENO => HookGroup::Cc,
            RB_TCP_PROBE => HookGroup::TcpProbe,
            _ => HookGroup::Rare,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_ring_has_a_group() {
        let per_packet = (0..RB_COUNT)
            .filter(|&rb| HookGroup::of(rb) != HookGroup::Rare)
            .count();
        // 8 header rings, 3 sock, 2 cwnd, 3 congestion control, tcp_probe
        assert_eq!(per_packet, 17);
        for rare in [
            RB_RETRANSMIT_SYNACK,
            RB_BAD_CSUM,
            RB_MPTCP_PM,
            RB_TCP_EVENTS,
            RB_SOCK_TIMER,
            RB_SOCK_EVENT,
            RB_OWNERS,
        ] {
            assert_eq!(
                HookGroup::of(rare),
                HookGroup::Rare,
                "{}",
                RINGBUFS[rare as usize].map
            );
        }
    }
}
