//! How the watcher groups the ring buffers: one probe group per chart or table row

use tcbee_common::stats::{
    RB_BAD_CSUM, RB_BBR, RB_CUBIC, RB_CWND_RECV, RB_CWND_SEND, RB_MPTCP_PM, RB_RENO,
    RB_RETRANSMIT_SYNACK, RB_SOCK_EVENT, RB_SOCK_INGRESS, RB_SOCK_RECV, RB_SOCK_SEND,
    RB_SOCK_TIMER, RB_TCP4_DRIVER_EGRESS, RB_TCP4_DRIVER_INGRESS, RB_TCP4_EGRESS, RB_TCP4_INGRESS,
    RB_TCP6_DRIVER_EGRESS, RB_TCP6_DRIVER_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS, RB_TCP_EVENTS,
    RB_TCP_PROBE,
};

/// A probe group, in the order its chart gets a slot
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// Packet headers at TC or in the driver (-h)
    Headers,
    /// Socket and cwnd hooks (-k, -w)
    Sock,
    /// Congestion control internals: CUBIC, BBR and Reno (-a)
    Cc,
    /// The tracepoints of -t
    Tracepoints,
    /// The TCP event hooks of -t
    TcpEvents,
    /// MPTCP path manager events
    Mptcp,
}

/// The probe group the watcher shows ring buffer `rb` in
pub fn display_group(rb: u32) -> Group {
    match rb {
        RB_TCP4_EGRESS | RB_TCP4_INGRESS | RB_TCP6_EGRESS | RB_TCP6_INGRESS => Group::Headers,
        RB_TCP4_DRIVER_INGRESS
        | RB_TCP6_DRIVER_INGRESS
        | RB_TCP4_DRIVER_EGRESS
        | RB_TCP6_DRIVER_EGRESS => Group::Headers,
        RB_SOCK_SEND | RB_SOCK_RECV | RB_SOCK_TIMER | RB_SOCK_INGRESS | RB_SOCK_EVENT => {
            Group::Sock
        }
        RB_CWND_SEND | RB_CWND_RECV => Group::Sock,
        RB_CUBIC | RB_BBR | RB_RENO => Group::Cc,
        RB_TCP_PROBE | RB_RETRANSMIT_SYNACK | RB_BAD_CSUM => Group::Tracepoints,
        RB_TCP_EVENTS => Group::TcpEvents,
        RB_MPTCP_PM => Group::Mptcp,
        _ => panic!("ring buffer {rb} has no display group"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use tcbee_common::stats::RB_COUNT;

    use super::*;

    #[test]
    fn every_ring_has_a_group() {
        let groups: HashSet<Group> = (0..RB_COUNT).map(display_group).collect();
        // And every group has a ring
        assert_eq!(groups.len(), 6);
    }
}
