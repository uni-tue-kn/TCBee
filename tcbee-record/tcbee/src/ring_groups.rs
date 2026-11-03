//! Which writer CPU drains which ring buffer. The hook of a ring decides how often it gets
//! records: the per-packet hooks come in pairs of ingress and egress rings and each pair gets
//! a writer CPU of its own where possible, the rings of the rare hooks share one.

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
    /// The per-packet groups in the order they get writer CPUs
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

/// The writer CPU of each of the ring buffers `rbs` (the enabled ones), from the CPUs `cpus`.
/// With G per-packet groups among them and N CPUs:
/// - G < N: each group gets a CPU of its own, in the order of `HookGroup::PER_PACKET`, and the
///   rare rings the next one; the CPUs after that get no rings.
/// - G >= N: the groups, then the rare rings, go one by one to the CPU with the fewest groups
///   (the first of those on a tie). With G == N the rare rings share the first group's CPU.
///
/// Empty without CPUs.
pub(crate) fn assign(rbs: &[u32], cpus: &[usize]) -> Vec<(u32, usize)> {
    if cpus.is_empty() {
        return Vec::new();
    }
    let present = |group: HookGroup| rbs.iter().any(|&rb| HookGroup::of(rb) == group);
    let mut groups: Vec<HookGroup> = HookGroup::PER_PACKET
        .into_iter()
        .filter(|&group| present(group))
        .collect();
    if present(HookGroup::Rare) {
        groups.push(HookGroup::Rare);
    }
    let mut load = vec![0usize; cpus.len()];
    let cpu_of: Vec<(HookGroup, usize)> = groups
        .into_iter()
        .map(|group| {
            let (i, _) = load
                .iter()
                .enumerate()
                .min_by_key(|&(i, &n)| (n, i))
                .expect("at least one CPU");
            load[i] += 1;
            (group, cpus[i])
        })
        .collect();
    rbs.iter()
        .map(|&rb| {
            let group = HookGroup::of(rb);
            let cpu = cpu_of
                .iter()
                .find(|(g, _)| *g == group)
                .map(|&(_, cpu)| cpu)
                .expect("every group of rbs has a CPU");
            (rb, cpu)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(assigned: &[(u32, usize)], rb: u32) -> usize {
        assigned.iter().find(|(r, _)| *r == rb).unwrap().1
    }

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

    /// The author's example: one per-packet hook pair on two CPUs, the rest on the other
    #[test]
    fn one_pair_and_the_rare_rings_on_two_cpus() {
        let rbs = [
            RB_TCP4_EGRESS,
            RB_TCP4_INGRESS,
            RB_TCP6_EGRESS,
            RB_TCP6_INGRESS,
            RB_OWNERS,
            RB_TCP_EVENTS,
        ];
        let assigned = assign(&rbs, &[26, 27]);
        for rb in [
            RB_TCP4_EGRESS,
            RB_TCP4_INGRESS,
            RB_TCP6_EGRESS,
            RB_TCP6_INGRESS,
        ] {
            assert_eq!(cpu(&assigned, rb), 26);
        }
        assert_eq!(cpu(&assigned, RB_OWNERS), 27);
        assert_eq!(cpu(&assigned, RB_TCP_EVENTS), 27);
    }

    /// All probes on two CPUs: the groups alternate, the rare rings take the emptier CPU
    #[test]
    fn all_probes_on_two_cpus() {
        let rbs = [
            RB_TCP4_EGRESS,
            RB_TCP4_INGRESS,
            RB_SOCK_SEND,
            RB_SOCK_RECV,
            RB_CWND_SEND,
            RB_CWND_RECV,
            RB_CUBIC,
            RB_TCP_PROBE,
            RB_SOCK_TIMER,
            RB_OWNERS,
        ];
        let assigned = assign(&rbs, &[26, 27]);
        assert_eq!(cpu(&assigned, RB_TCP4_EGRESS), 26);
        assert_eq!(cpu(&assigned, RB_SOCK_SEND), 27);
        assert_eq!(cpu(&assigned, RB_CWND_SEND), 26);
        assert_eq!(cpu(&assigned, RB_CUBIC), 27);
        assert_eq!(cpu(&assigned, RB_TCP_PROBE), 26);
        assert_eq!(cpu(&assigned, RB_SOCK_TIMER), 27);
        // A pair stays together
        assert_eq!(cpu(&assigned, RB_SOCK_RECV), 27);
        assert_eq!(cpu(&assigned, RB_TCP4_INGRESS), 26);
    }

    #[test]
    fn tc_and_driver_headers_are_two_pairs() {
        let rbs = [
            RB_TCP4_EGRESS,
            RB_TCP4_INGRESS,
            RB_TCP4_DRIVER_EGRESS,
            RB_TCP4_DRIVER_INGRESS,
            RB_OWNERS,
        ];
        let assigned = assign(&rbs, &[1, 2, 3]);
        assert_eq!(cpu(&assigned, RB_TCP4_EGRESS), 1);
        assert_eq!(cpu(&assigned, RB_TCP4_DRIVER_EGRESS), 2);
        assert_eq!(cpu(&assigned, RB_OWNERS), 3);
    }

    #[test]
    fn as_many_pairs_as_cpus() {
        let rbs = [RB_TCP4_EGRESS, RB_SOCK_SEND, RB_OWNERS];
        let assigned = assign(&rbs, &[1, 2]);
        assert_eq!(cpu(&assigned, RB_TCP4_EGRESS), 1);
        assert_eq!(cpu(&assigned, RB_SOCK_SEND), 2);
        // Stated: the rare rings share the first group's CPU
        assert_eq!(cpu(&assigned, RB_OWNERS), 1);
    }

    #[test]
    fn only_rare_rings_and_more_cpus_than_groups() {
        // -k with its default hooks: no per-packet ring
        let rbs = [RB_SOCK_TIMER, RB_SOCK_EVENT, RB_OWNERS];
        let assigned = assign(&rbs, &[4, 5, 6]);
        assert!(assigned.iter().all(|&(_, cpu)| cpu == 4));
        // One CPU takes everything
        let rbs = [RB_TCP4_EGRESS, RB_SOCK_SEND, RB_OWNERS];
        assert!(assign(&rbs, &[9]).iter().all(|&(_, cpu)| cpu == 9));
        // No CPUs: no assignment
        assert!(assign(&rbs, &[]).is_empty());
    }
}
