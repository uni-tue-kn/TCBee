//! Which writer CPU drains which ring buffer. The hook of a ring decides how often it gets
//! records: the per-packet hooks come in pairs of ingress and egress rings and each pair gets
//! a writer CPU of its own where possible, the rings of the rare hooks share one.

use std::mem::size_of;

use tcbee_common::{records::*, stats::*};
use tcbee_trace::raw;

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

/// Bytes a record of ring `rb` takes in the ring, its header and padding included; 0 for the
/// rare hooks.
/// The per-packet hooks run about once per segment each, so this is what a writer has to copy
/// per segment for the ring.
fn record_bytes(rb: u32, sock: usize) -> usize {
    let record = match rb {
        RB_TCP4_EGRESS | RB_TCP4_INGRESS | RB_TCP4_DRIVER_INGRESS | RB_TCP4_DRIVER_EGRESS => {
            size_of::<tcp4_packet_trace>()
        }
        RB_TCP6_EGRESS | RB_TCP6_INGRESS | RB_TCP6_DRIVER_INGRESS | RB_TCP6_DRIVER_EGRESS => {
            size_of::<tcp6_packet_trace>()
        }
        RB_SOCK_SEND | RB_SOCK_RECV | RB_SOCK_INGRESS => sock,
        RB_CWND_SEND | RB_CWND_RECV => size_of::<cwnd_trace_entry>(),
        RB_CUBIC => size_of::<cubic_trace_entry>(),
        RB_BBR => size_of::<bbr_trace_entry>(),
        RB_RENO => size_of::<reno_trace_entry>(),
        RB_TCP_PROBE => size_of::<tcp_probe_entry>(),
        _ => return 0,
    };
    raw::stride(record)
}

/// The hook and direction ring `rb` records: rings of one hook and direction are
/// alternatives (IPv4 or IPv6, one congestion control per connection), only one of them gets
/// a segment's record
fn hook_of(rb: u32) -> u32 {
    match rb {
        RB_TCP6_EGRESS => RB_TCP4_EGRESS,
        RB_TCP6_INGRESS => RB_TCP4_INGRESS,
        RB_TCP6_DRIVER_INGRESS => RB_TCP4_DRIVER_INGRESS,
        RB_TCP6_DRIVER_EGRESS => RB_TCP4_DRIVER_EGRESS,
        RB_BBR | RB_RENO => RB_CUBIC,
        rb => rb,
    }
}

/// The writer CPU of each of the ring buffers `rbs` (the enabled ones), from the CPUs `cpus`.
/// With G per-packet groups among them and N CPUs:
/// - G < N: each group gets a CPU of its own, in the order of `HookGroup::PER_PACKET`, and the
///   rare rings the next one; the CPUs after that get no rings.
/// - G >= N: the groups go, heaviest first, to the CPU with the fewest bytes per segment so far
///   (the first of those on a tie), then the rare rings. A group weighs, per hook and direction,
///   the `record_bytes` of its heaviest enabled ring: with all probes on two CPUs the sock rings
///   get a CPU of their own.
///
/// Empty without CPUs.
pub(crate) fn assign(rbs: &[u32], cpus: &[usize]) -> Vec<(u32, usize)> {
    assign_with(rbs, cpus, size_of::<sock_trace_entry>())
}

/// As `assign`, with sock records of `sock` bytes in the ring (field-selected records)
pub(crate) fn assign_with(rbs: &[u32], cpus: &[usize], sock: usize) -> Vec<(u32, usize)> {
    if cpus.is_empty() {
        return Vec::new();
    }
    let present = |group: HookGroup| rbs.iter().any(|&rb| HookGroup::of(rb) == group);
    let groups: Vec<HookGroup> = HookGroup::PER_PACKET
        .into_iter()
        .filter(|&group| present(group))
        .collect();
    // Per hook and direction its heaviest ring
    let weight = |group: HookGroup| -> usize {
        let mut hooks: Vec<(u32, usize)> = Vec::new();
        for &rb in rbs.iter().filter(|&&rb| HookGroup::of(rb) == group) {
            match hooks.iter_mut().find(|(hook, _)| *hook == hook_of(rb)) {
                Some((_, bytes)) => *bytes = (*bytes).max(record_bytes(rb, sock)),
                None => hooks.push((hook_of(rb), record_bytes(rb, sock))),
            }
        }
        hooks.iter().map(|&(_, bytes)| bytes).sum()
    };
    let mut weighed: Vec<(HookGroup, usize)> = groups.into_iter().map(|g| (g, weight(g))).collect();
    if weighed.len() >= cpus.len() {
        // Stable: equal weights keep the order of PER_PACKET
        weighed.sort_by_key(|&(_, bytes)| std::cmp::Reverse(bytes));
    }
    if present(HookGroup::Rare) {
        weighed.push((HookGroup::Rare, 0));
    }
    // With fewer groups than CPUs every group gets a CPU of its own, whatever it weighs
    let spread = weighed.len() <= cpus.len();
    let mut count = vec![0usize; cpus.len()];
    let mut bytes = vec![0usize; cpus.len()];
    let cpu_of: Vec<(HookGroup, usize)> = weighed
        .into_iter()
        .map(|(group, weight)| {
            let i = if spread {
                argmin(&count)
            } else {
                argmin(&bytes)
            };
            count[i] += 1;
            bytes[i] += weight;
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

/// Index of the smallest value, the first one on a tie
fn argmin(values: &[usize]) -> usize {
    (0..values.len())
        .min_by_key(|&i| (values[i], i))
        .expect("at least one CPU")
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

    /// All probes on two CPUs: the sock rings, the heaviest per segment, get a CPU alone
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
        assert_eq!(cpu(&assigned, RB_SOCK_SEND), 26);
        // A pair stays together
        assert_eq!(cpu(&assigned, RB_SOCK_RECV), 26);
        for rb in [
            RB_TCP4_EGRESS,
            RB_TCP4_INGRESS,
            RB_CWND_SEND,
            RB_CWND_RECV,
            RB_CUBIC,
            RB_TCP_PROBE,
            RB_SOCK_TIMER,
            RB_OWNERS,
        ] {
            assert_eq!(cpu(&assigned, rb), 27, "{}", RINGBUFS[rb as usize].map);
        }
    }

    /// Field-selected sock records weigh their length: short ones no longer need a CPU alone
    #[test]
    fn short_sock_records_share_a_cpu() {
        let rbs = [
            RB_TCP4_EGRESS,
            RB_TCP4_INGRESS,
            RB_SOCK_SEND,
            RB_SOCK_RECV,
            RB_CWND_SEND,
            RB_CWND_RECV,
            RB_CUBIC,
            RB_TCP_PROBE,
        ];
        let assigned = assign_with(&rbs, &[26, 27], 80);
        let sock_cpu = cpu(&assigned, RB_SOCK_SEND);
        assert!(rbs
            .iter()
            .filter(|&&rb| rb != RB_SOCK_SEND && rb != RB_SOCK_RECV)
            .any(|&rb| cpu(&assigned, rb) == sock_cpu));
        assert_eq!(
            assign_with(&rbs, &[26, 27], size_of::<sock_trace_entry>()),
            assign(&rbs, &[26, 27])
        );
    }

    /// The eval's all-probe set (-h -k -t -w -a, IPv4 and IPv6 rings, all three congestion
    /// controls): the alternatives count once, the sock rings still get a CPU alone
    #[test]
    fn alternatives_count_once() {
        let rbs = [
            RB_TCP4_EGRESS,
            RB_TCP4_INGRESS,
            RB_TCP6_EGRESS,
            RB_TCP6_INGRESS,
            RB_SOCK_SEND,
            RB_SOCK_INGRESS,
            RB_SOCK_TIMER,
            RB_CWND_SEND,
            RB_CWND_RECV,
            RB_CUBIC,
            RB_BBR,
            RB_RENO,
            RB_TCP_PROBE,
            RB_TCP_EVENTS,
            RB_RETRANSMIT_SYNACK,
            RB_BAD_CSUM,
        ];
        let assigned = assign(&rbs, &[26, 27]);
        let on_26: Vec<&str> = assigned
            .iter()
            .filter(|&&(_, cpu)| cpu == 26)
            .map(|&(rb, _)| RINGBUFS[rb as usize].map)
            .collect();
        for rb in [RB_SOCK_SEND, RB_SOCK_INGRESS] {
            assert_eq!(cpu(&assigned, rb), 26, "{on_26:?}");
        }
        for rb in [
            RB_TCP4_EGRESS,
            RB_TCP6_INGRESS,
            RB_CWND_SEND,
            RB_CUBIC,
            RB_BBR,
            RB_TCP_PROBE,
        ] {
            assert_eq!(cpu(&assigned, rb), 27, "{on_26:?}");
        }
    }

    /// On a receiver the ingress sock ring adds to the sock group, which stays the heaviest
    #[test]
    fn receiver_sock_rings_weigh_most() {
        let rbs = [
            RB_TCP4_EGRESS,
            RB_TCP4_INGRESS,
            RB_TCP6_EGRESS,
            RB_TCP6_INGRESS,
            RB_SOCK_RECV,
            RB_SOCK_INGRESS,
            RB_CWND_RECV,
            RB_TCP_PROBE,
        ];
        let assigned = assign(&rbs, &[1, 2, 3]);
        assert_eq!(cpu(&assigned, RB_SOCK_RECV), 1);
        assert_eq!(cpu(&assigned, RB_SOCK_INGRESS), 1);
        // Headers (4 rings) next, then cwnd and tcp_probe on the least loaded CPU
        assert_eq!(cpu(&assigned, RB_TCP4_EGRESS), 2);
        assert_eq!(cpu(&assigned, RB_CWND_RECV), 3);
        assert_eq!(cpu(&assigned, RB_TCP_PROBE), 3);
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

    /// As many groups as CPUs and no rare rings: each group a CPU of its own, heaviest first
    #[test]
    fn as_many_groups_as_cpus_without_rare_rings() {
        let rbs = [RB_TCP4_EGRESS, RB_CWND_SEND, RB_SOCK_SEND];
        let assigned = assign(&rbs, &[1, 2, 3]);
        assert_eq!(cpu(&assigned, RB_SOCK_SEND), 1);
        assert_eq!(cpu(&assigned, RB_CWND_SEND), 2);
        assert_eq!(cpu(&assigned, RB_TCP4_EGRESS), 3);
    }

    #[test]
    fn as_many_pairs_as_cpus() {
        let rbs = [RB_TCP4_EGRESS, RB_SOCK_SEND, RB_OWNERS];
        let assigned = assign(&rbs, &[1, 2]);
        // Heaviest first
        assert_eq!(cpu(&assigned, RB_SOCK_SEND), 1);
        assert_eq!(cpu(&assigned, RB_TCP4_EGRESS), 2);
        // The rare rings share the lighter group's CPU
        assert_eq!(cpu(&assigned, RB_OWNERS), 2);
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
