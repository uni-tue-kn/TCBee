use aya_ebpf::{
    bindings::TC_ACT_UNSPEC, helpers::generated::bpf_ktime_get_ns, macros::map, maps::RingBuf,
    programs::TcContext,
};
use memoffset::offset_of;
use tcbee_common::{
    bindings::{
        eth_header::ethhdr,
        flow::IpTuple,
        ip4_header::iphdr,
        ip6_header::ipv6hdr,
        tcp_header::{tcp4_packet_trace, tcp6_packet_trace, tcphdr},
    },
    stats::{RB_TCP4_EGRESS, RB_TCP4_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS},
};

use crate::{
    config::{
        ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETH_HDR_LEN, IP6_HDR_LEN, IP_HDR_LEN, IP_OFFSET_MASK,
        TC4_BUF_SIZE, TC6_BUF_SIZE, TCP_PROTOCOL,
    },
    counters::{count_attempt, submit},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
};

#[map(name = "TCP4_PACKETS_EGRESS")]
static TCP4_PACKETS_EGRESS: RingBuf = RingBuf::with_byte_size(TC4_BUF_SIZE, 0);

#[map(name = "TCP4_PACKETS_INGRESS")]
static TCP4_PACKETS_INGRESS: RingBuf = RingBuf::with_byte_size(TC4_BUF_SIZE, 0);

#[map(name = "TCP6_PACKETS_EGRESS")]
static TCP6_PACKETS_EGRESS: RingBuf = RingBuf::with_byte_size(TC6_BUF_SIZE, 0);

#[map(name = "TCP6_PACKETS_INGRESS")]
static TCP6_PACKETS_INGRESS: RingBuf = RingBuf::with_byte_size(TC6_BUF_SIZE, 0);

#[inline(always)]
pub fn tc_egress_hook(ctx: TcContext) -> Result<i32, i32> {
    trace_packet(
        &ctx,
        &TCP4_PACKETS_EGRESS,
        RB_TCP4_EGRESS,
        &TCP6_PACKETS_EGRESS,
        RB_TCP6_EGRESS,
    )
}

#[inline(always)]
pub fn tc_ingress_hook(ctx: TcContext) -> Result<i32, i32> {
    trace_packet(
        &ctx,
        &TCP4_PACKETS_INGRESS,
        RB_TCP4_INGRESS,
        &TCP6_PACKETS_INGRESS,
        RB_TCP6_INGRESS,
    )
}

// Every early return happens before the filter, so a packet that passes the filter is
// always counted as attempted and then as handled or dropped.
#[inline(always)]
fn trace_packet(
    ctx: &TcContext,
    rb4: &RingBuf,
    rb4_id: u32,
    rb6: &RingBuf,
    rb6_id: u32,
) -> Result<i32, i32> {
    // Get ethertype over memory offset, error leads to go to next action and skip processing
    let ethertype = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_UNSPEC)?,
    );

    if ethertype == ETHERTYPE_IPV4 {
        // If packet is too short, will throw error and stop classifier
        let ip4_hdr = ctx.load::<iphdr>(ETH_HDR_LEN).map_err(|_| TC_ACT_UNSPEC)?;
        // Non-first fragments carry no TCP header
        if ip4_hdr.protocol != TCP_PROTOCOL || u16::from_be(ip4_hdr.frag_off) & IP_OFFSET_MASK != 0
        {
            return Ok(TC_ACT_UNSPEC);
        }
        let ip_hdr_len = ((ip4_hdr.ihl() as usize) << 2).max(IP_HDR_LEN);
        let tcp_hdr = ctx
            .load::<tcphdr>(ETH_HDR_LEN + ip_hdr_len)
            .map_err(|_| TC_ACT_UNSPEC)?;

        let saddr = u32::from_be(ip4_hdr.saddr);
        let daddr = u32::from_be(ip4_hdr.daddr);
        let sport = u16::from_be(tcp_hdr.source);
        let dport = u16::from_be(tcp_hdr.dest);
        let mut src_ip = [0u8; 16];
        src_ip[..4].copy_from_slice(&saddr.to_be_bytes());
        let mut dst_ip = [0u8; 16];
        dst_ip[..4].copy_from_slice(&daddr.to_be_bytes());
        let tuple = IpTuple {
            src_ip,
            dst_ip,
            sport,
            dport,
            protocol: 6,
        };
        if !filter_ports_match(sport, dport)
            || (filter_needs_tuple() && !filter_tuple_match(&tuple))
        {
            return Ok(TC_ACT_UNSPEC);
        }

        count_attempt(rb4_id);
        submit(
            rb4,
            rb4_id,
            tcp4_packet_trace {
                time: unsafe { bpf_ktime_get_ns() },
                saddr,
                daddr,
                sport,
                dport,
                seq: u32::from_be(tcp_hdr.seq),
                ack: u32::from_be(tcp_hdr.ack_seq),
                window: u16::from_be(tcp_hdr.window),
                flags: tcp_hdr._bitfield_1.get(8, 8) as u8,
            },
        );

        let _ = try_flow_tracker(tuple);
    } else if ethertype == ETHERTYPE_IPV6 {
        // Extension headers are not parsed, nexthdr must be TCP directly
        let ip6_hdr = ctx
            .load::<ipv6hdr>(ETH_HDR_LEN)
            .map_err(|_| TC_ACT_UNSPEC)?;
        if ip6_hdr.nexthdr != TCP_PROTOCOL {
            return Ok(TC_ACT_UNSPEC);
        }
        let tcp_hdr = ctx
            .load::<tcphdr>(ETH_HDR_LEN + IP6_HDR_LEN)
            .map_err(|_| TC_ACT_UNSPEC)?;

        let sport = u16::from_be(tcp_hdr.source);
        let dport = u16::from_be(tcp_hdr.dest);
        let (saddr_v6, daddr_v6) =
            unsafe { (ip6_hdr.saddr.in6_u.u6_addr8, ip6_hdr.daddr.in6_u.u6_addr8) };
        let tuple = IpTuple {
            src_ip: saddr_v6,
            dst_ip: daddr_v6,
            sport,
            dport,
            protocol: 6,
        };
        if !filter_ports_match(sport, dport)
            || (filter_needs_tuple() && !filter_tuple_match(&tuple))
        {
            return Ok(TC_ACT_UNSPEC);
        }

        count_attempt(rb6_id);
        submit(
            rb6,
            rb6_id,
            tcp6_packet_trace {
                time: unsafe { bpf_ktime_get_ns() },
                saddr_v6,
                daddr_v6,
                sport,
                dport,
                seq: u32::from_be(tcp_hdr.seq),
                ack: u32::from_be(tcp_hdr.ack_seq),
                window: u16::from_be(tcp_hdr.window),
                flags: tcp_hdr._bitfield_1.get(8, 8) as u8,
            },
        );

        let _ = try_flow_tracker(tuple);
    }

    // TC_ACT_UNSPEC hands the packet to the next program unchanged. TC_ACT_OK would
    // end the chain on tcx and skip programs attached after this one.
    Ok(TC_ACT_UNSPEC)
}
