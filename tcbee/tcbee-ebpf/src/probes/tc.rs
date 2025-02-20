use aya_ebpf::{
    bindings::TC_ACT_OK, helpers::gen::bpf_ktime_get_ns, macros::map, maps::RingBuf,
    programs::TcContext,
};
use memoffset::offset_of;
use tcbee_common::bindings::{
    eth_header::ethhdr,
    ip4_header::iphdr,
    ip6_header::ipv6hdr,
    tcp_header::{tcp_packet_trace, tcphdr},
};

use crate::{
    config::{
        ETHERTYPE_IPV4, 
        ETHERTYPE_IPV6, 
        ETH_HDR_LEN, 
        IP6_HDR_LEN, 
        IP_HDR_LEN, 
        TCP_PROTOCOL,
        TC_BUF_SIZE,
    },
    counters::{
        try_dropped_counter, 
        try_egress_counter, 
        try_handled_counter
    },
};

#[map(name = "TCP_PACKETS_EGRESS")]
static mut TCP_PACKETS_EGRESS: RingBuf = RingBuf::with_byte_size(TC_BUF_SIZE, 0);

#[inline(always)]
pub fn tc_hook(ctx: TcContext) -> Result<i32, i32> {
    // Get memory offset to ethertype field of ethhdr
    let ethertype_offset = offset_of!(ethhdr, h_proto);

    // Get ethertype over memory offset, error leads to go to next action and skip processing
    let ethertype = u16::from_be(ctx.load(ethertype_offset).map_err(|_| TC_ACT_OK)?);

    // Try to extract protocol field to check for TCP, stop if not IPv4 or IPv6
    let protocol: u8;
    if ethertype == ETHERTYPE_IPV4 {
        // Get protocol from packet based on IPv4 header offset
        // If packet is too short, will throw error and stop classifier
        protocol = ctx
            .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
            .map_err(|_| TC_ACT_OK)?;
    } else if ethertype == ETHERTYPE_IPV6 {
        // Get protocol from packet based on IPv6 header offset
        // If packet is too short, will throw error and stop classifier
        protocol = ctx
            .load::<u8>(ETH_HDR_LEN + offset_of!(ipv6hdr, nexthdr))
            .map_err(|_| TC_ACT_OK)?;
    } else {
        // Neither IPv6 nor IPv4 stop processing
        return Ok(TC_ACT_OK);
    }

    // Packet is not TCP, stop processing
    if protocol != TCP_PROTOCOL {
        return Ok(TC_ACT_OK);
    }

    // If this code is reached, packet is IPv4 or IPv6 TCP so process and pass to map
    let packet_trace: tcp_packet_trace;
    if ethertype == ETHERTYPE_IPV4 {
        // Get IPv4 header
        let ip4_hdr = ctx.load::<iphdr>(ETH_HDR_LEN).map_err(|_| TC_ACT_OK)?;

        // Get TCP header
        let tcp_hdr = ctx
            .load::<tcphdr>(ETH_HDR_LEN + IP_HDR_LEN)
            .map_err(|_| TC_ACT_OK)?;

        unsafe {
            // TODO: better parsing?
            packet_trace = tcp_packet_trace {
                time: bpf_ktime_get_ns(),
                saddr: ip4_hdr.saddr.to_be(),
                daddr: ip4_hdr.daddr.to_be(),
                saddr_v6: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                daddr_v6: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                sport: tcp_hdr.source.to_be(),
                dport: tcp_hdr.dest.to_be(),
                seq: tcp_hdr.seq.to_be(),
                ack: tcp_hdr.ack_seq.to_be(),
                window: tcp_hdr.window.to_be(),
                flag_urg: tcp_hdr.urg().to_be() == 1,
                flag_ack: tcp_hdr.ack().to_be() == 1,
                flag_psh: tcp_hdr.psh().to_be() == 1,
                flag_rst: tcp_hdr.rst().to_be() == 1,
                flag_fin: tcp_hdr.fin().to_be() == 1,
                flag_syn: tcp_hdr.syn().to_be() == 1,
                checksum: tcp_hdr.check.to_be(),
            };
        }
    } else {
        // Get IPv6 header
        let ip6_hdr = ctx.load::<ipv6hdr>(ETH_HDR_LEN).map_err(|_| TC_ACT_OK)?;

        // Get TCP header
        let tcp_hdr = ctx
            .load::<tcphdr>(ETH_HDR_LEN + IP6_HDR_LEN)
            .map_err(|_| TC_ACT_OK)?;

        unsafe {
            // TODO: better parsing?
            packet_trace = tcp_packet_trace {
                time: bpf_ktime_get_ns(),
                saddr: 0,
                daddr: 0,
                saddr_v6: ip6_hdr.saddr.in6_u.u6_addr8,
                daddr_v6: ip6_hdr.daddr.in6_u.u6_addr8,
                sport: tcp_hdr.source.to_be(),
                dport: tcp_hdr.dest.to_be(),
                seq: tcp_hdr.seq.to_be(),
                ack: tcp_hdr.ack_seq.to_be(),
                window: tcp_hdr.window.to_be(),
                flag_urg: tcp_hdr.urg().to_be() == 1,
                flag_ack: tcp_hdr.ack().to_be() == 1,
                flag_psh: tcp_hdr.psh().to_be() == 1,
                flag_rst: tcp_hdr.rst().to_be() == 1,
                flag_fin: tcp_hdr.fin().to_be() == 1,
                flag_syn: tcp_hdr.syn().to_be() == 1,
                checksum: tcp_hdr.check.to_be(),
            };
        }
    }

    unsafe {
        // Prepare ringbuf entry
        let reserved = TCP_PACKETS_EGRESS.reserve::<tcp_packet_trace>(0);

        // Track egress packet count
        let _ = try_egress_counter();

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(packet_trace);
            entry.submit(0);
            let _ = try_handled_counter();
        } else {
            // Not enough space, drop event
            let _ = try_dropped_counter();
        }
    }

    // Always let traffic pass to interface
    Ok(TC_ACT_OK)
}
