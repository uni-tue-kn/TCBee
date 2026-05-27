use aya_ebpf::{
    bindings::TC_ACT_OK, helpers::generated::bpf_ktime_get_ns, macros::map, maps::RingBuf,
    programs::TcContext,
};
use memoffset::offset_of;
use tcbee_common::bindings::{
    eth_header::ethhdr,
    flow::IpTuple,
    ip4_header::iphdr,
    ip6_header::ipv6hdr,
    tcp_header::{tcp4_packet_trace, tcp6_packet_trace, tcphdr},
};

use crate::{
    config::{
        ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETH_HDR_LEN, IP6_HDR_LEN, IP_HDR_LEN, TC4_BUF_SIZE,
        TC6_BUF_SIZE, TCP_PROTOCOL,
    },
    counters::{try_dropped_counter, try_egress_counter, try_handled_counter, try_ingress_counter},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
};

#[map(name = "TCP4_PACKETS_EGRESS")]
static mut TCP4_PACKETS_EGRESS: RingBuf = RingBuf::with_byte_size(TC4_BUF_SIZE, 0);

#[map(name = "TCP4_PACKETS_INGRESS")]
static mut TCP4_PACKETS_INGRESS: RingBuf = RingBuf::with_byte_size(TC4_BUF_SIZE, 0);

#[map(name = "TCP6_PACKETS_EGRESS")]
static mut TCP6_PACKETS_EGRESS: RingBuf = RingBuf::with_byte_size(TC6_BUF_SIZE, 0);

#[map(name = "TCP6_PACKETS_INGRESS")]
static mut TCP6_PACKETS_INGRESS: RingBuf = RingBuf::with_byte_size(TC6_BUF_SIZE, 0);

#[inline(always)]
pub fn tc_egress_hook(ctx: TcContext) -> Result<i32, i32> {
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
    if ethertype == ETHERTYPE_IPV4 {
        // Get IPv4 header
        let ip4_hdr = ctx.load::<iphdr>(ETH_HDR_LEN).map_err(|_| TC_ACT_OK)?;
        let ip_hdr_len = ((ip4_hdr.ihl() as usize) << 2).max(IP_HDR_LEN);
        let tcp_offset = ETH_HDR_LEN + ip_hdr_len;

        // Get TCP header
        let tcp_hdr = ctx.load::<tcphdr>(tcp_offset).map_err(|_| TC_ACT_OK)?;

        unsafe {
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
                return Ok(TC_ACT_OK);
            }
            let seq = u32::from_be(tcp_hdr.seq);
            let ack = u32::from_be(tcp_hdr.ack_seq);
            let window = u16::from_be(tcp_hdr.window);
            //let checksum = u16::from_be(tcp_hdr.check);

            unsafe {
                // Prepare ringbuf entry
                let reserved = TCP4_PACKETS_EGRESS.reserve::<tcp4_packet_trace>(0);

                // Track egress packet count
                let _ = try_egress_counter();

                // Check if space left for entry
                if let Some(mut entry) = reserved {
                    // Enough space, write and track handled events
                    entry.write(tcp4_packet_trace {
                        time: bpf_ktime_get_ns(),
                        saddr,
                        daddr,
                        sport,
                        dport,
                        seq,
                        ack,
                        window,
                        //flags
                        flags: tcp_hdr._bitfield_1.get(8, 8) as u8,
                    });
                    entry.submit(1);
                    let _ = try_handled_counter();
                } else {
                    // Not enough space, drop event
                    let _ = try_dropped_counter();
                }
            }

            // TODO: can this be done cleaner? E.g. have one map for v4 and one map for v6?
            let _ = try_flow_tracker(tuple);
        }
    } else {
        // Get IPv6 header
        let ip6_hdr = ctx.load::<ipv6hdr>(ETH_HDR_LEN).map_err(|_| TC_ACT_OK)?;

        // Get TCP header
        let tcp_hdr = ctx
            .load::<tcphdr>(ETH_HDR_LEN + IP6_HDR_LEN)
            .map_err(|_| TC_ACT_OK)?;

        unsafe {
            let sport = u16::from_be(tcp_hdr.source);
            let dport = u16::from_be(tcp_hdr.dest);
            let tuple = IpTuple {
                src_ip: ip6_hdr.saddr.in6_u.u6_addr8,
                dst_ip: ip6_hdr.daddr.in6_u.u6_addr8,
                sport,
                dport,
                protocol: 6,
            };
            if !filter_ports_match(sport, dport)
                || (filter_needs_tuple() && !filter_tuple_match(&tuple))
            {
                return Ok(TC_ACT_OK);
            }
            let seq = u32::from_be(tcp_hdr.seq);
            let ack = u32::from_be(tcp_hdr.ack_seq);
            let window = u16::from_be(tcp_hdr.window);
            let checksum = u16::from_be(tcp_hdr.check);

            unsafe {
                // Prepare ringbuf entry
                let reserved = TCP6_PACKETS_EGRESS.reserve::<tcp6_packet_trace>(0);

                // Track egress packet count
                let _ = try_egress_counter();

                // Check if space left for entry
                if let Some(mut entry) = reserved {
                    // Enough space, write and track handled events
                    entry.write(tcp6_packet_trace {
                        time: bpf_ktime_get_ns(),
                        //saddr_v6: [0u8; 16],
                        //daddr_v6: [0u8; 16],
                        saddr_v6: ip6_hdr.saddr.in6_u.u6_addr8,
                        daddr_v6: ip6_hdr.daddr.in6_u.u6_addr8,
                        sport,
                        dport,
                        seq,
                        ack,
                        window,
                        //flags
                        flags: tcp_hdr._bitfield_1.get(8, 8) as u8,
                    });
                    entry.submit(1);
                    let _ = try_handled_counter();
                } else {
                    // Not enough space, drop event
                    let _ = try_dropped_counter();
                }
            }

            // Write to flow tracker

            let _a = try_flow_tracker(tuple);
        }
    }

    // Always let traffic pass to interface
    Ok(TC_ACT_OK)
}

#[inline(always)]
pub fn tc_ingress_hook(ctx: TcContext) -> Result<i32, i32> {
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
    if ethertype == ETHERTYPE_IPV4 {
        // Get IPv4 header
        let ip4_hdr = ctx.load::<iphdr>(ETH_HDR_LEN).map_err(|_| TC_ACT_OK)?;
        let ip_hdr_len = ((ip4_hdr.ihl() as usize) << 2).max(IP_HDR_LEN);
        let tcp_offset = ETH_HDR_LEN + ip_hdr_len;

        // Get TCP header
        let tcp_hdr = ctx.load::<tcphdr>(tcp_offset).map_err(|_| TC_ACT_OK)?;

        unsafe {
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
                return Ok(TC_ACT_OK);
            }
            let seq = u32::from_be(tcp_hdr.seq);
            let ack = u32::from_be(tcp_hdr.ack_seq);
            let window = u16::from_be(tcp_hdr.window);

            unsafe {
                // Prepare ringbuf entry
                let reserved = TCP4_PACKETS_INGRESS.reserve::<tcp4_packet_trace>(0);

                // Track egress packet count
                let _ = try_ingress_counter();

                // Check if space left for entry
                if let Some(mut entry) = reserved {
                    // Enough space, write and track handled events
                    entry.write(tcp4_packet_trace {
                        time: bpf_ktime_get_ns(),
                        saddr,
                        daddr,
                        sport,
                        dport,
                        seq,
                        ack,
                        window,
                        //flags
                        flags: tcp_hdr._bitfield_1.get(8, 8) as u8,
                    });
                    entry.submit(1);
                    let _ = try_handled_counter();
                } else {
                    // Not enough space, drop event
                    let _ = try_dropped_counter();
                }
            }

            let _ = try_flow_tracker(tuple);
        }
    } else {
        // Get IPv6 header
        let ip6_hdr = ctx.load::<ipv6hdr>(ETH_HDR_LEN).map_err(|_| TC_ACT_OK)?;

        // Get TCP header
        let tcp_hdr = ctx
            .load::<tcphdr>(ETH_HDR_LEN + IP6_HDR_LEN)
            .map_err(|_| TC_ACT_OK)?;

        unsafe {
            let sport = u16::from_be(tcp_hdr.source);
            let dport = u16::from_be(tcp_hdr.dest);
            let tuple = IpTuple {
                src_ip: ip6_hdr.saddr.in6_u.u6_addr8,
                dst_ip: ip6_hdr.daddr.in6_u.u6_addr8,
                sport,
                dport,
                protocol: 6,
            };
            if !filter_ports_match(sport, dport)
                || (filter_needs_tuple() && !filter_tuple_match(&tuple))
            {
                return Ok(TC_ACT_OK);
            }
            let seq = u32::from_be(tcp_hdr.seq);
            let ack = u32::from_be(tcp_hdr.ack_seq);
            let window = u16::from_be(tcp_hdr.window);
            let checksum = u16::from_be(tcp_hdr.check);

            unsafe {
                // Prepare ringbuf entry
                let reserved = TCP6_PACKETS_INGRESS.reserve::<tcp6_packet_trace>(0);

                // Track egress packet count
                let _ = try_ingress_counter();

                // Check if space left for entry
                if let Some(mut entry) = reserved {
                    // Enough space, write and track handled events
                    entry.write(tcp6_packet_trace {
                        time: bpf_ktime_get_ns(),
                        //saddr_v6: [0u8; 16],
                        //daddr_v6: [0u8; 16],
                        saddr_v6: ip6_hdr.saddr.in6_u.u6_addr8,
                        daddr_v6: ip6_hdr.daddr.in6_u.u6_addr8,
                        sport,
                        dport,
                        seq,
                        ack,
                        window,
                        //flags
                        flags: tcp_hdr._bitfield_1.get(8, 8) as u8,
                    });
                    entry.submit(1);
                    let _ = try_handled_counter();
                } else {
                    // Not enough space, drop event
                    let _ = try_dropped_counter();
                }
            }

            // Write to flow tracker

            let _ = try_flow_tracker(tuple);
        }
    }

    // Always let traffic pass to interface
    Ok(TC_ACT_OK)
}
