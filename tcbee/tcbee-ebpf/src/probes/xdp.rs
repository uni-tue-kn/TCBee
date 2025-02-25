use aya_ebpf::{
    bindings::xdp_action::XDP_PASS, helpers::gen::bpf_ktime_get_ns, macros::map, maps::RingBuf,
    programs::XdpContext,
};
use aya_log_ebpf::{info, warn};
use tcbee_common::bindings::{
    eth_header::ethhdr,
    flow::IpTuple,
    ip4_header::iphdr,
    ip6_header::ipv6hdr,
    tcp_header::{tcp_packet_trace, tcphdr},
};

use crate::{
    config::{
        ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETH_HDR_LEN, IP6_HDR_LEN, IP_HDR_LEN, TCP_HDR_LEN,
        TCP_PROTOCOL, XDP_BUF_SIZE,
    },
    counters::{try_dropped_counter, try_handled_counter, try_ingress_counter},
    flow_tracker::try_flow_tracker,
};

#[map(name = "TCP_PACKETS_INGRESS")]
static mut TCP_PACKETS_INGRESS: RingBuf = RingBuf::with_byte_size(XDP_BUF_SIZE as u32, 0);

#[inline(always)]
pub fn xdp_hook(ctx: XdpContext) -> Result<u32, u32> {
    // Get data boundaries
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    //let data_len = data_end - data_start;

    // Struct to write result to
    let packet_trace: tcp_packet_trace;

    // Check if data long enough to read eth header
    if data_start + ETH_HDR_LEN > data_end {
        return Ok(XDP_PASS);
    }

    // Get eth header
    let eth_hdr_ptr = data_start as *const ethhdr;
    let ethertype: u16;

    // TODO: can this be made smaller? Need IPv4 and IPv6 handling though
    unsafe {
        // Read value by dereferencing pointer
        // Original bytes are in big endian
        ethertype = u16::from_be((*eth_hdr_ptr).h_proto);

        // Not IPv4 or IPv6, do not process packet
        if ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6 {
            return Ok(XDP_PASS);
        }
    }

    // Handle both IP versions separately
    if ethertype == ETHERTYPE_IPV4 {
        // Check if data long enough to read ip header header
        if data_start + ETH_HDR_LEN + IP_HDR_LEN > data_end {
            return Ok(XDP_PASS);
        }

        // Get pointer to start of IPv4 header
        let ip4_hdr_ptr = (data_start + ETH_HDR_LEN) as *const iphdr;
        let ip4_hdr: iphdr;

        unsafe {
            ip4_hdr = *ip4_hdr_ptr;
        }

        // Check if next protocol is TCP
        if ip4_hdr.protocol != TCP_PROTOCOL {
            return Ok(XDP_PASS);
        }

        // Check if data long enough to read tcp header
        if data_start + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN > data_end {
            return Ok(XDP_PASS);
        }

        // Get pointer to start of TCP header
        let tcp_hdr_ptr = (data_start + ETH_HDR_LEN + IP_HDR_LEN) as *const tcphdr;
        let tcp_hdr: tcphdr;

        unsafe {
            tcp_hdr = tcp_hdr_ptr.read();

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

            // Write to flow tracker
            
            let mut src = [0; 16];
            let mut dst = [0; 16];
            src[12..16].copy_from_slice(&ip4_hdr.saddr.to_le_bytes());
            dst[12..16].copy_from_slice(&ip4_hdr.daddr.to_le_bytes());

            let _ = try_flow_tracker(IpTuple {
                src_ip: src,
                dst_ip: dst,
                sport: tcp_hdr.source,
                dport: tcp_hdr.dest,
                protocol: 6,
            });
            
        }

        // Check if next protocol is tcp
    } else if ethertype == ETHERTYPE_IPV6 {
        // Check if data long enough to read ip header header
        if data_start + ETH_HDR_LEN + IP6_HDR_LEN > data_end {
            return Ok(XDP_PASS);
        }

        // Get pointer to start of IPv6 header
        let ip6_hdr_ptr = (data_start + ETH_HDR_LEN) as *const ipv6hdr;
        let ip6_hdr: ipv6hdr;

        unsafe {
            ip6_hdr = ip6_hdr_ptr.read();
        }

        // Check if next protocol is TCP
        if ip6_hdr.nexthdr != TCP_PROTOCOL {
            return Ok(XDP_PASS);
        }

        // Check if data long enough to read tcp header
        if data_start + ETH_HDR_LEN + IP6_HDR_LEN + TCP_HDR_LEN > data_end {
            return Ok(XDP_PASS);
        }

        // Get pointer to start of TCP header
        let tcp_hdr_ptr = (data_start + ETH_HDR_LEN + IP6_HDR_LEN) as *const tcphdr;
        let tcp_hdr: tcphdr;

        unsafe {
            tcp_hdr = tcp_hdr_ptr.read();

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

            // Write to flow tracker
            let _ = try_flow_tracker(IpTuple {
                src_ip: ip6_hdr.saddr.in6_u.u6_addr8,
                dst_ip: ip6_hdr.daddr.in6_u.u6_addr8,
                sport: tcp_hdr.source,
                dport: tcp_hdr.dest,
                protocol: 6,
            });
        }
    } else {
        // Should never be reached!
        return Ok(XDP_PASS);
    }

    unsafe {
        // Prepare ringbuf entry
        let reserved = TCP_PACKETS_INGRESS.reserve::<tcp_packet_trace>(0);

        // Track ingress packet count
        let _ = try_ingress_counter();

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

    // Always let packet pass to kernel
    return Ok(XDP_PASS);
}
