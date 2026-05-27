use aya_ebpf::{
    bindings::xdp_action::XDP_PASS, helpers::gen::bpf_ktime_get_ns, macros::map, maps::RingBuf,
    programs::XdpContext,
};
use tcbee_common::bindings::{
    eth_header::ethhdr,
    ip4_header::iphdr,
    ip6_header::ipv6hdr,
    tcp_header::{tcp4_packet_trace, tcphdr},
};

use crate::{
    config::{
        ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETH_HDR_LEN, IP6_HDR_LEN, IP_HDR_LEN, TCP_HDR_LEN,
        TCP_PROTOCOL, XDP_BUF_SIZE,
    },
    counters::{try_dropped_counter, try_handled_counter, try_ingress_counter},
    FILTER_PORT,
};

#[map(name = "TCP_PACKETS_INGRESS_XDP")]
static mut TCP_PACKETS_INGRESS_XDP: RingBuf = RingBuf::with_byte_size(XDP_BUF_SIZE as u32, 0);

#[inline(always)]
pub fn xdp_hook(ctx: XdpContext) -> Result<u32, u32> {
    // Get data boundaries
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    //let data_len = data_end - data_start;

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

    /*
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
        let ip_hdr_len = ((ip4_hdr.ihl() as usize) << 2).max(IP_HDR_LEN);

        // Check if next protocol is TCP
        if ip4_hdr.protocol != TCP_PROTOCOL {
            return Ok(XDP_PASS);
        }

        // Check if data long enough to read tcp header
        if data_start + ETH_HDR_LEN + ip_hdr_len + TCP_HDR_LEN > data_end {
            return Ok(XDP_PASS);
        }

        // Get pointer to start of TCP header
        let tcp_hdr_ptr = (data_start + ETH_HDR_LEN + ip_hdr_len) as *const tcphdr;
        let tcp_hdr: tcphdr;

        unsafe {
            tcp_hdr = tcp_hdr_ptr.read();

            // Filter source and dest port if FILTER_PORT is set!
            if FILTER_PORT != 0
                && tcp_hdr.source.to_be() != FILTER_PORT
                && tcp_hdr.dest.to_be() != FILTER_PORT
            {
                return Ok(XDP_PASS);
            }

            /*
            let _ = try_flow_tracker(IpTuple {
                src_ip: src,
                dst_ip: dst,
                sport: tcp_hdr.source.to_be(),
                dport: tcp_hdr.dest.to_be(),
                protocol: 6,
            });

            */

            // Prepare ringbuf entry
            let reserved = TCP_PACKETS_INGRESS_XDP.reserve::<tcp_packet_trace>(0);

            // Track ingress packet count
            let _ = try_ingress_counter();

            // Check if space left for entry
            if let Some(mut entry) = reserved {
                // Enough space, write and track handled events
                let saddr = u32::from_be(ip4_hdr.saddr);
                let daddr = u32::from_be(ip4_hdr.daddr);
                let sport = u16::from_be(tcp_hdr.source);
                let dport = u16::from_be(tcp_hdr.dest);
                let seq = u32::from_be(tcp_hdr.seq);
                let ack = u32::from_be(tcp_hdr.ack_seq);
                let window = u16::from_be(tcp_hdr.window);
                let checksum = u16::from_be(tcp_hdr.check);
                entry.write(tcp4_packet_trace {
                    time: bpf_ktime_get_ns(),
                    saddr,
                    daddr,
                    saddr_v6: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    daddr_v6: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    sport,
                    dport,
                    seq,
                    ack,
                    window,
                    flag_urg: tcp_hdr.urg() != 0,
                    flag_ack: tcp_hdr.ack() != 0,
                    flag_psh: tcp_hdr.psh() != 0,
                    flag_rst: tcp_hdr.rst() != 0,
                    flag_fin: tcp_hdr.fin() != 0,
                    flag_syn: tcp_hdr.syn() != 0,
                    checksum,
                });
                entry.submit(1);
                let _ = try_handled_counter();
            } else {
                // Not enough space, drop event
                let _ = try_dropped_counter();
            }
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

            // Filter source and dest port if FILTER_PORT is set!
            if FILTER_PORT != 0
                && tcp_hdr.source.to_be() != FILTER_PORT
                && tcp_hdr.dest.to_be() != FILTER_PORT
            {
                return Ok(XDP_PASS);
            }

            // Write to flow tracker
            /*
            let _ = try_flow_tracker(IpTuple {
                src_ip: ip6_hdr.saddr.in6_u.u6_addr8,
                dst_ip: ip6_hdr.daddr.in6_u.u6_addr8,
                sport: tcp_hdr.source.to_be(),
                dport: tcp_hdr.dest.to_be(),
                protocol: 6,
            });
            */

            // Prepare ringbuf entry
            let reserved = TCP_PACKETS_INGRESS_XDP.reserve::<tcp_packet_trace>(0);

            // Track ingress packet count
            let _ = try_ingress_counter();

            // Check if space left for entry
            if let Some(mut entry) = reserved {
                // Enough space, write and track handled events
                let sport = u16::from_be(tcp_hdr.source);
                let dport = u16::from_be(tcp_hdr.dest);
                let seq = u32::from_be(tcp_hdr.seq);
                let ack = u32::from_be(tcp_hdr.ack_seq);
                let window = u16::from_be(tcp_hdr.window);
                let checksum = u16::from_be(tcp_hdr.check);
                entry.write(tcp_packet_trace {
                    time: bpf_ktime_get_ns(),
                    saddr: 0,
                    daddr: 0,
                    saddr_v6: ip6_hdr.saddr.in6_u.u6_addr8,
                    daddr_v6: ip6_hdr.daddr.in6_u.u6_addr8,
                    sport,
                    dport,
                    seq,
                    ack,
                    window,
                    flag_urg: tcp_hdr.urg() != 0,
                    flag_ack: tcp_hdr.ack() != 0,
                    flag_psh: tcp_hdr.psh() != 0,
                    flag_rst: tcp_hdr.rst() != 0,
                    flag_fin: tcp_hdr.fin() != 0,
                    flag_syn: tcp_hdr.syn() != 0,
                    checksum,
                });
                entry.submit(1);
                let _ = try_handled_counter();
            } else {
                // Not enough space, drop event
                let _ = try_dropped_counter();
            }
        }
    } else {
        // Should never be reached!
        return Ok(XDP_PASS);
    }
    */

    // Always let packet pass to kernel
    Ok(XDP_PASS)
}
