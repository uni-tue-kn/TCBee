use core::mem;

use tcbee_common::bindings::{
    eth_header::ethhdr,
    ip4_header::iphdr,
    ip6_header::ipv6hdr,
    tcp_header::{tcp_packet_trace, tcphdr},
    tcp_probe::tcp_probe_entry,
};

// Ringbuffer Sizes
pub const TCPPROBE_BUF_SIZE: u32 = (size_of::<tcp_probe_entry>() * 100000) as u32;
pub const XDP_BUF_SIZE: u32 = (size_of::<tcp_packet_trace>() * 100000) as u32;
pub const TC_BUF_SIZE: u32 = (size_of::<tcp_packet_trace>() * 100000) as u32;
pub const TCP_BAD_CSUM_BUF_SIZE: u32 = (size_of::<tcp_packet_trace>() * 100000) as u32;
pub const TCP_RETRANSMIT_SYNACK_BUF_SIZE: u32 = (size_of::<tcp_packet_trace>() * 100000) as u32;

// Type fields
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const TCP_PROTOCOL: u8 = 0x06;

// Header lengths
// TODO: import from aya_ebpf?
pub const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
pub const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
pub const IP6_HDR_LEN: usize = mem::size_of::<ipv6hdr>();
pub const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
