#![no_std]
#![no_main]

// XDP, TC, Tracepoint probes and counters
mod probes {
    pub mod tc;
    pub mod tcp_bad_csum;
    pub mod tcp_probe;
    pub mod tcp_retransmit_synack;
    pub mod xdp;
    pub mod tcp_socket;
}
// Configuration variables
mod config;
// Performance counters for UI
pub mod counters;
pub mod flow_tracker;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE},
    macros::{classifier, fentry, fexit, tracepoint, xdp},
    programs::{FEntryContext, FExitContext, TcContext, TracePointContext, XdpContext},
};

use counters::try_ingress_counter;
use probes::{
    tc::tc_hook, tcp_bad_csum::try_tcp_bad_csum, tcp_probe::try_tcp_probe, tcp_retransmit_synack::try_tcp_retransmit_synack, tcp_socket::{try_sock_sendmsg, try_tcp_recv_socket,try_sock_recvmsg_cwnd_only,try_sock_sendmsg_cwnd_only}, xdp::xdp_hook
};

#[no_mangle]
static mut FILTER_PORT: u16 = 0;

/// tcp_write_xmit from net/ipv4/tcp_output.c
#[fentry(function="__tcp_transmit_skb")]
pub fn sock_sendmsg(ctx: FEntryContext) -> u32 {
    match try_sock_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret
    }
}

/// tcp_rcv_established from net/ipv4/tcp_input.c
/// Only triggers after established state!
#[fentry(function="tcp_rcv_established")]
pub fn sock_recvmsg(ctx: FEntryContext) -> u32 {
    match try_tcp_recv_socket(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret
    }
}

// Performance variant of above functions that only capture cwnd
#[fentry(function="__tcp_transmit_skb")]
pub fn cwnd_sock_sendmsg(ctx: FEntryContext) -> u32 {
    match try_sock_sendmsg_cwnd_only(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret
    }
}
#[fentry(function="tcp_rcv_established")]
pub fn cwnd_sock_recvmsg(ctx: FEntryContext) -> u32 {
    match try_sock_recvmsg_cwnd_only(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret
    }
}


#[xdp]
pub fn xdp_packet_tracer(ctx: XdpContext) -> u32 {
    match xdp_hook(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn tc_packet_tracer(ctx: TcContext) -> i32 {
    match tc_hook(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[tracepoint]
pub fn tcp_retransmit_synack(ctx: TracePointContext) -> u32 {
    match try_tcp_retransmit_synack(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn tcp_probe(ctx: TracePointContext) -> u32 {
    match try_tcp_probe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn tcp_bad_csum(ctx: TracePointContext) -> u32 {
    match try_tcp_bad_csum(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
