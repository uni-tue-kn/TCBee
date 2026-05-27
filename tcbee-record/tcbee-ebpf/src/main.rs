#![no_std]
#![no_main]

// TC, Tracepoint probes and counters
mod probes {
    pub mod bbr;
    pub mod cubic;
    pub mod tc;
    pub mod tcp_bad_csum;
    pub mod tcp_probe;
    pub mod tcp_retransmit_synack;
    pub mod tcp_socket;
}

// Configuration variables
mod config;
mod filter;

// Performance counters for UI
pub mod counters;
pub mod flow_tracker;

// Helper functions
pub mod helpers;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, fentry, kprobe, tracepoint},
    programs::{FEntryContext, ProbeContext, TcContext, TracePointContext},
};

use probes::{
    tc::{tc_egress_hook, tc_ingress_hook},
    tcp_bad_csum::try_tcp_bad_csum,
    tcp_probe::try_tcp_probe,
    tcp_retransmit_synack::try_tcp_retransmit_synack,
    tcp_socket::{
        try_sock_recvmsg_cwnd_only, try_sock_sendmsg, try_sock_sendmsg_cwnd_only,
        try_tcp_recv_socket,
    },
};

use crate::probes::{bbr::bbr_handle, cubic::cubic_handle};

#[no_mangle]
static mut FILTER_PORT: u16 = 0;
#[no_mangle]
static mut FILTER_MODE: u32 = tcbee_common::filter::FILTER_MODE_NONE;
#[no_mangle]
static mut FILTER_RULE_FLAGS: u32 = 0;

/// net/ipv4/tcp_bbr.c
// Called on update
#[kprobe]
pub fn bbr_cong_control(ctx: ProbeContext) -> u32 {
    match bbr_handle(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
// Called on congestion
#[kprobe]
pub fn bbr_cwnd_event(ctx: ProbeContext) -> u32 {
    match bbr_handle(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// net/ipv4/tcp_cubic.c
// Called on update
#[fentry(function = "cubictcp_cong_avoid")]
pub fn cubic_cong_control(ctx: FEntryContext) -> u32 {
    match cubic_handle(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
// Called on congestion ? TODO: I think this is the wrong hook
#[fentry(function = "cubictcp_cwnd_event")]
pub fn cubic_cwnd_event(ctx: FEntryContext) -> u32 {
    match cubic_handle(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// tcp_write_xmit from net/ipv4/tcp_output.c
#[fentry(function = "__tcp_transmit_skb")]
pub fn sock_sendmsg(ctx: FEntryContext) -> u32 {
    match try_sock_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// tcp_rcv_established from net/ipv4/tcp_input.c
/// Only triggers after established state!
#[fentry(function = "tcp_rcv_established")]
pub fn sock_recvmsg(ctx: FEntryContext) -> u32 {
    match try_tcp_recv_socket(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// Performance variant of above functions that only capture cwnd
#[fentry(function = "__tcp_transmit_skb")]
pub fn cwnd_sock_sendmsg(ctx: FEntryContext) -> u32 {
    match try_sock_sendmsg_cwnd_only(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
#[fentry(function = "tcp_rcv_established")]
pub fn cwnd_sock_recvmsg(ctx: FEntryContext) -> u32 {
    match try_sock_recvmsg_cwnd_only(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn tc_ingress_packet_tracer(ctx: TcContext) -> i32 {
    match tc_ingress_hook(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[classifier]
pub fn tc_egress_packet_tracer(ctx: TcContext) -> i32 {
    match tc_egress_hook(ctx) {
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
