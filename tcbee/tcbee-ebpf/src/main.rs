#![no_std]
#![no_main]

// XDP, TC, Tracepoint probes and counters
mod probes {
    pub mod tc;
    pub mod tcp_bad_csum;
    pub mod tcp_probe;
    pub mod tcp_retransmit_synack;
    pub mod xdp;
}
// Configuration variables
mod config;
// Performance counters for UI
pub mod counters;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE},
    macros::{classifier, tracepoint, xdp},
    programs::{TcContext, TracePointContext, XdpContext},
};

use probes::{
    tc::tc_hook, tcp_bad_csum::try_tcp_bad_csum, tcp_probe::try_tcp_probe,
    tcp_retransmit_synack::try_tcp_retransmit_synack, xdp::xdp_hook,
};

#[xdp]
pub fn xdp_packet_tracer(ctx: XdpContext) -> u32 {
    match xdp_hook(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
#[classifier]
pub fn tc_packet_tracer(ctx: TcContext) -> i32 {
    match { tc_hook(ctx) } {
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
