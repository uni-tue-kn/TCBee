#![no_std]
#![no_main]

pub(crate) mod probe;

use probe::{try_sock_recvmsg, try_sock_sendmsg};

use aya_ebpf::{macros::fentry, programs::FEntryContext};

#[fentry(function = "__tcp_transmit_skb")]
pub fn cwnd_sock_sendmsg(ctx: FEntryContext) -> u32 {
    match try_sock_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[fentry(function = "tcp_rcv_established")]
pub fn cwnd_sock_recvmsg(ctx: FEntryContext) -> u32 {
    match try_sock_recvmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
