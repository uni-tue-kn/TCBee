use aya_ebpf::{macros::map, maps::RingBuf, programs::FEntryContext};
use tcbee_common::{
    bindings::tcp_sock::{cwnd_trace_entry, sk_buff, sock, sock_trace_entry, tcp_sock},
    stats::{
        RB_CWND_RECV, RB_CWND_SEND, RB_SOCK_RECV, RB_SOCK_SEND, SLOT_TCP_BYTES_RECEIVED,
        SLOT_TCP_BYTES_SENT,
    },
};

use crate::{
    counters::{add_stat, count_attempt, count_error, submit},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
    helpers::tuple_from_sk,
};

#[map(name = "TCP_SEND_CWND_EVENTS")]
static TCP_SEND_CWND_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<cwnd_trace_entry>() * 100000) as u32, 0);
#[map(name = "TCP_RECEIVE_CWND_EVENTS")]
static TCP_RECEIVE_CWND_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<cwnd_trace_entry>() * 100000) as u32, 0);

#[map(name = "TCP_SEND_SOCK_EVENTS")]
static TCP_SEND_SOCK_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<sock_trace_entry>() * 100000) as u32, 0);
#[map(name = "TCP_RECV_SOCK_EVENTS")]
static TCP_RECV_SOCK_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<sock_trace_entry>() * 100000) as u32, 0);

/// Applies the filter to the socket. Returns the ports if the event should be recorded.
#[inline(always)]
fn filter_sock(sk_ptr: *const sock) -> Option<(u16, u16)> {
    let ports = unsafe { (*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    let dport = ((ports & 0xFFFF) as u16).swap_bytes();
    let sport = (ports >> 16) as u16;
    if !filter_ports_match(sport, dport) {
        return None;
    }
    if filter_needs_tuple() {
        let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
        if !filter_tuple_match(&tuple) {
            return None;
        }
    }
    Some((sport, dport))
}

#[inline(always)]
fn trace_cwnd(ctx: &FEntryContext, ringbuf: &RingBuf, rb: u32) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let Some((sport, dport)) = filter_sock(sk_ptr) else {
        return Ok(0);
    };
    count_attempt(rb);

    match unsafe { cwnd_trace_entry::read_from(sk_ptr, sk_ptr as *const tcp_sock) } {
        Ok(entry) => submit(ringbuf, rb, entry),
        Err(_) => count_error(rb),
    }

    let _ = try_flow_tracker(unsafe { tuple_from_sk(sk_ptr, sport, dport) });
    Ok(0)
}

#[inline(always)]
fn trace_sock(
    ctx: &FEntryContext,
    ringbuf: &RingBuf,
    rb: u32,
    bytes_slot: u32,
) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let Some((sport, dport)) = filter_sock(sk_ptr) else {
        return Ok(0);
    };
    count_attempt(rb);

    let skb: *const sk_buff = unsafe { ctx.arg(1) };
    add_stat(bytes_slot, unsafe { (*skb).len } as u64);

    match unsafe { sock_trace_entry::read_from(sk_ptr, sk_ptr as *const tcp_sock) } {
        Ok(entry) => submit(ringbuf, rb, entry),
        Err(_) => count_error(rb),
    }

    let _ = try_flow_tracker(unsafe { tuple_from_sk(sk_ptr, sport, dport) });
    Ok(0)
}

#[inline(always)]
pub fn try_sock_recvmsg_cwnd_only(ctx: FEntryContext) -> Result<u32, u32> {
    trace_cwnd(&ctx, &TCP_RECEIVE_CWND_EVENTS, RB_CWND_RECV)
}

#[inline(always)]
pub fn try_sock_sendmsg_cwnd_only(ctx: FEntryContext) -> Result<u32, u32> {
    trace_cwnd(&ctx, &TCP_SEND_CWND_EVENTS, RB_CWND_SEND)
}

#[inline(always)]
pub fn try_sock_sendmsg(ctx: FEntryContext) -> Result<u32, u32> {
    trace_sock(
        &ctx,
        &TCP_SEND_SOCK_EVENTS,
        RB_SOCK_SEND,
        SLOT_TCP_BYTES_SENT,
    )
}

#[inline(always)]
pub fn try_tcp_recv_socket(ctx: FEntryContext) -> Result<u32, u32> {
    trace_sock(
        &ctx,
        &TCP_RECV_SOCK_EVENTS,
        RB_SOCK_RECV,
        SLOT_TCP_BYTES_RECEIVED,
    )
}
