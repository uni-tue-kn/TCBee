use aya_ebpf::{macros::map, maps::RingBuf, programs::FEntryContext};
use tcbee_common::{
    bindings::tcp_sock::{cwnd_trace_entry, sk_buff, sock, sock_trace_entry, tcp_sock},
    kread::read_kernel,
};

use crate::{
    counters::{
        try_dropped_counter, try_handled_counter, try_received_tcp_bytes, try_recv_tcp_sock,
        try_send_tcp_sock, try_sent_tcp_bytes,
    },
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
    helpers::tuple_from_sk,
};

#[map(name = "TCP_SEND_CWND_EVENTS")]
static mut TCP_SEND_CWND_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<cwnd_trace_entry>() * 100000) as u32, 0);
#[map(name = "TCP_RECEIVE_CWND_EVENTS")]
static mut TCP_RECEIVE_CWND_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<cwnd_trace_entry>() * 100000) as u32, 0);

#[map(name = "TCP_SEND_SOCK_EVENTS")]
static mut TCP_SEND_SOCK_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<sock_trace_entry>() * 100000) as u32, 0);
#[map(name = "TCP_RECV_SOCK_EVENTS")]
static mut TCP_RECV_SOCK_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<sock_trace_entry>() * 100000) as u32, 0);

#[inline(always)]
pub fn try_sock_recvmsg_cwnd_only(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    let dport = ((ports & 0xFFFF) as u16).swap_bytes();
    let sport = (ports >> 16) as u16;
    if !filter_ports_match(sport, dport) {
        return Ok(0);
    }
    if filter_needs_tuple() {
        let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
        if !filter_tuple_match(&tuple) {
            return Ok(0);
        }
    }

    unsafe {
        let cwnd_entry = cwnd_trace_entry::read_from(sk_ptr, tcp_sck_ptr)?;

        // Prepare ringbuf entry
        let reserved = TCP_RECEIVE_CWND_EVENTS.reserve::<cwnd_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            entry.write(cwnd_entry);
            entry.submit(1);
            let _ = try_send_tcp_sock();
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }

        // TODO: Disable with static variable for performance reasons? Not always needed but nice to have
        let tuple = tuple_from_sk(sk_ptr, sport, dport);
        let _ = try_flow_tracker(tuple);

        Ok(0)
    }
}

#[inline(always)]
pub fn try_sock_sendmsg_cwnd_only(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    let dport = ((ports & 0xFFFF) as u16).swap_bytes();
    let sport = (ports >> 16) as u16;
    if !filter_ports_match(sport, dport) {
        return Ok(0);
    }
    if filter_needs_tuple() {
        let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
        if !filter_tuple_match(&tuple) {
            return Ok(0);
        }
    }

    unsafe {
        let cwnd_entry = cwnd_trace_entry::read_from(sk_ptr, tcp_sck_ptr)?;

        // Prepare ringbuf entry
        let reserved = TCP_SEND_CWND_EVENTS.reserve::<cwnd_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(cwnd_entry);
            entry.submit(1);
            let _ = try_send_tcp_sock();
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }
    }

    // TODO: Disable with static variable for performance reasons? Not always needed but nice to have
    let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
    let _ = try_flow_tracker(tuple);

    Ok(0)
}

#[inline(always)]
pub fn try_sock_sendmsg(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };

    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    let dport = ((ports & 0xFFFF) as u16).swap_bytes();
    let sport = (ports >> 16) as u16;

    let skb: *const sk_buff = unsafe { ctx.arg(1) };
    let length = unsafe { read_kernel(&(*skb).data_len)? };
    let _ = try_sent_tcp_bytes(length);

    // Track flow IP and Port
    if !filter_ports_match(sport, dport) {
        return Ok(0);
    }
    if filter_needs_tuple() {
        let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
        if !filter_tuple_match(&tuple) {
            return Ok(0);
        }
    }

    unsafe {
        let sock_entry = sock_trace_entry::read_from(sk_ptr, tcp_sck_ptr)?;

        // Prepare ringbuf entry
        let reserved = TCP_SEND_SOCK_EVENTS.reserve::<sock_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            entry.write(sock_entry);
            entry.submit(1);
            let _ = try_send_tcp_sock();
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }
    }
    // TODO: Disable with static variable for performance reasons? Not always needed but nice to have
    let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
    let _ = try_flow_tracker(tuple);

    Ok(0)
}

#[inline(always)]
pub fn try_tcp_recv_socket(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };

    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    let dport = ((ports & 0xFFFF) as u16).swap_bytes();
    let sport = (ports >> 16) as u16;

    let skb: *const sk_buff = unsafe { ctx.arg(1) };
    let length = unsafe { read_kernel(&(*skb).data_len)? };
    let _ = try_received_tcp_bytes(length);
    if !filter_ports_match(sport, dport) {
        return Ok(0);
    }
    if filter_needs_tuple() {
        let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
        if !filter_tuple_match(&tuple) {
            return Ok(0);
        }
    }

    unsafe {
        let sock_entry = sock_trace_entry::read_from(sk_ptr, tcp_sck_ptr)?;

        // Prepare ringbuf entry
        let reserved = TCP_RECV_SOCK_EVENTS.reserve::<sock_trace_entry>(0);

        // Check if space left for entrysock_trace_entry {
        if let Some(mut entry) = reserved {
            entry.write(sock_entry);
            entry.submit(1);
            let _ = try_recv_tcp_sock();
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }
    }
    // TODO: Disable with static variable for performance reasons? Not always needed but nice to have
    let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
    let _ = try_flow_tracker(tuple);

    Ok(0)
}
