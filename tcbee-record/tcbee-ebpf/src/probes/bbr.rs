use core::ptr::addr_of;

use aya_ebpf::{
    helpers::bpf_probe_read_kernel, macros::map, maps::RingBuf, programs::ProbeContext,
};
use tcbee_common::{
    bindings::{
        bbr::{bbr, bbr_trace_entry},
        tcp_sock::{inet_connection_sock, sock},
    },
    stats::RB_BBR,
};

use crate::{
    config::BBR_BUF_SIZE,
    counters::{count_attempt, count_error, submit},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
    helpers::kernel_read_tuple_from_sk,
};

#[map(name = "BBR_EVENTS")]
static BBR_EVENTS: RingBuf = RingBuf::with_byte_size(BBR_BUF_SIZE, 0);

#[inline(always)]
pub fn bbr_handle(ctx: ProbeContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = match ctx.arg(0) {
        Some(ptr) if !(ptr as *const sock).is_null() => ptr,
        _ => {
            // The filter cannot be evaluated without the socket, count it as an error
            count_attempt(RB_BBR);
            count_error(RB_BBR);
            return Ok(0);
        }
    };

    // Congestion algorithm ptr is stored in inet_csk field
    let inet_csk_ptr: *const inet_connection_sock = sk_ptr as *const inet_connection_sock;
    let bbr_ptr = unsafe {
        let ca_priv_ptr = addr_of!((*inet_csk_ptr).icsk_ca_priv);
        ca_priv_ptr as *const bbr
    };

    let Ok(ports) = (unsafe {
        bpf_probe_read_kernel(addr_of!(
            (*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair
        ))
    }) else {
        count_attempt(RB_BBR);
        count_error(RB_BBR);
        return Ok(0);
    };

    let dport = ((ports & 0xFFFF) as u16).swap_bytes();
    let sport = (ports >> 16) as u16;
    if !filter_ports_match(sport, dport) {
        return Ok(0);
    }
    let tuple = unsafe { kernel_read_tuple_from_sk(sk_ptr, sport, dport) };
    if filter_needs_tuple() && !filter_tuple_match(&tuple) {
        return Ok(0);
    }

    count_attempt(RB_BBR);

    // Copies fields with same name from bbr_ptr
    match unsafe { bbr_trace_entry::read_from(sk_ptr, bbr_ptr) } {
        Ok(entry) => submit(&BBR_EVENTS, RB_BBR, entry),
        Err(_) => count_error(RB_BBR),
    }

    let _ = try_flow_tracker(tuple);

    Ok(0)
}
