use core::ptr::addr_of;

use aya_ebpf::{
    helpers::{bpf_probe_read_kernel, generated::bpf_ktime_get_ns},
    macros::map,
    maps::RingBuf,
    programs::{FEntryContext, ProbeContext},
};
use tcbee_common::bindings::{
    bbr::{bbr, bbr_trace_entry},
    flow::IpTuple,
    tcp_sock::{inet_connection_sock, sock},
};

use crate::{
    config::{AF_INET6, BBR_BUF_SIZE},
    counters::{try_count_bbr_event, try_dropped_counter, try_handled_counter},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
    helpers::kernel_read_tuple_from_sk,
};

#[map(name = "BBR_EVENTS")]
static mut BBR_EVENTS: RingBuf = RingBuf::with_byte_size(BBR_BUF_SIZE as u32, 0);

#[inline(always)]
pub fn bbr_handle(ctx: ProbeContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = ctx.arg(0).ok_or(0u32)?;

    if sk_ptr.is_null() {
        return Ok(0);
    }

    // Congestion algorithm ptr is stored in inet_csk field
    let inet_csk_ptr: *const inet_connection_sock = sk_ptr as *const inet_connection_sock;
    let bbr_ptr = unsafe {
        let ca_priv_ptr = addr_of!((*inet_csk_ptr).icsk_ca_priv);
        ca_priv_ptr as *const bbr
    };

    let ports: u32 = unsafe {
        bpf_probe_read_kernel(addr_of!(
            (*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair
        ))
        .map_err(|_| 0u32)?
    };

    let dport = ((ports & 0xFFFF) as u16).swap_bytes();
    let sport = (ports >> 16) as u16;
    if !filter_ports_match(sport, dport) {
        return Ok(0);
    }
    if filter_needs_tuple() {
        let tuple = unsafe { kernel_read_tuple_from_sk(sk_ptr, sport, dport) };
        if !filter_tuple_match(&tuple) {
            return Ok(0);
        }
    }

    unsafe {
        // Copies fields with same name from bbr_ptr
        let bbr_entry = bbr_trace_entry::read_from(sk_ptr, bbr_ptr)?;
        let reserved = BBR_EVENTS.reserve::<bbr_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(bbr_entry);
            entry.submit(1);
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }

        let _ = try_count_bbr_event();
    }

    let tuple = unsafe { kernel_read_tuple_from_sk(sk_ptr, sport, dport) };
    let _ = try_flow_tracker(tuple);

    Ok(0)
}
