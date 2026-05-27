use core::ptr::addr_of;

use aya_ebpf::{
    bindings::sa_family_t,
    helpers::{bpf_probe_read_kernel, generated::bpf_ktime_get_ns},
    macros::map,
    maps::RingBuf,
    programs::FEntryContext,
};
use tcbee_common::bindings::{
    cubic::{cubic, cubic_trace_entry},
    flow::IpTuple,
    tcp_sock::{inet_connection_sock, sock},
};

use crate::{
    config::{AF_INET6, CUBIC_BUF_SIZE},
    counters::{try_count_cubic_event, try_dropped_counter, try_handled_counter},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
    helpers::tuple_from_sk,
};

#[map(name = "CUBIC_EVENTS")]
static mut CUBIC_EVENTS: RingBuf = RingBuf::with_byte_size(CUBIC_BUF_SIZE as u32, 0);

// TODO: move to helpers
#[inline(always)]
fn read_kernel<T>(src: *const T) -> Result<T, u32> {
    unsafe { bpf_probe_read_kernel(src).map_err(|_| 1u32) }
}

// TODO: it should be possible to generate this entire function from a macro.....
#[inline(always)]
pub fn cubic_handle(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };

    let inet_csk_ptr: *const inet_connection_sock = sk_ptr as *const inet_connection_sock;
    let cubic_ptr = unsafe {
        let ca_priv_ptr = addr_of!((*inet_csk_ptr).icsk_ca_priv);
        ca_priv_ptr as *const cubic
    };

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };

    let dport = ((ports & 0xFFFF) as u16).swap_bytes();
    let sport = (ports >> 16) as u16;

    let family = unsafe { (*sk_ptr).__sk_common.skc_family };
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
        // Copies fields with same name from cubic_ptr
        let cubic_entry = cubic_trace_entry::read_from(sk_ptr, cubic_ptr)?;

        // Prepare ringbuf entry
        let reserved = CUBIC_EVENTS.reserve::<cubic_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(cubic_entry);
            entry.submit(1);
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }

        let _ = try_count_cubic_event();
    }

    // TODO: Disable with static variable for performance reasons? Not always needed but nice to have
    let tuple = unsafe { tuple_from_sk(sk_ptr, sport, dport) };
    let _ = try_flow_tracker(tuple);

    Ok(0)
}
