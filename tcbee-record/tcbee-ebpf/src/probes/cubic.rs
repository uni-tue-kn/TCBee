use core::ptr::addr_of;

use aya_ebpf::{macros::map, maps::RingBuf, programs::FEntryContext};
use tcbee_common::{
    bindings::{
        cubic::{cubic, cubic_trace_entry},
        tcp_sock::{inet_connection_sock, sock},
    },
    stats::RB_CUBIC,
};

use crate::{
    config::CUBIC_BUF_SIZE,
    counters::{count_attempt, count_error, submit},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
    helpers::tuple_from_sk,
};

#[map(name = "CUBIC_EVENTS")]
static CUBIC_EVENTS: RingBuf = RingBuf::with_byte_size(CUBIC_BUF_SIZE, 0);

// TODO: it should be possible to generate this entire function from a macro.....
#[inline(always)]
pub fn cubic_handle(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };

    let inet_csk_ptr: *const inet_connection_sock = sk_ptr as *const inet_connection_sock;
    let cubic_ptr = unsafe {
        let ca_priv_ptr = addr_of!((*inet_csk_ptr).icsk_ca_priv);
        ca_priv_ptr as *const cubic
    };

    let ports = unsafe { (*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
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

    count_attempt(RB_CUBIC);

    // Copies fields with same name from cubic_ptr
    match unsafe { cubic_trace_entry::read_from(sk_ptr, cubic_ptr) } {
        Ok(entry) => submit(&CUBIC_EVENTS, RB_CUBIC, entry),
        Err(_) => count_error(RB_CUBIC),
    }

    let _ = try_flow_tracker(unsafe { tuple_from_sk(sk_ptr, sport, dport) });

    Ok(0)
}
