use core::ptr::addr_of;

use aya_ebpf::{helpers::{bpf_probe_read_kernel, r#gen::bpf_ktime_get_ns}, macros::map, maps::RingBuf, programs::{FEntryContext, ProbeContext}};
use aya_log_ebpf::info;
use tcbee_common::bindings::{bbr::{bbr, bbr_trace_entry}, flow::IpTuple, tcp_sock::{inet_connection_sock, sock}};

use crate::{FILTER_PORT, config::{AF_INET6, BBR_BUF_SIZE}, counters::{try_count_bbr_event, try_dropped_counter, try_handled_counter}, flow_tracker::try_flow_tracker, helpers::kernel_read_tuple_from_sk};

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
        bpf_probe_read_kernel(addr_of!((*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair))
            .map_err(|_| 0u32)?
    };   

    let dport = ((ports & 0xFFFF) as u16).to_be();
    let sport = ((ports >> 16) as u16).to_be();

    unsafe {
        // dport needs to be called to_be otherwise value is wrong
        if FILTER_PORT != 0 && sport != FILTER_PORT && dport != FILTER_PORT {
            //info!(&ctx, "Dropped: {} - {}",sport,dport.to_be());
            return Ok(0);
        }

        // Copies fields with same name from bbr_ptr
        let bbr_entry = bbr_trace_entry::read_from(sk_ptr, bbr_ptr)?;
        //let bbr_entry = bbr_trace_entry::default();
        let reserved = BBR_EVENTS.reserve::<bbr_trace_entry>(0);


        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(bbr_entry);
            entry.submit(0);
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
