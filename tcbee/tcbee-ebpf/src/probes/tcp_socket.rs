use aya_ebpf::{helpers::gen::bpf_ktime_get_ns, macros::map, maps::RingBuf, programs::FExitContext, EbpfContext};
use tcbee_common::bindings::{flow::IpTuple, sock::sock, tcp_sock::{tcp_sock,sock_trace_entry}};

use crate::{config::AF_INET6, flow_tracker::try_flow_tracker};


#[map(name = "TCP_SOCK_EVENTS")]
static mut TCP_SOCK_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<sock_trace_entry>() * 100000) as u32, 0);

#[inline(always)]
pub fn try_tcp_send_socket(ctx: FExitContext) -> Result<u32, u32> {
    
    unsafe {
        let mut sock_ptr: *const sock = ctx.arg(0);
        let sock = sock_ptr.read();
        //let sock = sock_ptr.read();

        let trace = sock_trace_entry {
            time: bpf_ktime_get_ns(),
            addr_v4: sock.__sk_common.__bindgen_anon_1.skc_addrpair,
            src_v6: sock.__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
            dst_v6: sock.__sk_common.skc_v6_daddr.in6_u.u6_addr8,
            ports: sock.__sk_common.__bindgen_anon_3.skc_portpair,
            family: sock.__sk_common.skc_family
        };

            // Prepare ringbuf entry
            let reserved = TCP_SOCK_EVENTS.reserve::<sock_trace_entry>(0);

            // Check if space left for entry
            if let Some(mut entry) = reserved {
                // Enough space, write and track handled events
                entry.write(trace);
                entry.submit(0);
            }
    }
    Ok(0)
}

#[inline(always)]
pub fn try_tcp_recv_socket(ctx: FExitContext) -> Result<u32, u32> {
    unsafe {
        let mut sock_ptr: *const sock = ctx.arg(0);
        let sock = sock_ptr.read();
        //let sock = sock_ptr.read();
        
        let trace = sock_trace_entry {
            time: bpf_ktime_get_ns(),
            addr_v4: sock.__sk_common.__bindgen_anon_1.skc_addrpair,
            src_v6: sock.__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
            dst_v6: sock.__sk_common.skc_v6_daddr.in6_u.u6_addr8,
            ports: sock.__sk_common.__bindgen_anon_3.skc_portpair,
            family: sock.__sk_common.skc_family
        };

            // Prepare ringbuf entry
            let reserved = TCP_SOCK_EVENTS.reserve::<sock_trace_entry>(0);

            // Check if space left for entry
            if let Some(mut entry) = reserved {
                // Enough space, write and track handled events
                entry.write(trace);
                entry.submit(0);
            }
    }
    Ok(0)
}
