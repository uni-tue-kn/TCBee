use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_probe_read_kernel, bpf_probe_read_kernel_buf, bpf_skc_to_tcp_sock, bpf_tcp_sock
    },
    macros::map,
    maps::RingBuf,
    programs::{FEntryContext, FExitContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use tcbee_common::bindings::{
    flow::IpTuple,
    tcp_sock::{sock_trace_entry, tcp_sock,sock},
};


pub unsafe fn my_bpf_skc_to_tcp_sock(sk: *const aya_ebpf::cty::c_void) -> *const tcp_sock {
    let fun: unsafe extern "C" fn(sk: *const aya_ebpf::cty::c_void) -> *const tcp_sock =
        ::core::mem::transmute(137usize);
    fun(sk)
}

use crate::{config::AF_INET6, flow_tracker::try_flow_tracker};

#[map(name = "TCP_SOCK_EVENTS")]
static mut TCP_SOCK_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<sock_trace_entry>() * 100000) as u32, 0);

#[inline(always)]
pub fn try_sock_sendmsg(ctx: FEntryContext) -> Result<u32, u32> {
    
        let sk_ptr: *const sock = unsafe { ctx.arg(0) };

        let tcp_sck_ptr = sk_ptr as *const tcp_sock;

        let ports = unsafe { bpf_probe_read_kernel(&(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair).map_err(|_| 1u32)? };

        let dport = (ports & 0xFFFF) as u16;
        let sport = (ports >> 16) as u16;

        if sport != 5201 && dport != 5201 {
            //info!(&ctx, "Dropped: {} - {}",sport,dport.to_be());
            return Ok(0)
        } else {
            info!(&ctx, "Handled: {} - {}",sport,dport.to_be());
        }

        //info!(&ctx,"Found iperf port!");

        if tcp_sck_ptr.is_null() {
            // TODO: handle null case
        } else {
            let snd_wnd = unsafe { bpf_probe_read_kernel(&(*tcp_sck_ptr).snd_wnd).map_err(|_| 1u32)? };

            //let sk = sk_ptr.read();

            info!(&ctx,"Sock {}",snd_wnd);
            
            //let addrs_v4 = sk.__sk_common.__bindgen_anon_1.skc_addrpair;
            //let ports = sk.__sk_common.__bindgen_anon_3.skc_portpair;
        
    }
    Ok(0)
}
        /*

        //let sock_ptr = bpf_skc_to_tcp_sock(ctx.arg(0) as *mut c_void);
        //let tcp_sock_ptr: *const tcp_sock = bpf_skc_to_tcp_sock(sk);

        //let tcp_sock_ptr: *const tcp_sock = ctx.arg(0);

        if sock_ptr.is_null() {
            // Handle the error case where the cast was not successful
        } else {
            // Proceed with using tcp_sock_ptr
            //let tcp_sock = bpf_probe_read_kernel(tcp_sock_ptr).unwrap();
            let tcp_sock = sock_ptr.read();

            let inet_sock = tcp_sock.inet_conn.icsk_inet;

            //let c = tcp_sock.snd_nxt;
            //let sock = sock_ptr.read();


            // Store addresses before continuing with socket
            let trace = sock_trace_entry {
                time: bpf_ktime_get_ns(),
                addr_v4: inet_sock.sk.__sk_common.__bindgen_anon_1.skc_addrpair,
                src_v6: inet_sock.sk.__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
                dst_v6: inet_sock.sk.__sk_common.skc_v6_daddr.in6_u.u6_addr8,
                ports: inet_sock.sk.__sk_common.__bindgen_anon_3.skc_portpair,
                family: inet_sock.sk.__sk_common.skc_family,
                snd_cwnd: tcp_sock.snd_nxt,
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
        */



#[inline(always)]
pub fn try_tcp_recv_socket(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };

        let tcp_sck_ptr = sk_ptr as *const tcp_sock;

        let ports = unsafe { bpf_probe_read_kernel(&(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair).map_err(|_| 1u32)? };

        let dport = (ports & 0xFFFF) as u16;
        let sport = (ports >> 16) as u16;

        if sport != 5201 && dport != 5201 {
            //info!(&ctx, "Dropped: {} - {}",sport,dport.to_be());
            return Ok(0)
        } else {
            info!(&ctx, "Handled: {} - {}",sport,dport.to_be());
        }

        //info!(&ctx,"Found iperf port!");

        if tcp_sck_ptr.is_null() {
            // TODO: handle null case
        } else {
            let snd_wnd = unsafe { bpf_probe_read_kernel(&(*tcp_sck_ptr).snd_wnd).map_err(|_| 1u32)? };

            //let sk = sk_ptr.read();

            info!(&ctx,"Sock {}",snd_wnd);
            
            //let addrs_v4 = sk.__sk_common.__bindgen_anon_1.skc_addrpair;
            //let ports = sk.__sk_common.__bindgen_anon_3.skc_portpair;
        
    }
    Ok(0)
}
