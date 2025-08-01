use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_probe_read_kernel, bpf_probe_read_kernel_buf, bpf_skc_to_tcp_sock, bpf_tcp_sock,
        gen::bpf_ktime_get_ns,
    },
    macros::map,
    maps::RingBuf,
    programs::{FEntryContext, FExitContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use tcbee_common::bindings::{
    flow::IpTuple,
    tcp_sock::{sock, sock_trace_entry, tcp_sock,cwnd_trace_entry},
};

use crate::{
    config::AF_INET6,
    counters::{try_dropped_counter, try_handled_counter, try_recv_tcp_sock, try_send_tcp_sock},
    flow_tracker::try_flow_tracker, FILTER_PORT,
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
fn read_kernel<T>(src: *const T) -> Result<T, u32> {
    unsafe { bpf_probe_read_kernel(src).map_err(|_| 1u32) }
}


#[inline(always)]
pub fn try_sock_recvmsg_cwnd_only(ctx: FEntryContext) -> Result<u32, u32> {

    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    // The order of ports in the socket is fixed for both sending and receiving
    // So take the opposite order from sendmsg here
    let sport = (ports & 0xFFFF) as u16;
    let dport = (ports >> 16) as u16;

    // Swap source and destination for trace entry
    let addr_v4 = unsafe { (*sk_ptr).__sk_common.__bindgen_anon_1.skc_addrpair.rotate_right(32) };
    let ports = ports.rotate_right(16);

    unsafe {
        // dport needs to be called to_be otherwise value is wrong
        if FILTER_PORT != 0 && sport != FILTER_PORT && dport.to_be() != FILTER_PORT {
            //info!(&ctx, "Dropped: {} - {}",sport,dport.to_be());
            return Ok(0);
        }

        let cwnd_entry = cwnd_trace_entry {
            time: bpf_ktime_get_ns(),
            addr_v4,
            src_v6: (*sk_ptr).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
            dst_v6: (*sk_ptr).__sk_common.skc_v6_daddr.in6_u.u6_addr8,
            ports,
            family: (*sk_ptr).__sk_common.skc_family,
            snd_cwnd: read_kernel(&(*tcp_sck_ptr).snd_cwnd)?,
        };
        
        // Prepare ringbuf entry
        let reserved = TCP_RECEIVE_CWND_EVENTS.reserve::<cwnd_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(cwnd_entry);
            entry.submit(0);
            let _ = try_send_tcp_sock();
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }

        Ok(0)
    }
}


#[inline(always)]
pub fn try_sock_sendmsg_cwnd_only(ctx: FEntryContext) -> Result<u32, u32> {

    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    let dport = (ports & 0xFFFF) as u16;
    let sport = (ports >> 16) as u16;

    unsafe {
        // dport needs to be called to_be otherwise value is wrong
        if FILTER_PORT != 0 && sport != FILTER_PORT && dport.to_be() != FILTER_PORT {
            //info!(&ctx, "Dropped: {} - {}",sport,dport.to_be());
            return Ok(0);
        }

        let cwnd_entry = cwnd_trace_entry {
            time: bpf_ktime_get_ns(),
            addr_v4: (*sk_ptr).__sk_common.__bindgen_anon_1.skc_addrpair,
            src_v6: (*sk_ptr).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
            dst_v6: (*sk_ptr).__sk_common.skc_v6_daddr.in6_u.u6_addr8,
            ports: *ports,
            family: (*sk_ptr).__sk_common.skc_family,
            snd_cwnd: read_kernel(&(*tcp_sck_ptr).snd_cwnd)?,
        };
        
        // Prepare ringbuf entry
        let reserved = TCP_SEND_CWND_EVENTS.reserve::<cwnd_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(cwnd_entry);
            entry.submit(0);
            let _ = try_send_tcp_sock();
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }

        Ok(0)
    }
}

#[inline(always)]
pub fn try_sock_sendmsg(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };

    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    let dport = (ports & 0xFFFF) as u16;
    let sport = (ports >> 16) as u16;

    unsafe {
        // dport needs to be called to_be otherwise value is wrong
        if FILTER_PORT != 0 && sport != FILTER_PORT && dport.to_be() != FILTER_PORT {
            //info!(&ctx, "Dropped: {} - {}",sport,dport.to_be());
            return Ok(0);
        }

        let sock_entry = sock_trace_entry {
            time: bpf_ktime_get_ns(),
            addr_v4: read_kernel(&(*sk_ptr).__sk_common.__bindgen_anon_1.skc_addrpair)?,
            src_v6: read_kernel(&(*sk_ptr).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8)?,
            dst_v6: read_kernel(&(*sk_ptr).__sk_common.skc_v6_daddr.in6_u.u6_addr8)?,
            ports: read_kernel(&(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair)?,
            family: read_kernel(&(*sk_ptr).__sk_common.skc_family)?,
            // SOCK Stats
            pacing_rate: read_kernel(&(*sk_ptr).sk_pacing_rate)?,
            max_pacing_rate: read_kernel(&(*sk_ptr).sk_max_pacing_rate)?,
            // INET_CONN Stats
            backoff: read_kernel(&(*tcp_sck_ptr).inet_conn.icsk_backoff)?,
            rto: read_kernel(&(*tcp_sck_ptr).inet_conn.icsk_rto)?,
            // INET_CONN -> icsk_ack
            ato: 0, //read_kernel(&(*tcp_sck_ptr).inet_conn.icsk_ack.ato())?,
            rcv_mss: read_kernel(&(*tcp_sck_ptr).inet_conn.icsk_ack.rcv_mss)?,
            // TCP_SOCK Stats
            snd_cwnd: read_kernel(&(*tcp_sck_ptr).snd_cwnd)?,
            bytes_acked: read_kernel(&(*tcp_sck_ptr).bytes_acked)?,
            snd_ssthresh: read_kernel(&(*tcp_sck_ptr).snd_ssthresh)?,
            total_retrans: read_kernel(&(*tcp_sck_ptr).total_retrans)?,
            probes: read_kernel(&(*tcp_sck_ptr).keepalive_probes)?,
            lost: read_kernel(&(*tcp_sck_ptr).lost)?,
            sacked_out: read_kernel(&(*tcp_sck_ptr).sacked_out)?,
            retrans: read_kernel(&(*tcp_sck_ptr).retrans_out)?,
            rcv_ssthresh: read_kernel(&(*tcp_sck_ptr).rcv_ssthresh)?,
            rttvar: read_kernel(&(*tcp_sck_ptr).rttvar_us)?,
            advmss: read_kernel(&(*tcp_sck_ptr).advmss)?,
            reordering: read_kernel(&(*tcp_sck_ptr).reordering)?,
            rcv_rtt: read_kernel(&(*tcp_sck_ptr).rcv_rtt_est.rtt_us)?,
            rcv_space: read_kernel(&(*tcp_sck_ptr).rcvq_space.space)?,
            bytes_received: read_kernel(&(*tcp_sck_ptr).bytes_received)?,
            segs_out: read_kernel(&(*tcp_sck_ptr).segs_out)?,
            segs_in: read_kernel(&(*tcp_sck_ptr).segs_in)?,
            // TCP_SOCK -> tcp_options_received
            snd_wscale: 0, //read_kernel(&(*tcp_sck_ptr).rx_opt.snd_wscale())?,
            rcv_wscale: 0, //read_kernel(&(*tcp_sck_ptr).rx_opt.rcv_wscale())?,
        };

        // Prepare ringbuf entry
        let reserved = TCP_SEND_SOCK_EVENTS.reserve::<sock_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(sock_entry);
            entry.submit(0);
            let _ = try_send_tcp_sock();
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }
    }
    Ok(0)
}

#[inline(always)]
pub fn try_tcp_recv_socket(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };

    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };
    let sport = (ports & 0xFFFF) as u16;
    let dport = (ports >> 16) as u16;

    unsafe {
        // dport needs to be called to_be otherwise value is wrong
        if FILTER_PORT != 0 && sport != FILTER_PORT && dport.to_be() != FILTER_PORT {
            return Ok(0);
        }

        // Shift address to right, swaps source and destination
        let addr_v4 = read_kernel(&(*sk_ptr).__sk_common.__bindgen_anon_1.skc_addrpair)?.rotate_right(32);
        let ports = ports.rotate_right(16);
        
        let sock_entry = sock_trace_entry {
            time: bpf_ktime_get_ns(),
            addr_v4,
            src_v6: read_kernel(&(*sk_ptr).__sk_common.skc_v6_daddr.in6_u.u6_addr8)?,
            dst_v6: read_kernel(&(*sk_ptr).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8)?,
            ports,
            family: read_kernel(&(*sk_ptr).__sk_common.skc_family)?,
            // SOCK Stats
            pacing_rate: read_kernel(&(*sk_ptr).sk_pacing_rate)?,
            max_pacing_rate: read_kernel(&(*sk_ptr).sk_max_pacing_rate)?,
            // INET_CONN Stats
            backoff: read_kernel(&(*tcp_sck_ptr).inet_conn.icsk_backoff)?,
            rto: read_kernel(&(*tcp_sck_ptr).inet_conn.icsk_rto)?,
            // INET_CONN -> icsk_ack
            ato: 0, //read_kernel(&(*tcp_sck_ptr).inet_conn.icsk_ack.ato())?,
            rcv_mss: read_kernel(&(*tcp_sck_ptr).inet_conn.icsk_ack.rcv_mss)?,
            // TCP_SOCK Stats
            snd_cwnd: read_kernel(&(*tcp_sck_ptr).snd_cwnd)?,
            bytes_acked: read_kernel(&(*tcp_sck_ptr).bytes_acked)?,
            snd_ssthresh: read_kernel(&(*tcp_sck_ptr).snd_ssthresh)?,
            total_retrans: read_kernel(&(*tcp_sck_ptr).total_retrans)?,
            probes: read_kernel(&(*tcp_sck_ptr).keepalive_probes)?,
            lost: read_kernel(&(*tcp_sck_ptr).lost)?,
            sacked_out: read_kernel(&(*tcp_sck_ptr).sacked_out)?,
            retrans: read_kernel(&(*tcp_sck_ptr).retrans_out)?,
            rcv_ssthresh: read_kernel(&(*tcp_sck_ptr).rcv_ssthresh)?,
            rttvar: read_kernel(&(*tcp_sck_ptr).rttvar_us)?,
            advmss: read_kernel(&(*tcp_sck_ptr).advmss)?,
            reordering: read_kernel(&(*tcp_sck_ptr).reordering)?,
            rcv_rtt: read_kernel(&(*tcp_sck_ptr).rcv_rtt_est.rtt_us)?,
            rcv_space: read_kernel(&(*tcp_sck_ptr).rcvq_space.space)?,
            bytes_received: read_kernel(&(*tcp_sck_ptr).bytes_received)?,
            segs_out: read_kernel(&(*tcp_sck_ptr).segs_out)?,
            segs_in: read_kernel(&(*tcp_sck_ptr).segs_in)?,
            // TCP_SOCK -> tcp_options_received
            snd_wscale: 0, //read_kernel(&(*tcp_sck_ptr).rx_opt.snd_wscale())?,
            rcv_wscale: 0, //read_kernel(&(*tcp_sck_ptr).rx_opt.rcv_wscale())?,
        };

        // Prepare ringbuf entry
        let reserved = TCP_RECV_SOCK_EVENTS.reserve::<sock_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(sock_entry);
            entry.submit(0);
            let _ = try_recv_tcp_sock();
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }
    }
    Ok(0)
}
