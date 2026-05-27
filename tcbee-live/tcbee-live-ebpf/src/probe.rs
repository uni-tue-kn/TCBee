use aya_ebpf::{
    helpers::{bpf_probe_read_kernel, generated::bpf_ktime_get_ns},
    macros::map,
    maps::{HashMap, RingBuf},
    programs::FEntryContext,
};
use tcbee_live_common::tcp_sock::{cwnd_trace_entry, sock, tcp_sock, DebugMsg, FlowKey};

#[map(name = "DEBUG_EVENTS")]
static DEBUG_EVENTS: RingBuf = RingBuf::with_byte_size((64 * 256) as u32, 0);

/// Write a string literal into the debug ring buffer.
/// Read on the host with: `sudo cat /sys/kernel/debug/tracing/trace_pipe`
/// or via the DEBUG_EVENTS ring buffer in the userspace worker.
macro_rules! dbg_reach {
    ($msg:literal) => {
        unsafe {
            if let Some(mut entry) = DEBUG_EVENTS.reserve::<DebugMsg>(0) {
                const BYTES: &[u8] = $msg.as_bytes();
                const LEN: usize = if BYTES.len() < 64 { BYTES.len() } else { 64 };
                let mut dm = DebugMsg { msg: [0u8; 64], key: FlowKey::default(), has_key: 0 };
                core::ptr::copy_nonoverlapping(BYTES.as_ptr(), dm.msg.as_mut_ptr(), LEN);
                entry.write(dm);
                entry.submit(0);
            }
        }
    };
    ($msg:literal, $key:expr) => {
        unsafe {
            if let Some(mut entry) = DEBUG_EVENTS.reserve::<DebugMsg>(0) {
                const BYTES: &[u8] = $msg.as_bytes();
                const LEN: usize = if BYTES.len() < 64 { BYTES.len() } else { 64 };
                let mut dm = DebugMsg { msg: [0u8; 64], key: $key, has_key: 1 };
                core::ptr::copy_nonoverlapping(BYTES.as_ptr(), dm.msg.as_mut_ptr(), LEN);
                entry.write(dm);
                entry.submit(0);
            }
        }
    };
}

#[map(name = "KNOWN_FLOWS")]
static KNOWN_FLOWS: HashMap<FlowKey, u8> = HashMap::with_max_entries(1024, 0);

#[map(name = "FLOW_FILTER")]
static FLOW_FILTER: HashMap<FlowKey, u8> = HashMap::with_max_entries(256, 0);

#[map(name = "TCP_SEND_CWND_EVENTS")]
static TCP_SEND_CWND_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<cwnd_trace_entry>() * 100000) as u32, 0);

#[map(name = "TCP_RECEIVE_CWND_EVENTS")]
static TCP_RECEIVE_CWND_EVENTS: RingBuf =
    RingBuf::with_byte_size((size_of::<cwnd_trace_entry>() * 100000) as u32, 0);

#[inline(always)]
fn read_kernel<T: Default>(src: *const T) -> T {
    unsafe {
        bpf_probe_read_kernel(src)
            .map_err(|_| 1u32)
            .unwrap_or_default()
    }
}

// Extract a canonical FlowKey from a socket pointer (socket-local perspective:
// src = local side, dst = remote side). Consistent for both send and recv paths.
#[inline(always)]
unsafe fn make_flow_key(sk_ptr: *const sock) -> FlowKey {
    unsafe {
        let ports = (*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair;
        FlowKey {
            src_v6: (*sk_ptr).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
            dst_v6: (*sk_ptr).__sk_common.skc_v6_daddr.in6_u.u6_addr8,
            src_port: (ports >> 16) as u16,
            dst_port: ((ports & 0xFFFF) as u16).swap_bytes(),
            family: (*sk_ptr).__sk_common.skc_family,
            _pad: 0,
        }
    }
}

#[inline(always)]
pub fn try_sock_recvmsg(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let key = unsafe { make_flow_key(sk_ptr) };

    // Always register the flow for discovery (no-op if already known).
    let _ = unsafe { KNOWN_FLOWS.insert(&key, &1u8, 1 /* BPF_NOEXIST */) };

    // Only record cwnd data for flows the user has selected.
    if unsafe { FLOW_FILTER.get(&key) }.is_none() {
        //dbg_reach!("recvmsg filtered", key);
        return Ok(0);
    } else {
        //dbg_reach!("recvmsg passed", key);
    }

    // Swap addr_v4 to show from the receiver's perspective in the event.
    let addr_v4 = unsafe {
        (*sk_ptr)
            .__sk_common
            .__bindgen_anon_1
            .skc_addrpair
            .rotate_right(32)
    };

    unsafe {
        if let Some(mut entry) = TCP_RECEIVE_CWND_EVENTS.reserve::<cwnd_trace_entry>(0) {
            entry.write(cwnd_trace_entry {
                time: bpf_ktime_get_ns(),
                addr_v4,
                src_v6: key.src_v6,
                dst_v6: key.dst_v6,
                sport: key.src_port,
                dport: key.dst_port,
                family: key.family,
                snd_cwnd: read_kernel(&(*tcp_sck_ptr).snd_cwnd),
            });
            entry.submit(0);
        }
    }

    Ok(0)
}

#[inline(always)]
pub fn try_sock_sendmsg(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let tcp_sck_ptr = sk_ptr as *const tcp_sock;

    let key = unsafe { make_flow_key(sk_ptr) };

    // Always register the flow for discovery (no-op if already known).
    let _ = unsafe { KNOWN_FLOWS.insert(&key, &1u8, 1 /* BPF_NOEXIST */) };

    // Only record cwnd data for flows the user has selected.
    if unsafe { FLOW_FILTER.get(&key) }.is_none() {
        //dbg_reach!("sendmsg filtered", key);
        return Ok(0);
    } else {
        //dbg_reach!("sendmsg passed", key);
    }

    let addr_v4 = unsafe { (*sk_ptr).__sk_common.__bindgen_anon_1.skc_addrpair };

    unsafe {
        if let Some(mut entry) = TCP_SEND_CWND_EVENTS.reserve::<cwnd_trace_entry>(0) {
            entry.write(cwnd_trace_entry {
                time: bpf_ktime_get_ns(),
                addr_v4,
                src_v6: key.src_v6,
                dst_v6: key.dst_v6,
                sport: key.src_port,
                dport: key.dst_port,
                family: key.family,
                snd_cwnd: read_kernel(&(*tcp_sck_ptr).snd_cwnd),
            });
            entry.submit(0);
        }
    }

    Ok(0)
}
