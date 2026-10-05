use aya_ebpf::{
    helpers::generated::bpf_ktime_get_ns, macros::map, maps::RingBuf, programs::TracePointContext,
};

// Central buffer size config
use crate::{
    config::{AF_INET6, TCPPROBE_BUF_SIZE},
    counters::{count_attempt, count_error, submit},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
};

// Kernel tracepoint data structs
use tcbee_common::{
    bindings::{
        flow::IpTuple,
        tcp_probe::{tcp_probe_entry, trace_event_raw_tcp_probe},
    },
    stats::RB_TCP_PROBE,
};

// Ring buffer for trasnmitting data to user space
#[map(name = "TCP_PROBE_QUEUE")]
static TCP_PROBE_QUEUE: RingBuf = RingBuf::with_byte_size(TCPPROBE_BUF_SIZE, 0);

#[inline(always)]
pub fn try_tcp_probe(ctx: TracePointContext) -> Result<u32, u32> {
    // Parse event data to struct
    let Ok(event) = (unsafe { ctx.read_at::<trace_event_raw_tcp_probe>(0) }) else {
        // The filter cannot be evaluated without the event, count it as an error
        count_attempt(RB_TCP_PROBE);
        count_error(RB_TCP_PROBE);
        return Ok(0);
    };

    if !filter_ports_match(event.sport, event.dport) {
        return Ok(0);
    }

    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    if event.family == AF_INET6 {
        src_ip.copy_from_slice(&event.saddr[8..24]);
        dst_ip.copy_from_slice(&event.daddr[8..24]);
    } else {
        src_ip[..4].copy_from_slice(&event.saddr[4..8]);
        dst_ip[..4].copy_from_slice(&event.daddr[4..8]);
    }
    let tuple = IpTuple {
        src_ip,
        dst_ip,
        sport: event.sport,
        dport: event.dport,
        protocol: 6,
    };
    if filter_needs_tuple() && !filter_tuple_match(&tuple) {
        return Ok(0);
    }

    count_attempt(RB_TCP_PROBE);
    submit(
        &TCP_PROBE_QUEUE,
        RB_TCP_PROBE,
        tcp_probe_entry {
            time: unsafe { bpf_ktime_get_ns() },
            saddr: event.saddr,
            daddr: event.daddr,
            sport: event.sport,
            dport: event.dport,
            family: event.family,
            mark: event.mark,
            data_len: event.data_len,
            snd_nxt: event.snd_nxt,
            snd_una: event.snd_una,
            snd_cwnd: event.snd_cwnd,
            ssthresh: event.ssthresh,
            snd_wnd: event.snd_wnd,
            srtt: event.srtt,
            rcv_wnd: event.rcv_wnd,
            sock_cookie: event.sock_cookie,
        },
    );

    let _ = try_flow_tracker(tuple);

    Ok(0)
}
