use aya_ebpf::{
    helpers::generated::bpf_ktime_get_ns, macros::map, maps::RingBuf, programs::TracePointContext,
};

// Central buffer size config
use crate::{
    config::{AF_INET6, TCPPROBE_BUF_SIZE},
    counters::try_count_tracpoint,
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
};

// Kernel tracepoint data structs
use tcbee_common::bindings::{
    flow::IpTuple,
    tcp_probe::{tcp_probe_entry, trace_event_raw_tcp_probe},
};

// Counters for performance metrics
use crate::counters::{try_dropped_counter, try_handled_counter};

// Ring buffer for trasnmitting data to user space
#[map(name = "TCP_PROBE_QUEUE")]
static mut TCP_PROBE_QUEUE: RingBuf = RingBuf::with_byte_size(TCPPROBE_BUF_SIZE, 0);

#[inline(always)]
pub fn try_tcp_probe(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        // Parse event data to struct
        let event: trace_event_raw_tcp_probe = ctx
            .read_at::<trace_event_raw_tcp_probe>(0)
            .map_err(|e| e as u32)?;

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
        let _ = try_flow_tracker(tuple);

        // Create queue entry
        let queue_entry = tcp_probe_entry {
            time: bpf_ktime_get_ns(),
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
        };

        // Prepare ringbuf entry
        let reserved = TCP_PROBE_QUEUE.reserve::<tcp_probe_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(queue_entry);
            entry.submit(1);
            let _ = try_handled_counter();
        } else {
            // Not enough space, drop event
            let _ = try_dropped_counter();
        }
    }

    let _ = try_count_tracpoint();

    Ok(0)
}
