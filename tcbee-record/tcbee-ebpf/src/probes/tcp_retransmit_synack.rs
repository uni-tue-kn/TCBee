use aya_ebpf::{
    helpers::generated::bpf_ktime_get_ns, macros::map, maps::RingBuf, programs::TracePointContext,
};

// Central buffer size config
use crate::{
    config::{AF_INET6, TCP_RETRANSMIT_SYNACK_BUF_SIZE},
    counters::try_count_tracpoint,
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
};

// Kernel tracepoint data structs
use tcbee_common::bindings::{
    flow::IpTuple,
    tcp_retransmit_synack::{tcp_retransmit_synack_entry, trace_event_raw_tcp_retransmit_synack},
};

// Counters for performance metrics
use crate::counters::{try_dropped_counter, try_handled_counter};

#[map(name = "TCP_RETRANSMIT_SYNACK_QUEUE")]
static mut TCP_RETRANSMIT_SYNACK_QUEUE: RingBuf =
    RingBuf::with_byte_size(TCP_RETRANSMIT_SYNACK_BUF_SIZE, 0);

#[inline(always)]
pub fn try_tcp_retransmit_synack(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        // Parse event data to struct
        let event: trace_event_raw_tcp_retransmit_synack = ctx
            .read_at::<trace_event_raw_tcp_retransmit_synack>(0)
            .map_err(|e| e as u32)?;

        if !filter_ports_match(event.sport, event.dport) {
            return Ok(0);
        }

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        if event.family == AF_INET6 {
            src_ip = event.saddr_v6;
            dst_ip = event.daddr_v6;
        } else {
            src_ip[..4].copy_from_slice(&event.saddr);
            dst_ip[..4].copy_from_slice(&event.daddr);
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
        let queue_entry = tcp_retransmit_synack_entry {
            time: bpf_ktime_get_ns(),
            saddr: event.saddr,
            daddr: event.daddr,
            sport: event.sport,
            dport: event.dport,
            family: event.family,
            saddr_v6: event.saddr_v6,
            daddr_v6: event.daddr_v6,
        };

        // Prepare ringbuf entry
        let reserved = TCP_RETRANSMIT_SYNACK_QUEUE.reserve::<tcp_retransmit_synack_entry>(0);

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
