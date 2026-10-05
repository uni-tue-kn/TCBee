use aya_ebpf::{
    helpers::generated::bpf_ktime_get_ns, macros::map, maps::RingBuf, programs::TracePointContext,
};

// Central buffer size config
use crate::{
    config::{AF_INET6, TCP_RETRANSMIT_SYNACK_BUF_SIZE},
    counters::{count_attempt, count_error, submit},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
    flow_tracker::try_flow_tracker,
};

// Kernel tracepoint data structs
use tcbee_common::{
    bindings::{
        flow::IpTuple,
        tcp_retransmit_synack::{
            tcp_retransmit_synack_entry, trace_event_raw_tcp_retransmit_synack,
        },
    },
    stats::RB_RETRANSMIT_SYNACK,
};

#[map(name = "TCP_RETRANSMIT_SYNACK_QUEUE")]
static TCP_RETRANSMIT_SYNACK_QUEUE: RingBuf =
    RingBuf::with_byte_size(TCP_RETRANSMIT_SYNACK_BUF_SIZE, 0);

#[inline(always)]
pub fn try_tcp_retransmit_synack(ctx: TracePointContext) -> Result<u32, u32> {
    // Parse event data to struct
    let Ok(event) = (unsafe { ctx.read_at::<trace_event_raw_tcp_retransmit_synack>(0) }) else {
        // The filter cannot be evaluated without the event, count it as an error
        count_attempt(RB_RETRANSMIT_SYNACK);
        count_error(RB_RETRANSMIT_SYNACK);
        return Ok(0);
    };

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

    count_attempt(RB_RETRANSMIT_SYNACK);
    submit(
        &TCP_RETRANSMIT_SYNACK_QUEUE,
        RB_RETRANSMIT_SYNACK,
        tcp_retransmit_synack_entry {
            time: unsafe { bpf_ktime_get_ns() },
            saddr: event.saddr,
            daddr: event.daddr,
            sport: event.sport,
            dport: event.dport,
            family: event.family,
            saddr_v6: event.saddr_v6,
            daddr_v6: event.daddr_v6,
        },
    );

    let _ = try_flow_tracker(tuple);

    Ok(0)
}
