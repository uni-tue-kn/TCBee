use aya_ebpf::{
    helpers::generated::bpf_ktime_get_ns, macros::map, maps::RingBuf, programs::TracePointContext,
};

// Central buffer size config
use crate::{
    config::{AF_INET, TCP_BAD_CSUM_BUF_SIZE},
    counters::{count_attempt, count_error, submit},
    filter::{filter_needs_tuple, filter_ports_match, filter_tuple_match},
};

// Kernel tracepoint data structs
use tcbee_common::{
    bindings::{
        flow::IpTuple,
        tcp_bad_csum::{tcp_bad_csum_entry, trace_event_raw_tcp_bad_csum},
    },
    stats::RB_BAD_CSUM,
};

#[map(name = "TCP_BAD_CSUM_QUEUE")]
static TCP_BAD_CSUM_QUEUE: RingBuf = RingBuf::with_byte_size(TCP_BAD_CSUM_BUF_SIZE, 0);

#[inline(always)]
pub fn try_tcp_bad_csum(ctx: TracePointContext) -> Result<u32, u32> {
    // Parse event data to struct
    let Ok(event) = (unsafe { ctx.read_at::<trace_event_raw_tcp_bad_csum>(0) }) else {
        // The filter cannot be evaluated without the event, count it as an error
        count_attempt(RB_BAD_CSUM);
        count_error(RB_BAD_CSUM);
        return Ok(0);
    };

    // sin_port and sin6_port are at offset 2 in network byte order
    let sport = u16::from_be_bytes([event.saddr[2], event.saddr[3]]);
    let dport = u16::from_be_bytes([event.daddr[2], event.daddr[3]]);
    if !filter_ports_match(sport, dport) {
        return Ok(0);
    }

    // sin_addr is at offset 4, sin6_addr at offset 8
    let is_ipv4 = u16::from_ne_bytes([event.saddr[0], event.saddr[1]]) == AF_INET;
    if filter_needs_tuple() {
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        if is_ipv4 {
            src_ip[..4].copy_from_slice(&event.saddr[4..8]);
            dst_ip[..4].copy_from_slice(&event.daddr[4..8]);
        } else {
            src_ip.copy_from_slice(&event.saddr[8..24]);
            dst_ip.copy_from_slice(&event.daddr[8..24]);
        }
        let tuple = IpTuple {
            src_ip,
            dst_ip,
            sport,
            dport,
            protocol: 6,
        };
        if !filter_tuple_match(&tuple) {
            return Ok(0);
        }
    }

    // The record only holds IPv4 addresses, leave them zero for IPv6
    let mut saddr = [0u8; 4];
    let mut daddr = [0u8; 4];
    if is_ipv4 {
        saddr.copy_from_slice(&event.saddr[4..8]);
        daddr.copy_from_slice(&event.daddr[4..8]);
    }

    count_attempt(RB_BAD_CSUM);
    submit(
        &TCP_BAD_CSUM_QUEUE,
        RB_BAD_CSUM,
        tcp_bad_csum_entry {
            time: unsafe { bpf_ktime_get_ns() },
            saddr,
            daddr,
        },
    );

    Ok(0)
}
