use aya_ebpf::{
    helpers::generated::bpf_ktime_get_ns, macros::map, maps::RingBuf, programs::TracePointContext,
};

// Central buffer size config
use crate::{
    config::TCP_BAD_CSUM_BUF_SIZE,
    counters::{count_attempt, count_error, submit},
};

// Kernel tracepoint data structs
use tcbee_common::{
    bindings::tcp_bad_csum::{tcp_bad_csum_entry, trace_event_raw_tcp_bad_csum},
    stats::RB_BAD_CSUM,
};

#[map(name = "TCP_BAD_CSUM_QUEUE")]
static TCP_BAD_CSUM_QUEUE: RingBuf = RingBuf::with_byte_size(TCP_BAD_CSUM_BUF_SIZE, 0);

#[inline(always)]
pub fn try_tcp_bad_csum(ctx: TracePointContext) -> Result<u32, u32> {
    count_attempt(RB_BAD_CSUM);

    // Parse event data to struct
    let Ok(event) = (unsafe { ctx.read_at::<trace_event_raw_tcp_bad_csum>(0) }) else {
        count_error(RB_BAD_CSUM);
        return Ok(0);
    };

    submit(
        &TCP_BAD_CSUM_QUEUE,
        RB_BAD_CSUM,
        tcp_bad_csum_entry {
            time: unsafe { bpf_ktime_get_ns() },
            saddr: event.saddr,
            daddr: event.daddr,
        },
    );

    Ok(0)
}
