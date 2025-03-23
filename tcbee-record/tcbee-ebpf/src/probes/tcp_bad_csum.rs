use aya_ebpf::{
    helpers::gen::bpf_ktime_get_ns, 
    macros::map, maps::RingBuf, 
    programs::TracePointContext,
};

// Central buffer size config
use crate::config::TCP_BAD_CSUM_BUF_SIZE;

// Kernel tracepoint data structs
use tcbee_common::bindings::tcp_bad_csum::{tcp_bad_csum_entry,trace_event_raw_tcp_bad_csum};

// Counters for performance metrics
use crate::counters::{try_handled_counter,try_dropped_counter};

#[map(name = "TCP_BAD_CSUM_QUEUE")]
static mut TCP_BAD_CSUM_QUEUE: RingBuf = RingBuf::with_byte_size(TCP_BAD_CSUM_BUF_SIZE, 0);


#[inline(always)]
pub fn try_tcp_bad_csum(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        // Parse event data to struct
        let event: trace_event_raw_tcp_bad_csum = ctx
            .read_at::<trace_event_raw_tcp_bad_csum>(0)
            .map_err(|e| e as u32)?;
      
        // Create queue entry
        let queue_entry = tcp_bad_csum_entry {
            time: bpf_ktime_get_ns(),
            saddr: event.saddr,
            daddr: event.daddr
        };

        // Prepare ringbuf entry
        let reserved = TCP_BAD_CSUM_QUEUE.reserve::<tcp_bad_csum_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(queue_entry);
            entry.submit(0);
            let _ = try_handled_counter();
        }else {
            // Not enough space, drop event
            let _ = try_dropped_counter();
        }
        
    }

    Ok(0)
}