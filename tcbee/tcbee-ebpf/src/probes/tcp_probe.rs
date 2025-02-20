use aya_ebpf::{
    helpers::gen::bpf_ktime_get_ns, 
    macros::map, maps::RingBuf, 
    programs::TracePointContext,
};

// Central buffer size config
use crate::config::TCPPROBE_BUF_SIZE;

// Kernel tracepoint data structs
use tcbee_common::bindings::tcp_probe::{tcp_probe_entry,trace_event_raw_tcp_probe};

// Counters for performance metrics
use crate::counters::{try_handled_counter,try_dropped_counter};

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
            entry.submit(0);
            let _ = try_handled_counter();
        } else {
            // Not enough space, drop event
            let _ = try_dropped_counter();
        }
    }

    Ok(0)
}
