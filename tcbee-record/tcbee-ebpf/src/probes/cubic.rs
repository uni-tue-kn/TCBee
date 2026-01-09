use aya_ebpf::{helpers::{bpf_probe_read_kernel, r#gen::bpf_ktime_get_ns}, macros::map, maps::RingBuf, programs::FEntryContext};
use tcbee_common::bindings::{cubic::{cubic, cubic_trace_entry}, tcp_sock::sock};

use crate::{FILTER_PORT, config::CUBIC_BUF_SIZE, counters::{try_dropped_counter, try_handled_counter}};

#[map(name = "CUBIC_EVENTS")]
static mut CUBIC_EVENTS: RingBuf = RingBuf::with_byte_size(CUBIC_BUF_SIZE as u32, 0);

// TODO: move to helpers
#[inline(always)]
fn read_kernel<T>(src: *const T) -> Result<T, u32> {
    unsafe { bpf_probe_read_kernel(src).map_err(|_| 1u32) }
}


// TODO: it should be possible to generate this entire function from a macro.....
#[inline(always)]
pub fn cubic_handle(ctx: FEntryContext) -> Result<u32, u32> {
    let sk_ptr: *const sock = unsafe { ctx.arg(0) };
    let cubic_ptr = sk_ptr as *const cubic;

    let ports = unsafe { &(*sk_ptr).__sk_common.__bindgen_anon_3.skc_portpair };

    let sport = ((ports & 0xFFFF) as u16).to_be();
    let dport = ((ports >> 16) as u16).to_be();

    unsafe {
        // dport needs to be called to_be otherwise value is wrong
        if FILTER_PORT != 0 && sport != FILTER_PORT && dport != FILTER_PORT {
            //info!(&ctx, "Dropped: {} - {}",sport,dport.to_be());
            return Ok(0);
        }

        // Copies fields with same name from cubic_ptr
        let cubic_entry = cubic_trace_entry::read_from(sk_ptr, cubic_ptr)?;

        // Prepare ringbuf entry
        let reserved = CUBIC_EVENTS.reserve::<cubic_trace_entry>(0);

        // Check if space left for entry
        if let Some(mut entry) = reserved {
            // Enough space, write and track handled events
            entry.write(cubic_entry);
            entry.submit(0);
            let _ = try_handled_counter();
        } else {
            let _ = try_dropped_counter();
        }

    }
    Ok(0)
}
