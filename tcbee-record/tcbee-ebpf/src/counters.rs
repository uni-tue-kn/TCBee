use core::intrinsics::{atomic_xadd, AtomicOrdering};

use aya_ebpf::{macros::map, maps::PerCpuArray, maps::RingBuf};
use tcbee_common::stats::{
    slot, STATS_LEN, STAT_ATTEMPTED, STAT_DROPPED, STAT_ERROR, STAT_HANDLED,
};

// Per ring buffer [attempted, handled, dropped, error] counters, see tcbee_common::stats
#[map(name = "STATS")]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STATS_LEN, 0);

// fentry and tracepoint programs only run with migration disabled, so a softirq can
// interrupt an update on the same CPU. The atomic add keeps per-CPU increments exact.
// BPF has no compare-and-swap, so AtomicU64::fetch_add is not available.
#[inline(always)]
pub fn add_stat(index: u32, value: u64) {
    if let Some(ptr) = STATS.get_ptr_mut(index) {
        unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(ptr, value) };
    }
}

/// Count a probe invocation that passed the filter. Must be followed by exactly one
/// call to `count_error` or `submit`.
#[inline(always)]
pub fn count_attempt(rb: u32) {
    add_stat(slot(rb, STAT_ATTEMPTED), 1);
}

#[inline(always)]
pub fn count_error(rb: u32) {
    add_stat(slot(rb, STAT_ERROR), 1);
}

/// Write `value` to the ring buffer and count it as handled, or as dropped if full.
#[inline(always)]
pub fn submit<T: 'static>(ringbuf: &RingBuf, rb: u32, value: T) {
    match ringbuf.reserve::<T>(0) {
        Some(mut entry) => {
            entry.write(value);
            // BPF_RB_NO_WAKEUP: the writer threads busy-poll
            entry.submit(1);
            add_stat(slot(rb, STAT_HANDLED), 1);
        }
        None => add_stat(slot(rb, STAT_DROPPED), 1),
    }
}
