use aya_ebpf::bindings::BPF_NOEXIST;
use aya_ebpf::cty::c_long;

use aya_ebpf::{macros::map, maps::PerCpuHashMap};

use tcbee_common::bindings::flow::IpTuple;

use crate::{config::MAX_FLOWS, FLOW_TRACKING};

#[map(name = "FLOWS")]
static FLOWS: PerCpuHashMap<IpTuple, IpTuple> = PerCpuHashMap::with_max_entries(MAX_FLOWS, 0);

// TODO: IpTuple should just carry the family field, makes handling IP a LOT easier than weird format detectors
#[inline(always)]
pub fn try_flow_tracker(flow: IpTuple) -> Result<(), c_long> {
    // The flow list is only shown in the TUI
    if unsafe { core::ptr::read_volatile(&raw const FLOW_TRACKING) } == 0 {
        return Ok(());
    }

    // TODO: add map.increment() to track number of packets per flow
    let key = flow.canonical();
    unsafe {
        // The lookup is lockless, an update takes the bucket lock even if the
        // flow already exists, so only insert flows that are not tracked yet.
        if FLOWS.get(&key).is_none() {
            let _ = FLOWS.insert(&key, &key, BPF_NOEXIST as u64);
        }
    }

    Ok(())
}
