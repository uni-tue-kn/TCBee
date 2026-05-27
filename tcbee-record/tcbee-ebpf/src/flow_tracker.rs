use aya_ebpf::bindings::BPF_NOEXIST;
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::bpf_map_push_elem;

use aya_ebpf::{macros::map, maps::PerCpuHashMap};

use tcbee_common::bindings::flow::IpTuple;

use crate::config::MAX_FLOWS;

#[map(name = "FLOWS")]
static mut FLOWS: PerCpuHashMap<IpTuple, IpTuple> = PerCpuHashMap::with_max_entries(MAX_FLOWS, 0);

// TODO: IpTuple should just carry the family field, makes handling IP a LOT easier than weird format detectors
#[inline(always)]
pub fn try_flow_tracker(flow: IpTuple) -> Result<(), c_long> {
    // TODO: add map.increment() to track number of packets per flow
    let key = flow.canonical();
    unsafe {
        // BPF_NOEXIST: skip the write if this flow is already tracked.
        // EEXIST is expected for established flows; ignore it.
        let _ = FLOWS.insert(&key, &key, BPF_NOEXIST as u64);
    }

    Ok(())
}
