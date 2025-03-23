use aya_ebpf::bindings::BPF_EXIST;
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::bpf_map_push_elem;

use aya_ebpf::{macros::map, maps::PerCpuHashMap};

use aya_log_ebpf::warn;
use tcbee_common::bindings::flow::IpTuple;

use crate::config::MAX_FLOWS;

#[map(name = "FLOWS")]
static mut FLOWS: PerCpuHashMap<IpTuple,IpTuple> = PerCpuHashMap::with_max_entries(MAX_FLOWS, 0);


#[inline(always)] 
pub fn try_flow_tracker(flow: IpTuple) -> Result<(), c_long> {
    // TODO: add map.increment() to track number of packets per flow
    unsafe {
       FLOWS.insert(&flow, &flow, 0)?;
    }

    Ok(())
}