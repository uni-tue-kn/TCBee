use aya::{maps::RingBuf, programs::KProbe, Ebpf};
use std::error::Error;
use tcbee_common::{bindings::bbr::bbr_trace_entry, prog_bindings::TraceProbe};

use crate::{
    eBPF::{ebpf_runner::prepend_string, errors::EBPFRunnerError},
    writer::Writer,
};

pub struct BBRTracer {}

impl BBRTracer {
    pub fn spawn(ebpf: &mut Ebpf, dir: String, writer: &mut Writer) -> Result<(), Box<dyn Error>> {
        // For Algo Update
        let update_hook: &mut KProbe = ebpf.program_mut("bbr_cong_control").unwrap().try_into()?;
        update_hook.load()?;
        update_hook.attach("bbr_main", 0)?;

        // For Congestion Event
        let congestion_hook: &mut KProbe =
            ebpf.program_mut("bbr_cwnd_event").unwrap().try_into()?;
        congestion_hook.load()?;
        congestion_hook.attach("bbr_cwnd_event", 0)?;

        // Both programs write to the same map
        let map = ebpf
            .take_map("BBR_EVENTS")
            .ok_or(EBPFRunnerError::QueueNotFoundError {
                name: "BBR_EVENTS".to_string(),
                trace: "Congestion Algorithm Tracer - BBR".to_string(),
            })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // We use a centrealized writing scheme
        writer.register::<bbr_trace_entry>(
            buff,
            prepend_string(bbr_trace_entry::FILE.to_string(), &dir),
        )?;

        Ok(())
    }
}
