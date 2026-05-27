use anyhow::Context;
use aya::{maps::RingBuf, programs::FEntry, Btf, Ebpf};
use std::error::Error;
use tcbee_common::{bindings::cubic::cubic_trace_entry, prog_bindings::TraceProbe};

use crate::{
    eBPF::{ebpf_runner::prepend_string, errors::EBPFRunnerError},
    writer::Writer,
};

pub struct CubicTracer {}

impl CubicTracer {
    pub fn spawn(ebpf: &mut Ebpf, dir: String, writer: &mut Writer) -> Result<(), Box<dyn Error>> {
        let btf = Btf::from_sys_fs().context("BTF from sysfs")?;

        // For Algo Update
        let sendmsg: &mut FEntry = ebpf.program_mut("cubic_cong_control").unwrap().try_into()?;
        sendmsg.load("cubictcp_cong_avoid", &btf)?;
        sendmsg.attach()?;

        // For Congestion Event
        let recvmsg: &mut FEntry = ebpf.program_mut("cubic_cwnd_event").unwrap().try_into()?;
        recvmsg.load("cubictcp_cwnd_event", &btf)?;
        recvmsg.attach()?;

        // Both programs write to the same map
        let map = ebpf
            .take_map("CUBIC_EVENTS")
            .ok_or(EBPFRunnerError::QueueNotFoundError {
                name: "CUBIC_EVENTS".to_string(),
                trace: "Congestion Algorithm Tracer - Cubic".to_string(),
            })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // We use a centrealized writing scheme
        writer.register::<cubic_trace_entry>(
            buff,
            prepend_string(cubic_trace_entry::FILE.to_string(), &dir),
        )?;

        Ok(())
    }
}
