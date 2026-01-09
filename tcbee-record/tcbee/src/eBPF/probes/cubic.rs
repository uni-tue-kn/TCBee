use aya::{Btf, Ebpf, maps::RingBuf, programs::FEntry};
use tcbee_common::bindings::cubic::cubic_trace_entry;
use std::error::Error;
use anyhow::Context;

use crate::{eBPF::errors::EBPFRunnerError, handlers::writer::Writer};

pub struct CubicTracer {}

impl CubicTracer {
    pub fn spawn(
        ebpf: &mut Ebpf,
        file_path: String,
        writer: &mut Writer,
    ) -> Result<(), Box<dyn Error>> {
        let name = "cubic_tracer";
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
        let map =
            ebpf.take_map("CUBIC_EVENTS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "CUBIC_EVENTS".to_string(),
                    trace: "Congestion Algorithm Tracer - Cubic".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // We use a centrealized writing scheme
        writer.register::<cubic_trace_entry>(buff, file_path)?;

        Ok(())
    }
}