use std::error::Error;

use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use serde::Serialize;
use tcbee_common::prog_bindings::TracePointProbe;

use crate::{
    eBPF::{ebpf_runner::prepend_string, errors::EBPFRunnerError},
    writer::Writer,
};

pub struct TracepointTracer {}

impl TracepointTracer {
    // T is passed to determine struct and names for registration
    pub fn spawn<T: TracePointProbe + Serialize + Copy + Send + 'static>(
        ebpf: &mut Ebpf,
        dir: String,
        writer: &mut Writer,
    ) -> Result<(), Box<dyn Error>> {
        let name = T::NAME;
        let category = T::CATEGORY;

        // Get trace point object from eBPF library
        let trace_point: &mut TracePoint = ebpf
            .program_mut(name)
            .ok_or(EBPFRunnerError::InvalidProgramError {
                name: name.to_string(),
            })?
            .try_into()?;

        // Load and attach tracepoint to kernel
        trace_point.load()?;
        trace_point.attach(category, name)?;

        // Get queue from
        let map = ebpf
            .take_map(T::QUEUE)
            .ok_or(EBPFRunnerError::QueueNotFoundError {
                name: T::QUEUE.to_string(),
                trace: T::NAME.to_string(),
            })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        writer.register::<T>(buff, prepend_string(T::FILE.to_string(), &dir))?;

        Ok(())
    }
}
