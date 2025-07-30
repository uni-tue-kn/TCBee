use std::error::Error;

use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use tokio::task::{self, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{eBPF::errors::EBPFRunnerError, handlers::{tracepoints::HandlerConstraints, BufferHandler, BufferHandlerImpl}};

pub struct TracepointTracer {

}

impl TracepointTracer {
    // The BufferHandlerImpl trait is used to implement the unique handling function for T.
    pub fn spawn<T: HandlerConstraints<T>>(
        ebpf: &mut Ebpf,
        token: CancellationToken,
        file_path: String,
    ) -> Result<JoinHandle<()>, Box<dyn Error>>
    where
        // BufferHandlerImpl has to be implemented for BufferHandler for the passed T
        BufferHandler<T>: BufferHandlerImpl<T>,
    {
        // Get tracepoint name
        let name = T::NAME;

        // Get trace point object from eBPF library
        let trace_point: &mut TracePoint = ebpf
            .program_mut(name)
            .ok_or(EBPFRunnerError::InvalidProgramError {
                name: name.to_string(),
            })?
            .try_into()?;

        // Load and attach tracepoint to kernel
        trace_point.load()?;
        trace_point.attach(T::CATEGORY, name)?;

        // Get queue from
        let map = ebpf
            .take_map(T::QUEUE_NAME)
            .ok_or(EBPFRunnerError::QueueNotFoundError {
                name: T::QUEUE_NAME.to_string(),
                trace: T::NAME.to_string(),
            })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // Create handler object
        let mut handler = BufferHandler::<T>::new(name, token, buff, file_path).unwrap();

        // Start thread and store join handle
        Ok(task::spawn(async move {
            handler.run().await;
        }))
    }
}