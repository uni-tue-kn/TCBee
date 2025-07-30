use thiserror::Error;
use std::error::Error;

#[derive(Error, Debug)]
pub enum EBPFRunnerError {
    #[error("Could not find queue with name: {name} for tracepoint: {trace}!")]
    QueueNotFoundError {
        name: String,
        trace: String
    },
    #[error("Could not find an available kernel program with {name}!")]
    InvalidProgramError {
        name: String
    },
    #[error("Could not load eBPF program '{name}' into kernel! Original Error: {orig_e:?}")]
    TracepointKernelLoadError {
        name: String,
        orig_e: Box<dyn Error>
    }
}