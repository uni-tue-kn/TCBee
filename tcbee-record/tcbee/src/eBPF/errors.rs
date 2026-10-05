use thiserror::Error;

#[derive(Error, Debug)]
pub enum EBPFRunnerError {
    #[error("Could not attach eBPF program '{name}': {source}")]
    AttachError {
        name: String,
        source: libbpf_rs::Error,
    },
    #[error("Could not open ring buffer '{name}': {source}")]
    MapError {
        name: String,
        source: libbpf_rs::Error,
    },
    #[error("Interface '{name}' not found")]
    InterfaceNotFound { name: String },
    #[error("{0}")]
    Unavailable(String),
}
