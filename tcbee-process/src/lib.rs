//! `tcbee-process`: converts a TCBee trace directory into a SQLite or DuckDB database
//! (schema version 2).
//!
//! `main.rs` only parses arguments and maps errors to exit codes, so the tests call [`run`].

mod bindings;
mod cli;
mod decode;
mod event;
#[cfg(test)]
mod fixtures;
mod ip;
mod pipeline;
mod registry;

use std::path::PathBuf;

pub use cli::{engine_for_output, parse_args};
pub use pipeline::{FileSummary, Summary, NO_DECODER, UNIT_RECORDS};
pub use ts_storage::Engine;

/// Parsed command line.
#[derive(Debug, Clone)]
pub struct Args {
    /// A trace directory, or a directory to search for the latest `tcbee_*` recording.
    pub source: PathBuf,
    /// Database file to create.
    pub output: PathBuf,
    pub engine: Engine,
    /// Worker threads; `None` means the number of available cores.
    pub threads: Option<usize>,
    /// Replace an existing output file.
    pub force: bool,
}

impl Args {
    pub fn new(source: impl Into<PathBuf>, output: impl Into<PathBuf>, engine: Engine) -> Args {
        Args {
            source: source.into(),
            output: output.into(),
            engine,
            threads: None,
            force: false,
        }
    }
}

/// Processes the trace into the output database. On any error the output is not created (and an
/// existing output is only replaced when `force` is set and the run succeeds).
pub fn run(args: Args) -> anyhow::Result<Summary> {
    pipeline::run(&args)
}
