//! What the TUI shows about the run besides the counters

use crate::viz::flow_owners::SharedOwners;

/// The run as the recorder started it, built by the runner once every probe is attached
pub struct RunContext {
    pub dir: String,
    /// Interface of the header hooks, None without -h
    pub iface: Option<String>,
    /// CPUs with a ring buffer per probe output
    pub cpus: u32,
    /// Ring buffers that record, as `RB_*` ids
    pub active_rings: Vec<u32>,
    /// Requested hooks that are not recorded, with the reason
    pub skipped: Vec<String>,
    /// The sock and cwnd probes record on change only
    pub on_change: bool,
    /// The chart window at the start, None for the whole run
    pub observation_window: Option<f64>,
    /// The owners of the flows, filled while recording, with the TUI and the owner programs
    pub owners: Option<SharedOwners>,
}
