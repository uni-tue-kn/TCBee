use std::{collections::BTreeSet, error::Error};

use libbpf_rs::{skel::OpenSkel, Link};
use tcbee_common::records::cubic_trace_entry;

use tcbee_common::stats::RB_CUBIC;

use crate::{
    eBPF::{
        errors::EBPFRunnerError,
        host::KernelBtf,
        optional::OptionalGroup,
        probes::{
            attach,
            optional_hooks::{self, OptionalHook, Target},
            retarget,
        },
        rings,
        skel::{OpenTcbeeSkel, TcbeeSkel},
    },
    writer::Writer,
};

/// CUBIC is built in on most distributions, but may be a module
const MODULE: &str = "tcp_cubic";
const CONG_AVOID: &str = "cubictcp_cong_avoid";
/// Renamed in kernel 7.2
const CWND_EVENT: [&str; 2] = ["cubictcp_cwnd_event", "cubictcp_cwnd_event_tx_start"];

/// The CUBIC hooks of -a besides the ACK and cwnd event ones. Each one is optional on its own
/// (`OptionalGroup::CubicHook`).
pub const CUBIC_HOOKS: [OptionalHook<()>; 2] = [
    OptionalHook {
        programs: &["cubic_ssthresh"],
        target: Target::ModuleFunction(MODULE, "cubictcp_recalc_ssthresh"),
        name: "CUBIC ssthresh hook",
        selector: (),
    },
    OptionalHook {
        programs: &["cubic_state"],
        target: Target::ModuleFunction(MODULE, "cubictcp_state"),
        name: "CUBIC state hook",
        selector: (),
    },
];

fn not_recorded(name: &str) -> String {
    format!("the {name} is not recorded")
}

pub struct CubicTracer {}

impl CubicTracer {
    /// Fails if CUBIC is enabled but not available in the kernel. Loads the hooks of
    /// `CUBIC_HOOKS` that exist in the kernel and are not in `disabled`; returns their indices
    /// and a message for each one the kernel lacks.
    pub fn configure(
        open: &mut OpenTcbeeSkel<'_>,
        enabled: bool,
        disabled: &BTreeSet<OptionalGroup>,
        btf: &mut KernelBtf,
    ) -> Result<(Vec<usize>, Vec<String>), EBPFRunnerError> {
        let progs = &mut open.progs;
        progs.cubic_cong_control.set_autoload(enabled);
        progs.cubic_cwnd_event.set_autoload(enabled);
        if enabled && btf.available() {
            if !btf.has_func(Some(MODULE), CONG_AVOID) {
                return Err(EBPFRunnerError::Unavailable(format!(
                    "Kernel function {} not found, is {} loaded?",
                    CONG_AVOID, MODULE
                )));
            }
            retarget(&mut progs.cubic_cwnd_event, btf, Some(MODULE), &CWND_EVENT)?;
        }
        let exists = optional_hooks::existing(&CUBIC_HOOKS, |()| enabled, btf);
        let (load, missing) = optional_hooks::to_load(
            &CUBIC_HOOKS,
            |()| enabled,
            &exists,
            disabled,
            OptionalGroup::CubicHook,
        );
        let skipped = missing
            .into_iter()
            .map(|i| optional_hooks::report_missing(&CUBIC_HOOKS[i], not_recorded))
            .collect();
        let loaded = optional_hooks::set_autoload(&CUBIC_HOOKS, open.open_object_mut(), &load);
        Ok((loaded, skipped))
    }

    /// Attaches the programs and registers the writer. A hook of `CUBIC_HOOKS` that does not
    /// attach is left out with a warning; returns its index and a message for each.
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<Vec<(usize, String)>, Box<dyn Error>> {
        // For Algo Update
        attach(&skel.progs.cubic_cong_control, links)?;
        // For Congestion Event, unless the kernel has no such function
        if skel.progs.cubic_cwnd_event.autoload() {
            attach(&skel.progs.cubic_cwnd_event, links)?;
        }
        let (_, failed) = optional_hooks::attach_loaded(&CUBIC_HOOKS, skel, links, not_recorded);

        // All programs write to the same map
        writer.register::<cubic_trace_entry>(RB_CUBIC, rings::of(&skel.maps.CUBIC_EVENTS)?, dir)?;

        Ok(failed)
    }
}
