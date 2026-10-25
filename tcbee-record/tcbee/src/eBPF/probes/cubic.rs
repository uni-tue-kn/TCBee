use std::{collections::BTreeSet, error::Error};

use libbpf_rs::{skel::OpenSkel, Link};
use log::warn;
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

/// The CUBIC hooks of -a besides the ACK and cwnd event ones (`OptionalGroup::Cubic`), which
/// they load with. Each one is optional on its own (`OptionalGroup::CubicHook`).
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
    /// The ACK and cwnd event programs need tcp_cubic loaded (or built in). Without it, or if
    /// they are `disabled`, CUBIC is left out like BBR, with a message. Otherwise the hooks of
    /// `CUBIC_HOOKS` that exist in the kernel and are not `disabled` load too. Returns whether
    /// CUBIC loads, the indices of the loaded hooks and a message for each one the kernel
    /// lacks.
    pub fn configure(
        open: &mut OpenTcbeeSkel<'_>,
        enabled: bool,
        disabled: &BTreeSet<OptionalGroup>,
        btf: &mut KernelBtf,
    ) -> Result<(bool, Vec<usize>, Vec<String>), EBPFRunnerError> {
        let mut enabled = enabled && !disabled.contains(&OptionalGroup::Cubic);
        let mut skipped = Vec::new();
        if enabled && btf.available() && !btf.has_func(Some(MODULE), CONG_AVOID) {
            warn!(
                "The kernel function {} does not exist, CUBIC is not recorded (is {} loaded?)",
                CONG_AVOID, MODULE
            );
            skipped.push(format!(
                "CUBIC: no kernel function {} in this kernel",
                CONG_AVOID
            ));
            enabled = false;
        }
        let progs = &mut open.progs;
        progs.cubic_cong_control.set_autoload(enabled);
        progs.cubic_cwnd_event.set_autoload(enabled);
        if enabled && btf.available() {
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
        skipped.extend(
            missing
                .into_iter()
                .map(|i| optional_hooks::report_missing(&CUBIC_HOOKS[i], not_recorded)),
        );
        let loaded = optional_hooks::set_autoload(&CUBIC_HOOKS, open.open_object_mut(), &load);
        Ok((enabled, loaded, skipped))
    }

    /// Attaches the programs and registers the writer; on an error the caller detaches what
    /// was attached. A hook of `CUBIC_HOOKS` that does not attach is left out with a warning;
    /// returns its index and a message for each.
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
