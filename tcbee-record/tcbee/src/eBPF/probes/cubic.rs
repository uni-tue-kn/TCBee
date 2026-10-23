use std::{collections::BTreeSet, error::Error};

use libbpf_rs::{Link, OpenProgramMut, ProgramMut};
use log::warn;
use tcbee_common::records::cubic_trace_entry;

use tcbee_common::stats::RB_CUBIC;

use crate::{
    eBPF::{
        errors::EBPFRunnerError,
        host::KernelBtf,
        optional::OptionalGroup,
        probes::{attach, retarget},
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

/// CUBIC is built in on most distributions, but may be a module
const MODULE: &str = "tcp_cubic";
const CONG_AVOID: &str = "cubictcp_cong_avoid";
/// Renamed in kernel 7.2
const CWND_EVENT: [&str; 2] = ["cubictcp_cwnd_event", "cubictcp_cwnd_event_tx_start"];
const SSTHRESH: &str = "cubictcp_recalc_ssthresh";
const STATE: &str = "cubictcp_state";

pub struct CubicTracer {}

impl CubicTracer {
    /// Fails if CUBIC is enabled but not available in the kernel. The ssthresh and state hooks
    /// are optional on their own: returns the ones that load (unless in `disabled`) and a
    /// message for each one the kernel lacks.
    pub fn configure(
        progs: &mut OpenTcbeeProgs<'_>,
        enabled: bool,
        disabled: &BTreeSet<OptionalGroup>,
        btf: &mut KernelBtf,
    ) -> Result<(Vec<OptionalGroup>, Vec<String>), EBPFRunnerError> {
        progs.cubic_cong_control.set_autoload(enabled);
        progs.cubic_cwnd_event.set_autoload(enabled);
        progs.cubic_ssthresh.set_autoload(false);
        progs.cubic_state.set_autoload(false);
        if !enabled {
            return Ok((Vec::new(), Vec::new()));
        }
        if btf.available() && !btf.has_func(Some(MODULE), CONG_AVOID) {
            return Err(EBPFRunnerError::Unavailable(format!(
                "Kernel function {} not found, is {} loaded?",
                CONG_AVOID, MODULE
            )));
        }
        if btf.available() {
            retarget(&mut progs.cubic_cwnd_event, btf, Some(MODULE), &CWND_EVENT)?;
        }
        let mut loaded = Vec::new();
        let mut missing = Vec::new();
        for (group, program, func) in [
            (
                OptionalGroup::CubicSsthresh,
                &mut progs.cubic_ssthresh,
                SSTHRESH,
            ),
            (OptionalGroup::CubicState, &mut progs.cubic_state, STATE),
        ] {
            if disabled.contains(&group) {
                continue;
            }
            if let Some(message) = Self::load_optional(program, btf, func, group) {
                missing.push(message);
            } else {
                loaded.push(group);
            }
        }
        Ok((loaded, missing))
    }

    /// Loads an optional program if the kernel has its function, else returns the message
    fn load_optional(
        program: &mut OpenProgramMut<'_>,
        btf: &mut KernelBtf,
        func: &str,
        group: OptionalGroup,
    ) -> Option<String> {
        if btf.available() && !btf.has_func(Some(MODULE), func) {
            warn!(
                "The kernel function {} does not exist, the {} is not recorded",
                func,
                group.name()
            );
            return Some(format!("{}: no kernel function {}", group.name(), func));
        }
        program.set_autoload(true);
        None
    }

    /// Attaches the programs and registers the writer. An optional hook that does not attach
    /// is left out with a warning; returns its group and a message for each.
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<Vec<(OptionalGroup, String)>, Box<dyn Error>> {
        // For Algo Update
        attach(&skel.progs.cubic_cong_control, links)?;
        // For Congestion Event, unless the kernel has no such function
        if skel.progs.cubic_cwnd_event.autoload() {
            attach(&skel.progs.cubic_cwnd_event, links)?;
        }
        let mut failed = Vec::new();
        for (group, program) in [
            (OptionalGroup::CubicSsthresh, &skel.progs.cubic_ssthresh),
            (OptionalGroup::CubicState, &skel.progs.cubic_state),
        ] {
            if let Some(message) = Self::attach_optional(program, group, links) {
                failed.push((group, message));
            }
        }

        // All programs write to the same map
        writer.register::<cubic_trace_entry>(RB_CUBIC, rings::of(&skel.maps.CUBIC_EVENTS)?, dir)?;

        Ok(failed)
    }

    fn attach_optional(
        program: &ProgramMut<'_>,
        group: OptionalGroup,
        links: &mut Vec<Link>,
    ) -> Option<String> {
        if !program.autoload() {
            return None;
        }
        let err = attach(program, links).err()?;
        warn!("{}, the {} is not recorded", err, group.name());
        Some(format!("{}: attaching failed: {}", group.name(), err))
    }
}
