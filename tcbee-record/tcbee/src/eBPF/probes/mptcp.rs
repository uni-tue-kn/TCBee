use std::error::Error;

use libbpf_rs::{skel::Skel, Link, OpenObject};
use log::warn;
use tcbee_common::{records::mptcp_pm_entry, stats::RB_MPTCP_PM};

use crate::{
    eBPF::{host::KernelBtf, probes::attach, rings, skel::TcbeeSkel},
    writer::Writer,
};

/// The path manager programs and the kernel functions they attach to
pub const PM_HOOKS: [(&str, &str); 8] = [
    ("mptcp_pm_event", "mptcp_event"),
    ("mptcp_pm_announced", "mptcp_event_addr_announced"),
    ("mptcp_pm_removed", "mptcp_event_addr_removed"),
    ("mptcp_pm_token_destroy", "mptcp_token_destroy"),
    ("mptcp_pm_subflow_connect", "__mptcp_subflow_connect"),
    ("mptcp_pm_mp_fail", "mptcp_pm_mp_fail_received"),
    ("mptcp_pm_stale_check", "mptcp_pm_nl_subflow_chk_stale"),
    ("mptcp_pm_stale", "mptcp_pm_nl_subflow_chk_stale"),
];

pub struct MptcpPmTracer {}

impl MptcpPmTracer {
    /// Each program is loaded if its kernel function exists; a kernel may inline some or
    /// have no MPTCP at all. Returns whether any is loaded.
    pub fn configure(object: &mut OpenObject, enabled: bool, btf: &mut KernelBtf) -> bool {
        let check = enabled && btf.available();
        let mut any = false;
        for mut program in object.progs_mut() {
            let name = program.name().to_string_lossy();
            let Some((_, func)) = PM_HOOKS.iter().find(|(prog, _)| *prog == name) else {
                continue;
            };
            let load = enabled && (!check || btf.has_func(None, func));
            if enabled && !load {
                warn!("Kernel function {func} not found, MPTCP events from it are not recorded");
            }
            program.set_autoload(load);
            any |= load;
        }
        any
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        for program in skel.object().progs_mut() {
            let name = program.name().to_string_lossy();
            if program.autoload() && PM_HOOKS.iter().any(|(prog, _)| *prog == name) {
                attach(&program, links)?;
            }
        }
        writer.register::<mptcp_pm_entry>(
            RB_MPTCP_PM,
            rings::of(&skel.maps.MPTCP_PM_EVENTS)?,
            dir,
        )?;
        Ok(())
    }
}
