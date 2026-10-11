use std::error::Error;

use libbpf_rs::{skel::Skel, Link, OpenObject};
use log::warn;
use tcbee_common::{records::mptcp_pm_entry, stats::RB_MPTCP_PM};

use crate::{
    eBPF::{host::KernelBtf, probes::attach, rings, skel::TcbeeSkel},
    writer::Writer,
};

/// The path manager programs and the kernel functions they attach to, in attach order. Of a
/// pair on one function the exit program comes first: it does nothing without the state its
/// entry program stores, while an entry program attached alone could leave state that a later
/// exit takes for its own.
pub const PM_HOOKS: [(&str, &str); 14] = [
    ("mptcp_pm_event", "mptcp_event"),
    ("mptcp_pm_announced", "mptcp_event_addr_announced"),
    ("mptcp_pm_removed", "mptcp_event_addr_removed"),
    ("mptcp_pm_token_destroy", "mptcp_token_destroy"),
    ("mptcp_pm_subflow_connect", "__mptcp_subflow_connect"),
    ("mptcp_pm_mp_fail", "mptcp_pm_mp_fail_received"),
    ("mptcp_pm_stale", "mptcp_pm_nl_subflow_chk_stale"),
    ("mptcp_pm_stale_check", "mptcp_pm_nl_subflow_chk_stale"),
    ("mptcp_pm_prio_sent", "mptcp_pm_nl_mp_prio_send_ack"),
    ("mptcp_pm_retrans", "__mptcp_retrans"),
    ("mptcp_pm_retrans_start", "__mptcp_retrans"),
    ("mptcp_pm_requeue", "__mptcp_retransmit_pending_data"),
    ("mptcp_pm_fallback", "subflow_finish_connect"),
    ("mptcp_pm_connect_check", "subflow_finish_connect"),
];

pub struct MptcpPmTracer {}

impl MptcpPmTracer {
    /// Each program is loaded if its kernel function exists; a kernel may inline some or
    /// have no MPTCP at all. Returns whether any is loaded, and a message for each missing
    /// function.
    pub fn configure(
        object: &mut OpenObject,
        enabled: bool,
        btf: &mut KernelBtf,
    ) -> (bool, Vec<String>) {
        let check = enabled && btf.available();
        let mut any = false;
        let mut skipped = Vec::new();
        for mut program in object.progs_mut() {
            let name = program.name().to_string_lossy();
            let Some((_, func)) = PM_HOOKS.iter().find(|(prog, _)| *prog == name) else {
                continue;
            };
            let load = enabled && (!check || btf.has_func(None, func));
            if enabled && !load {
                warn!("Kernel function {func} not found, MPTCP events from it are not recorded");
                let message = format!("MPTCP events of {func}: no kernel function {func}");
                // Entry and exit programs of one function report it once
                if !skipped.contains(&message) {
                    skipped.push(message);
                }
            }
            program.set_autoload(load);
            any |= load;
        }
        (any, skipped)
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        for (name, _) in PM_HOOKS {
            let program = skel
                .object()
                .progs_mut()
                .find(|p| p.name().to_string_lossy() == name);
            if let Some(program) = program.filter(|p| p.autoload()) {
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
