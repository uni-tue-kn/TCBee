use std::error::Error;

use libbpf_rs::{Link, OpenProgramMut, ProgramMut};
use log::warn;
use tcbee_common::{records::mptcp_pm_entry, stats::RB_MPTCP_PM};

use crate::{
    eBPF::{
        host::KernelBtf,
        probes::attach,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct MptcpPmTracer {}

impl MptcpPmTracer {
    /// The path manager programs and the kernel functions they attach to
    fn programs<'a, 'obj>(
        progs: &'a mut OpenTcbeeProgs<'obj>,
    ) -> [(&'a mut OpenProgramMut<'obj>, &'static str); 6] {
        [
            (&mut progs.mptcp_pm_event, "mptcp_event"),
            (&mut progs.mptcp_pm_announced, "mptcp_event_addr_announced"),
            (&mut progs.mptcp_pm_removed, "mptcp_event_addr_removed"),
            (&mut progs.mptcp_pm_token_destroy, "mptcp_token_destroy"),
            (
                &mut progs.mptcp_pm_subflow_connect,
                "__mptcp_subflow_connect",
            ),
            (&mut progs.mptcp_pm_mp_fail, "mptcp_pm_mp_fail_received"),
        ]
    }

    /// Each program is loaded if its kernel function exists; a kernel may inline some or
    /// have no MPTCP at all. Returns whether any is loaded.
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool, btf: &mut KernelBtf) -> bool {
        let check = enabled && btf.available();
        let mut any = false;
        for (program, func) in Self::programs(progs) {
            let load = enabled && (!check || btf.has_func(None, func));
            if enabled && !load {
                warn!(
                    "Kernel function {} not found, MPTCP events from it are not recorded",
                    func
                );
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
        let progs = &skel.progs;
        let programs: [&ProgramMut<'_>; 6] = [
            &progs.mptcp_pm_event,
            &progs.mptcp_pm_announced,
            &progs.mptcp_pm_removed,
            &progs.mptcp_pm_token_destroy,
            &progs.mptcp_pm_subflow_connect,
            &progs.mptcp_pm_mp_fail,
        ];
        for program in programs.into_iter().filter(|p| p.autoload()) {
            attach(program, links)?;
        }
        writer.register::<mptcp_pm_entry>(
            RB_MPTCP_PM,
            rings::of(&skel.maps.MPTCP_PM_EVENTS)?,
            dir,
        )?;
        Ok(())
    }
}
