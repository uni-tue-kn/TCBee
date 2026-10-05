use std::error::Error;

use libbpf_rs::Link;
use tcbee_common::{prog_bindings::TraceProbe, records::cubic_trace_entry};

use tcbee_common::stats::RB_CUBIC;

use crate::{
    eBPF::{
        ebpf_runner::prepend_string,
        errors::EBPFRunnerError,
        host::KernelBtf,
        probes::{attach, handle, retarget},
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

/// CUBIC is built in on most distributions, but may be a module
const MODULE: &str = "tcp_cubic";
const CONG_AVOID: &str = "cubictcp_cong_avoid";
/// Renamed in kernel 7.2
const CWND_EVENT: [&str; 2] = ["cubictcp_cwnd_event", "cubictcp_cwnd_event_tx_start"];

pub struct CubicTracer {}

impl CubicTracer {
    /// Fails if CUBIC is enabled but not available in the kernel
    pub fn configure(
        progs: &mut OpenTcbeeProgs<'_>,
        enabled: bool,
        btf: &mut KernelBtf,
    ) -> Result<(), EBPFRunnerError> {
        progs.cubic_cong_control.set_autoload(enabled);
        progs.cubic_cwnd_event.set_autoload(enabled);
        if !enabled || !btf.available() {
            return Ok(());
        }
        if !btf.has_func(Some(MODULE), CONG_AVOID) {
            return Err(EBPFRunnerError::Unavailable(format!(
                "Kernel function {} not found, is {} loaded?",
                CONG_AVOID, MODULE
            )));
        }
        retarget(&mut progs.cubic_cwnd_event, btf, Some(MODULE), &CWND_EVENT)?;
        Ok(())
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        // For Algo Update
        attach(&skel.progs.cubic_cong_control, links)?;
        // For Congestion Event, unless the kernel has no such function
        if skel.progs.cubic_cwnd_event.autoload() {
            attach(&skel.progs.cubic_cwnd_event, links)?;
        }

        // Both programs write to the same map
        writer.register::<cubic_trace_entry>(
            RB_CUBIC,
            handle(&skel.maps.CUBIC_EVENTS)?,
            prepend_string(cubic_trace_entry::FILE.to_string(), dir),
        )?;

        Ok(())
    }
}
