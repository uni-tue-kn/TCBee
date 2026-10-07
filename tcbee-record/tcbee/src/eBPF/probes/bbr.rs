use std::error::Error;

use libbpf_rs::Link;
use log::error;
use tcbee_common::{prog_bindings::TraceProbe, records::bbr_trace_entry};

use tcbee_common::stats::RB_BBR;

use crate::{
    eBPF::{
        ebpf_runner::prepend_string,
        host::KernelBtf,
        probes::{attach, retarget},
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

const MODULE: &str = "tcp_bbr";
const MAIN: &str = "bbr_main";
/// Renamed in kernel 7.2
const CWND_EVENT: [&str; 2] = ["bbr_cwnd_event", "bbr_cwnd_event_tx_start"];

pub struct BBRTracer {}

impl BBRTracer {
    /// The fentry targets only exist while tcp_bbr is loaded (or built in). Without them
    /// the whole object would fail to load, so BBR is disabled with an error message
    /// instead. Returns whether BBR is enabled.
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool, btf: &mut KernelBtf) -> bool {
        Self::set_autoload(progs, enabled);
        if !enabled || !btf.available() {
            return enabled;
        }
        if !btf.has_func(Some(MODULE), MAIN) {
            error!(
                "Failed to initialize BBR Tracer. Is the kernel module loaded? ({} not found)",
                MAIN
            );
            Self::set_autoload(progs, false);
            return false;
        }
        match retarget(&mut progs.bbr_cwnd_event, btf, Some(MODULE), &CWND_EVENT) {
            Ok(_) => true,
            Err(err) => {
                error!("Failed to initialize BBR Tracer: {}", err);
                Self::set_autoload(progs, false);
                false
            }
        }
    }

    fn set_autoload(progs: &mut OpenTcbeeProgs<'_>, enabled: bool) {
        progs.bbr_cong_control.set_autoload(enabled);
        progs.bbr_cwnd_event.set_autoload(enabled);
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        // For Algo Update, fentry/bbr_main
        attach(&skel.progs.bbr_cong_control, links)?;
        // For Congestion Event, unless the kernel has no such function
        if skel.progs.bbr_cwnd_event.autoload() {
            attach(&skel.progs.bbr_cwnd_event, links)?;
        }

        // Both programs write to the same map
        writer.register::<bbr_trace_entry>(
            RB_BBR,
            rings::of(&skel.maps.BBR_EVENTS)?,
            prepend_string(bbr_trace_entry::FILE.to_string(), dir),
        )?;

        Ok(())
    }
}
