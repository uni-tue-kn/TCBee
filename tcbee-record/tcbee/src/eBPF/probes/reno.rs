use std::error::Error;

use libbpf_rs::Link;
use log::warn;
use tcbee_common::{records::reno_trace_entry, stats::RB_RENO};

use crate::{
    eBPF::{
        host::KernelBtf,
        probes::attach,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

/// Exported by the kernel and called through the congestion control operations of Reno and
/// other algorithms, so they are not inlined away
const CONG_AVOID: &str = "tcp_reno_cong_avoid";
const SSTHRESH: &str = "tcp_reno_ssthresh";

pub struct RenoTracer {}

impl RenoTracer {
    /// The Reno hooks of -a are optional as a group (`OptionalGroup::Reno`). Returns whether
    /// they load, or the message why not.
    pub fn configure(
        progs: &mut OpenTcbeeProgs<'_>,
        enabled: bool,
        btf: &mut KernelBtf,
    ) -> Result<bool, String> {
        Self::set_autoload(progs, false);
        if !enabled {
            return Ok(false);
        }
        if btf.available() {
            if let Some(func) = [CONG_AVOID, SSTHRESH]
                .into_iter()
                .find(|func| !btf.has_func(None, func))
            {
                warn!(
                    "The kernel function {} does not exist, Reno is not recorded",
                    func
                );
                return Err(format!("Reno: no kernel function {}", func));
            }
        }
        Self::set_autoload(progs, true);
        Ok(true)
    }

    fn set_autoload(progs: &mut OpenTcbeeProgs<'_>, enabled: bool) {
        progs.reno_cong_avoid.set_autoload(enabled);
        progs.reno_ssthresh.set_autoload(enabled);
    }

    /// Attaches both programs; on an error the caller detaches what was attached
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        attach(&skel.progs.reno_cong_avoid, links)?;
        attach(&skel.progs.reno_ssthresh, links)?;

        // Both programs write to the same map
        writer.register::<reno_trace_entry>(RB_RENO, rings::of(&skel.maps.RENO_EVENTS)?, dir)?;

        Ok(())
    }
}
