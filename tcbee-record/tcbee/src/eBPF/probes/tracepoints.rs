use std::error::Error;

use libbpf_rs::{Link, MapMut, ProgramMut};
use serde::Serialize;
use tcbee_common::{
    records::{tcp_bad_csum_entry, tcp_probe_entry, tcp_retransmit_synack_entry},
    stats::{RB_BAD_CSUM, RB_RETRANSMIT_SYNACK, RB_TCP_PROBE},
};

use crate::{
    eBPF::{
        ebpf_runner_config::TracepointSet,
        probes::attach,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

/// The classic tracepoints of `-t`; the other ones are TCP event hooks
pub struct TracepointTracer {}

impl TracepointTracer {
    /// The `--tp` names of this tracer's programs
    pub const NAMES: [&'static str; 3] = ["probe", "synack", "bad_csum"];

    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, set: TracepointSet) {
        progs.tcp_probe.set_autoload(set.contains("probe"));
        progs
            .tcp_retransmit_synack
            .set_autoload(set.contains("synack"));
        progs.tcp_bad_csum.set_autoload(set.contains("bad_csum"));
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        set: TracepointSet,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        let (progs, maps) = (&skel.progs, &skel.maps);
        if set.contains("probe") {
            Self::spawn_one::<tcp_probe_entry>(
                &progs.tcp_probe,
                &maps.TCP_PROBE_QUEUE,
                RB_TCP_PROBE,
                dir,
                writer,
                links,
            )?;
        }
        if set.contains("synack") {
            Self::spawn_one::<tcp_retransmit_synack_entry>(
                &progs.tcp_retransmit_synack,
                &maps.TCP_RETRANSMIT_SYNACK_QUEUE,
                RB_RETRANSMIT_SYNACK,
                dir,
                writer,
                links,
            )?;
        }
        if set.contains("bad_csum") {
            Self::spawn_one::<tcp_bad_csum_entry>(
                &progs.tcp_bad_csum,
                &maps.TCP_BAD_CSUM_QUEUE,
                RB_BAD_CSUM,
                dir,
                writer,
                links,
            )?;
        }
        Ok(())
    }

    // T is the record type of the ring buffer
    fn spawn_one<T: Serialize + Copy + Send + 'static>(
        program: &ProgramMut<'_>,
        map: &MapMut<'_>,
        rb: u32,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        // Attaches to the tracepoint named in the program's section
        attach(program, links)?;
        writer.register::<T>(rb, rings::of(map)?, dir)?;
        Ok(())
    }
}
