use std::error::Error;

use libbpf_rs::{Link, MapMut, ProgramMut};
use serde::Serialize;
use tcbee_common::{
    prog_bindings::TracePointProbe,
    records::{tcp_bad_csum_entry, tcp_probe_entry, tcp_retransmit_synack_entry},
    stats::{RB_BAD_CSUM, RB_RETRANSMIT_SYNACK, RB_TCP_PROBE},
};

use crate::{
    eBPF::{
        ebpf_runner::prepend_string,
        probes::attach,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct TracepointTracer {}

impl TracepointTracer {
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool) {
        progs.tcp_probe.set_autoload(enabled);
        progs.tcp_retransmit_synack.set_autoload(enabled);
        progs.tcp_bad_csum.set_autoload(enabled);
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        let (progs, maps) = (&skel.progs, &skel.maps);
        Self::spawn_one::<tcp_probe_entry>(
            &progs.tcp_probe,
            &maps.TCP_PROBE_QUEUE,
            RB_TCP_PROBE,
            dir,
            writer,
            links,
        )?;
        Self::spawn_one::<tcp_retransmit_synack_entry>(
            &progs.tcp_retransmit_synack,
            &maps.TCP_RETRANSMIT_SYNACK_QUEUE,
            RB_RETRANSMIT_SYNACK,
            dir,
            writer,
            links,
        )?;
        Self::spawn_one::<tcp_bad_csum_entry>(
            &progs.tcp_bad_csum,
            &maps.TCP_BAD_CSUM_QUEUE,
            RB_BAD_CSUM,
            dir,
            writer,
            links,
        )?;
        Ok(())
    }

    // T is passed to determine struct and names for registration
    fn spawn_one<T: TracePointProbe + Serialize + Copy + Send + 'static>(
        program: &ProgramMut<'_>,
        map: &MapMut<'_>,
        rb: u32,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        // Attaches to tracepoint/<T::CATEGORY>/<T::NAME> from the section name
        attach(program, links)?;
        writer.register::<T>(
            rb,
            rings::of(map)?,
            prepend_string(T::FILE.to_string(), dir),
        )?;
        Ok(())
    }
}
