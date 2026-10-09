use std::error::Error;

use libbpf_rs::Link;
use tcbee_common::{prog_bindings::TraceInoutProbe, records::cwnd_trace_entry};

use tcbee_common::stats::{RB_CWND_RECV, RB_CWND_SEND};

use crate::{
    eBPF::{
        ebpf_runner::prepend_string,
        probes::attach,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct CwndTracer {}

impl CwndTracer {
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool) {
        progs.cwnd_sock_sendmsg.set_autoload(enabled);
        progs.cwnd_sock_recvmsg.set_autoload(enabled);
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        // Outgoing TCP, fentry/__tcp_transmit_skb
        attach(&skel.progs.cwnd_sock_sendmsg, links)?;
        // Incoming TCP, fentry/tcp_rcv_established
        attach(&skel.progs.cwnd_sock_recvmsg, links)?;

        writer.register::<cwnd_trace_entry>(
            RB_CWND_SEND,
            rings::of(&skel.maps.TCP_SEND_CWND_EVENTS)?,
            prepend_string(cwnd_trace_entry::OUT_FILE.to_string(), dir),
        )?;
        writer.register::<cwnd_trace_entry>(
            RB_CWND_RECV,
            rings::of(&skel.maps.TCP_RECEIVE_CWND_EVENTS)?,
            prepend_string(cwnd_trace_entry::IN_FILE.to_string(), dir),
        )?;

        Ok(())
    }
}
