use std::error::Error;

use libbpf_rs::Link;
use tcbee_common::{prog_bindings::TraceInoutProbe, records::sock_trace_entry};

use tcbee_common::stats::{RB_SOCK_RECV, RB_SOCK_SEND};

use crate::{
    eBPF::{
        ebpf_runner::prepend_string,
        probes::{attach, handle},
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct KernelTracer {}

impl KernelTracer {
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool) {
        progs.sock_sendmsg.set_autoload(enabled);
        progs.sock_recvmsg.set_autoload(enabled);
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        // Outgoing TCP, fentry/__tcp_transmit_skb
        attach(&skel.progs.sock_sendmsg, links)?;
        // Incoming TCP, fentry/tcp_rcv_established
        attach(&skel.progs.sock_recvmsg, links)?;

        writer.register::<sock_trace_entry>(
            RB_SOCK_SEND,
            handle(&skel.maps.TCP_SEND_SOCK_EVENTS)?,
            prepend_string(sock_trace_entry::OUT_FILE.to_string(), dir),
        )?;
        writer.register::<sock_trace_entry>(
            RB_SOCK_RECV,
            handle(&skel.maps.TCP_RECV_SOCK_EVENTS)?,
            prepend_string(sock_trace_entry::IN_FILE.to_string(), dir),
        )?;

        Ok(())
    }
}
