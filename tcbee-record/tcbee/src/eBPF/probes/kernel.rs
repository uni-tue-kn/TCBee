use std::error::Error;

use libbpf_rs::Link;
use tcbee_common::records::sock_trace_entry;
use tcbee_trace::TraceFile;

use tcbee_common::stats::{RB_SOCK_RECV, RB_SOCK_SEND};

use crate::{
    eBPF::{
        probes::attach,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct KernelTracer {}

impl KernelTracer {
    /// The on-change programs replace the default ones in on-change mode
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool, on_change: bool) {
        progs.sock_sendmsg.set_autoload(enabled && !on_change);
        progs.sock_recvmsg.set_autoload(enabled && !on_change);
        progs.sock_oc_sendmsg.set_autoload(enabled && on_change);
        progs.sock_oc_recvmsg.set_autoload(enabled && on_change);
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
        on_change: bool,
    ) -> Result<(), Box<dyn Error>> {
        let (out_file, in_file) = if on_change {
            // Outgoing TCP, fentry/__tcp_transmit_skb; incoming, fexit/tcp_rcv_established
            attach(&skel.progs.sock_oc_sendmsg, links)?;
            attach(&skel.progs.sock_oc_recvmsg, links)?;
            (TraceFile::SendSockOc, TraceFile::RecvSockOc)
        } else {
            // Outgoing TCP, fentry/__tcp_transmit_skb; incoming, fentry/tcp_rcv_established
            attach(&skel.progs.sock_sendmsg, links)?;
            attach(&skel.progs.sock_recvmsg, links)?;
            (TraceFile::SendSock, TraceFile::RecvSock)
        };

        writer.register_as::<sock_trace_entry>(
            RB_SOCK_SEND,
            rings::of(&skel.maps.TCP_SEND_SOCK_EVENTS)?,
            out_file,
            dir,
        )?;
        writer.register_as::<sock_trace_entry>(
            RB_SOCK_RECV,
            rings::of(&skel.maps.TCP_RECV_SOCK_EVENTS)?,
            in_file,
            dir,
        )?;

        Ok(())
    }
}
