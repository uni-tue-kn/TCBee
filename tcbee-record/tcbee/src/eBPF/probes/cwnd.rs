use std::error::Error;

use libbpf_rs::Link;
use tcbee_common::records::cwnd_trace_entry;
use tcbee_trace::TraceFile;

use tcbee_common::stats::{RB_CWND_RECV, RB_CWND_SEND};

use crate::{
    eBPF::{
        probes::attach,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct CwndTracer {}

impl CwndTracer {
    /// The on-change programs replace the default ones in on-change mode
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool, on_change: bool) {
        progs.cwnd_sock_sendmsg.set_autoload(enabled && !on_change);
        progs.cwnd_sock_recvmsg.set_autoload(enabled && !on_change);
        progs.cwnd_oc_sendmsg.set_autoload(enabled && on_change);
        progs.cwnd_oc_recvmsg.set_autoload(enabled && on_change);
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
            attach(&skel.progs.cwnd_oc_sendmsg, links)?;
            attach(&skel.progs.cwnd_oc_recvmsg, links)?;
            (TraceFile::SendCwndOc, TraceFile::RecvCwndOc)
        } else {
            // Outgoing TCP, fentry/__tcp_transmit_skb; incoming, fentry/tcp_rcv_established
            attach(&skel.progs.cwnd_sock_sendmsg, links)?;
            attach(&skel.progs.cwnd_sock_recvmsg, links)?;
            (TraceFile::SendCwnd, TraceFile::RecvCwnd)
        };

        writer.register_as::<cwnd_trace_entry>(
            RB_CWND_SEND,
            rings::of(&skel.maps.TCP_SEND_CWND_EVENTS)?,
            out_file,
            dir,
        )?;
        writer.register_as::<cwnd_trace_entry>(
            RB_CWND_RECV,
            rings::of(&skel.maps.TCP_RECEIVE_CWND_EVENTS)?,
            in_file,
            dir,
        )?;

        Ok(())
    }
}
