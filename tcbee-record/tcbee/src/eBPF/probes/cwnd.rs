use std::error::Error;

use libbpf_rs::Link;
use tcbee_common::records::cwnd_trace_entry;
use tcbee_trace::{
    onchange::{Hook, HookSet},
    TraceFile,
};

use tcbee_common::stats::{RB_CWND_RECV, RB_CWND_SEND};

use crate::{
    eBPF::{
        probes::{attach, attach_on_change},
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct CwndTracer {}

impl CwndTracer {
    /// The on-change programs of the hooks in `on_change` replace the default ones
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool, on_change: Option<HookSet>) {
        let hooked = |hook| enabled && on_change.is_some_and(|h| h.contains(hook));
        progs
            .cwnd_sock_sendmsg
            .set_autoload(enabled && on_change.is_none());
        progs
            .cwnd_sock_recvmsg
            .set_autoload(enabled && on_change.is_none());
        progs.cwnd_oc_sendmsg.set_autoload(hooked(Hook::Egress));
        progs.cwnd_oc_recvmsg.set_autoload(hooked(Hook::Ingress));
        progs.cwnd_oc_rcv_state.set_autoload(hooked(Hook::Ingress));
        progs.cwnd_oc_timer.set_autoload(hooked(Hook::Timer));
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
        on_change: Option<HookSet>,
    ) -> Result<(), Box<dyn Error>> {
        let (send, receive) = match on_change {
            // Egress into the send file; ingress and timer into the receive file
            Some(hooks) => attach_on_change(
                hooks,
                &[
                    (Hook::Egress, &skel.progs.cwnd_oc_sendmsg),
                    (Hook::Ingress, &skel.progs.cwnd_oc_recvmsg),
                    (Hook::Ingress, &skel.progs.cwnd_oc_rcv_state),
                    (Hook::Timer, &skel.progs.cwnd_oc_timer),
                ],
                links,
                (TraceFile::SendCwndOc, TraceFile::RecvCwndOc),
            )?,
            None => {
                // Outgoing TCP, fentry/__tcp_transmit_skb; incoming, fentry/tcp_rcv_established
                attach(&skel.progs.cwnd_sock_sendmsg, links)?;
                attach(&skel.progs.cwnd_sock_recvmsg, links)?;
                (Some(TraceFile::SendCwnd), Some(TraceFile::RecvCwnd))
            }
        };

        if let Some(file) = send {
            writer.register_as::<cwnd_trace_entry>(
                RB_CWND_SEND,
                rings::of(&skel.maps.TCP_SEND_CWND_EVENTS)?,
                file,
                dir,
            )?;
        }
        if let Some(file) = receive {
            writer.register_as::<cwnd_trace_entry>(
                RB_CWND_RECV,
                rings::of(&skel.maps.TCP_RECEIVE_CWND_EVENTS)?,
                file,
                dir,
            )?;
        }

        Ok(())
    }
}
