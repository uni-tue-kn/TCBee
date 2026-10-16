use std::error::Error;

use libbpf_rs::Link;
use tcbee_common::records::sock_trace_entry;
use tcbee_trace::{
    onchange::{Hook, HookSet},
    TraceFile,
};

use tcbee_common::stats::{RB_SOCK_RECV, RB_SOCK_SEND};

use crate::{
    eBPF::{
        probes::{attach, attach_on_change},
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct KernelTracer {}

impl KernelTracer {
    /// The on-change programs of the hooks in `on_change` replace the default ones
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool, on_change: Option<HookSet>) {
        let hooked = |hook| enabled && on_change.is_some_and(|h| h.contains(hook));
        progs
            .sock_sendmsg
            .set_autoload(enabled && on_change.is_none());
        progs
            .sock_recvmsg
            .set_autoload(enabled && on_change.is_none());
        progs.sock_oc_sendmsg.set_autoload(hooked(Hook::Egress));
        progs.sock_oc_recvmsg.set_autoload(hooked(Hook::Ingress));
        progs.sock_oc_rcv_state.set_autoload(hooked(Hook::Ingress));
        progs.sock_oc_timer.set_autoload(hooked(Hook::Timer));
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
                    (Hook::Egress, &skel.progs.sock_oc_sendmsg),
                    (Hook::Ingress, &skel.progs.sock_oc_recvmsg),
                    (Hook::Ingress, &skel.progs.sock_oc_rcv_state),
                    (Hook::Timer, &skel.progs.sock_oc_timer),
                ],
                links,
                (TraceFile::SendSockOc, TraceFile::RecvSockOc),
            )?,
            None => {
                // Outgoing TCP, fentry/__tcp_transmit_skb; incoming, fentry/tcp_rcv_established
                attach(&skel.progs.sock_sendmsg, links)?;
                attach(&skel.progs.sock_recvmsg, links)?;
                (Some(TraceFile::SendSock), Some(TraceFile::RecvSock))
            }
        };

        if let Some(file) = send {
            writer.register_as::<sock_trace_entry>(
                RB_SOCK_SEND,
                rings::of(&skel.maps.TCP_SEND_SOCK_EVENTS)?,
                file,
                dir,
            )?;
        }
        if let Some(file) = receive {
            writer.register_as::<sock_trace_entry>(
                RB_SOCK_RECV,
                rings::of(&skel.maps.TCP_RECV_SOCK_EVENTS)?,
                file,
                dir,
            )?;
        }

        Ok(())
    }
}
