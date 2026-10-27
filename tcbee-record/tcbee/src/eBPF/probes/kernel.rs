use std::error::Error;

use libbpf_rs::Link;
use tcbee_common::records::sock_trace_entry;
use tcbee_trace::{
    sock_hooks::{Hook, HookSet},
    TraceFile,
};

use tcbee_common::stats::{RB_SOCK_INGRESS, RB_SOCK_RECV, RB_SOCK_SEND, RB_SOCK_TIMER};

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
    /// Whether the write timer program of the default mode loads: with -k, not in on-change
    /// mode (it has its own timer hook), not switched off or disabled after a failed load,
    /// and only if the kernel has the function (`has_target`, true without BTF to check)
    pub fn timer_hook(
        enabled: bool,
        on_change: Option<HookSet>,
        wanted: bool,
        has_target: bool,
    ) -> bool {
        enabled && on_change.is_none() && wanted && has_target
    }

    /// The on-change programs of the hooks in `on_change` replace the default ones, which
    /// load for the hooks in `full`. `timer` loads the write timer program of the default
    /// mode, see `timer_hook`.
    pub fn configure(
        progs: &mut OpenTcbeeProgs<'_>,
        enabled: bool,
        on_change: Option<HookSet>,
        full: Option<HookSet>,
        timer: bool,
    ) {
        let hooked = |hook| enabled && on_change.is_some_and(|h| h.contains(hook));
        let full_hooked =
            |hook| enabled && on_change.is_none() && full.is_some_and(|h| h.contains(hook));
        progs.sock_sendmsg.set_autoload(full_hooked(Hook::Egress));
        progs
            .sock_recvmsg
            .set_autoload(full_hooked(Hook::IngressEntry));
        progs.sock_ingress.set_autoload(full_hooked(Hook::Ingress));
        progs
            .sock_ingress_state
            .set_autoload(full_hooked(Hook::Ingress));
        progs.sock_timer.set_autoload(timer);
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
        full: Option<HookSet>,
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
                let full_hooked = |hook| full.is_some_and(|h| h.contains(hook));
                let mut files = (None, None);
                if full_hooked(Hook::Egress) {
                    attach(&skel.progs.sock_sendmsg, links)?;
                    files.0 = Some(TraceFile::SendSock);
                }
                if full_hooked(Hook::IngressEntry) {
                    attach(&skel.progs.sock_recvmsg, links)?;
                    files.1 = Some(TraceFile::RecvSock);
                }
                // After each received segment, into its own file
                if full_hooked(Hook::Ingress) {
                    attach(&skel.progs.sock_ingress, links)?;
                    attach(&skel.progs.sock_ingress_state, links)?;
                    writer.register_as::<sock_trace_entry>(
                        RB_SOCK_INGRESS,
                        rings::of(&skel.maps.TCP_INGRESS_SOCK_EVENTS)?,
                        TraceFile::IngressSock,
                        dir,
                    )?;
                }
                files
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

    /// The write timer program and its writer. Started after all other writers, so that
    /// they keep their place in the writer CPU rotation.
    pub fn spawn_timer(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        attach(&skel.progs.sock_timer, links)?;
        writer.register_as::<sock_trace_entry>(
            RB_SOCK_TIMER,
            rings::of(&skel.maps.TCP_TIMER_SOCK_EVENTS)?,
            TraceFile::TimerSock,
            dir,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use libbpf_rs::skel::{OpenSkel, SkelBuilder};

    use super::*;
    use crate::eBPF::skel::TcbeeSkelBuilder;

    #[test]
    fn timer_hook_only_in_the_default_mode_of_k() {
        let on_change = Some(HookSet::ON_CHANGE_DEFAULT);
        assert!(KernelTracer::timer_hook(true, None, true, true));
        assert!(!KernelTracer::timer_hook(false, None, true, true));
        assert!(!KernelTracer::timer_hook(true, on_change, true, true));
        assert!(!KernelTracer::timer_hook(true, None, false, true));
        assert!(!KernelTracer::timer_hook(true, None, true, false));
    }

    #[test]
    fn on_change_mode_loads_only_its_own_timer_program() {
        let mut storage = MaybeUninit::uninit();
        let mut open = TcbeeSkelBuilder::default().open(&mut storage).unwrap();
        let full = HookSet::of(&[Hook::Egress, Hook::IngressEntry, Hook::Timer]);
        KernelTracer::configure(&mut open.progs, true, None, Some(full), true);
        assert!(open.progs.sock_timer.autoload());
        assert!(!open.progs.sock_oc_timer.autoload());
        KernelTracer::configure(&mut open.progs, true, None, Some(full), false);
        assert!(!open.progs.sock_timer.autoload());
        assert!(open.progs.sock_recvmsg.autoload());
        let timer = KernelTracer::timer_hook(true, Some(HookSet::ON_CHANGE_DEFAULT), true, true);
        KernelTracer::configure(
            &mut open.progs,
            true,
            Some(HookSet::ON_CHANGE_DEFAULT),
            Some(full),
            timer,
        );
        assert!(!open.progs.sock_timer.autoload());
        assert!(open.progs.sock_oc_timer.autoload());
        assert!(!open.progs.sock_recvmsg.autoload());
    }

    #[test]
    fn sock_hooks_pick_the_default_programs() {
        let mut storage = MaybeUninit::uninit();
        let mut open = TcbeeSkelBuilder::default().open(&mut storage).unwrap();
        let hooks = Some(HookSet::of(&[Hook::IngressEntry]));
        KernelTracer::configure(&mut open.progs, true, None, hooks, false);
        assert!(open.progs.sock_recvmsg.autoload());
        assert!(!open.progs.sock_sendmsg.autoload());
        assert!(!open.progs.sock_oc_recvmsg.autoload());
        assert!(!open.progs.sock_ingress.autoload());
        let hooks = Some(HookSet::of(&[Hook::Ingress]));
        KernelTracer::configure(&mut open.progs, true, None, hooks, false);
        assert!(open.progs.sock_ingress.autoload() && open.progs.sock_ingress_state.autoload());
        assert!(!open.progs.sock_recvmsg.autoload() && !open.progs.sock_oc_recvmsg.autoload());
        KernelTracer::configure(
            &mut open.progs,
            true,
            Some(HookSet::ON_CHANGE_DEFAULT),
            None,
            false,
        );
        assert!(!open.progs.sock_ingress.autoload());
    }
}
