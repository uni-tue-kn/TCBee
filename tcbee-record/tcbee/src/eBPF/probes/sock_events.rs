use std::{collections::BTreeSet, error::Error};

use libbpf_rs::{Link, OpenObject};
use tcbee_common::{records::sock_trace_entry, stats::RB_SOCK_EVENT};
use tcbee_trace::{
    sock_hooks::{Hook, HookSet},
    TraceFile,
};

use crate::{
    eBPF::{
        host::KernelBtf,
        optional::OptionalGroup,
        probes::optional_hooks::{self, OptionalHook, Target},
        rings,
        skel::TcbeeSkel,
    },
    writer::Writer,
};

/// A program that records the socket at a TCP event (`-k`, `event_sock.tcp`), selected by
/// its sock hook
pub type SockEventHook = OptionalHook<Hook>;

/// The socket event programs, in the order of `Hook::SOCK_EVENTS`. Each one is optional on
/// its own (`OptionalGroup::SockEvent`).
pub const SOCK_EVENT_HOOKS: [SockEventHook; 5] = [
    OptionalHook {
        selector: Hook::State,
        programs: &["sock_event_state"],
        target: Target::Tracepoint("inet_sock_set_state"),
        name: "socket at TCP state changes",
    },
    OptionalHook {
        selector: Hook::CaState,
        programs: &["sock_event_ca_state"],
        target: Target::Tracepoint("tcp_cong_state_set"),
        name: "socket at congestion state changes",
    },
    OptionalHook {
        selector: Hook::Retransmit,
        programs: &["sock_event_retransmit"],
        target: Target::Tracepoint("tcp_retransmit_skb"),
        name: "socket at retransmissions",
    },
    OptionalHook {
        selector: Hook::Restart,
        programs: &["sock_event_restart"],
        target: Target::Function("tcp_cwnd_restart"),
        name: "socket at cwnd restarts after idle",
    },
    OptionalHook {
        selector: Hook::Rcvbuf,
        programs: &["sock_event_rcvbuf"],
        target: Target::Tracepoint("tcp_rcvbuf_grow"),
        name: "socket at receive buffer growth",
    },
];

fn not_recorded(name: &str) -> String {
    format!("the {name} is not recorded")
}

/// Which hooks to load: those in `hooks` that exist in the kernel and are not `disabled`,
/// with a message for each one in `hooks` that the kernel lacks. None loads nothing.
fn hooks_to_load(
    hooks: Option<HookSet>,
    exists: &[bool],
    disabled: &BTreeSet<OptionalGroup>,
) -> (Vec<bool>, Vec<String>) {
    let requested = |hook| hooks.is_some_and(|h| h.contains(hook));
    let (load, missing) = optional_hooks::to_load(
        &SOCK_EVENT_HOOKS,
        requested,
        exists,
        disabled,
        OptionalGroup::SockEvent,
    );
    let skipped = missing
        .into_iter()
        .map(|i| optional_hooks::report_missing(&SOCK_EVENT_HOOKS[i], not_recorded))
        .collect();
    (load, skipped)
}

pub struct SockEventTracer {}

impl SockEventTracer {
    /// Loads the programs of the socket event hooks in `hooks` (None without -k or with
    /// on-change) that exist in the kernel and are not in `disabled`. Returns the indices of
    /// the loaded hooks and a message for each requested hook that is left out.
    pub fn configure(
        object: &mut OpenObject,
        hooks: Option<HookSet>,
        disabled: &BTreeSet<OptionalGroup>,
        btf: &mut KernelBtf,
    ) -> (Vec<usize>, Vec<String>) {
        let requested = |hook| hooks.is_some_and(|h| h.contains(hook));
        let exists = optional_hooks::existing(&SOCK_EVENT_HOOKS, requested, btf);
        let (load, skipped) = hooks_to_load(hooks, &exists, disabled);
        let loaded = optional_hooks::set_autoload(&SOCK_EVENT_HOOKS, object, &load);
        (loaded, skipped)
    }

    /// Attaches the loaded programs. A program that does not attach is left out with a
    /// warning, like one the kernel lacks; returns its hook index and a message for each.
    /// Without any attached program the ring gets no writer and no file.
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<Vec<(usize, String)>, Box<dyn Error>> {
        let (attached, failed) =
            optional_hooks::attach_loaded(&SOCK_EVENT_HOOKS, skel, links, not_recorded);
        if attached {
            writer.register_as::<sock_trace_entry>(
                RB_SOCK_EVENT,
                rings::of(&skel.maps.TCP_EVENT_SOCK_EVENTS)?,
                TraceFile::EventSock,
                dir,
            )?;
        }
        Ok(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [bool; SOCK_EVENT_HOOKS.len()] = [true; SOCK_EVENT_HOOKS.len()];

    #[test]
    fn hooks_follow_the_order_of_the_socket_events() {
        let hooks: Vec<Hook> = SOCK_EVENT_HOOKS
            .iter()
            .map(|event| event.selector)
            .collect();
        assert_eq!(hooks, Hook::SOCK_EVENTS);
    }

    #[test]
    fn only_requested_and_existing_hooks_load() {
        let hooks = HookSet::of(&[Hook::State, Hook::Rcvbuf, Hook::Timer]);
        let mut exists = ALL;
        exists[4] = false;
        let none = BTreeSet::new();
        let (load, skipped) = hooks_to_load(Some(hooks), &exists, &none);
        assert_eq!(load, [true, false, false, false, false]);
        assert_eq!(skipped.len(), 1);
        let state = BTreeSet::from([OptionalGroup::SockEvent(0)]);
        let (load, skipped) = hooks_to_load(Some(hooks), &ALL, &state);
        assert_eq!(load, [false, false, false, false, true]);
        assert!(skipped.is_empty());
        let (load, skipped) = hooks_to_load(None, &[false; SOCK_EVENT_HOOKS.len()], &none);
        assert_eq!(load, [false; SOCK_EVENT_HOOKS.len()]);
        assert!(skipped.is_empty());
    }
}
