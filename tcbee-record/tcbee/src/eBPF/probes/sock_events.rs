use std::error::Error;

use libbpf_rs::{skel::Skel, Link, OpenObject};
use log::warn;
use tcbee_common::{records::sock_trace_entry, stats::RB_SOCK_EVENT};
use tcbee_trace::{
    sock_hooks::{Hook, HookSet},
    TraceFile,
};

use crate::{
    eBPF::{
        host::KernelBtf,
        probes::{attach, tcp_events::Target},
        rings,
        skel::TcbeeSkel,
    },
    writer::Writer,
};

/// A program that records the socket at a TCP event (`-k`, `event_sock.tcp`)
#[derive(Clone, Copy, Debug)]
pub struct SockEventHook {
    pub hook: Hook,
    /// One program per hook, a slice so that it can serve as an optional group's programs
    pub programs: &'static [&'static str],
    pub target: Target,
    /// Name for messages and the run metadata
    pub name: &'static str,
}

/// The socket event programs, in the order of `Hook::SOCK_EVENTS`. Each one is optional on
/// its own (`OptionalGroup::SockEvent`).
pub const SOCK_EVENT_HOOKS: [SockEventHook; 5] = [
    SockEventHook {
        hook: Hook::State,
        programs: &["sock_event_state"],
        target: Target::Tracepoint("inet_sock_set_state"),
        name: "socket at TCP state changes",
    },
    SockEventHook {
        hook: Hook::CaState,
        programs: &["sock_event_ca_state"],
        target: Target::Tracepoint("tcp_cong_state_set"),
        name: "socket at congestion state changes",
    },
    SockEventHook {
        hook: Hook::Retransmit,
        programs: &["sock_event_retransmit"],
        target: Target::Tracepoint("tcp_retransmit_skb"),
        name: "socket at retransmissions",
    },
    SockEventHook {
        hook: Hook::Restart,
        programs: &["sock_event_restart"],
        target: Target::Function("tcp_cwnd_restart"),
        name: "socket at cwnd restarts after idle",
    },
    SockEventHook {
        hook: Hook::Rcvbuf,
        programs: &["sock_event_rcvbuf"],
        target: Target::Tracepoint("tcp_rcvbuf_grow"),
        name: "socket at receive buffer growth",
    },
];

/// Which hooks to load: those in `hooks` that exist in the kernel and are not `disabled`,
/// with a message for each one in `hooks` that the kernel lacks. None loads nothing.
fn hooks_to_load(
    hooks: Option<HookSet>,
    exists: &[bool],
    disabled: &[usize],
) -> (Vec<bool>, Vec<String>) {
    let wanted = |hook| hooks.is_some_and(|h| h.contains(hook));
    let mut skipped = Vec::new();
    let load = SOCK_EVENT_HOOKS
        .iter()
        .enumerate()
        .map(|(i, event)| {
            if !wanted(event.hook) {
                return false;
            }
            if !exists[i] {
                let target = match event.target {
                    Target::Tracepoint(tp) => format!("tracepoint {tp}"),
                    Target::Function(func) => format!("kernel function {func}"),
                };
                warn!(
                    "The {target} does not exist, the {} is not recorded",
                    event.name
                );
                skipped.push(format!("{}: no {target} in this kernel", event.name));
                return false;
            }
            !disabled.contains(&i)
        })
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
        disabled: &[usize],
        btf: &mut KernelBtf,
    ) -> (Vec<usize>, Vec<String>) {
        let check = btf.available();
        let exists: Vec<bool> = SOCK_EVENT_HOOKS
            .iter()
            .map(|event| {
                !check
                    || !hooks.is_some_and(|h| h.contains(event.hook))
                    || match event.target {
                        Target::Tracepoint(tp) => btf.has_tracepoint(tp),
                        Target::Function(func) => btf.has_func(None, func),
                    }
            })
            .collect();
        let (load, skipped) = hooks_to_load(hooks, &exists, disabled);
        for mut program in object.progs_mut() {
            let name = program.name().to_string_lossy();
            if let Some(i) = SOCK_EVENT_HOOKS
                .iter()
                .position(|event| event.programs.contains(&name.as_ref()))
            {
                program.set_autoload(load[i]);
            }
        }
        let loaded = (0..load.len()).filter(|i| load[*i]).collect();
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
        let mut failed = Vec::new();
        let mut attached = 0;
        for program in skel.object().progs_mut() {
            let name = program.name().to_string_lossy();
            let Some(i) = SOCK_EVENT_HOOKS
                .iter()
                .position(|event| event.programs.contains(&name.as_ref()))
            else {
                continue;
            };
            if !program.autoload() {
                continue;
            }
            match attach(&program, links) {
                Ok(()) => attached += 1,
                Err(err) => {
                    let event = &SOCK_EVENT_HOOKS[i];
                    warn!("{}, the {} is not recorded", err, event.name);
                    failed.push((i, format!("{}: attaching failed: {}", event.name, err)));
                }
            }
        }
        if attached == 0 {
            return Ok(failed);
        }
        writer.register_as::<sock_trace_entry>(
            RB_SOCK_EVENT,
            rings::of(&skel.maps.TCP_EVENT_SOCK_EVENTS)?,
            TraceFile::EventSock,
            dir,
        )?;
        Ok(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [bool; SOCK_EVENT_HOOKS.len()] = [true; SOCK_EVENT_HOOKS.len()];

    #[test]
    fn hooks_follow_the_order_of_the_socket_events() {
        let hooks: Vec<Hook> = SOCK_EVENT_HOOKS.iter().map(|event| event.hook).collect();
        assert_eq!(hooks, Hook::SOCK_EVENTS);
    }

    #[test]
    fn only_requested_and_existing_hooks_load() {
        let hooks = HookSet::of(&[Hook::State, Hook::Rcvbuf, Hook::Timer]);
        let mut exists = ALL;
        exists[4] = false;
        let (load, skipped) = hooks_to_load(Some(hooks), &exists, &[]);
        assert_eq!(load, [true, false, false, false, false]);
        assert_eq!(skipped.len(), 1);
        let (load, skipped) = hooks_to_load(Some(hooks), &ALL, &[0]);
        assert_eq!(load, [false, false, false, false, true]);
        assert!(skipped.is_empty());
        let (load, skipped) = hooks_to_load(None, &[false; SOCK_EVENT_HOOKS.len()], &[]);
        assert_eq!(load, [false; SOCK_EVENT_HOOKS.len()]);
        assert!(skipped.is_empty());
    }
}
