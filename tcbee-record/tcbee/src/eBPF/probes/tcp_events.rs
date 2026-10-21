use std::error::Error;

use libbpf_rs::{skel::Skel, Link, OpenObject};
use log::warn;
use tcbee_common::{records::tcp_event_entry, stats::RB_TCP_EVENTS};

use crate::{
    eBPF::{host::KernelBtf, probes::attach, rings, skel::TcbeeSkel},
    writer::Writer,
};

/// Where a TCP event program attaches
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Tracepoint(&'static str),
    Function(&'static str),
}

/// A TCP event program and the hook it records
#[derive(Clone, Copy, Debug)]
pub struct TcpEventHook {
    /// One program per hook, a slice so that it can serve as an optional group's programs
    pub programs: &'static [&'static str],
    pub target: Target,
    /// Name for messages and the run metadata
    pub name: &'static str,
    /// Recorded with `--drops` instead of `-e`
    pub drops: bool,
}

const fn hook(
    programs: &'static [&'static str],
    target: Target,
    name: &'static str,
) -> TcpEventHook {
    TcpEventHook {
        programs,
        target,
        name,
        drops: false,
    }
}

/// The programs of `-e` and `--drops`. Each one is optional on its own
/// (`OptionalGroup::TcpEvent`).
pub const TCP_EVENT_HOOKS: [TcpEventHook; 8] = [
    hook(
        &["tcp_event_retransmit"],
        Target::Tracepoint("tcp_retransmit_skb"),
        "TCP retransmissions",
    ),
    hook(
        &["tcp_event_rst_sent"],
        Target::Tracepoint("tcp_send_reset"),
        "TCP RSTs sent",
    ),
    hook(
        &["tcp_event_rst_received"],
        Target::Tracepoint("tcp_receive_reset"),
        "TCP RSTs received",
    ),
    hook(
        &["tcp_event_state"],
        Target::Tracepoint("inet_sock_set_state"),
        "TCP state changes",
    ),
    hook(
        &["tcp_event_ca_state"],
        Target::Tracepoint("tcp_cong_state_set"),
        "TCP congestion state changes",
    ),
    hook(
        &["tcp_event_rto"],
        Target::Function("tcp_enter_loss"),
        "TCP retransmission timeouts",
    ),
    hook(
        &["tcp_event_cwr"],
        Target::Function("tcp_enter_cwr"),
        "TCP window reductions (CWR)",
    ),
    TcpEventHook {
        drops: true,
        ..hook(
            &["tcp_event_drop"],
            Target::Tracepoint("kfree_skb"),
            "TCP packet drops",
        )
    },
];

/// Index of the hook running `program`
const fn hook_index(program: &str) -> usize {
    let mut i = 0;
    while i < TCP_EVENT_HOOKS.len() {
        let name = TCP_EVENT_HOOKS[i].programs[0].as_bytes();
        let wanted = program.as_bytes();
        if name.len() == wanted.len() {
            let mut j = 0;
            while j < name.len() && name[j] == wanted[j] {
                j += 1;
            }
            if j == name.len() {
                return i;
            }
        }
        i += 1;
    }
    panic!("no such TCP event program");
}

/// The congestion state changes include the CWR state; tcp_enter_cwr is their fallback
const CA_STATE_HOOK: usize = hook_index("tcp_event_ca_state");
const CWR_HOOK: usize = hook_index("tcp_event_cwr");

/// Which hooks to load, given which ones exist in the kernel and which ones the kernel
/// rejected (`disabled`), and a message for each requested hook that the kernel lacks
fn hooks_to_load(
    events: bool,
    drops: bool,
    exists: &[bool],
    disabled: &[usize],
) -> (Vec<bool>, Vec<String>) {
    let requested = |hook: &TcpEventHook| if hook.drops { drops } else { events };
    let mut skipped = Vec::new();
    for (i, hook) in TCP_EVENT_HOOKS.iter().enumerate() {
        if !requested(hook) || exists[i] {
            continue;
        }
        let target = match hook.target {
            Target::Tracepoint(tp) => format!("tracepoint {tp}"),
            Target::Function(func) => format!("kernel function {func}"),
        };
        if i == CA_STATE_HOOK {
            warn!("The {target} does not exist (before 5.19), only RTOs and CWR are recorded");
            skipped.push(format!(
                "{}: no {target} in this kernel, only RTOs and CWR",
                hook.name
            ));
        } else {
            warn!(
                "The {target} does not exist, {} are not recorded",
                hook.name
            );
            skipped.push(format!("{}: no {target} in this kernel", hook.name));
        }
    }
    let mut load: Vec<bool> = TCP_EVENT_HOOKS
        .iter()
        .enumerate()
        .map(|(i, hook)| requested(hook) && exists[i] && !disabled.contains(&i))
        .collect();
    if load[CA_STATE_HOOK] {
        load[CWR_HOOK] = false;
    }
    (load, skipped)
}

pub struct TcpEventTracer {}

impl TcpEventTracer {
    /// Loads the programs of the requested hooks (`-e` events, `--drops`) that exist in the
    /// kernel and are not in `disabled`. Returns the indices of the loaded hooks and a message
    /// for each requested hook that is left out.
    pub fn configure(
        object: &mut OpenObject,
        events: bool,
        drops: bool,
        disabled: &[usize],
        btf: &mut KernelBtf,
    ) -> (Vec<usize>, Vec<String>) {
        let check = (events || drops) && btf.available();
        let exists: Vec<bool> = TCP_EVENT_HOOKS
            .iter()
            .map(|hook| {
                !check
                    || match hook.target {
                        Target::Tracepoint(tp) => btf.has_tracepoint(tp),
                        Target::Function(func) => btf.has_func(None, func),
                    }
            })
            .collect();
        let (load, skipped) = hooks_to_load(events, drops, &exists, disabled);
        for mut program in object.progs_mut() {
            let name = program.name().to_string_lossy();
            if let Some(i) = TCP_EVENT_HOOKS
                .iter()
                .position(|hook| hook.programs.contains(&name.as_ref()))
            {
                program.set_autoload(load[i]);
            }
        }
        let loaded = (0..load.len()).filter(|i| load[*i]).collect();
        (loaded, skipped)
    }

    /// Attaches the loaded programs. A program that does not attach is left out with a
    /// warning, like one the kernel lacks; returns its hook index and a message for each.
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<Vec<(usize, String)>, Box<dyn Error>> {
        let mut failed = Vec::new();
        for program in skel.object().progs_mut() {
            let name = program.name().to_string_lossy();
            let Some(i) = TCP_EVENT_HOOKS
                .iter()
                .position(|hook| hook.programs.contains(&name.as_ref()))
            else {
                continue;
            };
            if !program.autoload() {
                continue;
            }
            if let Err(err) = attach(&program, links) {
                let hook = &TCP_EVENT_HOOKS[i];
                warn!("{}, {} are not recorded", err, hook.name);
                failed.push((i, format!("{}: attaching failed: {}", hook.name, err)));
            }
        }
        writer.register::<tcp_event_entry>(
            RB_TCP_EVENTS,
            rings::of(&skel.maps.TCP_EVENTS)?,
            dir,
        )?;
        Ok(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [bool; TCP_EVENT_HOOKS.len()] = [true; TCP_EVENT_HOOKS.len()];

    fn loaded(load: &[bool]) -> Vec<&'static str> {
        (0..load.len())
            .filter(|i| load[*i])
            .map(|i| TCP_EVENT_HOOKS[i].programs[0])
            .collect()
    }

    #[test]
    fn congestion_state_changes_replace_cwr() {
        let (load, skipped) = hooks_to_load(true, false, &ALL, &[]);
        let names = loaded(&load);
        assert!(names.contains(&"tcp_event_ca_state"));
        assert!(!names.contains(&"tcp_event_cwr"));
        assert!(!names.contains(&"tcp_event_drop"));
        assert!(skipped.is_empty());
    }

    #[test]
    fn cwr_is_the_fallback_when_congestion_states_are_missing_or_rejected() {
        let mut exists = ALL;
        exists[CA_STATE_HOOK] = false;
        let (load, skipped) = hooks_to_load(true, false, &exists, &[]);
        assert!(loaded(&load).contains(&"tcp_event_cwr"));
        assert_eq!(skipped.len(), 1);

        let (load, _) = hooks_to_load(true, false, &ALL, &[CA_STATE_HOOK]);
        let names = loaded(&load);
        assert!(names.contains(&"tcp_event_cwr"));
        assert!(!names.contains(&"tcp_event_ca_state"));
    }

    #[test]
    fn drops_alone_load_only_the_drop_hook() {
        let (load, _) = hooks_to_load(false, true, &ALL, &[]);
        assert_eq!(loaded(&load), ["tcp_event_drop"]);
        let (load, skipped) = hooks_to_load(false, false, &[false; TCP_EVENT_HOOKS.len()], &[]);
        assert!(loaded(&load).is_empty());
        assert!(skipped.is_empty());
    }
}
