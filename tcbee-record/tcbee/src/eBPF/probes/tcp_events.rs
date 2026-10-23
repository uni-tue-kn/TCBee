use std::error::Error;

use libbpf_rs::{Link, OpenObject};
use log::warn;
use tcbee_common::{records::tcp_event_entry, stats::RB_TCP_EVENTS};

use crate::{
    eBPF::{
        host::KernelBtf,
        probes::{
            optional_hooks::{self, OptionalHook, Target},
            tracepoints::{Tracepoint, TracepointSet},
        },
        rings,
        skel::TcbeeSkel,
    },
    writer::Writer,
};

/// A TCP event program, selected by its tracepoint of `-t`
pub type TcpEventHook = OptionalHook<Tracepoint>;

const fn hook(
    programs: &'static [&'static str],
    target: Target,
    name: &'static str,
    tracepoint: Tracepoint,
) -> TcpEventHook {
    OptionalHook {
        programs,
        target,
        name,
        selector: tracepoint,
    }
}

/// The TCP event programs of `-t`. Each one is optional on its own
/// (`OptionalGroup::TcpEvent`).
pub const TCP_EVENT_HOOKS: [TcpEventHook; 9] = [
    hook(
        &["tcp_event_retransmit"],
        Target::Tracepoint("tcp_retransmit_skb"),
        "TCP retransmissions",
        Tracepoint::Retransmit,
    ),
    hook(
        &["tcp_event_rst_sent"],
        Target::Tracepoint("tcp_send_reset"),
        "TCP RSTs sent",
        Tracepoint::RstSent,
    ),
    hook(
        &["tcp_event_rst_received"],
        Target::Tracepoint("tcp_receive_reset"),
        "TCP RSTs received",
        Tracepoint::RstReceived,
    ),
    hook(
        &["tcp_event_state"],
        Target::Tracepoint("inet_sock_set_state"),
        "TCP state changes",
        Tracepoint::State,
    ),
    hook(
        &["tcp_event_ca_state"],
        Target::Tracepoint("tcp_cong_state_set"),
        "TCP congestion state changes",
        Tracepoint::CaState,
    ),
    hook(
        &["tcp_event_rto"],
        Target::Function("tcp_enter_loss"),
        "TCP retransmission timeouts",
        Tracepoint::Rto,
    ),
    hook(
        &["tcp_event_cwr"],
        Target::Function("tcp_enter_cwr"),
        "TCP window reductions (CWR)",
        Tracepoint::CaState,
    ),
    hook(
        &["tcp_event_destroy"],
        Target::Tracepoint("tcp_destroy_sock"),
        "TCP sockets destroyed",
        Tracepoint::Destroy,
    ),
    hook(
        &["tcp_event_drop"],
        Target::Tracepoint("kfree_skb"),
        "TCP packet drops",
        Tracepoint::Drops,
    ),
];

fn not_recorded(name: &str) -> String {
    format!("{name} are not recorded")
}

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

/// The congestion state changes include the CWR state; tcp_enter_cwr is their fallback and
/// is selected with them (`Tracepoint::CaState`)
const CA_STATE_HOOK: usize = hook_index("tcp_event_ca_state");
const CWR_HOOK: usize = hook_index("tcp_event_cwr");

/// Which hooks to load, given which ones exist in the kernel and which ones the kernel
/// rejected (`disabled`), and a message for each requested hook that the kernel lacks
fn hooks_to_load(
    set: TracepointSet,
    exists: &[bool],
    disabled: &[usize],
) -> (Vec<bool>, Vec<String>) {
    let requested = |tracepoint| set.contains(tracepoint);
    let (mut load, missing) =
        optional_hooks::to_load(&TCP_EVENT_HOOKS, requested, exists, disabled);
    let skipped = missing
        .into_iter()
        .map(|i| {
            let hook = &TCP_EVENT_HOOKS[i];
            if i != CA_STATE_HOOK {
                return optional_hooks::report_missing(hook, not_recorded);
            }
            let target = hook.target;
            warn!("The {target} does not exist (before 5.19), only RTOs and CWR are recorded");
            format!(
                "{}: no {target} in this kernel, only RTOs and CWR",
                hook.name
            )
        })
        .collect();
    if load[CA_STATE_HOOK] {
        load[CWR_HOOK] = false;
    }
    (load, skipped)
}

pub struct TcpEventTracer {}

impl TcpEventTracer {
    /// Loads the programs of the hooks in `set` that exist in the kernel and are not in
    /// `disabled`. Returns the indices of the loaded hooks and a message for each requested
    /// hook that is left out.
    pub fn configure(
        object: &mut OpenObject,
        set: TracepointSet,
        disabled: &[usize],
        btf: &mut KernelBtf,
    ) -> (Vec<usize>, Vec<String>) {
        let exists = optional_hooks::existing(&TCP_EVENT_HOOKS, |tp| set.contains(tp), btf);
        let (load, skipped) = hooks_to_load(set, &exists, disabled);
        let loaded = optional_hooks::set_autoload(&TCP_EVENT_HOOKS, object, &load);
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
            optional_hooks::attach_loaded(&TCP_EVENT_HOOKS, skel, links, not_recorded);
        if attached {
            writer.register::<tcp_event_entry>(
                RB_TCP_EVENTS,
                rings::of(&skel.maps.TCP_EVENTS)?,
                dir,
            )?;
        }
        Ok(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [bool; TCP_EVENT_HOOKS.len()] = [true; TCP_EVENT_HOOKS.len()];

    fn events() -> TracepointSet {
        TracepointSet::EVENTS
    }

    fn loaded(load: &[bool]) -> Vec<&'static str> {
        (0..load.len())
            .filter(|i| load[*i])
            .map(|i| TCP_EVENT_HOOKS[i].programs[0])
            .collect()
    }

    #[test]
    fn congestion_state_changes_replace_cwr() {
        let (load, skipped) = hooks_to_load(events(), &ALL, &[]);
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
        let (load, skipped) = hooks_to_load(events(), &exists, &[]);
        assert!(loaded(&load).contains(&"tcp_event_cwr"));
        assert_eq!(skipped.len(), 1);

        let (load, _) = hooks_to_load(events(), &ALL, &[CA_STATE_HOOK]);
        let names = loaded(&load);
        assert!(names.contains(&"tcp_event_cwr"));
        assert!(!names.contains(&"tcp_event_ca_state"));
    }

    #[test]
    fn hooks_load_for_their_tracepoints() {
        let set = TracepointSet::of(&[Tracepoint::Rto, Tracepoint::Destroy]);
        let (load, _) = hooks_to_load(set, &ALL, &[]);
        assert_eq!(loaded(&load), ["tcp_event_rto", "tcp_event_destroy"]);
    }

    #[test]
    fn drops_alone_load_only_the_drop_hook() {
        let (load, _) = hooks_to_load(TracepointSet::of(&[Tracepoint::Drops]), &ALL, &[]);
        assert_eq!(loaded(&load), ["tcp_event_drop"]);
        let (load, skipped) =
            hooks_to_load(TracepointSet::EMPTY, &[false; TCP_EVENT_HOOKS.len()], &[]);
        assert!(loaded(&load).is_empty());
        assert!(skipped.is_empty());
    }
}
