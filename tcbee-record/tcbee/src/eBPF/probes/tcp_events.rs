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
}

const fn hook(
    program: &'static [&'static str],
    target: Target,
    name: &'static str,
) -> TcpEventHook {
    TcpEventHook {
        programs: program,
        target,
        name,
    }
}

/// The programs of `-e`. Each one is optional on its own (`OptionalGroup::TcpEvent`).
pub const TCP_EVENT_HOOKS: [TcpEventHook; 7] = [
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
];

/// Index of the hook whose events replace `tcp_event_cwr` where it exists
const CA_STATE_HOOK: usize = 4;
const CWR_HOOK: usize = 6;

pub struct TcpEventTracer {}

impl TcpEventTracer {
    /// Loads the programs of the hooks that exist in the kernel and are not in `disabled`.
    /// Returns the indices of the loaded hooks and a message for each requested hook that is
    /// left out.
    pub fn configure(
        object: &mut OpenObject,
        enabled: bool,
        disabled: &[usize],
        btf: &mut KernelBtf,
    ) -> (Vec<usize>, Vec<String>) {
        let check = enabled && btf.available();
        let mut exists: Vec<bool> = TCP_EVENT_HOOKS
            .iter()
            .map(|hook| {
                !check
                    || match hook.target {
                        Target::Tracepoint(tp) => btf.has_tracepoint(tp),
                        Target::Function(func) => btf.has_func(None, func),
                    }
            })
            .collect();
        let mut skipped = Vec::new();
        for (i, hook) in TCP_EVENT_HOOKS.iter().enumerate() {
            if !enabled || exists[i] {
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
        // The congestion state changes include the CWR state; tcp_enter_cwr is the fallback
        if check && exists[CA_STATE_HOOK] {
            exists[CWR_HOOK] = false;
        }
        let mut loaded = Vec::new();
        for mut program in object.progs_mut() {
            let name = program.name().to_string_lossy();
            let Some(i) = TCP_EVENT_HOOKS
                .iter()
                .position(|hook| hook.programs.contains(&name.as_ref()))
            else {
                continue;
            };
            let load = enabled && exists[i] && !disabled.contains(&i);
            program.set_autoload(load);
            if load {
                loaded.push(i);
            }
        }
        loaded.sort_unstable();
        (loaded, skipped)
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        for program in skel.object().progs_mut() {
            let name = program.name().to_string_lossy();
            let ours = TCP_EVENT_HOOKS
                .iter()
                .any(|hook| hook.programs.contains(&name.as_ref()));
            if ours && program.autoload() {
                attach(&program, links)?;
            }
        }
        writer.register::<tcp_event_entry>(
            RB_TCP_EVENTS,
            rings::of(&skel.maps.TCP_EVENTS)?,
            dir,
        )?;
        Ok(())
    }
}
