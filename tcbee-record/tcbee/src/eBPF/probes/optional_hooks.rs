//! Tables of programs that are optional one by one (`OptionalGroup::TcpEvent`,
//! `OptionalGroup::SockEvent`): each one loads if it is requested and the kernel has its
//! target, and is left out with a message if not, or if it does not attach.

use libbpf_rs::{skel::Skel, Link, OpenObject};
use log::warn;

use crate::eBPF::{host::KernelBtf, probes::attach, skel::TcbeeSkel};

/// Where an optional program attaches
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Tracepoint(&'static str),
    Function(&'static str),
}

impl Target {
    fn exists(self, btf: &mut KernelBtf) -> bool {
        match self {
            Target::Tracepoint(tp) => btf.has_tracepoint(tp),
            Target::Function(func) => btf.has_func(None, func),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Tracepoint(tp) => write!(f, "tracepoint {tp}"),
            Target::Function(func) => write!(f, "kernel function {func}"),
        }
    }
}

/// An optional program, the hook it records and `S`, what the user selects it with
#[derive(Clone, Copy, Debug)]
pub struct OptionalHook<S> {
    /// One program per hook, a slice so that it can serve as an optional group's programs
    pub programs: &'static [&'static str],
    pub target: Target,
    /// Name for messages and the run metadata
    pub name: &'static str,
    pub selector: S,
}

/// How a table's warnings say that a hook's records are missing, e.g. "TCP retransmissions
/// are not recorded"
pub type NotRecorded = fn(&str) -> String;

/// Whether the kernel has the target of each requested hook. Hooks that are not requested
/// and all hooks without kernel BTF to check count as present.
pub fn existing<S: Copy>(
    hooks: &[OptionalHook<S>],
    requested: impl Fn(S) -> bool,
    btf: &mut KernelBtf,
) -> Vec<bool> {
    hooks
        .iter()
        .map(|hook| !requested(hook.selector) || !btf.available() || hook.target.exists(btf))
        .collect()
}

/// Which hooks to load: the requested ones that exist and are not `disabled` (indices).
/// Returns the indices of the requested ones that do not exist too.
pub fn to_load<S: Copy>(
    hooks: &[OptionalHook<S>],
    requested: impl Fn(S) -> bool,
    exists: &[bool],
    disabled: &[usize],
) -> (Vec<bool>, Vec<usize>) {
    let load = (0..hooks.len())
        .map(|i| requested(hooks[i].selector) && exists[i] && !disabled.contains(&i))
        .collect();
    let missing = (0..hooks.len())
        .filter(|i| requested(hooks[*i].selector) && !exists[*i])
        .collect();
    (load, missing)
}

/// Warns that the kernel lacks the target of a requested hook; returns the message for the
/// run metadata
pub fn report_missing<S>(hook: &OptionalHook<S>, not_recorded: NotRecorded) -> String {
    warn!(
        "The {} does not exist, {}",
        hook.target,
        not_recorded(hook.name)
    );
    format!("{}: no {} in this kernel", hook.name, hook.target)
}

/// Switches each program of the table on or off as `load` says; returns the indices of the
/// loaded hooks
pub fn set_autoload<S>(
    hooks: &[OptionalHook<S>],
    object: &mut OpenObject,
    load: &[bool],
) -> Vec<usize> {
    for mut program in object.progs_mut() {
        let name = program.name().to_string_lossy();
        if let Some(i) = index_of(hooks, &name) {
            program.set_autoload(load[i]);
        }
    }
    (0..load.len()).filter(|i| load[*i]).collect()
}

/// Attaches the loaded programs of the table. A program that does not attach is left out
/// with a warning, like one the kernel lacks. Returns whether any attached, and the hook
/// index and a message for each that failed.
pub fn attach_loaded<S>(
    hooks: &[OptionalHook<S>],
    skel: &TcbeeSkel<'_>,
    links: &mut Vec<Link>,
    not_recorded: NotRecorded,
) -> (bool, Vec<(usize, String)>) {
    let mut attached = false;
    let mut failed = Vec::new();
    for program in skel.object().progs_mut() {
        let name = program.name().to_string_lossy();
        let Some(i) = index_of(hooks, &name) else {
            continue;
        };
        if !program.autoload() {
            continue;
        }
        match attach(&program, links) {
            Ok(()) => attached = true,
            Err(err) => {
                let hook = &hooks[i];
                warn!("{}, {}", err, not_recorded(hook.name));
                failed.push((i, format!("{}: attaching failed: {}", hook.name, err)));
            }
        }
    }
    (attached, failed)
}

fn index_of<S>(hooks: &[OptionalHook<S>], program: &str) -> Option<usize> {
    hooks
        .iter()
        .position(|hook| hook.programs.contains(&program))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOOKS: [OptionalHook<u8>; 3] = [
        OptionalHook {
            programs: &["a"],
            target: Target::Tracepoint("a"),
            name: "a",
            selector: 0,
        },
        OptionalHook {
            programs: &["b"],
            target: Target::Function("b"),
            name: "b",
            selector: 1,
        },
        OptionalHook {
            programs: &["c"],
            target: Target::Tracepoint("c"),
            name: "c",
            selector: 1,
        },
    ];

    #[test]
    fn requested_existing_and_enabled_hooks_load() {
        let selected = |s: u8| s == 1;
        let (load, missing) = to_load(&HOOKS, selected, &[true, true, false], &[]);
        assert_eq!(load, [false, true, false]);
        assert_eq!(missing, [2]);
        let (load, missing) = to_load(&HOOKS, selected, &[false, true, true], &[1]);
        assert_eq!(load, [false, false, true]);
        assert!(missing.is_empty());
    }

    #[test]
    fn missing_hooks_are_named_with_their_target() {
        let not_recorded: NotRecorded = |name| format!("{name} are not recorded");
        assert_eq!(
            report_missing(&HOOKS[1], not_recorded),
            "b: no kernel function b in this kernel"
        );
        assert_eq!(
            report_missing(&HOOKS[2], not_recorded),
            "c: no tracepoint c in this kernel"
        );
    }
}
