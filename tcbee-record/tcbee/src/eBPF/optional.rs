//! Probe groups that may fail to load without stopping the recording.
//!
//! A skeleton loads all its programs at once, so one program that the kernel rejects fails
//! all of them. The programs of an optional group depend on kernel code that may be missing
//! or different (a module that is not loaded, an out-of-tree variant with other struct
//! fields). When loading fails in one of them, the runner opens the object again without
//! that group and retries.

use std::collections::BTreeSet;

use crate::eBPF::probes::mptcp::PM_HOOKS;

/// The program names of `PM_HOOKS`
const MPTCP_PM_PROGRAMS: [&str; PM_HOOKS.len()] = {
    let mut names = [""; PM_HOOKS.len()];
    let mut i = 0;
    while i < PM_HOOKS.len() {
        names[i] = PM_HOOKS[i].0;
        i += 1;
    }
    names
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OptionalGroup {
    Bbr,
    /// The MPTCP code in the sock and cwnd programs (MPTCP_TAG); without it they still load
    MptcpTag,
    MptcpPm,
}

impl OptionalGroup {
    pub const ALL: [OptionalGroup; 3] = [
        OptionalGroup::Bbr,
        OptionalGroup::MptcpTag,
        OptionalGroup::MptcpPm,
    ];

    pub fn name(self) -> &'static str {
        match self {
            OptionalGroup::Bbr => "BBR",
            OptionalGroup::MptcpTag => "MPTCP tagging",
            OptionalGroup::MptcpPm => "MPTCP path manager events",
        }
    }

    /// The group's programs, as libbpf names them (the C function names)
    pub fn programs(self) -> &'static [&'static str] {
        match self {
            OptionalGroup::Bbr => &["bbr_cong_control", "bbr_cwnd_event"],
            OptionalGroup::MptcpTag => &[
                "sock_sendmsg",
                "sock_recvmsg",
                "cwnd_sock_sendmsg",
                "cwnd_sock_recvmsg",
            ],
            OptionalGroup::MptcpPm => &MPTCP_PM_PROGRAMS,
        }
    }

    fn of_program(program: &str) -> Option<OptionalGroup> {
        Self::ALL
            .into_iter()
            .find(|group| group.programs().contains(&program))
    }
}

/// Names of the programs that libbpf reports as failed in `warnings`, in order. libbpf
/// prefixes its messages about a program with `prog '<name>': `.
fn failed_programs(warnings: &[String]) -> Vec<&str> {
    warnings
        .iter()
        .filter(|warning| warning.contains("fail"))
        .filter_map(|warning| {
            let rest = &warning[warning.find("prog '")? + "prog '".len()..];
            Some(&rest[..rest.find('\'')?])
        })
        .collect()
}

/// The groups to disable for the next load attempt after a load failed with `warnings`, or
/// `None` if a retry cannot help: the failing program belongs to no enabled optional group.
/// If libbpf named no program, every enabled optional group is disabled, as loading failed
/// somewhere and they are the parts that are allowed to fail.
pub fn to_disable(
    enabled: &BTreeSet<OptionalGroup>,
    warnings: &[String],
) -> Option<BTreeSet<OptionalGroup>> {
    let failed = failed_programs(warnings);
    let groups: BTreeSet<OptionalGroup> = if failed.is_empty() {
        enabled.clone()
    } else {
        let groups: Option<BTreeSet<_>> = failed
            .iter()
            .map(|program| OptionalGroup::of_program(program))
            .collect();
        groups?
    };
    (!groups.is_empty() && groups.is_subset(enabled)).then_some(groups)
}

/// Names of `groups` for log messages
pub fn names(groups: &BTreeSet<OptionalGroup>) -> String {
    groups
        .iter()
        .map(|group| group.name())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use libbpf_rs::skel::{OpenSkel, SkelBuilder};

    use super::*;
    use crate::eBPF::skel::TcbeeSkelBuilder;

    #[test]
    fn group_programs_exist_in_the_object() {
        let mut storage = MaybeUninit::uninit();
        let open = TcbeeSkelBuilder::default().open(&mut storage).unwrap();
        let programs: Vec<String> = open
            .open_object()
            .progs()
            .map(|program| program.name().to_string_lossy().into_owned())
            .collect();
        for group in OptionalGroup::ALL {
            for program in group.programs() {
                assert!(programs.iter().any(|p| p == program), "{program}");
            }
        }
    }

    fn warnings(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|line| line.to_string()).collect()
    }

    fn bbr() -> BTreeSet<OptionalGroup> {
        BTreeSet::from([OptionalGroup::Bbr])
    }

    #[test]
    fn failing_optional_program_disables_its_group() {
        let w = warnings(&[
            "libbpf: prog 'bbr_cong_control': BPF program load failed: Invalid argument",
            "libbpf: prog 'bbr_cong_control': failed to load: -22",
            "libbpf: failed to load object 'tcbee_bpf'",
        ]);
        assert_eq!(to_disable(&bbr(), &w), Some(bbr()));
    }

    #[test]
    fn failing_core_program_is_not_retried() {
        let w = warnings(&["libbpf: prog 'tc_ingress_packet_tracer': failed to load: -13"]);
        assert_eq!(to_disable(&bbr(), &w), None);
    }

    #[test]
    fn failing_sock_program_retries_without_mptcp_tagging_only_once() {
        let w = warnings(&["libbpf: prog 'sock_sendmsg': failed to load: -13"]);
        let tag = BTreeSet::from([OptionalGroup::Bbr, OptionalGroup::MptcpTag]);
        assert_eq!(
            to_disable(&tag, &w),
            Some(BTreeSet::from([OptionalGroup::MptcpTag]))
        );
        assert_eq!(to_disable(&bbr(), &w), None);
    }

    #[test]
    fn failing_path_manager_program_disables_only_its_group() {
        let w = warnings(&["libbpf: prog 'mptcp_pm_announced': failed to load: -22"]);
        let enabled = BTreeSet::from(OptionalGroup::ALL);
        assert_eq!(
            to_disable(&enabled, &w),
            Some(BTreeSet::from([OptionalGroup::MptcpPm]))
        );
    }

    #[test]
    fn group_that_is_already_disabled_is_not_retried() {
        let w = warnings(&["libbpf: prog 'bbr_cwnd_event': failed to load: -22"]);
        assert_eq!(to_disable(&BTreeSet::new(), &w), None);
    }

    #[test]
    fn unnamed_failure_disables_all_enabled_groups() {
        let w = warnings(&["libbpf: failed to load object 'tcbee_bpf'"]);
        assert_eq!(to_disable(&bbr(), &w), Some(bbr()));
        assert_eq!(to_disable(&BTreeSet::new(), &w), None);
    }

    #[test]
    fn program_messages_without_failure_are_ignored() {
        let w = warnings(&[
            "libbpf: prog 'sock_sendmsg': relo #3: patched insn",
            "libbpf: prog 'bbr_cwnd_event': failed to resolve CO-RE relocation",
        ]);
        assert_eq!(failed_programs(&w), vec!["bbr_cwnd_event"]);
    }
}
