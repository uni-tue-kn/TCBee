//! Probe groups that may fail to load without stopping the recording.
//!
//! A skeleton loads all its programs at once, so one program that the kernel rejects fails
//! all of them. The programs of an optional group depend on kernel code that may be missing
//! or different (a module that is not loaded, an out-of-tree variant with other struct
//! fields). When loading fails in one of them, the runner opens the object again without
//! that group and retries.

use std::collections::BTreeSet;

use crate::eBPF::probes::{
    cubic::CUBIC_HOOKS, mptcp::PM_HOOKS, owners::OWNER_HOOKS, reno::RENO_HOOKS,
    sock_events::SOCK_EVENT_HOOKS, tcp_events::TCP_EVENT_HOOKS,
};

/// Number of optional groups: BBR, CUBIC, Reno, MPTCP tagging, the timer, the path manager
/// and one per hook of the tables
const GROUPS: usize =
    6 + CUBIC_HOOKS.len() + TCP_EVENT_HOOKS.len() + SOCK_EVENT_HOOKS.len() + OWNER_HOOKS.len();

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
    /// The CUBIC programs of -a at each ACK and at the cwnd event, the ones of the default
    /// recording; they need tcp_cubic loaded or built in
    Cubic,
    /// One more CUBIC hook of -a, the index into `CUBIC_HOOKS`
    CubicHook(usize),
    /// The Reno hooks of -a, `RENO_HOOKS`
    Reno,
    /// The write timer program of -k (fexit/tcp_write_timer_handler)
    SockTimer,
    /// The MPTCP code in the sock and cwnd programs (MPTCP_TAG); without it they still load
    MptcpTag,
    MptcpPm,
    /// One TCP event program, the index into `TCP_EVENT_HOOKS`
    TcpEvent(usize),
    /// One socket event program of -k, the index into `SOCK_EVENT_HOOKS`
    SockEvent(usize),
    /// One flow owner program, the index into `OWNER_HOOKS`
    Owner(usize),
}

impl OptionalGroup {
    /// A failed program is blamed on the first enabled group here that has it. MPTCP tagging
    /// comes before the timer and socket event groups: its code is in every sock program, so
    /// a tagging relocation that fails would otherwise drop them one by one until -k records
    /// nothing. A program that still fails without tagging is then blamed on its own group.
    pub const ALL: [OptionalGroup; GROUPS] = {
        let mut all = [OptionalGroup::Bbr; GROUPS];
        all[1] = OptionalGroup::Cubic;
        let mut n = 2;
        let mut i = 0;
        while i < CUBIC_HOOKS.len() {
            all[n] = OptionalGroup::CubicHook(i);
            n += 1;
            i += 1;
        }
        all[n] = OptionalGroup::Reno;
        all[n + 1] = OptionalGroup::MptcpTag;
        all[n + 2] = OptionalGroup::SockTimer;
        n += 3;
        let mut i = 0;
        while i < SOCK_EVENT_HOOKS.len() {
            all[n] = OptionalGroup::SockEvent(i);
            n += 1;
            i += 1;
        }
        all[n] = OptionalGroup::MptcpPm;
        n += 1;
        let mut i = 0;
        while i < TCP_EVENT_HOOKS.len() {
            all[n] = OptionalGroup::TcpEvent(i);
            n += 1;
            i += 1;
        }
        let mut i = 0;
        while i < OWNER_HOOKS.len() {
            all[n] = OptionalGroup::Owner(i);
            n += 1;
            i += 1;
        }
        all
    };

    pub fn name(self) -> &'static str {
        match self {
            OptionalGroup::Bbr => "BBR",
            OptionalGroup::Cubic => "CUBIC",
            OptionalGroup::CubicHook(i) => CUBIC_HOOKS[i].name,
            OptionalGroup::Reno => RENO_HOOKS[0].name,
            OptionalGroup::SockTimer => "write timer hook",
            OptionalGroup::MptcpTag => "MPTCP tagging",
            OptionalGroup::MptcpPm => "MPTCP path manager events",
            OptionalGroup::TcpEvent(i) => TCP_EVENT_HOOKS[i].name,
            OptionalGroup::SockEvent(i) => SOCK_EVENT_HOOKS[i].name,
            OptionalGroup::Owner(i) => OWNER_HOOKS[i].name,
        }
    }

    pub fn is_tcp_event(self) -> bool {
        matches!(self, OptionalGroup::TcpEvent(_))
    }

    pub fn is_sock_event(self) -> bool {
        matches!(self, OptionalGroup::SockEvent(_))
    }

    pub fn is_owner(self) -> bool {
        matches!(self, OptionalGroup::Owner(_))
    }

    /// The group's programs, as libbpf names them (the C function names)
    pub fn programs(self) -> &'static [&'static str] {
        match self {
            OptionalGroup::Bbr => &["bbr_cong_control", "bbr_cwnd_event"],
            OptionalGroup::Cubic => &["cubic_cong_control", "cubic_cwnd_event"],
            OptionalGroup::CubicHook(i) => CUBIC_HOOKS[i].programs,
            OptionalGroup::Reno => RENO_HOOKS[0].programs,
            OptionalGroup::SockTimer => &["sock_timer"],
            OptionalGroup::MptcpTag => &[
                "sock_sendmsg",
                "sock_recvmsg",
                "sock_timer",
                "cwnd_sock_sendmsg",
                "cwnd_sock_recvmsg",
                "sock_oc_sendmsg",
                "sock_oc_recvmsg",
                "cwnd_oc_sendmsg",
                "cwnd_oc_recvmsg",
                "sock_oc_rcv_state",
                "sock_oc_timer",
                "cwnd_oc_rcv_state",
                "cwnd_oc_timer",
                "sock_ingress",
                "sock_ingress_state",
                "sock_event_state",
                "sock_event_ca_state",
                "sock_event_retransmit",
                "sock_event_restart",
                "sock_event_rcvbuf",
            ],
            OptionalGroup::MptcpPm => &MPTCP_PM_PROGRAMS,
            OptionalGroup::TcpEvent(i) => TCP_EVENT_HOOKS[i].programs,
            OptionalGroup::SockEvent(i) => SOCK_EVENT_HOOKS[i].programs,
            OptionalGroup::Owner(i) => OWNER_HOOKS[i].programs,
        }
    }

    /// The group to blame for a failed program: the first enabled one that has it
    fn of_program(program: &str, enabled: &BTreeSet<OptionalGroup>) -> Option<OptionalGroup> {
        Self::ALL
            .into_iter()
            .find(|group| enabled.contains(group) && group.programs().contains(&program))
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
            .map(|program| OptionalGroup::of_program(program, enabled))
            .collect();
        groups?
    };
    (!groups.is_empty()).then_some(groups)
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

    #[test]
    fn every_sock_and_cwnd_program_is_in_mptcp_tagging() {
        let mut storage = MaybeUninit::uninit();
        let open = TcbeeSkelBuilder::default().open(&mut storage).unwrap();
        for program in open.open_object().progs() {
            let name = program.name().to_string_lossy();
            if name.starts_with("sock_") || name.starts_with("cwnd_") {
                assert!(
                    OptionalGroup::MptcpTag.programs().contains(&&*name),
                    "{name}"
                );
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
    fn failing_timer_program_disables_only_the_timer_hook() {
        let w = warnings(&["libbpf: prog 'sock_timer': failed to load: -524"]);
        let mut enabled = BTreeSet::from(OptionalGroup::ALL);
        enabled.remove(&OptionalGroup::MptcpTag);
        assert_eq!(
            to_disable(&enabled, &w),
            Some(BTreeSet::from([OptionalGroup::SockTimer]))
        );
    }

    /// With MPTCP tagging, a failing sock program drops tagging first, and its own group only
    /// if it still fails: a broken tagging relocation must not take the -k hooks with it
    #[test]
    fn failing_sock_programs_drop_mptcp_tagging_before_their_own_groups() {
        let mut enabled = BTreeSet::from(OptionalGroup::ALL);
        for program in ["sock_event_state", "sock_timer"] {
            let w = warnings(&[&format!("libbpf: prog '{program}': failed to load: -22")]);
            assert_eq!(
                to_disable(&enabled, &w),
                Some(BTreeSet::from([OptionalGroup::MptcpTag])),
                "{program}"
            );
        }
        enabled.remove(&OptionalGroup::MptcpTag);
        let w = warnings(&["libbpf: prog 'sock_event_state': failed to load: -22"]);
        assert_eq!(
            to_disable(&enabled, &w),
            Some(BTreeSet::from([OptionalGroup::SockEvent(0)]))
        );
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
    fn failing_tcp_event_program_disables_only_its_hook() {
        let w = warnings(&["libbpf: prog 'tcp_event_rst_sent': failed to load: -13"]);
        let enabled = BTreeSet::from(OptionalGroup::ALL);
        let rst_sent = TCP_EVENT_HOOKS
            .iter()
            .position(|hook| hook.programs == ["tcp_event_rst_sent"])
            .unwrap();
        assert_eq!(
            to_disable(&enabled, &w),
            Some(BTreeSet::from([OptionalGroup::TcpEvent(rst_sent)]))
        );
    }

    #[test]
    fn failing_sock_event_program_disables_only_its_hook() {
        let w = warnings(&["libbpf: prog 'sock_event_rcvbuf': failed to load: -13"]);
        let mut enabled = BTreeSet::from(OptionalGroup::ALL);
        enabled.remove(&OptionalGroup::MptcpTag);
        assert_eq!(
            to_disable(&enabled, &w),
            Some(BTreeSet::from([OptionalGroup::SockEvent(4)]))
        );
    }

    #[test]
    fn failing_owner_program_disables_only_its_hook() {
        let w = warnings(&["libbpf: prog 'owner_accept': failed to load: -22"]);
        let enabled = BTreeSet::from(OptionalGroup::ALL);
        assert_eq!(
            to_disable(&enabled, &w),
            Some(BTreeSet::from([OptionalGroup::Owner(2)]))
        );
    }

    #[test]
    fn failing_cubic_hook_disables_only_that_hook() {
        let w = warnings(&["libbpf: prog 'cubic_state': failed to load: -524"]);
        let enabled = BTreeSet::from(OptionalGroup::ALL);
        assert_eq!(
            to_disable(&enabled, &w),
            Some(BTreeSet::from([OptionalGroup::CubicHook(1)]))
        );
        // The default CUBIC programs are optional together, like BBR's
        let w = warnings(&["libbpf: prog 'cubic_cong_control': failed to load: -22"]);
        assert_eq!(
            to_disable(&enabled, &w),
            Some(BTreeSet::from([OptionalGroup::Cubic]))
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
