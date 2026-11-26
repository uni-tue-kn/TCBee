use std::{collections::BTreeSet, error::Error};

use libbpf_rs::{Link, OpenObject};
use tcbee_common::{records::flow_owner_entry, stats::RB_OWNERS};

use crate::{
    eBPF::{
        host::KernelBtf,
        optional::OptionalGroup,
        probes::optional_hooks::{self, OptionalHook, Target},
        rings,
        skel::TcbeeSkel,
    },
    writer::{Observer, Writer},
};

/// A program that records the process opening a connection (`flow_owners.tcp`). There is
/// nothing to select, `--no-owners` switches them all off.
pub type OwnerHook = OptionalHook<()>;

/// The flow owner programs, each optional on its own (`OptionalGroup::Owner`)
pub const OWNER_HOOKS: [OwnerHook; 3] = [
    OptionalHook {
        selector: (),
        programs: &["owner_connect_v4"],
        target: Target::Function("tcp_v4_connect"),
        name: "owners of IPv4 connects",
    },
    OptionalHook {
        selector: (),
        programs: &["owner_connect_v6"],
        target: Target::ModuleFunction("ipv6", "tcp_v6_connect"),
        name: "owners of IPv6 connects",
    },
    OptionalHook {
        selector: (),
        programs: &["owner_accept"],
        target: Target::Function("inet_csk_accept"),
        name: "owners of accepted connections",
    },
];

fn not_recorded(name: &str) -> String {
    format!("the {name} are not recorded")
}

/// Which hooks to load: all that exist in the kernel and are not `disabled` if `enabled`,
/// with a message for each one the kernel lacks
fn hooks_to_load(
    enabled: bool,
    exists: &[bool],
    disabled: &BTreeSet<OptionalGroup>,
) -> (Vec<bool>, Vec<String>) {
    let (load, missing) = optional_hooks::to_load(
        &OWNER_HOOKS,
        |()| enabled,
        exists,
        disabled,
        OptionalGroup::Owner,
    );
    let skipped = missing
        .into_iter()
        .map(|i| optional_hooks::report_missing(&OWNER_HOOKS[i], not_recorded))
        .collect();
    (load, skipped)
}

pub struct OwnerTracer {}

impl OwnerTracer {
    /// Loads the owner programs if `enabled`, those that exist in the kernel and are not in
    /// `disabled`. Returns the indices of the loaded hooks and a message for each one left out.
    pub fn configure(
        object: &mut OpenObject,
        enabled: bool,
        disabled: &BTreeSet<OptionalGroup>,
        btf: &mut KernelBtf,
    ) -> (Vec<usize>, Vec<String>) {
        let exists = optional_hooks::existing(&OWNER_HOOKS, |()| enabled, btf);
        let (load, skipped) = hooks_to_load(enabled, &exists, disabled);
        let loaded = optional_hooks::set_autoload(&OWNER_HOOKS, object, &load);
        (loaded, skipped)
    }

    /// Attaches the loaded programs. A program that does not attach is left out with a
    /// warning; returns its hook index and a message for each. Without any attached program
    /// the ring gets no writer and no file. `observer`, if any, sees every record written.
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
        observer: Option<Observer>,
    ) -> Result<Vec<(usize, String)>, Box<dyn Error>> {
        let (attached, failed) =
            optional_hooks::attach_loaded(&OWNER_HOOKS, skel, links, not_recorded);
        if attached {
            let maps = rings::of(&skel.maps.FLOW_OWNERS)?;
            match observer {
                Some(observer) => {
                    writer.register_observed::<flow_owner_entry>(RB_OWNERS, maps, dir, observer)?
                }
                None => writer.register::<flow_owner_entry>(RB_OWNERS, maps, dir)?,
            }
        }
        Ok(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [bool; OWNER_HOOKS.len()] = [true; OWNER_HOOKS.len()];

    #[test]
    fn all_owner_hooks_load_unless_switched_off() {
        let none = BTreeSet::new();
        let (load, skipped) = hooks_to_load(true, &ALL, &none);
        assert_eq!(load, ALL);
        assert!(skipped.is_empty());
        let (load, skipped) = hooks_to_load(false, &[false; OWNER_HOOKS.len()], &none);
        assert_eq!(load, [false; OWNER_HOOKS.len()]);
        assert!(skipped.is_empty());
    }

    #[test]
    fn a_missing_or_rejected_hook_leaves_the_others() {
        let mut exists = ALL;
        exists[1] = false;
        let accept = BTreeSet::from([OptionalGroup::Owner(2)]);
        let (load, skipped) = hooks_to_load(true, &exists, &accept);
        assert_eq!(load, [true, false, false]);
        assert_eq!(
            skipped,
            ["owners of IPv6 connects: no kernel function tcp_v6_connect in this kernel"]
        );
    }
}
