use std::{collections::BTreeSet, error::Error};

use libbpf_rs::{Link, OpenObject};
use tcbee_common::{records::reno_trace_entry, stats::RB_RENO};

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

/// The Reno hooks of -a, one hook with two programs that are optional together
/// (`OptionalGroup::Reno`). tcp_reno_cong_avoid and tcp_reno_ssthresh are exported by the
/// kernel (tcp_cong.c) and called through the congestion control operations of Reno and
/// other algorithms, so they are not inlined away.
pub const RENO_HOOKS: [OptionalHook<()>; 1] = [OptionalHook {
    programs: &["reno_cong_avoid", "reno_ssthresh"],
    target: Target::Function("tcp_reno_cong_avoid"),
    name: "Reno",
    selector: (),
}];

fn not_recorded(name: &str) -> String {
    format!("{name} is not recorded")
}

pub struct RenoTracer {}

impl RenoTracer {
    /// Loads the Reno programs if the kernel has them and they are not `disabled`. Returns
    /// whether they load, and a message if the kernel lacks them.
    pub fn configure(
        object: &mut OpenObject,
        enabled: bool,
        disabled: &BTreeSet<OptionalGroup>,
        btf: &mut KernelBtf,
    ) -> (bool, Vec<String>) {
        let exists = optional_hooks::existing(&RENO_HOOKS, |()| enabled, btf);
        let (load, missing) = optional_hooks::to_load(
            &RENO_HOOKS,
            |()| enabled,
            &exists,
            disabled,
            |_| OptionalGroup::Reno,
        );
        let skipped = missing
            .into_iter()
            .map(|i| optional_hooks::report_missing(&RENO_HOOKS[i], not_recorded))
            .collect();
        let loaded = optional_hooks::set_autoload(&RENO_HOOKS, object, &load);
        (!loaded.is_empty(), skipped)
    }

    /// Attaches both programs. If they do not attach, Reno is left out with a warning and a
    /// message is returned; the ring then gets no writer and no file.
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<Option<String>, Box<dyn Error>> {
        let (attached, failed) =
            optional_hooks::attach_loaded(&RENO_HOOKS, skel, links, not_recorded);
        if attached {
            // Both programs write to the same map
            writer.register::<reno_trace_entry>(
                RB_RENO,
                rings::of(&skel.maps.RENO_EVENTS)?,
                dir,
            )?;
        }
        Ok(failed.into_iter().next().map(|(_, message)| message))
    }
}
