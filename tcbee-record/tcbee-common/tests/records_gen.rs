//! `src/records_gen.rs` holds the Rust record types generated from `tcbee/src/bpf/records.h`, the
//! single source of truth for the layout shared by the eBPF programs and userspace. The file is
//! checked in, so crates that only read trace files (tcbee-process) build without libclang. This
//! test regenerates it and fails if it differs. After changing records.h, rewrite it with
//! `TCBEE_REGEN_RECORDS=1 cargo test -p tcbee-common --test records_gen`.
//!
//! The first line holds a hash of records.h and the headers it includes, so that the recorder's
//! build fails when one of them changed without regenerating (tcbee/build.rs), also without
//! libclang.

use std::{env, fs, path::PathBuf, process::Command};

use bindgen::callbacks::{DeriveInfo, ItemInfo, ParseCallbacks};

const RECORDS: &[&str] = &[
    "tcp4_packet_trace",
    "tcp6_packet_trace",
    "sock_trace_entry",
    "cwnd_trace_entry",
    "cubic_trace_entry",
    "bbr_trace_entry",
    "tcp_probe_entry",
    "tcp_retransmit_synack_entry",
    "tcp_bad_csum_entry",
    "mptcp_pm_entry",
    "tcbee_mptcp_event",
    "tcp_event_entry",
    "tcbee_tcp_event",
    "ip_tuple",
    "hook_seq_key",
    "filter_ip",
    "tcbee_sock_field",
    "tcbee_onchg_reason",
];

/// C names that keep their historical Rust names
const RENAMES: &[(&str, &str)] = &[("ip_tuple", "IpTuple"), ("filter_ip", "FilterIp")];

/// Adds the serde derives used to write the records to the trace files
#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, info: ItemInfo) -> Option<String> {
        RENAMES
            .iter()
            .find(|(c, _)| *c == info.name)
            .map(|(_, rust)| rust.to_string())
    }

    fn add_derives(&self, _info: &DeriveInfo<'_>) -> Vec<String> {
        vec!["serde::Serialize".into(), "serde::Deserialize".into()]
    }
}

/// records.h followed by every header it includes with `#include "..."` (onchange.h), in
/// order: the layout of the records depends on all of them
fn records_sources(records_h: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = std::fs::read(records_h)?;
    let dir = records_h.parent().unwrap_or(std::path::Path::new("."));
    let text = String::from_utf8_lossy(&bytes).into_owned();
    for line in text.lines() {
        if let Some(name) = line
            .trim()
            .strip_prefix("#include \"")
            .and_then(|rest| rest.split('"').next())
        {
            bytes.extend(std::fs::read(dir.join(name))?);
        }
    }
    Ok(bytes)
}

/// FNV-1a, the same hash as in tcbee/build.rs
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn generate() -> String {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let records_h = crate_dir.join("../tcbee/src/bpf/records.h");

    // bindgen formats its output with rustfmt and silently skips that if rustfmt is missing,
    // which would look like a changed records.h
    let rustfmt = env::var_os("RUSTFMT").unwrap_or_else(|| "rustfmt".into());
    let found = Command::new(&rustfmt).arg("--version").output();
    assert!(
        found.is_ok_and(|o| o.status.success()),
        "rustfmt is needed to generate the records (rustup component add rustfmt)"
    );

    let mut builder = bindgen::Builder::default()
        .header(records_h.to_str().expect("non-UTF-8 path"))
        // Lay the records out like the eBPF compiler does, independent of the host
        .clang_arg("--target=bpfel")
        .use_core()
        .ctypes_prefix("::core::ffi")
        .derive_debug(true)
        .derive_copy(true)
        .derive_default(true)
        .derive_hash(true)
        .derive_partialeq(true)
        .derive_eq(true)
        .generate_comments(false)
        // TCBEE_MPTCP_CREATED, not tcbee_mptcp_event_TCBEE_MPTCP_CREATED
        .prepend_enum_name(false)
        .parse_callbacks(Box::new(Callbacks));
    for record in RECORDS {
        builder = builder.allowlist_type(record);
    }
    let bindings = builder
        .generate()
        .expect("bindgen failed on records.h")
        .to_string();
    let hash = fnv1a(&records_sources(&records_h).expect("reading records.h"));
    format!("// records.h FNV-1a: {hash:#018x}\n{bindings}")
}

#[test]
fn checked_in_records_match_records_h() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/records_gen.rs");
    let generated = generate();
    if env::var_os("TCBEE_REGEN_RECORDS").is_some() {
        fs::write(&path, &generated).expect("writing records_gen.rs");
        return;
    }
    let checked_in = fs::read_to_string(&path).unwrap_or_default();
    assert!(
        checked_in == generated,
        "{} is out of date with records.h, regenerate it with \
         TCBEE_REGEN_RECORDS=1 cargo test -p tcbee-common --test records_gen",
        path.display()
    );
}
