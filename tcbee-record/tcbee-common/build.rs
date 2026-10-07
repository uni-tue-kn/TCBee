//! Generates the Rust record types from `tcbee/src/bpf/records.h`, the single source of
//! truth for the layout shared by the eBPF programs and userspace.

use std::{env, path::PathBuf};

use bindgen::callbacks::{DeriveInfo, ItemInfo, ParseCallbacks};

const RECORDS_H: &str = "../tcbee/src/bpf/records.h";

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
    "ip_tuple",
    "hook_seq_key",
    "filter_ip",
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

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));

    let mut builder = bindgen::Builder::default()
        .header(RECORDS_H)
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
        .parse_callbacks(Box::new(Callbacks));
    for record in RECORDS {
        builder = builder.allowlist_type(record);
    }

    builder
        .generate()
        .expect("bindgen failed on records.h")
        .write_to_file(out.join("records.rs"))
        .expect("writing records.rs");

    println!("cargo:rerun-if-changed={RECORDS_H}");
}
