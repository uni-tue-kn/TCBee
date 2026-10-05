//! Generates the Rust record types from `tcbee/src/bpf/records.h`, the single source of
//! truth for the layout shared by the eBPF programs and userspace.

use std::{env, path::PathBuf};

use bindgen::callbacks::{AttributeInfo, DeriveInfo, FieldAttributeInfo, ItemInfo, ParseCallbacks};

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
    "filter_ip",
];

/// C names that keep their historical Rust names
const RENAMES: &[(&str, &str)] = &[("ip_tuple", "IpTuple"), ("filter_ip", "FilterIp")];

#[derive(Debug)]
struct Callbacks {
    user: bool,
    ebpf: bool,
}

impl Callbacks {
    /// `kernel_read` arguments for the KernelRead derive of the old aya eBPF crate
    fn kernel_read_ctx(name: &str) -> Option<&'static str> {
        Some(match name {
            "sock_trace_entry" | "cwnd_trace_entry" => {
                r#"ctx(sk: *const sock, tcp: *const tcp_sock), default_src = "tcp""#
            }
            "cubic_trace_entry" => r#"ctx(sk: *const sock, cubic: *const cubic), default_src = "cubic""#,
            "bbr_trace_entry" => r#"ctx(sk: *const sock, bbr: *const bbr), default_src = "bbr""#,
            _ => return None,
        })
    }
}

impl ParseCallbacks for Callbacks {
    fn item_name(&self, info: ItemInfo) -> Option<String> {
        RENAMES
            .iter()
            .find(|(c, _)| *c == info.name)
            .map(|(_, rust)| rust.to_string())
    }

    fn add_derives(&self, info: &DeriveInfo<'_>) -> Vec<String> {
        let mut derives = Vec::new();
        if self.user {
            derives.push("serde::Serialize".into());
            derives.push("serde::Deserialize".into());
        }
        if self.ebpf && Self::kernel_read_ctx(info.name).is_some() {
            derives.push("kernel_read_derive::KernelRead".into());
        }
        derives
    }

    fn add_attributes(&self, info: &AttributeInfo<'_>) -> Vec<String> {
        match Self::kernel_read_ctx(info.name) {
            Some(ctx) if self.ebpf => vec![format!("#[kernel_read({ctx})]")],
            _ => vec![],
        }
    }

    fn field_attributes(&self, info: &FieldAttributeInfo<'_>) -> Vec<String> {
        if !self.ebpf || info.type_name != "sock_trace_entry" {
            return vec![];
        }
        let kr = match info.field_name {
            "pacing_rate" => r#"src = "sk", path = "sk_pacing_rate""#,
            "max_pacing_rate" => r#"src = "sk", path = "sk_max_pacing_rate""#,
            "backoff" => r#"src = "tcp", path = "inet_conn.icsk_backoff""#,
            "rto" => r#"src = "tcp", path = "inet_conn.icsk_rto""#,
            "rcv_mss" => r#"src = "tcp", path = "inet_conn.icsk_ack.rcv_mss""#,
            "probes" => r#"src = "tcp", path = "keepalive_probes""#,
            "retrans" => r#"src = "tcp", path = "retrans_out""#,
            "rttvar" => r#"src = "tcp", path = "rttvar_us""#,
            "rcv_rtt" => r#"src = "tcp", path = "rcv_rtt_est.rtt_us""#,
            "rcv_space" => r#"src = "tcp", path = "rcvq_space.space""#,
            "ato" | "snd_wscale" | "rcv_wscale" => r#"expr = "0""#,
            _ => return vec![],
        };
        vec![format!("kr({kr})")]
    }
}

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let callbacks = Callbacks {
        user: env::var_os("CARGO_FEATURE_USER").is_some(),
        ebpf: env::var_os("CARGO_FEATURE_EBPF").is_some(),
    };

    let mut builder = bindgen::Builder::default()
        .header(RECORDS_H)
        .use_core()
        .ctypes_prefix("::core::ffi")
        .derive_debug(true)
        .derive_copy(true)
        .derive_default(true)
        .derive_hash(true)
        .derive_partialeq(true)
        .derive_eq(true)
        .generate_comments(false)
        .parse_callbacks(Box::new(callbacks));
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
