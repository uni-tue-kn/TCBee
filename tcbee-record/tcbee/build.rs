use std::{env, fs, path::PathBuf};

use anyhow::{anyhow, bail, Context as _};
use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/tcbee.bpf.c";
const RECORDS_H: &str = "src/bpf/records.h";
const RECORDS_GEN: &str = "../tcbee-common/src/records_gen.rs";

fn main() -> anyhow::Result<()> {
    check_records_generated()?;
    build_skeleton()
}

/// FNV-1a, the same hash as in tcbee-common/tests/records_gen.rs
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
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

/// The Rust record types (tcbee-common/src/records_gen.rs) are generated from records.h by a
/// test, not at build time. Its first line holds the hash of the records.h (and the headers it
/// includes) it was generated from: the eBPF programs and the writer must not disagree on the
/// layout.
fn check_records_generated() -> anyhow::Result<()> {
    let records_h = records_sources(std::path::Path::new(RECORDS_H)).context(RECORDS_H)?;
    let generated = fs::read_to_string(RECORDS_GEN).context(RECORDS_GEN)?;
    let expected = format!("// records.h FNV-1a: {:#018x}", fnv1a(&records_h));
    if generated.lines().next() != Some(expected.as_str()) {
        bail!(
            "{RECORDS_H} changed since {RECORDS_GEN} was generated, regenerate it with \
             TCBEE_REGEN_RECORDS=1 cargo test -p tcbee-common --test records_gen"
        );
    }
    println!("cargo:rerun-if-changed={RECORDS_GEN}");
    Ok(())
}

/// Compile the C eBPF object and generate its libbpf-rs skeleton.
fn build_skeleton() -> anyhow::Result<()> {
    let out = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR not set")?);
    let arch = env::var("CARGO_CFG_TARGET_ARCH").context("CARGO_CFG_TARGET_ARCH not set")?;
    let vmlinux = PathBuf::from("src/bpf/vmlinux").join(&arch);
    if !vmlinux.join("vmlinux.h").exists() {
        return Err(anyhow!(
            "no vendored vmlinux.h for {arch} in {}",
            vmlinux.display()
        ));
    }

    SkeletonBuilder::new()
        .source(BPF_SRC)
        // Kept for testing/bpf_identity.sh, which compares the default programs' code
        .obj(out.join("tcbee.bpf.o"))
        .clang_args([
            "-Wall".into(),
            // BPF_FETCH atomics (kernel 5.12) for the hook_seq fetch-add, whose result is
            // used. Older clang defaults to v1, which cannot express it.
            "-mcpu=v3".into(),
            // vmlinux.h of newer kernels declares anonymous tagged struct members
            // (`struct foo;`), which the kernel itself builds with -fms-extensions.
            "-fms-extensions".into(),
            "-Wno-microsoft-anon-tag".into(),
            "-I".into(),
            vmlinux.into_os_string(),
        ])
        .build_and_generate(out.join("tcbee.skel.rs"))
        .context("building the eBPF skeleton")?;

    println!("cargo:rerun-if-changed=src/bpf");
    Ok(())
}
