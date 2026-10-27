use std::{env, path::PathBuf};

use anyhow::Context as _;
use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/live.bpf.c";

/// Compile the C eBPF object and generate its libbpf-rs skeleton.
fn main() -> anyhow::Result<()> {
    let out = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR not set")?);

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args(["-Wall"])
        .build_and_generate(out.join("live.skel.rs"))
        .context("building the eBPF skeleton")?;

    println!("cargo:rerun-if-changed=src/bpf");
    Ok(())
}
