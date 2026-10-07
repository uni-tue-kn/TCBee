use std::{env, path::PathBuf};

use anyhow::{anyhow, Context as _};
use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/tcbee.bpf.c";

fn main() -> anyhow::Result<()> {
    build_skeleton()
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
