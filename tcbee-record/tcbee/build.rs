use std::{env, path::PathBuf};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/tcbee.bpf.c";

fn main() -> anyhow::Result<()> {
    build_skeleton()?;
    build_aya()
}

/// Compile the C eBPF object and generate its libbpf-rs skeleton.
fn build_skeleton() -> anyhow::Result<()> {
    let out = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR not set")?);
    let arch = env::var("CARGO_CFG_TARGET_ARCH").context("CARGO_CFG_TARGET_ARCH not set")?;
    let vmlinux = PathBuf::from("src/bpf/vmlinux").join(&arch);
    if !vmlinux.join("vmlinux.h").exists() {
        return Err(anyhow!("no vendored vmlinux.h for {arch} in {}", vmlinux.display()));
    }

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args([
            "-Wall".into(),
            "-Werror".into(),
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

fn build_aya() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "tcbee-ebpf")
        .ok_or_else(|| anyhow!("tcbee-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
