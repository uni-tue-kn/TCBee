mod app;
mod bpf;
mod types;
mod worker;

use std::{mem::MaybeUninit, path::Path, sync::mpsc};

use anyhow::{Context as _, bail};
use app::TcbeeApp;
use bpf::LiveSkelBuilder;
use libbpf_rs::{
    PrintLevel,
    skel::{OpenSkel, SkelBuilder},
};
use log::{debug, info, warn};

fn libbpf_log(level: PrintLevel, msg: String) {
    let msg = msg.trim_end();
    match level {
        PrintLevel::Warn => warn!(target: "libbpf", "{msg}"),
        PrintLevel::Info => info!(target: "libbpf", "{msg}"),
        PrintLevel::Debug => debug!(target: "libbpf", "{msg}"),
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    libbpf_rs::set_print(Some((PrintLevel::Debug, libbpf_log)));

    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        bail!("the kernel has no BTF (/sys/kernel/btf/vmlinux), it needs CONFIG_DEBUG_INFO_BTF=y");
    }

    // Raise the memlock limit so eBPF maps can be allocated.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load the eBPF object and attach the probes. The skeleton borrows its storage
    // for its whole life, which is the life of the program.
    let storage = Box::leak(Box::new(MaybeUninit::uninit()));
    let open = LiveSkelBuilder::default()
        .open(storage)
        .context("opening the eBPF object")?;
    let skel = open
        .load()
        .context("loading the eBPF programs (needs root; RUST_LOG=libbpf=debug shows why)")?;

    let mut links = Vec::new();
    for (program, hook) in [
        (&skel.progs.cwnd_transmit_skb, "__tcp_transmit_skb"),
        (&skel.progs.cwnd_rcv_established, "tcp_rcv_established"),
    ] {
        let link = program
            .attach()
            .with_context(|| format!("attaching to {hook}"))?;
        links.push(link);
        info!("FEntry probe attached to {hook}");
    }

    // Channels bridging the worker thread and the egui main thread.
    let (event_tx, event_rx) = mpsc::sync_channel(10_000);
    let (disc_tx, disc_rx) = mpsc::sync_channel(1_000);
    let (filter_tx, filter_rx) = mpsc::sync_channel(64);

    let maps = worker::WorkerMaps::new(&skel.maps, event_tx)?;

    let select_ports: std::collections::HashSet<u16> = std::env::args()
        .zip(std::env::args().skip(1))
        .filter(|(flag, _)| flag == "--select-port")
        .filter_map(|(_, val)| val.parse().ok())
        .collect();
    let combined_plot = std::env::args().any(|a| a == "--combined-plot");
    let auto_fit_x    = std::env::args().any(|a| a == "--auto-fit-x");
    if select_ports.is_empty() {
        info!("No auto-select ports specified");
    } else {
        info!("Auto-select enabled for ports: {:?}", select_ports);
    }

    let native_options = eframe::NativeOptions::default();

    eframe::run_native(
        "tcbee-live",
        native_options,
        Box::new(move |cc| {
            let egui_ctx = cc.egui_ctx.clone();
            info!("GUI initialised, spawning eBPF worker");
            let worker_ports = select_ports.clone();
            std::thread::Builder::new()
                .name("ebpf-worker".into())
                .spawn(move || {
                    worker::run_ebpf_worker(maps, disc_tx, filter_rx, egui_ctx, worker_ports)
                })?;
            Ok(Box::new(TcbeeApp::new(
                event_rx,
                disc_rx,
                filter_tx,
                select_ports,
                combined_plot,
                auto_fit_x,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))?;

    // Detach the probes only after the GUI is closed
    drop(links);
    drop(skel);
    Ok(())
}
