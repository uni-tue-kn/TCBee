mod app;
mod types;
mod worker;

use anyhow::Context as _;
use app::TcbeeApp;
use aya::{programs::FEntry, Btf};
use log::{debug, info, warn};
use std::sync::mpsc;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Raise the memlock limit so eBPF maps can be allocated.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF bytecode and attach probes.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tcbee-live"
    )))?;

    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;

    let program: &mut FEntry = ebpf.program_mut("cwnd_sock_sendmsg").unwrap().try_into()?;
    program.load("__tcp_transmit_skb", &btf)?;
    program.attach()?;
    info!("FEntry probe attached to __tcp_transmit_skb");

    let program: &mut FEntry = ebpf.program_mut("cwnd_sock_recvmsg").unwrap().try_into()?;
    program.load("tcp_rcv_established", &btf)?;
    program.attach()?;
    info!("FEntry probe attached to tcp_rcv_established");

    // Channels bridging the Tokio worker and the egui main thread.
    let (event_tx, event_rx) = mpsc::sync_channel(10_000);
    let (disc_tx, disc_rx) = mpsc::sync_channel(1_000);
    let (filter_tx, filter_rx) = mpsc::sync_channel(64);

    // Build a multi-threaded Tokio runtime on a background OS thread.
    // eframe must own the main thread, so we cannot use #[tokio::main].
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

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
            rt.spawn(worker::run_ebpf_worker(
                ebpf, event_tx, disc_tx, filter_rx, egui_ctx, select_ports.clone(),
            ));
            Ok(Box::new(TcbeeApp::new(
                rt,
                event_rx,
                disc_rx,
                filter_tx,
                select_ports,
                combined_plot,
                auto_fit_x,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}
