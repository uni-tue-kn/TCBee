use std::error::Error;

use aya::{
    Ebpf, EbpfLoader,
};
use log::{debug, info, warn};
use tcbee_common::bindings::{
    tcp_bad_csum::tcp_bad_csum_entry,
    tcp_probe::tcp_probe_entry, tcp_retransmit_synack::tcp_retransmit_synack_entry,
};
use tokio::task::{self, spawn_blocking, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    eBPF::probes::{
        cwnd::CwndTracer, headers::{TCTracer, XDPTracer}, kernel::KernelTracer, tracepoints::TracepointTracer
    }, handlers::writer::Writer, viz::ebpf_watcher::EBPFWatcher
};

use super::ebpf_runner_config::EbpfRunnerConfig;

// TODO: how to handle multiple tracepoints at the same time?
pub struct EbpfRunner {
    stop_token: CancellationToken,
    threads: Vec<JoinHandle<()>>,
    config: EbpfRunnerConfig,
    ebpf: Option<Ebpf>,
    writer: Option<Writer>
}

pub fn prepend_string(mut src: String, prefix: &str) -> String {
    src.insert_str(0, prefix);
    src
}

impl EbpfRunner {
    // Load eBPF program and setup references
    pub fn new(stop_token: CancellationToken, config: EbpfRunnerConfig) -> EbpfRunner {
        EbpfRunner {
            stop_token,
            // TODO: new with capacity?
            threads: Vec::new(),
            config,
            ebpf: None,
            writer: None
        }
    }

    pub async fn stop(self) {
        // Signal child threads to stop
        self.stop_token.cancel();

        // Wait for threads to finish
        for t in self.threads {
            let _ = t.await;
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        // ###########################
        // SETUP
        // ###########################

        env_logger::init();

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        let mut ebpf = EbpfLoader::new()
            .set_global("FILTER_PORT", &self.config.port, true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/tcbee"
            )))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }

        info!("Starting eBPF probes!");

        // TODO: I feel that the file names should be moved to some config file

        // This is the backend writer thread that reads and writes data to files
        let mut writer = Writer::new();

        // Tracing for packet headers via TC and XDP
        if self.config.headers {
            TCTracer::spawn(
                &mut ebpf,
                self.config.iface.clone(),
                prepend_string("tc.tcp".to_string(),&self.config.dir),
                &mut writer
            )?;

            XDPTracer::spawn(
                &mut ebpf,
                self.config.iface.clone(),
                prepend_string("xdp.tcp".to_string(),&self.config.dir),
                &mut writer
            )?;
        }

        // Tracing kernel metrics via FEntry probe
        if self.config.kernel {
            KernelTracer::spawn(
                &mut ebpf,
                prepend_string("send_sock.tcp".to_string(),&self.config.dir),
                prepend_string("recv_sock.tcp".to_string(),&self.config.dir),
                &mut writer
            )?;
        }
        // Performance variant of above hook
        if self.config.cwnd {
            CwndTracer::spawn(
                &mut ebpf,
                prepend_string("send_cwnd.tcp".to_string(),&self.config.dir),
                prepend_string("recv_cwnd.tcp".to_string(),&self.config.dir),
                &mut writer
            )?;
        }

        // Tracing kernel tracepoints
        if self.config.tracepoints {
            TracepointTracer::spawn::<tcp_probe_entry>(
                    &mut ebpf,
                    prepend_string("probe.tcp".to_string(),&self.config.dir),
                    &mut writer
                )?;

            TracepointTracer::spawn::<tcp_retransmit_synack_entry>(
                    &mut ebpf,
                    prepend_string("retransmit_synack.tcp".to_string(),&self.config.dir),
                    &mut writer
                )?;

            TracepointTracer::spawn::<tcp_bad_csum_entry>(
                    &mut ebpf,
                    prepend_string("bad_csum.tcp".to_string(),&self.config.dir),
                    &mut writer
                )?;
        }

        // Start watcher thread
        // Stop token is cloned such that cancellation affects all other threads
        let mut watcher = EBPFWatcher::new(
            &mut ebpf,
            self.config.update_period,
            self.stop_token.clone(),
            self.config.watcher_config(),
            self.config.do_tui,
        )?;

        self.threads.push(spawn_blocking(move || {
            watcher.run();
        }));

        info!("Finished starting TUI!");

        // Store to ensure that it is not dropped after this function finishes!
        self.ebpf = Some(ebpf);
        self.writer = Some(writer);

        Ok(())
    }
}
