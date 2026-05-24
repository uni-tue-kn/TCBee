use std::error::Error;

use aya::{Ebpf, EbpfLoader};
use log::{debug, error, info, warn};
use tcbee_common::bindings::{
    tcp_bad_csum::tcp_bad_csum_entry, tcp_probe::tcp_probe_entry,
    tcp_retransmit_synack::tcp_retransmit_synack_entry,
};
use tokio::task::{spawn_blocking, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    eBPF::probes::{
        bbr::BBRTracer, cubic::CubicTracer, cwnd::CwndTracer, headers::{TCTracer, XDPTracer}, kernel::KernelTracer, tracepoints::TracepointTracer
    },
    writer::Writer,
    viz::ebpf_watcher::EBPFWatcher,
};

use super::ebpf_runner_config::EbpfRunnerConfig;

// TODO: how to handle multiple tracepoints at the same time?
pub struct EbpfRunner {
    stop_token: CancellationToken,
    threads: Vec<JoinHandle<()>>,
    config: EbpfRunnerConfig,
    ebpf: Option<Ebpf>,
    writer: Option<Writer>,
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
            writer: None,
        }
    }

    pub async fn stop(self) {
        // Signal child threads to stop
        self.stop_token.cancel();

        if let Some(writer) = self.writer {
            println!("FLUSHING WRITER!");
            let flush_res = writer.shutdown();
            if let Err(res) = flush_res {
                println!("Failed during flush: {}", res);
            } else {
                println!("Flushed successfully!");
            }
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
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

        // TODO: I feel that the dir should be passed to the writer, and the Tracers should just add the filename

        // This is the backend writer thread that reads and writes data to files
        let mut writer = Writer::new();
        let mut watcher_config = self.config.watcher_config();

        // Tracing for packet headers via TC and XDP
        if self.config.headers {
            TCTracer::spawn(
                &mut ebpf,
                self.config.iface.clone(),
                self.config.dir.clone(),
                &mut writer,
            )?;

            // FIXME: currently not doing anything
            XDPTracer::spawn(
                &mut ebpf,
                self.config.iface.clone(),
                self.config.dir.clone(),
                &mut writer,
            )?;

            watcher_config.graphs.packets = true;
        }

        // Tracing kernel metrics via FEntry probe
        if self.config.kernel {
            KernelTracer::spawn(
                &mut ebpf,
                self.config.dir.clone(),
                &mut writer,
            )?;

            watcher_config.graphs.kernel = true;
        }
        // Performance variant of above hook
        if self.config.cwnd {
            CwndTracer::spawn(
                &mut ebpf,
                self.config.dir.clone(),
                &mut writer,
            )?;

            watcher_config.graphs.kernel = true;
        }

        // Tracing kernel tracepoints
        if self.config.tracepoints {
            TracepointTracer::spawn::<tcp_probe_entry>(
                &mut ebpf,
                self.config.dir.clone(),
                &mut writer,
            )?;

            TracepointTracer::spawn::<tcp_retransmit_synack_entry>(
                &mut ebpf,
                self.config.dir.clone(),
                &mut writer,
            )?;

            TracepointTracer::spawn::<tcp_bad_csum_entry>(
                &mut ebpf,
                self.config.dir.clone(),
                &mut writer,
            )?;

            watcher_config.graphs.tracepoints = true;
        }

        if self.config.algorithms {
            CubicTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer)?;
            watcher_config.graphs.cubic = true;
            if let Err(err) = BBRTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer) {
                error!("Failed to initialize BBR Tracer. Is the kernel module loaded? ({})",err);
            };
            watcher_config.graphs.bbr = true;
        }

        // TODO: should be true by default in get_watcher_config()
        watcher_config.graphs.events = true;

        // Start watcher thread
        // Stop token is cloned such that cancellation affects all other threads
        let mut watcher = EBPFWatcher::new(
            &mut ebpf,
            self.config.update_period,
            self.stop_token.clone(),
            watcher_config,
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
