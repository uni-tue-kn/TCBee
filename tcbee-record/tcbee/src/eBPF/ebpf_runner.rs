use std::error::Error;

use anyhow::Context;
use aya::{
    maps::{PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{tc, FEntry, FExit, SchedClassifier, TcAttachType, TracePoint, Xdp, XdpFlags},
    Btf, Ebpf, EbpfLoader,
};
use log::{debug, info, warn};
use tcbee_common::bindings::{
    flow::IpTuple, tcp_bad_csum::tcp_bad_csum_entry, tcp_header::tcp_packet_trace,
    tcp_probe::tcp_probe_entry, tcp_retransmit_synack::tcp_retransmit_synack_entry,
    tcp_sock::sock_trace_entry, EBPFTracePointType,
};
use tokio::task::{self, spawn_blocking, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    eBPF::probes::{
        headers::{TCTracer, XDPTracer},
        kernel::KernelTracer,
        tracepoints::TracepointTracer,
        cwnd::CwndTracer,
    },
    handlers::{tracepoints::HandlerConstraints, BufferHandler, BufferHandlerImpl},
    viz::ebpf_watcher::EBPFWatcher,
};

use super::{ebpf_runner_config::EbpfRunnerConfig, errors::EBPFRunnerError};

// TODO: how to handle multiple tracepoints at the same time?
pub struct EbpfRunner {
    stop_token: CancellationToken,
    threads: Vec<JoinHandle<()>>,
    config: EbpfRunnerConfig,
    ebpf: Option<Ebpf>,
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

        // Tracing for packet headers via TC and XDP
        if self.config.headers {
            self.threads.push(TCTracer::spawn(
                &mut ebpf,
                self.config.iface.clone(),
                self.stop_token.child_token(),
                prepend_string("tc.tcp".to_string(),&self.config.dir),
            )?);

            self.threads.push(XDPTracer::spawn(
                &mut ebpf,
                self.config.iface.clone(),
                self.stop_token.child_token(),
                prepend_string("xdp.tcp".to_string(),&self.config.dir),
            )?);
        }

        // Tracing kernel metrics via FEntry probe
        if self.config.kernel {
            self.threads.extend(KernelTracer::spawn(
                &mut ebpf,
                self.stop_token.child_token(),
                prepend_string("send_sock.tcp".to_string(),&self.config.dir),
                prepend_string("recv_sock.tcp".to_string(),&self.config.dir),
            )?);
        }
        // Performance variant of above hook
        if self.config.cwnd {
            self.threads.extend(CwndTracer::spawn(
                &mut ebpf,
                self.stop_token.child_token(),
                prepend_string("send_cwnd.tcp".to_string(),&self.config.dir),
                prepend_string("recv_cwnd.tcp".to_string(),&self.config.dir),
            )?);
        }

        // Tracing kernel tracepoints
        if self.config.tracepoints {
            self.threads
                .push(TracepointTracer::spawn::<tcp_probe_entry>(
                    &mut ebpf,
                    self.stop_token.child_token(),
                    prepend_string("probe.tcp".to_string(),&self.config.dir),
                )?);

            self.threads
                .push(TracepointTracer::spawn::<tcp_retransmit_synack_entry>(
                    &mut ebpf,
                    self.stop_token.child_token(),
                    prepend_string("retransmit_synack.tcp".to_string(),&self.config.dir),
                )?);

            self.threads
                .push(TracepointTracer::spawn::<tcp_bad_csum_entry>(
                    &mut ebpf,
                    self.stop_token.child_token(),
                    prepend_string("bad_csum.tcp".to_string(),&self.config.dir),
                )?);
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

        // Store ebpf to ensure that it is not dropped after this function finishes!
        self.ebpf = Some(ebpf);

        // Yield to let created tasks work
        task::yield_now().await;
        Ok(())
    }
}
