use std::{
    error::Error,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use aya::{maps::HashMap, Ebpf, EbpfLoader};
use log::{debug, error, info, warn};
use tcbee_common::{
    bindings::{
        tcp_bad_csum::tcp_bad_csum_entry, tcp_probe::tcp_probe_entry,
        tcp_retransmit_synack::tcp_retransmit_synack_entry,
    },
    filter::FilterIp,
    stats::{RB_BAD_CSUM, RB_RETRANSMIT_SYNACK, RB_TCP_PROBE, RINGBUFS},
};
use tokio::{
    task::{spawn_blocking, JoinHandle},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

use crate::{
    eBPF::probes::{
        bbr::BBRTracer,
        cubic::CubicTracer,
        cwnd::CwndTracer,
        headers::{remove_clsact, TCTracer},
        kernel::KernelTracer,
        tracepoints::TracepointTracer,
    },
    metrics::{program_stats, ringbuf_sizes, Metrics, ProgramStats},
    stats::Stats,
    viz::ebpf_watcher::EBPFWatcher,
    writer::{Writer, WriterReport},
};

use super::ebpf_runner_config::EbpfRunnerConfig;

// TODO: how to handle multiple tracepoints at the same time?
pub struct EbpfRunner {
    stop_token: CancellationToken,
    threads: Vec<JoinHandle<()>>,
    config: EbpfRunnerConfig,
    ebpf: Option<Ebpf>,
    writer: Option<Writer>,
    stats: Option<Arc<Stats>>,
    ringbuf_sizes: Vec<Option<u32>>,
    started: Option<Instant>,
    clsact_iface: Option<String>,
}

pub fn prepend_string(filename: String, dir: &str) -> String {
    std::path::Path::new(dir)
        .join(&filename)
        .to_string_lossy()
        .into_owned()
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
            stats: None,
            ringbuf_sizes: Vec::new(),
            started: None,
            clsact_iface: None,
        }
    }

    fn insert_filter_ports(
        ebpf: &mut Ebpf,
        map_name: &str,
        ports: &[u16],
    ) -> Result<(), Box<dyn Error>> {
        let mut map: HashMap<_, u16, u8> = HashMap::try_from(
            ebpf.map_mut(map_name)
                .ok_or_else(|| format!("Filter map {} not found", map_name))?,
        )?;
        for port in ports {
            map.insert(port, &1, 0)?;
        }
        Ok(())
    }

    fn insert_filter_ips(
        ebpf: &mut Ebpf,
        map_name: &str,
        ips: &[[u8; 16]],
    ) -> Result<(), Box<dyn Error>> {
        let mut map: HashMap<_, FilterIp, u8> = HashMap::try_from(
            ebpf.map_mut(map_name)
                .ok_or_else(|| format!("Filter map {} not found", map_name))?,
        )?;
        for ip in ips {
            map.insert(&FilterIp { addr: *ip }, &1, 0)?;
        }
        Ok(())
    }

    fn configure_filter(&self, ebpf: &mut Ebpf) -> Result<(), Box<dyn Error>> {
        Self::insert_filter_ports(ebpf, "FILTER_ANY_PORTS", &self.config.filter.any_ports)?;
        Self::insert_filter_ports(ebpf, "FILTER_SRC_PORTS", &self.config.filter.src_ports)?;
        Self::insert_filter_ports(ebpf, "FILTER_DST_PORTS", &self.config.filter.dst_ports)?;
        Self::insert_filter_ips(ebpf, "FILTER_ANY_IPS", &self.config.filter.any_ips)?;
        Self::insert_filter_ips(ebpf, "FILTER_SRC_IPS", &self.config.filter.src_ips)?;
        Self::insert_filter_ips(ebpf, "FILTER_DST_IPS", &self.config.filter.dst_ips)?;
        Ok(())
    }

    pub async fn stop(mut self) {
        // Signal child threads to stop
        self.stop_token.cancel();

        // Wait for the watcher, it restores the terminal
        for thread in self.threads.drain(..) {
            let _ = thread.await;
        }

        // Recursion misses only grow while the programs are attached
        let programs = self.ebpf.as_ref().map(program_stats).unwrap_or_default();
        let duration_s = self
            .started
            .map(|started| started.elapsed().as_secs_f64())
            .unwrap_or_default();

        // Detach all programs so no new records arrive while draining. Dropping the
        // Ebpf object only closes the maps that were not taken by the writer.
        drop(self.ebpf.take());
        if let Some(iface) = self.clsact_iface.take() {
            remove_clsact(&iface);
        }

        // Programs that were already running when they were detached may still submit
        sleep(Duration::from_millis(100)).await;

        if let Some(writer) = self.writer.take() {
            info!("Draining ring buffers and finishing files");
            let reports = spawn_blocking(move || writer.shutdown())
                .await
                .unwrap_or_default();

            for report in &reports {
                match &report.error {
                    Some(err) => error!(
                        "Writer for {} failed after {} records: {}",
                        report.file.display(),
                        report.records,
                        err
                    ),
                    None => info!(
                        "Wrote {} records to {}",
                        report.records,
                        report.file.display()
                    ),
                }
            }
            let records: u64 = reports.iter().map(|r| r.records).sum();
            println!("\nWrote {} records to {}", records, self.config.dir);

            if self.config.metrics {
                self.write_metrics(duration_s, &reports, programs);
            }
        }
    }

    fn write_metrics(&self, duration_s: f64, reports: &[WriterReport], programs: Vec<ProgramStats>) {
        let Some(stats) = &self.stats else {
            return;
        };
        let snapshot = match stats.snapshot() {
            Ok(snapshot) => snapshot,
            Err(err) => {
                error!("Could not read event counters for metrics: {}", err);
                return;
            }
        };

        let metrics = Metrics::new(
            duration_s,
            &snapshot,
            reports,
            &self.ringbuf_sizes,
            programs,
        );
        let path = Path::new(&self.config.dir).join("metrics.json");
        match metrics.write(&path) {
            Ok(()) => println!("Wrote metrics to {}", path.display()),
            Err(err) => error!("Could not write {}: {}", path.display(), err),
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

        let filter_mode = self.config.filter.mode();
        let filter_rules = self.config.filter.rule_flags();
        let flow_tracking = self.config.do_tui as u8;
        let submit_flags = self.config.poll_mode.submit_flags();
        let mut loader = EbpfLoader::new();
        loader
            .override_global("FILTER_PORT", &self.config.filter.single_port, true)
            .override_global("FILTER_MODE", &filter_mode, true)
            .override_global("FILTER_RULE_FLAGS", &filter_rules, true)
            .override_global("FLOW_TRACKING", &flow_tracking, true)
            .override_global("RB_SUBMIT_FLAGS", &submit_flags, true);
        for (name, size) in &self.config.ringbuf_sizes {
            loader.map_max_entries(name, *size);
        }
        let mut ebpf = loader
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/tcbee"
            )))?;
        self.configure_filter(&mut ebpf)?;
        self.ringbuf_sizes = ringbuf_sizes(&ebpf);
        for ((name, _), size) in RINGBUFS.iter().zip(&self.ringbuf_sizes) {
            debug!("Ring buffer {} has {:?} bytes", name, size);
        }


        info!("Starting eBPF probes!");

        // TODO: I feel that the dir should be passed to the writer, and the Tracers should just add the filename

        // This is the backend writer thread that reads and writes data to files
        let mut writer =
            Writer::new(self.config.poll_mode).with_cpu_affinity(self.config.writer_cpus.clone());
        let mut watcher_config = self.config.watcher_config();

        // Tracing for packet headers via TC and XDP
        if self.config.headers {
            let created_clsact = TCTracer::spawn(
                &mut ebpf,
                self.config.iface.clone(),
                self.config.dir.clone(),
                &mut writer,
            )?;
            if created_clsact {
                self.clsact_iface = Some(self.config.iface.clone());
            }

            watcher_config.graphs.packets = true;
        }

        // Tracing kernel metrics via FEntry probe
        if self.config.kernel {
            KernelTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer)?;

            watcher_config.graphs.kernel = true;
        }
        // Performance variant of above hook
        if self.config.cwnd {
            CwndTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer)?;

            watcher_config.graphs.kernel = true;
        }

        // Tracing kernel tracepoints
        if self.config.tracepoints {
            TracepointTracer::spawn::<tcp_probe_entry>(
                &mut ebpf,
                RB_TCP_PROBE,
                self.config.dir.clone(),
                &mut writer,
            )?;

            TracepointTracer::spawn::<tcp_retransmit_synack_entry>(
                &mut ebpf,
                RB_RETRANSMIT_SYNACK,
                self.config.dir.clone(),
                &mut writer,
            )?;

            TracepointTracer::spawn::<tcp_bad_csum_entry>(
                &mut ebpf,
                RB_BAD_CSUM,
                self.config.dir.clone(),
                &mut writer,
            )?;

            watcher_config.graphs.tracepoints = true;
        }

        if self.config.algorithms {
            CubicTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer)?;
            watcher_config.graphs.cubic = true;
            if let Err(err) = BBRTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer) {
                error!(
                    "Failed to initialize BBR Tracer. Is the kernel module loaded? ({})",
                    err
                );
            };
            watcher_config.graphs.bbr = true;
        }

        // TODO: should be true by default in get_watcher_config()
        watcher_config.graphs.events = true;

        // Start watcher thread
        // Stop token is cloned such that cancellation affects all other threads
        let stats = Arc::new(Stats::new(&mut ebpf)?);
        self.stats = Some(stats.clone());
        let mut watcher = EBPFWatcher::new(
            &mut ebpf,
            stats,
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
        self.started = Some(Instant::now());

        Ok(())
    }
}
