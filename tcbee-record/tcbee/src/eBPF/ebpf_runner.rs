use std::{
    error::Error,
    mem::MaybeUninit,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    Link, MapCore, MapFlags, MapHandle, MapMut, PrintLevel,
};
use log::{debug, error, info, warn};
use tcbee_common::stats::{
    RB_BAD_CSUM, RB_BBR, RB_CUBIC, RB_CWND_RECV, RB_CWND_SEND, RB_RETRANSMIT_SYNACK, RB_SOCK_RECV,
    RB_SOCK_SEND, RB_TCP4_EGRESS, RB_TCP4_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS, RB_TCP_PROBE,
    RINGBUFS,
};
use tokio::{
    task::{spawn_blocking, JoinHandle},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

use crate::{
    eBPF::{
        host::KernelBtf,
        probes::{
            bbr::BBRTracer,
            cubic::CubicTracer,
            cwnd::CwndTracer,
            handle,
            headers::{uses_tcx, TCTracer, TcAttachment},
            kernel::KernelTracer,
            tracepoints::TracepointTracer,
        },
        rings,
        skel::{OpenTcbeeSkel, TcbeeSkel, TcbeeSkelBuilder},
    },
    metrics::{program_stats, HookSeqTotals, Metrics, ProgramStats},
    stats::Stats,
    viz::ebpf_watcher::EBPFWatcher,
    writer::{Writer, WriterReport},
};

use super::ebpf_runner_config::{EbpfRunnerConfig, FilterConfig};

// TODO: how to handle multiple tracepoints at the same time?
pub struct EbpfRunner {
    stop_token: CancellationToken,
    threads: Vec<JoinHandle<()>>,
    config: EbpfRunnerConfig,
    skel: Option<TcbeeSkel<'static>>,
    /// Attached fentry and tracepoint programs, dropping a link detaches it
    links: Vec<Link>,
    tc: Option<TcAttachment>,
    writer: Option<Writer>,
    stats: Option<Arc<Stats>>,
    /// The hook_seq counters, read for the metrics after the programs are detached
    hook_seq: Option<MapHandle>,
    /// Size of each CPU's ring buffer, indexed like `RINGBUFS`, None if not created
    ringbuf_sizes: Vec<Option<u32>>,
    /// CPUs with a ring buffer per probe output
    ring_cpus: u32,
    started: Option<Instant>,
}

pub fn prepend_string(filename: String, dir: &str) -> String {
    std::path::Path::new(dir)
        .join(&filename)
        .to_string_lossy()
        .into_owned()
}

/// Last libbpf warnings, shown when loading fails. They name the program, map or the
/// kernel struct field that could not be relocated.
static LIBBPF_WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
const LIBBPF_WARNINGS_KEPT: usize = 20;

fn libbpf_log(level: PrintLevel, msg: String) {
    let msg = msg.trim_end();
    match level {
        PrintLevel::Warn => {
            warn!(target: "libbpf", "{}", msg);
            if let Ok(mut warnings) = LIBBPF_WARNINGS.lock() {
                if warnings.len() == LIBBPF_WARNINGS_KEPT {
                    warnings.remove(0);
                }
                warnings.push(msg.to_string());
            }
        }
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
    }
}

/// Opens the skeleton of the C eBPF object.
///
/// The skeleton borrows the storage of its object for its whole life. The runner keeps
/// it until the program ends, so the storage (a pointer) is leaked to get a 'static
/// skeleton. Dropping the skeleton still closes the object and its programs and maps.
/// At most two are opened (see the BBR retry in `run`), so at most two pointers leak.
fn open_skel() -> libbpf_rs::Result<OpenTcbeeSkel<'static>> {
    let storage = Box::leak(Box::new(MaybeUninit::uninit()));
    TcbeeSkelBuilder::default().open(storage)
}

fn insert_filter_keys<'a>(
    map: &MapMut<'_>,
    keys: impl IntoIterator<Item = &'a [u8]>,
) -> libbpf_rs::Result<()> {
    for key in keys {
        map.update(key, &[1], MapFlags::ANY)?;
    }
    Ok(())
}

fn configure_filter(skel: &TcbeeSkel<'_>, filter: &FilterConfig) -> libbpf_rs::Result<()> {
    let maps = &skel.maps;
    let ports = |ports: &[u16]| ports.iter().map(|p| p.to_ne_bytes()).collect::<Vec<_>>();
    for (map, ports) in [
        (&maps.FILTER_ANY_PORTS, ports(&filter.any_ports)),
        (&maps.FILTER_SRC_PORTS, ports(&filter.src_ports)),
        (&maps.FILTER_DST_PORTS, ports(&filter.dst_ports)),
    ] {
        insert_filter_keys(map, ports.iter().map(|p| p.as_slice()))?;
    }
    // The key is struct filter_ip, just the 16 address bytes
    for (map, ips) in [
        (&maps.FILTER_ANY_IPS, &filter.any_ips),
        (&maps.FILTER_SRC_IPS, &filter.src_ips),
        (&maps.FILTER_DST_IPS, &filter.dst_ips),
    ] {
        insert_filter_keys(map, ips.iter().map(|ip| ip.as_slice()))?;
    }
    Ok(())
}

/// Loads the programs and maps into the kernel. libbpf relocates all kernel struct
/// accesses against the BTF of the running kernel here, a field that does not exist
/// fails the load instead of reading garbage. The error includes the last libbpf
/// warnings, they name the program, map or field that failed.
///
/// On failure the object is closed, which also closes every program and map it had
/// already created in the kernel.
fn load(open: OpenTcbeeSkel<'static>) -> Result<TcbeeSkel<'static>, String> {
    if let Ok(mut warnings) = LIBBPF_WARNINGS.lock() {
        warnings.clear();
    }
    open.load().map_err(|err| {
        let warnings = LIBBPF_WARNINGS
            .lock()
            .map(|warnings| warnings.join("\n"))
            .unwrap_or_default();
        format!("Could not load the eBPF programs: {}\n{}", err, warnings)
    })
}

/// Ring buffers that the enabled probe groups write to
fn enabled_ringbufs(config: &EbpfRunnerConfig, bbr: bool) -> Vec<u32> {
    let groups: [(bool, &[u32]); 6] = [
        (
            config.headers,
            &[
                RB_TCP4_EGRESS,
                RB_TCP4_INGRESS,
                RB_TCP6_EGRESS,
                RB_TCP6_INGRESS,
            ],
        ),
        (config.kernel, &[RB_SOCK_SEND, RB_SOCK_RECV]),
        (config.cwnd, &[RB_CWND_SEND, RB_CWND_RECV]),
        (
            config.tracepoints,
            &[RB_TCP_PROBE, RB_RETRANSMIT_SYNACK, RB_BAD_CSUM],
        ),
        (config.algorithms, &[RB_CUBIC]),
        (config.algorithms && bbr, &[RB_BBR]),
    ];
    groups
        .into_iter()
        .filter(|(enabled, _)| *enabled)
        .flat_map(|(_, rbs)| rbs.iter().copied())
        .collect()
}

impl EbpfRunner {
    // Load eBPF program and setup references
    pub fn new(stop_token: CancellationToken, config: EbpfRunnerConfig) -> EbpfRunner {
        EbpfRunner {
            stop_token,
            // TODO: new with capacity?
            threads: Vec::new(),
            config,
            skel: None,
            links: Vec::new(),
            tc: None,
            writer: None,
            stats: None,
            hook_seq: None,
            ringbuf_sizes: Vec::new(),
            ring_cpus: 0,
            started: None,
        }
    }

    pub async fn stop(mut self) {
        // Signal child threads to stop
        self.stop_token.cancel();

        // Wait for the watcher, it restores the terminal
        for thread in self.threads.drain(..) {
            let _ = thread.await;
        }

        // Recursion misses only grow while the programs are attached
        let programs = self
            .skel
            .as_ref()
            .map(|skel| program_stats(skel.object()))
            .unwrap_or_default();
        let duration_s = self
            .started
            .map(|started| started.elapsed().as_secs_f64())
            .unwrap_or_default();

        // Detach all programs so no new records arrive while draining. The writer, the
        // stats and the TUI hold their own map handles, so the maps stay open after the
        // object is closed.
        self.links.clear();
        if let Some(tc) = self.tc.take() {
            tc.detach();
        }
        drop(self.skel.take());

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

    fn write_metrics(
        &self,
        duration_s: f64,
        reports: &[WriterReport],
        programs: Vec<ProgramStats>,
    ) {
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
        let hook_seq = self.hook_seq.as_ref().and_then(|map| {
            HookSeqTotals::read(map)
                .inspect_err(|err| error!("Could not read the hook_seq counters: {}", err))
                .ok()
        });

        let metrics = Metrics::new(
            duration_s,
            &snapshot,
            reports,
            &self.ringbuf_sizes,
            self.ring_cpus,
            programs,
            hook_seq.as_ref(),
        );
        let path = Path::new(&self.config.dir).join("metrics.json");
        match metrics.write(&path) {
            Ok(()) => println!("Wrote metrics to {}", path.display()),
            Err(err) => error!("Could not write {}: {}", path.display(), err),
        }
    }

    /// Opens the skeleton and configures it from the config: rodata constants, one ring
    /// buffer slot per CPU and which programs are loaded. BBR is only loaded if `with_bbr` is
    /// set. Returns the skeleton and whether BBR is enabled.
    fn open_configured(
        &self,
        tcx: bool,
        with_bbr: bool,
        btf: &mut KernelBtf,
        cpus: &rings::Cpus,
    ) -> Result<(OpenTcbeeSkel<'static>, bool), Box<dyn Error>> {
        let mut open = open_skel()?;

        // Configuration is read-only for the programs, so the verifier sees constants
        let rodata = open
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or("eBPF object has no .rodata section")?;
        rodata.FILTER_PORT = self.config.filter.single_port;
        rodata.FILTER_MODE = self.config.filter.mode();
        rodata.FILTER_RULE_FLAGS = self.config.filter.rule_flags();
        rodata.FLOW_TRACKING = self.config.do_tui as u8;
        rodata.RB_SUBMIT_FLAGS = self.config.poll_mode.submit_flags();

        rings::set_slots(open.open_object_mut(), cpus)?;

        // A skeleton loads all programs, the ones of disabled groups must be switched off.
        // Their attach targets may not even exist on this kernel.
        TCTracer::configure(&mut open.progs, self.config.headers, tcx);
        KernelTracer::configure(&mut open.progs, self.config.kernel);
        CwndTracer::configure(&mut open.progs, self.config.cwnd);
        TracepointTracer::configure(&mut open.progs, self.config.tracepoints);
        CubicTracer::configure(&mut open.progs, self.config.algorithms, btf)?;
        let bbr = BBRTracer::configure(&mut open.progs, self.config.algorithms && with_bbr, btf);
        Ok((open, bbr))
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        env_logger::init();
        libbpf_rs::set_print(Some((PrintLevel::Debug, libbpf_log)));

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

        // A skeleton loads all programs at once, so one program that the kernel rejects
        // fails all of them. BBR is optional (it may be an out-of-tree variant with other
        // struct fields), so if loading fails with BBR, it is tried once more without.
        let tcx = self.config.headers && uses_tcx();
        let cpus = rings::Cpus::get()?;
        let mut btf = KernelBtf::default();
        let (open, mut bbr) = self.open_configured(tcx, true, &mut btf, &cpus)?;
        let skel = match load(open) {
            Ok(skel) => skel,
            Err(err) if bbr => {
                error!("{}\nRetrying without the BBR programs", err);
                // The failed object was closed when load() returned, its programs and
                // maps are gone
                let (open, _) = self.open_configured(tcx, false, &mut btf, &cpus)?;
                bbr = false;
                load(open)?
            }
            Err(err) => return Err(err.into()),
        };
        drop(btf);
        let skel = self.skel.insert(skel);
        configure_filter(skel, &self.config.filter)?;

        // The ring buffers exist before any program is attached, so no event finds its
        // CPU's ring missing. Records submitted before a writer starts wait in the ring.
        let enabled = enabled_ringbufs(&self.config, bbr);
        let size = |rb: u32| self.config.ringbuf_size(rb);
        rings::create(skel.object(), &enabled, size, &cpus)?;
        self.ring_cpus = cpus.online.len() as u32;
        self.ringbuf_sizes = (0..RINGBUFS.len() as u32)
            .map(|rb| enabled.contains(&rb).then(|| size(rb)))
            .collect();
        for (ringbuf, size) in RINGBUFS.iter().zip(&self.ringbuf_sizes) {
            debug!("Ring buffer {} has {:?} bytes per CPU", ringbuf.map, size);
        }

        info!("Starting eBPF probes!");

        // TODO: I feel that the dir should be passed to the writer, and the Tracers should just add the filename

        // This is the backend writer thread that reads and writes data to files. It is
        // kept in self right away, so that stop() detaches the programs before draining
        // the writers if starting fails below.
        let writer = self.writer.insert(
            Writer::new(self.config.poll_mode).with_cpu_affinity(self.config.writer_cpus.clone()),
        );
        self.started = Some(Instant::now());
        let mut watcher_config = self.config.watcher_config();
        let dir = self.config.dir.as_str();
        let links = &mut self.links;

        // Tracing for packet headers via TC
        if self.config.headers {
            TCTracer::spawn(skel, &self.config.iface, dir, writer, tcx, &mut self.tc)?;

            watcher_config.graphs.packets = true;
        }

        // Tracing kernel metrics via FEntry probe
        if self.config.kernel {
            KernelTracer::spawn(skel, dir, writer, links)?;

            watcher_config.graphs.kernel = true;
        }
        // Performance variant of above hook
        if self.config.cwnd {
            CwndTracer::spawn(skel, dir, writer, links)?;

            watcher_config.graphs.kernel = true;
        }

        // Tracing kernel tracepoints
        if self.config.tracepoints {
            TracepointTracer::spawn(skel, dir, writer, links)?;

            watcher_config.graphs.tracepoints = true;
        }

        if self.config.algorithms {
            CubicTracer::spawn(skel, dir, writer, links)?;
            watcher_config.graphs.cubic = true;
            if bbr {
                // BBR fails softly, so a program that was attached before the error has
                // to be detached here. Other groups fail the start, stop() detaches them.
                let attached = links.len();
                match BBRTracer::spawn(skel, dir, writer, links) {
                    Ok(()) => watcher_config.graphs.bbr = true,
                    Err(err) => {
                        links.truncate(attached);
                        error!(
                            "Failed to initialize BBR Tracer. Is the kernel module loaded? ({})",
                            err
                        );
                    }
                }
            }
        }

        // TODO: should be true by default in get_watcher_config()
        watcher_config.graphs.events = true;

        // Start watcher thread
        // Stop token is cloned such that cancellation affects all other threads
        let stats = Arc::new(Stats::new(handle(&skel.maps.STATS)?));
        self.hook_seq = Some(handle(&skel.maps.HOOK_SEQ)?);
        self.stats = Some(stats.clone());
        let bytes_written = writer.bytes_written();
        let mut watcher = EBPFWatcher::new(
            handle(&skel.maps.FLOWS)?,
            stats,
            bytes_written,
            self.config.update_period,
            self.stop_token.clone(),
            watcher_config,
            self.config.do_tui,
        )?;

        self.threads.push(spawn_blocking(move || {
            watcher.run();
        }));

        info!("Finished starting TUI!");

        Ok(())
    }
}
