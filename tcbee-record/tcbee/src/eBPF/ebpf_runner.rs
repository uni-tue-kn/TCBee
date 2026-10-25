use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    mem::MaybeUninit,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    Link, MapCore, MapFlags, MapHandle, MapMut, PrintLevel,
};
use log::{debug, error, info, log, warn};
use tcbee_common::stats::{
    RB_BAD_CSUM, RB_BBR, RB_CUBIC, RB_CWND_RECV, RB_CWND_SEND, RB_MPTCP_PM, RB_RENO,
    RB_RETRANSMIT_SYNACK, RB_SOCK_EVENT, RB_SOCK_INGRESS, RB_SOCK_RECV, RB_SOCK_SEND,
    RB_SOCK_TIMER, RB_TCP4_DRIVER_EGRESS, RB_TCP4_DRIVER_INGRESS, RB_TCP4_EGRESS, RB_TCP4_INGRESS,
    RB_TCP6_DRIVER_EGRESS, RB_TCP6_DRIVER_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS, RB_TCP_EVENTS,
    RB_TCP_PROBE, RINGBUFS,
};
use tokio::{
    task::{spawn_blocking, JoinHandle},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

use crate::{
    eBPF::{
        host::KernelBtf,
        optional::{self, OptionalGroup},
        probes::{
            bbr::BBRTracer,
            cubic::CubicTracer,
            cwnd::CwndTracer,
            handle,
            headers::{
                check_offloads, if_index, uses_tcx, DriverTracer, TCTracer, TcAttachment, XdpLink,
            },
            kernel::KernelTracer,
            mptcp::MptcpPmTracer,
            reno::RenoTracer,
            sock_events::SockEventTracer,
            tcp_events::TcpEventTracer,
            tracepoints::{Tracepoint, TracepointTracer},
        },
        rings,
        skel::{OpenTcbeeSkel, TcbeeSkel, TcbeeSkelBuilder},
    },
    metadata::{NamedRingCounters, Offloads, Recorder, RunMetadata},
    metrics::{program_stats, HookSeqTotals, Metrics, ProgramStats, RingCounters},
    stats::Stats,
    viz::ebpf_watcher::EBPFWatcher,
    writer::{Writer, WriterReport},
};
use tcbee_trace::sock_hooks::Hook;

use super::ebpf_runner_config::{EbpfRunnerConfig, FilterConfig, MptcpModes};

// TODO: how to handle multiple tracepoints at the same time?
pub struct EbpfRunner {
    stop_token: CancellationToken,
    threads: Vec<JoinHandle<()>>,
    config: EbpfRunnerConfig,
    skel: Option<TcbeeSkel<'static>>,
    /// Attached fentry and tracepoint programs, dropping a link detaches it
    links: Vec<Link>,
    tc: Option<TcAttachment>,
    /// The XDP program of the driver header hook, detached when dropped
    xdp: Option<XdpLink>,
    writer: Option<Writer>,
    stats: Option<Arc<Stats>>,
    /// The hook_seq counters, read for the metrics after the programs are detached
    hook_seq: Option<MapHandle>,
    /// Size of each CPU's ring buffer, indexed like `RINGBUFS`, None if not created
    ringbuf_sizes: Vec<Option<u32>>,
    /// CPUs with a ring buffer per probe output
    ring_cpus: u32,
    started: Option<Instant>,
    /// Requested hooks that are not recorded, with the reason, for the run metadata
    skipped: Vec<String>,
    /// Written at start and completed at stop with `--metadata`
    metadata: Option<RunMetadata>,
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
/// It is opened once per load attempt (see `run`), so at most one pointer per optional
/// group and one more leak.
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

/// A failed load with the last libbpf warnings, they name the program, map or field that
/// failed.
struct LoadError {
    error: libbpf_rs::Error,
    warnings: Vec<String>,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Could not load the eBPF programs: {}\n{}",
            self.error,
            self.warnings.join("\n")
        )
    }
}

/// Loads the programs and maps into the kernel. libbpf relocates all kernel struct
/// accesses against the BTF of the running kernel here, a field that does not exist
/// fails the load instead of reading garbage.
///
/// On failure the object is closed, which also closes every program and map it had
/// already created in the kernel.
fn load(open: OpenTcbeeSkel<'static>) -> Result<TcbeeSkel<'static>, LoadError> {
    if let Ok(mut warnings) = LIBBPF_WARNINGS.lock() {
        warnings.clear();
    }
    open.load().map_err(|error| LoadError {
        error,
        warnings: LIBBPF_WARNINGS
            .lock()
            .map(|warnings| warnings.clone())
            .unwrap_or_default(),
    })
}

/// -k without on-change has only optional hooks unless a per-packet one was asked for. False
/// if the kernel lacks or rejected all of them and -k records nothing, an error if -k is the
/// only thing to record.
fn sock_hooks_left(
    config: &EbpfRunnerConfig,
    optional: &BTreeSet<OptionalGroup>,
) -> Result<bool, Box<dyn Error>> {
    let Some(hooks) = config.sock_hooks else {
        return Ok(true);
    };
    let left = hooks.hooks().any(Hook::per_packet)
        || optional
            .iter()
            .any(|group| *group == OptionalGroup::SockTimer || group.is_sock_event());
    let others = config.headers
        || !config.tracepoints.is_empty()
        || config.cwnd
        || config.algorithms
        || config.mptcp.pm;
    if !left && !others {
        return Err("-k has no hook left in this kernel, it would record nothing".into());
    }
    Ok(left)
}

/// Ring buffers that the enabled probe groups write to
fn enabled_ringbufs(config: &EbpfRunnerConfig, optional: &BTreeSet<OptionalGroup>) -> Vec<u32> {
    let tcp_events = optional.iter().any(|group| group.is_tcp_event());
    let sock_events = optional.iter().any(|group| group.is_sock_event());
    // In on-change mode, the hooks decide which of the send and receive rings are written;
    // without, the sock probe's hooks and every cwnd hook
    let (send, receive) = config
        .on_change
        .map_or((true, true), |o| (o.hooks.send(), o.hooks.receive()));
    let (sock_send, sock_receive) = match config.on_change {
        Some(_) => (send, receive),
        None => (
            config.sock_hooked(Hook::Egress),
            config.sock_hooked(Hook::IngressEntry),
        ),
    };
    let groups: [(bool, &[u32]); 17] = [
        (
            config.headers && config.headers_at.tc,
            &[
                RB_TCP4_EGRESS,
                RB_TCP4_INGRESS,
                RB_TCP6_EGRESS,
                RB_TCP6_INGRESS,
            ],
        ),
        (
            config.headers && config.headers_at.driver,
            &[
                RB_TCP4_DRIVER_INGRESS,
                RB_TCP6_DRIVER_INGRESS,
                RB_TCP4_DRIVER_EGRESS,
                RB_TCP6_DRIVER_EGRESS,
            ],
        ),
        (config.kernel && sock_send, &[RB_SOCK_SEND]),
        (config.kernel && sock_receive, &[RB_SOCK_RECV]),
        (config.sock_hooked(Hook::Ingress), &[RB_SOCK_INGRESS]),
        (
            optional.contains(&OptionalGroup::SockTimer),
            &[RB_SOCK_TIMER],
        ),
        (config.cwnd && send, &[RB_CWND_SEND]),
        (config.cwnd && receive, &[RB_CWND_RECV]),
        (
            config.tracepoints.contains(Tracepoint::Probe),
            &[RB_TCP_PROBE],
        ),
        (
            config.tracepoints.contains(Tracepoint::Synack),
            &[RB_RETRANSMIT_SYNACK],
        ),
        (
            config.tracepoints.contains(Tracepoint::BadCsum),
            &[RB_BAD_CSUM],
        ),
        (config.algorithms, &[RB_CUBIC]),
        (optional.contains(&OptionalGroup::Bbr), &[RB_BBR]),
        (optional.contains(&OptionalGroup::MptcpPm), &[RB_MPTCP_PM]),
        (tcp_events, &[RB_TCP_EVENTS]),
        (sock_events, &[RB_SOCK_EVENT]),
        (optional.contains(&OptionalGroup::Reno), &[RB_RENO]),
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
            xdp: None,
            writer: None,
            stats: None,
            hook_seq: None,
            ringbuf_sizes: Vec::new(),
            ring_cpus: 0,
            started: None,
            skipped: Vec::new(),
            metadata: None,
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
        drop(self.xdp.take());
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

        if self.config.headers {
            self.warn_aggregated();
        }

        if let Some(mut metadata) = self.metadata.take() {
            metadata.finish(self.ring_counters());
            self.write_metadata(&metadata);
        }
    }

    /// Tells at the end of the run how many packets the header hooks saw as one that stand for
    /// several segments
    fn warn_aggregated(&self) {
        let Some(snapshot) = self.stats.as_ref().and_then(|stats| stats.snapshot().ok()) else {
            return;
        };
        let hooks = [
            ("TC egress", [RB_TCP4_EGRESS, RB_TCP6_EGRESS]),
            ("TC ingress", [RB_TCP4_INGRESS, RB_TCP6_INGRESS]),
            (
                "net_dev_start_xmit",
                [RB_TCP4_DRIVER_EGRESS, RB_TCP6_DRIVER_EGRESS],
            ),
            ("XDP", [RB_TCP4_DRIVER_INGRESS, RB_TCP6_DRIVER_INGRESS]),
        ];
        for (hook, rbs) in hooks {
            let aggregated: u64 = rbs.iter().map(|rb| snapshot.aggregated(*rb)).sum();
            if aggregated == 0 {
                continue;
            }
            let packets: u64 = rbs.iter().map(|rb| snapshot.invocations(*rb)).sum();
            eprintln!(
                "Warning: {aggregated} of the {packets} packets at {hook} were aggregated \
                 (GSO, GRO or LRO); each of their header records stands for several segments"
            );
        }
    }

    /// The event counters of the ring buffers that were created
    fn ring_counters(&self) -> Option<Vec<NamedRingCounters>> {
        let snapshot = self
            .stats
            .as_ref()?
            .snapshot()
            .inspect_err(|err| error!("Could not read event counters for metadata: {}", err))
            .ok()?;
        Some(
            RINGBUFS
                .iter()
                .zip(&self.ringbuf_sizes)
                .enumerate()
                .filter(|(_, (_, size))| size.is_some())
                .map(|(rb, (ringbuf, _))| NamedRingCounters {
                    name: ringbuf.map.to_string(),
                    counters: RingCounters::of(&snapshot, rb as u32),
                })
                .collect(),
        )
    }

    fn write_metadata(&self, metadata: &RunMetadata) {
        let path = Path::new(&self.config.dir).join(tcbee_trace::METADATA_FILE);
        if let Err(err) = metadata.write(&path) {
            error!("Could not write {}: {}", path.display(), err);
        }
    }

    /// Writes the kernel's drop reasons, value to name without the SKB_DROP_REASON_ prefix
    fn write_drop_reasons(&self, btf: &mut KernelBtf) {
        let reasons: BTreeMap<String, String> = btf
            .enum_values("skb_drop_reason")
            .into_iter()
            .map(|(value, name)| {
                let name = name.strip_prefix("SKB_DROP_REASON_").unwrap_or(&name);
                (value.to_string(), name.to_string())
            })
            .collect();
        if reasons.is_empty() {
            warn!("The kernel has no drop reasons (before 5.17), drops are recorded without");
            return;
        }
        let path = Path::new(&self.config.dir).join(tcbee_trace::DROP_REASONS_FILE);
        let written = fs::File::create(&path).and_then(|file| {
            serde_json::to_writer_pretty(file, &reasons).map_err(std::io::Error::from)
        });
        if let Err(err) = written {
            error!("Could not write {}: {}", path.display(), err);
        }
    }

    /// Collects the run metadata once everything is attached
    fn collect_metadata(&self, optional: &BTreeSet<OptionalGroup>) -> RunMetadata {
        let c = &self.config;
        let mut groups: Vec<String> = [
            (c.headers, "headers"),
            (c.kernel, "kernel"),
            (c.cwnd, "cwnd"),
            (
                c.tracepoints.intersects(TracepointTracer::TRACEPOINTS),
                "tracepoints",
            ),
            (c.algorithms, "cubic"),
        ]
        .into_iter()
        .filter(|(enabled, _)| *enabled)
        .map(|(_, name)| name.to_string())
        .collect();
        groups.extend(optional.iter().map(|group| group.name().to_string()));
        if c.headers {
            let at = c.headers_at;
            let hooks = [(at.tc, "tc"), (at.driver, "driver")]
                .into_iter()
                .filter_map(|(on, name)| on.then_some(name));
            groups.push(format!(
                "headers at: {}",
                hooks.collect::<Vec<_>>().join(", ")
            ));
        }
        if let Some(hooks) = c.sock_hooks {
            let hooks: Vec<_> = hooks.hooks().map(|hook| hook.name()).collect();
            groups.push(format!("sock hooks: {}", hooks.join(", ")));
        }
        if let Some(on_change) = c.on_change.filter(|_| c.kernel || c.cwnd) {
            let hooks: Vec<_> = on_change.hooks.hooks().map(|hook| hook.name()).collect();
            groups.push(format!("on-change: {}", hooks.join(", ")));
        }
        RunMetadata::collect(Recorder {
            argv: std::env::args().collect(),
            groups,
            skipped: self.skipped.clone(),
            interface: c.headers.then(|| c.iface.clone()),
            ringbuf_sizes: RINGBUFS
                .iter()
                .zip(&self.ringbuf_sizes)
                .filter_map(|(ringbuf, size)| Some((ringbuf.map.to_string(), (*size)?)))
                .collect(),
        })
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
    /// buffer slot per CPU and which programs are loaded. The optional groups in `disabled`
    /// are not loaded. Returns the skeleton, the enabled optional groups and the requested
    /// hooks that the kernel lacks.
    fn open_configured(
        &self,
        tcx: bool,
        disabled: &BTreeSet<OptionalGroup>,
        btf: &mut KernelBtf,
        cpus: &rings::Cpus,
    ) -> Result<(OpenTcbeeSkel<'static>, BTreeSet<OptionalGroup>, Vec<String>), Box<dyn Error>>
    {
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
        let mptcp_tag = self.config.mptcp.tag && !disabled.contains(&OptionalGroup::MptcpTag);
        rodata.MPTCP_TAG = mptcp_tag as u8;
        if self.config.headers && self.config.headers_at.driver {
            rodata.HEADERS_IFINDEX = if_index(&self.config.iface)? as u32;
            rodata.HEADERS_NETNS = DriverTracer::netns()?;
            rodata.HEADERS_MTU = DriverTracer::mtu(&self.config.iface)?;
        }
        if let Some(on_change) = self.config.on_change {
            rodata.SOCK_WATCH_MASK = on_change.watch.mask();
            rodata.ONCHG_SHADOW = on_change.shadow as u8;
        }
        let on_change = self.config.on_change.map(|o| o.hooks);
        let on_change_probes = self.config.kernel || self.config.cwnd;
        if let Some(hooks) = on_change.filter(|_| on_change_probes && btf.available()) {
            // Every hook must exist, or the whole skeleton fails to load
            for hook in hooks.hooks() {
                for target in hook.kernel_hooks() {
                    let func = target.split_once('/').map_or(*target, |(_, func)| func);
                    if btf.find_func(None, &[func]).is_none() {
                        return Err(format!(
                            "--on-change-hooks {}: the kernel has no {}, choose other hooks",
                            hook.name(),
                            func
                        )
                        .into());
                    }
                }
            }
        }

        rings::set_slots(open.open_object_mut(), cpus)?;

        // A skeleton loads all programs, the ones of disabled groups must be switched off.
        // Their attach targets may not even exist on this kernel.
        let headers_at = self.config.headers_at;
        TCTracer::configure(&mut open.progs, self.config.headers && headers_at.tc, tcx);
        DriverTracer::configure(&mut open.progs, self.config.headers && headers_at.driver);
        // The write timer program of -k fails softly: without the function or if the kernel
        // rejects it, the recording runs without it
        let timer_wanted =
            self.config.sock_hooked(Hook::Timer) && !disabled.contains(&OptionalGroup::SockTimer);
        let has_timer = !btf.available() || btf.has_func(None, "tcp_write_timer_handler");
        let timer =
            KernelTracer::timer_hook(self.config.kernel, on_change, timer_wanted, has_timer);
        KernelTracer::configure(
            &mut open.progs,
            self.config.kernel,
            on_change,
            self.config.sock_hooks,
            timer,
        );
        CwndTracer::configure(&mut open.progs, self.config.cwnd, on_change);
        TracepointTracer::configure(&mut open.progs, self.config.tracepoints);
        let (cubic_hooks, missing_cubic) =
            CubicTracer::configure(&mut open, self.config.algorithms, disabled, btf)?;
        let mut optional =
            BTreeSet::from_iter(cubic_hooks.into_iter().map(OptionalGroup::CubicHook));
        if mptcp_tag {
            optional.insert(OptionalGroup::MptcpTag);
        }
        let bbr = self.config.algorithms && !disabled.contains(&OptionalGroup::Bbr);
        if BBRTracer::configure(&mut open.progs, bbr, btf) {
            optional.insert(OptionalGroup::Bbr);
        }
        let (reno, missing_reno) = RenoTracer::configure(
            open.open_object_mut(),
            self.config.algorithms,
            disabled,
            btf,
        );
        if reno {
            optional.insert(OptionalGroup::Reno);
        }
        if timer {
            optional.insert(OptionalGroup::SockTimer);
        }
        let pm = self.config.mptcp.pm && !disabled.contains(&OptionalGroup::MptcpPm);
        let (any_pm, mut missing) = MptcpPmTracer::configure(open.open_object_mut(), pm, btf);
        if !has_timer && KernelTracer::timer_hook(self.config.kernel, on_change, timer_wanted, true)
        {
            missing.push("write timer hook: the kernel has no tcp_write_timer_handler".to_string());
        }
        if any_pm {
            optional.insert(OptionalGroup::MptcpPm);
        }
        missing.extend(missing_cubic);
        missing.extend(missing_reno);
        let (hooks, missing_events) = TcpEventTracer::configure(
            open.open_object_mut(),
            self.config.tracepoints,
            disabled,
            btf,
        );
        optional.extend(hooks.into_iter().map(OptionalGroup::TcpEvent));
        missing.extend(missing_events);
        let (hooks, missing_sock_events) = SockEventTracer::configure(
            open.open_object_mut(),
            self.config.sock_hooks,
            disabled,
            btf,
        );
        optional.extend(hooks.into_iter().map(OptionalGroup::SockEvent));
        missing.extend(missing_sock_events);
        Ok((open, optional, missing))
    }

    /// Without MPTCP in the kernel, -m records nothing: a warning, or an error if it is the
    /// only thing to record. The kernel has struct mptcp_sock whenever it has MPTCP; missing
    /// path manager functions are handled per hook.
    fn check_kernel_mptcp(&mut self, btf: &mut KernelBtf) -> Result<(), Box<dyn Error>> {
        let wanted = self.config.mptcp.tag || self.config.mptcp.pm;
        if !wanted {
            return Ok(());
        }
        if !btf.available() || btf.has_struct("mptcp_sock") {
            let modes = &self.config.mptcp;
            info!(
                "Recording MPTCP:{}{}",
                if modes.pm { " path manager events" } else { "" },
                if modes.tag { " connection tags" } else { "" }
            );
            return Ok(());
        }
        let c = &self.config;
        if !(c.headers || !c.tracepoints.is_empty() || c.kernel || c.cwnd || c.algorithms) {
            return Err("The kernel has no MPTCP (CONFIG_MPTCP), -m has nothing to record".into());
        }
        warn!("The kernel has no MPTCP (CONFIG_MPTCP), -m records nothing");
        self.config.mptcp = MptcpModes::default();
        Ok(())
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

        // If loading fails in an optional group, the object is opened again without that
        // group. Every retry disables at least one more group, so this ends.
        let tcx = self.config.headers && self.config.headers_at.tc && uses_tcx();
        let cpus = rings::Cpus::get()?;
        let mut btf = KernelBtf::default();
        self.check_kernel_mptcp(&mut btf)?;
        if self.config.headers {
            let iface = &self.config.iface;
            let offloads = Offloads::read(iface);
            for (level, message) in check_offloads(iface, self.config.headers_at, &offloads)? {
                log!(level, "{}", message);
            }
        }
        let mut disabled = BTreeSet::new();
        let (skel, mut optional, missing) = loop {
            let (open, optional, missing) =
                self.open_configured(tcx, &disabled, &mut btf, &cpus)?;
            match load(open) {
                Ok(skel) => break (skel, optional, missing),
                Err(err) => match optional::to_disable(&optional, &err.warnings) {
                    Some(groups) => {
                        // The failed object was closed when load() returned, its programs
                        // and maps are gone
                        error!("{}\nRetrying without {}", err, optional::names(&groups));
                        disabled.extend(groups);
                    }
                    None => return Err(err.to_string().into()),
                },
            }
        };
        if self.config.tracepoints.contains(Tracepoint::Drops) {
            self.write_drop_reasons(&mut btf);
        }
        drop(btf);
        self.skipped.extend(missing);
        for group in &disabled {
            self.skipped.push(format!(
                "{}: the kernel rejected its programs",
                group.name()
            ));
        }
        if self
            .config
            .sock_hooks
            .is_some_and(|hooks| !hooks.contains(Hook::Timer))
        {
            self.skipped
                .push("write timer hook: off (--sock-hooks, --no-timer-hook)".to_string());
        }
        if self.config.algorithms
            && !optional.contains(&OptionalGroup::Bbr)
            && !disabled.contains(&OptionalGroup::Bbr)
        {
            self.skipped.push("BBR: tcp_bbr is not loaded".to_string());
        }
        let skel = self.skel.insert(skel);
        configure_filter(skel, &self.config.filter)?;

        // The ring buffers exist before any program is attached, so no event finds its
        // CPU's ring missing. Records submitted before a writer starts wait in the ring.
        let enabled = enabled_ringbufs(&self.config, &optional);
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

        // Tracing for packet headers via TC and in the driver
        if self.config.headers && self.config.headers_at.tc {
            TCTracer::spawn(skel, &self.config.iface, dir, writer, tcx, &mut self.tc)?;
        }
        if self.config.headers && self.config.headers_at.driver {
            DriverTracer::spawn(skel, &self.config.iface, dir, writer, links, &mut self.xdp)?;
        }
        if self.config.headers {
            watcher_config.graphs.packets = true;
        }

        // Tracing kernel metrics via FEntry probe
        if self.config.kernel {
            KernelTracer::spawn(
                skel,
                dir,
                writer,
                links,
                self.config.on_change.map(|o| o.hooks),
                self.config.sock_hooks,
            )?;

            watcher_config.graphs.kernel = true;
        }
        // Performance variant of above hook
        if self.config.cwnd {
            CwndTracer::spawn(
                skel,
                dir,
                writer,
                links,
                self.config.on_change.map(|o| o.hooks),
            )?;

            watcher_config.graphs.kernel = true;
        }

        // Tracing kernel tracepoints
        let tracepoints = self.config.tracepoints;
        if tracepoints.intersects(TracepointTracer::TRACEPOINTS) {
            TracepointTracer::spawn(skel, tracepoints, dir, writer, links)?;

            watcher_config.graphs.tracepoints = true;
        }

        if self.config.algorithms {
            for (hook, message) in CubicTracer::spawn(skel, dir, writer, links)? {
                optional.remove(&OptionalGroup::CubicHook(hook));
                self.skipped.push(message);
            }
            watcher_config.graphs.cubic = true;
            if optional.contains(&OptionalGroup::Bbr) {
                // BBR fails softly, so a program that was attached before the error has
                // to be detached here. Other groups fail the start, stop() detaches them.
                let attached = links.len();
                match BBRTracer::spawn(skel, dir, writer, links) {
                    Ok(()) => watcher_config.graphs.bbr = true,
                    Err(err) => {
                        links.truncate(attached);
                        // Its ring exists but holds nothing, like the timer's below
                        self.ringbuf_sizes[RB_BBR as usize] = None;
                        self.skipped.push(format!("BBR: attaching failed: {}", err));
                        error!(
                            "Failed to initialize BBR Tracer. Is the kernel module loaded? ({})",
                            err
                        );
                    }
                }
            }
        }

        if optional.contains(&OptionalGroup::Reno) {
            if let Some(message) = RenoTracer::spawn(skel, dir, writer, links)? {
                optional.remove(&OptionalGroup::Reno);
                // Its ring exists but holds nothing, like the TCP events' below
                self.ringbuf_sizes[RB_RENO as usize] = None;
                self.skipped.push(message);
            }
        }

        if optional.contains(&OptionalGroup::MptcpPm) {
            MptcpPmTracer::spawn(skel, dir, writer, links)?;
        }

        if optional.iter().any(|group| group.is_tcp_event()) {
            for (hook, message) in TcpEventTracer::spawn(skel, dir, writer, links)? {
                optional.remove(&OptionalGroup::TcpEvent(hook));
                self.skipped.push(message);
            }
            if !optional.iter().any(|group| group.is_tcp_event()) {
                // Its ring exists but holds nothing, like the socket events' below
                self.ringbuf_sizes[RB_TCP_EVENTS as usize] = None;
            }
        }

        if optional.iter().any(|group| group.is_sock_event()) {
            for (hook, message) in SockEventTracer::spawn(skel, dir, writer, links)? {
                optional.remove(&OptionalGroup::SockEvent(hook));
                self.skipped.push(message);
            }
            if !optional.iter().any(|group| group.is_sock_event()) {
                // Its ring exists but holds nothing, like the timer's below
                self.ringbuf_sizes[RB_SOCK_EVENT as usize] = None;
            }
        }

        // Last, so the other writers keep their writer CPUs. Fails softly like BBR.
        if optional.contains(&OptionalGroup::SockTimer) {
            let attached = links.len();
            if let Err(err) = KernelTracer::spawn_timer(skel, dir, writer, links) {
                links.truncate(attached);
                optional.remove(&OptionalGroup::SockTimer);
                // Its ring exists but holds nothing, the metadata lists only the rings in use
                self.ringbuf_sizes[RB_SOCK_TIMER as usize] = None;
                self.skipped
                    .push(format!("write timer hook: attaching failed: {}", err));
                warn!("Recording without the write timer hook: {}", err);
            }
        }

        if !sock_hooks_left(&self.config, &optional)? {
            warn!("-k has no hook left in this kernel and records nothing");
            self.skipped
                .push("-k: no hook left in this kernel".to_string());
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

        if self.config.metadata {
            let metadata = self.collect_metadata(&optional);
            self.write_metadata(&metadata);
            self.metadata = Some(metadata);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tcbee_trace::sock_hooks::HookSet;

    use crate::eBPF::ebpf_runner_config::parse_on_change;

    #[test]
    fn timer_ring_follows_the_timer_group() {
        let config = EbpfRunnerConfig::new().kernel(true);
        let none = BTreeSet::new();
        let timer = BTreeSet::from([OptionalGroup::SockTimer]);
        assert!(!enabled_ringbufs(&config, &none).contains(&RB_SOCK_TIMER));
        assert!(enabled_ringbufs(&config, &timer).contains(&RB_SOCK_TIMER));
        let on_change = parse_on_change("cc", "", false, true, false).unwrap();
        let config = EbpfRunnerConfig::new().kernel(true).on_change(on_change);
        let rings = enabled_ringbufs(&config, &none);
        assert!(rings.contains(&RB_SOCK_RECV) && !rings.contains(&RB_SOCK_TIMER));
    }

    #[test]
    fn sock_rings_follow_the_sock_hooks() {
        let config = EbpfRunnerConfig::new()
            .kernel(true)
            .sock_hooks(Some(HookSet::FULL_DEFAULT));
        let events = BTreeSet::from([OptionalGroup::SockEvent(0)]);
        let rings = enabled_ringbufs(&config, &events);
        assert!(rings.contains(&RB_SOCK_EVENT));
        assert!(![RB_SOCK_SEND, RB_SOCK_RECV, RB_SOCK_INGRESS]
            .iter()
            .any(|rb| rings.contains(rb)));
        assert!(!enabled_ringbufs(&config, &BTreeSet::new()).contains(&RB_SOCK_EVENT));
        let config = config.sock_hooks(Some(HookSet::of(&[Hook::Ingress, Hook::Egress])));
        let rings = enabled_ringbufs(&config, &BTreeSet::new());
        assert!(rings.contains(&RB_SOCK_INGRESS) && rings.contains(&RB_SOCK_SEND));
        assert!(!rings.contains(&RB_SOCK_RECV));
    }

    #[test]
    fn k_without_any_hook_left_is_an_error_only_alone() {
        let config = EbpfRunnerConfig::new()
            .kernel(true)
            .sock_hooks(Some(HookSet::FULL_DEFAULT));
        let none = BTreeSet::new();
        assert!(sock_hooks_left(&config, &none).is_err());
        let timer = BTreeSet::from([OptionalGroup::SockTimer]);
        assert!(sock_hooks_left(&config, &timer).unwrap());
        let with_headers = EbpfRunnerConfig::new()
            .kernel(true)
            .headers(true)
            .sock_hooks(Some(HookSet::FULL_DEFAULT));
        assert!(!sock_hooks_left(&with_headers, &none).unwrap());
        let ingress = config.sock_hooks(Some(HookSet::of(&[Hook::Ingress])));
        assert!(sock_hooks_left(&ingress, &none).unwrap());
    }

    #[test]
    fn reno_ring_follows_the_reno_group() {
        let config = EbpfRunnerConfig::new().algorithms(true);
        let none = BTreeSet::new();
        let reno = BTreeSet::from([OptionalGroup::Reno]);
        assert!(enabled_ringbufs(&config, &none).contains(&RB_CUBIC));
        assert!(!enabled_ringbufs(&config, &none).contains(&RB_RENO));
        assert!(enabled_ringbufs(&config, &reno).contains(&RB_RENO));
    }
}
