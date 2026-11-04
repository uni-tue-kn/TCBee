use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, ErrorKind, Write},
    mem,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use bincode::ErrorKind as BincodeErrorKind;
use libbpf_rs::MapHandle;
use log::{debug, error, info, trace, warn};
use memmap2::MmapMut;
use serde::Serialize;
use tcbee_common::{records::RECORD_DELIMITER, stats::RINGBUFS};
use tcbee_trace::{raw, TraceFile};

pub use crate::placement::Placement;
pub use crate::pooled::{SinkConfig, SinkKind, SinkStats};
use crate::{
    config::WRITER_BUFFER_SIZE,
    placement::{
        balance_loop, pin_to_cpu, report_helper_time, thread_cpu_ns, Follower, HelperPlacement,
        WriterCpus, WriterSlot,
    },
    pooled::PooledFile,
    rawring::{walk, RingMap, RingWaiter, Stop, WalkError},
    ring_groups::{assign, assign_with, HookGroup},
};

/// How writer threads wait for new records
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PollMode {
    /// Spin on the ring buffers while records arrive, then sleep 50 µs whenever a poll
    /// returns fewer than 256 records, so that several writer threads can share a core.
    #[default]
    Busy,
    /// Block in poll() until the kernel signals new records.
    Wait,
}

impl PollMode {
    /// Ring buffer submit flags the eBPF programs have to use for this mode
    pub fn submit_flags(self) -> u64 {
        match self {
            PollMode::Busy => libbpf_rs::libbpf_sys::BPF_RB_NO_WAKEUP as u64,
            PollMode::Wait => 0,
        }
    }
}

/// How writer threads put records into the trace files
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WriterFormat {
    /// Record by record through libbpf, each packed without padding and followed by a
    /// delimiter
    #[default]
    Records,
    /// The ring buffers' bytes copied in spans, see `tcbee_trace::raw`
    Raw,
}

impl WriterFormat {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "records" => Some(WriterFormat::Records),
            "raw" => Some(WriterFormat::Raw),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            WriterFormat::Records => "records",
            WriterFormat::Raw => "raw",
        }
    }
}

/// Raw format: the most bytes one span copies before the ring gets them back. Producers
/// see the ring as full until then, and the pooled sinks take at most this much at once.
const RAW_SPAN_BYTES: usize = 64 << 10;
const _: () = assert!(RAW_SPAN_BYTES <= crate::pooled::SLACK);

/// Raw format: how long the final drain waits for records that are still being written
const SHUTDOWN_BUSY_WAIT: Duration = Duration::from_millis(100);

/// Upper bound for a blocking wait, so that a stop request is noticed
const WAIT_TIMEOUT: Duration = Duration::from_millis(100);

/// Busy mode: a poll that consumed at least this many records means a backlog, so poll again
/// at once; a smaller batch means the writer keeps up and can sleep.
const BACKLOG_RECORDS: i32 = 256;
/// Busy mode: sleep between polls of light or idle rings. Far below the time a per-CPU ring takes
/// to fill, so it costs no records, and writer threads sharing a core leave it to the loaded one.
const IDLE_SLEEP: Duration = Duration::from_micros(50);

/// A writer CPU's thread: passes that found (almost) nothing before it starts to sleep
const SPIN_PASSES: u32 = 512;
/// A writer CPU's thread: its first sleep, doubled up to `MAX_IDLE_SLEEP` while idle
const MIN_IDLE_SLEEP: Duration = Duration::from_micros(1);
/// Far below the time a per-CPU ring takes to fill at the highest rates measured
const MAX_IDLE_SLEEP: Duration = Duration::from_micros(100);
/// A pass that copied this many bytes means a backlog: the thread keeps polling at once
const BACKLOG_BYTES: u64 = RAW_SPAN_BYTES as u64 / 2;
/// A writer CPU's thread drains the rings of the rare hooks this often, not in every pass
const RARE_INTERVAL: Duration = Duration::from_micros(50);
/// Timer slack of a writer CPU's thread, in ns: the default 50 µs would stretch its short
/// sleeps many times over
const WRITER_TIMER_SLACK_NS: libc::c_ulong = 1_000;
/// The kernel's default timer slack, in ns, for the helpers a writer thread starts
const DEFAULT_TIMER_SLACK_NS: libc::c_ulong = 50_000;

/// Serializes entries pulled from eBPF maps and writes them to files.
///
/// Without writer CPUs, each output file gets its own dedicated OS thread so that a busy
/// probe cannot starve others. With writer CPUs, one thread per writer CPU drains the files
/// that `ring_groups::assign` gives it, from `start` on. A thread reads all ring buffers of
/// its files (one per CPU) through their mapping. `BPF_MAP_TYPE_RINGBUF` is single-consumer,
/// so a ring buffer is never shared between threads.
pub struct Writer {
    poll_mode: PollMode,
    running: Arc<AtomicBool>,
    bytes_written: Arc<AtomicU64>,
    handles: Vec<(Vec<WriterReport>, JoinHandle<ThreadResult>)>,
    /// With writer CPUs: the writer CPU of each enabled ring buffer
    assignment: Vec<(u32, usize)>,
    /// With writer CPUs: the jobs registered but not started yet, per writer CPU
    pending: Vec<CpuJobs>,
    /// Jobs whose thread could not start, finished
    failed: Vec<WriterReport>,
    /// The CPUs to pin writer threads to, assigned round-robin at the start, and the writers.
    /// Requires `isolcpus=<ids>` in the kernel boot parameters for full isolation.
    cpus: Arc<WriterCpus>,
    next_cpu: usize,
    /// The thread that moves writers between the writer CPUs, and its stop flag
    balancer: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
    /// How the trace files are written
    sink: SinkConfig,
    format: WriterFormat,
    /// Ring bytes of field-selected sock records, for the placement
    sock_record: Option<usize>,
}

impl Writer {
    pub fn new(poll_mode: PollMode) -> Self {
        Writer {
            poll_mode,
            running: Arc::new(AtomicBool::new(true)),
            bytes_written: Arc::new(AtomicU64::new(0)),
            handles: Vec::new(),
            assignment: Vec::new(),
            pending: Vec::new(),
            failed: Vec::new(),
            cpus: Arc::new(WriterCpus::default()),
            next_cpu: 0,
            balancer: None,
            sink: SinkConfig::default(),
            format: WriterFormat::default(),
            sock_record: None,
        }
    }

    /// Put records into the trace files as `format` says
    pub fn with_format(mut self, format: WriterFormat) -> Self {
        self.format = format;
        self
    }

    /// Write the trace files as `sink` says instead of through memory-mapped files
    pub fn with_sink(mut self, sink: SinkConfig) -> Self {
        self.sink = sink;
        self
    }

    /// Field-selected sock records of `ring_len` bytes: `with_cpu_affinity` weighs the sock
    /// rings by them. Call it before that.
    pub fn with_sock_record(mut self, ring_len: usize) -> Self {
        self.sock_record = Some(ring_len);
        self
    }

    /// Drain the ring buffers `rbs` (the enabled ones) on the given CPU IDs, one thread per
    /// CPU, the rings of each CPU as `ring_groups::assign` says. A ring registered but not in
    /// `rbs` goes round-robin. For full isolation, also boot with `isolcpus=<ids>` so the
    /// kernel scheduler never places other tasks on those cores. `placement` decides where
    /// file helpers run, the threads do not move.
    pub fn with_cpu_affinity(
        mut self,
        cpus: Vec<usize>,
        placement: Placement,
        rbs: &[u32],
    ) -> Self {
        self.assignment = match self.sock_record {
            Some(len) => assign_with(rbs, &cpus, len),
            None => assign(rbs, &cpus),
        };
        self.cpus = Arc::new(WriterCpus::new(cpus, placement));
        self
    }

    /// Bytes written to all trace files so far
    pub fn bytes_written(&self) -> Arc<AtomicU64> {
        self.bytes_written.clone()
    }

    /// Register the ring buffer maps of one output file, with the CPU of each. Spawns a
    /// dedicated worker thread immediately. `rb` is the ring buffer index from
    /// `tcbee_common::stats`. The handles keep the maps open, so the thread can drain them
    /// after the eBPF object is closed.
    pub fn register<T>(
        &mut self,
        rb: u32,
        maps: Vec<(u32, MapHandle)>,
        trace_dir: impl AsRef<Path>,
    ) -> Result<(), WriterError>
    where
        T: Serialize + Copy + Send + 'static,
    {
        self.spawn::<T>(rb, maps, RINGBUFS[rb as usize].file, trace_dir, None, None)
    }

    /// As `register`, but into `file` instead of the ring buffer's own file (on-change mode
    /// writes the sock and cwnd rings to their `_oc` files)
    pub fn register_as<T>(
        &mut self,
        rb: u32,
        maps: Vec<(u32, MapHandle)>,
        file: TraceFile,
        trace_dir: impl AsRef<Path>,
    ) -> Result<(), WriterError>
    where
        T: Serialize + Copy + Send + 'static,
    {
        self.spawn::<T>(rb, maps, file, trace_dir, None, None)
    }

    /// As `register_as`, for records of `shape` instead of whole `T`s (field-selected sock
    /// records)
    pub fn register_shaped<T>(
        &mut self,
        rb: u32,
        maps: Vec<(u32, MapHandle)>,
        file: TraceFile,
        trace_dir: impl AsRef<Path>,
        shape: RecordShape,
    ) -> Result<(), WriterError>
    where
        T: Serialize + Copy + Send + 'static,
    {
        self.spawn::<T>(rb, maps, file, trace_dir, None, Some(shape))
    }

    /// As `register`, and hands every written record (its ring buffer bytes) to `observer`
    /// on the writer thread. For rings with few records: the observer delays the writer.
    pub fn register_observed<T>(
        &mut self,
        rb: u32,
        maps: Vec<(u32, MapHandle)>,
        trace_dir: impl AsRef<Path>,
        observer: Observer,
    ) -> Result<(), WriterError>
    where
        T: Serialize + Copy + Send + 'static,
    {
        self.spawn::<T>(
            rb,
            maps,
            RINGBUFS[rb as usize].file,
            trace_dir,
            Some(observer),
            None,
        )
    }

    fn spawn<T>(
        &mut self,
        rb: u32,
        maps: Vec<(u32, MapHandle)>,
        file: TraceFile,
        trace_dir: impl AsRef<Path>,
        observer: Option<Observer>,
        shape: Option<RecordShape>,
    ) -> Result<(), WriterError>
    where
        T: Serialize + Copy + Send + 'static,
    {
        let file_path = trace_dir.as_ref().join(file.filename());
        let mut job = MapWriterJob::<T>::with_sink(
            file_path,
            self.bytes_written.clone(),
            self.sink.clone(),
            self.format,
            shape,
        )?;
        job.observer = observer;
        if !self.cpus.pool.is_empty() {
            return self.add_to_cpu(rb, job, maps);
        }
        let running = self.running.clone();

        let pool = &self.cpus.pool;
        let slot = if pool.is_empty() {
            None
        } else {
            let id = pool[self.next_cpu % pool.len()];
            self.next_cpu += 1;
            Some(self.cpus.add_writer(id, file.filename()))
        };
        let cpu = slot.as_ref().map(|slot| slot.cpu.load(Ordering::Relaxed));
        let job = job.with_helpers(HelperPlacement {
            cpus: self.cpus.clone(),
            writer: slot.clone(),
        });
        // Only a balanced writer follows the balancer
        let follow = slot
            .clone()
            .filter(|_| self.cpus.balanced())
            .map(|slot| (self.cpus.clone(), slot));

        debug!(
            "Spawning writer thread for {} (cpu: {:?})",
            job.file_path.display(),
            cpu
        );

        let report = self.report(rb, &job);
        let poll_mode = self.poll_mode;
        // The ring buffers are set up inside the thread, which then reports whether that
        // worked, so a broken map fails here and not only at shutdown
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            let result = ring_loop(job, maps, running, cpu, follow, poll_mode, ready_tx);
            (vec![result], None)
        });
        let result = match ready_rx.recv() {
            Ok(Ok(())) => {
                self.handles.push((vec![report], handle));
                self.start_balancer();
                return Ok(());
            }
            Ok(Err(err)) => Err(err),
            Err(_) => Err(WriterError::WorkerPanicked),
        };
        let _ = handle.join();
        if let Some(slot) = slot.filter(|_| self.cpus.balanced()) {
            self.cpus.remove_writer(&slot);
        }
        result
    }

    fn report<T>(&self, rb: u32, job: &MapWriterJob<T>) -> WriterReport
    where
        T: Serialize + Copy + Send + 'static,
    {
        WriterReport {
            rb,
            file: job.file_path.clone(),
            format: self.format,
            records: 0,
            error: None,
            sink: None,
            thread: None,
        }
    }

    /// Maps the rings of `job` and adds it to the jobs of its writer CPU, see `start`
    fn add_to_cpu<T>(
        &mut self,
        rb: u32,
        mut job: MapWriterJob<T>,
        maps: Vec<(u32, MapHandle)>,
    ) -> Result<(), WriterError>
    where
        T: Serialize + Copy + Send + 'static,
    {
        let rings = match maps
            .into_iter()
            .map(|(cpu, map)| RingMap::new(map).map(|ring| (cpu, ring)))
            .collect::<io::Result<Vec<_>>>()
        {
            Ok(rings) => rings,
            Err(err) => {
                if let Err(flush) = abandon(&mut job) {
                    error!("Failed to finish {}: {}", job.file_path.display(), flush);
                }
                return Err(WriterError::Io(err));
            }
        };
        let pool = &self.cpus.pool;
        let cpu = match self.assignment.iter().find(|(r, _)| *r == rb) {
            Some(&(_, cpu)) => cpu,
            None => {
                self.next_cpu += 1;
                pool[(self.next_cpu - 1) % pool.len()]
            }
        };
        let k = match self.pending.iter().position(|jobs| jobs.cpu == cpu) {
            Some(k) => k,
            None => {
                let slot = self.cpus.add_writer(cpu, &format!("writer CPU {cpu}"));
                self.pending.push(CpuJobs {
                    cpu,
                    slot,
                    jobs: Vec::new(),
                });
                self.pending.len() - 1
            }
        };
        let report = self.report(rb, &job);
        let jobs = &mut self.pending[k];
        let job = job.with_helpers(HelperPlacement {
            cpus: self.cpus.clone(),
            writer: Some(jobs.slot.clone()),
        });
        debug!(
            "Writer job for {} on writer CPU {}",
            job.file_path.display(),
            cpu
        );
        jobs.jobs.push(CpuJob {
            rare: HookGroup::of(rb) == HookGroup::Rare,
            report,
            job: Box::new(Draining { job, rings }),
        });
        Ok(())
    }

    /// Starts the threads of the writer CPUs with the jobs registered so far. Without writer
    /// CPUs, the threads run from their registration on and this does nothing.
    /// A writer CPU whose thread cannot start finishes its jobs with the error at once, and
    /// the first such error is returned; the other CPUs start anyway.
    pub fn start(&mut self) -> Result<(), WriterError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let mut first_err = None;
        for CpuJobs { cpu, slot, jobs } in mem::take(&mut self.pending) {
            let (reports, jobs): (Vec<_>, Vec<_>) = jobs
                .into_iter()
                .map(|job| (job.report, (job.rare, job.job)))
                .unzip();
            info!("Writer CPU {} drains {} files", cpu, jobs.len());
            let started = self.start_cpu(cpu, slot, jobs);
            match started {
                Ok(handle) => self.handles.push((reports, handle)),
                Err((err, jobs)) => {
                    error!("Cannot start the writer thread of CPU {}: {}", cpu, err);
                    for (mut report, (_, job)) in reports.into_iter().zip(jobs) {
                        let (records, stats, result) = job.finish(Err(JobError::Io(
                            io::Error::new(err.kind(), err.to_string()),
                        )));
                        report.records = records;
                        report.sink = stats;
                        report.error = result.err().map(|err| err.to_string());
                        self.failed.push(report);
                    }
                    first_err.get_or_insert(WriterError::Io(err));
                }
            }
        }
        self.start_balancer();
        first_err.map_or(Ok(()), Err)
    }

    /// Starts the thread of writer CPU `cpu`, or hands its jobs back with the error
    fn start_cpu(
        &self,
        cpu: usize,
        slot: Arc<WriterSlot>,
        jobs: CpuJobList,
    ) -> Result<JoinHandle<ThreadResult>, (io::Error, CpuJobList)> {
        let waiter = match self.poll_mode {
            PollMode::Busy => None,
            PollMode::Wait => {
                let rings = jobs
                    .iter()
                    .flat_map(|(_, job)| job.rings().iter().map(|(_, ring)| ring));
                match RingWaiter::new(rings) {
                    Ok(waiter) => Some(waiter),
                    Err(err) => return Err((err, jobs)),
                }
            }
        };
        let running = self.running.clone();
        // Round-robin keeps the slot too: helpers avoid the CPUs with writers
        let follow = self.cpus.balanced().then(|| (self.cpus.clone(), slot));
        // The jobs go to the thread once it runs, so that they are still here if it cannot start
        let (tx, rx) = mpsc::channel::<CpuJobList>();
        let spawned = thread::Builder::new()
            .name(format!("tcbee-w{cpu}"))
            .spawn(move || match rx.recv() {
                Ok(jobs) => {
                    let (results, stats) = cpu_loop(jobs, running, cpu, follow, waiter);
                    (results, Some(stats))
                }
                Err(_) => (Vec::new(), None),
            });
        match spawned {
            Ok(handle) => {
                tx.send(jobs).expect("the thread waits for its jobs");
                Ok(handle)
            }
            Err(err) => Err((err, jobs)),
        }
    }

    /// Starts the balancer with the first writer, if writers are balanced over several CPUs
    fn start_balancer(&mut self) {
        if !self.cpus.balanced() || self.cpus.pool.len() < 2 || self.balancer.is_some() {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (cpus, stopped) = (self.cpus.clone(), stop.clone());
        let spawned = thread::Builder::new()
            .name("tcbee-balance".into())
            .spawn(move || balance_loop(&cpus, &stopped));
        match spawned {
            Ok(handle) => self.balancer = Some((stop, handle)),
            Err(err) => warn!(
                "Cannot start the writer balancer, writers stay round-robin: {}",
                err
            ),
        }
    }

    fn stop_balancer(&mut self) {
        if let Some((stop, handle)) = self.balancer.take() {
            stop.store(true, Ordering::Relaxed);
            handle.thread().unpark();
            let _ = handle.join();
            info!(
                "Moved writer threads {} times",
                self.cpus.moves.load(Ordering::Relaxed)
            );
        }
    }

    /// Signal all worker threads to stop, drain their ring buffers, finish the files and
    /// join them. The eBPF programs must be detached before, otherwise records that are
    /// submitted after the final drain are lost.
    pub fn shutdown(mut self) -> Vec<WriterReport> {
        // Jobs that never started still finish their files
        let _ = self.start();
        self.stop_balancer();
        self.signal_stop();
        self.join_all()
    }

    fn signal_stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn join_all(&mut self) -> Vec<WriterReport> {
        self.handles
            .drain(..)
            .flat_map(|(mut reports, handle)| {
                match handle.join() {
                    Ok((results, thread)) => {
                        for (report, (records, stats, result)) in reports.iter_mut().zip(results) {
                            report.records = records;
                            report.sink = stats;
                            report.error = result.err().map(|err| err.to_string());
                            report.thread.clone_from(&thread);
                        }
                    }
                    // A panic marks the jobs of its thread
                    Err(_) => {
                        for report in &mut reports {
                            report.error = Some(WriterError::WorkerPanicked.to_string());
                        }
                    }
                }
                reports
            })
            .chain(self.failed.drain(..))
            .collect()
    }
}

/// Runs `work` on a new thread restricted to `cpus`. Its CPU time counts toward the load of
/// the writer CPU it ends on in `load_sink`, if given.
pub(crate) fn spawn_helper(
    name: &str,
    cpus: Option<libc::cpu_set_t>,
    load_sink: Option<Arc<WriterCpus>>,
    work: impl FnOnce() + Send + 'static,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name(name.into()).spawn(move || {
        // Not the low slack of a writer thread that starts it
        set_timer_slack(DEFAULT_TIMER_SLACK_NS);
        if let Some(set) = cpus {
            let ret = unsafe { libc::sched_setaffinity(0, mem::size_of_val(&set), &set) };
            if ret != 0 {
                error!(
                    "Failed to move a file helper off the writer's CPU: errno {}",
                    io::Error::last_os_error()
                );
            }
        }
        work();
        if let Some(sink) = load_sink {
            report_helper_time(&sink);
        }
    })
}

/// Sets the calling thread's timer slack, in ns
fn set_timer_slack(ns: libc::c_ulong) {
    if unsafe { libc::prctl(libc::PR_SET_TIMERSLACK, ns) } != 0 {
        debug!("Cannot set the timer slack: {}", io::Error::last_os_error());
    }
}

/// Logs the error that stopped a writer and finishes its file
fn finish_job<T>(mut job: MapWriterJob<T>, result: Result<(), JobError>) -> JobResult
where
    T: Serialize + Copy + Send + 'static,
{
    if let Err(err) = &result {
        error!(
            "Writer job {} failed after {} records: {}. Stopping thread.",
            job.name(),
            job.records,
            err
        );
    }

    // Finish the file even after an error so that the records written so far are kept
    let flushed = job.flush();
    if let Err(err) = &flushed {
        error!(
            "Failed to flush job {} during shutdown: {}",
            job.name(),
            err
        );
    }

    // The records written before an error are in the file and still count
    (job.records, job.sink_stats.take(), result.and(flushed))
}

/// Pins the writer thread to `cpu` and returns its follower of the balancer, if balanced
fn pin_and_follow(
    cpu: Option<usize>,
    follow: Option<(Arc<WriterCpus>, Arc<WriterSlot>)>,
) -> Option<Follower> {
    let pinned = cpu.is_some_and(pin_to_cpu);
    // A writer that is not where its slot says stays out of the balancing
    follow.and_then(|(cpus, slot)| {
        if pinned {
            Some(Follower::new(cpus, slot))
        } else {
            cpus.remove_writer(&slot);
            None
        }
    })
}

/// A writer thread: maps the rings itself and drains the committed records of each in
/// spans, see `RingJob`
fn ring_loop<T>(
    mut job: MapWriterJob<T>,
    maps: Vec<(u32, MapHandle)>,
    running: Arc<AtomicBool>,
    cpu: Option<usize>,
    follow: Option<(Arc<WriterCpus>, Arc<WriterSlot>)>,
    poll_mode: PollMode,
    ready: mpsc::SyncSender<Result<(), WriterError>>,
) -> JobResult
where
    T: Serialize + Copy + Send + 'static,
{
    let mut follower = pin_and_follow(cpu, follow);
    let rings = (|| {
        let rings = maps
            .into_iter()
            .map(|(cpu, map)| RingMap::new(map).map(|ring| (cpu, ring)))
            .collect::<io::Result<Vec<_>>>()?;
        let waiter = match poll_mode {
            PollMode::Busy => None,
            PollMode::Wait => Some(RingWaiter::new(rings.iter().map(|(_, ring)| ring))?),
        };
        Ok::<_, io::Error>((rings, waiter))
    })();
    let (rings, waiter) = match rings {
        Ok(rings) => {
            let _ = ready.send(Ok(()));
            rings
        }
        Err(err) => return fail_start(&mut job, &ready, WriterError::Io(err)),
    };
    let mut job: Box<dyn RingJob> = Box::new(Draining { job, rings });

    let result = (|| {
        while running.load(Ordering::Relaxed) {
            let copied = drain_all(&mut *job)?;
            match &waiter {
                // Poll again at once while there is a backlog
                None if copied >= BACKLOG_RECORDS as u64 => std::hint::spin_loop(),
                None => thread::sleep(IDLE_SLEEP),
                Some(waiter) if copied == 0 => {
                    waiter.wait(job.rings().iter().map(|(_, ring)| ring), WAIT_TIMEOUT)?
                }
                Some(_) => {}
            }
            job.tick()?;
            if let Some(follower) = &mut follower {
                follower.tick();
            }
        }
        drain_at_shutdown(&mut *job, Instant::now() + SHUTDOWN_BUSY_WAIT)
    })();
    job.finish(result)
}

/// A writer CPU thread's jobs, each with whether it belongs to the rare hooks
type CpuJobList = Vec<(bool, Box<dyn RingJob>)>;

/// The jobs of one writer CPU until `Writer::start`
struct CpuJobs {
    cpu: usize,
    slot: Arc<WriterSlot>,
    jobs: Vec<CpuJob>,
}

struct CpuJob {
    /// The job's rings belong to the rare hooks
    rare: bool,
    report: WriterReport,
    job: Box<dyn RingJob>,
}

/// When a writer CPU's thread sleeps: it polls at once while there is a backlog, spins for
/// `SPIN_PASSES` passes without one, then sleeps from `MIN_IDLE_SLEEP` on, twice as long each
/// time up to `MAX_IDLE_SLEEP`. Only a backlog starts over: rings that get a few records now
/// and then do not keep the thread awake.
#[derive(Debug)]
struct IdleLadder {
    quiet: u32,
    sleep: Duration,
}

impl IdleLadder {
    fn new() -> Self {
        IdleLadder {
            quiet: 0,
            sleep: MIN_IDLE_SLEEP,
        }
    }

    /// After a pass with a backlog
    fn backlog(&mut self) {
        *self = IdleLadder::new();
    }

    /// After a pass without one: how long to sleep, None to poll again at once
    fn quiet(&mut self) -> Option<Duration> {
        if self.quiet < SPIN_PASSES {
            self.quiet += 1;
            return None;
        }
        let sleep = self.sleep;
        self.sleep = (self.sleep * 2).min(MAX_IDLE_SLEEP);
        Some(sleep)
    }
}

/// The thread of a writer CPU: drains its jobs one span per ring and pass, so that a loaded
/// ring cannot hold up the others, and sleeps as `IdleLadder` says, or until a ring has
/// records with a `waiter` (`PollMode::Wait`). Without a waiter, `rare` jobs are drained
/// every `RARE_INTERVAL` only. A job that fails is finished at once, the others go on.
/// Returns the result of each job and what the thread did.
fn cpu_loop(
    jobs: CpuJobList,
    running: Arc<AtomicBool>,
    cpu: usize,
    follow: Option<(Arc<WriterCpus>, Arc<WriterSlot>)>,
    waiter: Option<RingWaiter>,
) -> (Vec<JobResult>, WriterThreadStats) {
    let started = Instant::now();
    let mut stats = WriterThreadStats {
        cpu,
        files: jobs.len(),
        ..WriterThreadStats::default()
    };
    set_timer_slack(WRITER_TIMER_SLACK_NS);
    let mut follower = pin_and_follow(Some(cpu), follow);
    let mut results: Vec<Option<JobResult>> = jobs.iter().map(|_| None).collect();
    let (rare, mut jobs): (Vec<bool>, Vec<Option<Box<dyn RingJob>>>) = jobs
        .into_iter()
        .map(|(rare, job)| (rare, Some(job)))
        .unzip();
    // A pass that copied a quarter of the smallest ring counts as a backlog too, so that the
    // thread does not sleep while a small ring fills
    let backlog_bytes = jobs
        .iter()
        .flatten()
        .flat_map(|job| job.rings().iter().map(|(_, ring)| ring.size() as u64 / 4))
        .fold(BACKLOG_BYTES, u64::min);
    let mut failed: Option<io::Error> = None;
    let mut ladder = IdleLadder::new();
    let mut last_rare = Instant::now();
    while running.load(Ordering::Relaxed) {
        let rare_due = last_rare.elapsed() >= RARE_INTERVAL;
        if rare_due {
            last_rare = Instant::now();
        }
        let mut pass = Drained::default();
        for (k, slot) in jobs.iter_mut().enumerate() {
            let Some(job) = slot else { continue };
            // A waiter wakes for the rare rings too: drain them at once
            if rare[k] && !rare_due && waiter.is_none() {
                continue;
            }
            match drain_once(&mut **job).and_then(|drained| job.tick().map(|()| drained)) {
                Ok(drained) => pass.add(drained),
                Err(err) => {
                    let job = slot.take().expect("checked above");
                    results[k] = Some(job.finish(Err(err)));
                }
            }
        }
        stats.passes += 1;
        match &waiter {
            None if pass.more || pass.bytes >= backlog_bytes => {
                stats.backlog_passes += 1;
                ladder.backlog()
            }
            None => {
                if let Some(sleep) = ladder.quiet() {
                    stats.sleeps += 1;
                    thread::sleep(sleep);
                } else {
                    std::hint::spin_loop();
                }
            }
            Some(waiter) if pass.copied == 0 => {
                let rings = jobs
                    .iter()
                    .flatten()
                    .flat_map(|job| job.rings().iter().map(|(_, ring)| ring));
                if let Err(err) = waiter.wait(rings, WAIT_TIMEOUT) {
                    error!("Writer CPU {}: waiting for records failed: {}", cpu, err);
                    failed = Some(err);
                    break;
                }
            }
            Some(_) => {}
        }
        if let Some(follower) = &mut follower {
            follower.tick();
        }
    }

    // One deadline for all jobs of the thread, so that the shutdown takes as long as with
    // one job
    let deadline = Instant::now() + SHUTDOWN_BUSY_WAIT;
    for (k, slot) in jobs.into_iter().enumerate() {
        if let Some(mut job) = slot {
            let result = match &failed {
                // Drained before the wait failed, and stopped with it
                Some(err) => Err(JobError::Io(io::Error::new(err.kind(), err.to_string()))),
                None => drain_at_shutdown(&mut *job, deadline),
            };
            results[k] = Some(job.finish(result));
        }
    }
    stats.wall_ns = started.elapsed().as_nanos() as u64;
    stats.cpu_ns = thread_cpu_ns().unwrap_or(0);
    let results = results
        .into_iter()
        .map(|result| result.expect("every job finished"))
        .collect();
    (results, stats)
}

/// Copies at most one span of each ring of `job`
fn drain_once(job: &mut dyn RingJob) -> Result<Drained, JobError> {
    let mut drained = Drained::default();
    for index in 0..job.rings().len() {
        drained.add(job.drain(index)?);
    }
    Ok(drained)
}

/// A writer job together with its rings, one per CPU, as a writer thread drives it. Object
/// safe, so that one thread can drive the jobs of several record types.
trait RingJob: Send {
    fn name(&self) -> &str;
    /// The rings with their CPU
    fn rings(&self) -> &[(u32, RingMap)];
    /// Copies at most one span of committed records of ring `index` into the file
    fn drain(&mut self, index: usize) -> Result<Drained, JobError>;
    /// Regular upkeep between passes over the rings
    fn tick(&mut self) -> Result<(), JobError>;
    /// Ends the job after its last drain: counts its bytes, finishes its file
    fn finish(self: Box<Self>, result: Result<(), JobError>) -> JobResult;
}

/// What one `RingJob::drain` did
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Drained {
    /// Records and discarded records copied
    pub copied: u64,
    /// Bytes of the ring copied
    pub bytes: u64,
    /// The span ended at its size limit: the ring may hold more
    pub more: bool,
}

impl Drained {
    fn add(&mut self, other: Drained) {
        self.copied += other.copied;
        self.bytes += other.bytes;
        self.more |= other.more;
    }
}

/// The `RingJob` of a `MapWriterJob`
struct Draining<T>
where
    T: Serialize + Copy + Send + 'static,
{
    job: MapWriterJob<T>,
    rings: Vec<(u32, RingMap)>,
}

impl<T> RingJob for Draining<T>
where
    T: Serialize + Copy + Send + 'static,
{
    fn name(&self) -> &str {
        self.job.name()
    }

    fn rings(&self) -> &[(u32, RingMap)] {
        &self.rings
    }

    /// Copies the span up to the producer position, a record that is still being written,
    /// or `RAW_SPAN_BYTES`, as it is (raw format) or record by record (records format), and
    /// gives it back to the producers once it is copied
    fn drain(&mut self, index: usize) -> Result<Drained, JobError> {
        let (cpu, ring) = &self.rings[index];
        let consumer = ring.consumer();
        let span = walk(
            |pos| ring.header(pos),
            consumer,
            ring.producer(),
            self.job.ring_len,
            RAW_SPAN_BYTES,
        )
        .map_err(JobError::Ring)?;
        if span.end == consumer {
            return Ok(Drained::default());
        }
        let bytes = ring.span(consumer, span.end);
        if self.job.raw.is_some() {
            self.job
                .write_span(*cpu, bytes, span.records, span.discards)?;
        } else {
            for frame in raw::frames(bytes, self.job.ring_len) {
                if let raw::Frame::Record(record) = frame {
                    if self.job.write_from(*cpu, record) != 0 {
                        return Err(self
                            .job
                            .error
                            .take()
                            .expect("a failed write keeps its error"));
                    }
                }
            }
        }
        ring.release(span.end);
        Ok(Drained {
            copied: span.records + span.discards,
            bytes: span.end - consumer,
            more: span.stop == Stop::Cap,
        })
    }

    fn tick(&mut self) -> Result<(), JobError> {
        self.job.tick()
    }

    fn finish(self: Box<Self>, result: Result<(), JobError>) -> JobResult {
        let Draining { mut job, rings } = *self;
        job.count_bytes();
        drop(rings);
        finish_job(job, result)
    }
}

/// Drains every ring of `job` until it is empty or stops at a record still being written,
/// returns the records and discarded records copied
fn drain_all(job: &mut dyn RingJob) -> Result<u64, JobError> {
    let mut copied = 0;
    for index in 0..job.rings().len() {
        loop {
            let drained = job.drain(index)?;
            copied += drained.copied;
            if !drained.more {
                break;
            }
        }
    }
    Ok(copied)
}

/// Drains what was submitted before the programs were detached. A program that still runs
/// (detaching does not wait for it) leaves its record busy, and the committed records behind
/// it wait for it too: retry until `deadline`, then give up on what is left.
fn drain_at_shutdown(job: &mut dyn RingJob, deadline: Instant) -> Result<(), JobError> {
    loop {
        while drain_all(job)? > 0 {}
        let left: u64 = job
            .rings()
            .iter()
            .map(|(_, ring)| ring.producer() - ring.consumer())
            .sum();
        if left == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            warn!(
                "{}: {} bytes of records were still being written at the end and are lost",
                job.name(),
                left
            );
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// A writer thread could not set up its rings: finishes the file and reports `err`
fn fail_start<T>(
    job: &mut MapWriterJob<T>,
    ready: &mpsc::SyncSender<Result<(), WriterError>>,
    err: WriterError,
) -> JobResult
where
    T: Serialize + Copy + Send + 'static,
{
    let flushed = abandon(job);
    let _ = ready.send(Err(err));
    (0, None, flushed)
}

/// Finishes the file of a job that has no rings
fn abandon<T>(job: &mut MapWriterJob<T>) -> Result<(), JobError>
where
    T: Serialize + Copy + Send + 'static,
{
    let flushed = job.flush();
    // Without a ring buffer there is no trace, so don't leave an empty file
    if flushed.is_ok() {
        remove_if_empty(&job.file_path);
    }
    flushed
}

/// Removes a file that has no data. A file that had data before is kept.
fn remove_if_empty(path: &Path) {
    let empty = fs::metadata(path).is_ok_and(|metadata| metadata.len() == 0);
    if empty {
        if let Err(err) = fs::remove_file(path) {
            debug!("Could not remove empty file {}: {}", path.display(), err);
        }
    }
}

/// Records a writer thread wrote, what its pooled sink did, and the error that stopped it
type JobResult = (u64, Option<SinkStats>, Result<(), JobError>);

/// The results of a writer thread's jobs, and what the thread did if it is a writer CPU's
type ThreadResult = (Vec<JobResult>, Option<WriterThreadStats>);

/// What the thread of a writer CPU did, for metrics.json
#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct WriterThreadStats {
    pub cpu: usize,
    /// Trace files it wrote
    pub files: usize,
    /// Its CPU time and lifetime, ns
    pub cpu_ns: u64,
    pub wall_ns: u64,
    /// Passes over its rings, those that found a backlog, and its sleeps
    pub passes: u64,
    pub backlog_passes: u64,
    pub sleeps: u64,
}

/// Sees every record a writer wrote, see `Writer::register_observed`
pub type Observer = Box<dyn FnMut(&[u8]) + Send>;

/// One observer that hands each record to all of `observers`, None without any
pub fn observe_all(mut observers: Vec<Observer>) -> Option<Observer> {
    match observers.len() {
        0 => None,
        1 => observers.pop(),
        _ => Some(Box::new(move |entry: &[u8]| {
            for observer in observers.iter_mut() {
                observer(entry);
            }
        })),
    }
}

/// Allocates the blocks of a file range. Without this, a full disk is only noticed when a
/// write into the mapping faults, and the kernel kills the process with SIGBUS.
pub(crate) fn allocate(file: &File, offset: usize, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    loop {
        let ret = unsafe { libc::fallocate(file.as_raw_fd(), 0, offset as i64, len as i64) };
        if ret == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // tmpfs gives up a long allocation when a signal arrives (SIGSTOP/SIGCONT, for
            // example) and frees what it had allocated. Giving up here would stop the writer.
            Some(libc::EINTR) => continue,
            // Not every file system supports it, fall back to a sparse file
            Some(libc::EOPNOTSUPP) => return Ok(()),
            _ => return Err(err),
        }
    }
}

const MIN_MMAP_GROWTH: usize = 64 * 1024;
const MAX_MMAP_GROWTH: usize = 1 << 30;
/// Smallest step when growing in the background, so that small files do not spawn a
/// helper every few kilobytes
const MIN_BACKGROUND_GROWTH: usize = 16 << 20;

/// Capacity after growing a file of `capacity` that must hold `required` bytes: geometric
/// steps between MIN_BACKGROUND_GROWTH and MAX_MMAP_GROWTH, in multiples of `growth`
pub(crate) fn next_capacity(capacity: usize, growth: usize, required: usize) -> usize {
    let step = capacity.clamp(growth.max(MIN_BACKGROUND_GROWTH), MAX_MMAP_GROWTH);
    required
        .max(capacity.saturating_add(step))
        .next_multiple_of(growth)
}

/// Whether to grow in the background once `required` bytes are used: when less than half of
/// the file, and less than the next step, is free. Growing whenever half of the file was used
/// kept the file at twice the bytes written once the step reached its maximum, and the helper
/// zeroed new tmpfs pages at twice the write rate. Below the maximum step a step is as large
/// as the file, so the half bound keeps small files small.
pub(crate) fn starts_growth(capacity: usize, required: usize, new_capacity: usize) -> bool {
    capacity.saturating_sub(required) < (new_capacity - capacity).min(capacity / 2)
}

struct MmapBackedFile {
    file: File,
    map: Option<MmapMut>,
    position: usize,
    capacity: usize,
    growth: usize,
    /// Background growth in flight: the new mapping and the capacity it covers
    pending: Option<mpsc::Receiver<io::Result<(MmapMut, usize)>>>,
    /// Where the growth and unmap helpers run, None to inherit the writer's CPUs
    helpers: Option<HelperPlacement>,
}

impl MmapBackedFile {
    fn new(path: &Path, chunk_size: usize) -> io::Result<Self> {
        let growth = chunk_size.max(MIN_MMAP_GROWTH);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)?;

        let metadata = file.metadata()?;
        let existing_len = metadata.len() as usize;

        let mut capacity = existing_len.max(growth);
        if capacity == 0 {
            capacity = growth;
        }

        if capacity as u64 != metadata.len() {
            file.set_len(capacity as u64)?;
        }
        allocate(&file, existing_len, capacity - existing_len)?;

        let map = unsafe { MmapMut::map_mut(&file)? };

        Ok(Self {
            file,
            map: Some(map),
            position: existing_len,
            capacity,
            growth,
            pending: None,
            helpers: None,
        })
    }

    /// Next capacity when the file has to grow to hold `required` bytes. Grows
    /// geometrically so that remapping stays rare at high record rates.
    fn next_capacity(&self, required: usize) -> usize {
        next_capacity(self.capacity, self.growth, required)
    }

    /// Extends the file to `new_capacity` and maps all of it
    fn grow(file: &File, old_capacity: usize, new_capacity: usize) -> io::Result<MmapMut> {
        allocate(file, old_capacity, new_capacity - old_capacity)?;
        file.set_len(new_capacity as u64)?;
        unsafe { MmapMut::map_mut(file) }
    }

    /// Preallocates the next chunk on a helper thread, the writer keeps using the old
    /// mapping until the new one is ready. fallocate can block for a long time and the
    /// ring buffer would overflow meanwhile.
    fn start_growth(&mut self, new_capacity: usize) -> io::Result<()> {
        let file = self.file.try_clone()?;
        let old_capacity = self.capacity;
        let (tx, rx) = mpsc::channel();
        spawn_helper(
            "tcbee-grow",
            self.helper_set(),
            self.load_sink(),
            move || {
                let _ = tx
                    .send(Self::grow(&file, old_capacity, new_capacity).map(|m| (m, new_capacity)));
            },
        )
        .map(drop)?;
        self.pending = Some(rx);
        Ok(())
    }

    fn helper_set(&self) -> Option<libc::cpu_set_t> {
        self.helpers.as_ref().and_then(HelperPlacement::cpu_set)
    }

    fn load_sink(&self) -> Option<Arc<WriterCpus>> {
        self.helpers.as_ref().and_then(HelperPlacement::load_sink)
    }

    fn adopt(&mut self, map: MmapMut, capacity: usize) {
        self.capacity = capacity;
        if let Some(old) = self.map.replace(map) {
            // Unmapping a large dirty mapping is slow, keep it off the writer thread.
            // The written pages stay in the page cache.
            let unmap = spawn_helper("tcbee-unmap", self.helper_set(), self.load_sink(), || {
                drop(old)
            });
            if let Err(err) = unmap {
                error!("Failed to start the unmap helper: {}", err);
            }
        }
    }

    fn ensure_capacity(&mut self, additional: usize) -> io::Result<()> {
        if additional == 0 {
            return Ok(());
        }

        let required = self
            .position
            .checked_add(additional)
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "file size overflow"))?;

        if required > self.capacity {
            // Out of room: the helper was too slow or not started, wait for it
            if let Some(rx) = self.pending.take() {
                let (map, capacity) = rx
                    .recv()
                    .map_err(|_| io::Error::new(ErrorKind::Other, "file growth thread died"))??;
                self.adopt(map, capacity);
            }
            if required > self.capacity {
                let new_capacity = self.next_capacity(required);
                let map = Self::grow(&self.file, self.capacity, new_capacity)?;
                self.adopt(map, new_capacity);
            }
        }

        // Start the next growth while one growth step is still free
        if self.pending.is_none() {
            let new_capacity = self.next_capacity(required);
            if starts_growth(self.capacity, required, new_capacity) {
                self.start_growth(new_capacity)?;
            }
        }

        Ok(())
    }

    /// Takes over a finished background growth without waiting for it. Runs between polls,
    /// not per record: until then the old mapping still has room, see `starts_growth`.
    fn adopt_finished_growth(&mut self) -> io::Result<()> {
        let Some(rx) = &self.pending else {
            return Ok(());
        };
        match rx.try_recv() {
            Ok(grown) => {
                self.pending = None;
                let (map, capacity) = grown?;
                self.adopt(map, capacity);
                Ok(())
            }
            Err(mpsc::TryRecvError::Empty) => Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.pending = None;
                Err(io::Error::new(ErrorKind::Other, "file growth thread died"))
            }
        }
    }

    /// Returns the next `len` bytes of the file for writing
    fn reserve(&mut self, len: usize) -> io::Result<&mut [u8]> {
        self.ensure_capacity(len)?;
        let start = self.position;
        let map = self
            .map
            .as_mut()
            .ok_or_else(|| io::Error::new(ErrorKind::BrokenPipe, "memory-mapped writer closed"))?;
        self.position += len;
        Ok(&mut map[start..start + len])
    }

    fn finish(mut self) -> io::Result<()> {
        // Let a running growth end, it must not extend the file after the final set_len
        if let Some(rx) = self.pending.take() {
            let _ = rx.recv();
        }
        if let Some(map) = self.map.take() {
            map.flush_range(0, self.position)?;
        }
        self.file.set_len(self.position as u64)?;
        self.file.sync_all()?;
        Ok(())
    }
}

/// Where a writer puts the file bytes of its records
enum Sink {
    /// A memory-mapped file, grown in the background
    Mmap(MmapBackedFile),
    /// Buffers written by I/O threads
    Pooled(Box<PooledFile>),
}

impl Sink {
    fn open(path: &Path, chunk_bytes: usize, config: SinkConfig) -> io::Result<Self> {
        Ok(match config.kind {
            SinkKind::Mmap => Sink::Mmap(MmapBackedFile::new(path, chunk_bytes)?),
            SinkKind::Direct | SinkKind::Buffered | SinkKind::Uring | SinkKind::Sync => {
                Sink::Pooled(Box::new(PooledFile::new(path, config)?))
            }
        })
    }

    /// Runs the sink's helper threads on `helpers` instead of the writer's CPU
    fn set_helpers(&mut self, helpers: HelperPlacement) {
        match self {
            Sink::Mmap(file) => file.helpers = Some(helpers),
            Sink::Pooled(file) => file.set_helpers(helpers),
        }
    }

    /// Returns the next `len` bytes of the file for writing
    #[inline]
    fn reserve(&mut self, len: usize) -> io::Result<&mut [u8]> {
        match self {
            Sink::Mmap(file) => file.reserve(len),
            Sink::Pooled(file) => file.reserve(len),
        }
    }

    /// Appends `data`; the sync sink writes long runs from there without copying them
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Sink::Mmap(file) => {
                file.reserve(data.len())?.copy_from_slice(data);
                Ok(())
            }
            Sink::Pooled(file) => file.write_bytes(data),
        }
    }

    /// Regular upkeep on the writer thread between polls of the rings
    #[inline]
    fn tick(&mut self) -> io::Result<()> {
        match self {
            Sink::Mmap(file) => file.adopt_finished_growth(),
            Sink::Pooled(file) => file.tick(),
        }
    }

    /// Writes out all reserved bytes, cuts the file to them and syncs it. Returns how many
    /// records of `record_len` bytes the file got, None for all that were reserved.
    fn finish(self, record_len: usize) -> (Option<u64>, Option<SinkStats>, io::Result<()>) {
        match self {
            Sink::Mmap(file) => (None, None, file.finish()),
            Sink::Pooled(file) => {
                let (records, stats, result) = file.finish(record_len);
                (Some(records), Some(stats), result)
            }
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Jobs that never started still finish their files
        let _ = self.start();
        self.stop_balancer();
        if self.handles.is_empty() {
            return;
        }
        self.signal_stop();
        for (_, handle) in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

/// The record layout of a ring whose records are shorter than its record type, the
/// field-selected sock records (`--sock-fields`, `tcbee_trace::sockfields`)
#[derive(Debug, Clone)]
pub struct RecordShape {
    /// Bytes of a record in the ring buffer
    pub ring_len: usize,
    /// (offset, length) ranges of a ring record that make up its file record, in order
    pub runs: Vec<(usize, usize)>,
    /// Layout id in the header of a raw trace
    pub layout_id: u32,
}

impl RecordShape {
    /// The shape of the field-selected sock records `shape`
    pub fn of_sock(shape: &tcbee_trace::sockfields::SockShape) -> Self {
        RecordShape {
            ring_len: shape.ring_len,
            runs: shape.runs(),
            layout_id: tcbee_trace::raw::sock_fields_layout_id(
                tcbee_common::records::LAYOUT_ID,
                shape.fields.mask(),
            ),
        }
    }
}

/// The file format of a record is its bincode 1 encoding: the fields of the `#[repr(C)]`
/// struct back to back in little endian, without padding. On a little endian host that
/// is the record's memory with the padding cut out, so it can be copied as a few byte
/// ranges instead of serializing field by field.
struct PackedLayout {
    /// (offset, length) ranges of the record, in file order
    runs: Vec<(usize, usize)>,
}

impl PackedLayout {
    /// Derives the ranges from bincode itself: values whose byte `i` is the low and the high
    /// byte of `i` serialize to the source offset of every output byte. Their complements
    /// check that the output is a plain copy of the input bytes. None if that does not hold
    /// for `T` (or `T` is too large to number its bytes), the caller then uses bincode.
    ///
    /// `T` must be plain old data, valid for any bit pattern, like all record types.
    fn of<T: Serialize + Copy>() -> Option<Self> {
        let size = mem::size_of::<T>();
        if size == 0 || size > usize::from(u16::MAX) + 1 {
            return None;
        }
        let encode = |pattern: &dyn Fn(usize) -> u8| -> Option<Vec<u8>> {
            let bytes: Vec<u8> = (0..size).map(pattern).collect();
            let value = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) };
            bincode::serialize(&value).ok()
        };
        let low = encode(&|i| i as u8)?;
        let high = encode(&|i| (i >> 8) as u8)?;
        let low_check = encode(&|i| !(i as u8))?;
        let high_check = encode(&|i| !((i >> 8) as u8))?;
        if [&high, &low_check, &high_check]
            .iter()
            .any(|encoded| encoded.len() != low.len())
            || (0..low.len()).any(|k| low_check[k] != !low[k] || high_check[k] != !high[k])
        {
            return None;
        }
        let offsets = low
            .iter()
            .zip(&high)
            .map(|(&lo, &hi)| usize::from(lo) | usize::from(hi) << 8);

        let mut runs: Vec<(usize, usize)> = Vec::new();
        for off in offsets {
            match runs.last_mut() {
                Some((start, len)) if *start + *len == off => *len += 1,
                _ => runs.push((off, 1)),
            }
        }
        Some(Self { runs })
    }

    /// Writes the file bytes of one record. `entry` is at least the ring record long and
    /// `out` has the record's encoded size.
    #[inline]
    fn write(&self, entry: &[u8], out: &mut [u8]) {
        let mut pos = 0;
        for &(off, len) in &self.runs {
            out[pos..pos + len].copy_from_slice(&entry[off..off + len]);
            pos += len;
        }
    }
}

struct MapWriterJob<T>
where
    T: Serialize + Copy + Send + 'static,
{
    bytes_written: Arc<AtomicU64>,
    sink: Option<Sink>,
    file_path: PathBuf,
    /// Bytes of a record in the ring buffer, `size_of::<T>()` unless the job has a
    /// `RecordShape`
    ring_len: usize,
    /// Layout id in the header of a raw trace
    layout_id: u32,
    /// Size of a record in the file without the delimiter
    record_size: usize,
    /// How the ring buffer bytes become file bytes, None to serialize with bincode
    layout: Option<PackedLayout>,
    /// Records written so far
    records: u64,
    /// Records already added to `bytes_written`
    counted: u64,
    /// Error that made the callback stop consuming
    error: Option<JobError>,
    /// The CPU of every written record, `<file>.cpu`
    cpus: CpuRuns,
    /// Sees each written record
    observer: Option<Observer>,
    /// What a pooled sink did, once the file is finished
    sink_stats: Option<SinkStats>,
    /// Set for the raw format
    raw: Option<RawState>,
    _marker: std::marker::PhantomData<T>,
}

/// What a writer of the raw format wrote so far
#[derive(Default)]
struct RawState {
    /// The header frame is in the file (it comes with the first span)
    header: bool,
    /// Frames after the header: records and discarded records
    frames: u64,
}

impl<T> MapWriterJob<T>
where
    T: Serialize + Copy + Send + 'static,
{
    #[cfg(test)]
    fn new(file_path: PathBuf, bytes_written: Arc<AtomicU64>) -> Result<Self, WriterError> {
        Self::with_sink(
            file_path,
            bytes_written,
            SinkConfig::default(),
            WriterFormat::Records,
            None,
        )
    }

    fn with_sink(
        file_path: PathBuf,
        bytes_written: Arc<AtomicU64>,
        sink: SinkConfig,
        format: WriterFormat,
        shape: Option<RecordShape>,
    ) -> Result<Self, WriterError> {
        let ring_len = shape
            .as_ref()
            .map_or(std::mem::size_of::<T>(), |shape| shape.ring_len);
        let entry_size = ring_len.max(1);
        let chunk_bytes = entry_size
            .checked_mul(WRITER_BUFFER_SIZE)
            .unwrap_or(WRITER_BUFFER_SIZE * 128)
            .max(WRITER_BUFFER_SIZE);

        let sink = Sink::open(&file_path, chunk_bytes, sink)?;
        // Records are plain old data, all zeros is a valid value
        let zero: T = unsafe { mem::zeroed() };
        let record_size = bincode::serialized_size(&zero)
            .map_err(|err| io::Error::new(ErrorKind::InvalidInput, err))?
            as usize;
        // A shaped record is shorter than T, so it is copied by its runs, never deserialized
        let (record_size, layout, layout_id) = match shape {
            Some(shape) => (
                shape.runs.iter().map(|(_, len)| len).sum(),
                Some(PackedLayout { runs: shape.runs }),
                shape.layout_id,
            ),
            None => (
                record_size,
                PackedLayout::of::<T>(),
                tcbee_common::records::LAYOUT_ID,
            ),
        };
        if layout.is_none() {
            info!(
                "No packed layout for {}, serializing with bincode",
                std::any::type_name::<T>()
            );
        }

        info!(
            "Registered writer for type {} at {} (entry {} bytes, chunk {} bytes)",
            std::any::type_name::<T>(),
            file_path.display(),
            entry_size,
            chunk_bytes
        );

        Ok(Self {
            cpus: CpuRuns::new(&file_path),
            bytes_written,
            sink: Some(sink),
            file_path,
            ring_len,
            layout_id,
            record_size,
            layout,
            records: 0,
            counted: 0,
            error: None,
            observer: None,
            sink_stats: None,
            raw: (format == WriterFormat::Raw).then(RawState::default),
            _marker: std::marker::PhantomData,
        })
    }

    /// Grows and unmaps the file on `helpers` instead of the writer's CPU
    fn with_helpers(mut self, helpers: HelperPlacement) -> Self {
        if let Some(sink) = &mut self.sink {
            sink.set_helpers(helpers);
        }
        self
    }

    fn name(&self) -> &str {
        self.file_path.to_str().unwrap_or("<unknown>")
    }

    /// Ring buffer callback of the ring of `cpu`: writes one record and notes its CPU
    fn write_from(&mut self, cpu: u32, entry: &[u8]) -> i32 {
        let index = self.records;
        let ret = self.write(entry);
        if ret == 0 {
            self.cpus.note(index, cpu);
        }
        ret
    }

    /// Raw format: writes `span`, frames copied from the ring of `cpu` holding `records`
    /// records and `discards` discarded ones. Writes the header frame before the first.
    fn write_span(
        &mut self,
        cpu: u32,
        span: &[u8],
        records: u64,
        discards: u64,
    ) -> Result<(), JobError> {
        let Some(sink) = self.sink.as_mut() else {
            return Ok(());
        };
        let state = self.raw.as_mut().expect("raw format");
        if !state.header {
            let header = raw::header_frame(self.ring_len, self.layout_id);
            sink.reserve(header.len())?.copy_from_slice(&header);
            state.header = true;
        }
        // From the ring's mapping straight into the file where the sink can: the producers get
        // the span back only after this returns
        sink.write_bytes(span)?;
        // The side file counts frames, which are the records unless some were discarded
        self.cpus.note(state.frames, cpu);
        state.frames += records + discards;
        self.records += records;
        if let Some(observer) = &mut self.observer {
            for frame in raw::frames(span, self.ring_len) {
                if let raw::Frame::Record(record) = frame {
                    observer(record);
                }
            }
        }
        Ok(())
    }

    /// Bytes of one record (or frame) in the file
    fn frame_len(&self) -> usize {
        match self.raw {
            Some(_) => raw::stride(self.ring_len),
            None => self.record_size + RECORD_DELIMITER.len(),
        }
    }

    /// Records, or frames including the header, in the file so far
    fn frames_written(&self) -> u64 {
        match &self.raw {
            Some(state) => state.frames + u64::from(state.header),
            None => self.records,
        }
    }

    /// Writes one record. A non-zero return value stops libbpf from consuming further
    /// records, the error is kept for the writer loop.
    fn write(&mut self, entry: &[u8]) -> i32 {
        match self.try_write(entry) {
            Ok(()) => {
                self.records += 1;
                if let Some(observer) = &mut self.observer {
                    observer(entry);
                }
                0
            }
            Err(err) => {
                self.error = Some(err);
                -libc::ECANCELED
            }
        }
    }

    fn try_write(&mut self, entry: &[u8]) -> Result<(), JobError> {
        let sink = match self.sink.as_mut() {
            Some(sink) => sink,
            None => return Ok(()),
        };

        if entry.len() < self.ring_len {
            return Err(JobError::ShortRecord(entry.len()));
        }

        let size = self.record_size;
        let buf = sink
            .reserve(size + RECORD_DELIMITER.len())
            .map_err(JobError::Io)?;
        let (record, delimiter) = buf.split_at_mut(size);
        match &self.layout {
            Some(layout) => layout.write(entry, record),
            None => {
                let value = unsafe { std::ptr::read_unaligned(entry.as_ptr() as *const T) };
                bincode::serialize_into(record, &value).map_err(JobError::Serialize)?;
            }
        }
        delimiter.copy_from_slice(&RECORD_DELIMITER);
        Ok(())
    }

    /// Counts the bytes written and lets the sink catch up between polls of the rings
    fn tick(&mut self) -> Result<(), JobError> {
        self.count_bytes();
        match &mut self.sink {
            Some(sink) => sink.tick().map_err(JobError::Io),
            None => Ok(()),
        }
    }

    /// Adds the records written since the last call to `bytes_written`
    fn count_bytes(&mut self) {
        let written = self.frames_written();
        let new = written - self.counted;
        if new == 0 {
            return;
        }
        self.counted = written;
        trace!("Wrote {} records to {}", new, self.file_path.display());
        let bytes = new * self.frame_len() as u64;
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    fn flush(&mut self) -> Result<(), JobError> {
        let mut result = Ok(());
        if let Some(sink) = self.sink.take() {
            let (frames, stats, finished) = sink.finish(self.frame_len());
            // A failed write cuts the file before records that were already counted
            if let Some(frames) = frames {
                match &mut self.raw {
                    Some(state) => {
                        let kept = frames.saturating_sub(u64::from(state.header));
                        state.frames = state.frames.min(kept);
                        self.records = self.records.min(kept);
                    }
                    None => self.records = self.records.min(frames),
                }
            }
            if let Some(stats) = &stats {
                info!(
                    "Finished {} ({}): {} writes, the writer waited {} times for {} ms",
                    self.file_path.display(),
                    stats.sink,
                    stats.writes,
                    stats.stalls,
                    stats.stall_ns / 1_000_000
                );
            }
            self.sink_stats = stats;
            result = finished.map_err(JobError::Io);
        }
        // The side file is finished even if the trace is not, it describes the records written
        let frames = self.raw.as_ref().map_or(self.records, |state| state.frames);
        self.cpus.finish(frames);
        result
    }
}

/// `<file>.cpu` next to a trace file: the CPU (ring buffer) each record came from, as one
/// 12-byte entry per run of records from the same CPU: u64 index of the run's first record
/// and u32 CPU id, little endian. A last entry with CPU `CPU_SIDE_END` holds the number of
/// records; a file without it was cut short. The records of a flow are spread over the CPUs'
/// rings, so this tells which ring a gap in a flow's hook_seq belongs to. Entries are written
/// as the runs start, so memory stays flat; the file is created with the first record, and a
/// failure to write it only loses the side file, never the trace.
const CPU_SIDE_END: u32 = u32::MAX;

fn cpu_side_path(trace: &Path) -> PathBuf {
    let mut path = trace.to_path_buf().into_os_string();
    path.push(".cpu");
    path.into()
}

struct CpuRuns {
    path: PathBuf,
    out: Option<BufWriter<File>>,
    last: Option<u32>,
    failed: bool,
}

impl CpuRuns {
    fn new(trace: &Path) -> Self {
        Self {
            path: cpu_side_path(trace),
            out: None,
            last: None,
            failed: false,
        }
    }

    /// Notes that record `index` came from `cpu`
    #[inline]
    fn note(&mut self, index: u64, cpu: u32) {
        if self.last == Some(cpu) || self.failed {
            return;
        }
        self.last = Some(cpu);
        self.entry(index, cpu);
    }

    fn entry(&mut self, index: u64, cpu: u32) {
        let mut entry = [0u8; 12];
        entry[..8].copy_from_slice(&index.to_le_bytes());
        entry[8..].copy_from_slice(&cpu.to_le_bytes());
        if let Err(err) = self.out().and_then(|out| out.write_all(&entry)) {
            self.fail(err);
        }
    }

    fn out(&mut self) -> io::Result<&mut BufWriter<File>> {
        if self.out.is_none() {
            let file = File::create(&self.path)?;
            self.out = Some(BufWriter::with_capacity(64 << 10, file));
        }
        Ok(self.out.as_mut().expect("just created"))
    }

    /// Ends a side file that has entries with the number of records written
    fn finish(&mut self, records: u64) {
        if self.out.is_none() {
            return;
        }
        self.entry(records, CPU_SIDE_END);
        if let Some(mut out) = self.out.take() {
            if let Err(err) = out.flush() {
                self.fail(err);
            }
        }
    }

    /// An incomplete side file would point records at the wrong CPU, so it is removed
    fn fail(&mut self, err: io::Error) {
        error!(
            "Writing {} failed, recording without it: {}",
            self.path.display(),
            err
        );
        self.failed = true;
        self.out = None;
        let _ = fs::remove_file(&self.path);
    }
}

/// Outcome of one writer thread
pub struct WriterReport {
    pub rb: u32,
    pub file: PathBuf,
    pub format: WriterFormat,
    pub records: u64,
    pub error: Option<String>,
    /// What a pooled sink did, None for the memory-mapped file
    pub sink: Option<SinkStats>,
    /// What the writer CPU's thread that wrote it did, None for a thread per file
    pub thread: Option<WriterThreadStats>,
}

#[derive(Debug)]
pub enum WriterError {
    Io(io::Error),
    WorkerPanicked,
}

impl fmt::Display for WriterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriterError::Io(err) => write!(f, "I/O error: {}", err),
            WriterError::WorkerPanicked => write!(f, "writer worker thread panicked"),
        }
    }
}

impl std::error::Error for WriterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WriterError::Io(err) => Some(err),
            WriterError::WorkerPanicked => None,
        }
    }
}

impl From<io::Error> for WriterError {
    fn from(err: io::Error) -> Self {
        WriterError::Io(err)
    }
}

#[derive(Debug)]
enum JobError {
    Io(io::Error),
    Serialize(Box<BincodeErrorKind>),
    ShortRecord(usize),
    Ring(WalkError),
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::Io(err) => write!(f, "I/O error: {}", err),
            JobError::Serialize(err) => write!(f, "serialization error: {}", err),
            JobError::ShortRecord(len) => write!(f, "ring buffer record of only {} bytes", len),
            JobError::Ring(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for JobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JobError::Io(err) => Some(err),
            JobError::Serialize(err) => Some(err),
            JobError::ShortRecord(_) | JobError::Ring(_) => None,
        }
    }
}

impl From<io::Error> for JobError {
    fn from(err: io::Error) -> Self {
        JobError::Io(err)
    }
}

#[cfg(test)]
#[path = "writer_bench.rs"]
mod bench;

#[cfg(test)]
mod tests {
    use std::{env, sync::Mutex};

    use tcbee_common::records::*;

    use super::*;
    use crate::{
        placement::tests::allowed_cpus,
        rawring::tests::{page, FakeRing, MemRing},
    };

    /// xorshift64*, enough to fill records with arbitrary bytes
    pub(super) struct Rng(pub(super) u64);

    impl Rng {
        pub(super) fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len)
                .map(|_| {
                    self.0 ^= self.0 >> 12;
                    self.0 ^= self.0 << 25;
                    self.0 ^= self.0 >> 27;
                    (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
                })
                .collect()
        }
    }

    /// The packed copy must produce exactly the bincode encoding the file format is
    /// defined by, for random field values (and random padding)
    fn assert_packed_matches_bincode<T: Serialize + Copy>() {
        let name = std::any::type_name::<T>();
        let layout = PackedLayout::of::<T>().unwrap_or_else(|| panic!("no layout for {name}"));
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ mem::size_of::<T>() as u64);
        for _ in 0..1000 {
            let entry = rng.bytes(mem::size_of::<T>());
            let value = unsafe { std::ptr::read_unaligned(entry.as_ptr() as *const T) };
            let expected = bincode::serialize(&value).unwrap();
            let mut packed = vec![0u8; expected.len()];
            layout.write(&entry, &mut packed);
            assert_eq!(packed, expected, "{name}");
        }
    }

    #[test]
    fn packed_layout_matches_bincode() {
        assert_packed_matches_bincode::<tcp4_packet_trace>();
        assert_packed_matches_bincode::<tcp6_packet_trace>();
        assert_packed_matches_bincode::<sock_trace_entry>();
        assert_packed_matches_bincode::<cwnd_trace_entry>();
        assert_packed_matches_bincode::<cubic_trace_entry>();
        assert_packed_matches_bincode::<bbr_trace_entry>();
        assert_packed_matches_bincode::<reno_trace_entry>();
        assert_packed_matches_bincode::<tcp_probe_entry>();
        assert_packed_matches_bincode::<tcp_retransmit_synack_entry>();
        assert_packed_matches_bincode::<tcp_bad_csum_entry>();
        assert_packed_matches_bincode::<mptcp_pm_entry>();
        assert_packed_matches_bincode::<tcp_event_entry>();
        assert_packed_matches_bincode::<flow_owner_entry>();
    }

    /// Records written across several remaps all end up in the file
    #[test]
    fn mmap_file_keeps_all_bytes() {
        let path = env::temp_dir().join(format!("tcbee-writer-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut file = MmapBackedFile::new(&path, 1000).unwrap();
        let mut expected = Vec::new();
        let mut rng = Rng(42);
        for _ in 0..20_000 {
            let record = rng.bytes(37);
            file.reserve(record.len()).unwrap().copy_from_slice(&record);
            expected.extend_from_slice(&record);
        }
        file.finish().unwrap();
        let written = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(written == expected);
    }

    /// Writing faster than the helper can grow forces several background and blocking growths
    #[test]
    fn mmap_file_grows_in_background() {
        let path = env::temp_dir().join(format!("tcbee-grow-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut file = MmapBackedFile::new(&path, 1000).unwrap();
        let mut expected = Vec::new();
        let mut rng = Rng(7);
        for _ in 0..50_000 {
            let record = rng.bytes(1000);
            file.reserve(record.len()).unwrap().copy_from_slice(&record);
            expected.extend_from_slice(&record);
        }
        file.finish().unwrap();
        let written = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(written == expected);
    }

    /// Two CPUs' rings, filled through the fake kernel side, drained by a raw job
    fn raw_rings(
        records: &[usize],
        ring_size: usize,
    ) -> (Vec<(u32, RingMap)>, Vec<MemRing>, Vec<FakeRing>) {
        raw_rings_of(mem::size_of::<tcp4_packet_trace>(), records, ring_size)
    }

    /// As `raw_rings`, with records of `len` bytes
    fn raw_rings_of(
        len: usize,
        records: &[usize],
        ring_size: usize,
    ) -> (Vec<(u32, RingMap)>, Vec<MemRing>, Vec<FakeRing>) {
        let mut rings = Vec::new();
        let mut mems = Vec::new();
        let mut fakes = Vec::new();
        for (i, &n) in records.iter().enumerate() {
            let mut fake = FakeRing::new(ring_size, len);
            // Start near the end of the data so that the records wrap around
            let skip = (ring_size / raw::stride(len)).saturating_sub(n / 2);
            for _ in 0..skip {
                fake.push(0xee);
            }
            fake.consumer = fake.producer;
            for r in 0..n {
                fake.push((i * 64 + r % 64) as u8);
            }
            let mut mem = MemRing::new(ring_size);
            mem.load(&fake);
            let ring = mem.ring_map();
            ring.release(fake.consumer);
            rings.push((i as u32 * 3, ring));
            mems.push(mem);
            fakes.push(fake);
        }
        (rings, mems, fakes)
    }

    fn raw_job(path: &Path, sink: SinkConfig) -> MapWriterJob<tcp4_packet_trace> {
        let _ = std::fs::remove_file(path);
        MapWriterJob::<tcp4_packet_trace>::with_sink(
            path.into(),
            Arc::new(AtomicU64::new(0)),
            sink,
            WriterFormat::Raw,
            None,
        )
        .unwrap()
    }

    #[test]
    fn raw_spans_hold_every_record_once() {
        let path = env::temp_dir().join(format!("tcbee-raw-{}", std::process::id()));
        let (rings, mems, fakes) = raw_rings(&[100, 40], 2 * page());
        let mut job = Draining {
            job: raw_job(&path, SinkConfig::default()),
            rings,
        };
        assert_eq!(drain_all(&mut job).unwrap(), 140);
        // Nothing new: nothing copied twice
        assert_eq!(drain_all(&mut job).unwrap(), 0);
        for (mem, fake) in mems.iter().zip(&fakes) {
            assert_eq!(mem.consumer_pos(), fake.producer);
        }
        job.job.count_bytes();
        let bytes_written = job.job.bytes_written.load(Ordering::Relaxed);
        job.job.flush().unwrap();
        assert_eq!(job.job.records, 140);

        let len = mem::size_of::<tcp4_packet_trace>();
        let stride = raw::stride(len);
        let file = std::fs::read(&path).unwrap();
        assert_eq!(file.len(), 141 * stride);
        assert_eq!(bytes_written, file.len() as u64);
        assert!(raw::parse_header(&file).unwrap().is_ok());
        let fills: Vec<u8> = file[stride..]
            .chunks(stride)
            .map(|frame| match raw::frame(frame, len) {
                raw::Frame::Record(record) => record[0],
                other => panic!("{other:?}"),
            })
            .collect();
        let expected: Vec<u8> = (0..100)
            .map(|r| (r % 64) as u8)
            .chain((0..40).map(|r| (64 + r % 64) as u8))
            .collect();
        assert_eq!(fills, expected);

        // The side file names the CPU of each ring's span, counting frames after the header
        let side = std::fs::read(cpu_side_path(&path)).unwrap();
        let entries: Vec<(u64, u32)> = side
            .chunks(12)
            .map(|e| {
                (
                    u64::from_le_bytes(e[..8].try_into().unwrap()),
                    u32::from_le_bytes(e[8..].try_into().unwrap()),
                )
            })
            .collect();
        // The first ring wraps: two spans, one entry
        assert_eq!(entries, [(0, 0), (100, 3), (140, CPU_SIDE_END)]);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(cpu_side_path(&path)).unwrap();
    }

    /// The records format drained from the ring mapping writes the same file as record by
    /// record writes (what the libbpf callback did), also across the wrap and in spans
    #[test]
    fn records_from_rings_match_record_writes() {
        let len = mem::size_of::<tcp4_packet_trace>();
        let records = 2 * RAW_SPAN_BYTES / raw::stride(len);
        let (rings, _mems, fakes) = raw_rings(&[records, 7], 256 << 10);
        let ring_path = env::temp_dir().join(format!("tcbee-rec-ring-{}", std::process::id()));
        let _ = std::fs::remove_file(&ring_path);
        let mut job = Draining {
            job: MapWriterJob::<tcp4_packet_trace>::new(
                ring_path.clone(),
                Arc::new(AtomicU64::new(0)),
            )
            .unwrap(),
            rings,
        };
        assert_eq!(drain_all(&mut job).unwrap(), records as u64 + 7);
        job.job.flush().unwrap();

        let direct_path = env::temp_dir().join(format!("tcbee-rec-direct-{}", std::process::id()));
        let _ = std::fs::remove_file(&direct_path);
        let mut direct = MapWriterJob::<tcp4_packet_trace>::new(
            direct_path.clone(),
            Arc::new(AtomicU64::new(0)),
        )
        .unwrap();
        for fake in &fakes {
            let span = fake.span(fake.consumer, fake.producer);
            for frame in raw::frames(span, len) {
                if let raw::Frame::Record(record) = frame {
                    assert_eq!(direct.write(record), 0);
                }
            }
        }
        direct.flush().unwrap();
        let from_rings = std::fs::read(&ring_path).unwrap();
        assert_eq!(from_rings.len(), (records + 7) * (direct.record_size + 4));
        assert!(from_rings == std::fs::read(&direct_path).unwrap());
        for path in [&ring_path, &direct_path] {
            std::fs::remove_file(path).unwrap();
            let _ = std::fs::remove_file(cpu_side_path(path));
        }
    }

    /// Field-selected sock records: the ring records are the shape's length, the file records
    /// its packed runs, in both formats
    #[test]
    fn shaped_records_hold_every_record_once() {
        use tcbee_trace::sockfields::{Group, SockFields, SockShape};
        let sock = SockShape::of(SockFields::of(&[Group::Cwnd, Group::Rtt]));
        let shape = RecordShape::of_sock(&sock);
        let records = 2 * RAW_SPAN_BYTES / raw::stride(shape.ring_len);
        for format in [WriterFormat::Records, WriterFormat::Raw] {
            let path = env::temp_dir().join(format!(
                "tcbee-shaped-{}-{}",
                format.name(),
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            let (rings, _mems, fakes) = raw_rings_of(shape.ring_len, &[records, 7], 256 << 10);
            let mut job = Draining {
                job: MapWriterJob::<sock_trace_entry>::with_sink(
                    path.clone(),
                    Arc::new(AtomicU64::new(0)),
                    SinkConfig::default(),
                    format,
                    Some(shape.clone()),
                )
                .unwrap(),
                rings,
            };
            assert_eq!(drain_all(&mut job).unwrap(), records as u64 + 7);
            assert_eq!(job.job.records, records as u64 + 7);
            job.job.flush().unwrap();
            let file = std::fs::read(&path).unwrap();
            // The bytes of each ring record, in ring order
            let expected: Vec<Vec<u8>> = fakes
                .iter()
                .flat_map(|fake| {
                    raw::frames(fake.span(fake.consumer, fake.producer), shape.ring_len)
                        .filter_map(|frame| match frame {
                            raw::Frame::Record(record) => Some(record.to_vec()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            match format {
                WriterFormat::Records => {
                    let stride = sock.file_len + RECORD_DELIMITER.len();
                    assert_eq!(file.len(), expected.len() * stride);
                    for (record, written) in expected.iter().zip(file.chunks(stride)) {
                        let packed: Vec<u8> = shape
                            .runs
                            .iter()
                            .flat_map(|&(off, len)| record[off..off + len].to_vec())
                            .collect();
                        assert_eq!(&written[..sock.file_len], &packed[..]);
                        assert_eq!(&written[sock.file_len..], &RECORD_DELIMITER);
                    }
                }
                WriterFormat::Raw => {
                    let header = raw::parse_header(&file).unwrap().unwrap();
                    assert_eq!(header.record_len as usize, shape.ring_len);
                    assert_eq!(header.layout, shape.layout_id);
                    assert_ne!(header.layout, tcbee_common::records::LAYOUT_ID);
                    let frames: Vec<Vec<u8>> =
                        raw::frames(&file[raw::stride(shape.ring_len)..], shape.ring_len)
                            .filter_map(|frame| match frame {
                                raw::Frame::Record(record) => Some(record.to_vec()),
                                _ => None,
                            })
                            .collect();
                    assert_eq!(frames, expected);
                }
            }
            std::fs::remove_file(&path).unwrap();
            let _ = std::fs::remove_file(cpu_side_path(&path));
        }
    }

    /// Spans longer than RAW_SPAN_BYTES are copied in several pieces, the same in every sink
    #[test]
    fn raw_sinks_write_the_same_bytes() {
        let len = mem::size_of::<tcp4_packet_trace>();
        let records = 3 * RAW_SPAN_BYTES / raw::stride(len);
        let write = |kind: SinkKind, name: &str| {
            let path = env::temp_dir().join(format!("tcbee-raw-{}-{}", name, std::process::id()));
            let (rings, _mems, _fakes) = raw_rings(&[records], 256 << 10);
            let sink = SinkConfig {
                kind,
                buffer_bytes: 64 << 10,
                buffers: 3,
                io_threads: 2,
                ..SinkConfig::default()
            };
            let mut job = Draining {
                job: raw_job(&path, sink),
                rings,
            };
            assert_eq!(drain_all(&mut job).unwrap(), records as u64);
            job.job.flush().unwrap();
            assert_eq!(job.job.records, records as u64);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            let _ = std::fs::remove_file(cpu_side_path(&path));
            bytes
        };
        let mmap = write(SinkKind::Mmap, "mmap");
        assert_eq!(mmap.len(), (records + 1) * raw::stride(len));
        assert!(write(SinkKind::Direct, "direct") == mmap);
        assert!(write(SinkKind::Buffered, "buffered") == mmap);
        assert!(write(SinkKind::Uring, "uring") == mmap);
        assert!(write(SinkKind::Sync, "sync") == mmap);
    }

    /// A discarded record is copied as a frame: the side file counts frames, the job records
    #[test]
    fn raw_discards_count_as_frames() {
        let len = mem::size_of::<tcp4_packet_trace>();
        let size = 2 * page();
        let path = env::temp_dir().join(format!("tcbee-raw-discard-{}", std::process::id()));
        let mut fake = FakeRing::new(size, len);
        fake.push(1);
        let pos = fake.reserve(2);
        fake.discard(pos);
        fake.push(3);
        let mut mem = MemRing::new(size);
        mem.load(&fake);
        let rings = vec![(5, mem.ring_map())];
        let mut job = Draining {
            job: raw_job(&path, SinkConfig::default()),
            rings,
        };
        assert_eq!(drain_all(&mut job).unwrap(), 3);
        job.job.flush().unwrap();
        assert_eq!(job.job.records, 2);
        let file = std::fs::read(&path).unwrap();
        assert_eq!(file.len(), 4 * raw::stride(len));
        let kinds: Vec<_> = raw::frames(&file, len)
            .map(|frame| match frame {
                raw::Frame::Record(record) => record[0],
                raw::Frame::Discarded => 0,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(kinds, [0, 1, 0, 3]);
        let side = std::fs::read(cpu_side_path(&path)).unwrap();
        assert_eq!(side.len(), 24);
        assert_eq!(u64::from_le_bytes(side[12..20].try_into().unwrap()), 3);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(cpu_side_path(&path)).unwrap();
    }

    /// A record of another length stops the writer at it: nothing behind it is copied or
    /// given back to the producers
    #[test]
    fn raw_writer_stops_at_a_foreign_record() {
        let len = mem::size_of::<tcp4_packet_trace>();
        let size = 2 * page();
        let path = env::temp_dir().join(format!("tcbee-raw-foreign-{}", std::process::id()));
        let mut fake = FakeRing::new(size, len);
        fake.push(1);
        let bad = fake.push(2);
        fake.put(bad, &16u32.to_ne_bytes());
        fake.push(3);
        let mut mem = MemRing::new(size);
        mem.load(&fake);
        let rings = vec![(0, mem.ring_map())];
        let mut job = Draining {
            job: raw_job(&path, SinkConfig::default()),
            rings,
        };
        let err = drain_all(&mut job).unwrap_err();
        assert!(
            matches!(err, JobError::Ring(WalkError::Length { len: 16, .. })),
            "{err}"
        );
        assert_eq!(mem.consumer_pos(), 0);
        assert_eq!(job.job.records, 0);
        job.job.flush().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(cpu_side_path(&path));
    }

    /// The final drain waits for a record that is still being written and takes the
    /// committed ones behind it too
    #[test]
    fn shutdown_waits_for_busy_records() {
        let len = mem::size_of::<tcp4_packet_trace>();
        let size = 2 * page();
        let path = env::temp_dir().join(format!("tcbee-raw-busy-{}", std::process::id()));
        let mut fake = FakeRing::new(size, len);
        fake.push(1);
        let busy = fake.reserve(2);
        fake.push(3);
        let mut mem = MemRing::new(size);
        mem.load(&fake);
        let rings = vec![(0, mem.ring_map())];
        let mut job = Draining {
            job: raw_job(&path, SinkConfig::default()),
            rings,
        };
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(20));
                fake.commit(busy);
                mem.load(&fake);
            });
            drain_at_shutdown(&mut job, Instant::now() + Duration::from_secs(5)).unwrap();
        });
        assert_eq!(job.job.records, 3);
        job.job.flush().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(cpu_side_path(&path));
    }

    /// A record that never gets committed ends the drain after the wait
    #[test]
    fn shutdown_gives_up_on_stuck_records() {
        let len = mem::size_of::<tcp4_packet_trace>();
        let size = 2 * page();
        let path = env::temp_dir().join(format!("tcbee-raw-stuck-{}", std::process::id()));
        let mut fake = FakeRing::new(size, len);
        fake.push(1);
        fake.reserve(2);
        fake.push(3);
        let mut mem = MemRing::new(size);
        mem.load(&fake);
        let rings = vec![(0, mem.ring_map())];
        let mut job = Draining {
            job: raw_job(&path, SinkConfig::default()),
            rings,
        };
        let start = Instant::now();
        drain_at_shutdown(&mut job, Instant::now() + Duration::from_millis(30)).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(30));
        assert_eq!(job.job.records, 1);
        job.job.flush().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(cpu_side_path(&path));
    }

    #[test]
    fn idle_ladder_spins_then_sleeps_longer() {
        let mut ladder = IdleLadder::new();
        for _ in 0..SPIN_PASSES {
            assert_eq!(ladder.quiet(), None);
        }
        let sleeps: Vec<Duration> = (0..9).map(|_| ladder.quiet().unwrap()).collect();
        assert_eq!(sleeps[0], MIN_IDLE_SLEEP);
        assert_eq!(sleeps[1], 2 * MIN_IDLE_SLEEP);
        assert!(sleeps.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(*sleeps.last().unwrap(), MAX_IDLE_SLEEP);
        ladder.backlog();
        assert_eq!(ladder.quiet(), None);
    }

    /// Rings of one CPU's jobs, each filled with `n` records, as a raw job each
    fn cpu_jobs(
        name: &str,
        records: &[usize],
        ring_size: usize,
    ) -> (CpuJobList, Vec<MemRing>, Vec<PathBuf>) {
        let mut jobs: CpuJobList = Vec::new();
        let mut all_mems = Vec::new();
        let mut paths = Vec::new();
        for (i, &n) in records.iter().enumerate() {
            let path = env::temp_dir().join(format!("tcbee-cpu-{name}-{i}-{}", std::process::id()));
            let (rings, mems, _fakes) = raw_rings(&[n], ring_size);
            let job = raw_job(&path, SinkConfig::default());
            // The last job stands for the rare hooks
            jobs.push((i + 1 == records.len(), Box::new(Draining { job, rings })));
            all_mems.extend(mems);
            paths.push(path);
        }
        (jobs, all_mems, paths)
    }

    fn remove(paths: &[PathBuf]) {
        for path in paths {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(cpu_side_path(path));
        }
    }

    /// One thread drains a loaded job and trickle jobs: each file gets each record once
    #[test]
    fn cpu_thread_drains_all_its_jobs() {
        let Some(&cpu) = allowed_cpus().first() else {
            return;
        };
        let len = mem::size_of::<tcp4_packet_trace>();
        let loaded = 3 * RAW_SPAN_BYTES / raw::stride(len);
        let counts = [loaded, 3, 1, 7];
        let (jobs, mems, paths) = cpu_jobs("all", &counts, 256 << 10);
        let running = Arc::new(AtomicBool::new(true));
        let stop = running.clone();
        let results = thread::scope(|scope| {
            let handle = scope.spawn(|| cpu_loop(jobs, running, cpu, None, None));
            thread::sleep(Duration::from_millis(30));
            stop.store(false, Ordering::Relaxed);
            handle.join().unwrap()
        });
        let (results, stats) = results;
        assert_eq!((stats.cpu, stats.files), (cpu, counts.len()));
        assert!(stats.passes > stats.backlog_passes && stats.backlog_passes >= 2);
        assert!(stats.cpu_ns > 0 && stats.wall_ns >= stats.cpu_ns / 2);
        assert_eq!(results.len(), counts.len());
        for ((records, _, result), &n) in results.iter().zip(&counts) {
            assert!(result.is_ok());
            assert_eq!(*records, n as u64);
        }
        for (path, &n) in paths.iter().zip(&counts) {
            assert_eq!(
                std::fs::metadata(path).unwrap().len(),
                ((n + 1) * raw::stride(len)) as u64
            );
        }
        drop(mems);
        remove(&paths);
    }

    /// A job that fails is finished alone, the others of its thread go on
    #[test]
    fn cpu_thread_retires_a_failed_job_alone() {
        let Some(&cpu) = allowed_cpus().first() else {
            return;
        };
        let len = mem::size_of::<tcp4_packet_trace>();
        let size = 2 * page();
        let (mut jobs, mems, mut paths) = cpu_jobs("fail", &[5, 2], size);
        let path = env::temp_dir().join(format!("tcbee-cpu-fail-bad-{}", std::process::id()));
        let mut fake = FakeRing::new(size, len);
        fake.push(1);
        let bad = fake.push(2);
        fake.put(bad, &16u32.to_ne_bytes());
        let mut mem = MemRing::new(size);
        mem.load(&fake);
        let job = raw_job(&path, SinkConfig::default());
        jobs.insert(
            0,
            (
                false,
                Box::new(Draining {
                    job,
                    rings: vec![(0, mem.ring_map())],
                }),
            ),
        );
        paths.push(path);
        let running = Arc::new(AtomicBool::new(true));
        let stop = running.clone();
        let results = thread::scope(|scope| {
            let handle = scope.spawn(|| cpu_loop(jobs, running, cpu, None, None));
            thread::sleep(Duration::from_millis(20));
            stop.store(false, Ordering::Relaxed);
            handle.join().unwrap().0
        });
        assert!(matches!(
            results[0].2,
            Err(JobError::Ring(WalkError::Length { len: 16, .. }))
        ));
        assert_eq!(results[1].0, 5);
        assert_eq!(results[2].0, 2);
        assert!(results[1].2.is_ok() && results[2].2.is_ok());
        drop((mems, mem));
        remove(&paths);
    }

    #[test]
    fn raw_observer_sees_the_records() {
        let path = env::temp_dir().join(format!("tcbee-raw-observer-{}", std::process::id()));
        let (rings, _mems, _fakes) = raw_rings(&[5], 2 * page());
        let mut job = Draining {
            job: raw_job(&path, SinkConfig::default()),
            rings,
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        job.job.observer = Some(Box::new(move |entry: &[u8]| {
            assert_eq!(entry.len(), mem::size_of::<tcp4_packet_trace>());
            sink.lock().unwrap().push(entry[0]);
        }));
        drain_all(&mut job).unwrap();
        job.job.flush().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(cpu_side_path(&path));
        assert_eq!(*seen.lock().unwrap(), [0, 1, 2, 3, 4]);
    }

    /// A finished background growth is taken over between polls, without another reserve
    #[test]
    fn tick_adopts_finished_growth() {
        let path = env::temp_dir().join(format!("tcbee-adopt-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut file = MmapBackedFile::new(&path, 1000).unwrap();
        while file.pending.is_none() {
            file.reserve(1000).unwrap().fill(1);
        }
        let before = file.capacity;
        for _ in 0..1000 {
            file.adopt_finished_growth().unwrap();
            if file.pending.is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(file.pending.is_none());
        assert!(file.capacity > before);
        file.finish().unwrap();
        std::fs::remove_file(&path).unwrap();
    }

    /// The free space ahead of the writer stays within a few growth steps, also for large files
    #[test]
    fn growth_stays_close_to_the_data() {
        let growth = 1000 * WRITER_BUFFER_SIZE;
        let mut capacity = growth.max(MIN_MMAP_GROWTH);
        let mut grown = 0;
        let mut position = 0;
        while position < 50 << 30 {
            position += 1 << 20;
            if position > capacity {
                capacity = next_capacity(capacity, growth, position);
            }
            let next = next_capacity(capacity, growth, position);
            if starts_growth(capacity, position, next) {
                capacity = next;
                grown += 1;
            }
            assert!(
                capacity - position <= 3 * MAX_MMAP_GROWTH,
                "{capacity} for {position}"
            );
        }
        // About one growth per step written, not one whenever half of the file is used
        assert!(grown < 60, "{grown} growths");

        // A file with a few records stays at its first size
        let capacity = growth.max(MIN_MMAP_GROWTH);
        let next = next_capacity(capacity, growth, 300);
        assert!(!starts_growth(capacity, 300, next));
    }

    /// A writer's file grows and unmaps on the writer's helper CPUs
    #[test]
    fn writer_jobs_get_the_helper_cpus() {
        let path = env::temp_dir().join(format!("tcbee-helper-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let job = MapWriterJob::<tcp4_packet_trace>::new(path.clone(), Arc::new(AtomicU64::new(0)))
            .unwrap()
            .with_helpers(HelperPlacement {
                cpus: Arc::new(WriterCpus::new(vec![0], Placement::RoundRobin)),
                writer: None,
            });
        let Some(Sink::Mmap(file)) = &job.sink else {
            panic!("the default sink is the memory-mapped file");
        };
        assert!(file.helpers.is_some());
        drop(job);
        let _ = std::fs::remove_file(&path);
    }

    /// Helpers run on the CPUs without a writer, not on the CPU of the thread that starts them
    #[test]
    fn helpers_avoid_writer_cpus() {
        let online = allowed_cpus();
        if online.len() < 2 {
            return;
        }
        let (writer, other) = (online[0], online[1]);
        let helpers = WriterCpus::new(vec![writer, other], Placement::RoundRobin);
        helpers.add_writer(writer, "w");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            pin_to_cpu(writer);
            spawn_helper(
                "test-helper",
                helpers.round_robin_helper_set(),
                None,
                move || {
                    tx.send(allowed_cpus()).unwrap();
                },
            )
            .unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(rx.recv().unwrap(), vec![other]);
        // Every pool CPU has a writer: the helpers may use the whole pool
        let full = WriterCpus::new(vec![writer], Placement::RoundRobin);
        full.add_writer(writer, "w");
        let set = full.round_robin_helper_set().unwrap();
        assert!(unsafe { libc::CPU_ISSET(writer, &set) });
    }

    /// A file that was opened but never written is removed, one with data is kept
    #[test]
    fn unused_file_is_removed() {
        let path = env::temp_dir().join(format!("tcbee-writer-empty-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        MmapBackedFile::new(&path, 1000).unwrap().finish().unwrap();
        remove_if_empty(&path);
        assert!(!path.exists());

        let mut file = MmapBackedFile::new(&path, 1000).unwrap();
        file.reserve(4).unwrap().copy_from_slice(&RECORD_DELIMITER);
        file.finish().unwrap();
        // Opening it again appends, failing then must not delete the data
        MmapBackedFile::new(&path, 1000).unwrap().finish().unwrap();
        remove_if_empty(&path);
        let kept = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(kept, RECORD_DELIMITER);
    }

    fn cpu_side_file(path: &Path) -> Vec<(u64, u32)> {
        std::fs::read(cpu_side_path(path))
            .unwrap()
            .chunks(12)
            .map(|e| {
                (
                    u64::from_le_bytes(e[..8].try_into().unwrap()),
                    u32::from_le_bytes(e[8..].try_into().unwrap()),
                )
            })
            .collect()
    }

    /// The side file has one entry per run of records from one CPU, with the CPU's real id
    #[test]
    fn side_file_notes_the_cpu_of_every_run() {
        let path = env::temp_dir().join(format!("tcbee-cpu-side-{}", std::process::id()));
        let mut job =
            MapWriterJob::<tcp4_packet_trace>::new(path.clone(), Arc::new(AtomicU64::new(0)))
                .unwrap();
        let entry = vec![0u8; mem::size_of::<tcp4_packet_trace>()];
        for cpu in [0, 0, 2, 5, 5, 0] {
            assert_eq!(job.write_from(cpu, &entry), 0);
        }
        // A record that is not written starts no run
        assert_ne!(job.write_from(7, &entry[..3]), 0);
        job.flush().unwrap();
        let runs = cpu_side_file(&path);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(job.cpus.path).unwrap();
        assert_eq!(runs, [(0, 0), (2, 2), (3, 5), (5, 0), (6, CPU_SIDE_END)]);
    }

    /// Every sink writes the same file bytes, also when the job moves to another thread as in
    /// `Writer::spawn`, and when it appends to an existing file
    #[test]
    fn sinks_write_the_same_bytes() {
        let size = mem::size_of::<tcp4_packet_trace>();
        let mut rng = Rng(0x5eed);
        let entries: Vec<Vec<u8>> = (0..20_000).map(|_| rng.bytes(size)).collect();
        let write = |kind: SinkKind, name: &str| {
            let path = env::temp_dir().join(format!("tcbee-sink-{}-{}", name, std::process::id()));
            let _ = std::fs::remove_file(&path);
            let sink = SinkConfig {
                kind,
                buffer_bytes: 64 << 10,
                buffers: 3,
                io_threads: 2,
                ..SinkConfig::default()
            };
            for half in [&entries[..7_777], &entries[7_777..]] {
                let job = MapWriterJob::<tcp4_packet_trace>::with_sink(
                    path.clone(),
                    Arc::new(AtomicU64::new(0)),
                    sink.clone(),
                    WriterFormat::Records,
                    None,
                )
                .unwrap();
                let records = thread::scope(|scope| {
                    scope
                        .spawn(move || {
                            let mut job = job;
                            for entry in half {
                                assert_eq!(job.write(entry), 0);
                            }
                            job.flush().unwrap();
                            assert_eq!(job.sink_stats.is_some(), kind != SinkKind::Mmap);
                            job.records
                        })
                        .join()
                        .unwrap()
                });
                assert_eq!(records, half.len() as u64);
            }
            let bytes = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            bytes
        };
        let mmap = write(SinkKind::Mmap, "mmap");
        assert_eq!(mmap.len() % entries.len(), 0);
        assert!(write(SinkKind::Direct, "direct") == mmap);
        assert!(write(SinkKind::Buffered, "buffered") == mmap);
        assert!(write(SinkKind::Uring, "uring") == mmap);
        assert!(write(SinkKind::Sync, "sync") == mmap);
    }

    #[test]
    fn observer_sees_the_written_records() {
        let path = env::temp_dir().join(format!("tcbee-observer-{}", std::process::id()));
        let mut job =
            MapWriterJob::<tcp4_packet_trace>::new(path.clone(), Arc::new(AtomicU64::new(0)))
                .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        job.observer = Some(Box::new(move |entry: &[u8]| {
            sink.lock().unwrap().push(entry[0]);
        }));
        let size = mem::size_of::<tcp4_packet_trace>();
        for first in [1u8, 2] {
            let mut entry = vec![0u8; size];
            entry[0] = first;
            assert_eq!(job.write(&entry), 0);
        }
        assert_ne!(job.write(&[3]), 0);
        job.flush().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&job.cpus.path);
        assert_eq!(*seen.lock().unwrap(), [1, 2]);
    }

    /// Without records there is no side file
    #[test]
    fn no_side_file_without_records() {
        let path = env::temp_dir().join(format!("tcbee-cpu-none-{}", std::process::id()));
        let mut job =
            MapWriterJob::<tcp4_packet_trace>::new(path.clone(), Arc::new(AtomicU64::new(0)))
                .unwrap();
        job.flush().unwrap();
        remove_if_empty(&path);
        assert!(!cpu_side_path(&path).exists());
    }

    /// A side file that cannot be written is given up, the trace is still written
    #[test]
    fn failing_side_file_keeps_the_trace() {
        let path = env::temp_dir().join(format!("tcbee-cpu-fail-{}", std::process::id()));
        let side = cpu_side_path(&path);
        std::fs::create_dir_all(&side).unwrap();
        let mut job =
            MapWriterJob::<tcp4_packet_trace>::new(path.clone(), Arc::new(AtomicU64::new(0)))
                .unwrap();
        let entry = vec![0u8; mem::size_of::<tcp4_packet_trace>()];
        for cpu in [0, 1, 0] {
            assert_eq!(job.write_from(cpu, &entry), 0);
        }
        job.flush().unwrap();
        let written = std::fs::metadata(&path).unwrap().len();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&side).unwrap();
        assert!(job.cpus.failed);
        assert_eq!(job.records, 3);
        assert!(written > 0);
    }

    #[test]
    fn packed_layout_rejects_non_copies() {
        // An encoding that is not a plain copy of the record's bytes
        #[derive(Clone, Copy)]
        struct Shifted(u32);
        impl Serialize for Shifted {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_u32(self.0.wrapping_add(1))
            }
        }
        assert!(PackedLayout::of::<Shifted>().is_none());
    }
}
