use std::{
    cell::RefCell,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, ErrorKind, Write},
    mem,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use bincode::ErrorKind as BincodeErrorKind;
use libbpf_rs::{MapHandle, RingBufferBuilder};
use log::{debug, error, info, trace, warn};
use memmap2::MmapMut;
use serde::Serialize;
use tcbee_common::{records::RECORD_DELIMITER, stats::RINGBUFS};
use tcbee_trace::TraceFile;

use crate::config::WRITER_BUFFER_SIZE;

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

/// Upper bound for a blocking wait, so that a stop request is noticed
const WAIT_TIMEOUT: Duration = Duration::from_millis(100);

/// Busy mode: a poll that consumed at least this many records means a backlog, so poll again
/// at once; a smaller batch means the writer keeps up and can sleep.
const BACKLOG_RECORDS: i32 = 256;
/// Busy mode: sleep between polls of light or idle rings. Far below the time a per-CPU ring takes
/// to fill, so it costs no records, and writer threads sharing a core leave it to the loaded one.
const IDLE_SLEEP: Duration = Duration::from_micros(50);

/// Serializes entries pulled from eBPF maps and writes them to files.
///
/// Each output file gets its own dedicated OS thread so that a busy probe cannot starve
/// others. The thread reads all ring buffers of its file (one per CPU) through one libbpf
/// ring buffer manager. `BPF_MAP_TYPE_RINGBUF` is single-consumer, so a ring buffer is never
/// shared between threads.
pub struct Writer {
    poll_mode: PollMode,
    running: Arc<AtomicBool>,
    bytes_written: Arc<AtomicU64>,
    handles: Vec<(WriterReport, JoinHandle<JobResult>)>,
    /// CPU IDs to pin writer threads to, assigned round-robin.
    /// Requires `isolcpus=<ids>` in the kernel boot parameters for full isolation.
    cpu_pool: Vec<usize>,
    next_cpu: usize,
    /// Where the file helpers of all writer threads run
    helper_cpus: Arc<HelperCpus>,
}

impl Writer {
    pub fn new(poll_mode: PollMode) -> Self {
        Writer {
            poll_mode,
            running: Arc::new(AtomicBool::new(true)),
            bytes_written: Arc::new(AtomicU64::new(0)),
            handles: Vec::new(),
            cpu_pool: Vec::new(),
            next_cpu: 0,
            helper_cpus: Arc::new(HelperCpus::default()),
        }
    }

    /// Pin each writer thread to one of the given CPU IDs (round-robin).
    /// For full isolation, also boot with `isolcpus=<ids>` so the kernel
    /// scheduler never places other tasks on those cores.
    pub fn with_cpu_affinity(mut self, cpus: Vec<usize>) -> Self {
        self.helper_cpus = Arc::new(HelperCpus::new(cpus.clone()));
        self.cpu_pool = cpus;
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
        self.register_as::<T>(rb, maps, RINGBUFS[rb as usize].file, trace_dir)
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
        let file_path = trace_dir.as_ref().join(file.filename());
        let job = MapWriterJob::<T>::new(file_path, self.bytes_written.clone())?
            .with_helper_cpus(self.helper_cpus.clone());
        let running = self.running.clone();

        let cpu = if self.cpu_pool.is_empty() {
            None
        } else {
            let id = self.cpu_pool[self.next_cpu % self.cpu_pool.len()];
            self.next_cpu += 1;
            self.helper_cpus.add_writer(id);
            Some(id)
        };

        debug!(
            "Spawning writer thread for {} (cpu: {:?})",
            job.file_path.display(),
            cpu
        );

        let report = WriterReport {
            rb,
            file: job.file_path.clone(),
            records: 0,
            error: None,
        };
        let poll_mode = self.poll_mode;
        // The ring buffers are set up inside the thread, which then reports whether that
        // worked, so a broken map fails here and not only at shutdown
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || job_loop(job, maps, running, cpu, poll_mode, ready_tx));
        match ready_rx.recv() {
            Ok(Ok(())) => {
                self.handles.push((report, handle));
                Ok(())
            }
            Ok(Err(err)) => {
                let _ = handle.join();
                Err(WriterError::RingBuffer(err))
            }
            Err(_) => {
                let _ = handle.join();
                Err(WriterError::WorkerPanicked)
            }
        }
    }

    /// Signal all worker threads to stop, drain their ring buffers, finish the files and
    /// join them. The eBPF programs must be detached before, otherwise records that are
    /// submitted after the final drain are lost.
    pub fn shutdown(mut self) -> Vec<WriterReport> {
        self.signal_stop();
        self.join_all()
    }

    fn signal_stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn join_all(&mut self) -> Vec<WriterReport> {
        self.handles
            .drain(..)
            .map(|(mut report, handle)| {
                match handle.join() {
                    Ok((records, result)) => {
                        report.records = records;
                        report.error = result.err().map(|err| err.to_string());
                    }
                    Err(_) => report.error = Some(WriterError::WorkerPanicked.to_string()),
                }
                report
            })
            .collect()
    }
}

fn pin_to_cpu(cpu_id: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu_id, &mut set);
        let ret = libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &set);
        if ret != 0 {
            error!(
                "Failed to pin writer thread to CPU {}: errno {}",
                cpu_id,
                io::Error::last_os_error()
            );
        } else {
            info!("Writer thread pinned to CPU {}", cpu_id);
        }
    }
}

/// The CPUs for the threads that grow and unmap trace files. A thread inherits the CPU
/// affinity of the thread that starts it, so without this they would run on their writer's
/// CPU: at about 1 GB/s into one file, zeroing the new tmpfs pages takes half of that CPU and
/// the writer falls behind its ring buffers.
#[derive(Default)]
struct HelperCpus {
    /// The writer CPU pool, empty if writers are not pinned
    pool: Vec<usize>,
    /// The CPUs that have a writer thread
    writers: Mutex<Vec<usize>>,
    /// The warning that helpers share the writers' CPUs was logged
    warned: AtomicBool,
}

impl HelperCpus {
    fn new(pool: Vec<usize>) -> Self {
        HelperCpus {
            pool,
            writers: Mutex::new(Vec::new()),
            warned: AtomicBool::new(false),
        }
    }

    fn add_writer(&self, cpu: usize) {
        self.writers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(cpu);
    }

    /// The pool CPUs without a writer, or the whole pool if every one has a writer. None if
    /// writers are not pinned: helpers then run wherever their writer may.
    fn set(&self) -> Option<libc::cpu_set_t> {
        if self.pool.is_empty() {
            return None;
        }
        let writers = self.writers.lock().unwrap_or_else(|e| e.into_inner());
        let mut free: Vec<usize> = self
            .pool
            .iter()
            .copied()
            .filter(|c| !writers.contains(c))
            .collect();
        if free.is_empty() {
            if !self.warned.swap(true, Ordering::Relaxed) {
                warn!("Every writer CPU has a writer, file growth shares their CPUs");
            }
            free = self.pool.clone();
        }
        unsafe {
            let mut set: libc::cpu_set_t = mem::zeroed();
            libc::CPU_ZERO(&mut set);
            for cpu in free {
                libc::CPU_SET(cpu, &mut set);
            }
            Some(set)
        }
    }
}

/// Runs `work` on a new thread restricted to `cpus`
fn spawn_helper(
    name: &str,
    cpus: Option<libc::cpu_set_t>,
    work: impl FnOnce() + Send + 'static,
) -> io::Result<()> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Some(set) = cpus {
                let ret = unsafe { libc::sched_setaffinity(0, mem::size_of_val(&set), &set) };
                if ret != 0 {
                    error!(
                        "Failed to move a file helper off the writer's CPU: errno {}",
                        io::Error::last_os_error()
                    );
                }
            }
            work()
        })
        .map(drop)
}

fn job_loop<T>(
    job: MapWriterJob<T>,
    maps: Vec<(u32, MapHandle)>,
    running: Arc<AtomicBool>,
    cpu: Option<usize>,
    poll_mode: PollMode,
    ready: mpsc::SyncSender<Result<(), libbpf_rs::Error>>,
) -> JobResult
where
    T: Serialize + Copy + Send + 'static,
{
    if let Some(cpu_id) = cpu {
        pin_to_cpu(cpu_id);
    }

    // libbpf calls the callback for every record while consuming the ring buffers. The
    // loop below needs the job too, so the callbacks only borrow it.
    let job = RefCell::new(job);
    let rb = (|| {
        let mut builder = RingBufferBuilder::new();
        let job = &job;
        for (cpu, map) in &maps {
            let cpu = *cpu;
            builder.add(map, move |data| job.borrow_mut().write_from(cpu, data))?;
        }
        builder.build()
    })();
    let rb = match rb {
        Ok(rb) => {
            let _ = ready.send(Ok(()));
            rb
        }
        Err(err) => {
            let mut job = job.borrow_mut();
            let flushed = job.flush();
            // Without a ring buffer there is no trace, so don't leave an empty file
            if flushed.is_ok() {
                remove_if_empty(&job.file_path);
            }
            let _ = ready.send(Err(err));
            return (0, flushed);
        }
    };

    let result = (|| {
        while running.load(Ordering::Relaxed) {
            match poll_mode {
                PollMode::Busy => {
                    // consume drains the rings. Poll again at once (no syscall) while there is a
                    // backlog, otherwise sleep briefly so other writers on the same core get it.
                    if check(&job, rb.consume_raw())? >= BACKLOG_RECORDS {
                        std::hint::spin_loop();
                    } else {
                        thread::sleep(IDLE_SLEEP);
                    }
                }
                PollMode::Wait => {
                    check(&job, rb.poll_raw(WAIT_TIMEOUT))?;
                }
            }
            job.borrow_mut().count_bytes();
        }
        // Drain what was submitted before the programs were detached
        while check(&job, rb.consume_raw())? > 0 {}
        job.borrow_mut().count_bytes();
        Ok(())
    })();
    // A callback can fail after earlier records in the same consume batch were written.
    job.borrow_mut().count_bytes();
    drop(rb);

    let mut job = job.borrow_mut();
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
    (job.records, result.and(flushed))
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

/// Records a writer thread wrote, and the error that stopped it, if any
type JobResult = (u64, Result<(), JobError>);

/// Turns the return value of `ring_buffer__consume`/`ring_buffer__poll` into the number
/// of records read or the error that stopped the callback
fn check<T>(job: &RefCell<MapWriterJob<T>>, ret: i32) -> Result<i32, JobError>
where
    T: Serialize + Copy + Send + 'static,
{
    if ret >= 0 {
        return Ok(ret);
    }
    if let Some(err) = job.borrow_mut().error.take() {
        return Err(err);
    }
    match -ret {
        // A signal interrupted the wait, try again
        libc::EINTR => Ok(0),
        errno => Err(JobError::Io(io::Error::from_raw_os_error(errno))),
    }
}

/// Allocates the blocks of a file range. Without this, a full disk is only noticed when a
/// write into the mapping faults, and the kernel kills the process with SIGBUS.
fn allocate(file: &File, offset: usize, len: usize) -> io::Result<()> {
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
fn next_capacity(capacity: usize, growth: usize, required: usize) -> usize {
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
fn starts_growth(capacity: usize, required: usize, new_capacity: usize) -> bool {
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
    helper_cpus: Option<Arc<HelperCpus>>,
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
            helper_cpus: None,
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
        spawn_helper("tcbee-grow", self.helper_set(), move || {
            let _ =
                tx.send(Self::grow(&file, old_capacity, new_capacity).map(|m| (m, new_capacity)));
        })?;
        self.pending = Some(rx);
        Ok(())
    }

    fn helper_set(&self) -> Option<libc::cpu_set_t> {
        self.helper_cpus.as_ref().and_then(|h| h.set())
    }

    fn adopt(&mut self, map: MmapMut, capacity: usize) {
        self.capacity = capacity;
        if let Some(old) = self.map.replace(map) {
            // Unmapping a large dirty mapping is slow, keep it off the writer thread.
            // The written pages stay in the page cache.
            if let Err(err) = spawn_helper("tcbee-unmap", self.helper_set(), move || drop(old)) {
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

        // Take over a finished background growth without waiting for it
        if let Some(rx) = &self.pending {
            match rx.try_recv() {
                Ok(grown) => {
                    self.pending = None;
                    let (map, capacity) = grown?;
                    self.adopt(map, capacity);
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    return Err(io::Error::new(ErrorKind::Other, "file growth thread died"));
                }
            }
        }

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

impl Drop for Writer {
    fn drop(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        self.signal_stop();
        for (_, handle) in self.handles.drain(..) {
            let _ = handle.join();
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
    /// Derives the ranges from bincode itself: a value whose byte `i` is `i` serializes to
    /// the source offset of every output byte. A second pattern checks that the output is
    /// a plain copy of the input bytes. None if that does not hold for `T` (or `T` is too
    /// large to number its bytes), the caller then uses bincode.
    ///
    /// `T` must be plain old data, valid for any bit pattern, like all record types.
    fn of<T: Serialize + Copy>() -> Option<Self> {
        let size = mem::size_of::<T>();
        if size == 0 || size > usize::from(u8::MAX) + 1 {
            return None;
        }
        let encode = |pattern: &dyn Fn(usize) -> u8| -> Option<Vec<u8>> {
            let bytes: Vec<u8> = (0..size).map(pattern).collect();
            let value = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) };
            bincode::serialize(&value).ok()
        };
        let offsets = encode(&|i| i as u8)?;
        let check = encode(&|i| !(i as u8))?;
        if offsets.len() != check.len()
            || offsets.iter().zip(&check).any(|(&off, &byte)| byte != !off)
        {
            return None;
        }

        let mut runs: Vec<(usize, usize)> = Vec::new();
        for off in offsets.iter().map(|&off| usize::from(off)) {
            match runs.last_mut() {
                Some((start, len)) if *start + *len == off => *len += 1,
                _ => runs.push((off, 1)),
            }
        }
        Some(Self { runs })
    }

    /// Writes the file bytes of one record. `entry` is at least `size_of::<T>()` long and
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
    sink: Option<MmapBackedFile>,
    file_path: PathBuf,
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
    _marker: std::marker::PhantomData<T>,
}

impl<T> MapWriterJob<T>
where
    T: Serialize + Copy + Send + 'static,
{
    fn new(file_path: PathBuf, bytes_written: Arc<AtomicU64>) -> Result<Self, WriterError> {
        let entry_size = std::mem::size_of::<T>().max(1);
        let chunk_bytes = entry_size
            .checked_mul(WRITER_BUFFER_SIZE)
            .unwrap_or(WRITER_BUFFER_SIZE * 128)
            .max(WRITER_BUFFER_SIZE);

        let sink = MmapBackedFile::new(&file_path, chunk_bytes)?;
        // Records are plain old data, all zeros is a valid value
        let zero: T = unsafe { mem::zeroed() };
        let record_size = bincode::serialized_size(&zero)
            .map_err(|err| io::Error::new(ErrorKind::InvalidInput, err))?
            as usize;
        let layout = PackedLayout::of::<T>();
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
            record_size,
            layout,
            records: 0,
            counted: 0,
            error: None,
            _marker: std::marker::PhantomData,
        })
    }

    /// Grows and unmaps the file on `helpers` instead of the writer's CPU
    fn with_helper_cpus(mut self, helpers: Arc<HelperCpus>) -> Self {
        if let Some(sink) = &mut self.sink {
            sink.helper_cpus = Some(helpers);
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

    /// Writes one record. A non-zero return value stops libbpf from consuming further
    /// records, the error is kept for the writer loop.
    fn write(&mut self, entry: &[u8]) -> i32 {
        match self.try_write(entry) {
            Ok(()) => {
                self.records += 1;
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

        if entry.len() < mem::size_of::<T>() {
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

    /// Adds the records written since the last call to `bytes_written`
    fn count_bytes(&mut self) {
        let new = self.records - self.counted;
        if new == 0 {
            return;
        }
        self.counted = self.records;
        trace!("Wrote {} records to {}", new, self.file_path.display());
        let bytes = new * (self.record_size + RECORD_DELIMITER.len()) as u64;
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    fn flush(&mut self) -> Result<(), JobError> {
        // The side file is finished even if the trace is not, it describes the records written
        self.cpus.finish(self.records);
        if let Some(sink) = self.sink.take() {
            sink.finish().map_err(JobError::Io)?;
        }
        Ok(())
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
    pub records: u64,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum WriterError {
    Io(io::Error),
    RingBuffer(libbpf_rs::Error),
    WorkerPanicked,
}

impl fmt::Display for WriterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriterError::Io(err) => write!(f, "I/O error: {}", err),
            WriterError::RingBuffer(err) => write!(f, "ring buffer error: {}", err),
            WriterError::WorkerPanicked => write!(f, "writer worker thread panicked"),
        }
    }
}

impl std::error::Error for WriterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WriterError::Io(err) => Some(err),
            WriterError::RingBuffer(err) => Some(err),
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
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::Io(err) => write!(f, "I/O error: {}", err),
            JobError::Serialize(err) => write!(f, "serialization error: {}", err),
            JobError::ShortRecord(len) => write!(f, "ring buffer record of only {} bytes", len),
        }
    }
}

impl std::error::Error for JobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JobError::Io(err) => Some(err),
            JobError::Serialize(err) => Some(err),
            JobError::ShortRecord(_) => None,
        }
    }
}

impl From<io::Error> for JobError {
    fn from(err: io::Error) -> Self {
        JobError::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use tcbee_common::records::*;

    use super::*;

    /// xorshift64*, enough to fill records with arbitrary bytes
    struct Rng(u64);

    impl Rng {
        fn bytes(&mut self, len: usize) -> Vec<u8> {
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
        assert_packed_matches_bincode::<tcp_probe_entry>();
        assert_packed_matches_bincode::<tcp_retransmit_synack_entry>();
        assert_packed_matches_bincode::<tcp_bad_csum_entry>();
        assert_packed_matches_bincode::<mptcp_pm_entry>();
        assert_packed_matches_bincode::<tcp_event_entry>();
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

    /// Helpers run on the CPUs without a writer, not on the CPU of the thread that starts them
    #[test]
    fn helpers_avoid_writer_cpus() {
        let online: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| unsafe {
                let mut set: libc::cpu_set_t = mem::zeroed();
                libc::sched_getaffinity(0, mem::size_of_val(&set), &mut set) == 0
                    && libc::CPU_ISSET(c, &set)
            })
            .collect();
        if online.len() < 2 {
            return;
        }
        let (writer, other) = (online[0], online[1]);
        let helpers = HelperCpus::new(vec![writer, other]);
        helpers.add_writer(writer);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            pin_to_cpu(writer);
            spawn_helper("test-helper", helpers.set(), move || {
                let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
                unsafe { libc::sched_getaffinity(0, mem::size_of_val(&set), &mut set) };
                let cpus: Vec<usize> = online
                    .iter()
                    .copied()
                    .filter(|&c| unsafe { libc::CPU_ISSET(c, &set) })
                    .collect();
                tx.send(cpus).unwrap();
            })
            .unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(rx.recv().unwrap(), vec![other]);
        // Every pool CPU has a writer: the helpers may use the whole pool
        let full = HelperCpus::new(vec![writer]);
        full.add_writer(writer);
        let set = full.set().unwrap();
        assert!(unsafe { libc::CPU_ISSET(writer, &set) });
        assert!(HelperCpus::default().set().is_none());
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
