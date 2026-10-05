use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, ErrorKind},
    mem,
    os::fd::{AsRawFd, RawFd},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
};

use aya::maps::{MapData, RingBuf};
use bincode::ErrorKind as BincodeErrorKind;
use log::{debug, error, info, trace};
use memmap2::MmapMut;
use serde::Serialize;

use crate::config::WRITER_BUFFER_SIZE;

const RECORD_DELIMITER: [u8; 4] = [0xFF; 4];

/// Serializes entries pulled from eBPF maps and writes them to files.
///
/// Each registered ring buffer gets its own dedicated OS thread so that a busy
/// probe cannot starve others. `BPF_MAP_TYPE_RINGBUF` is single-consumer, so
/// one thread per buffer is both the safe and the optimal arrangement.
/// How writer threads wait for new records
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PollMode {
    /// Spin on the ring buffer. Lowest latency, but every writer thread uses a full core.
    #[default]
    Busy,
    /// Block in poll() until the kernel signals new records.
    Wait,
}

impl PollMode {
    /// Ring buffer submit flags the eBPF programs have to use for this mode
    pub fn submit_flags(self) -> u64 {
        match self {
            PollMode::Busy => aya_obj::generated::BPF_RB_NO_WAKEUP as u64,
            PollMode::Wait => 0,
        }
    }
}

/// Upper bound for a blocking wait, so that a stop request is noticed
const WAIT_TIMEOUT_MS: i32 = 100;

pub struct Writer {
    poll_mode: PollMode,
    running: Arc<AtomicBool>,
    handles: Vec<(WriterReport, JoinHandle<Result<u64, JobError>>)>,
    /// CPU IDs to pin writer threads to, assigned round-robin.
    /// Requires `isolcpus=<ids>` in the kernel boot parameters for full isolation.
    cpu_pool: Vec<usize>,
    next_cpu: usize,
}

impl Writer {
    pub fn new(poll_mode: PollMode) -> Self {
        Writer {
            poll_mode,
            running: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
            cpu_pool: Vec::new(),
            next_cpu: 0,
        }
    }

    /// Pin each writer thread to one of the given CPU IDs (round-robin).
    /// For full isolation, also boot with `isolcpus=<ids>` so the kernel
    /// scheduler never places other tasks on those cores.
    pub fn with_cpu_affinity(mut self, cpus: Vec<usize>) -> Self {
        self.cpu_pool = cpus;
        self
    }

    /// Register a ring buffer map. Spawns a dedicated worker thread immediately.
    /// `rb` is the ring buffer index from `tcbee_common::stats`.
    pub fn register<T>(
        &mut self,
        rb: u32,
        map: RingBuf<MapData>,
        file_path: impl Into<PathBuf>,
    ) -> Result<(), WriterError>
    where
        T: Serialize + Copy + Send + 'static,
    {
        let job = MapWriterJob::<T>::new(map, file_path.into())?;
        let running = self.running.clone();

        let cpu = if self.cpu_pool.is_empty() {
            None
        } else {
            let id = self.cpu_pool[self.next_cpu % self.cpu_pool.len()];
            self.next_cpu += 1;
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
        let handle = thread::spawn(move || job_loop(Box::new(job), running, cpu, poll_mode));
        self.handles.push((report, handle));

        Ok(())
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
                    Ok(Ok(records)) => report.records = records,
                    Ok(Err(err)) => report.error = Some(err.to_string()),
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

fn job_loop(
    mut job: Box<dyn Job>,
    running: Arc<AtomicBool>,
    cpu: Option<usize>,
    poll_mode: PollMode,
) -> Result<u64, JobError> {
    if let Some(cpu_id) = cpu {
        pin_to_cpu(cpu_id);
    }

    let mut records: u64 = 0;
    let result = (|| {
        while running.load(Ordering::Relaxed) {
            let read = job.poll()?;
            records += read;
            match poll_mode {
                PollMode::Busy => thread::yield_now(),
                PollMode::Wait if read == 0 => wait_readable(job.fd()),
                PollMode::Wait => {}
            }
        }
        // Drain what was submitted before the programs were detached
        loop {
            let read = job.poll()?;
            if read == 0 {
                break;
            }
            records += read;
        }
        Ok(())
    })();

    if let Err(err) = &result {
        error!(
            "Writer job {} failed after {} records: {}. Stopping thread.",
            job.name(),
            records,
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

    result.and(flushed).map(|_| records)
}

fn wait_readable(fd: RawFd) {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // Errors and timeouts only lead to another poll of the ring buffer
    unsafe { libc::poll(&mut pollfd, 1, WAIT_TIMEOUT_MS) };
}

const MIN_MMAP_GROWTH: usize = 64 * 1024;
const MAX_MMAP_GROWTH: usize = 1 << 30;

struct MmapBackedFile {
    file: File,
    map: Option<MmapMut>,
    position: usize,
    capacity: usize,
    growth: usize,
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

        let map = unsafe { MmapMut::map_mut(&file)? };

        Ok(Self {
            file,
            map: Some(map),
            position: existing_len,
            capacity,
            growth,
        })
    }

    fn ensure_capacity(&mut self, additional: usize) -> io::Result<()> {
        if additional == 0 {
            return Ok(());
        }

        let required = self
            .position
            .checked_add(additional)
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "file size overflow"))?;

        if required <= self.capacity {
            return Ok(());
        }

        // Grow geometrically so that remapping stays rare at high record rates
        let step = self.capacity.clamp(self.growth, MAX_MMAP_GROWTH);
        let new_capacity = required
            .max(self.capacity.saturating_add(step))
            .next_multiple_of(self.growth);

        // Unmapping a shared mapping keeps the written pages in the page cache
        drop(self.map.take());

        self.file.set_len(new_capacity as u64)?;
        let map = unsafe { MmapMut::map_mut(&self.file)? };
        self.map = Some(map);
        self.capacity = new_capacity;

        Ok(())
    }

    /// Returns the next `len` bytes of the file for writing
    fn reserve(&mut self, len: usize) -> io::Result<&mut [u8]> {
        self.ensure_capacity(len)?;
        let start = self.position;
        let map = self.map.as_mut().ok_or_else(|| {
            io::Error::new(ErrorKind::BrokenPipe, "memory-mapped writer closed")
        })?;
        self.position += len;
        Ok(&mut map[start..start + len])
    }

    fn finish(mut self) -> io::Result<()> {
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

trait Job: Send {
    fn name(&self) -> &str;
    /// File descriptor of the ring buffer, readable when records are available
    fn fd(&self) -> RawFd;
    /// Writes all records that are currently in the ring buffer, returns their count.
    fn poll(&mut self) -> Result<u64, JobError>;
    fn flush(&mut self) -> Result<(), JobError>;
}

struct MapWriterJob<T>
where
    T: Serialize + Copy + Send + 'static,
{
    map: RingBuf<MapData>,
    sink: Option<MmapBackedFile>,
    file_path: PathBuf,
    record_size: Option<usize>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> MapWriterJob<T>
where
    T: Serialize + Copy + Send + 'static,
{
    fn new(map: RingBuf<MapData>, file_path: PathBuf) -> Result<Self, WriterError> {
        let entry_size = std::mem::size_of::<T>().max(1);
        let chunk_bytes = entry_size
            .checked_mul(WRITER_BUFFER_SIZE)
            .unwrap_or(WRITER_BUFFER_SIZE * 128)
            .max(WRITER_BUFFER_SIZE);

        let sink = MmapBackedFile::new(&file_path, chunk_bytes)?;

        info!(
            "Registered writer for type {} at {} (entry {} bytes, chunk {} bytes)",
            std::any::type_name::<T>(),
            file_path.display(),
            entry_size,
            chunk_bytes
        );

        Ok(Self {
            map,
            sink: Some(sink),
            file_path,
            record_size: None,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<T> Job for MapWriterJob<T>
where
    T: Serialize + Copy + Send + 'static,
{
    fn name(&self) -> &str {
        self.file_path.to_str().unwrap_or("<unknown>")
    }

    fn fd(&self) -> RawFd {
        self.map.as_raw_fd()
    }

    fn poll(&mut self) -> Result<u64, JobError> {
        let mut reads = 0;
        let sink = match self.sink.as_mut() {
            Some(sink) => sink,
            None => return Ok(0),
        };

        while let Some(entry) = self.map.next() {
            if entry.len() < mem::size_of::<T>() {
                return Err(JobError::ShortRecord(entry.len()));
            }
            let value = unsafe { std::ptr::read_unaligned(entry.as_ptr() as *const T) };
            drop(entry);

            // All record types have a fixed size, so it is computed only once
            let size = match self.record_size {
                Some(size) => size,
                None => {
                    let size = bincode::serialized_size(&value).map_err(JobError::Serialize)?
                        as usize;
                    self.record_size = Some(size);
                    size
                }
            };

            let buf = sink
                .reserve(size + RECORD_DELIMITER.len())
                .map_err(JobError::Io)?;
            let (record, delimiter) = buf.split_at_mut(size);
            bincode::serialize_into(record, &value).map_err(JobError::Serialize)?;
            delimiter.copy_from_slice(&RECORD_DELIMITER);

            reads += 1;
        }

        if reads > 0 {
            trace!("Wrote {} records to {}", reads, self.file_path.display());
        }

        Ok(reads)
    }

    fn flush(&mut self) -> Result<(), JobError> {
        if let Some(sink) = self.sink.take() {
            sink.finish().map_err(JobError::Io)?;
        }
        Ok(())
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
            _ => None,
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
