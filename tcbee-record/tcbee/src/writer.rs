use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, ErrorKind, Write},
    mem,
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
pub struct Writer {
    running: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    /// CPU IDs to pin writer threads to, assigned round-robin.
    /// Requires `isolcpus=<ids>` in the kernel boot parameters for full isolation.
    cpu_pool: Vec<usize>,
    next_cpu: usize,
}

impl Writer {
    pub fn new() -> Self {
        Writer {
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
    pub fn register<T>(
        &mut self,
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

        let handle = thread::spawn(move || job_loop(Box::new(job), running, cpu));
        self.handles.push(handle);

        Ok(())
    }

    /// Signal all worker threads to stop, flush their buffers, and join them.
    pub fn shutdown(mut self) -> Result<(), WriterError> {
        self.signal_stop();
        self.join_all()
    }

    fn signal_stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn join_all(&mut self) -> Result<(), WriterError> {
        for handle in self.handles.drain(..) {
            handle.join().map_err(|_| WriterError::WorkerPanicked)?;
        }
        Ok(())
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

fn job_loop(mut job: Box<dyn Job>, running: Arc<AtomicBool>, cpu: Option<usize>) {
    if let Some(cpu_id) = cpu {
        pin_to_cpu(cpu_id);
    }

    while running.load(Ordering::Relaxed) {
        match job.poll() {
            Ok(()) => {}
            Err(err) => {
                error!(
                    "Writer job {} failed: {}. Stopping thread.",
                    job.name(),
                    err
                );
                break;
            }
        }
        thread::yield_now();
    }

    if let Err(err) = job.flush() {
        error!(
            "Failed to flush job {} during shutdown: {}",
            job.name(),
            err
        );
    }
}

const MIN_MMAP_GROWTH: usize = 64 * 1024;

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

        let mut new_capacity = self.capacity;
        let growth = self.growth.max(MIN_MMAP_GROWTH);
        while required > new_capacity {
            new_capacity = new_capacity
                .checked_add(growth)
                .ok_or_else(|| io::Error::new(ErrorKind::Other, "file size overflow"))?;
        }

        if let Some(map) = self.map.as_mut() {
            map.flush_async_range(0, self.position)?;
        }

        drop(self.map.take());

        self.file.set_len(new_capacity as u64)?;
        let map = unsafe { MmapMut::map_mut(&self.file)? };
        self.map = Some(map);
        self.capacity = new_capacity;

        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        if let Some(mut map) = self.map.take() {
            map.flush_range(0, self.position)?;
        }
        self.file.set_len(self.position as u64)?;
        self.file.sync_all()?;
        Ok(())
    }
}

impl Write for MmapBackedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        self.ensure_capacity(buf.len())?;

        let start = self.position;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "file size overflow"))?;

        match self.map.as_mut() {
            Some(map) => {
                map[start..end].copy_from_slice(buf);
                self.position = end;
                Ok(buf.len())
            }
            None => Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "memory-mapped writer closed",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(map) = self.map.as_ref() {
            map.flush_async_range(0, self.position)?;
        }
        Ok(())
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        self.signal_stop();
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

trait Job: Send {
    fn name(&self) -> &str;
    fn poll(&mut self) -> Result<(), JobError>;
    fn flush(&mut self) -> Result<(), JobError>;
}

struct MapWriterJob<T>
where
    T: Serialize + Copy + Send + 'static,
{
    map: RingBuf<MapData>,
    sink: Option<MmapBackedFile>,
    file_path: PathBuf,
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

    fn poll(&mut self) -> Result<(), JobError> {
        let mut reads = 0;
        let sink = match self.sink.as_mut() {
            Some(sink) => sink,
            None => return Ok(()),
        };

        while let Some(entry) = self.map.next() {
            let value = unsafe { *(entry.as_ptr() as *const T) };
            drop(entry);

            bincode::serialize_into(&mut *sink, &value).map_err(JobError::Serialize)?;
            sink.write_all(&RECORD_DELIMITER).map_err(JobError::Io)?;

            reads += 1;
        }

        if reads > 0 {
            trace!("Wrote {} records to {}", reads, self.file_path.display());
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<(), JobError> {
        if let Some(sink) = self.sink.take() {
            sink.finish().map_err(JobError::Io)?;
        }
        Ok(())
    }
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
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::Io(err) => write!(f, "I/O error: {}", err),
            JobError::Serialize(err) => write!(f, "serialization error: {}", err),
        }
    }
}

impl std::error::Error for JobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JobError::Io(err) => Some(err),
            JobError::Serialize(err) => Some(err),
        }
    }
}

impl From<io::Error> for JobError {
    fn from(err: io::Error) -> Self {
        JobError::Io(err)
    }
}
