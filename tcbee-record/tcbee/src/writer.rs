use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError},
    thread::{self, JoinHandle},
    time::Duration,
};

use aya::maps::{MapData, RingBuf};
use bincode::ErrorKind as BincodeErrorKind;
use log::{debug, error, info, trace};
use memmap2::MmapMut;
use serde::Serialize;

use crate::config::WRITER_BUFFER_SIZE;

const RECORD_DELIMITER: [u8; 4] = [0xFF; 4];
const IDLE_WAIT: Duration = Duration::from_millis(2);

type JobBox = Box<dyn Job>;

/// Serializes entries pulled from eBPF maps and writes them to files on a single worker thread.
pub struct Writer {
    tx: Sender<WriterCommand>,
    handle: Option<JoinHandle<()>>,
}

impl Writer {
    /// Spawn a dedicated worker thread.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<WriterCommand>();

        let handle = thread::spawn(move || worker_loop(rx));

        Writer {
            tx,
            handle: Some(handle),
        }
    }

    /// Register a ring buffer map whose entries should be written
    pub fn register<T>(
        &self,
        map: RingBuf<MapData>,
        file_path: impl Into<PathBuf>,
    ) -> Result<(), WriterError>
    where
        T: Serialize + Copy + Send + 'static,
    {
        let job = MapWriterJob::<T>::new(map, file_path.into())?;

        self.tx
            .send(WriterCommand::Register(Box::new(job)))
            .map_err(|_| WriterError::WorkerClosed)
    }

    /// Flush outstanding data and stop the worker thread.
    pub fn shutdown(mut self) -> Result<(), WriterError> {
        self.send_shutdown()?;
        self.join()?;
        Ok(())
    }

    fn send_shutdown(&mut self) -> Result<(), WriterError> {
        self.tx
            .send(WriterCommand::Shutdown)
            .map_err(|_| WriterError::WorkerClosed)
    }

    fn join(&mut self) -> Result<(), WriterError> {
        if let Some(handle) = self.handle.take() {
            handle.join().map_err(|_| WriterError::WorkerPanicked)?;
        }
        Ok(())
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
        if self.handle.is_none() {
            return;
        }

        if self.send_shutdown().is_ok() {
            let _ = self.join();
        }
    }
}

trait Job: Send {
    fn name(&self) -> &'static str;
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
    fn name(&self) -> &'static str {
        std::any::type_name::<T>()
    }

    fn poll(&mut self) -> Result<(), JobError> {
        let mut reads = 0;
        let sink = match self.sink.as_mut() {
            Some(sink) => sink,
            None => return Ok(()),
        };

        while let Some(entry) = self.map.next() {
            // Safety: the map entry is the same struct T that the eBPF program writes.
            let value = unsafe { *(entry.as_ptr() as *const T) };
            drop(entry);

            bincode::serialize_into(&mut *sink, &value).map_err(JobError::Serialize)?;

            sink.write_all(&RECORD_DELIMITER).map_err(JobError::Io)?;

            reads += 1;
        }

        if reads > 0 {
            trace!(
                "Wrote {} records of {} to {}",
                reads,
                std::any::type_name::<T>(),
                self.file_path.display()
            );
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

fn worker_loop(rx: Receiver<WriterCommand>) {
    let mut jobs: Vec<JobBox> = Vec::new();
    let mut running = true;

    while running {
        // Drain pending commands without blocking.
        loop {
            match rx.try_recv() {
                Ok(command) => handle_command(command, &mut jobs, &mut running),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    running = false;
                    break;
                }
            }
        }

        if !running {
            break;
        }

        if jobs.is_empty() {
            match rx.recv_timeout(IDLE_WAIT) {
                Ok(command) => handle_command(command, &mut jobs, &mut running),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    running = false;
                }
            }
            continue;
        }

        let mut idx = 0;
        while idx < jobs.len() {
            match jobs[idx].poll() {
                Ok(()) => idx += 1,
                Err(err) => {
                    error!(
                        "Writer job {} failed: {}. Dropping job.",
                        jobs[idx].name(),
                        err
                    );
                    let mut job = jobs.remove(idx);
                    if let Err(flush_err) = job.flush() {
                        error!(
                            "Failed to flush job {} after error: {}",
                            job.name(),
                            flush_err
                        );
                    }
                }
            }
        }

        thread::yield_now();
    }

    // Flush remaining jobs before shutting down.
    for mut job in jobs {
        if let Err(err) = job.flush() {
            error!(
                "Failed to flush job {} during shutdown: {}",
                job.name(),
                err
            );
        }
    }
}

fn handle_command(command: WriterCommand, jobs: &mut Vec<JobBox>, running: &mut bool) {
    match command {
        WriterCommand::Register(job) => {
            debug!("Registered new writer job {}", job.name());
            jobs.push(job);
        }
        WriterCommand::Shutdown => {
            *running = false;
        }
    }
}

enum WriterCommand {
    Register(JobBox),
    Shutdown,
}

#[derive(Debug)]
pub enum WriterError {
    Io(io::Error),
    WorkerClosed,
    WorkerPanicked,
}

impl fmt::Display for WriterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriterError::Io(err) => write!(f, "I/O error: {}", err),
            WriterError::WorkerClosed => write!(f, "writer worker is no longer running"),
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
