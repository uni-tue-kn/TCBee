//! A trace file written from a pool of large aligned buffers. The writer copies records into
//! the current buffer; full buffers go to I/O threads, which write them with `pwrite`, by
//! default with `O_DIRECT`. The writer never takes a page fault or a file system lock for a
//! record. It only waits when every buffer is still being written, and that wait is counted.
//!
//! The file bytes are the same as from the memory-mapped file: records back to back, cut to
//! their exact length at the end. `O_DIRECT` needs aligned offsets and lengths, so the last
//! buffer is padded with zeros and the file is truncated afterwards. A file that exists is
//! appended to: its last partial block is read back once and written again.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, ErrorKind},
    mem,
    os::fd::AsRawFd,
    path::Path,
    ptr::NonNull,
    sync::{mpsc, Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use log::{info, warn};
use serde::Serialize;

use crate::{
    placement::{cpu_set, report_helper_delta, HelperPlacement},
    writer::{allocate, next_capacity, spawn_helper, starts_growth},
};

/// Room after a buffer's end for the record that crosses it. A record never exceeds it.
const SLACK: usize = 64 << 10;
/// Alignment of the buffers in memory, and the offset alignment if the file system does
/// not report its own
const PAGE: usize = 4096;
/// First preallocation step of an O_DIRECT file. Every step waits for the writes in flight
/// (the file system drains direct I/O to change the file's size), so steps are large, and
/// grow with the file as for the memory-mapped file.
const PREALLOC_STEP: usize = 64 << 20;
/// How often an I/O thread reports its CPU time to the balancer and moves with its writer
const IO_UPKEEP: Duration = Duration::from_secs(1);
/// A buffer that has been filling for this long is written as it is, so that a quiet ring
/// does not keep its records in memory only. The full buffer is written again later.
const IDLE_WRITE: Duration = Duration::from_secs(1);

/// How the trace file is written
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SinkKind {
    /// Memory-mapped file, grown in the background
    #[default]
    Mmap,
    /// Buffer pool, I/O threads write with O_DIRECT
    Direct,
    /// Buffer pool, I/O threads write through the page cache
    Buffered,
}

impl SinkKind {
    pub fn name(self) -> &'static str {
        match self {
            SinkKind::Mmap => "mmap",
            SinkKind::Direct => "direct",
            SinkKind::Buffered => "buffered",
        }
    }
}

/// How a writer's trace file is written
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkConfig {
    pub kind: SinkKind,
    /// Size of one buffer of a pooled sink
    pub buffer_bytes: usize,
    /// Buffers per file, at least 2
    pub buffers: usize,
    /// I/O threads per file, at most `buffers - 1` writes run at once
    pub io_threads: usize,
    /// Extend an O_DIRECT file ahead of the writes on a helper thread. A direct write past
    /// the end of the file takes the file system's exclusive lock.
    pub preallocate: bool,
    /// CPUs for the I/O threads, outside the balancing. Empty: they run as the file helpers
    /// on the writer CPUs, their CPU time counts there, and they follow their writer.
    pub io_cpus: Vec<usize>,
}

impl Default for SinkConfig {
    fn default() -> Self {
        Self {
            kind: SinkKind::Mmap,
            buffer_bytes: 2 << 20,
            buffers: 8,
            io_threads: 2,
            preallocate: true,
            io_cpus: Vec::new(),
        }
    }
}

/// What a pooled sink did, for the writer report
#[derive(Clone, Debug, Default, Serialize)]
pub struct SinkStats {
    /// The kind of sink that wrote, after any fallback
    pub sink: &'static str,
    /// Buffers handed to the I/O threads
    pub writes: u64,
    /// Times the writer waited for a free buffer, and how long in total and at most
    pub stalls: u64,
    pub stall_ns: u64,
    pub stall_max_ns: u64,
    /// Preallocation steps, the failed ones, and the stall time while one was running
    pub preallocs: u64,
    pub prealloc_failures: u64,
    pub prealloc_stall_ns: u64,
}

/// A page-aligned anonymous mapping, owned by whoever holds it: the writer or, while it is
/// written, an I/O thread
struct AlignedBuf {
    ptr: NonNull<u8>,
    len: usize,
}

// The buffer is plain memory owned by one thread at a time
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    fn new(len: usize) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(ptr.cast()).ok_or_else(|| io::Error::other("mmap returned null"))?;
        Ok(Self { ptr, len })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

/// A buffer for an I/O thread: write `len` bytes of it at `offset`. A partial job is a copy
/// of the current buffer before it is full.
struct IoJob {
    buf: AlignedBuf,
    offset: u64,
    len: usize,
    partial: bool,
}

/// A written buffer back from an I/O thread: how many bytes reached the file, and the error
/// that stopped it short
struct IoDone {
    buf: AlignedBuf,
    offset: u64,
    written: usize,
    partial: bool,
    result: io::Result<()>,
}

/// Writes all of `data` at `offset`, retrying after signals and short writes
fn pwrite_all(file: &File, data: &[u8], offset: u64) -> (usize, io::Result<()>) {
    let mut done = 0;
    while done < data.len() {
        let rest = &data[done..];
        let ret = unsafe {
            libc::pwrite(
                file.as_raw_fd(),
                rest.as_ptr().cast(),
                rest.len(),
                (offset + done as u64) as libc::off_t,
            )
        };
        match ret {
            n if n > 0 => done += n as usize,
            0 => return (done, Err(io::Error::from(ErrorKind::WriteZero))),
            _ => {
                let err = io::Error::last_os_error();
                if err.kind() != ErrorKind::Interrupted {
                    return (done, Err(err));
                }
            }
        }
    }
    (done, Ok(()))
}

/// The I/O threads of one file. Dropping them lets every queued write finish first.
struct IoThreads {
    jobs: Option<mpsc::Sender<IoJob>>,
    done: mpsc::Receiver<IoDone>,
    handles: Vec<JoinHandle<()>>,
}

impl IoThreads {
    /// Starts `threads` I/O threads on `io_cpus`, or if empty where `helpers` says
    fn start(
        file: &Arc<File>,
        threads: usize,
        io_cpus: &[usize],
        helpers: Option<&HelperPlacement>,
    ) -> io::Result<Self> {
        let (jobs_tx, jobs_rx) = mpsc::channel::<IoJob>();
        let (done_tx, done_rx) = mpsc::channel();
        let jobs_rx = Arc::new(Mutex::new(jobs_rx));
        // Placed with the file helpers, the threads follow them while they run
        let follow = helpers.filter(|_| io_cpus.is_empty()).cloned();
        let cpus = if io_cpus.is_empty() {
            helpers.and_then(HelperPlacement::cpu_set)
        } else {
            Some(cpu_set(io_cpus))
        };
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads.max(1) {
            let (file, jobs, done) = (file.clone(), jobs_rx.clone(), done_tx.clone());
            let mut upkeep = IoUpkeep::new(follow.clone(), cpus);
            // The thread reports its CPU time itself, not only when it ends
            handles.push(spawn_helper("tcbee-io", cpus, None, move || loop {
                // The lock is held only while taking the next job
                let job = jobs.lock().map(|rx| rx.recv_timeout(IO_UPKEEP));
                upkeep.tick();
                let job = match job {
                    Ok(Ok(job)) => job,
                    Ok(Err(mpsc::RecvTimeoutError::Timeout)) => continue,
                    _ => return upkeep.report(),
                };
                let (written, result) =
                    pwrite_all(&file, &job.buf.as_slice()[..job.len], job.offset);
                let back = IoDone {
                    buf: job.buf,
                    offset: job.offset,
                    written,
                    partial: job.partial,
                    result,
                };
                if done.send(back).is_err() {
                    return upkeep.report();
                }
            })?);
        }
        Ok(Self {
            jobs: Some(jobs_tx),
            done: done_rx,
            handles,
        })
    }

    fn submit(&self, job: IoJob) -> io::Result<()> {
        self.jobs
            .as_ref()
            .and_then(|jobs| jobs.send(job).ok())
            .ok_or_else(|| io::Error::other("the file's I/O threads stopped"))
    }
}

/// An I/O thread placed as a file helper: reports its CPU time to the balancer, and moves
/// where a helper of its writer would start now, as the writers move
struct IoUpkeep {
    helpers: Option<HelperPlacement>,
    cpus: Option<libc::cpu_set_t>,
    reported_ns: u64,
    last: Instant,
}

impl IoUpkeep {
    fn new(helpers: Option<HelperPlacement>, cpus: Option<libc::cpu_set_t>) -> Self {
        Self {
            helpers,
            cpus,
            reported_ns: 0,
            last: Instant::now(),
        }
    }

    fn tick(&mut self) {
        if self.helpers.is_none() || self.last.elapsed() < IO_UPKEEP {
            return;
        }
        self.last = Instant::now();
        self.report();
        let cpus = self.helpers.as_ref().and_then(HelperPlacement::cpu_set);
        let moved = match (&cpus, &self.cpus) {
            (Some(new), Some(old)) => unsafe { !libc::CPU_EQUAL(new, old) },
            (new, old) => new.is_some() != old.is_some(),
        };
        if let (true, Some(set)) = (moved, cpus) {
            if unsafe { libc::sched_setaffinity(0, mem::size_of_val(&set), &set) } == 0 {
                self.cpus = Some(set);
            }
        }
    }

    fn report(&mut self) {
        if let Some(sink) = self.helpers.as_ref().and_then(HelperPlacement::load_sink) {
            report_helper_delta(&sink, &mut self.reported_ns);
        }
    }
}

impl Drop for IoThreads {
    fn drop(&mut self) {
        // Closing the queue ends the threads once it is empty
        self.jobs = None;
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

pub struct PooledFile {
    file: Arc<File>,
    config: SinkConfig,
    /// Whether the file is open with O_DIRECT
    direct: bool,
    /// Offsets and lengths of direct writes are multiples of this
    align: usize,
    /// Bytes per buffer handed to the I/O threads, a multiple of `align`
    buf_size: usize,
    /// Length of the file when it was opened: the records written here start there
    start: u64,
    /// The buffer records go to, its file offset and the bytes in it (beyond `buf_size`
    /// while a record crosses the buffer's end)
    cur: AlignedBuf,
    cur_offset: u64,
    cur_len: usize,
    free: Vec<AlignedBuf>,
    /// Started with the first full buffer, on the writer's thread
    io: Option<IoThreads>,
    helpers: Option<HelperPlacement>,
    in_flight: usize,
    /// A copy of the current buffer is being written. A later write of the same range must
    /// not overtake it.
    partial_in_flight: bool,
    /// Bytes of the current buffer written by the last partial write, and when the current
    /// buffer was started or partially written
    partial_len: usize,
    partial_at: Instant,
    /// File ranges written that do not yet join the durable prefix, by start offset
    written: BTreeMap<u64, u64>,
    /// Everything before this offset is in the file
    durable_end: u64,
    /// The first failed write. The writer stops at the next reserve.
    error: Option<io::Error>,
    failed: bool,
    /// Length of the file with its preallocated space, and the preallocation in flight
    allocated: u64,
    prealloc: Option<mpsc::Receiver<io::Result<u64>>>,
    stats: SinkStats,
}

impl PooledFile {
    /// Opens `path` for appending. With `SinkKind::Direct`, falls back to buffered writes if
    /// the file system refuses O_DIRECT.
    pub fn new(path: &Path, config: SinkConfig) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        let start = file.metadata()?.len();
        let mut direct = config.kind == SinkKind::Direct;
        let align = if direct {
            match dio_alignment(&file) {
                Some((mem_align, offset_align)) if mem_align <= PAGE => offset_align.max(512),
                Some((mem_align, _)) => {
                    warn!(
                        "{}: O_DIRECT needs {} byte aligned memory, writing through the page cache",
                        path.display(),
                        mem_align
                    );
                    direct = false;
                    1
                }
                None => PAGE,
            }
        } else {
            1
        };
        let buf_size = config
            .buffer_bytes
            .max(PAGE)
            .next_multiple_of(PAGE.max(align));
        let buffers = config.buffers.max(2);
        let mut cur = AlignedBuf::new(buf_size + SLACK)?;
        let free = (1..buffers)
            .map(|_| AlignedBuf::new(buf_size + SLACK))
            .collect::<io::Result<Vec<_>>>()?;

        // A direct write starts at an aligned offset, so the partial block at the end of an
        // existing file is read into the first buffer and written again with the new records
        let partial = (start % align as u64) as usize;
        let cur_offset = start - partial as u64;
        if partial > 0 {
            read_exact_at(&file, &mut cur.as_mut_slice()[..partial], cur_offset)?;
        }
        if direct {
            direct = enable_direct(&file, &cur, cur_offset, align, path)?;
        }
        let kind = if direct {
            SinkKind::Direct
        } else {
            SinkKind::Buffered
        };
        info!(
            "Writing {} with {} buffers of {} KiB ({}, {} I/O threads)",
            path.display(),
            buffers,
            buf_size >> 10,
            if direct { "O_DIRECT" } else { "page cache" },
            config.io_threads.max(1)
        );
        Ok(Self {
            file: Arc::new(file),
            config,
            direct,
            align: if direct { align } else { 1 },
            buf_size,
            start,
            cur,
            cur_offset,
            cur_len: partial,
            free,
            io: None,
            helpers: None,
            in_flight: 0,
            partial_in_flight: false,
            partial_len: 0,
            partial_at: Instant::now(),
            written: BTreeMap::new(),
            durable_end: cur_offset,
            error: None,
            failed: false,
            allocated: start.max(cur_offset + align as u64),
            prealloc: None,
            stats: SinkStats {
                sink: kind.name(),
                ..SinkStats::default()
            },
        })
    }

    pub fn set_helpers(&mut self, helpers: HelperPlacement) {
        self.helpers = Some(helpers);
    }

    /// Returns the next `len` bytes of the file for writing. The bytes of a record that
    /// crosses the buffer's end are moved to the next buffer at the next call, once written.
    #[inline]
    pub fn reserve(&mut self, len: usize) -> io::Result<&mut [u8]> {
        if self.cur_len >= self.buf_size {
            self.rotate()?;
        }
        if len > SLACK {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("record of {} bytes is larger than {} bytes", len, SLACK),
            ));
        }
        let start = self.cur_len;
        self.cur_len += len;
        Ok(&mut self.cur.as_mut_slice()[start..start + len])
    }

    /// Hands the full buffer to the I/O threads and continues in a free one
    fn rotate(&mut self) -> io::Result<()> {
        self.reap()?;
        let next = self.free_buffer()?;
        let full = mem::replace(&mut self.cur, next);
        let overflow = self.cur_len - self.buf_size;
        self.cur.as_mut_slice()[..overflow]
            .copy_from_slice(&full.as_slice()[self.buf_size..self.cur_len]);
        self.submit(full, self.cur_offset, self.buf_size, false)?;
        self.cur_offset += self.buf_size as u64;
        self.cur_len = overflow;
        self.partial_len = 0;
        self.partial_at = Instant::now();
        self.preallocate();
        Ok(())
    }

    /// Takes over a finished preallocation, and starts the next one when the free space
    /// ahead of the writes gets short
    fn preallocate(&mut self) {
        if !self.direct || !self.config.preallocate {
            return;
        }
        if let Some(rx) = &self.prealloc {
            match rx.try_recv() {
                Ok(Ok(allocated)) => self.allocated = self.allocated.max(allocated),
                Ok(Err(err)) => self.prealloc_failed(err),
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.prealloc_failed(io::Error::other("the preallocation helper died"))
                }
            }
            self.prealloc = None;
        }
        // The writes in flight and the next buffer must fit
        let required = (self.cur_offset as usize).saturating_add(self.buffers() * self.buf_size);
        let capacity = self.allocated as usize;
        let next = next_capacity(capacity, PREALLOC_STEP, required);
        if required <= capacity && !starts_growth(capacity, required, next) {
            return;
        }
        let file = self.file.clone();
        let (tx, rx) = mpsc::channel();
        let (cpus, load_sink) = match &self.helpers {
            Some(helpers) => (helpers.cpu_set(), helpers.load_sink()),
            None => (None, None),
        };
        let spawned = spawn_helper("tcbee-prealloc", cpus, load_sink, move || {
            let _ = tx.send(allocate(&file, capacity, next - capacity).map(|()| next as u64));
        });
        match spawned {
            Ok(_) => {
                self.prealloc = Some(rx);
                self.stats.preallocs += 1;
            }
            Err(err) => self.prealloc_failed(err),
        }
    }

    /// Writes go on without preallocation, past the end of the file. A full disk fails them.
    fn prealloc_failed(&mut self, err: io::Error) {
        if self.stats.prealloc_failures == 0 {
            warn!(
                "Preallocating the trace file failed, writing without: {}",
                err
            );
        }
        self.stats.prealloc_failures += 1;
    }

    fn buffers(&self) -> usize {
        self.free.len() + self.in_flight + 1
    }

    /// Called regularly by the writer: takes back finished buffers, fails with a write error,
    /// and writes the current buffer as it is once it has been filling for `IDLE_WRITE`
    pub fn tick(&mut self) -> io::Result<()> {
        self.reap()?;
        if self.cur_len > self.partial_len
            && self.cur_len < self.buf_size
            && !self.partial_in_flight
            && self.partial_at.elapsed() >= IDLE_WRITE
        {
            self.write_partial()?;
        }
        Ok(())
    }

    /// Writes a copy of the current buffer, padded for O_DIRECT. Skipped without a free buffer:
    /// then writes are in flight and the buffer fills.
    fn write_partial(&mut self) -> io::Result<()> {
        let Some(mut copy) = self.free.pop() else {
            return Ok(());
        };
        let len = self.cur_len.next_multiple_of(self.align);
        copy.as_mut_slice()[..self.cur_len].copy_from_slice(&self.cur.as_slice()[..self.cur_len]);
        copy.as_mut_slice()[self.cur_len..len].fill(0);
        self.submit(copy, self.cur_offset, len, true)?;
        self.partial_in_flight = true;
        self.partial_len = self.cur_len;
        self.partial_at = Instant::now();
        Ok(())
    }

    fn submit(
        &mut self,
        buf: AlignedBuf,
        offset: u64,
        len: usize,
        partial: bool,
    ) -> io::Result<()> {
        // The I/O threads may write in any order, so a partial write of this range ends first
        if !partial {
            self.wait_partial()?;
        }
        if self.io.is_none() {
            self.io = Some(IoThreads::start(
                &self.file,
                self.config.io_threads,
                &self.config.io_cpus,
                self.helpers.as_ref(),
            )?);
        }
        let io = self.io.as_ref().expect("just started");
        io.submit(IoJob {
            buf,
            offset,
            len,
            partial,
        })?;
        self.in_flight += 1;
        self.stats.writes += 1;
        Ok(())
    }

    /// A free buffer, waiting for a write to finish if there is none
    fn free_buffer(&mut self) -> io::Result<AlignedBuf> {
        if self.free.is_empty() {
            self.stall(|file| file.free.is_empty())?;
        }
        Ok(self.free.pop().expect("a write finished"))
    }

    /// Waits for a partial write of the current buffer to end
    fn wait_partial(&mut self) -> io::Result<()> {
        if self.partial_in_flight {
            self.stall(|file| file.partial_in_flight)?;
        }
        Ok(())
    }

    /// Waits for finished writes while `waiting` holds, counted as a stall of the writer
    fn stall(&mut self, waiting: impl Fn(&Self) -> bool) -> io::Result<()> {
        let waited = Instant::now();
        while waiting(self) {
            self.wait_one()?;
        }
        let ns = waited.elapsed().as_nanos() as u64;
        self.stats.stalls += 1;
        self.stats.stall_ns += ns;
        self.stats.stall_max_ns = self.stats.stall_max_ns.max(ns);
        if self.prealloc.is_some() {
            self.stats.prealloc_stall_ns += ns;
        }
        self.take_error()
    }

    /// Takes back the buffers of finished writes without waiting. Fails with the first
    /// write error.
    fn reap(&mut self) -> io::Result<()> {
        if let Some(io) = &self.io {
            let finished: Vec<IoDone> = io.done.try_iter().collect();
            for done in finished {
                self.finished(done);
            }
        }
        self.take_error()
    }

    /// Waits for one write to finish
    fn wait_one(&mut self) -> io::Result<()> {
        let done = match &self.io {
            Some(io) if self.in_flight > 0 => io
                .done
                .recv()
                .map_err(|_| io::Error::other("the file's I/O threads stopped"))?,
            _ => return Err(io::Error::other("no write in flight to wait for")),
        };
        self.finished(done);
        Ok(())
    }

    fn finished(&mut self, done: IoDone) {
        self.in_flight -= 1;
        self.free.push(done.buf);
        if done.partial {
            self.partial_in_flight = false;
        }
        // A partial write is durable up to its records, not its padding
        let written = if done.partial {
            done.written.min(self.partial_len)
        } else {
            done.written
        };
        if written > 0 {
            // A range written again after a partial write starts inside the durable prefix
            let end = done.offset + written as u64;
            let known = self.written.entry(done.offset).or_insert(end);
            *known = (*known).max(end);
            while let Some((&start, &end)) = self.written.first_key_value() {
                if start > self.durable_end {
                    break;
                }
                self.written.remove(&start);
                self.durable_end = self.durable_end.max(end);
            }
        }
        if let Err(err) = done.result {
            if self.error.is_none() && !self.failed {
                self.error = Some(err);
            }
        }
    }

    fn take_error(&mut self) -> io::Result<()> {
        if let Some(err) = self.error.take() {
            self.failed = true;
            return Err(err);
        }
        if self.failed {
            return Err(io::Error::other("an earlier write to the file failed"));
        }
        Ok(())
    }

    /// Writes out the rest, cuts the file to the records and syncs it. Returns how many
    /// whole records of `record_len` bytes from this session are in the file: all of them,
    /// or after a failed write the prefix before it, to which the file is then cut.
    pub fn finish(mut self, record_len: usize) -> (u64, SinkStats, io::Result<()>) {
        let end = self.cur_offset + self.cur_len as u64;
        let mut result = self.write_rest();
        // Every write must be back before the file is cut, whatever failed
        while self.in_flight > 0 {
            if let Err(err) = self.wait_one() {
                result = result.and(Err(err));
                break;
            }
        }
        result = result.and_then(|()| self.take_error());
        // A running preallocation must not extend the file after it is cut
        if let Some(rx) = self.prealloc.take() {
            let _ = rx.recv();
        }
        let record_len = record_len.max(1) as u64;
        let (records, len) = match &result {
            Ok(()) => ((end - self.start) / record_len, end),
            Err(_) => {
                let durable = self.durable_end.min(end).saturating_sub(self.start);
                let records = durable / record_len;
                (records, self.start + records * record_len)
            }
        };
        let cut = self.file.set_len(len).and_then(|()| self.file.sync_all());
        let stats = mem::take(&mut self.stats);
        (records, stats, result.and(cut))
    }

    /// Submits the full buffer, if any, and the partial last one, padded for O_DIRECT
    fn write_rest(&mut self) -> io::Result<()> {
        if self.cur_len >= self.buf_size {
            self.rotate()?;
        }
        if self.cur_len == 0 {
            return Ok(());
        }
        let len = self.cur_len.next_multiple_of(self.align);
        self.cur.as_mut_slice()[self.cur_len..len].fill(0);
        let last = mem::replace(&mut self.cur, AlignedBuf::new(PAGE)?);
        self.submit(last, self.cur_offset, len, false)?;
        self.cur_len = 0;
        Ok(())
    }

    #[cfg(test)]
    fn is_direct(&self) -> bool {
        self.direct
    }
}

/// Memory and file offset alignment for O_DIRECT, from statx. None if the kernel or file
/// system does not report them.
fn dio_alignment(file: &File) -> Option<(usize, usize)> {
    let mut stx: libc::statx = unsafe { mem::zeroed() };
    let ret = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_DIOALIGN,
            &mut stx,
        )
    };
    (ret == 0 && stx.stx_mask & libc::STATX_DIOALIGN != 0 && stx.stx_dio_offset_align > 0)
        .then_some((
            stx.stx_dio_mem_align as usize,
            stx.stx_dio_offset_align as usize,
        ))
}

fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

/// Switches the file to O_DIRECT and checks with one aligned write of the first block (the
/// partial block it already holds, or zeros past its end) that the file system takes direct
/// writes. False, with the file left buffered, if it does not.
fn enable_direct(
    file: &File,
    first: &AlignedBuf,
    offset: u64,
    align: usize,
    path: &Path,
) -> io::Result<bool> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let refused = |err: io::Error| {
        warn!(
            "{}: no O_DIRECT ({}), writing through the page cache",
            path.display(),
            err
        );
        Ok(false)
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_DIRECT) } < 0 {
        return refused(io::Error::last_os_error());
    }
    let probe = probe_direct_write(file, &first.as_slice()[..align], offset);
    match probe {
        Ok(()) => Ok(true),
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
                return Err(io::Error::last_os_error());
            }
            refused(err)
        }
        Err(err) => Err(err),
    }
}

#[cfg(not(test))]
fn probe_direct_write(file: &File, block: &[u8], offset: u64) -> io::Result<()> {
    pwrite_all(file, block, offset).1
}

/// Tests can make the probe fail as on a file system without O_DIRECT
#[cfg(test)]
fn probe_direct_write(file: &File, block: &[u8], offset: u64) -> io::Result<()> {
    if tests::REFUSE_DIRECT.with(|refuse| refuse.get()) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    pwrite_all(file, block, offset).1
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{cell::Cell, env, fs};

    use super::*;

    thread_local! {
        pub(crate) static REFUSE_DIRECT: Cell<bool> = const { Cell::new(false) };
    }

    fn config(kind: SinkKind) -> SinkConfig {
        SinkConfig {
            kind,
            buffer_bytes: 8192,
            buffers: 3,
            io_threads: 2,
            preallocate: true,
            io_cpus: Vec::new(),
        }
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let path = env::temp_dir().join(format!("tcbee-pooled-{}-{}", name, std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    /// Writes `records` records of `len` bytes, record i filled with byte i
    fn fill(file: &mut PooledFile, records: usize, len: usize) -> Vec<u8> {
        let mut expected = Vec::new();
        for i in 0..records {
            let buf = file.reserve(len).unwrap();
            buf.fill(i as u8);
            expected.extend(std::iter::repeat_n(i as u8, len));
        }
        expected
    }

    #[test]
    fn pooled_file_keeps_all_bytes() {
        for kind in [SinkKind::Direct, SinkKind::Buffered] {
            // Ends before, at and after a buffer's end, and after several buffers
            for records in [0, 1, 8192 / 100, 8192 / 100 + 1, 500] {
                let path = temp("bytes");
                let mut file = PooledFile::new(&path, config(kind)).unwrap();
                let expected = fill(&mut file, records, 100);
                let (written, stats, result) = file.finish(100);
                result.unwrap();
                assert_eq!(written, records as u64);
                assert_eq!(fs::read(&path).unwrap(), expected, "{:?} {}", kind, records);
                assert!(stats.writes >= (records * 100 / 8192) as u64);
                fs::remove_file(&path).unwrap();
            }
        }
    }

    #[test]
    fn pooled_file_appends() {
        for kind in [SinkKind::Direct, SinkKind::Buffered] {
            let path = temp("append");
            // An odd length, as a memory-mapped file leaves it
            fs::write(&path, vec![7u8; 1234]).unwrap();
            let mut file = PooledFile::new(&path, config(kind)).unwrap();
            let mut expected = vec![7u8; 1234];
            expected.extend(fill(&mut file, 300, 52));
            let (written, _, result) = file.finish(52);
            result.unwrap();
            assert_eq!(written, 300);
            assert_eq!(fs::read(&path).unwrap(), expected, "{:?}", kind);
            fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn refused_direct_writes_through_the_page_cache() {
        let path = temp("refused");
        REFUSE_DIRECT.with(|refuse| refuse.set(true));
        let file = PooledFile::new(&path, config(SinkKind::Direct));
        REFUSE_DIRECT.with(|refuse| refuse.set(false));
        let mut file = file.unwrap();
        assert!(!file.is_direct());
        let expected = fill(&mut file, 200, 100);
        let (_, stats, result) = file.finish(100);
        result.unwrap();
        assert_eq!(stats.sink, "buffered");
        assert_eq!(fs::read(&path).unwrap(), expected);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn writer_waits_for_free_buffers() {
        let path = temp("stall");
        let mut config = config(SinkKind::Buffered);
        config.buffers = 2;
        config.io_threads = 1;
        let mut file = PooledFile::new(&path, config).unwrap();
        let expected = fill(&mut file, 5000, 100);
        let (written, _, result) = file.finish(100);
        result.unwrap();
        assert_eq!(written, 5000);
        assert_eq!(fs::read(&path).unwrap(), expected);
        fs::remove_file(&path).unwrap();
    }

    /// The file is preallocated ahead of the writes and cut to the records at the end
    #[test]
    fn preallocated_file_keeps_all_bytes() {
        let path = temp("prealloc");
        let mut file = PooledFile::new(&path, config(SinkKind::Direct)).unwrap();
        if !file.is_direct() {
            return;
        }
        let expected = fill(&mut file, 2000, 100);
        let (written, stats, result) = file.finish(100);
        result.unwrap();
        assert_eq!(written, 2000);
        assert!(stats.preallocs >= 1);
        assert_eq!(fs::read(&path).unwrap(), expected);
        fs::remove_file(&path).unwrap();
    }

    /// A quiet buffer reaches the file before it is full, and is written in full later
    #[test]
    fn idle_buffer_is_written() {
        for kind in [SinkKind::Direct, SinkKind::Buffered] {
            let path = temp("idle");
            let mut file = PooledFile::new(&path, config(kind)).unwrap();
            let mut expected = fill(&mut file, 10, 100);
            file.partial_at -= IDLE_WRITE;
            file.tick().unwrap();
            while file.partial_in_flight {
                file.wait_one().unwrap();
            }
            assert_eq!(fs::read(&path).unwrap()[..1000], expected[..]);
            expected.extend(fill(&mut file, 300, 100));
            let (written, _, result) = file.finish(100);
            result.unwrap();
            assert_eq!(written, 310);
            assert_eq!(fs::read(&path).unwrap(), expected, "{:?}", kind);
            fs::remove_file(&path).unwrap();
        }
    }

    /// A failed write stops the writer, and the file keeps the whole records before it
    #[test]
    fn failed_write_keeps_the_records_before_it() {
        let path = temp("fail");
        let mut file = PooledFile::new(&path, config(SinkKind::Buffered)).unwrap();
        let expected = fill(&mut file, 100, 100);
        // Writes fail from now on: new I/O threads get a read-only descriptor
        file.reap().unwrap();
        while file.in_flight > 0 {
            file.wait_one().unwrap();
        }
        let durable = file.durable_end;
        let read_only = Arc::new(File::open(&path).unwrap());
        file.io = Some(IoThreads::start(&read_only, 1, &[], None).unwrap());
        let mut failed = false;
        for _ in 0..1000 {
            if file.reserve(100).is_err() {
                failed = true;
                break;
            }
        }
        let (written, _, result) = file.finish(100);
        assert!(failed || result.is_err());
        assert_eq!(written, durable / 100);
        let kept = fs::read(&path).unwrap();
        assert_eq!(kept.len() as u64, written * 100);
        assert_eq!(kept[..], expected[..kept.len()]);
        fs::remove_file(&path).unwrap();
    }
}
