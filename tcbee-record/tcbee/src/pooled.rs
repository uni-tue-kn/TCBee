//! A trace file written from a pool of large aligned buffers. The writer copies records into
//! the current buffer; full buffers go to I/O threads, which write them with `pwrite`, by
//! default with `O_DIRECT`, or the writer submits them to an io_uring. The writer never takes a page fault or a file system lock for a
//! record. It only waits when every buffer is still being written, and that wait is counted.
//!
//! The file bytes are the same as from the memory-mapped file: records back to back, cut to
//! their exact length at the end. `O_DIRECT` needs aligned offsets and lengths, so the last
//! buffer is padded with zeros and the file is truncated afterwards. A file that exists is
//! appended to: its last partial block is read back once and written again.

use std::{
    collections::{BTreeMap, VecDeque},
    fs::{File, OpenOptions},
    io::{self, ErrorKind},
    mem,
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::FileExt,
    },
    path::Path,
    ptr::NonNull,
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use io_uring::{opcode, types, IoUring};
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

/// io_uring submissions refused for lack of kernel memory are retried for about a second
const ENTER_RETRIES: u32 = 1000;

/// How the trace file is written
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SinkKind {
    /// Memory-mapped file, grown in the background
    #[default]
    Mmap,
    /// Buffer pool, I/O threads write with O_DIRECT
    Direct,
    /// Buffer pool, I/O threads write through the page cache and push the written pages to
    /// the disk right away, then drop them from the cache
    Buffered,
    /// Buffer pool, the writer submits O_DIRECT writes to an io_uring
    Uring,
}

impl SinkKind {
    pub const ALL: [SinkKind; 4] = [
        SinkKind::Mmap,
        SinkKind::Direct,
        SinkKind::Uring,
        SinkKind::Buffered,
    ];

    pub fn name(self) -> &'static str {
        match self {
            SinkKind::Mmap => "mmap",
            SinkKind::Direct => "direct",
            SinkKind::Buffered => "buffered",
            SinkKind::Uring => "uring",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
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
    /// Writes running at once per file: I/O threads, or io_uring writes in flight. At most
    /// `buffers - 1` can run.
    pub io_threads: usize,
    /// Extend an O_DIRECT file ahead of the writes on a helper thread. A direct write past
    /// the end of the file takes the file system's exclusive lock.
    pub preallocate: bool,
    /// CPUs for the I/O threads (or the io_uring's kernel workers), outside the balancing.
    /// Empty: they run as the file helpers on the writer CPUs, the I/O threads' CPU time
    /// counts there, and they follow their writer.
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
    /// Index among the buffers registered with an io_uring
    fixed: Option<u16>,
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
        Ok(Self {
            ptr,
            len,
            fixed: None,
        })
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

/// Write-behind for buffered writes: starts writeback of the range just written, then waits
/// for the range two buffers before it and drops it from the page cache. So the dirty pages
/// stay at a few buffers, and the writes never run into the kernel's dirty throttling.
fn write_behind(file: &File, offset: u64, len: usize) {
    let fd = file.as_raw_fd();
    unsafe {
        libc::sync_file_range(
            fd,
            offset as libc::off64_t,
            len as libc::off64_t,
            libc::SYNC_FILE_RANGE_WRITE,
        );
    }
    let Some(older) = offset.checked_sub(2 * len as u64) else {
        return;
    };
    unsafe {
        libc::sync_file_range(
            fd,
            older as libc::off64_t,
            len as libc::off64_t,
            libc::SYNC_FILE_RANGE_WAIT_BEFORE
                | libc::SYNC_FILE_RANGE_WRITE
                | libc::SYNC_FILE_RANGE_WAIT_AFTER,
        );
        libc::posix_fadvise(
            fd,
            older as libc::off_t,
            len as libc::off_t,
            libc::POSIX_FADV_DONTNEED,
        );
    }
}

/// Where the I/O of a file runs: on `io_cpus`, or with the file helpers, which it then
/// follows as the writers move
fn io_placement(
    io_cpus: &[usize],
    helpers: Option<&HelperPlacement>,
) -> (Option<HelperPlacement>, Option<libc::cpu_set_t>) {
    if io_cpus.is_empty() {
        (helpers.cloned(), helpers.and_then(HelperPlacement::cpu_set))
    } else {
        (None, Some(cpu_set(io_cpus)))
    }
}

/// Whether the I/O has to move to `new` from where it runs
fn moved(new: &libc::cpu_set_t, old: Option<&libc::cpu_set_t>) -> bool {
    old.is_none_or(|old| unsafe { !libc::CPU_EQUAL(new, old) })
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
        write_behind_buffers: bool,
        io_cpus: &[usize],
        helpers: Option<&HelperPlacement>,
    ) -> io::Result<Self> {
        let (jobs_tx, jobs_rx) = mpsc::channel::<IoJob>();
        let (done_tx, done_rx) = mpsc::channel();
        let jobs_rx = Arc::new(Mutex::new(jobs_rx));
        let (follow, cpus) = io_placement(io_cpus, helpers);
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
                // Write-behind errors show at the final sync
                if write_behind_buffers && !job.partial && result.is_ok() {
                    write_behind(&file, job.offset, job.len);
                }
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
            .ok_or_else(threads_stopped)
    }

    fn reap(&self) -> Vec<IoDone> {
        self.done.try_iter().collect()
    }

    fn wait(&self) -> io::Result<IoDone> {
        self.done.recv().map_err(|_| threads_stopped())
    }
}

fn threads_stopped() -> io::Error {
    io::Error::other("the file's I/O threads stopped")
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
        let Some(set) = self.helpers.as_ref().and_then(HelperPlacement::cpu_set) else {
            return;
        };
        if moved(&set, self.cpus.as_ref())
            && unsafe { libc::sched_setaffinity(0, mem::size_of_val(&set), &set) } == 0
        {
            self.cpus = Some(set);
        }
    }

    fn report(&mut self) {
        if let Some(sink) = self.helpers.as_ref().and_then(HelperPlacement::load_sink) {
            report_helper_delta(&sink, &mut self.reported_ns);
        }
    }
}

/// Where the writes of a file go
enum Io {
    Threads(IoThreads),
    Uring(Box<UringIo>),
}

impl Io {
    /// Hands a write over. The I/O threads drop it if they are gone, the io_uring keeps it
    /// even if it cannot submit it now.
    fn submit(&mut self, job: IoJob) -> io::Result<()> {
        match self {
            Io::Threads(threads) => threads.submit(job),
            Io::Uring(uring) => uring.submit(job),
        }
    }

    /// The writes that completed, without waiting, and an error on the way. The completed
    /// writes come back even then: their buffers return and their bytes count.
    fn reap(&mut self) -> (Vec<IoDone>, io::Result<()>) {
        match self {
            Io::Threads(threads) => (threads.reap(), Ok(())),
            Io::Uring(uring) => uring.reap(),
        }
    }

    /// Waits until at least one write completed, as `reap`
    fn wait(&mut self) -> (Vec<IoDone>, io::Result<()>) {
        match self {
            Io::Threads(threads) => match threads.wait() {
                Ok(done) => (vec![done], Ok(())),
                Err(err) => (Vec::new(), Err(err)),
            },
            Io::Uring(uring) => uring.wait(),
        }
    }

    /// Moves the kernel's I/O workers with the writer. I/O threads move themselves.
    fn upkeep(&mut self) {
        if let Io::Uring(uring) = self {
            uring.upkeep();
        }
    }
}

/// An io_uring the writer thread submits the file's writes to and reaps them from. It is set
/// up on the writer thread, which alone may use it (single issuer, deferred task work).
struct UringIo {
    ring: IoUring,
    /// The writes in flight, by user data. The kernel reads their buffers until they complete.
    slots: Vec<Option<IoJob>>,
    /// Writes beyond `max_in_flight`, submitted as others complete, like the I/O threads'
    /// queue
    queued: VecDeque<IoJob>,
    max_in_flight: usize,
    fd: RawFd,
    file_registered: bool,
    buffers_registered: bool,
    /// The kernel's I/O workers follow the writer's helper CPUs
    follow: Option<HelperPlacement>,
    cpus: Option<libc::cpu_set_t>,
    upkeep_at: Instant,
}

impl UringIo {
    /// Sets up the ring and registers the file and `buffers`, which must outlive it. At most
    /// `in_flight` writes are in the kernel at once.
    fn start(
        file: &File,
        buffers: &mut [&mut AlignedBuf],
        in_flight: usize,
        io_cpus: &[usize],
        helpers: Option<&HelperPlacement>,
    ) -> io::Result<Self> {
        let entries = (in_flight.max(buffers.len()) as u32)
            .next_power_of_two()
            .max(8);
        let ring = IoUring::builder()
            .setup_single_issuer()
            .setup_defer_taskrun()
            .setup_taskrun_flag()
            .build(entries)
            .or_else(|err| match err.raw_os_error() {
                // A kernel before 6.1
                Some(libc::EINVAL) => IoUring::builder().build(entries),
                _ => Err(err),
            })?;
        let fd = file.as_raw_fd();
        let file_registered = ring.submitter().register_files(&[fd]).is_ok();
        let iovecs: Vec<libc::iovec> = buffers
            .iter()
            .map(|buf| libc::iovec {
                iov_base: buf.ptr.as_ptr().cast(),
                iov_len: buf.len,
            })
            .collect();
        // SAFETY: the buffers are only unmapped when the file is dropped. The kernel pins
        // their pages while they are registered.
        let buffers_registered = unsafe { ring.submitter().register_buffers(&iovecs) }.is_ok();
        if buffers_registered {
            for (index, buf) in buffers.iter_mut().enumerate() {
                buf.fixed = Some(index as u16);
            }
        } else {
            info!("Cannot register the trace buffers with the io_uring, writing without");
        }
        let (follow, cpus) = io_placement(io_cpus, helpers);
        if let Some(set) = &cpus {
            if let Err(err) = ring.submitter().register_iowq_aff(set) {
                info!("Cannot place the io_uring's workers: {}", err);
            }
        }
        Ok(Self {
            ring,
            slots: Vec::new(),
            queued: VecDeque::new(),
            max_in_flight: in_flight,
            fd,
            file_registered,
            buffers_registered,
            follow,
            cpus,
            upkeep_at: Instant::now(),
        })
    }

    fn submit(&mut self, job: IoJob) -> io::Result<()> {
        self.queued.push_back(job);
        self.pump()
    }

    /// Submits queued writes while fewer than `max_in_flight` are in the kernel
    fn pump(&mut self) -> io::Result<()> {
        let mut pushed = false;
        while self.slots.iter().filter(|slot| slot.is_some()).count() < self.max_in_flight {
            let Some(job) = self.queued.pop_front() else {
                break;
            };
            self.push(job)?;
            pushed = true;
        }
        if pushed {
            self.enter(0)?;
        }
        Ok(())
    }

    fn push(&mut self, job: IoJob) -> io::Result<()> {
        let slot = match self.slots.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => {
                self.slots.push(None);
                self.slots.len() - 1
            }
        };
        let (buf, len) = (job.buf.ptr.as_ptr() as *const u8, job.len as u32);
        let fixed = job.buf.fixed.filter(|_| self.buffers_registered);
        let entry = match (self.file_registered, fixed) {
            (true, Some(index)) => opcode::WriteFixed::new(types::Fixed(0), buf, len, index)
                .offset(job.offset)
                .build(),
            (false, Some(index)) => opcode::WriteFixed::new(types::Fd(self.fd), buf, len, index)
                .offset(job.offset)
                .build(),
            (true, None) => opcode::Write::new(types::Fixed(0), buf, len)
                .offset(job.offset)
                .build(),
            (false, None) => opcode::Write::new(types::Fd(self.fd), buf, len)
                .offset(job.offset)
                .build(),
        }
        .user_data(slot as u64);
        self.slots[slot] = Some(job);
        // SAFETY: the buffer stays in `slots`, and mapped, until the write completes
        while unsafe { self.ring.submission().push(&entry) }.is_err() {
            self.enter(0)?;
        }
        Ok(())
    }

    /// Submits the queued entries and, with `want > 0`, waits for that many completions
    fn enter(&mut self, want: usize) -> io::Result<()> {
        let mut retries = 0;
        loop {
            match self.ring.submit_and_wait(want) {
                Ok(_) => return Ok(()),
                Err(err) => match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // The kernel is short of memory for the requests for now
                    Some(libc::EAGAIN | libc::ENOMEM) if retries < ENTER_RETRIES => {
                        retries += 1;
                        thread::sleep(Duration::from_millis(1));
                    }
                    // Completions wait for room in the completion queue: reap them
                    Some(libc::EBUSY) => return Ok(()),
                    _ => return Err(err),
                },
            }
        }
    }

    /// The writes that completed, without waiting
    fn reap(&mut self) -> (Vec<IoDone>, io::Result<()>) {
        // Deferred completions are posted only by an enter that asks for events. The kernel
        // flags when there are any, so an idle ring costs no system call.
        let entered = if self.ring.submission().taskrun() {
            self.enter(0)
        } else {
            Ok(())
        };
        let done = self.completed();
        let pumped = entered.and_then(|()| self.pump());
        (done, pumped)
    }

    /// Waits until at least one write completed
    fn wait(&mut self) -> (Vec<IoDone>, io::Result<()>) {
        loop {
            let done = self.completed();
            if !done.is_empty() {
                let pumped = self.pump();
                return (done, pumped);
            }
            if let Err(err) = self.enter(1) {
                return (done, Err(err));
            }
        }
    }

    fn completed(&mut self) -> Vec<IoDone> {
        let mut done = Vec::new();
        for cqe in self.ring.completion() {
            let job = self
                .slots
                .get_mut(cqe.user_data() as usize)
                .and_then(Option::take);
            let Some(job) = job else { continue };
            let ret = cqe.result();
            let (written, result) = if ret < 0 {
                (0, Err(io::Error::from_raw_os_error(-ret)))
            } else if (ret as usize) < job.len {
                // The rest would be unaligned for O_DIRECT, and is a full disk or an I/O error
                (
                    ret as usize,
                    Err(io::Error::new(ErrorKind::WriteZero, "short write")),
                )
            } else {
                (job.len, Ok(()))
            };
            done.push(IoDone {
                buf: job.buf,
                offset: job.offset,
                written,
                partial: job.partial,
                result,
            });
        }
        done
    }

    /// Moves the kernel's I/O workers where a helper of the writer would start now
    fn upkeep(&mut self) {
        let Some(helpers) = &self.follow else { return };
        if self.upkeep_at.elapsed() < IO_UPKEEP {
            return;
        }
        self.upkeep_at = Instant::now();
        let Some(set) = helpers.cpu_set() else { return };
        if moved(&set, self.cpus.as_ref()) && self.ring.submitter().register_iowq_aff(&set).is_ok()
        {
            self.cpus = Some(set);
        }
    }
}

impl Drop for UringIo {
    fn drop(&mut self) {
        // The kernel may still read the buffers of writes in flight
        while self.slots.iter().any(Option::is_some) {
            if self.enter(1).is_err() {
                // Leak them rather than unmap memory the kernel may still read
                for job in self.slots.iter_mut().filter_map(Option::take) {
                    mem::forget(job.buf);
                }
                return;
            }
            drop(self.completed());
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
    io: Option<Io>,
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
        let mut direct = matches!(config.kind, SinkKind::Direct | SinkKind::Uring);
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
            file.read_exact_at(&mut cur.as_mut_slice()[..partial], cur_offset)?;
        }
        if direct {
            direct = enable_direct(&file, &cur, cur_offset, align, path)?;
        }
        // io_uring writes O_DIRECT only, the page cache path uses the I/O threads
        let kind = match (direct, config.kind) {
            (true, SinkKind::Uring) => SinkKind::Uring,
            (true, _) => SinkKind::Direct,
            (false, _) => SinkKind::Buffered,
        };
        info!(
            "Writing {} with {} buffers of {} KiB ({}, {} writes at once)",
            path.display(),
            buffers,
            buf_size >> 10,
            kind.name(),
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
            let rotated = self.rotate();
            self.fail_on(rotated)?;
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
    /// writes the current buffer when it is full, and as it is once it has been filling for
    /// `IDLE_WRITE`
    pub fn tick(&mut self) -> io::Result<()> {
        let ticked = self.idle_write();
        self.fail_on(ticked)
    }

    fn idle_write(&mut self) -> io::Result<()> {
        self.reap()?;
        if let Some(io) = &mut self.io {
            io.upkeep();
        }
        // A full buffer waits for the next record otherwise
        if self.cur_len >= self.buf_size {
            return self.rotate();
        }
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
        let in_flight = self.in_flight;
        let submitted = self.submit(copy, self.cur_offset, len, true);
        // A copy the io_uring kept is written even if submitting it failed
        if self.in_flight > in_flight {
            self.partial_in_flight = true;
            self.partial_len = self.cur_len;
            self.partial_at = Instant::now();
        }
        submitted
    }

    fn submit(
        &mut self,
        mut buf: AlignedBuf,
        offset: u64,
        len: usize,
        partial: bool,
    ) -> io::Result<()> {
        // Writes may complete in any order, so a partial write of this range ends first
        if !partial {
            self.wait_partial()?;
        }
        if self.io.is_none() {
            self.io = Some(self.start_io(&mut buf)?);
        }
        let job = IoJob {
            buf,
            offset,
            len,
            partial,
        };
        let io = self.io.as_mut().expect("just started");
        let submitted = io.submit(job);
        // An io_uring keeps a write it could not submit yet: it still comes back
        if submitted.is_ok() || matches!(io, Io::Uring(_)) {
            self.in_flight += 1;
            self.stats.writes += 1;
        }
        submitted
    }

    /// Sets up the io_uring or the I/O threads, on the writer's thread. `taken` is the buffer
    /// about to be written, the others are in the pool.
    fn start_io(&mut self, taken: &mut AlignedBuf) -> io::Result<Io> {
        if self.config.kind == SinkKind::Uring && self.direct {
            let mut buffers: Vec<&mut AlignedBuf> = self.free.iter_mut().collect();
            buffers.push(&mut self.cur);
            buffers.push(taken);
            let uring = UringIo::start(
                &self.file,
                &mut buffers,
                self.config.io_threads.max(1),
                &self.config.io_cpus,
                self.helpers.as_ref(),
            );
            match uring {
                Ok(uring) => return Ok(Io::Uring(Box::new(uring))),
                Err(err) => {
                    warn!("No io_uring ({}), writing O_DIRECT from I/O threads", err);
                    self.stats.sink = SinkKind::Direct.name();
                }
            }
        }
        IoThreads::start(
            &self.file,
            self.config.io_threads,
            !self.direct,
            &self.config.io_cpus,
            self.helpers.as_ref(),
        )
        .map(Io::Threads)
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
        let Some(io) = &mut self.io else {
            return self.take_error();
        };
        let (finished, result) = io.reap();
        for done in finished {
            self.finished(done);
        }
        result?;
        self.take_error()
    }

    /// Waits for one write to finish
    fn wait_one(&mut self) -> io::Result<()> {
        let (finished, result) = match &mut self.io {
            Some(io) if self.in_flight > 0 => io.wait(),
            _ => return Err(io::Error::other("no write in flight to wait for")),
        };
        for done in finished {
            self.finished(done);
        }
        result
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

    /// After an error the file's state may be half updated: nothing more is written, and
    /// `finish` keeps only the records before the first failed write
    fn fail_on<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            self.failed = true;
        }
        result
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
        let rest = self.write_rest();
        let mut result = self.fail_on(rest);
        // Every write must be back before the file is cut, whatever failed
        while self.in_flight > 0 {
            if let Err(err) = self.wait_one() {
                result = result.and(Err(err));
                break;
            }
        }
        result = result.and_then(|()| self.take_error());
        // Writes still queued or in flight after an error end before the file is cut
        drop(self.io.take());
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
        self.take_error()?;
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

    const POOLED: [SinkKind; 3] = [SinkKind::Direct, SinkKind::Buffered, SinkKind::Uring];

    #[test]
    fn pooled_file_keeps_all_bytes() {
        for kind in POOLED {
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
    fn lengths_at_the_block_and_buffer_ends_are_kept() {
        for kind in POOLED {
            for len in [511, 512, 513, 4095, 4096, 4097, 8191, 8192, 8193] {
                let path = temp("edges");
                let mut file = PooledFile::new(&path, config(kind)).unwrap();
                let expected = fill(&mut file, len, 1);
                let (written, _, result) = file.finish(1);
                result.unwrap();
                assert_eq!(written, len as u64);
                assert_eq!(fs::read(&path).unwrap(), expected, "{:?} {}", kind, len);
                fs::remove_file(&path).unwrap();
            }
        }
    }

    #[test]
    fn pooled_file_appends() {
        for kind in POOLED {
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

    #[test]
    fn full_buffer_is_written_without_more_records() {
        let path = temp("full");
        let mut file = PooledFile::new(&path, config(SinkKind::Buffered)).unwrap();
        let expected = fill(&mut file, 8192 / 64, 64);
        file.tick().unwrap();
        assert_eq!(file.stats.writes, 1);
        let (written, _, result) = file.finish(64);
        result.unwrap();
        assert_eq!(written, 8192 / 64);
        assert_eq!(fs::read(&path).unwrap(), expected);
        fs::remove_file(&path).unwrap();
    }

    /// A write that cannot be handed over stops the file, even if the I/O works again
    /// later: the buffers are half rotated, and writing on would put stale bytes in the file
    #[test]
    fn failed_hand_over_stops_the_file() {
        let path = temp("handover");
        let mut file = PooledFile::new(&path, config(SinkKind::Buffered)).unwrap();
        let (jobs, _) = mpsc::channel();
        let (_, done) = mpsc::channel();
        file.io = Some(Io::Threads(IoThreads {
            jobs: Some(jobs),
            done,
            handles: Vec::new(),
        }));
        let failed = (0..300).any(|i| match file.reserve(100) {
            Ok(buf) => {
                buf.fill(i as u8);
                false
            }
            Err(_) => true,
        });
        assert!(failed);
        file.io = Some(Io::Threads(
            IoThreads::start(&file.file, 1, true, &[], None).unwrap(),
        ));
        assert!(file.reserve(100).is_err());
        let (written, _, result) = file.finish(100);
        assert!(result.is_err());
        assert_eq!(written, 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        fs::remove_file(&path).unwrap();
    }

    /// A finished io_uring write comes back without waiting for it: the deferred completion is
    /// posted when the writer looks
    #[test]
    fn uring_reaps_without_waiting() {
        let path = temp("uring");
        let mut file = PooledFile::new(&path, config(SinkKind::Uring)).unwrap();
        let expected = fill(&mut file, 8192 / 100 + 1, 100);
        file.reserve(0).unwrap();
        assert_eq!(file.in_flight, 1);
        if !matches!(file.io, Some(Io::Uring(_))) {
            eprintln!("no io_uring here, skipped");
            fs::remove_file(&path).unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
        file.reap().unwrap();
        assert_eq!(file.in_flight, 0);
        let (_, stats, result) = file.finish(100);
        result.unwrap();
        assert_eq!(stats.sink, "uring");
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
        for kind in POOLED {
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
        file.io = Some(Io::Threads(
            IoThreads::start(&read_only, 1, false, &[], None).unwrap(),
        ));
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
