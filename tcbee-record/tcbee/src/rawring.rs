//! Draining BPF ring buffers in spans for `--writer-format raw`: instead of handing every
//! record to a callback, the writer finds how far the committed records reach and copies
//! all of them at once. See `tcbee_trace::raw` for the file format.

use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    ptr::{self, NonNull},
    sync::atomic::{fence, AtomicU32, AtomicU64, Ordering},
    time::Duration,
};

use libbpf_rs::{MapCore, MapHandle, MapType};
use tcbee_trace::raw::{stride, BUSY_BIT, DISCARD_BIT};

/// A BPF ring buffer mapped for draining it directly, the way libbpf maps it: the consumer
/// page writable (the kernel allows exactly one page), then the producer page and the data
/// read-only. The kernel maps the data pages twice in a row, so a span of up to the ring's
/// size is contiguous even where it wraps around the end.
///
/// Only one consumer may drain a ring: never use a `RingMap` and a libbpf ring buffer on
/// the same map.
pub(crate) struct RingMap {
    /// The map's fd, for epoll
    fd: OwnedFd,
    consumer: NonNull<u8>,
    /// Producer page, then the data mapped twice
    producer: NonNull<u8>,
    page: usize,
    /// Data bytes (max_entries), a power of two
    size: usize,
}

// The mappings belong to the RingMap alone and are only read and written through atomics
// or by the one writer thread that owns it
unsafe impl Send for RingMap {}

impl RingMap {
    pub fn new(map: MapHandle) -> io::Result<Self> {
        if map.map_type() != MapType::RingBuf {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a ring buffer map",
            ));
        }
        Self::from_fd(
            map.as_fd().try_clone_to_owned()?,
            map.max_entries() as usize,
        )
    }

    /// Maps the ring buffer behind `fd` with `size` data bytes
    fn from_fd(fd: OwnedFd, size: usize) -> io::Result<Self> {
        let (consumer, producer, page) = map_ring(fd.as_fd(), size)?;
        Ok(Self {
            fd,
            consumer,
            producer,
            page,
            size,
        })
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    fn mask(&self) -> u64 {
        self.size as u64 - 1
    }

    fn consumer_pos(&self) -> &AtomicU64 {
        // The kernel keeps consumer_pos at the start of the consumer page (struct bpf_ringbuf)
        unsafe { &*(self.consumer.as_ptr() as *const AtomicU64) }
    }

    /// Where the next record to drain starts. Only this consumer moves it.
    pub fn consumer(&self) -> u64 {
        self.consumer_pos().load(Ordering::Relaxed)
    }

    /// Where the producers will reserve the next record. Records before it are reserved,
    /// not necessarily committed.
    pub fn producer(&self) -> u64 {
        // producer_pos is at the start of the producer page, stored with release by the kernel
        unsafe { &*(self.producer.as_ptr() as *const AtomicU64) }.load(Ordering::Acquire)
    }

    /// The length word of the record at ring position `pos`, loaded with acquire so that
    /// the record's bytes are visible once it is committed
    pub fn header(&self, pos: u64) -> u32 {
        let offset = self.page + (pos & self.mask()) as usize;
        // Records are 8-byte aligned in the data area, the word is the record's first
        unsafe { &*(self.producer.as_ptr().add(offset) as *const AtomicU32) }
            .load(Ordering::Acquire)
    }

    /// The ring's bytes from position `from` to `to`, contiguous across the wrap. The span
    /// must hold committed records only (see `walk`) and stay unreleased while in use.
    pub fn span(&self, from: u64, to: u64) -> &[u8] {
        let len = (to - from) as usize;
        assert!(len <= self.size, "span longer than the ring");
        let offset = self.page + (from & self.mask()) as usize;
        unsafe { std::slice::from_raw_parts(self.producer.as_ptr().add(offset), len) }
    }

    /// Hands the records before `pos` back to the producers. Release: the copy of the span
    /// happens before the producers may overwrite it.
    pub fn release(&self, pos: u64) {
        self.consumer_pos().store(pos, Ordering::Release);
    }

    /// Whether the record at the consumer position is committed, so a drain gets something
    pub fn has_committed(&self) -> bool {
        let consumer = self.consumer();
        self.producer() > consumer && self.header(consumer) & BUSY_BIT == 0
    }
}

impl Drop for RingMap {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.consumer.as_ptr().cast(), self.page);
            libc::munmap(self.producer.as_ptr().cast(), self.page + 2 * self.size);
        }
    }
}

/// Blocks until one of a writer's rings has new records, for `--poll wait`.
///
/// The kernel wakes a waiter only when a record is committed at the consumer position, so
/// records committed while the writer copied a span (with the consumer position still in
/// front of them) wake nobody. Before blocking, `wait` therefore looks at the rings once
/// more, after a full fence: it pairs with the full barrier of the commit, which reads the
/// consumer position after it marks the record committed. Either the commit sees the new
/// consumer position and wakes the waiter, or the writer sees the committed record.
pub(crate) struct RingWaiter {
    epoll: OwnedFd,
    /// Rings registered, the most events one wait can return
    rings: usize,
}

impl RingWaiter {
    pub fn new<'a>(rings: impl IntoIterator<Item = &'a RingMap>) -> io::Result<Self> {
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let epoll = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
        let mut count = 0;
        for ring in rings {
            // Level-triggered: a ring that still holds records stays ready
            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: count as u64,
            };
            let ret = unsafe {
                libc::epoll_ctl(
                    epoll.as_raw_fd(),
                    libc::EPOLL_CTL_ADD,
                    ring.fd().as_raw_fd(),
                    &mut event,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            count += 1;
        }
        Ok(Self {
            epoll,
            rings: count.max(1),
        })
    }

    /// Waits up to `timeout` unless a ring already has committed records
    pub fn wait<'a>(
        &self,
        rings: impl IntoIterator<Item = &'a RingMap>,
        timeout: Duration,
    ) -> io::Result<()> {
        fence(Ordering::SeqCst);
        if rings.into_iter().any(RingMap::has_committed) {
            return Ok(());
        }
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; self.rings];
        let ret = unsafe {
            libc::epoll_wait(
                self.epoll.as_raw_fd(),
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                timeout.as_millis().min(i32::MAX as u128) as libc::c_int,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        Ok(())
    }
}

/// Maps a ring buffer of `size` data bytes from `fd`: the consumer page read-write at
/// offset 0, the producer page and the twice-mapped data read-only from offset page size
fn map_ring(fd: BorrowedFd<'_>, size: usize) -> io::Result<(NonNull<u8>, NonNull<u8>, usize)> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    if !size.is_power_of_two() || !size.is_multiple_of(page) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("ring buffer of {} bytes is no power of two of pages", size),
        ));
    }
    let map = |len: usize, prot: libc::c_int, offset: usize| {
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(NonNull::new(addr.cast::<u8>()).expect("mmap returned null"))
        }
    };
    let consumer = map(page, libc::PROT_READ | libc::PROT_WRITE, 0)?;
    match map(page + 2 * size, libc::PROT_READ, page) {
        Ok(producer) => Ok((consumer, producer, page)),
        Err(err) => {
            unsafe { libc::munmap(consumer.as_ptr().cast(), page) };
            Err(err)
        }
    }
}

/// How far a walk over a ring buffer got
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Walk {
    /// Ring position after the last record of the span
    pub end: u64,
    /// Committed records in the span
    pub records: u64,
    /// Discarded records in the span (copied too, readers skip them)
    pub discards: u64,
    pub stop: Stop,
}

/// Why a walk ended
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// It reached the producer position: the span holds everything that was there
    Producer,
    /// The next record is still being written, possibly with committed ones behind it
    Busy,
    /// The span reached the requested size
    Cap,
}

/// The ring buffer holds something this writer cannot have written there
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkError {
    /// A committed record whose length is not the ring's record length
    Length { pos: u64, len: u32 },
    /// A record that ends after the producer position
    PastProducer { pos: u64, producer: u64 },
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalkError::Length { pos, len } => {
                write!(f, "ring buffer record of {} bytes at position {}", len, pos)
            }
            WalkError::PastProducer { pos, producer } => write!(
                f,
                "ring buffer record at position {} ends after the producer position {}",
                pos, producer
            ),
        }
    }
}

/// Walks the records from `consumer` towards `producer`, every one `record_len` bytes
/// (`stride` in the ring), and returns the span that can be copied: up to the producer
/// position, the first record that is still busy, or `max_bytes` (at least one stride).
/// `header(pos)` loads the length word of the record at ring position `pos` with acquire
/// ordering, so the record's bytes are visible once the word says it is committed.
pub(crate) fn walk(
    header: impl Fn(u64) -> u32,
    consumer: u64,
    producer: u64,
    record_len: usize,
    max_bytes: usize,
) -> Result<Walk, WalkError> {
    let step = stride(record_len) as u64;
    let limit = consumer + (max_bytes as u64 / step).max(1) * step;
    let mut walk = Walk {
        end: consumer,
        records: 0,
        discards: 0,
        stop: Stop::Producer,
    };
    while walk.end < producer {
        if walk.end + step > limit {
            walk.stop = Stop::Cap;
            break;
        }
        let word = header(walk.end);
        if word & BUSY_BIT != 0 {
            walk.stop = Stop::Busy;
            break;
        }
        let len = word & !(BUSY_BIT | DISCARD_BIT);
        if len as usize != record_len {
            return Err(WalkError::Length { pos: walk.end, len });
        }
        if walk.end + step > producer {
            return Err(WalkError::PastProducer {
                pos: walk.end,
                producer,
            });
        }
        if word & DISCARD_BIT != 0 {
            walk.discards += 1;
        } else {
            walk.records += 1;
        }
        walk.end += step;
    }
    Ok(walk)
}

#[cfg(test)]
pub(crate) mod tests {
    use tcbee_trace::raw::RINGBUF_HEADER_LEN;

    use super::*;

    /// A ring buffer in plain memory: `size` data bytes mapped twice, like the kernel maps
    /// them, and the positions the producer and consumer keep
    pub(crate) struct FakeRing {
        pub data: Vec<u8>,
        pub producer: u64,
        pub consumer: u64,
        record_len: usize,
    }

    impl FakeRing {
        pub fn new(size: usize, record_len: usize) -> Self {
            assert!(size.is_power_of_two());
            Self {
                data: vec![0; 2 * size],
                producer: 0,
                consumer: 0,
                record_len,
            }
        }

        fn mask(&self) -> u64 {
            (self.data.len() / 2 - 1) as u64
        }

        /// Writes `bytes` at ring position `pos` into both mappings
        pub fn put(&mut self, pos: u64, bytes: &[u8]) {
            let size = self.data.len() / 2;
            for (i, b) in bytes.iter().enumerate() {
                let at = (pos as usize + i) % size;
                self.data[at] = *b;
                self.data[at + size] = *b;
            }
        }

        /// Reserves the next record (busy) and returns its position
        pub fn reserve(&mut self, fill: u8) -> u64 {
            let pos = self.producer;
            let step = stride(self.record_len) as u64;
            assert!(pos + step - self.consumer <= self.mask() + 1, "ring full");
            self.put(pos, &(self.record_len as u32 | BUSY_BIT).to_ne_bytes());
            self.put(
                pos + RINGBUF_HEADER_LEN as u64,
                &vec![fill; self.record_len],
            );
            self.producer += step;
            pos
        }

        pub fn commit(&mut self, pos: u64) {
            self.put(pos, &(self.record_len as u32).to_ne_bytes());
        }

        pub fn discard(&mut self, pos: u64) {
            self.put(pos, &(self.record_len as u32 | DISCARD_BIT).to_ne_bytes());
        }

        pub fn push(&mut self, fill: u8) -> u64 {
            let pos = self.reserve(fill);
            self.commit(pos);
            pos
        }

        pub fn header(&self, pos: u64) -> u32 {
            let at = (pos & self.mask()) as usize;
            u32::from_ne_bytes(self.data[at..at + 4].try_into().unwrap())
        }

        /// The bytes of the span [from, to), contiguous thanks to the double mapping
        pub fn span(&self, from: u64, to: u64) -> &[u8] {
            let at = (from & self.mask()) as usize;
            &self.data[at..at + (to - from) as usize]
        }

        pub fn walk(&self, max_bytes: usize) -> Result<Walk, WalkError> {
            walk(
                |pos| self.header(pos),
                self.consumer,
                self.producer,
                self.record_len,
                max_bytes,
            )
        }
    }

    const LEN: usize = 24; // stride 32

    pub(crate) fn page() -> usize {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    /// A file laid out like a mapped ring buffer: consumer page, producer page, then the
    /// data twice. Holds a writable mapping of all of it for the test to play the kernel.
    pub(crate) struct MemRing {
        fd: OwnedFd,
        map: memmap2::MmapMut,
        size: usize,
    }

    impl MemRing {
        pub fn new(size: usize) -> Self {
            let name = std::ffi::CString::new("tcbee-ring-test").unwrap();
            let raw = unsafe { libc::memfd_create(name.as_ptr(), 0) };
            assert!(raw >= 0, "memfd_create: {}", io::Error::last_os_error());
            let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
            let file = std::fs::File::from(fd.try_clone().unwrap());
            file.set_len((2 * page() + 2 * size) as u64).unwrap();
            let map = unsafe { memmap2::MmapMut::map_mut(&file).unwrap() };
            Self { fd, map, size }
        }

        /// Copies the fake ring's data (both mappings) and producer position in
        pub fn load(&mut self, ring: &FakeRing) {
            let page = page();
            self.map[page..page + 8].copy_from_slice(&ring.producer.to_ne_bytes());
            self.map[2 * page..2 * page + 2 * self.size].copy_from_slice(&ring.data);
        }

        pub fn consumer_pos(&self) -> u64 {
            u64::from_ne_bytes(self.map[..8].try_into().unwrap())
        }

        pub fn ring_map(&self) -> RingMap {
            RingMap::from_fd(self.fd.try_clone().unwrap(), self.size).unwrap()
        }
    }

    #[test]
    fn ring_map_reads_records_across_the_wrap() {
        let size = 2 * page();
        let mut fake = FakeRing::new(size, LEN);
        let records = size / 32;
        for i in 0..records - 3 {
            fake.push(i as u8);
        }
        fake.consumer = fake.producer;
        for i in 0..6 {
            fake.push(100 + i);
        }
        let mut mem = MemRing::new(size);
        mem.load(&fake);
        let ring = mem.ring_map();
        ring.release(fake.consumer);
        assert_eq!(mem.consumer_pos(), fake.consumer);
        assert_eq!(ring.consumer(), fake.consumer);
        assert_eq!(ring.producer(), fake.producer);
        let walk = walk(
            |pos| ring.header(pos),
            ring.consumer(),
            ring.producer(),
            LEN,
            1 << 20,
        )
        .unwrap();
        assert_eq!((walk.records, walk.stop), (6, Stop::Producer));
        let span = ring.span(ring.consumer(), walk.end);
        let fills: Vec<u8> = span.chunks(32).map(|frame| frame[8]).collect();
        assert_eq!(fills, [100, 101, 102, 103, 104, 105]);
        ring.release(walk.end);
        assert_eq!(mem.consumer_pos(), walk.end);
    }

    #[test]
    fn has_committed_waits_for_the_record_at_the_consumer() {
        let size = 2 * page();
        let mut fake = FakeRing::new(size, LEN);
        let mut mem = MemRing::new(size);
        mem.load(&fake);
        assert!(!mem.ring_map().has_committed());
        let busy = fake.reserve(1);
        fake.push(2);
        mem.load(&fake);
        // A committed record behind a busy one cannot be drained yet
        assert!(!mem.ring_map().has_committed());
        fake.commit(busy);
        mem.load(&fake);
        assert!(mem.ring_map().has_committed());
    }

    #[test]
    fn ring_map_rejects_odd_sizes() {
        let mem = MemRing::new(2 * page());
        assert!(RingMap::from_fd(mem.fd.try_clone().unwrap(), 3 * page()).is_err());
        assert!(RingMap::from_fd(mem.fd.try_clone().unwrap(), 100).is_err());
    }

    /// The kernel's mapping rules for a real ring buffer (needs CAP_BPF: run as root with
    /// `cargo test -- --ignored ring_map_maps_a_kernel_ring`)
    #[test]
    #[ignore]
    fn ring_map_maps_a_kernel_ring() {
        let size = 4 * page() as u32;
        let opts = libbpf_rs::libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_rs::libbpf_sys::bpf_map_create_opts>() as _,
            ..Default::default()
        };
        let map = MapHandle::create(MapType::RingBuf, Some("rawring_test"), 0, 0, size, &opts)
            .expect("creating a ring buffer needs CAP_BPF");
        let ring = RingMap::new(map).unwrap();
        // RingMap keeps its own fd, the map's closes with the handle
        let fd = ring.fd().as_raw_fd();
        assert_eq!(ring.size, size as usize);
        assert_eq!((ring.consumer(), ring.producer()), (0, 0));
        // An empty ring lets the waiter time out
        let waiter = RingWaiter::new([&ring]).unwrap();
        let start = std::time::Instant::now();
        waiter.wait([&ring], Duration::from_millis(20)).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(15));
        // More than the consumer page writable is refused
        let rw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                2 * page(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_eq!(rw, libc::MAP_FAILED);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn empty_ring() {
        let ring = FakeRing::new(4096, LEN);
        let walk = ring.walk(1 << 20).unwrap();
        assert_eq!((walk.end, walk.records, walk.stop), (0, 0, Stop::Producer));
    }

    #[test]
    fn committed_records_up_to_the_producer() {
        let mut ring = FakeRing::new(4096, LEN);
        for i in 0..5 {
            ring.push(i);
        }
        let walk = ring.walk(1 << 20).unwrap();
        assert_eq!(
            (walk.end, walk.records, walk.stop),
            (160, 5, Stop::Producer)
        );
    }

    #[test]
    fn stops_at_the_first_busy_record() {
        let mut ring = FakeRing::new(4096, LEN);
        ring.push(1);
        let busy = ring.reserve(2);
        // A nested program committed after the busy one: it must wait for it
        ring.push(3);
        let walk = ring.walk(1 << 20).unwrap();
        assert_eq!((walk.end, walk.records, walk.stop), (32, 1, Stop::Busy));
        ring.commit(busy);
        let walk = ring.walk(1 << 20).unwrap();
        assert_eq!((walk.end, walk.records, walk.stop), (96, 3, Stop::Producer));
    }

    #[test]
    fn busy_first_gives_an_empty_span() {
        let mut ring = FakeRing::new(4096, LEN);
        ring.reserve(1);
        let walk = ring.walk(1 << 20).unwrap();
        assert_eq!((walk.end, walk.records, walk.stop), (0, 0, Stop::Busy));
    }

    #[test]
    fn discarded_records_are_counted_apart() {
        let mut ring = FakeRing::new(4096, LEN);
        ring.push(1);
        let pos = ring.reserve(2);
        ring.discard(pos);
        ring.push(3);
        let walk = ring.walk(1 << 20).unwrap();
        assert_eq!((walk.records, walk.discards, walk.end), (2, 1, 96));
    }

    #[test]
    fn cap_ends_on_whole_records() {
        let mut ring = FakeRing::new(4096, LEN);
        for i in 0..10 {
            ring.push(i);
        }
        // 100 bytes hold three strides of 32
        let walk = ring.walk(100).unwrap();
        assert_eq!((walk.end, walk.records, walk.stop), (96, 3, Stop::Cap));
        // Less than a stride still moves on by one record
        let walk = ring.walk(1).unwrap();
        assert_eq!((walk.end, walk.records, walk.stop), (32, 1, Stop::Cap));
    }

    #[test]
    fn spans_wrap_around_the_ring() {
        let mut ring = FakeRing::new(128, LEN); // four records
        for i in 0..3 {
            ring.push(i);
        }
        ring.consumer = ring.walk(1 << 20).unwrap().end;
        for i in 10..14 {
            ring.push(i);
        }
        let walk = ring.walk(1 << 20).unwrap();
        assert_eq!((walk.records, walk.stop), (4, Stop::Producer));
        let span = ring.span(ring.consumer, walk.end);
        let fills: Vec<u8> = span.chunks(32).map(|frame| frame[8]).collect();
        assert_eq!(fills, [10, 11, 12, 13]);
        assert!(span
            .chunks(32)
            .all(|frame| u32::from_ne_bytes(frame[..4].try_into().unwrap()) == LEN as u32));
    }

    #[test]
    fn foreign_lengths_are_errors() {
        let mut ring = FakeRing::new(4096, LEN);
        ring.push(1);
        ring.put(32, &16u32.to_ne_bytes());
        ring.producer += 32;
        assert_eq!(
            ring.walk(1 << 20),
            Err(WalkError::Length { pos: 32, len: 16 })
        );
    }

    #[test]
    fn records_past_the_producer_are_errors() {
        let mut ring = FakeRing::new(4096, LEN);
        ring.push(1);
        ring.producer -= 8;
        assert_eq!(
            ring.walk(1 << 20),
            Err(WalkError::PastProducer {
                pos: 0,
                producer: 24
            })
        );
    }
}
