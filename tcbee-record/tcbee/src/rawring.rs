//! Draining BPF ring buffers in spans for `--writer-format raw`: instead of handing every
//! record to a callback, the writer finds how far the committed records reach and copies
//! all of them at once. See `tcbee_trace::raw` for the file format.

use tcbee_trace::raw::{stride, BUSY_BIT, DISCARD_BIT};

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
        fn put(&mut self, pos: u64, bytes: &[u8]) {
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
            self.put(pos + 8, &vec![fill; self.record_len]);
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
