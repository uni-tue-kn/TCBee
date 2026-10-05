//! Reads records of one trace file in 4 MiB chunks and decodes them.
//!
//! Detecting a truncated tail is the job of the unit planner (WP6): `decode_range` only reads the
//! records it is asked for, and a range that reaches past the end of the file is an I/O error
//! with the offset of the missing record.

use std::{fmt, fs::File, io, ops::Range, os::unix::fs::FileExt};

use crate::event::{DecodeError, Event, Row};

const CHUNK_BYTES: usize = 4 << 20;

/// Failure of `decode_range`; `E` is the error of the caller's callback.
#[derive(Debug)]
pub enum RangeError<E> {
    /// Reading failed or the file ended; `offset` (bytes) is the first record that is missing.
    Io { offset: u64, source: io::Error },
    /// The record at `offset` (bytes) is not valid.
    Decode { offset: u64, source: DecodeError },
    /// The callback failed.
    Callback(E),
}

impl<E: fmt::Display> fmt::Display for RangeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RangeError::Io { offset, source } => {
                write!(f, "read error at file offset {offset}: {source}")
            }
            RangeError::Decode { offset, source } => {
                write!(f, "bad record at file offset {offset}: {source}")
            }
            RangeError::Callback(e) => e.fmt(f),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RangeError<E> {}

/// Error type of the type erased callback of `DecodeFn`.
pub type RowError = Box<dyn std::error::Error + Send + Sync>;

/// Decodes records `records` (indices, not bytes) of `file` and calls `f(seq, event)` for each,
/// where `seq` is the record's index in the file. Every record's divider is checked.
///
/// If the file ends early, the complete records before the end are still delivered, then the
/// error is `Io` with the byte offset of the first missing record.
pub fn decode_range<E: Event, Err>(
    file: &File,
    records: Range<u64>,
    mut f: impl FnMut(u64, E) -> Result<(), Err>,
) -> Result<(), RangeError<Err>> {
    let size = E::ENTRY_SIZE;
    let per_chunk = (CHUNK_BYTES / size).max(1) as u64;
    let total = records.end.saturating_sub(records.start);
    let mut buf = vec![0u8; total.min(per_chunk) as usize * size];

    let mut next = records.start;
    while next < records.end {
        let n = (records.end - next).min(per_chunk) as usize;
        let offset = next * size as u64;
        let bytes = &mut buf[..n * size];
        let (got, read_err) = read_at_most(file, bytes, offset);
        let whole = got / size;

        for (i, rec) in bytes[..whole * size].chunks_exact(size).enumerate() {
            let rec_offset = offset + (i * size) as u64;
            let event = E::decode(rec).map_err(|source| RangeError::Decode {
                offset: rec_offset,
                source,
            })?;
            if !event.check_divider() {
                return Err(RangeError::Decode {
                    offset: rec_offset,
                    source: DecodeError::Divider,
                });
            }
            f(next + i as u64, event).map_err(RangeError::Callback)?;
        }
        if whole < n {
            return Err(RangeError::Io {
                offset: offset + (whole * size) as u64,
                source: read_err.unwrap_or_else(|| io::ErrorKind::UnexpectedEof.into()),
            });
        }
        next += n as u64;
    }
    Ok(())
}

/// Fills `buf` from `offset`; returns the bytes read and the error that stopped it (`None` at
/// end of file).
fn read_at_most(file: &File, buf: &mut [u8], offset: u64) -> (usize, Option<io::Error>) {
    let mut got = 0;
    while got < buf.len() {
        match file.read_at(&mut buf[got..], offset + got as u64) {
            Ok(0) => return (got, None),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return (got, Some(e)),
        }
    }
    (got, None)
}

/// Callback of a `DecodeFn`: sequence number and the decoded record.
pub type RowFn<'a> = dyn FnMut(u64, &dyn Row) -> Result<(), RowError> + 'a;

/// `decode_range` with the binding type erased, so the file table can hold one per binding.
pub type DecodeFn = fn(&File, Range<u64>, &mut RowFn<'_>) -> Result<(), RangeError<RowError>>;

/// `decode_range::<E>` behind the `DecodeFn` signature; the callback gets the record as `&dyn Row`.
pub fn decode_dyn<E: Event>(
    file: &File,
    records: Range<u64>,
    f: &mut RowFn<'_>,
) -> Result<(), RangeError<RowError>> {
    decode_range::<E, RowError>(file, records, |seq, e| f(seq, &e))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::bindings::{sock::sock_trace_entry, tcp4_packet::Tcp4Packet};

    fn fixture(dir: &str, file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(dir)
            .join(file)
    }

    /// Opens a temp file with `bytes` as content; the name is already unlinked.
    fn temp_file(tag: &str, bytes: &[u8]) -> File {
        let path = std::env::temp_dir().join(format!("tcbee_decode_{tag}_{}", std::process::id()));
        fs::write(&path, bytes).unwrap();
        let file = File::open(&path).unwrap();
        let _ = fs::remove_file(&path);
        file
    }

    fn collect<E: Event>(
        file: &File,
        r: Range<u64>,
    ) -> Result<Vec<(u64, E)>, RangeError<std::convert::Infallible>> {
        let mut out = Vec::new();
        decode_range::<E, _>(file, r, |seq, e| {
            out.push((seq, e));
            Ok(())
        })?;
        Ok(out)
    }

    #[test]
    fn decodes_ranges_with_sequence_numbers() {
        let file = File::open(fixture("tcbee_small", "tcp4_send.tcp")).unwrap();
        let all = collect::<Tcp4Packet>(&file, 0..2000).unwrap();
        assert_eq!(all.len(), 2000);
        assert!(all.iter().enumerate().all(|(i, (s, _))| *s == i as u64));

        let mid = collect::<Tcp4Packet>(&file, 700..703).unwrap();
        assert_eq!(
            mid.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            [700, 701, 702]
        );
        assert_eq!(mid[1].1.time, all[701].1.time);
        assert_eq!(mid[1].1.seq, all[701].1.seq);

        assert!(collect::<Tcp4Packet>(&file, 5..5).unwrap().is_empty());
    }

    #[test]
    fn range_past_the_end_delivers_whole_records_then_reports_the_missing_one() {
        let file = File::open(fixture("tcbee_truncated", "send_sock.tcp")).unwrap();
        assert_eq!(collect::<sock_trace_entry>(&file, 0..10).unwrap().len(), 10);

        // The eleventh record is only 17 bytes long: records 0..10 arrive, then the error.
        let mut seen = Vec::new();
        let res = decode_range::<sock_trace_entry, ()>(&file, 0..11, |seq, _| {
            seen.push(seq);
            Ok(())
        });
        match res {
            Err(RangeError::Io { offset, source }) => {
                assert_eq!(offset, 1600);
                assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("expected an I/O error, got {other:?}"),
        }
        assert_eq!(seen, (0..10).collect::<Vec<_>>());

        match collect::<sock_trace_entry>(&file, 10..11) {
            Err(RangeError::Io { offset, .. }) => assert_eq!(offset, 1600),
            other => panic!("expected an I/O error, got {other:?}"),
        }
        match collect::<sock_trace_entry>(&file, 12..14) {
            Err(RangeError::Io { offset, .. }) => assert_eq!(offset, 12 * 160),
            other => panic!("expected an I/O error, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_divider_reports_the_record_offset() {
        let mut bytes = fs::read(fixture("tcbee_small", "tcp4_send.tcp")).unwrap();
        let size = Tcp4Packet::ENTRY_SIZE;
        bytes.truncate(5 * size);
        bytes[3 * size + size - 1] ^= 0xFF; // last divider byte of record 3
        let file = temp_file("div", &bytes);

        let mut seen = Vec::new();
        let res = decode_range::<Tcp4Packet, ()>(&file, 0..5, |seq, _| {
            seen.push(seq);
            Ok(())
        });
        match res {
            Err(RangeError::Decode { offset, source }) => {
                assert_eq!(offset, 3 * size as u64);
                assert_eq!(source, DecodeError::Divider);
            }
            other => panic!("expected a divider error, got {other:?}"),
        }
        assert_eq!(seen, [0, 1, 2]);
    }

    #[test]
    fn wrong_buffer_size_is_an_error_not_a_default_record() {
        assert_eq!(
            Tcp4Packet::decode(&[0u8; 10]).unwrap_err(),
            DecodeError::Size {
                expected: Tcp4Packet::ENTRY_SIZE,
                got: 10
            }
        );
    }

    #[test]
    fn callback_error_stops_decoding() {
        let file = File::open(fixture("tcbee_small", "tcp4_send.tcp")).unwrap();
        let mut calls = 0;
        let res = decode_range::<Tcp4Packet, &str>(&file, 0..100, |seq, _| {
            calls += 1;
            if seq == 4 {
                Err("stop")
            } else {
                Ok(())
            }
        });
        assert!(matches!(res, Err(RangeError::Callback("stop"))));
        assert_eq!(calls, 5);
    }

    /// A file of fixture records repeated past two chunks; checks every delivered record against
    /// the fixture record it was copied from.
    #[test]
    fn chunk_boundaries() {
        let size = Tcp4Packet::ENTRY_SIZE;
        let src = fs::read(fixture("tcbee_small", "tcp4_send.tcp")).unwrap();
        let src_recs = src.len() / size;
        let per_chunk = CHUNK_BYTES / size;
        let total = 2 * per_chunk + 10;
        let mut bytes = Vec::with_capacity(total * size);
        for i in 0..total {
            let r = i % src_recs;
            bytes.extend_from_slice(&src[r * size..(r + 1) * size]);
        }
        let expect = collect::<Tcp4Packet>(&temp_file("src", &src), 0..src_recs as u64).unwrap();
        let file = temp_file("chunks", &bytes);

        let pc = per_chunk as u64;
        let ranges = [
            0..total as u64,
            pc - 3..pc + 5,      // start > 0, crosses the first boundary
            5..5 + pc,           // exactly one chunk, start > 0
            0..pc,               // exactly one chunk
            0..2 * pc,           // exactly two chunks
            pc + 7..3 * pc / 2,  // inside the second chunk
            pc - 1..pc,          // last record of the first chunk
            2 * pc..2 * pc + 10, // tail after two full chunks
        ];
        for r in ranges {
            let mut next = r.start;
            decode_range::<Tcp4Packet, ()>(&file, r.clone(), |seq, e| {
                assert_eq!(seq, next);
                let want = &expect[seq as usize % src_recs].1;
                assert_eq!((e.time, e.seq), (want.time, want.seq));
                next += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(next, r.end, "range {r:?}");
        }
    }
}
