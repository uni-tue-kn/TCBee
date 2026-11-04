//! Reading trace files of `tcbee-record --writer-format raw` (format in `tcbee_trace::raw`):
//! frames of one stride, the first one the header. A frame's record is the `#[repr(C)]`
//! struct the eBPF program wrote, the same type the bindings decode, so it is read as is.

use std::{fs::File, io, mem, ops::Range, os::unix::fs::FileExt, path::Path};

use tcbee_trace::raw::{self, Frame, Header, HeaderError};

use crate::{
    decode::{read_entries, RangeError, RowError, RowFn},
    event::{DecodeError, Event},
};

/// The header of the raw trace file at `path`, None if it is no raw trace
pub fn probe(path: &Path) -> io::Result<Option<Result<Header, HeaderError>>> {
    let file = File::open(path)?;
    let mut head = [0u8; raw::RINGBUF_HEADER_LEN + raw::HEADER_PAYLOAD_LEN];
    let mut got = 0;
    while got < head.len() {
        match file.read_at(&mut head[got..], got as u64)? {
            0 => break,
            n => got += n,
        }
    }
    Ok(raw::parse_header(&head[..got]))
}

/// The number of frames before the end of the data: the recorder can leave preallocated
/// zeros behind the last frame, and a frame of length 0 starts them. `frames` whole frames
/// of `stride` bytes are in the file.
pub fn data_frames(file: &File, stride: usize, frames: u64) -> io::Result<u64> {
    let ends = |frame: u64| -> io::Result<bool> {
        let mut word = [0u8; 4];
        file.read_exact_at(&mut word, frame * stride as u64)?;
        Ok(u32::from_ne_bytes(word) == 0)
    };
    // The zeros are a suffix: find the first frame that starts them
    let (mut lo, mut hi) = (1, frames);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if ends(mid)? {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(lo.min(frames))
}

/// As `decode::decode_range`, for frames `frames` of a raw file whose records are `E`.
/// Discarded frames are skipped; returns how many.
pub fn decode_raw_range<E: Event + Copy, Err>(
    file: &File,
    frames: Range<u64>,
    mut f: impl FnMut(u64, E) -> Result<(), Err>,
) -> Result<u64, RangeError<Err>> {
    let len = mem::size_of::<E>();
    let mut skipped = 0;
    read_entries(file, frames, raw::stride(len), |index, offset, bytes| {
        let decode = |source| RangeError::Decode { offset, source };
        match raw::frame(bytes, len) {
            Frame::Record(record) => f(index, read_record(record)).map_err(RangeError::Callback),
            Frame::Discarded => {
                skipped += 1;
                Ok(())
            }
            Frame::Busy => Err(decode(DecodeError::Busy)),
            Frame::End => Err(decode(DecodeError::DataEnded)),
            Frame::Length(got) => Err(decode(DecodeError::Size {
                expected: len,
                got: got as usize,
            })),
        }
    })?;
    Ok(skipped)
}

/// A record of a raw trace (`len == size_of::<E>()`, see `tcbee_trace::raw::frame`) as the
/// `#[repr(C)]` struct the recorder wrote
pub fn read_record<E: Copy>(record: &[u8]) -> E {
    assert_eq!(record.len(), mem::size_of::<E>());
    // The records are plain old data, valid for any bit pattern
    unsafe { std::ptr::read_unaligned(record.as_ptr() as *const E) }
}

/// `decode_raw_range::<E>` behind the `DecodeFn` signature
pub fn decode_raw_dyn<E: Event + Copy>(
    file: &File,
    frames: Range<u64>,
    f: &mut RowFn<'_>,
) -> Result<u64, RangeError<RowError>> {
    decode_raw_range::<E, RowError>(file, frames, |index, e| f(index, &e))
}

#[cfg(test)]
pub mod tests {
    use std::fs;

    use tcbee_common::records::tcp4_packet_trace;

    use super::*;

    /// A raw trace of `records` (header frame first), as the recorder writes it
    pub fn raw_bytes<E: Copy>(records: &[E]) -> Vec<u8> {
        let len = mem::size_of::<E>();
        let mut bytes = raw::header_frame(len, tcbee_common::records::LAYOUT_ID);
        for record in records {
            let raw = unsafe { std::slice::from_raw_parts(record as *const E as *const u8, len) };
            bytes.extend_from_slice(&raw::record_frame(raw));
        }
        bytes
    }

    fn temp_file(tag: &str, bytes: &[u8]) -> (File, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("tcbee_raw_{tag}_{}", std::process::id()));
        fs::write(&path, bytes).unwrap();
        (File::open(&path).unwrap(), path)
    }

    fn packet(seq: u32) -> tcp4_packet_trace {
        tcp4_packet_trace {
            seq,
            ..Default::default()
        }
    }

    fn seqs(file: &File, frames: Range<u64>) -> Result<(Vec<u32>, u64), String> {
        let mut seqs = Vec::new();
        decode_raw_range::<tcp4_packet_trace, ()>(file, frames, |_, p| {
            seqs.push(p.seq);
            Ok(())
        })
        .map(|skipped| (seqs, skipped))
        .map_err(|e| format!("{e:?}"))
    }

    #[test]
    fn records_decode_as_written() {
        let records: Vec<_> = (0..1000).map(packet).collect();
        let (file, path) = temp_file("decode", &raw_bytes(&records));
        let header = probe(&path).unwrap().unwrap().unwrap();
        assert_eq!(
            header.record_len as usize,
            mem::size_of::<tcp4_packet_trace>()
        );
        let (got, skipped) = seqs(&file, 1..1001).unwrap();
        assert_eq!(got, (0..1000).collect::<Vec<_>>());
        assert_eq!(skipped, 0);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn discarded_frames_are_skipped_and_busy_ones_are_errors() {
        let stride = raw::stride(mem::size_of::<tcp4_packet_trace>());
        let mut bytes = raw_bytes(&[packet(1), packet(2), packet(3)]);
        let word = |bytes: &mut Vec<u8>, frame: usize, flag: u32| {
            let at = frame * stride;
            let len = u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap());
            bytes[at..at + 4].copy_from_slice(&(len | flag).to_ne_bytes());
        };
        word(&mut bytes, 2, raw::DISCARD_BIT);
        let (file, path) = temp_file("discard", &bytes);
        assert_eq!(seqs(&file, 1..4).unwrap(), (vec![1, 3], 1));
        fs::remove_file(path).unwrap();

        word(&mut bytes, 3, raw::BUSY_BIT);
        let (file, path) = temp_file("busy", &bytes);
        assert!(seqs(&file, 1..4).unwrap_err().contains("Busy"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn zero_tail_ends_the_data() {
        let stride = raw::stride(mem::size_of::<tcp4_packet_trace>());
        for (records, zeros) in [(0, 0), (0, 5), (7, 0), (7, 1), (7, 100)] {
            let list: Vec<_> = (0..records).map(packet).collect();
            let mut bytes = raw_bytes(&list);
            bytes.resize(bytes.len() + zeros * stride, 0);
            let (file, path) = temp_file("zeros", &bytes);
            let frames = (bytes.len() / stride) as u64;
            assert_eq!(
                data_frames(&file, stride, frames).unwrap(),
                1 + records as u64,
                "{records} records, {zeros} zero frames"
            );
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn binding_for_reads_raw_traces() {
        use tcbee_trace::TraceFile;

        use crate::bindings::binding_for;

        let records: Vec<_> = (10..20).map(packet).collect();
        let (_file, path) = temp_file("binding", &raw_bytes(&records));
        let binding = binding_for(TraceFile::Tcp4Send, &path, None)
            .unwrap()
            .unwrap();
        assert!(binding.raw);
        assert_eq!(binding.first(), 1);
        assert_eq!(
            binding.entry_size,
            raw::stride(mem::size_of::<tcp4_packet_trace>())
        );
        let file = File::open(&path).unwrap();
        let mut seen = Vec::new();
        let skipped = (binding.decode)(&file, 1..11, &mut |index, row| {
            seen.push((index, row.hook_seq()));
            Ok(())
        })
        .unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(seen.len(), 10);
        assert_eq!(seen[0].0, 1);

        // A raw file of another record type is an error, not garbage
        let err = binding_for(TraceFile::SendSock, &path, None).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_file(path).unwrap();

        // So is one written with other record layouts
        let mut other = raw_bytes(&records);
        other[raw::RINGBUF_HEADER_LEN + 20..raw::RINGBUF_HEADER_LEN + 24]
            .copy_from_slice(&(tcbee_common::records::LAYOUT_ID ^ 1).to_ne_bytes());
        let (_file, path) = temp_file("layout", &other);
        let err = binding_for(TraceFile::Tcp4Send, &path, None).err().unwrap();
        assert!(err.to_string().contains("record layouts"), "{err}");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn owners_of_raw_traces() {
        use tcbee_common::records::flow_owner_entry;

        let owners: Vec<_> = (0..3)
            .map(|pid| flow_owner_entry {
                pid,
                ..Default::default()
            })
            .collect();
        let mut warnings = Vec::new();
        let owned =
            crate::owners::decode_records(&raw_bytes(&owners), None, &mut warnings).unwrap();
        assert_eq!(owned.len(), 3);
        assert!(warnings.is_empty());
    }

    #[test]
    fn other_files_are_no_raw_traces() {
        let (_file, path) = temp_file("other", &[0xff; 200]);
        assert!(probe(&path).unwrap().is_none());
        fs::remove_file(path).unwrap();
        let (_file, path) = temp_file("empty", &[]);
        assert!(probe(&path).unwrap().is_none());
        fs::remove_file(path).unwrap();
    }
}
