//! The raw trace format of `--writer-format raw`: the bytes of the BPF ring buffers as the
//! kernel holds them, copied in spans instead of record by record.
//!
//! A raw file is a sequence of frames of one fixed length, the stride. A frame is the
//! kernel's 8-byte ring buffer header followed by the record as the eBPF program reserved
//! it: the `#[repr(C)]` struct with its padding, then zeros up to the next 8 bytes. All
//! values are in the byte order of the recording host.
//!
//! The first frame describes the file. Its ring buffer header has the discard bit set, so
//! anything that walks the frames like the kernel does skips it. Its payload holds the magic
//! `TCBEERAW`, the format version, the codec, the record length and a byte order marker.
//! Everything after the last frame that the recorder wrote can be zeros (preallocated
//! space); a frame of length 0 ends the data.

/// Length of the kernel's ring buffer header in front of every record
pub const RINGBUF_HEADER_LEN: usize = 8;
/// The record is still being written (BPF_RINGBUF_BUSY_BIT)
pub const BUSY_BIT: u32 = 1 << 31;
/// The record was discarded (BPF_RINGBUF_DISCARD_BIT)
pub const DISCARD_BIT: u32 = 1 << 30;

/// Marks the first frame of a raw file
pub const MAGIC: [u8; 8] = *b"TCBEERAW";
/// Format version of the header frame
pub const VERSION: u16 = 1;
/// Codec: every ring buffer record is one record of the file's type
pub const CODEC_ONE_RECORD: u16 = 1;
/// Reads as this value only in the byte order of the recording host
pub const BYTE_ORDER_MARKER: u32 = 0x0102_0304;
/// Bytes of the header frame's payload: magic, version, codec, record length, marker
pub const HEADER_PAYLOAD_LEN: usize = 20;

/// Bytes of one frame for records of `record_len` bytes: header, record, padding to 8
pub const fn stride(record_len: usize) -> usize {
    (RINGBUF_HEADER_LEN + record_len + 7) & !7
}

/// What the header frame of a raw file says
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub codec: u16,
    pub record_len: u32,
}

/// Why a file that starts like a raw file cannot be read
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// Recorded on a host with the other byte order
    ByteOrder,
    Version(u16),
    Codec(u16),
    /// The header frame's length does not match the record length it states
    Length {
        frame: u32,
        record: u32,
    },
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::ByteOrder => write!(f, "raw trace from a host with another byte order"),
            HeaderError::Version(v) => write!(f, "unknown raw trace version {}", v),
            HeaderError::Codec(c) => write!(f, "unknown raw trace codec {}", c),
            HeaderError::Length { frame, record } => write!(
                f,
                "raw trace header frame of {} bytes for records of {} bytes",
                frame, record
            ),
        }
    }
}

impl std::error::Error for HeaderError {}

/// The header frame for records of `record_len` bytes, one stride long
pub fn header_frame(record_len: usize) -> Vec<u8> {
    assert!(
        record_len >= HEADER_PAYLOAD_LEN,
        "records of {} bytes cannot hold the raw header",
        record_len
    );
    let record_len = u32::try_from(record_len).expect("record length fits the ring buffer header");
    let mut frame = vec![0; stride(record_len as usize)];
    frame[..4].copy_from_slice(&(record_len | DISCARD_BIT).to_ne_bytes());
    let payload = &mut frame[RINGBUF_HEADER_LEN..];
    payload[..8].copy_from_slice(&MAGIC);
    payload[8..10].copy_from_slice(&VERSION.to_ne_bytes());
    payload[10..12].copy_from_slice(&CODEC_ONE_RECORD.to_ne_bytes());
    payload[12..16].copy_from_slice(&record_len.to_ne_bytes());
    payload[16..20].copy_from_slice(&BYTE_ORDER_MARKER.to_ne_bytes());
    frame
}

/// Reads the header frame at the start of `file`. None if the file is not a raw trace.
pub fn parse_header(file: &[u8]) -> Option<Result<Header, HeaderError>> {
    let payload = file.get(RINGBUF_HEADER_LEN..RINGBUF_HEADER_LEN + HEADER_PAYLOAD_LEN)?;
    if payload[..8] != MAGIC {
        return None;
    }
    let u16_at = |i: usize| u16::from_ne_bytes([payload[i], payload[i + 1]]);
    let u32_at = |i: usize| u32::from_ne_bytes(payload[i..i + 4].try_into().unwrap());
    if u32_at(16) != BYTE_ORDER_MARKER {
        return Some(Err(HeaderError::ByteOrder));
    }
    let header = Header {
        version: u16_at(8),
        codec: u16_at(10),
        record_len: u32_at(12),
    };
    let frame_len = u32::from_ne_bytes(file[..4].try_into().unwrap()) & !(BUSY_BIT | DISCARD_BIT);
    Some(if header.version != VERSION {
        Err(HeaderError::Version(header.version))
    } else if header.codec != CODEC_ONE_RECORD {
        Err(HeaderError::Codec(header.codec))
    } else if frame_len != header.record_len {
        Err(HeaderError::Length {
            frame: frame_len,
            record: header.record_len,
        })
    } else {
        Ok(header)
    })
}

/// One frame of a raw file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A committed record, `record_len` bytes
    Record(&'a [u8]),
    /// A record the program discarded (or the header frame)
    Discarded,
    /// Length 0: the end of the data, the rest of the file is unused
    End,
    /// The recorder copied a record that was not committed yet: a recorder bug
    Busy,
    /// The frame's length is not the file's record length
    Length(u32),
}

/// Decodes the frame that starts `bytes` (at least one stride long) of a file whose records
/// are `record_len` bytes
pub fn frame(bytes: &[u8], record_len: usize) -> Frame<'_> {
    let word = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
    let len = word & !(BUSY_BIT | DISCARD_BIT);
    if word & BUSY_BIT != 0 {
        Frame::Busy
    } else if word == 0 {
        Frame::End
    } else if len as usize != record_len {
        Frame::Length(len)
    } else if word & DISCARD_BIT != 0 {
        Frame::Discarded
    } else {
        Frame::Record(&bytes[RINGBUF_HEADER_LEN..RINGBUF_HEADER_LEN + record_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stride_rounds_to_eight() {
        assert_eq!(stride(24), 32);
        assert_eq!(stride(48), 56);
        assert_eq!(stride(280), 288);
        assert_eq!(stride(136), 144);
    }

    #[test]
    fn header_round_trip() {
        let frame = header_frame(280);
        assert_eq!(frame.len(), 288);
        assert_eq!(
            parse_header(&frame),
            Some(Ok(Header {
                version: VERSION,
                codec: CODEC_ONE_RECORD,
                record_len: 280
            }))
        );
        // A frame walker skips it like a discarded record
        assert_eq!(super::frame(&frame, 280), Frame::Discarded);
    }

    #[test]
    fn other_files_are_not_raw() {
        assert_eq!(parse_header(&[0xff; 64]), None);
        assert_eq!(parse_header(&[]), None);
        assert_eq!(parse_header(b"short"), None);
    }

    #[test]
    fn bad_headers_are_rejected() {
        let swap_u32 = |frame: &mut Vec<u8>, at: usize| frame[at..at + 4].reverse();
        let mut foreign = header_frame(48);
        swap_u32(&mut foreign, RINGBUF_HEADER_LEN + 16);
        assert_eq!(parse_header(&foreign), Some(Err(HeaderError::ByteOrder)));

        let mut version = header_frame(48);
        version[RINGBUF_HEADER_LEN + 8..RINGBUF_HEADER_LEN + 10]
            .copy_from_slice(&9u16.to_ne_bytes());
        assert_eq!(parse_header(&version), Some(Err(HeaderError::Version(9))));

        let mut codec = header_frame(48);
        codec[RINGBUF_HEADER_LEN + 10..RINGBUF_HEADER_LEN + 12]
            .copy_from_slice(&2u16.to_ne_bytes());
        assert_eq!(parse_header(&codec), Some(Err(HeaderError::Codec(2))));

        let mut length = header_frame(48);
        length[..4].copy_from_slice(&(56 | DISCARD_BIT).to_ne_bytes());
        assert_eq!(
            parse_header(&length),
            Some(Err(HeaderError::Length {
                frame: 56,
                record: 48
            }))
        );
    }

    #[test]
    fn frames_decode_by_their_header() {
        let mut bytes = vec![0u8; stride(24)];
        bytes[..4].copy_from_slice(&24u32.to_ne_bytes());
        bytes[8..32].fill(7);
        assert_eq!(frame(&bytes, 24), Frame::Record(&[7; 24]));

        bytes[..4].copy_from_slice(&(24 | DISCARD_BIT).to_ne_bytes());
        assert_eq!(frame(&bytes, 24), Frame::Discarded);
        bytes[..4].copy_from_slice(&(24 | BUSY_BIT).to_ne_bytes());
        assert_eq!(frame(&bytes, 24), Frame::Busy);
        bytes[..4].copy_from_slice(&16u32.to_ne_bytes());
        assert_eq!(frame(&bytes, 24), Frame::Length(16));
        bytes[..4].copy_from_slice(&0u32.to_ne_bytes());
        assert_eq!(frame(&bytes, 24), Frame::End);
    }

    #[test]
    #[should_panic]
    fn records_too_short_for_the_header() {
        header_frame(16);
    }
}
