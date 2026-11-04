//! Field-selected sock records (`tcbee-record --sock-fields`, `tcbee_trace::sockfields`):
//! the files `*_sock_sel.tcp` hold only some groups of the sock record's fields, as the
//! manifest says. Each record is expanded into a full `sock_trace_entry` whose other fields
//! are 0, and those fields' series are left out (`Binding::missing_columns`).

use std::{fs::File, io, ops::Range};

use tcbee_common::records::{sock_trace_entry, LAYOUT_ID, RECORD_DELIMITER};
use tcbee_trace::{
    onchange::Manifest,
    raw::{self, Header},
    sockfields::{self, SockShape},
    TraceFile,
};
use ts_storage::{Dir, EventTable};

use super::{binding_into, Binding, SOCK_TIMER};
use crate::{
    decode::{read_entries, RangeError, RowError, RowFn},
    event::{DecodeError, Event},
    raw::read_raw_records,
};

/// The layout of one field-selected file, kept for as long as the process runs
pub struct SockSel {
    shape: SockShape,
    /// Copy runs from a packed record into a packed full record
    expansion: Vec<(usize, usize, usize)>,
    /// Byte runs of a ring record (raw traces) that make up its packed record
    runs: Vec<(usize, usize)>,
}

/// The binding of the field-selected file `file` at `path` with the layout `manifest` gives
/// it; an error without one
pub fn binding_for(
    file: TraceFile,
    manifest: Option<&Manifest>,
    raw_header: Option<Header>,
) -> io::Result<Binding> {
    let invalid = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
    let name = file.filename();
    let meta = manifest
        .and_then(|m| m.source(name))
        .and_then(|s| s.sock_fields.as_ref())
        .ok_or_else(|| {
            invalid(format!(
                "{name} holds field-selected sock records, but the manifest.json of the \
                 recording does not say which fields"
            ))
        })?;
    let shape = meta.shape()?;
    let (table, dir): (&'static EventTable, Dir) = match file {
        TraceFile::SendSockSel => (<sock_trace_entry as Event>::TABLE, Dir::Send),
        TraceFile::RecvSockSel => (<sock_trace_entry as Event>::TABLE, Dir::Recv),
        TraceFile::TimerSockSel => (&SOCK_TIMER, Dir::None),
        other => panic!("{} is no field-selected file", other.filename()),
    };
    let raw = match raw_header {
        Some(header) => {
            let layout = raw::sock_fields_layout_id(LAYOUT_ID, shape.fields.mask());
            if header.layout != layout || header.record_len as usize != shape.ring_len {
                return Err(invalid(format!(
                    "{name}: raw trace of {} byte records in layout {:08x}, the manifest says {} \
                     bytes in layout {:08x}",
                    header.record_len, header.layout, shape.ring_len, layout
                )));
            }
            true
        }
        None => false,
    };
    let missing: Vec<&'static str> = shape.missing();
    let sel: &'static SockSel = Box::leak(Box::new(SockSel {
        expansion: shape.expansion(),
        runs: shape.runs(),
        shape,
    }));
    Ok(Binding {
        entry_size: if raw {
            raw::stride(sel.shape.ring_len)
        } else {
            sel.shape.file_len + RECORD_DELIMITER.len()
        },
        raw,
        missing_columns: Box::leak(missing.into_boxed_slice()),
        sock_sel: Some(sel),
        ..binding_into::<sock_trace_entry>(table, dir)
    })
}

/// Decodes records `records` (frames of a raw trace) of a field-selected file, as `DecodeFn`
pub fn decode(
    sel: &SockSel,
    raw: bool,
    file: &File,
    records: Range<u64>,
    f: &mut RowFn<'_>,
) -> Result<u64, RangeError<RowError>> {
    let full_len = sockfields::full_bytes();
    let mut full = vec![0u8; full_len + RECORD_DELIMITER.len()];
    full[full_len..].copy_from_slice(&RECORD_DELIMITER);
    let mut packed = vec![0u8; sel.shape.file_len];
    let mut emit = |index: u64, offset: u64, packed: &[u8]| {
        sel.shape
            .expand(&sel.expansion, packed, &mut full[..full_len]);
        let event = sock_trace_entry::decode(&full)
            .map_err(|source| RangeError::Decode { offset, source })?;
        f(index, &event).map_err(RangeError::Callback)
    };
    if !raw {
        let size = sel.shape.file_len + RECORD_DELIMITER.len();
        read_entries(file, records, size, |index, offset, entry| {
            let (record, divider) = entry.split_at(sel.shape.file_len);
            if divider != RECORD_DELIMITER {
                return Err(RangeError::Decode {
                    offset,
                    source: DecodeError::Divider,
                });
            }
            emit(index, offset, record)
        })?;
        return Ok(0);
    }
    read_raw_records(
        file,
        records,
        sel.shape.ring_len,
        |index, offset, record| {
            let mut at = 0;
            for &(off, run) in &sel.runs {
                packed[at..at + run].copy_from_slice(&record[off..off + run]);
                at += run;
            }
            emit(index, offset, &packed)
        },
    )
}
