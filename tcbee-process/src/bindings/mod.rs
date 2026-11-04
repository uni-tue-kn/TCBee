//! Trace record bindings and the table that maps trace files to them.

pub mod bbr;
pub mod cubic;
pub mod cwnd;
pub mod legacy;
pub mod mptcp_pm;
pub mod reno;
pub mod sock;
pub mod tcp4_packet;
pub mod tcp6_packet;
pub mod tcp_event;
pub mod tcp_probe;

use std::{io, path::Path};

use tcbee_common::records::{
    bbr_trace_entry, cubic_trace_entry, cwnd_trace_entry, mptcp_pm_entry, reno_trace_entry,
    sock_trace_entry, tcp4_packet_trace, tcp6_packet_trace, tcp_event_entry, tcp_probe_entry,
    LAYOUT_ID,
};
use tcbee_trace::TraceFile;
use ts_storage::{Dir, EventTable};

use crate::decode::{decode_dyn, DecodeFn};
use crate::event::Event;
use crate::raw::{self, decode_raw_dyn};

/// How one trace file is decoded and where its rows go.
#[derive(Clone, Copy)]
pub struct Binding {
    pub dir: Dir,
    pub table: &'static EventTable,
    pub entry_size: usize,
    pub decode: DecodeFn,
    /// The file is a raw trace (`tcbee_trace::raw`): `entry_size` is the frame stride and
    /// frame 0 is the header, the records start at index 1
    pub raw: bool,
    /// Size of the `#[repr(C)]` record and its decoder for raw traces. Only current layouts
    /// are written raw, so `binding_for` takes these from `binding(file)`.
    record_len: usize,
    raw_decode: DecodeFn,
    /// Columns the records of this file do not have; their rows hold 0 there and their series
    /// are left out of the catalog
    pub missing_columns: &'static [&'static str],
    /// Size of the record's bincode encoding, to check `entry_size` against
    #[cfg(test)]
    pub encoded_size: fn() -> usize,
}

/// On-change files (`*_oc.tcp`) hold the same records as their full counterparts, but as step
/// series: their own sources keep them apart from the full series of a flow.
static SOCK_OC: EventTable = EventTable {
    source: "sock_oc",
    columns: <sock_trace_entry as Event>::TABLE.columns,
};
static CWND_OC: EventTable = EventTable {
    source: "cwnd_oc",
    columns: <cwnd_trace_entry as Event>::TABLE.columns,
};
/// Sock records written after the write timer ran (-k): their own source keeps their hook_seq
/// series apart from the send and receive series of a flow.
static SOCK_TIMER: EventTable = EventTable {
    source: "sock_timer",
    columns: <sock_trace_entry as Event>::TABLE.columns,
};

/// Sock records written after each received segment (-k with --sock-hooks ingress), the
/// state after ACK processing; their own source, like the timer records.
static SOCK_INGRESS: EventTable = EventTable {
    source: "sock_ingress",
    columns: <sock_trace_entry as Event>::TABLE.columns,
};

/// Sock records written at TCP events (-k): state and congestion state changes,
/// retransmissions, cwnd restarts, receive buffer growth. The hook is in bits 8-15 of `ato`,
/// the new state of a state change in bits 16-23.
static SOCK_EVENT: EventTable = EventTable {
    source: "sock_event",
    columns: <sock_trace_entry as Event>::TABLE.columns,
};

/// Header records of the driver hooks (-h with --headers-at driver): their own sources keep
/// them apart from the TC records of the same packets.
static TCP4_DRIVER: EventTable = EventTable {
    source: "tcp4_driver",
    columns: <tcp4_packet_trace as Event>::TABLE.columns,
};
static TCP6_DRIVER: EventTable = EventTable {
    source: "tcp6_driver",
    columns: <tcp6_packet_trace as Event>::TABLE.columns,
};

fn binding_of<E: Event + Default + Copy + serde::Serialize>(dir: Dir) -> Binding {
    Binding {
        dir,
        table: E::TABLE,
        entry_size: E::ENTRY_SIZE,
        decode: decode_dyn::<E>,
        raw: false,
        record_len: std::mem::size_of::<E>(),
        raw_decode: decode_raw_dyn::<E>,
        missing_columns: &[],
        #[cfg(test)]
        encoded_size: || bincode::serialized_size(&E::default()).unwrap() as usize,
    }
}

/// As `binding_of`, into `table` instead of the record's own table
fn binding_into<E: Event + Default + Copy + serde::Serialize>(
    table: &'static EventTable,
    dir: Dir,
) -> Binding {
    Binding {
        table,
        ..binding_of::<E>(dir)
    }
}

/// The binding of a trace file, or `None` for files that are skipped (no binding exists).
/// `dir` comes from the file, not from the record.
pub fn binding(file: TraceFile) -> Option<Binding> {
    Some(match file {
        TraceFile::SendSock => binding_of::<sock_trace_entry>(Dir::Send),
        TraceFile::RecvSock => binding_of::<sock_trace_entry>(Dir::Recv),
        TraceFile::SendCwnd => binding_of::<cwnd_trace_entry>(Dir::Send),
        TraceFile::RecvCwnd => binding_of::<cwnd_trace_entry>(Dir::Recv),
        TraceFile::Tcp4Send => binding_of::<tcp4_packet_trace>(Dir::Send),
        TraceFile::Tcp4Receive => binding_of::<tcp4_packet_trace>(Dir::Recv),
        TraceFile::Tcp6Send => binding_of::<tcp6_packet_trace>(Dir::Send),
        TraceFile::Tcp6Receive => binding_of::<tcp6_packet_trace>(Dir::Recv),
        TraceFile::TcpProbe => binding_of::<tcp_probe_entry>(Dir::None),
        TraceFile::Cubic => binding_of::<cubic_trace_entry>(Dir::None),
        TraceFile::Bbr => binding_of::<bbr_trace_entry>(Dir::None),
        TraceFile::Reno => binding_of::<reno_trace_entry>(Dir::None),
        TraceFile::MptcpPm => binding_of::<mptcp_pm_entry>(Dir::None),
        TraceFile::TcpEvents => binding_of::<tcp_event_entry>(Dir::None),
        TraceFile::SendSockOc => binding_into::<sock_trace_entry>(&SOCK_OC, Dir::Send),
        TraceFile::RecvSockOc => binding_into::<sock_trace_entry>(&SOCK_OC, Dir::Recv),
        TraceFile::SendCwndOc => binding_into::<cwnd_trace_entry>(&CWND_OC, Dir::Send),
        TraceFile::RecvCwndOc => binding_into::<cwnd_trace_entry>(&CWND_OC, Dir::Recv),
        TraceFile::TimerSock => binding_into::<sock_trace_entry>(&SOCK_TIMER, Dir::None),
        TraceFile::IngressSock => binding_into::<sock_trace_entry>(&SOCK_INGRESS, Dir::None),
        TraceFile::EventSock => binding_into::<sock_trace_entry>(&SOCK_EVENT, Dir::None),
        TraceFile::Tcp4DriverReceive => binding_into::<tcp4_packet_trace>(&TCP4_DRIVER, Dir::Recv),
        TraceFile::Tcp6DriverReceive => binding_into::<tcp6_packet_trace>(&TCP6_DRIVER, Dir::Recv),
        TraceFile::Tcp4DriverSend => binding_into::<tcp4_packet_trace>(&TCP4_DRIVER, Dir::Send),
        TraceFile::Tcp6DriverSend => binding_into::<tcp6_packet_trace>(&TCP6_DRIVER, Dir::Send),
        // The owners are no event table, owners.rs reads them
        TraceFile::TcpRetransmitSynack | TraceFile::TcpBadCsum | TraceFile::FlowOwners => {
            return None
        }
        // Not read yet
        TraceFile::SendSockSel | TraceFile::RecvSockSel | TraceFile::TimerSockSel => return None,
    })
}

impl Binding {
    /// Index of the first record in the file
    pub fn first(&self) -> u64 {
        u64::from(self.raw)
    }
}

/// The binding of the trace file at `path`: `binding(file)`, its raw variant for a raw trace,
/// or the binding of an older record layout of the same table (`legacy`) if the file was
/// written in one.
pub fn binding_for(file: TraceFile, path: &Path) -> io::Result<Option<Binding>> {
    let Some(current) = binding(file) else {
        return Ok(None);
    };
    match raw::probe(path)? {
        Some(Ok(header)) if header.layout != LAYOUT_ID => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "raw trace with record layouts {:08x}, this tcbee-process reads {:08x}: use \
                     the tcbee-process of the recorder's version",
                    header.layout, LAYOUT_ID
                ),
            ))
        }
        Some(Ok(header)) if header.record_len as usize == current.record_len => {
            return Ok(Some(Binding {
                entry_size: tcbee_trace::raw::stride(current.record_len),
                decode: current.raw_decode,
                raw: true,
                ..current
            }))
        }
        Some(Ok(header)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "raw trace of {} byte records, the {} records of this version are {} bytes",
                    header.record_len, current.table.source, current.record_len
                ),
            ))
        }
        Some(Err(err)) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
        None => {}
    }
    let old = legacy::layouts(current.table.source);
    if old.is_empty() {
        return Ok(Some(current));
    }
    Ok(Some(match legacy::probe(path, current.entry_size, old)? {
        legacy::Layout::Current => current,
        // the rows stay in the file's own table (sock_oc keeps its step series apart)
        legacy::Layout::Legacy(l) => Binding {
            table: current.table,
            ..(l.binding)(current.dir)
        },
    }))
}

/// Every event table, once, in the order of `TraceFile::all()`.
pub fn event_tables() -> Vec<&'static EventTable> {
    let mut tables: Vec<&'static EventTable> = Vec::new();
    for binding in TraceFile::all().iter().filter_map(|file| binding(*file)) {
        if !tables.iter().any(|t| t.source == binding.table.source) {
            tables.push(binding.table);
        }
    }
    tables
}

#[cfg(test)]
mod tests;
