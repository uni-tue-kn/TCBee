//! Trace record bindings and the table that maps trace files to them.

pub mod bbr;
pub mod cubic;
pub mod cwnd;
pub mod mptcp_pm;
pub mod sock;
pub mod tcp4_packet;
pub mod tcp6_packet;
pub mod tcp_probe;

use tcbee_common::records::{
    bbr_trace_entry, cubic_trace_entry, cwnd_trace_entry, mptcp_pm_entry, sock_trace_entry,
    tcp4_packet_trace, tcp6_packet_trace, tcp_probe_entry,
};
use tcbee_trace::TraceFile;
use ts_storage::{Dir, EventTable};

use crate::decode::{decode_dyn, DecodeFn};
use crate::event::Event;

/// How one trace file is decoded and where its rows go.
#[derive(Clone, Copy)]
pub struct Binding {
    pub dir: Dir,
    pub table: &'static EventTable,
    pub entry_size: usize,
    pub decode: DecodeFn,
    /// Size of the record's bincode encoding, to check `entry_size` against
    #[cfg(test)]
    pub encoded_size: fn() -> usize,
}

fn binding_of<E: Event + Default + serde::Serialize>(dir: Dir) -> Binding {
    Binding {
        dir,
        table: E::TABLE,
        entry_size: E::ENTRY_SIZE,
        decode: decode_dyn::<E>,
        #[cfg(test)]
        encoded_size: || bincode::serialized_size(&E::default()).unwrap() as usize,
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
        TraceFile::MptcpPm => binding_of::<mptcp_pm_entry>(Dir::None),
        TraceFile::TcpRetransmitSynack | TraceFile::TcpBadCsum => return None,
    })
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
