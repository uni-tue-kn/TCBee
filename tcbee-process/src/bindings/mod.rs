//! Trace record bindings and the table that maps trace files to them.

pub mod bbr;
pub mod ctypes;
pub mod cubic;
pub mod cwnd;
pub mod event_indexer;
pub mod sock;
pub mod tcp4_packet;
pub mod tcp6_packet;
pub mod tcp_packet;
pub mod tcp_probe;

use tcbee_trace::TraceFile;
use ts_storage::{Dir, EventTable};

use crate::decode::{decode_dyn, DecodeFn};
use crate::event::Event;

use bbr::BbrEvent;
use cubic::CubicEvent;
use cwnd::cwnd_trace_entry;
use sock::sock_trace_entry;
use tcp4_packet::Tcp4Packet;
use tcp6_packet::Tcp6Packet;
use tcp_probe::TcpProbe;

// WP6: remove the dead_code allows on the items below.
/// How one trace file is decoded and where its rows go.
#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct Binding {
    pub dir: Dir,
    pub table: &'static EventTable,
    pub entry_size: usize,
    pub decode: DecodeFn,
}

#[cfg_attr(not(test), allow(dead_code))]
fn binding_of<E: Event>(dir: Dir) -> Binding {
    Binding {
        dir,
        table: E::TABLE,
        entry_size: E::ENTRY_SIZE,
        decode: decode_dyn::<E>,
    }
}

/// The binding of a trace file, or `None` for files that are skipped (no binding exists).
/// `dir` comes from the file, not from the record (PROCESS-REWRITE.md A2).
#[cfg_attr(not(test), allow(dead_code))]
pub fn binding(file: TraceFile) -> Option<Binding> {
    Some(match file {
        TraceFile::SendSock => binding_of::<sock_trace_entry>(Dir::Send),
        TraceFile::RecvSock => binding_of::<sock_trace_entry>(Dir::Recv),
        TraceFile::SendCwnd => binding_of::<cwnd_trace_entry>(Dir::Send),
        TraceFile::RecvCwnd => binding_of::<cwnd_trace_entry>(Dir::Recv),
        TraceFile::Tcp4Send => binding_of::<Tcp4Packet>(Dir::Send),
        TraceFile::Tcp4Receive => binding_of::<Tcp4Packet>(Dir::Recv),
        TraceFile::Tcp6Send => binding_of::<Tcp6Packet>(Dir::Send),
        TraceFile::Tcp6Receive => binding_of::<Tcp6Packet>(Dir::Recv),
        TraceFile::TcpProbe => binding_of::<TcpProbe>(Dir::None),
        TraceFile::Cubic => binding_of::<CubicEvent>(Dir::None),
        TraceFile::Bbr => binding_of::<BbrEvent>(Dir::None),
        TraceFile::TcpRetransmitSynack | TraceFile::TcpBadCsum => return None,
    })
}

/// Every event table, in the order of the sources of PROCESS-REWRITE.md A2.
#[cfg_attr(not(test), allow(dead_code))]
pub fn event_tables() -> [&'static EventTable; 7] {
    [
        sock_trace_entry::TABLE,
        TcpProbe::TABLE,
        cwnd_trace_entry::TABLE,
        CubicEvent::TABLE,
        BbrEvent::TABLE,
        Tcp4Packet::TABLE,
        Tcp6Packet::TABLE,
    ]
}

#[cfg(test)]
mod tests;
