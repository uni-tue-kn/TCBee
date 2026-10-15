//! Trace record bindings and the table that maps trace files to them.

pub mod bbr;
pub mod ctypes;
pub mod cubic;
pub mod cwnd;
pub mod sock;
pub mod tcp4_packet;
pub mod tcp6_packet;
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

/// How one trace file is decoded and where its rows go.
#[derive(Clone, Copy)]
pub struct Binding {
    pub dir: Dir,
    pub table: &'static EventTable,
    pub entry_size: usize,
    pub decode: DecodeFn,
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

fn binding_of<E: Event>(dir: Dir) -> Binding {
    Binding {
        dir,
        table: E::TABLE,
        entry_size: E::ENTRY_SIZE,
        decode: decode_dyn::<E>,
    }
}

fn on_change_binding_of<E: Event>(table: &'static EventTable, dir: Dir) -> Binding {
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
        TraceFile::Tcp4Send => binding_of::<Tcp4Packet>(Dir::Send),
        TraceFile::Tcp4Receive => binding_of::<Tcp4Packet>(Dir::Recv),
        TraceFile::Tcp6Send => binding_of::<Tcp6Packet>(Dir::Send),
        TraceFile::Tcp6Receive => binding_of::<Tcp6Packet>(Dir::Recv),
        TraceFile::TcpProbe => binding_of::<TcpProbe>(Dir::None),
        TraceFile::Cubic => binding_of::<CubicEvent>(Dir::None),
        TraceFile::Bbr => binding_of::<BbrEvent>(Dir::None),
        TraceFile::SendSockOc => on_change_binding_of::<sock_trace_entry>(&SOCK_OC, Dir::Send),
        TraceFile::RecvSockOc => on_change_binding_of::<sock_trace_entry>(&SOCK_OC, Dir::Recv),
        TraceFile::SendCwndOc => on_change_binding_of::<cwnd_trace_entry>(&CWND_OC, Dir::Send),
        TraceFile::RecvCwndOc => on_change_binding_of::<cwnd_trace_entry>(&CWND_OC, Dir::Recv),
        TraceFile::TcpRetransmitSynack | TraceFile::TcpBadCsum => return None,
    })
}

/// Every event table: sock, tcp_probe, cwnd, cubic, bbr, tcp4, tcp6, sock_oc, cwnd_oc.
pub fn event_tables() -> [&'static EventTable; 9] {
    [
        sock_trace_entry::TABLE,
        TcpProbe::TABLE,
        cwnd_trace_entry::TABLE,
        CubicEvent::TABLE,
        BbrEvent::TABLE,
        Tcp4Packet::TABLE,
        Tcp6Packet::TABLE,
        &SOCK_OC,
        &CWND_OC,
    ]
}

#[cfg(test)]
mod tests;
