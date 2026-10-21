//! Record layouts of older recordings, so that every trace file ever written still decodes.
//!
//! Each old layout is frozen in a struct that converts to the current record; the columns it
//! does not have hold 0 and their series are left out of the catalog (`missing_columns`). A
//! file's layout is told by where the dividers of its first records sit (`probe`).
//!
//! | table | size | written by | missing |
//! |---|---|---|---|
//! | sock | 168 | the per-CPU and on-change lines (no `conn_id`) | `sock::ADDED_COLUMNS` |
//! | sock | 172 | dev with MPTCP (`OldSockEntry`) | `sock::ADDED_COLUMNS` |
//! | sock | 201 | on-change with the TCP_INFO fields, build 4d3cffb7 (no `conn_id`) | delivery rate and chrono |
//! | sock | 202 | dev with run metadata (before the rest of TCP_INFO) | the rest of TCP_INFO |
//! | cwnd | 70 | the per-CPU and on-change lines (no `conn_id`) | – |
//!
//! Layouts without `conn_id` belong to no MPTCP connection (`connection_key` 0).

use std::{fs::File, io, os::unix::fs::FileExt, path::Path};

use serde::{Deserialize, Serialize};
use tcbee_common::records::{cwnd_trace_entry, sock_trace_entry, RECORD_DELIMITER};
use ts_storage::{Dir, EventBatch, EventTable, IpTuple};

use super::{binding_of, sock, Binding};
use crate::event::{decode_record, DecodeError, Event};

/// An older layout of a table's records
pub struct Legacy {
    pub entry_size: usize,
    pub binding: fn(Dir) -> Binding,
}

/// The older layouts of the table with this source name (the on-change files hold the same
/// records as their full counterparts)
pub fn layouts(source: &str) -> &'static [Legacy] {
    match source {
        "sock" | "sock_oc" => &SOCK,
        "cwnd" | "cwnd_oc" => &CWND,
        _ => &[],
    }
}

static SOCK: [Legacy; 4] = [
    Legacy {
        entry_size: 172,
        binding: sock172,
    },
    Legacy {
        entry_size: 168,
        binding: sock168,
    },
    Legacy {
        entry_size: 201,
        binding: sock201,
    },
    Legacy {
        entry_size: 202,
        binding: sock202,
    },
];
static CWND: [Legacy; 1] = [Legacy {
    entry_size: 70,
    binding: cwnd70,
}];

fn sock172(dir: Dir) -> Binding {
    Binding {
        missing_columns: sock::ADDED_COLUMNS,
        ..binding_of::<sock::OldSockEntry>(dir)
    }
}

fn sock168(dir: Dir) -> Binding {
    Binding {
        missing_columns: sock::ADDED_COLUMNS,
        ..binding_of::<Sock168Entry>(dir)
    }
}

/// Columns of the current sock record that the 201 B layout does not have
pub const SOCK201_MISSING: &[&str] = &[
    "delivered_ce",
    "app_limited",
    "chrono_type",
    "chrono_busy",
    "chrono_rwnd_limited",
    "chrono_sndbuf_limited",
];

fn sock201(dir: Dir) -> Binding {
    Binding {
        missing_columns: SOCK201_MISSING,
        ..binding_of::<Sock201Entry>(dir)
    }
}

/// Columns of the current sock record that the 202 B layout does not have
pub const SOCK202_MISSING: &[&str] = &["srtt", "mdev", "min_rtt", "snd_una", "snd_nxt", "lost_out"];

fn sock202(dir: Dir) -> Binding {
    Binding {
        missing_columns: SOCK202_MISSING,
        ..binding_of::<Sock202Entry>(dir)
    }
}

fn cwnd70(dir: Dir) -> Binding {
    binding_of::<Cwnd70Entry>(dir)
}

/// Which layout a file is in
#[derive(Clone, Copy)]
pub enum Layout {
    Current,
    Legacy(&'static Legacy),
}

/// Records whose dividers are looked at to tell the layouts apart
const PROBE_RECORDS: usize = 8;
/// Records looked at when the first `PROBE_RECORDS` fit several layouts
const PROBE_RECORDS_DEEP: usize = 4096;

/// The layout of the trace file at `path`: the one size, among the current and the legacy
/// ones, at which the dividers of the first complete records all sit. A file without a complete
/// record in any layout (an empty file of an unused probe group) gets the current layout; a
/// partial last record (a writer that was killed) is ignored. If the first records fit several
/// sizes, up to `PROBE_RECORDS_DEEP` records decide, then the size that the file's length is a
/// multiple of; a file that still fits several is an error, never a guess. The deeper look
/// can rule out every size when a killed writer left its preallocated zeros within those
/// records; the length then decides among the sizes that fit the first records.
pub fn probe(path: &Path, current: usize, legacy: &'static [Legacy]) -> io::Result<Layout> {
    let layouts: Vec<(usize, Layout)> = std::iter::once((current, Layout::Current))
        .chain(legacy.iter().map(|l| (l.entry_size, Layout::Legacy(l))))
        .collect();
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut fits = fitting(&file, layouts, PROBE_RECORDS)?;
    let fit_first_records = fits.len();
    if fits.len() > 1 {
        let deep = fitting(&file, fits.clone(), PROBE_RECORDS_DEEP)?;
        if !deep.is_empty() {
            fits = deep;
        }
    }
    if fits.len() > 1 {
        fits.retain(|(size, _)| len % *size as u64 == 0);
    }
    match (fit_first_records, fits.len()) {
        (0, _) => Ok(Layout::Current),
        (_, 1) => Ok(fits.pop().unwrap().1),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: the records fit several record layouts", path.display()),
        )),
    }
}

/// The `layouts` at whose size the dividers of the first (up to) `records` complete records
/// of `file` all sit
fn fitting(
    file: &File,
    layouts: Vec<(usize, Layout)>,
    records: usize,
) -> io::Result<Vec<(usize, Layout)>> {
    let max = layouts.iter().map(|(size, _)| *size).max().unwrap_or(0);
    let mut head = vec![0u8; records * max];
    let mut got = 0;
    while got < head.len() {
        match file.read_at(&mut head[got..], got as u64)? {
            0 => break,
            n => got += n,
        }
    }
    let dividers_at = |size: usize| {
        let complete = (got / size).min(records);
        complete > 0
            && (0..complete).all(|i| {
                head[(i + 1) * size - RECORD_DELIMITER.len()..(i + 1) * size] == RECORD_DELIMITER
            })
    };
    Ok(layouts
        .into_iter()
        .filter(|(size, _)| dividers_at(*size))
        .collect())
}

/// The fields every sock layout starts with, up to `rcv_wscale` (164 bytes encoded)
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SockPrefix {
    pub time: u64,
    pub hook_seq: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16],
    pub dst_v6: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    pub backoff: u8,
    pub rto: u32,
    pub ato: u32,
    pub rcv_mss: u16,
    pub snd_cwnd: u32,
    pub bytes_acked: u64,
    pub snd_ssthresh: u32,
    pub total_retrans: u32,
    pub probes: u8,
    pub lost: u32,
    pub sacked_out: u32,
    pub retrans: u32,
    pub rcv_ssthresh: u32,
    pub rttvar: u32,
    pub advmss: u16,
    pub reordering: u32,
    pub rcv_rtt: u32,
    pub rcv_space: u32,
    pub bytes_received: u64,
    pub segs_out: u32,
    pub segs_in: u32,
    pub snd_wscale: u16,
    pub rcv_wscale: u16,
}

impl SockPrefix {
    fn current(&self) -> sock_trace_entry {
        sock_trace_entry {
            time: self.time,
            hook_seq: self.hook_seq,
            addr_v4: self.addr_v4,
            src_v6: self.src_v6,
            dst_v6: self.dst_v6,
            sport: self.sport,
            dport: self.dport,
            family: self.family,
            pacing_rate: self.pacing_rate,
            max_pacing_rate: self.max_pacing_rate,
            backoff: self.backoff,
            rto: self.rto,
            ato: self.ato,
            rcv_mss: self.rcv_mss,
            snd_cwnd: self.snd_cwnd,
            bytes_acked: self.bytes_acked,
            snd_ssthresh: self.snd_ssthresh,
            total_retrans: self.total_retrans,
            probes: self.probes,
            lost: self.lost,
            sacked_out: self.sacked_out,
            retrans: self.retrans,
            rcv_ssthresh: self.rcv_ssthresh,
            rttvar: self.rttvar,
            advmss: self.advmss,
            reordering: self.reordering,
            rcv_rtt: self.rcv_rtt,
            rcv_space: self.rcv_space,
            bytes_received: self.bytes_received,
            segs_out: self.segs_out,
            segs_in: self.segs_in,
            snd_wscale: self.snd_wscale,
            rcv_wscale: self.rcv_wscale,
            ..Default::default()
        }
    }
}

/// The sock record of the per-CPU and on-change lines: the prefix, no `conn_id`
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Sock168Entry {
    pub p: SockPrefix,
}

impl Sock168Entry {
    fn current(&self) -> sock_trace_entry {
        self.p.current()
    }
}

/// The sock record of the on-change line with the rest of TCP_INFO (build 4d3cffb7), no
/// `conn_id`
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Sock201Entry {
    pub p: SockPrefix,
    pub srtt: u32,
    pub mdev: u32,
    pub min_rtt: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub packets_out: u32,
    pub lost_out: u32,
    pub delivered: u32,
    pub ca_state: u8,
}

impl Sock201Entry {
    fn current(&self) -> sock_trace_entry {
        sock_trace_entry {
            srtt: self.srtt,
            mdev: self.mdev,
            min_rtt: self.min_rtt,
            snd_una: self.snd_una,
            snd_nxt: self.snd_nxt,
            packets_out: self.packets_out,
            lost_out: self.lost_out,
            delivered: self.delivered,
            ca_state: self.ca_state,
            ..self.p.current()
        }
    }
}

/// The sock record of dev with run metadata: the prefix, the congestion state, delivery and
/// chrono fields, `conn_id`
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Sock202Entry {
    pub p: SockPrefix,
    pub ca_state: u8,
    pub packets_out: u32,
    pub delivered: u32,
    pub delivered_ce: u32,
    pub app_limited: u32,
    pub chrono_type: u8,
    pub chrono_busy: u32,
    pub chrono_rwnd_limited: u32,
    pub chrono_sndbuf_limited: u32,
    pub conn_id: u32,
}

impl Sock202Entry {
    fn current(&self) -> sock_trace_entry {
        sock_trace_entry {
            ca_state: self.ca_state,
            packets_out: self.packets_out,
            delivered: self.delivered,
            delivered_ce: self.delivered_ce,
            app_limited: self.app_limited,
            chrono_type: self.chrono_type,
            chrono_busy: self.chrono_busy,
            chrono_rwnd_limited: self.chrono_rwnd_limited,
            chrono_sndbuf_limited: self.chrono_sndbuf_limited,
            conn_id: self.conn_id,
            ..self.p.current()
        }
    }
}

/// The cwnd record without `conn_id`
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Cwnd70Entry {
    pub time: u64,
    pub hook_seq: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16],
    pub dst_v6: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub snd_cwnd: u32,
}

impl Cwnd70Entry {
    fn current(&self) -> cwnd_trace_entry {
        cwnd_trace_entry {
            time: self.time,
            hook_seq: self.hook_seq,
            addr_v4: self.addr_v4,
            src_v6: self.src_v6,
            dst_v6: self.dst_v6,
            sport: self.sport,
            dport: self.dport,
            family: self.family,
            snd_cwnd: self.snd_cwnd,
            ..Default::default()
        }
    }
}

/// An `Event` for a legacy layout that converts every record to the current one
macro_rules! legacy_event {
    ($ty:ty, $current:ty, $size:expr) => {
        impl Event for $ty {
            const TABLE: &'static EventTable = <$current>::TABLE;
            const ENTRY_SIZE: usize = $size;

            fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
                decode_record(buf, Self::ENTRY_SIZE)
            }
            fn flow_key(&self) -> IpTuple {
                Event::flow_key(&self.current())
            }
            fn ts_ns(&self) -> i64 {
                Event::ts_ns(&self.current())
            }
            fn connection_key(&self) -> u32 {
                Event::connection_key(&self.current())
            }
            fn socket_level(&self) -> bool {
                Event::socket_level(&self.current())
            }
            fn hook_seq(&self) -> i64 {
                Event::hook_seq(&self.current())
            }
            fn push_row(&self, batch: &mut EventBatch) {
                Event::push_row(&self.current(), batch)
            }
        }
    };
}

legacy_event!(Sock168Entry, sock_trace_entry, 168);
legacy_event!(Sock201Entry, sock_trace_entry, 201);
legacy_event!(Sock202Entry, sock_trace_entry, 202);
legacy_event!(Cwnd70Entry, cwnd_trace_entry, 70);
