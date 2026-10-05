use std::{
    fs::File,
    io::{self, BufWriter, Write},
    mem,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};

use aya::{maps::Map, Ebpf};
use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_prog_info};
use serde::Serialize;
use tcbee_common::stats::{
    slot, RB_CWND_RECV, RB_CWND_SEND, RB_SOCK_RECV, RB_SOCK_SEND, RB_TCP4_EGRESS,
    RB_TCP4_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS, RINGBUFS, SLOT_TCP_BYTES_RECEIVED,
    SLOT_TCP_BYTES_SENT, STAT_ATTEMPTED, STAT_DROPPED, STAT_ERROR, STAT_HANDLED,
};

use crate::{stats::Snapshot, writer::WriterReport};

/// Kernel statistics of one loaded eBPF program
#[derive(Serialize, Clone)]
pub struct ProgramStats {
    pub name: String,
    /// Invocations skipped by the kernel because the program was already running on
    /// the CPU (fentry, tracepoint). These events are not counted in STATS.
    pub recursion_misses: u64,
    /// Only counted while kernel.bpf_stats_enabled=1
    pub run_cnt: u64,
    pub run_time_ns: u64,
}

#[derive(Serialize)]
pub struct RingBufMetrics {
    pub name: &'static str,
    pub file: Option<String>,
    pub size_bytes: Option<u32>,
    pub attempted: u64,
    pub handled: u64,
    pub dropped: u64,
    pub error: u64,
    /// None if no writer was registered for this ring buffer
    pub records_written: Option<u64>,
    pub writer_error: Option<String>,
}

#[derive(Serialize)]
pub struct Metrics {
    pub duration_s: f64,
    pub attempted: u64,
    pub handled: u64,
    pub dropped: u64,
    pub error: u64,
    pub records_written: u64,
    pub ingress: u64,
    pub egress: u64,
    pub ingress_calls: u64,
    pub egress_calls: u64,
    pub tcp_bytes_sent: u64,
    pub tcp_bytes_received: u64,
    pub ringbufs: Vec<RingBufMetrics>,
    pub programs: Vec<ProgramStats>,
}

impl Metrics {
    pub fn new(
        duration_s: f64,
        snapshot: &Snapshot,
        reports: &[WriterReport],
        ringbuf_sizes: &[Option<u32>],
        programs: Vec<ProgramStats>,
    ) -> Metrics {
        let attempts = |rbs: &[u32]| {
            rbs.iter()
                .map(|rb| snapshot.get(slot(*rb, STAT_ATTEMPTED)))
                .sum()
        };

        let ringbufs: Vec<RingBufMetrics> = RINGBUFS
            .iter()
            .enumerate()
            .map(|(rb, (name, _))| {
                let rb = rb as u32;
                let report = reports.iter().find(|r| r.rb == rb);
                RingBufMetrics {
                    name,
                    file: report.map(|r| r.file.to_string_lossy().into_owned()),
                    size_bytes: ringbuf_sizes.get(rb as usize).copied().flatten(),
                    attempted: snapshot.rb(rb, STAT_ATTEMPTED),
                    handled: snapshot.rb(rb, STAT_HANDLED),
                    dropped: snapshot.rb(rb, STAT_DROPPED),
                    error: snapshot.rb(rb, STAT_ERROR),
                    records_written: report.map(|r| r.records),
                    writer_error: report.and_then(|r| r.error.clone()),
                }
            })
            .collect();

        Metrics {
            duration_s,
            attempted: snapshot.attempted(),
            handled: snapshot.handled(),
            dropped: snapshot.dropped(),
            error: snapshot.errors(),
            records_written: reports.iter().map(|r| r.records).sum(),
            ingress: attempts(&[RB_TCP4_INGRESS, RB_TCP6_INGRESS]),
            egress: attempts(&[RB_TCP4_EGRESS, RB_TCP6_EGRESS]),
            ingress_calls: attempts(&[RB_SOCK_RECV, RB_CWND_RECV]),
            egress_calls: attempts(&[RB_SOCK_SEND, RB_CWND_SEND]),
            tcp_bytes_sent: snapshot.get(SLOT_TCP_BYTES_SENT),
            tcp_bytes_received: snapshot.get(SLOT_TCP_BYTES_RECEIVED),
            ringbufs,
            programs,
        }
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        let mut writer = BufWriter::new(File::create(path)?);
        serde_json::to_writer_pretty(&mut writer, self)?;
        writer.flush()
    }
}

/// Effective byte size of every ring buffer, indexed like `RINGBUFS`.
/// Must be called before the maps are taken out of `ebpf`.
pub fn ringbuf_sizes(ebpf: &Ebpf) -> Vec<Option<u32>> {
    RINGBUFS
        .iter()
        .map(|(name, _)| match ebpf.map(name) {
            Some(Map::RingBuf(data)) => data.info().ok().map(|info| info.max_entries()),
            _ => None,
        })
        .collect()
}

/// Reads the kernel statistics of all loaded programs
pub fn program_stats(ebpf: &Ebpf) -> Vec<ProgramStats> {
    ebpf.programs()
        .filter_map(|(name, program)| {
            let fd = program.fd().ok()?;
            let info = prog_info(fd.as_fd().as_raw_fd())?;
            Some(ProgramStats {
                name: name.to_string(),
                recursion_misses: info.recursion_misses,
                run_cnt: info.run_cnt,
                run_time_ns: info.run_time_ns,
            })
        })
        .collect()
}

fn prog_info(fd: i32) -> Option<bpf_prog_info> {
    // aya's ProgramInfo does not expose the run and miss counters
    let mut info: bpf_prog_info = unsafe { mem::zeroed() };
    let mut attr: bpf_attr = unsafe { mem::zeroed() };
    attr.info.bpf_fd = fd as u32;
    attr.info.info_len = mem::size_of::<bpf_prog_info>() as u32;
    attr.info.info = &mut info as *mut _ as u64;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as i32,
            &mut attr as *mut bpf_attr,
            mem::size_of::<bpf_attr>(),
        )
    };
    (ret == 0).then_some(info)
}
