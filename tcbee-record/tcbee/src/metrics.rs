use std::{
    fs::File,
    io::{self, BufWriter, Write},
    mem,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    path::Path,
};

use libbpf_rs::{
    libbpf_sys::{self, bpf_prog_info},
    MapCore, MapFlags, MapHandle, Object,
};
use serde::Serialize;
use tcbee_common::{
    records::hook_seq_key,
    stats::{
        RB_COUNT, RB_CWND_RECV, RB_CWND_SEND, RB_SOCK_RECV, RB_SOCK_SEND, RB_TCP4_EGRESS,
        RB_TCP4_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS, RINGBUFS, STAT_DROPPED, STAT_ERROR,
        STAT_HANDLED,
    },
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
    /// Size of each CPU's ring buffer, None if the ring buffers were not created
    pub size_per_cpu_bytes: Option<u32>,
    pub attempted: u64,
    pub handled: u64,
    pub dropped: u64,
    pub error: u64,
    /// None if no writer was registered for this ring buffer
    pub records_written: Option<u64>,
    pub writer_error: Option<String>,
    /// Sum of the last hook_seq of every flow direction at this ring buffer's hook. Equals
    /// handled + dropped + the errors after the filter, so it also covers drops at the end
    /// of a flow, which leave no gap. None if the counters could not be read.
    pub hook_seq_issued: Option<u64>,
}

/// The final hook_seq counters, read after the programs are detached
pub struct HookSeqTotals {
    /// Flow directions times hooks that got a counter
    pub keys: u64,
    pub capacity: u32,
    /// Sum of the counters per ring buffer, indexed like `RINGBUFS`
    pub issued: [u64; RB_COUNT as usize],
}

impl HookSeqTotals {
    pub fn read(map: &MapHandle) -> libbpf_rs::Result<HookSeqTotals> {
        let mut totals = HookSeqTotals {
            keys: 0,
            capacity: map.max_entries(),
            issued: [0; RB_COUNT as usize],
        };
        for key in map.keys() {
            let Some(value) = map.lookup(&key, MapFlags::ANY)? else {
                continue;
            };
            let rb = key[mem::offset_of!(hook_seq_key, rb)] as usize;
            totals.keys += 1;
            totals.issued[rb] += u64::from_ne_bytes(value[..8].try_into().expect("u64 value"));
        }
        Ok(totals)
    }
}

#[derive(Serialize)]
pub struct Metrics {
    pub duration_s: f64,
    /// CPUs with a ring buffer per probe output (the online ones)
    pub ring_cpus: u32,
    pub attempted: u64,
    pub handled: u64,
    pub dropped: u64,
    pub error: u64,
    pub records_written: u64,
    pub ingress: u64,
    pub egress: u64,
    pub ingress_calls: u64,
    pub egress_calls: u64,
    pub ringbufs: Vec<RingBufMetrics>,
    pub programs: Vec<ProgramStats>,
    /// Entries in use and capacity of the hook_seq counter map. A full map turns the
    /// events of new flows into errors.
    pub hook_seq_keys: Option<u64>,
    pub hook_seq_capacity: Option<u32>,
}

impl Metrics {
    pub fn new(
        duration_s: f64,
        snapshot: &Snapshot,
        reports: &[WriterReport],
        ringbuf_sizes: &[Option<u32>],
        ring_cpus: u32,
        programs: Vec<ProgramStats>,
        hook_seq: Option<&HookSeqTotals>,
    ) -> Metrics {
        let attempts = |rbs: &[u32]| rbs.iter().map(|rb| snapshot.invocations(*rb)).sum();

        let ringbufs: Vec<RingBufMetrics> = RINGBUFS
            .iter()
            .enumerate()
            .map(|(rb, ringbuf)| {
                let rb = rb as u32;
                let report = reports.iter().find(|r| r.rb == rb);
                RingBufMetrics {
                    name: ringbuf.map,
                    file: report.map(|r| r.file.to_string_lossy().into_owned()),
                    size_per_cpu_bytes: ringbuf_sizes.get(rb as usize).copied().flatten(),
                    attempted: snapshot.invocations(rb),
                    handled: snapshot.rb(rb, STAT_HANDLED),
                    dropped: snapshot.rb(rb, STAT_DROPPED),
                    error: snapshot.rb(rb, STAT_ERROR),
                    records_written: report.map(|r| r.records),
                    writer_error: report.and_then(|r| r.error.clone()),
                    hook_seq_issued: hook_seq.map(|totals| totals.issued[rb as usize]),
                }
            })
            .collect();

        Metrics {
            duration_s,
            ring_cpus,
            attempted: snapshot.attempted(),
            handled: snapshot.handled(),
            dropped: snapshot.dropped(),
            error: snapshot.errors(),
            records_written: reports.iter().map(|r| r.records).sum(),
            ingress: attempts(&[RB_TCP4_INGRESS, RB_TCP6_INGRESS]),
            egress: attempts(&[RB_TCP4_EGRESS, RB_TCP6_EGRESS]),
            ingress_calls: attempts(&[RB_SOCK_RECV, RB_CWND_RECV]),
            egress_calls: attempts(&[RB_SOCK_SEND, RB_CWND_SEND]),
            ringbufs,
            programs,
            hook_seq_keys: hook_seq.map(|totals| totals.keys),
            hook_seq_capacity: hook_seq.map(|totals| totals.capacity),
        }
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        let mut writer = BufWriter::new(File::create(path)?);
        serde_json::to_writer_pretty(&mut writer, self)?;
        writer.flush()
    }
}

/// Reads the kernel statistics of all loaded programs
pub fn program_stats(object: &Object) -> Vec<ProgramStats> {
    object
        .progs()
        // Programs of disabled groups are not loaded and have no fd
        .filter(|program| program.autoload())
        .filter_map(|program| {
            let info = prog_info(program.as_fd())?;
            Some(ProgramStats {
                name: program.name().to_string_lossy().into_owned(),
                recursion_misses: info.recursion_misses,
                run_cnt: info.run_cnt,
                run_time_ns: info.run_time_ns,
            })
        })
        .collect()
}

fn prog_info(fd: BorrowedFd<'_>) -> Option<bpf_prog_info> {
    // libbpf-rs' ProgramInfo also reads the instructions, the plain info is enough here
    let mut info = bpf_prog_info::default();
    let mut len = mem::size_of::<bpf_prog_info>() as u32;
    let ret = unsafe { libbpf_sys::bpf_prog_get_info_by_fd(fd.as_raw_fd(), &mut info, &mut len) };
    (ret == 0).then_some(info)
}
