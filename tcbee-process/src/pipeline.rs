//! The processing pipeline: plan work units, decode them on a pool of
//! worker threads, hand column batches to the storage engine, write the catalog at the end.

use std::{
    any::Any,
    collections::BTreeMap,
    fmt,
    fs::File,
    ops::Range,
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use tcbee_trace::{
    onchange::{Manifest, Sampling, MANIFEST_VERSION},
    TCBeeTrace, TraceFile,
};
use ts_storage::{
    BatchWriter, Catalog, CreateOptions, Dir, EventBatch, IngestSession, StatsAccumulator,
};

use crate::{
    bindings::{binding, binding_for, event_tables, tcp_event, Binding},
    connections::{self, TaggedFlows},
    decode::{RangeError, RowError},
    metadata,
    registry::FlowRegistry,
    Args,
};

/// Records per work unit.
pub const UNIT_RECORDS: u64 = 1_000_000;
/// Rows per batch handed to the engine.
const BATCH_ROWS: usize = 64 * 1024;

/// What a run did, for the final line and for tests.
#[derive(Debug, Default)]
pub struct Summary {
    /// The trace directory that was read.
    pub trace_dir: PathBuf,
    /// Whole records found in the trace files (what the file sizes promise).
    pub records: u64,
    /// Rows the workers wrote to the event tables. A run only succeeds when this equals
    /// `records`.
    pub rows: u64,
    /// Rows written per event table (`sock`, `tcp4`, ...), only tables that got rows.
    pub rows_by_table: BTreeMap<&'static str, u64>,
    /// Distinct flows.
    pub flows: usize,
    /// Connections that group flows (MPTCP).
    pub connections: usize,
    /// Rows of the `series` catalog table.
    pub series: usize,
    /// One entry per trace file that has a decoder and at least one record.
    pub files: Vec<FileSummary>,
    /// Names of files with data but no decoder (`tcp_retransmit_synack`, `tcp_bad_csum`).
    pub skipped: Vec<String>,
    /// Truncated tails and the like; the run still succeeded.
    pub warnings: Vec<String>,
    /// Wall time of the whole run.
    pub elapsed: Duration,
    /// Time from the last worker finishing to the finished database (catalog, indexes,
    /// checkpoint, rename).
    pub finish: Duration,
    /// Size of the output file.
    pub output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSummary {
    /// File name inside the trace directory.
    pub file: String,
    /// Event table (`sock`, `tcp4`, ...).
    pub source: &'static str,
    pub dir: Dir,
    pub records: u64,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} records, {} rows, {} flows, {} connections, {} series in {:.2} s (finish {:.2} s), \
             output {}",
            self.records,
            self.rows,
            self.flows,
            self.connections,
            self.series,
            self.elapsed.as_secs_f64(),
            self.finish.as_secs_f64(),
            human_bytes(self.output_bytes)
        )
    }
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// One trace file that will be read.
struct FilePlan {
    file: TraceFile,
    name: String,
    path: PathBuf,
    binding: Binding,
    records: u64,
    bar: ProgressBar,
}

/// A range of records of one file.
struct Unit {
    file: usize,
    records: Range<u64>,
}

/// A trace directory: the given one if it holds trace files, else the latest `tcbee_*` below it.
fn resolve_trace(source: &Path) -> Result<TCBeeTrace> {
    if source.is_dir() {
        let trace = TCBeeTrace::open(source)
            .with_context(|| format!("cannot open trace directory {}", source.display()))?;
        if !trace.available_traces().is_empty() {
            return Ok(trace);
        }
    }
    TCBeeTrace::find_latest(source).ok_or_else(|| {
        anyhow!(
            "{} holds no trace files and no tcbee_* recording was found below it",
            source.display()
        )
    })
}

fn bar_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.green} {prefix:.bold.dim} [{elapsed_precise}] \
         {bar:40.cyan/blue} {pos:>9}/{len:9} {percent:>3}% eta {eta_precise}",
    )
    .unwrap_or_else(|_| ProgressStyle::default_bar())
    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
}

const LABEL_WIDTH: usize = 24;

fn label(name: &str) -> String {
    format!("{name:<LABEL_WIDTH$.LABEL_WIDTH$}")
}

/// Finds the files to read and splits them into units. A truncated last record is a warning.
fn plan(
    trace: &TCBeeTrace,
    bars: &MultiProgress,
    summary: &mut Summary,
) -> Result<(Vec<FilePlan>, Vec<Unit>)> {
    let mut files = Vec::new();
    let mut units = Vec::new();
    for file in trace.available_traces() {
        let path = trace.path_for(file);
        let name = file.filename().to_string();
        let len = std::fs::metadata(&path)
            .with_context(|| format!("cannot stat {}", path.display()))?
            .len();
        let binding =
            binding_for(file, &path).with_context(|| format!("cannot read {}", path.display()))?;
        let Some(binding) = binding else {
            info!("Skipping {name}: {NO_DECODER}");
            if len > 0 {
                summary.skipped.push(name);
            }
            continue;
        };
        let size = binding.entry_size as u64;
        let records = len / size;
        let tail = len % size;
        if tail != 0 {
            let msg = format!(
                "{name}: {tail} trailing bytes do not form a whole record ({size} bytes) \
                 and are ignored (recording stopped mid-write?)"
            );
            warn!("{msg}");
            summary.warnings.push(msg);
        }
        if records == 0 {
            continue;
        }
        if !binding.missing_columns.is_empty() {
            info!(
                "{name}: older record layout without {}; their series are left out",
                binding.missing_columns.join(", ")
            );
        }
        let bar = bars.add(ProgressBar::new(records));
        bar.set_style(bar_style());
        bar.set_prefix(label(&name));
        let idx = files.len();
        let mut start = 0;
        while start < records {
            let end = (start + UNIT_RECORDS).min(records);
            units.push(Unit {
                file: idx,
                records: start..end,
            });
            start = end;
        }
        summary.files.push(FileSummary {
            file: name.clone(),
            source: binding.table.source,
            dir: binding.dir,
            records,
        });
        files.push(FilePlan {
            file,
            name,
            path,
            binding,
            records,
            bar,
        });
    }
    Ok((files, units))
}

/// Why files without a decoder are skipped; also used by `main` for its message.
pub const NO_DECODER: &str = "no decoder for this file type";

/// Sentinel the decode callback returns to stop a unit once another worker has failed.
#[derive(Debug)]
struct Aborted;

impl fmt::Display for Aborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("aborted")
    }
}

impl std::error::Error for Aborted {}

/// How many records a worker decodes between looks at the abort flag.
const ABORT_CHECK_RECORDS: u64 = 4096;

/// What a successful worker hands back.
#[derive(Default)]
struct WorkerOutput {
    stats: StatsAccumulator,
    rows_by_table: BTreeMap<&'static str, u64>,
    tagged: TaggedFlows,
}

struct Shared<'a> {
    session: &'a dyn IngestSession,
    registry: &'a FlowRegistry,
    files: &'a [FilePlan],
    units: &'a [Unit],
    /// Names of the kernel's drop reasons for the event labels
    drop_reasons: Arc<BTreeMap<u32, String>>,
    next_unit: AtomicUsize,
    abort: AtomicBool,
    first_error: Mutex<Option<anyhow::Error>>,
}

impl Shared<'_> {
    /// Records the failure of a worker; only the first one is kept, later ones are usually
    /// consequences of it (a stopped writer, for example).
    fn fail(&self, err: anyhow::Error) {
        if !self.abort.swap(true, Ordering::SeqCst) {
            *self.first_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(err);
        }
    }

    fn fail_panic(&self, payload: Box<dyn Any + Send>) {
        self.fail(anyhow!(
            "worker thread panicked: {}",
            panic_message(payload)
        ));
    }

    fn aborted(&self) -> bool {
        self.abort.load(Ordering::Relaxed)
    }

    fn take_error(&self) -> Option<anyhow::Error> {
        self.first_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

/// `error` and its sources, joined like `{:#}` does for anyhow.
fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut out = error.to_string();
    let mut cur = error.source();
    while let Some(e) = cur {
        out.push_str(": ");
        out.push_str(&e.to_string());
        cur = e.source();
    }
    out
}

/// Sends the batch to the writer after adding it to the statistics, and advances the progress
/// bar. Leaves a fresh empty batch behind.
fn flush_batch(
    batch: &mut EventBatch,
    writer: &mut dyn BatchWriter,
    output: &mut WorkerOutput,
    bar: &ProgressBar,
) -> Result<()> {
    let table = batch.table();
    let rows = batch.len() as u64;
    let full = std::mem::replace(batch, EventBatch::new(table, BATCH_ROWS));
    output.stats.observe(&full).context("invalid batch")?;
    writer.write(full).context("cannot write a batch")?;
    *output.rows_by_table.entry(table.source).or_default() += rows;
    bar.inc(rows);
    Ok(())
}

fn worker(shared: &Shared<'_>) -> Result<WorkerOutput> {
    let mut writer = shared
        .session
        .writer()
        .context("cannot open a batch writer")?;
    let mut cache = shared.registry.cache();
    let mut output = WorkerOutput::default();
    tcp_event::set_drop_reasons(shared.drop_reasons.clone());

    loop {
        if shared.aborted() {
            break;
        }
        let unit_index = shared.next_unit.fetch_add(1, Ordering::Relaxed);
        let Some(unit) = shared.units.get(unit_index) else {
            break;
        };
        let file_plan = &shared.files[unit.file];
        let binding = file_plan.binding;
        debug!("{}: records {:?}", file_plan.name, unit.records);

        let file = File::open(&file_plan.path)
            .with_context(|| format!("cannot open {}", file_plan.path.display()))?;
        let mut batch = EventBatch::new(binding.table, BATCH_ROWS);

        let res = (binding.decode)(&file, unit.records.clone(), &mut |index, row| {
            if index % ABORT_CHECK_RECORDS == 0 && shared.aborted() {
                return Err(Box::new(Aborted) as RowError);
            }
            let flow = cache.id(row.flow_key());
            let connection_key = row.connection_key();
            if connection_key != 0 {
                output.tagged.observe(flow, connection_key, row.ts_ns());
            } else if row.socket_level() {
                output.tagged.untagged_socket(flow);
            }
            // A series is read in (ts, seq) order. hook_seq is the exact hook order, ts sorts
            // first, so the two only differ if a CPU's clock read went backwards
            batch.push_header(flow, binding.dir, row.ts_ns(), row.hook_seq());
            row.push_row(&mut batch);
            if batch.len() >= BATCH_ROWS {
                flush_batch(&mut batch, &mut *writer, &mut output, &file_plan.bar)?;
            }
            Ok(())
        });
        match res {
            Ok(()) => {
                if !batch.is_empty() {
                    flush_batch(&mut batch, &mut *writer, &mut output, &file_plan.bar)?;
                }
            }
            Err(RangeError::Callback(e)) if e.is::<Aborted>() => break,
            Err(RangeError::Callback(e)) => {
                return Err(anyhow!(
                    "{}: {}",
                    file_plan.path.display(),
                    error_chain(&*e)
                ));
            }
            Err(e) => return Err(anyhow!("{}: {}", file_plan.path.display(), e)),
        }
    }
    writer.close().context("cannot close a batch writer")?;
    Ok(output)
}

/// Runs `threads` workers until the queue is empty or one fails. Returns the merged statistics
/// and rows per table, or the first error (panics included).
fn run_workers(shared: &Shared<'_>, threads: usize) -> Result<WorkerOutput> {
    let mut total = WorkerOutput::default();
    thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| match catch_unwind(AssertUnwindSafe(|| worker(shared))) {
                    Ok(Ok(output)) => Some(output),
                    Ok(Err(e)) => {
                        shared.fail(e);
                        None
                    }
                    Err(payload) => {
                        shared.fail_panic(payload);
                        None
                    }
                })
            })
            .collect();
        for handle in handles {
            // The closure above catches panics, so a join error cannot normally happen.
            match handle.join() {
                Ok(Some(output)) => {
                    total.stats.merge(output.stats);
                    total.tagged.merge(output.tagged);
                    for (table, rows) in output.rows_by_table {
                        *total.rows_by_table.entry(table).or_default() += rows;
                    }
                }
                Ok(None) => {}
                Err(payload) => shared.fail_panic(payload),
            }
        }
    });
    match shared.take_error() {
        Some(e) => Err(e),
        None => Ok(total),
    }
}

/// Catalog meta entries `sampling.<source>.<dir>` for the on-change files of the manifest,
/// e.g. `sampling.sock_oc.1 = on_change(snd_cwnd,total_retrans)`, with ` shadow` appended in
/// shadow mode. Readers draw those series as steps.
fn sampling_meta(manifest: &Manifest) -> Vec<(String, String)> {
    let mut meta = Vec::new();
    for source in &manifest.sources {
        let Sampling::OnChange { fields } = &source.sampling else {
            continue;
        };
        let Some(b) = TraceFile::all()
            .iter()
            .find(|f| f.filename() == source.file)
            .and_then(|f| binding(*f))
        else {
            continue;
        };
        let mut value = format!("on_change({})", fields.join(","));
        if source.shadow {
            value.push_str(" shadow");
        }
        meta.push((
            format!("sampling.{}.{}", b.table.source, b.dir.code()),
            value,
        ));
    }
    meta
}

/// The catalog meta entries of the on-change manifest, if the recording has one. A manifest
/// that cannot be read or is newer than this reader is a warning, not an error.
fn manifest_meta(trace: &TCBeeTrace, summary: &mut Summary) -> Vec<(String, String)> {
    match Manifest::read(trace.dir()) {
        Ok(Some(manifest)) => {
            if manifest.format_version > MANIFEST_VERSION {
                let msg = format!(
                    "manifest format version {} is newer than {MANIFEST_VERSION}, sampling may be misread",
                    manifest.format_version
                );
                warn!("{msg}");
                summary.warnings.push(msg);
            }
            sampling_meta(&manifest)
        }
        Ok(None) => Vec::new(),
        Err(e) => {
            let msg = format!("cannot read the on-change manifest: {e}");
            warn!("{msg}");
            summary.warnings.push(msg);
            Vec::new()
        }
    }
}

fn build_catalog(
    registry: FlowRegistry,
    stats: StatsAccumulator,
    tagged: TaggedFlows,
    pm_events: &[connections::PmEvent],
    trace: &TCBeeTrace,
    run_meta: Vec<(String, String)>,
    files: &[FilePlan],
) -> Catalog {
    let flows = registry.into_flows();
    let (connections, connection_flows) = connections::assemble(tagged, pm_events, &flows);
    // Columns a file's records do not have hold 0; a series of them would look recorded
    let mut series = stats.into_series(1);
    series.retain(|s| {
        !files.iter().any(|f| {
            f.binding.table.source == s.source
                && f.binding.dir == s.dir
                && f.binding.missing_columns.contains(&s.name.as_str())
        })
    });
    for (id, s) in (1..).zip(series.iter_mut()) {
        s.id = id;
    }
    Catalog {
        flows,
        connections,
        connection_flows,
        series,
        meta: vec![
            (
                "writer".to_string(),
                format!("tcbee-process {}", env!("CARGO_PKG_VERSION")),
            ),
            ("trace_dir".to_string(), trace.dir().display().to_string()),
        ]
        .into_iter()
        .chain(run_meta)
        .collect(),
    }
}

pub fn run(args: &Args) -> Result<Summary> {
    let start = Instant::now();
    let mut summary = Summary::default();

    let trace = resolve_trace(&args.source)?;
    summary.trace_dir = trace.dir().to_path_buf();
    info!("Reading from {}", trace.dir().display());

    let bars = MultiProgress::new();
    let (files, units) = plan(&trace, &bars, &mut summary)?;
    if files.is_empty() {
        let msg = format!("{} contains no records", trace.dir().display());
        warn!("{msg}");
        summary.warnings.push(msg);
    }
    summary.records = files.iter().map(|f| f.records).sum();

    // Fails early, before any work, if the output exists and `force` is not set. Dropping the
    // session on any later error removes the partial output.
    let session = ts_storage::create(
        args.engine,
        &args.output,
        CreateOptions { force: args.force },
    )
    .with_context(|| format!("cannot create {}", args.output.display()))?;
    session
        .create_tables(&event_tables())
        .context("cannot create the event tables")?;

    let threads = args
        .threads
        .unwrap_or_else(|| thread::available_parallelism().map_or(1, |n| n.get()))
        .clamp(1, units.len().max(1));

    let registry = FlowRegistry::new();
    let drop_reasons = metadata::drop_reasons(trace.dir()).unwrap_or_else(|msg| {
        warn!("{msg}");
        summary.warnings.push(msg);
        BTreeMap::new()
    });
    let drop_reason_rows: Vec<(String, String)> = drop_reasons
        .iter()
        .map(|(value, name)| (format!("drop_reason.{value}"), name.clone()))
        .collect();
    let shared = Shared {
        session: &*session,
        registry: &registry,
        files: &files,
        units: &units,
        drop_reasons: Arc::new(drop_reasons),
        next_unit: AtomicUsize::new(0),
        abort: AtomicBool::new(false),
        first_error: Mutex::new(None),
    };
    let result = run_workers(&shared, threads);
    for file in &files {
        match result {
            Ok(_) => file.bar.finish(),
            Err(_) => file.bar.abandon(),
        }
    }
    let output = result?;

    summary.rows_by_table = output.rows_by_table;
    summary.rows = summary.rows_by_table.values().sum();
    if summary.rows != summary.records {
        anyhow::bail!(
            "internal error: wrote {} rows for {} records",
            summary.rows,
            summary.records
        );
    }

    let finish_start = Instant::now();
    // The path manager events once more, in full: they cut tokens into connections
    let pm_events = match files.iter().find(|f| f.file == connections::EVENT_FILE) {
        Some(f) => connections::read_pm_events(&f.path, 0..f.records)?,
        None => Vec::new(),
    };
    let run_meta = metadata::read(trace.dir()).unwrap_or_else(|msg| {
        warn!("{msg}");
        summary.warnings.push(msg);
        Vec::new()
    });
    let on_change_meta = manifest_meta(&trace, &mut summary);
    let run_meta = run_meta
        .into_iter()
        .chain(drop_reason_rows)
        .chain(on_change_meta)
        .collect();
    let catalog = build_catalog(
        registry,
        output.stats,
        output.tagged,
        &pm_events,
        &trace,
        run_meta,
        &files,
    );
    summary.connections = catalog.connections.len();
    summary.flows = catalog.flows.len();
    summary.series = catalog.series.len();
    session
        .finish(catalog)
        .with_context(|| format!("cannot finish {}", args.output.display()))?;
    summary.finish = finish_start.elapsed();
    summary.elapsed = start.elapsed();
    summary.output_bytes = std::fs::metadata(&args.output).map_or(0, |m| m.len());
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use tcbee_trace::onchange::SourceMeta;

    use super::*;

    fn source(file: &str, sampling: Sampling, shadow: bool) -> SourceMeta {
        SourceMeta {
            file: file.into(),
            sampling,
            shadow,
            recv_hook: "fexit/tcp_rcv_established".into(),
        }
    }

    #[test]
    fn manifest_becomes_sampling_meta() {
        let on_change = |f: &[&str]| Sampling::OnChange {
            fields: f.iter().map(|s| s.to_string()).collect(),
        };
        let manifest = Manifest {
            format_version: MANIFEST_VERSION,
            sources: vec![
                source("send_sock_oc.tcp", on_change(&["snd_cwnd", "rto"]), true),
                source("recv_cwnd_oc.tcp", on_change(&["snd_cwnd"]), false),
                source("send_sock.tcp", Sampling::EveryRun, false),
                source("unknown.tcp", on_change(&["snd_cwnd"]), false),
            ],
        };
        assert_eq!(
            sampling_meta(&manifest),
            vec![
                (
                    "sampling.sock_oc.1".to_string(),
                    "on_change(snd_cwnd,rto) shadow".to_string()
                ),
                (
                    "sampling.cwnd_oc.2".to_string(),
                    "on_change(snd_cwnd)".to_string()
                ),
            ]
        );
    }
}
