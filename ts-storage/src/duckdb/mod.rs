//! DuckDB engine of the storage API.
//!
//! Ingest: one `Connection` lives in the session (metadata, `try_clone`); every `BatchWriter`
//! owns a cloned connection and appends Arrow record batches through the appender API. The
//! `Vec`s of an `EventBatch` move into Arrow arrays without a copy (see [`arrow`]). Each writer
//! caches one appender per table and flushes in `close`, where flush errors surface.
//!
//! Measured (`bench.rs`, 20 M values in batches of 4096 rows, release build): a cached appender
//! writes 34 M values/s, an appender created and flushed per batch only 14.5 M values/s (every
//! flush makes a small row group), so the cache is kept despite the `unsafe` it needs.
//!
//! Storage: native unsigned and signed integer types, so `u64` is lossless; reads saturate `u64`
//! above `i64::MAX`. `NaN` is rejected in event batches (`EventBatch::validate`, as on every
//! engine); derived float series may hold NaN.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ::duckdb::{params, params_from_iter, Appender, Connection, Row, Statement};

use super::batch::EventBatch;
use super::catalog::{derived_ts, flow_from_parts, Catalog, DerivedStats, SeriesInfo, SeriesRow};
use super::error::StoreError;
use super::schema::{
    create_fixed_table_sql, create_table_sql, ColType, Dialect, Dir, EventTable, SeriesKind,
    ValueKind, DERIVED_SAMPLES, FLOWS, META, SCHEMA_VERSION, SERIES,
};
use super::time::now_iso8601;
use super::{sql, BatchWriter, CreateOptions, Engine, IngestSession, Store};
use crate::{DataPoint, DataValue, Flow};

mod arrow;
#[cfg(test)]
mod bench;
#[cfg(test)]
mod tests;

use arrow::to_record_batch;

const D: Dialect = Dialect::DuckDb;

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn remove_if_exists(path: &Path) -> Result<(), StoreError> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------------------------

struct DuckSession {
    path: PathBuf,
    partial: PathBuf,
    force: bool,
    conn: Mutex<Option<Connection>>,
    /// Number of writers that have not been closed or dropped.
    live_writers: Arc<AtomicUsize>,
    finished: bool,
}

/// Creates `path.partial` and the four fixed tables.
pub(crate) fn create(
    path: &Path,
    opts: CreateOptions,
) -> Result<Box<dyn IngestSession>, StoreError> {
    if path.exists() && !opts.force {
        return Err(StoreError::Exists(path.display().to_string()));
    }
    let partial = with_suffix(path, ".partial");
    remove_if_exists(&partial)?;
    remove_if_exists(&with_suffix(&partial, ".wal"))?;
    if !path.exists() {
        // A WAL without its database would be replayed against the new file.
        remove_if_exists(&with_suffix(path, ".wal"))?;
    }
    let conn = Connection::open(&partial)?;
    // From here on the session's Drop deletes the partial file when anything fails.
    let session = DuckSession {
        path: path.to_path_buf(),
        partial,
        force: opts.force,
        conn: Mutex::new(Some(conn)),
        live_writers: Arc::new(AtomicUsize::new(0)),
        finished: false,
    };
    session.with_conn(|c| {
        for t in [&META, &FLOWS, &SERIES, &DERIVED_SAMPLES] {
            c.execute_batch(&create_fixed_table_sql(D, t))?;
        }
        Ok(())
    })?;
    Ok(Box::new(session))
}

impl DuckSession {
    fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        f(guard
            .as_ref()
            .expect("session connection is open until finish"))
    }
}

impl Drop for DuckSession {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Close the connection first, then delete the partial file and its WAL.
        drop(
            self.conn
                .get_mut()
                .unwrap_or_else(|e| e.into_inner())
                .take(),
        );
        let _ = std::fs::remove_file(&self.partial);
        let _ = std::fs::remove_file(with_suffix(&self.partial, ".wal"));
    }
}

impl IngestSession for DuckSession {
    fn create_tables(&self, tables: &[&'static EventTable]) -> Result<(), StoreError> {
        self.with_conn(|c| {
            for t in tables {
                c.execute_batch(&create_table_sql(D, t))?;
            }
            Ok(())
        })
    }

    fn writer(&self) -> Result<Box<dyn BatchWriter>, StoreError> {
        let conn = self.with_conn(|c| Ok(c.try_clone()?))?;
        Ok(Box::new(DuckWriter::new(conn, &self.live_writers)))
    }

    fn finish(mut self: Box<Self>, catalog: Catalog) -> Result<(), StoreError> {
        let live = self.live_writers.load(Ordering::Acquire);
        if live != 0 {
            return Err(StoreError::Io(std::io::Error::other(format!(
                "finish called while {live} writer(s) are still open"
            ))));
        }
        let conn = self
            .conn
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("session connection is open until finish");
        write_catalog(&conn, &catalog)?;
        conn.execute_batch("CHECKPOINT")?;
        conn.close().map_err(|(_, e)| e)?;
        if !self.force && self.path.exists() {
            return Err(StoreError::Exists(self.path.display().to_string()));
        }
        // A WAL left next to the target (of the file being replaced, or of a deleted one) would
        // be replayed against the new file.
        remove_if_exists(&with_suffix(&self.path, ".wal"))?;
        std::fs::rename(&self.partial, &self.path)?;
        self.finished = true;
        let _ = std::fs::remove_file(with_suffix(&self.partial, ".wal"));
        Ok(())
    }
}

fn write_catalog(conn: &Connection, catalog: &Catalog) -> Result<(), StoreError> {
    let tx = conn.unchecked_transaction()?;
    insert_flows(conn, catalog)?;
    insert_series(conn, catalog)?;
    insert_meta(conn, catalog)?;
    tx.commit()?;
    Ok(())
}

fn insert_flows(conn: &Connection, catalog: &Catalog) -> Result<(), StoreError> {
    let mut st = conn.prepare(sql::INSERT_FLOW)?;
    for f in &catalog.flows {
        st.execute(params![
            f.id,
            f.tuple.src.to_string(),
            f.tuple.dst.to_string(),
            f.tuple.sport,
            f.tuple.dport,
            f.tuple.l4proto
        ])?;
    }
    Ok(())
}

fn insert_series(conn: &Connection, catalog: &Catalog) -> Result<(), StoreError> {
    let mut st = conn.prepare(&sql::insert_series())?;
    for s in &catalog.series {
        insert_series_row(&mut st, s)?;
    }
    Ok(())
}

fn insert_meta(conn: &Connection, catalog: &Catalog) -> Result<(), StoreError> {
    let mut st = conn.prepare(sql::UPSERT_META)?;
    for (k, v) in &catalog.meta {
        st.execute(params![k, v])?;
    }
    // Ours come last so that a caller entry cannot override them.
    st.execute(params!["schema_version", SCHEMA_VERSION.to_string()])?;
    st.execute(params!["created_at", now_iso8601()])?;
    Ok(())
}

/// Binds the 14 columns of `series` from `s` and executes the prepared `sql::insert_series()`.
fn insert_series_row(stmt: &mut Statement, s: &SeriesInfo) -> Result<(), StoreError> {
    let r = SeriesRow::from(s);
    stmt.execute(params![
        r.id,
        r.flow_id,
        r.kind,
        r.source,
        r.dir,
        r.name,
        r.value_type,
        r.tbl,
        r.col,
        r.n,
        r.t_min,
        r.t_max,
        r.v_min,
        r.v_max
    ])?;
    Ok(())
}

/// Counts a live writer in the session; decrements when the writer is closed or dropped.
struct LiveToken(Arc<AtomicUsize>);

impl LiveToken {
    fn new(live: &Arc<AtomicUsize>) -> LiveToken {
        live.fetch_add(1, Ordering::AcqRel);
        LiveToken(live.clone())
    }
}

impl Drop for LiveToken {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A writer owns a cloned connection and one cached appender per table.
///
/// An appender creates a new row group per flush, so a flush per batch is much slower than one
/// long-lived appender per table (see the module docs). DuckDB reports constraint violations
/// when the appender flushes, which is why `close` flushes every appender and returns the first
/// error.
///
/// After an `Err` from `write` or `close` the writer must be discarded: the appender may still
/// hold part of the failed chunk, and a later flush would write it or fail again.
///
/// # Self-reference
///
/// `Appender<'conn>` borrows its `Connection`. The appenders are stored next to the connection
/// with their lifetime extended to `'static`. The invariants that make this sound:
///
/// - the connection lives in a `Box`: moving the `DuckWriter` moves only the box pointer, so the
///   address the appenders point to stays valid. (Without the box, moving the writer by value
///   after the first appender exists would leave them dangling; with it that is harmless, but
///   writers are anyway only used behind `Box<dyn BatchWriter>`.)
/// - invariant: do not move the `DuckWriter` by value after the first appender exists (it is only
///   ever used behind `Box<dyn BatchWriter>`); the box above makes a violation harmless,
/// - the connection is only used through `&` while appenders exist,
/// - the appenders are dropped before the connection: they are declared first (fields drop in
///   declaration order) and `close` clears them explicitly before closing the connection,
/// - the extended lifetime never leaves this struct.
struct DuckWriter {
    appenders: Vec<(&'static EventTable, Appender<'static>)>,
    conn: Box<Connection>,
    _live: LiveToken,
}

impl DuckWriter {
    fn new(conn: Connection, live: &Arc<AtomicUsize>) -> DuckWriter {
        DuckWriter {
            appenders: Vec::new(),
            conn: Box::new(conn),
            _live: LiveToken::new(live),
        }
    }

    fn appender(
        &mut self,
        table: &'static EventTable,
    ) -> Result<&mut Appender<'static>, StoreError> {
        let idx = match self
            .appenders
            .iter()
            .position(|(t, _)| t.source == table.source)
        {
            Some(i) => {
                debug_assert_eq!(
                    *self.appenders[i].0, *table,
                    "two tables named {}",
                    table.source
                );
                i
            }
            None => {
                let app = self.conn.appender(&table.table_name())?;
                // SAFETY: see "Self-reference" on `DuckWriter`. `app` borrows the connection in
                // the heap allocation of `self.conn`, which outlives every appender.
                let app: Appender<'static> = unsafe { std::mem::transmute(app) };
                self.appenders.push((table, app));
                self.appenders.len() - 1
            }
        };
        Ok(&mut self.appenders[idx].1)
    }
}

impl BatchWriter for DuckWriter {
    fn write(&mut self, batch: EventBatch) -> Result<(), StoreError> {
        let (table, empty) = (batch.table(), batch.is_empty());
        let rb = to_record_batch(batch)?; // validates
        if empty {
            return Ok(());
        }
        self.appender(table)?.append_record_batch(rb)?;
        Ok(())
    }

    fn close(mut self: Box<Self>) -> Result<(), StoreError> {
        let mut first_err = None;
        for (_, app) in &mut self.appenders {
            if let Err(e) = app.flush() {
                first_err.get_or_insert(StoreError::DuckDb(e));
            }
        }
        // The appenders go before the connection they borrow.
        self.appenders.clear();
        let closed = self.conn.close().map_err(|(_, e)| StoreError::DuckDb(e));
        match first_err {
            Some(e) => Err(e),
            None => closed,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Read side
// ---------------------------------------------------------------------------------------------

/// Opens an existing DuckDB file and checks `meta.schema_version`.
pub(crate) fn open(path: &Path) -> Result<Box<dyn Store>, StoreError> {
    let conn = Connection::open(path)?;
    let has_meta: i64 = conn.query_row(
        "SELECT count(*) FROM information_schema.tables WHERE table_name = 'meta'",
        [],
        |r| r.get(0),
    )?;
    let found: Option<String> = if has_meta == 0 {
        None
    } else {
        let mut st = conn.prepare(sql::SELECT_META_VALUE)?;
        let mut rows = st.query(params!["schema_version"])?;
        match rows.next()? {
            Some(r) => Some(r.get(0)?),
            None => None,
        }
    };
    if found.as_deref() != Some(SCHEMA_VERSION.to_string().as_str()) {
        return Err(StoreError::UnsupportedSchema { found });
    }
    Ok(Box::new(DuckStore { conn }))
}

struct DuckStore {
    conn: Connection,
}

fn row_to_flow(r: &Row) -> Result<Flow, StoreError> {
    flow_from_parts(
        r.get(0)?,
        &r.get::<_, String>(1)?,
        &r.get::<_, String>(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
    )
}

fn row_to_series(r: &Row) -> Result<SeriesInfo, StoreError> {
    SeriesInfo::try_from(SeriesRow {
        id: r.get(0)?,
        flow_id: r.get(1)?,
        kind: r.get(2)?,
        source: r.get(3)?,
        dir: r.get(4)?,
        name: r.get(5)?,
        value_type: r.get(6)?,
        tbl: r.get(7)?,
        col: r.get(8)?,
        n: r.get(9)?,
        t_min: r.get(10)?,
        t_max: r.get(11)?,
        v_min: r.get(12)?,
        v_max: r.get(13)?,
    })
}

/// Reads column `i` as the value the read API returns for `ty`; u64 saturates to `i64::MAX`.
fn read_value(r: &Row, i: usize, ty: ColType) -> Result<DataValue, StoreError> {
    Ok(match ty {
        ColType::Bool => DataValue::Boolean(r.get(i)?),
        ColType::U8 => DataValue::Int(i64::from(r.get::<_, u8>(i)?)),
        ColType::U16 => DataValue::Int(i64::from(r.get::<_, u16>(i)?)),
        ColType::U32 => DataValue::Int(i64::from(r.get::<_, u32>(i)?)),
        ColType::U64 => DataValue::Int(r.get::<_, u64>(i)?.min(i64::MAX as u64) as i64),
        ColType::I64 => DataValue::Int(r.get(i)?),
        ColType::F64 => DataValue::Float(r.get(i)?),
        ColType::Text => DataValue::String(r.get(i)?),
    })
}

/// The query for the points of `s` and its parameters; `None` for an empty (NaN) range.
fn point_query(
    s: &SeriesInfo,
    range: Option<(f64, f64)>,
) -> Result<Option<(String, Vec<i64>)>, StoreError> {
    // Inclusive bounds on integer timestamps: round the lower bound up, the upper down.
    let bounds = match range {
        Some((lo, hi)) if lo.is_nan() || hi.is_nan() => return Ok(None),
        Some((lo, hi)) => Some((lo.ceil() as i64, hi.floor() as i64)),
        None => None,
    };
    let (query, mut args) = match s.kind {
        SeriesKind::Raw => {
            let (Some(tbl), Some(col)) = (&s.tbl, &s.col) else {
                return Err(StoreError::Corrupt(format!(
                    "raw series {} has no table/column",
                    s.id
                )));
            };
            let q = if bounds.is_some() {
                sql::range_query(tbl, col)
            } else {
                sql::all_points_query(tbl, col)
            };
            (q, vec![s.flow_id, i64::from(s.dir.code())])
        }
        SeriesKind::Derived => {
            let q = if bounds.is_some() {
                sql::derived_range_query(s.value_type)
            } else {
                sql::derived_all_query(s.value_type)
            };
            (q, vec![s.id])
        }
    };
    if let Some((lo, hi)) = bounds {
        args.extend([lo, hi]);
    }
    Ok(Some((query, args)))
}

impl DuckStore {
    fn get_series(&self, id: i64) -> Result<Option<SeriesInfo>, StoreError> {
        let mut st = self.conn.prepare(&sql::select_series_by_id())?;
        let mut rows = st.query(params![id])?;
        rows.next()?.map(row_to_series).transpose()
    }

    /// Re-reads the stored row of `s` and checks that it is the same derived series: raw series
    /// are `NotDerived`, a missing row or a different id, name or flow is `NotFound`.
    fn stored_derived(&self, s: &SeriesInfo) -> Result<SeriesInfo, StoreError> {
        if s.kind != SeriesKind::Derived {
            return Err(StoreError::NotDerived);
        }
        match self.get_series(s.id)? {
            None => Err(StoreError::NotFound(format!("series {}", s.id))),
            Some(d) if d.kind != SeriesKind::Derived => Err(StoreError::NotDerived),
            Some(d) if d.name != s.name || d.flow_id != s.flow_id => Err(StoreError::NotFound(
                format!("series {} \"{}\" in flow {}", s.id, s.name, s.flow_id),
            )),
            Some(d) => Ok(d),
        }
    }

    /// Appends the samples; `DerivedStats::from_points` has validated the points. Only the value
    /// column of `ty` is named, the others stay NULL.
    fn insert_samples(&self, id: i64, ty: ColType, points: &[DataPoint]) -> Result<(), StoreError> {
        let mut app = self.conn.appender_with_columns(
            "derived_samples",
            &["series_id", "ts", "seq", sql::derived_value_column(ty)],
        )?;
        for (seq, p) in points.iter().enumerate() {
            let (ts, seq) = (derived_ts(p.timestamp), seq as i64);
            match &p.value {
                DataValue::Int(v) => app.append_row(params![id, ts, seq, v])?,
                DataValue::Float(v) => app.append_row(params![id, ts, seq, v])?,
                DataValue::Boolean(v) => app.append_row(params![id, ts, seq, v])?,
                DataValue::String(v) => app.append_row(params![id, ts, seq, v])?,
            }
        }
        app.flush()?;
        Ok(())
    }
}

impl Store for DuckStore {
    fn engine(&self) -> Engine {
        Engine::DuckDb
    }

    fn flows(&self) -> Result<Vec<Flow>, StoreError> {
        let mut st = self.conn.prepare(sql::SELECT_FLOWS)?;
        let mut rows = st.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_flow(r)?);
        }
        Ok(out)
    }

    fn flow(&self, id: i64) -> Result<Option<Flow>, StoreError> {
        let mut st = self.conn.prepare(sql::SELECT_FLOW)?;
        let mut rows = st.query(params![id])?;
        rows.next()?.map(row_to_flow).transpose()
    }

    fn series(&self, flow_id: i64) -> Result<Vec<SeriesInfo>, StoreError> {
        let mut st = self.conn.prepare(&sql::select_series_by_flow())?;
        let mut rows = st.query(params![flow_id])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_series(r)?);
        }
        Ok(out)
    }

    fn series_by_id(&self, id: i64) -> Result<Option<SeriesInfo>, StoreError> {
        self.get_series(id)
    }

    fn for_each_point(
        &self,
        s: &SeriesInfo,
        range: Option<(f64, f64)>,
        f: &mut dyn FnMut(DataPoint),
    ) -> Result<(), StoreError> {
        let Some((query, args)) = point_query(s, range)? else {
            return Ok(());
        };
        let mut st = self.conn.prepare(&query)?;
        let mut rows = st.query(params_from_iter(args))?;
        while let Some(r) = rows.next()? {
            let ts: i64 = r.get(0)?;
            f(DataPoint {
                timestamp: ts as f64,
                value: read_value(r, 1, s.value_type)?,
            });
        }
        Ok(())
    }

    fn create_derived(
        &self,
        flow_id: i64,
        name: &str,
        ty: ValueKind,
        points: &[DataPoint],
    ) -> Result<SeriesInfo, StoreError> {
        let stats = DerivedStats::from_points(points, ty)?;
        let ty = ColType::from(ty);
        let tx = self.conn.unchecked_transaction()?;
        let taken: bool =
            self.conn
                .query_row(sql::DERIVED_NAME_TAKEN, params![flow_id, name], |r| {
                    r.get(0)
                })?;
        if taken {
            return Err(StoreError::Exists(name.to_string()));
        }
        let id: i64 = self.conn.query_row(sql::NEXT_SERIES_ID, [], |r| r.get(0))?;
        self.insert_samples(id, ty, points)?;
        let info = SeriesInfo {
            id,
            flow_id,
            kind: SeriesKind::Derived,
            source: "derived".into(),
            dir: Dir::None,
            name: name.to_string(),
            value_type: ty,
            tbl: None,
            col: None,
            n: stats.n,
            t_min: stats.t_min,
            t_max: stats.t_max,
            v_min: stats.v_min,
            v_max: stats.v_max,
        };
        insert_series_row(&mut self.conn.prepare(&sql::insert_series())?, &info)?;
        tx.commit()?;
        Ok(info)
    }

    /// Replaces the samples and statistics; the series keeps its id and name.
    fn replace_derived(
        &self,
        existing: &SeriesInfo,
        points: &[DataPoint],
    ) -> Result<SeriesInfo, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut info = self.stored_derived(existing)?;
        let stats = DerivedStats::from_points(points, info.value_type.value_kind())?;
        self.conn
            .execute(sql::DELETE_DERIVED_SAMPLES, params![info.id])?;
        self.insert_samples(info.id, info.value_type, points)?;
        self.conn.execute(
            sql::UPDATE_SERIES_STATS,
            params![
                stats.n,
                stats.t_min,
                stats.t_max,
                stats.v_min,
                stats.v_max,
                info.id
            ],
        )?;
        tx.commit()?;
        (info.n, info.t_min, info.t_max) = (stats.n, stats.t_min, stats.t_max);
        (info.v_min, info.v_max) = (stats.v_min, stats.v_max);
        Ok(info)
    }

    fn delete_derived(&self, s: &SeriesInfo) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let info = self.stored_derived(s)?;
        self.conn
            .execute(sql::DELETE_DERIVED_SAMPLES, params![info.id])?;
        self.conn.execute(sql::DELETE_SERIES, params![info.id])?;
        tx.commit()?;
        Ok(())
    }
}
