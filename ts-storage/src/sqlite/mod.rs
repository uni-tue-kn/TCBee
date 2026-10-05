//! SQLite engine of the storage API, on `rusqlite`.
//!
//! Ingest: one writer thread owns the only `Connection` while the file is written. Batches reach
//! it through a bounded channel; `create_tables` and `finish` are control messages. The thread
//! inserts with one cached prepared statement per table inside a transaction that commits every
//! [`COMMIT_ROWS`] rows. The data goes to `<path>.partial` (no journal, no fsync) and is renamed
//! to `path` when `finish` has committed everything.
//!
//! Storage: integers (also `u64`, as its `i64` bit pattern) in `INTEGER`, `f64` in `REAL`.
//! Reads convert back with `series.value_type` and saturate `u64` values above `i64::MAX`.
//! SQLite stores NaN as NULL, which the `NOT NULL` event columns would reject, so
//! `EventBatch::validate` (called by `BatchWriter::write`) rejects NaN with `TypeMismatch` on every
//! engine. Derived series may hold NaN floats: they are stored as NULL and read back as NaN.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

use rusqlite::types::ValueRef;
use rusqlite::{
    params, types::ToSql, Connection, OpenFlags, OptionalExtension, Row, Transaction,
    TransactionBehavior,
};

use super::batch::{ColumnData, EventBatch};
use super::catalog::{derived_ts, flow_from_parts, Catalog, DerivedStats, SeriesInfo, SeriesRow};
use super::error::StoreError;
use super::schema::{
    create_derived_index_sql, create_fixed_table_sql, create_index_sql, create_table_sql, ColType,
    Dialect, Dir, EventTable, SeriesKind, ValueKind, DERIVED_SAMPLES, FLOWS, META, SCHEMA_VERSION,
    SERIES,
};
use super::time::now_iso8601;
use super::{sql, BatchWriter, Engine, IngestSession, Store};
use crate::{DataPoint, DataValue, Flow};

/// Rows per transaction during ingest.
pub const COMMIT_ROWS: u64 = 1_000_000;
/// Capacity of the batch channel between the writers and the SQLite thread.
const CHANNEL_CAPACITY: usize = 8;

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn partial_path(path: &Path) -> PathBuf {
    with_suffix(path, ".partial")
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

enum Msg {
    CreateTables(Vec<&'static EventTable>, SyncSender<Result<(), StoreError>>),
    Batch(EventBatch),
    /// Reply once every earlier message has been processed.
    Flush(SyncSender<()>),
    Finish(Catalog),
}

pub(crate) fn create(
    path: &Path,
    opts: super::CreateOptions,
) -> Result<Box<dyn IngestSession>, StoreError> {
    create_with(path, opts, COMMIT_ROWS)
}

fn create_with(
    path: &Path,
    opts: super::CreateOptions,
    commit_rows: u64,
) -> Result<Box<dyn IngestSession>, StoreError> {
    if !opts.force && path.exists() {
        return Err(StoreError::Exists(path.display().to_string()));
    }
    let partial = partial_path(path);
    remove_if_exists(&partial)?;
    // Whatever fails from here on must not leave a partial file behind.
    start_session(path, &partial, opts.force, commit_rows).inspect_err(|_| {
        let _ = std::fs::remove_file(&partial);
    })
}

fn start_session(
    path: &Path,
    partial: &Path,
    force: bool,
    commit_rows: u64,
) -> Result<Box<dyn IngestSession>, StoreError> {
    let conn = Connection::open(partial)?;
    // The partial file is deleted when anything fails, so durability is not needed.
    conn.execute_batch("PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;")?;
    conn.set_prepared_statement_cache_capacity(64);
    for t in [&META, &FLOWS, &SERIES, &DERIVED_SAMPLES] {
        conn.execute_batch(&create_fixed_table_sql(Dialect::Sqlite, t))?;
    }
    if let Some(idx) = create_derived_index_sql(Dialect::Sqlite) {
        conn.execute_batch(&idx)?;
    }
    conn.execute_batch("BEGIN")?;

    let abort = Arc::new(AtomicBool::new(false));
    let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
    let worker = Worker {
        conn,
        rx,
        abort: abort.clone(),
        partial: partial.to_path_buf(),
        path: path.to_path_buf(),
        force,
        commit_rows,
        rows_in_tx: 0,
        tables: Vec::new(),
        insert_sql: HashMap::new(),
    };
    let handle = std::thread::Builder::new()
        .name("tcbee-sqlite-writer".into())
        .spawn(move || worker.run())?;
    Ok(Box::new(SqliteSession {
        tx: Some(tx),
        handle: Some(handle),
        abort,
        writers: Arc::new(()),
        partial: partial.to_path_buf(),
        committed: false,
    }))
}

struct Worker {
    conn: Connection,
    rx: Receiver<Msg>,
    abort: Arc<AtomicBool>,
    partial: PathBuf,
    path: PathBuf,
    force: bool,
    commit_rows: u64,
    rows_in_tx: u64,
    tables: Vec<&'static EventTable>,
    insert_sql: HashMap<&'static str, String>,
}

impl Worker {
    /// Returns when the channel closes (all senders dropped), on abort, or after `Finish`.
    /// Dropping `self` on an early return closes the connection, which rolls back.
    fn run(mut self) -> Result<(), StoreError> {
        while let Ok(msg) = self.rx.recv() {
            if self.abort.load(Ordering::Relaxed) {
                return Ok(());
            }
            match msg {
                Msg::CreateTables(tables, reply) => {
                    let r = self.create_tables(&tables);
                    // The caller may have gone away; nothing to do about it.
                    let _ = reply.send(r);
                }
                Msg::Batch(b) => self.insert(&b)?,
                Msg::Flush(reply) => {
                    let _ = reply.send(());
                }
                Msg::Finish(catalog) => return self.finish(catalog),
            }
        }
        Ok(())
    }

    fn create_tables(&mut self, tables: &[&'static EventTable]) -> Result<(), StoreError> {
        for &t in tables {
            if self.tables.iter().any(|x| x.source == t.source) {
                continue;
            }
            self.conn
                .execute_batch(&create_table_sql(Dialect::Sqlite, t))?;
            self.tables.push(t);
        }
        Ok(())
    }

    fn insert(&mut self, batch: &EventBatch) -> Result<(), StoreError> {
        let table = batch.table();
        let sql = self
            .insert_sql
            .entry(table.source)
            .or_insert_with(|| sql::insert_events(table));
        let mut stmt = self.conn.prepare_cached(sql)?;
        let (flows, dirs, tss, seqs) = (
            batch.flow_ids(),
            batch.dirs(),
            batch.timestamps(),
            batch.seqs(),
        );
        let cols = batch.columns();
        for r in 0..batch.len() {
            stmt.raw_bind_parameter(1, flows[r])?;
            stmt.raw_bind_parameter(2, dirs[r])?;
            stmt.raw_bind_parameter(3, tss[r])?;
            stmt.raw_bind_parameter(4, seqs[r])?;
            for (i, c) in cols.iter().enumerate() {
                let idx = 5 + i;
                match c {
                    ColumnData::Bool(v) => stmt.raw_bind_parameter(idx, v[r])?,
                    ColumnData::U8(v) => stmt.raw_bind_parameter(idx, v[r])?,
                    ColumnData::U16(v) => stmt.raw_bind_parameter(idx, v[r])?,
                    ColumnData::U32(v) => stmt.raw_bind_parameter(idx, v[r])?,
                    // Bit pattern, so that the whole u64 range is stored losslessly.
                    ColumnData::U64(v) => stmt.raw_bind_parameter(idx, v[r] as i64)?,
                    ColumnData::I64(v) => stmt.raw_bind_parameter(idx, v[r])?,
                    ColumnData::F64(v) => stmt.raw_bind_parameter(idx, v[r])?,
                    ColumnData::Text(v) => stmt.raw_bind_parameter(idx, v[r].as_str())?,
                }
            }
            stmt.raw_execute()?;
            self.rows_in_tx += 1;
            if self.rows_in_tx >= self.commit_rows {
                self.conn.execute_batch("COMMIT; BEGIN")?;
                self.rows_in_tx = 0;
            }
        }
        Ok(())
    }

    fn finish(self, catalog: Catalog) -> Result<(), StoreError> {
        let Worker {
            conn,
            partial,
            path,
            force,
            tables,
            ..
        } = self;
        {
            let mut flow = conn.prepare(sql::INSERT_FLOW)?;
            for f in &catalog.flows {
                flow.execute(params![
                    f.id,
                    f.tuple.src.to_string(),
                    f.tuple.dst.to_string(),
                    f.tuple.sport,
                    f.tuple.dport,
                    f.tuple.l4proto
                ])?;
            }
            let mut series = conn.prepare(&sql::insert_series())?;
            for s in &catalog.series {
                insert_series_row(&mut series, s)?;
            }
            let mut meta = conn.prepare(sql::UPSERT_META)?;
            for (k, v) in &catalog.meta {
                meta.execute(params![k, v])?;
            }
            // Ours come last so that a caller entry cannot override them.
            meta.execute(params!["schema_version", SCHEMA_VERSION.to_string()])?;
            meta.execute(params!["created_at", now_iso8601()])?;
        }
        // Indexes after the load: much cheaper than maintaining them row by row.
        for t in &tables {
            if let Some(idx) = create_index_sql(Dialect::Sqlite, t) {
                conn.execute_batch(&idx)?;
            }
        }
        conn.execute_batch("COMMIT")?;
        conn.close().map_err(|(_, e)| e)?;
        if !force && path.exists() {
            return Err(StoreError::Exists(path.display().to_string()));
        }
        if force {
            // Leftovers of the file being replaced would be applied to the new one.
            for suffix in ["-journal", "-wal", "-shm"] {
                remove_if_exists(&with_suffix(&path, suffix))?;
            }
        }
        std::fs::rename(&partial, &path)?;
        Ok(())
    }
}

/// Binds the 14 columns of `series` from `s` and executes the prepared `sql::insert_series()`.
fn insert_series_row(stmt: &mut rusqlite::Statement, s: &SeriesInfo) -> Result<(), StoreError> {
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

struct SqliteSession {
    tx: Option<SyncSender<Msg>>,
    handle: Option<JoinHandle<Result<(), StoreError>>>,
    abort: Arc<AtomicBool>,
    /// Every writer holds a clone, so `strong_count` tells whether writers are still alive.
    writers: Arc<()>,
    partial: PathBuf,
    committed: bool,
}

impl IngestSession for SqliteSession {
    fn create_tables(&self, tables: &[&'static EventTable]) -> Result<(), StoreError> {
        for t in tables {
            t.check()?;
        }
        let tx = self.tx.as_ref().ok_or(StoreError::WriterGone)?;
        let (rtx, rrx) = sync_channel(1);
        tx.send(Msg::CreateTables(tables.to_vec(), rtx))
            .map_err(|_| StoreError::WriterGone)?;
        rrx.recv().map_err(|_| StoreError::WriterGone)?
    }

    fn writer(&self) -> Result<Box<dyn BatchWriter>, StoreError> {
        let tx = self.tx.as_ref().ok_or(StoreError::WriterGone)?.clone();
        Ok(Box::new(SqliteWriter {
            tx,
            _token: self.writers.clone(),
        }))
    }

    fn finish(mut self: Box<Self>, catalog: Catalog) -> Result<(), StoreError> {
        let tx = self.tx.take().ok_or(StoreError::WriterGone)?;
        let sent = tx.send(Msg::Finish(catalog));
        drop(tx);
        let handle = self.handle.take().ok_or(StoreError::WriterGone)?;
        // The thread's own error is more useful than "gone", so it wins.
        match handle.join() {
            Ok(Ok(())) if sent.is_ok() => {
                self.committed = true;
                Ok(())
            }
            Ok(Ok(())) => Err(StoreError::WriterGone),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(StoreError::WriterGone),
        }
    }
}

impl Drop for SqliteSession {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.abort.store(true, Ordering::Relaxed);
        self.tx = None;
        // Joining would block while a writer still holds the channel open.
        if Arc::strong_count(&self.writers) == 1 {
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
        let _ = std::fs::remove_file(&self.partial);
    }
}

struct SqliteWriter {
    tx: SyncSender<Msg>,
    _token: Arc<()>,
}

impl BatchWriter for SqliteWriter {
    fn write(&mut self, batch: EventBatch) -> Result<(), StoreError> {
        batch.validate()?;
        if batch.is_empty() {
            return Ok(());
        }
        self.tx
            .send(Msg::Batch(batch))
            .map_err(|_| StoreError::WriterGone)
    }

    /// Waits until the SQLite thread has processed everything this writer sent.
    fn close(self: Box<Self>) -> Result<(), StoreError> {
        let (rtx, rrx) = sync_channel(1);
        self.tx
            .send(Msg::Flush(rtx))
            .map_err(|_| StoreError::WriterGone)?;
        rrx.recv().map_err(|_| StoreError::WriterGone)
    }
}

// ---------------------------------------------------------------------------------------------
// Read side
// ---------------------------------------------------------------------------------------------

pub(crate) fn open(path: &Path) -> Result<Box<dyn Store>, StoreError> {
    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        // Read-only files can still be browsed; derived edits will then fail.
        Err(first) => Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| first)?,
    };
    let has_meta: bool = conn.query_row(sql::SQLITE_HAS_META, [], |r| r.get(0))?;
    let found: Option<String> = if has_meta {
        conn.query_row(sql::SELECT_META_VALUE, ["schema_version"], |r| r.get(0))
            .optional()?
    } else {
        None
    };
    if found.as_deref() != Some(SCHEMA_VERSION.to_string().as_str()) {
        return Err(StoreError::UnsupportedSchema { found });
    }
    Ok(Box::new(SqliteStore { conn }))
}

struct SqliteStore {
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

/// Decodes one stored value according to the series' column type.
fn decode(ty: ColType, v: ValueRef) -> Result<DataValue, StoreError> {
    Ok(match ty {
        ColType::Bool => DataValue::Boolean(v.as_i64()? != 0),
        ColType::U8 | ColType::U16 | ColType::U32 | ColType::I64 => DataValue::Int(v.as_i64()?),
        // Stored as the i64 bit pattern; saturate what does not fit the read API's i64.
        ColType::U64 => DataValue::Int((v.as_i64()? as u64).min(i64::MAX as u64) as i64),
        ColType::F64 => match v {
            // NaN is stored as NULL (derived series only, event columns are NOT NULL).
            ValueRef::Null => DataValue::Float(f64::NAN),
            v => DataValue::Float(v.as_f64()?),
        },
        ColType::Text => DataValue::String(v.as_str()?.to_owned()),
    })
}

impl SqliteStore {
    fn get_series(&self, id: i64) -> Result<Option<SeriesInfo>, StoreError> {
        let mut stmt = self.conn.prepare_cached(&sql::select_series_by_id())?;
        let mut rows = stmt.query([id])?;
        rows.next()?.map(row_to_series).transpose()
    }

    /// Edits of derived series take the write lock up front (no upgrade failures).
    fn edit_tx(&self) -> Result<Transaction<'_>, StoreError> {
        Ok(Transaction::new_unchecked(
            &self.conn,
            TransactionBehavior::Immediate,
        )?)
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

    /// Inserts the samples; `DerivedStats::from_points` has validated the points.
    fn insert_samples(&self, id: i64, ty: ColType, points: &[DataPoint]) -> Result<(), StoreError> {
        let mut stmt = self.conn.prepare_cached(&sql::insert_derived_sample(ty))?;
        for (seq, p) in points.iter().enumerate() {
            let v: &dyn ToSql = match &p.value {
                DataValue::Int(v) => v,
                DataValue::Float(v) => v,
                DataValue::Boolean(v) => v,
                DataValue::String(v) => v,
            };
            stmt.execute(params![id, derived_ts(p.timestamp), seq as i64, v])?;
        }
        Ok(())
    }
}

impl Store for SqliteStore {
    fn engine(&self) -> Engine {
        Engine::Sqlite
    }

    fn flows(&self) -> Result<Vec<Flow>, StoreError> {
        let mut stmt = self.conn.prepare_cached(sql::SELECT_FLOWS)?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_flow(r)?);
        }
        Ok(out)
    }

    fn flow(&self, id: i64) -> Result<Option<Flow>, StoreError> {
        let mut stmt = self.conn.prepare_cached(sql::SELECT_FLOW)?;
        let mut rows = stmt.query([id])?;
        rows.next()?.map(row_to_flow).transpose()
    }

    fn series(&self, flow_id: i64) -> Result<Vec<SeriesInfo>, StoreError> {
        let mut stmt = self.conn.prepare_cached(&sql::select_series_by_flow())?;
        let mut rows = stmt.query([flow_id])?;
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
        // Inclusive bounds on integer timestamps: round the lower bound up, the upper down.
        let bounds = match range {
            Some((lo, hi)) if lo.is_nan() || hi.is_nan() => return Ok(()),
            Some((lo, hi)) => Some((lo.ceil() as i64, hi.floor() as i64)),
            None => None,
        };
        let query = match s.kind {
            SeriesKind::Raw => {
                let (Some(tbl), Some(col)) = (&s.tbl, &s.col) else {
                    return Err(StoreError::Corrupt(format!(
                        "raw series {} has no table/column",
                        s.id
                    )));
                };
                if bounds.is_some() {
                    sql::range_query(tbl, col)
                } else {
                    sql::all_points_query(tbl, col)
                }
            }
            SeriesKind::Derived => {
                if bounds.is_some() {
                    sql::derived_range_query(s.value_type)
                } else {
                    sql::derived_all_query(s.value_type)
                }
            }
        };
        let mut stmt = self.conn.prepare_cached(&query)?;
        let mut rows = match (s.kind, bounds) {
            (SeriesKind::Raw, Some((lo, hi))) => {
                stmt.query(params![s.flow_id, s.dir.code(), lo, hi])?
            }
            (SeriesKind::Raw, None) => stmt.query(params![s.flow_id, s.dir.code()])?,
            (SeriesKind::Derived, Some((lo, hi))) => stmt.query(params![s.id, lo, hi])?,
            (SeriesKind::Derived, None) => stmt.query(params![s.id])?,
        };
        while let Some(r) = rows.next()? {
            let ts: i64 = r.get(0)?;
            f(DataPoint {
                timestamp: ts as f64,
                value: decode(s.value_type, r.get_ref(1)?)?,
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
        let tx = self.edit_tx()?;
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
        let mut stmt = self.conn.prepare_cached(&sql::insert_series())?;
        insert_series_row(&mut stmt, &info)?;
        drop(stmt);
        tx.commit()?;
        Ok(info)
    }

    /// Replaces the samples and statistics; the series keeps its id and name.
    fn replace_derived(
        &self,
        existing: &SeriesInfo,
        points: &[DataPoint],
    ) -> Result<SeriesInfo, StoreError> {
        let tx = self.edit_tx()?;
        let mut info = self.stored_derived(existing)?;
        let stats = DerivedStats::from_points(points, info.value_type.value_kind())?;
        self.conn
            .prepare_cached(sql::DELETE_DERIVED_SAMPLES)?
            .execute([info.id])?;
        self.insert_samples(info.id, info.value_type, points)?;
        self.conn
            .prepare_cached(sql::UPDATE_SERIES_STATS)?
            .execute(params![
                stats.n,
                stats.t_min,
                stats.t_max,
                stats.v_min,
                stats.v_max,
                info.id
            ])?;
        tx.commit()?;
        (info.n, info.t_min, info.t_max) = (stats.n, stats.t_min, stats.t_max);
        (info.v_min, info.v_max) = (stats.v_min, stats.v_max);
        Ok(info)
    }

    fn delete_derived(&self, s: &SeriesInfo) -> Result<(), StoreError> {
        let tx = self.edit_tx()?;
        let info = self.stored_derived(s)?;
        self.conn
            .prepare_cached(sql::DELETE_DERIVED_SAMPLES)?
            .execute([info.id])?;
        self.conn
            .prepare_cached(sql::DELETE_SERIES)?
            .execute([info.id])?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
