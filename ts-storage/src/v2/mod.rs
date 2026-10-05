//! Schema v2 storage API. Lives next to the old `TSDBInterface` until its callers have moved.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::{DataPoint, Flow};

pub mod batch;
pub mod catalog;
#[cfg(feature = "duckdb")]
pub mod duckdb;
pub mod error;
pub mod schema;
pub mod sql;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod time;
#[cfg(test)]
pub(crate) mod testutil;

pub use batch::{ColumnData, EventBatch};
pub use catalog::{Catalog, SeriesInfo, StatsAccumulator};
pub use error::StoreError;
pub use schema::{
    ColType, Column, Dialect, Dir, EventTable, SeriesKind, Table, ValueKind, SCHEMA_VERSION,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Sqlite,
    DuckDb,
}

impl Engine {
    /// Whether this build includes the engine (cargo features `sqlite` and `duckdb`).
    pub fn is_enabled(self) -> bool {
        match self {
            Engine::Sqlite => cfg!(feature = "sqlite"),
            Engine::DuckDb => cfg!(feature = "duckdb"),
        }
    }

    pub fn dialect(self) -> Dialect {
        match self {
            Engine::Sqlite => Dialect::Sqlite,
            Engine::DuckDb => Dialect::DuckDb,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CreateOptions {
    /// Overwrite an existing file.
    pub force: bool,
}

/// Creates a database file. Sessions write to `<path>.partial` and rename it to `path` in
/// `finish`; dropping a session without `finish` deletes the partial file.
pub fn create(
    engine: Engine,
    path: &Path,
    opts: CreateOptions,
) -> Result<Box<dyn IngestSession>, StoreError> {
    if !engine.is_enabled() {
        return Err(StoreError::EngineDisabled(engine));
    }
    match engine {
        #[cfg(feature = "sqlite")]
        Engine::Sqlite => sqlite::create(path, opts),
        #[cfg(not(feature = "sqlite"))]
        Engine::Sqlite => unreachable!("checked by is_enabled"),
        #[cfg(feature = "duckdb")]
        Engine::DuckDb => duckdb::create(path, opts),
        #[cfg(not(feature = "duckdb"))]
        Engine::DuckDb => unreachable!("checked by is_enabled"),
    }
}

pub trait IngestSession: Send + Sync {
    fn create_tables(&self, tables: &[&'static EventTable]) -> Result<(), StoreError>;
    /// Called on the worker thread that will use the writer. Writers are not `Send`.
    fn writer(&self) -> Result<Box<dyn BatchWriter>, StoreError>;
    /// After all writers are closed: writes flows, series, meta, builds indexes, checkpoints, renames.
    fn finish(self: Box<Self>, catalog: Catalog) -> Result<(), StoreError>;
}

pub trait BatchWriter {
    fn write(&mut self, batch: EventBatch) -> Result<(), StoreError>;
    /// Flushes and surfaces deferred errors.
    fn close(self: Box<Self>) -> Result<(), StoreError>;
}

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Reads the first 16 bytes of the file and recognizes SQLite ("SQLite format 3\0") and DuckDB
/// ("DUCK" at offset 8).
pub fn detect_engine(path: &Path) -> Result<Engine, StoreError> {
    let mut header = Vec::with_capacity(16);
    File::open(path)?.take(16).read_to_end(&mut header)?;
    if header == SQLITE_MAGIC.as_slice() {
        Ok(Engine::Sqlite)
    } else if header.get(8..12) == Some(&b"DUCK"[..]) {
        Ok(Engine::DuckDb)
    } else {
        Err(StoreError::UnknownEngine)
    }
}

/// Detects the engine, opens the file and checks `meta.schema_version == 2`.
pub fn open(path: &Path) -> Result<Box<dyn Store>, StoreError> {
    let engine = detect_engine(path)?;
    if !engine.is_enabled() {
        return Err(StoreError::EngineDisabled(engine));
    }
    match engine {
        #[cfg(feature = "sqlite")]
        Engine::Sqlite => sqlite::open(path),
        #[cfg(not(feature = "sqlite"))]
        Engine::Sqlite => unreachable!("checked by is_enabled"),
        #[cfg(feature = "duckdb")]
        Engine::DuckDb => duckdb::open(path),
        #[cfg(not(feature = "duckdb"))]
        Engine::DuckDb => unreachable!("checked by is_enabled"),
    }
}

/// No `Send` bound: the visualizer is single-threaded.
pub trait Store {
    fn engine(&self) -> Engine;
    fn flows(&self) -> Result<Vec<Flow>, StoreError>;
    fn flow(&self, id: i64) -> Result<Option<Flow>, StoreError>;
    fn series(&self, flow_id: i64) -> Result<Vec<SeriesInfo>, StoreError>;
    fn series_by_id(&self, id: i64) -> Result<Option<SeriesInfo>, StoreError>;
    /// Points ordered by (ts, seq). `range` is inclusive, in f64 ns.
    fn for_each_point(
        &self,
        s: &SeriesInfo,
        range: Option<(f64, f64)>,
        f: &mut dyn FnMut(DataPoint),
    ) -> Result<(), StoreError>;
    fn create_derived(
        &self,
        flow_id: i64,
        name: &str,
        ty: ValueKind,
        points: &[DataPoint],
    ) -> Result<SeriesInfo, StoreError>;
    /// Delete + create in one transaction. Only `kind = derived` series can be replaced or deleted.
    fn replace_derived(
        &self,
        existing: &SeriesInfo,
        points: &[DataPoint],
    ) -> Result<SeriesInfo, StoreError>;
    fn delete_derived(&self, s: &SeriesInfo) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ts_storage_v2_{}_{}", std::process::id(), name));
        File::create(&p).unwrap().write_all(bytes).unwrap();
        p
    }

    #[test]
    fn engine_detection() {
        let mut sqlite = SQLITE_MAGIC.to_vec();
        sqlite.extend([0u8; 100]);
        let mut duck = vec![0u8; 8];
        duck.extend(b"DUCK");
        duck.extend([1u8; 20]);

        let a = tmp("sqlite", &sqlite);
        let b = tmp("duck", &duck);
        let c = tmp("junk", b"hello world, not a db at all");
        let d = tmp("empty", b"");
        assert_eq!(detect_engine(&a).unwrap(), Engine::Sqlite);
        assert_eq!(detect_engine(&b).unwrap(), Engine::DuckDb);
        assert!(matches!(detect_engine(&c), Err(StoreError::UnknownEngine)));
        assert!(matches!(detect_engine(&d), Err(StoreError::UnknownEngine)));
        assert!(matches!(
            detect_engine(Path::new("/nonexistent/ts_storage_v2")),
            Err(StoreError::Io(_))
        ));
        assert_eq!(Engine::Sqlite.is_enabled(), cfg!(feature = "sqlite"));
        for p in [a, b, c, d] {
            let _ = std::fs::remove_file(p);
        }
    }
}
