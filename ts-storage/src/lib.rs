//! Storage layer of TCBee: reads and writes TCBee flow databases on SQLite or DuckDB behind one API.
//!
//! [`create`] starts writing a database, [`open`] reads one; the engine of an existing file is
//! detected from its header. The cargo features `sqlite` and `duckdb` select the engines.

use std::fs::File;
use std::io::Read;
use std::path::Path;

pub mod batch;
pub mod catalog;
#[cfg(feature = "duckdb")]
pub mod duckdb;
pub mod error;
pub mod model;
pub mod schema;
pub mod sql;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod store;
#[cfg(test)]
pub(crate) mod testutil;
pub mod time;

pub use batch::{ColumnData, EventBatch};
pub use catalog::{Catalog, SeriesInfo, StatsAccumulator};
pub use error::StoreError;
pub use model::{DataPoint, DataValue, Flow, IpTuple};
pub use schema::{
    ColType, Column, Dialect, Dir, EventTable, SeriesKind, Table, ValueKind, SCHEMA_VERSION,
};
pub use store::{BatchWriter, CreateOptions, Engine, IngestSession, Store};

/// Creates a database file. Sessions write to `<path>.partial` and rename it to `path` in
/// `finish`; dropping a session without `finish` deletes the partial file.
pub fn create(
    engine: Engine,
    path: &Path,
    opts: CreateOptions,
) -> Result<Box<dyn IngestSession>, StoreError> {
    match engine {
        #[cfg(feature = "sqlite")]
        Engine::Sqlite => sqlite::create(path, opts),
        #[cfg(feature = "duckdb")]
        Engine::DuckDb => duckdb::create(path, opts),
        #[allow(unreachable_patterns)] // every engine is built in
        _ => Err(StoreError::EngineDisabled(engine)),
    }
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
    match engine {
        #[cfg(feature = "sqlite")]
        Engine::Sqlite => sqlite::open(path),
        #[cfg(feature = "duckdb")]
        Engine::DuckDb => duckdb::open(path),
        #[allow(unreachable_patterns)] // every engine is built in
        _ => Err(StoreError::EngineDisabled(engine)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ts_storage_{}_{}", std::process::id(), name));
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
            detect_engine(Path::new("/nonexistent/ts_storage")),
            Err(StoreError::Io(_))
        ));
        assert_eq!(Engine::Sqlite.is_enabled(), cfg!(feature = "sqlite"));
        for p in [a, b, c, d] {
            let _ = std::fs::remove_file(p);
        }
    }
}
