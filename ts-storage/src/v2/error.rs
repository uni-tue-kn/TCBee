use thiserror::Error;

/// Errors of the schema v2 storage API.
#[derive(Error, Debug)]
pub enum StoreError {
    /// An error reported by the SQLite engine.
    #[cfg(feature = "sqlite")]
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[cfg(feature = "duckdb")]
    #[error("DuckDB error: {0}")]
    DuckDb(#[from] duckdb::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "unsupported database schema (found version {}), reprocess the trace with tcbee-process",
        found.as_deref().unwrap_or("none")
    )]
    UnsupportedSchema { found: Option<String> },
    #[error("only derived series can be modified or deleted")]
    NotDerived,
    /// A value does not fit the schema or the series it is written to.
    #[error("type mismatch: {0}")]
    TypeMismatch(String),
    /// A series (or other row) that has to exist does not.
    #[error("not found: {0}")]
    NotFound(String),
    /// The file holds a value no writer of this crate produces (unknown kind, dir or type code,
    /// unparsable address).
    #[error("corrupt database: {0}")]
    Corrupt(String),
    #[error("database file already exists: {0}")]
    Exists(String),
    #[error("file is neither a SQLite nor a DuckDB database")]
    UnknownEngine,
    #[error("the {0:?} engine is not enabled in this build")]
    EngineDisabled(super::Engine),
    #[error("the writer thread is gone")]
    WriterGone,
}

#[cfg(feature = "sqlite")]
impl From<rusqlite::types::FromSqlError> for StoreError {
    /// A stored value that cannot be read as the requested type.
    fn from(e: rusqlite::types::FromSqlError) -> StoreError {
        StoreError::Sqlite(e.into())
    }
}
