use thiserror::Error;

/// Errors of the schema v2 storage API.
#[derive(Error, Debug)]
pub enum StoreError {
    /// An error reported by the SQLite engine. Boxed because the `rusqlite` dependency cannot
    /// be added while the old `sqlite` crate is linked (both link libsqlite3).
    #[error("SQLite error: {0}")]
    Sqlite(Box<dyn std::error::Error + Send + Sync>),
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
    #[error("type mismatch: {0}")]
    TypeMismatch(String),
    #[error("database file already exists: {0}")]
    Exists(String),
    #[error("file is neither a SQLite nor a DuckDB database")]
    UnknownEngine,
    #[error("the {0:?} engine is not enabled in this build")]
    EngineDisabled(super::Engine),
    #[error("the writer thread is gone")]
    WriterGone,
}
