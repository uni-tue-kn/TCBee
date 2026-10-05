//! The storage engines and the traits of the API: reading (`Store`) and writing (`IngestSession`,
//! `BatchWriter`).

use crate::batch::EventBatch;
use crate::catalog::{Catalog, SeriesInfo};
use crate::error::StoreError;
use crate::model::{DataPoint, Flow};
use crate::schema::{Dialect, EventTable, ValueKind};

/// The database engines TCBee can store flows in.
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

/// Options of [`create`](crate::create).
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateOptions {
    /// Overwrite an existing file.
    pub force: bool,
}

/// Writes a database in one pass: tables, batches from any number of writers, then `finish`.
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

/// Read access to a database. No `Send` bound: the visualizer is single-threaded.
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
