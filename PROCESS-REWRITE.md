# `tcbee-process` and `ts-storage` rewrite plan

Status: design reviewed and decided (2026-10-05); implementation not started. Part A is the design and
the reasons for it, Part B the work packages for implementation agents. Agents implement against
Part B and treat Part A as the specification; when the code forces a deviation, update this file in
the same commit.

## Status

Updated by the orchestrating session after every step. Branch `process-rewrite` (from `dev`).
If a session died, resume from the first unchecked package; `git log` shows what is committed.

- Source traces in `/tmp/tcbee_2026-10-05T*` are gone (reboot). WP0 fixtures are generated with the
  helper; WP9 cannot compare against the 300 MB trace and uses a synthetic one.

| WP | State |
| --- | --- |
| WP0 fixtures | done, reviewed, committed |
| WP1 ts-storage core | done, reviewed, committed |
| WP2 bindings macro + decoder | done, reviewed, committed |
| WP3 SQLite engine | done, reviewed, committed |
| WP4 DuckDB engine | done, reviewed, committed |
| WP5 contract tests | done, reviewed, committed |
| WP6 pipeline | done, reviewed, committed |
| WP7 viz migration | done, reviewed, committed (GUI never run by an agent) |
| WP8 cleanup, docs, build time | implementing (agent running) |
| WP9 benchmarks | not started |

Log (newest last):

- 2026-10-05: branch created.
- 2026-10-05: a real trace was recorded (`~/tcbee-traces/tcbee_2026-10-05T18-16-22`, 110 MB, no bbr, no tcp6); WP0 fixtures use its first 2000 records per file plus generated bbr/cwnd/tcp6. WP9 can use it as the benchmark input.
- 2026-10-05: WP0 done, correctness and style review fixed.
- 2026-10-05: WP1 written (v2 types, schema renderer, features); WP2 started in parallel.
- 2026-10-05: WP1 reviewed and committed. WP2 written and in review; WP3 and WP4 started in parallel (separate files). No InfluxDB work (out of scope, A7).
- 2026-10-05: WP2 reviewed and committed. Waiting on WP3 and WP4.
- 2026-10-05: WP3 and WP4 written and under review. WP4 measured cached appender 34 M values/s vs 14.5 M per-batch, so writers keep one cached appender per table (uses one `unsafe` lifetime transmute). WP3 deleted the old SQLite backend (those deletions landed in the WP2 commit by accident). Review settled the inconsistency: both engines keep the series id on `replace_derived`, ids start at 1, a missing series is `NotFound`, NaN in event f64 columns is rejected by `EventBatch::validate`. Shared helpers live in `v2/{time,catalog,sql}.rs`.
- 2026-10-05: WP3 and WP4 committed; WP5 and WP6 started in parallel.
- 2026-10-05: a 294 MB trace (`~/tcbee-traces/tcbee_2026-10-05T18-52-18`: cubic 8.6 MB, recv_sock 104, send_sock 67, tcp4 23+15, tcp_probe 76; no bbr/tcp6) is the WP9 benchmark input. It is cubic-only, so compare with the A1 numbers by file size, not record mix.
- 2026-10-05: WP6 first run (release, SQLite only, 16 cores): 110 MB trace 3.4 s / 76 MB RSS / 91 MiB output; 294 MB trace 5.2 s (1.9 s after last worker) / 124 MB RSS / 247 MiB output. WP5 found one engine difference: SQLite drops the sign of -0.0, DuckDB keeps it (accepted, documented by an ignored test).
- 2026-10-05: WP5 committed (90 contract tests on both engines). WP6 committed after review fixes (row counting checked against records, abort checks every 4096 records, failure-path tests); WP7 running. Legacy `ts-storage/tests/duckdb.rs` fails on re-runs when `db_duck_test.duck` is left over; it is deleted in WP8.
- 2026-10-05: WP7 written, uncommitted in `tcbee-viz`. Both review agents died on a usage limit and were relaunched. Next after WP7: WP8, WP9.
- 2026-10-05: WP7 reviewed (real tcbee-process output opened through the viz data layer on both engines: no panics, bindings correct); committed after review fixes. Deferred, to go into CLAUDE.md open work in WP8: SenderLimitation inputs (tcp_probe SND_* vs sock advmss) are zipped by index although their timestamps differ; `preprocessing.rs` `time_granularity_ms` is treated as ms->s although timestamps are ns; NaN in derived float series plots as NaN; flow ids differ between runs (thread order), by design.

Decisions made by the maintainer:

- **Wide event tables**: one table per trace record type, one row per record, one typed column per
  field. Only series created by the visualizer use a narrow table.
- **No v1 compatibility**: databases written by the current code are not read, migrated or
  converted. Opening one fails with "schema v1 is not supported, reprocess the trace with
  tcbee-process". Raw traces are the source of truth.
- **Selectable engines, minimal DuckDB rebuilds** (added during implementation): building DuckDB is
  slow, so `ts-storage` has cargo features `sqlite` and `duckdb` (default: both), forwarded as
  features of `tcbee-process` and `tcbee-viz`. A build without `duckdb` never compiles
  `libduckdb-sys`; opening a file of a disabled engine returns a clear error. `libduckdb-sys` must
  be rebuilt only when unavoidable: all three crates use the same feature set and flags, and WP8
  evaluates a cargo workspace with one shared `target/` (today each crate has its own `target/` and
  `Cargo.lock`, so DuckDB compiles three times), linking a system libduckdb instead of `bundled`
  for development (`DUCKDB_LIB_DIR`), and documents it in the READMEs and CI.

---

# Part A: design

## A1. Why: findings on the current code

Measured on the two traces in `/tmp` (16 cores, system DuckDB 1.4.3, SQLite 3.53.4):

| Trace | Records | Rows today | Backend | Read phase | Tail after readers finish | Peak RSS | File |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 15-01-43 (39 MB) | 432 k | 4.43 M | DuckDB | 2.0 s | 30.1 s | 755 MB | 273 MB |
| 15-01-43 | | | SQLite | 1.5 s | 7.6 s | 749 MB | 185 MB |
| 14-49-29 (300 MB) | 3.04 M | 40.8 M | DuckDB | 17.3 s | 302.6 s | 2.47 GB | 2.6 GB |
| 14-49-29 | | | SQLite | 13.4 s | 74.5 s | 2.70 GB | 1.8 GB |

About 94 % of the wall time comes after the readers finish: most series never reach the 100 k flush
threshold, so the whole trace stays in memory as `DataPoint`s and is written at the end.

Correctness bugs (verified on processed files):

1. **DuckDB stores every value as a string.** `val_to_union` appends a VARCHAR such as
   `{'inum': 10}`, which the cast puts into the `str` member of the UNION. All 4.4 M values in the
   small trace have `union_tag = 'str'`. The y-bounds query sorts these as text (it reports a
   `snd_cwnd` max of 98 where the real max is 220). The `inum` member is 32 bit, so u32/u64 values
   would not fit in it anyway.
2. **SQLite stops reading a series at the first `-1`.** The cursor treats `-1` as "not this column",
   falls through to a NULL text read and ends the iterator. `max_pacing_rate = u64::MAX` becomes
   `-1` through `as i64`, so this happens 107,875 times in the small trace.
3. **Send and receive samples are merged.** `send_sock`/`recv_sock` and `send_cwnd`/`recv_cwnd`
   share the binding struct, the field names and the flow tuple orientation. Both directions are
   written into one series (`snd_cwnd`, 67,168 points next to 33,573 for `SND_CWND`). About 24 % of
   consecutive points in such a series go backwards in time.
4. **The SQLite bulk insert is built from formatted literals.** Strings are not quoted (derived
   String series cannot be saved), and an empty batch produces `VALUES;`. A series whose length is
   an exact multiple of 100,000 panics at the final flush.
5. **Failures are silent.** Reader and writer join results are discarded, `add_event` errors are
   logged and the event dropped, and panics in readers or flushes still exit with status 0. A
   `read_exact` error, including a truncated last record, counts as EOF.
6. **Timestamps are `f64` nanoseconds since boot.** These are exact only up to 2^53 ns, about
   104 days of uptime.
7. The `(series, timestamp)` primary key has not fired on these traces. With merged send/recv series
   or long uptimes it can, and that panics the flush.

What costs the time (prototype measurements on synthetic data, 20 M values, single thread unless noted):

| Change | DuckDB rows/s | SQLite rows/s |
| --- | --- | --- |
| Today: UNION from a string, PK + FK | 0.12 M | 0.58 M |
| Narrow typed columns, no PK | 3.0 M | 2.2 M |
| Narrow, Arrow `append_record_batch`, no PK | 8.1 M | n/a |
| **Wide table (25 columns), Arrow, no PK** | **25.9 M value-equivalents** | **19 M** (prepared, 1 transaction) |
| Wide, with PK `(flow, ts)` | 12.3 M | 12.4 M |
| Narrow Arrow, 4 connections into one table | 26.2 M | n/a (one writer) |

The ranked causes: the string-to-UNION cast (about 14× on DuckDB), the unique key on sample rows
(about 4× on both engines), row-by-row instead of Arrow appends (2.7×), and the narrow model itself
(3× on DuckDB, 8.5× on SQLite). Session pragmas and row sorting matter little. After these fixes
decode is roughly 30–50 % of the work, so it must not allocate per field. Several DuckDB connections
(`try_clone`) appending to the same table work and scale almost linearly up to 4.

Reads on DuckDB without any index, 20 M rows: a whole series takes 9 ms, a 10 % time range 3 ms.
Zonemaps on `ts` are enough; no sort or index is needed at this size.

## A2. Data model (schema version 2)

The same logical schema is used on both engines. Only column types and index timing differ, and both
are produced by one renderer from Rust definitions (A3). Identifiers are lower case, except event
columns, which keep today's series names verbatim (`SND_CWND`, `perf_snd_cwnd`, `bic_K`) and are
therefore always quoted. Every SQL identifier comes from a static Rust definition; nothing
user-supplied is ever spliced into SQL.

```text
meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)
    schema_version = '2', writer = 'tcbee-process <version>', trace_dir, created_at

flows(id BIGINT PRIMARY KEY, src TEXT NOT NULL, dst TEXT NOT NULL,
      sport INTEGER NOT NULL, dport INTEGER NOT NULL, l4proto INTEGER NOT NULL,
      UNIQUE(src, dst, sport, dport, l4proto))

series(id BIGINT PRIMARY KEY, flow_id BIGINT NOT NULL,
       kind INTEGER NOT NULL,      -- 0 = raw, 1 = derived
       source TEXT NOT NULL,       -- 'sock', 'tcp_probe', 'cwnd', 'cubic', 'bbr', 'tcp4', 'tcp6' | 'derived'
       dir INTEGER NOT NULL,       -- 0 = none, 1 = send, 2 = recv
       name TEXT NOT NULL,         -- bare field name as today ('snd_cwnd', 'SND_UNA', ...)
       value_type INTEGER NOT NULL,-- ColType code (A3)
       tbl TEXT, col TEXT,         -- raw only: event table and column
       n BIGINT NOT NULL, t_min BIGINT, t_max BIGINT, v_min DOUBLE, v_max DOUBLE,
       UNIQUE(flow_id, source, dir, name))

ev_<source>(flow_id BIGINT NOT NULL, dir TINYINT NOT NULL, ts BIGINT NOT NULL, seq BIGINT NOT NULL,
            <one column per binding field, named as today's series, native type>)
    ev_sock (25 fields), ev_tcp_probe (10), ev_cwnd (1), ev_cubic (14), ev_bbr (12),
    ev_tcp4 (4), ev_tcp6 (4)

derived_samples(series_id BIGINT NOT NULL, ts BIGINT NOT NULL, seq BIGINT NOT NULL,
                v_int BIGINT, v_float DOUBLE, v_bool BOOLEAN, v_text TEXT)
    -- exactly one value column is non-NULL, matching series.value_type
```

Rules:

- `ts` is `i64` nanoseconds (the recorder's `bpf_ktime_get_ns` value), stored exactly. The read API
  keeps returning `f64` nanoseconds, as today, so the visualizer's units do not change.
- `seq` is the record's index in its trace file. `(flow_id, dir, ts, seq)` orders every event table
  totally, so duplicate timestamps are kept and read back in a stable order. No sample table has a
  unique key; the policy is "keep every recorded sample".
- `dir` comes from the trace file, not from the record:

  | `TraceFile` | source | dir |
  | --- | --- | --- |
  | `SendSock` / `RecvSock` | sock | send / recv |
  | `SendCwnd` / `RecvCwnd` | cwnd | send / recv |
  | `Tcp4Send` / `Tcp4Receive` | tcp4 | send / recv |
  | `Tcp6Send` / `Tcp6Receive` | tcp6 | send / recv |
  | `TcpProbe`, `Cubic`, `Bbr` | tcp_probe, cubic, bbr | none |
  | `TcpRetransmitSynack`, `TcpBadCsum` | skipped (no binding) | |

  Empty (0-byte) trace files exist in real recordings and produce no work units.
- A raw series is one column of one `(flow, source, dir)` group. The catalog row is written only if
  at least one row of the group exists. `name` stays the bare field name, because the visualizer
  matches on it (A6). Send and receive become two series with the same name and different `dir`.
- Value types: DuckDB uses native `BOOLEAN, UTINYINT, USMALLINT, UINTEGER, UBIGINT, BIGINT, DOUBLE,
  VARCHAR`. SQLite uses `INTEGER`/`REAL`/`TEXT`; u64 values are stored as their `i64` bit pattern
  and converted back on read using `series.value_type`, so storage is lossless on both engines.
  `DataValue::Int` is `i64`; the read API saturates u64 values above `i64::MAX` (for example
  `max_pacing_rate = u64::MAX`, which means "unlimited") to `i64::MAX`, identically on both engines.
- Statistics (`n`, `t_min`, `t_max`, `v_min`, `v_max`) are computed in Rust while ingesting and
  written to the catalog at the end. They describe the values the read API returns, so u64 values
  are saturated to `i64::MAX` before entering `v_min`/`v_max`. Derived-series writes compute them too. Bounds and counts are
  then catalog lookups instead of the visualizer's 2–6 queries per series. `v_min`/`v_max` are
  NULL for text series; boolean series use 0/1.
- No foreign keys anywhere: they cost on every appended row and add nothing in a file the program
  writes once. Referential integrity is a contract test.
- Indexes: DuckDB builds none on event tables or `derived_samples`; `PRIMARY KEY`/`UNIQUE` exist
  only on `meta`, `flows` and `series`. SQLite builds `ev_x(flow_id, dir, ts, seq)` per event table
  **after** the load, and `derived_samples(series_id, ts, seq)` when the table is created.
- `flow_attributes` is dropped: nothing writes or reads it today. Re-add it when there is a user.
- Flow and series IDs are assigned in Rust. Flow IDs follow discovery order, which varies with the
  thread schedule. Series IDs are sorted by (flow id, source, dir, column order), so they are only
  deterministic for a given flow numbering. Tests compare flows by tuple and series by
  `(tuple, source, dir, name)`, never by ID.
- Flow identity is ported byte for byte from today's `get_ip_tuple` implementations, without
  unifying them: sock/cwnd test `family == AF_INET`, cubic/bbr test `addr_v4 != 0`, tcp4 uses
  `Ipv4Addr::from(u32)`, v4-mapped tcp6 addresses become V4 tuples (`ip.rs`), ports are stored as
  read (unswapped; `examples/db` relies on it), `l4proto` is 6.
- Conversions between the `f64` read API and `i64` storage: inclusive range bounds use `ceil` for
  the lower and `floor` for the upper bound; derived-series timestamps use `round`.

## A3. Schema in Rust instead of SQL string files

No SQL builder crate fits: SeaQuery has no DuckDB backend and its Postgres DDL uses identity columns
DuckDB lacks; diesel and sqlx do not support DuckDB. The schema is small and static, so it is
described with plain Rust data and rendered by about 150 lines of code:

```rust
// ts-storage/src/schema.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ColType { Bool = 0, U8 = 1, U16 = 2, U32 = 3, U64 = 4, I64 = 5, F64 = 6, Text = 7 }

pub struct Column { pub name: &'static str, pub ty: ColType }

pub struct EventTable {
    pub source: &'static str,          // "sock"; the table is "ev_" + source
    pub columns: &'static [Column],    // binding fields, without the four fixed columns
}

pub enum Dialect { Sqlite, DuckDb }
pub fn create_table_sql(d: Dialect, t: &EventTable) -> String;
pub fn create_index_sql(d: Dialect, t: &EventTable) -> Option<String>;   // SQLite only
// fixed tables (meta, flows, series, derived_samples) are also `Table` values rendered the same way
```

The binding structs declare their schema with one declarative macro in `tcbee-process`. It replaces
`EventIndexer::get_field`/`get_field_name`/`get_default_field`/`get_max_index` and the hand-written
match arms:

```rust
event_schema! {
    sock_trace_entry => "sock" {
        pacing_rate => "pacing_rate": U64, max_pacing_rate => "max_pacing_rate": U64, /* ... */
    }
    cwnd_trace_entry => "cwnd" { snd_cwnd => "perf_snd_cwnd": U32 }
    TcpProbe => "tcp_probe" { ssthresh => "SSTRESH": U32, /* typo kept: it is today's name */ }
    Tcp4Packet => "tcp4" { seq => "SEQ_NUM": U32, /* ... */ }
}
// generates: impl Event for sock_trace_entry {
//     const TABLE: &'static EventTable = &EventTable { source: "sock", columns: &[...] };
//     fn push_row(&self, b: &mut EventBatch) { b.u64(0).push(self.pacing_rate); ... }
// }
```

`Event` (in `tcbee-process`) also provides `flow_key()`, `ts_ns()` and `check_divider()`, which stay
hand-written per binding. The column name is today's `get_field_name` string verbatim (mixed case,
renames and the `SSTRESH` typo included), because the visualizer and `examples/db` match on it. The
macro is the only place a column name is spelled. A unit test checks for every binding that
`push_row` fills every column exactly once with the declared type, and that no column name equals
`flow_id`, `dir`, `ts` or `seq` case-insensitively. Every `get_field` today is a plain `as i64`
cast, so the column type is simply the struct field's type.

Queries that are not DDL (catalog reads, range reads, derived edits) are portable between the two
engines (both accept `?` parameters and `ON CONFLICT`). They live once in `ts-storage/src/sql.rs` as
functions that take the identifiers from the schema, for example
`range_query(tbl, col) -> String` producing
`SELECT ts, "col" FROM "tbl" WHERE flow_id = ? AND dir = ? AND ts >= ? AND ts <= ? ORDER BY ts, seq`.
Engine modules only bind parameters, map rows and implement bulk ingest.

`ts-storage` stays generic: it knows `EventTable`, `ColType`, `EventBatch` and the catalog, but not
the binding structs. Readers learn table and column names from the `series` rows, not from Rust.

## A4. Storage API

Replaces `TSDBInterface`, `DBBackend`, `database_factory`, `Condition`, `TSBounds`, `FlowAttribute`
and both `queries.rs` files.

```rust
// ingest batch: column-oriented, owned by ts-storage
pub struct EventBatch {
    table: &'static EventTable,
    flow_id: Vec<i64>, dir: Vec<u8>, ts: Vec<i64>, seq: Vec<i64>,
    cols: Vec<ColumnData>,            // one per table column, typed per ColType
}
pub enum ColumnData { Bool(Vec<bool>), U8(Vec<u8>), U16(Vec<u16>), U32(Vec<u32>),
                      U64(Vec<u64>), I64(Vec<i64>), F64(Vec<f64>), Text(Vec<String>) }
impl EventBatch {
    pub fn new(table: &'static EventTable, capacity: usize) -> Self;
    pub fn push_header(&mut self, flow_id: i64, dir: Dir, ts: i64, seq: i64);
    pub fn u64(&mut self, col: usize) -> &mut Vec<u64>;   // one accessor per ColType; panics on a type mismatch
    pub fn len(&self) -> usize;
    pub fn approx_bytes(&self) -> usize;
}

pub enum Engine { Sqlite, DuckDb }
pub struct CreateOptions { pub force: bool }

/// Writes to `<path>.partial` and renames to `path` in `finish`. Dropping it without `finish`
/// deletes the partial file.
pub fn create(engine: Engine, path: &Path, opts: CreateOptions) -> Result<Box<dyn IngestSession>, StoreError>;

pub trait IngestSession: Send + Sync {
    fn create_tables(&self, tables: &[&'static EventTable]) -> Result<(), StoreError>;
    /// Called on the worker thread that will use the writer. Writers are not `Send`.
    fn writer(&self) -> Result<Box<dyn BatchWriter>, StoreError>;
    /// After all writers are closed: writes flows, series, meta, builds indexes, checkpoints, renames.
    fn finish(self: Box<Self>, catalog: Catalog) -> Result<(), StoreError>;
}
pub trait BatchWriter {
    fn write(&mut self, batch: EventBatch) -> Result<(), StoreError>;
    fn close(self: Box<Self>) -> Result<(), StoreError>;   // flushes, surfaces deferred errors
}

/// `meta` holds caller entries (writer, trace_dir); ts-storage adds schema_version and created_at.
pub struct Catalog { pub flows: Vec<Flow>, pub series: Vec<SeriesInfo>, pub meta: Vec<(String, String)> }

/// Detects the engine from the file header (SQLite "SQLite format 3\0", DuckDB "DUCK" at offset 8),
/// checks meta.schema_version == 2.
pub fn open(path: &Path) -> Result<Box<dyn Store>, StoreError>;

pub trait Store {                     // no Send bound: the visualizer is single-threaded
    fn engine(&self) -> Engine;
    fn flows(&self) -> Result<Vec<Flow>, StoreError>;
    fn flow(&self, id: i64) -> Result<Option<Flow>, StoreError>;
    fn series(&self, flow_id: i64) -> Result<Vec<SeriesInfo>, StoreError>;
    fn series_by_id(&self, id: i64) -> Result<Option<SeriesInfo>, StoreError>;
    /// Points ordered by (ts, seq). `range` is inclusive, in f64 ns.
    fn for_each_point(&self, s: &SeriesInfo, range: Option<(f64, f64)>,
                      f: &mut dyn FnMut(DataPoint)) -> Result<(), StoreError>;
    fn create_derived(&self, flow_id: i64, name: &str, ty: ValueKind, points: &[DataPoint])
        -> Result<SeriesInfo, StoreError>;
    /// Delete + create in one transaction. Only `kind = derived` series can be replaced or deleted.
    fn replace_derived(&self, existing: &SeriesInfo, points: &[DataPoint]) -> Result<SeriesInfo, StoreError>;
    fn delete_derived(&self, s: &SeriesInfo) -> Result<(), StoreError>;
}

pub struct SeriesInfo { pub id: i64, pub flow_id: i64, pub kind: SeriesKind, pub source: String,
                        pub dir: Dir, pub name: String, pub value_type: ColType,
                        pub tbl: Option<String>, pub col: Option<String>,
                        pub n: i64, pub t_min: Option<i64>, pub t_max: Option<i64>,
                        pub v_min: Option<f64>, pub v_max: Option<f64> }
```

Kept from today, under the same names: `IpTuple`, `Flow`,
`DataValue`, `DataPoint` (`timestamp: f64`). `ValueKind` is the four `DataValue` kinds for derived
series.

Notes:

- `for_each_point` takes a callback instead of returning an iterator. It avoids the self-referencing
  cursor structs (ouroboros) and makes every decode or SQL error a returned `Err` instead of an
  early end of iteration.
- `Store` methods take `&self`; transactions use `unchecked_transaction()` (rusqlite and duckdb
  both have it).
- Derived series get `source = 'derived'`, `dir = none`, so they never collide with raw names, and
  `UNIQUE(flow_id, source, dir, name)` makes a second derived series with the same name an error.
- Crates: `rusqlite` replaces `sqlite` (prepared/cached statements, `Transaction` with rollback on
  drop, `Option<T>` reads, `bundled`). `duckdb` gets the `appender-arrow` feature; Arrow types come
  from the `duckdb::arrow` re-export so the versions cannot drift. `ouroboros` is removed. The
  `ts_storage/bundled` feature keeps working and now enables `duckdb/bundled` and
  `rusqlite/bundled`.

Engine implementations:

- **DuckDB**: one `Connection`, kept in a `Mutex` inside the session for metadata and for
  `try_clone()`. `writer()` clones a connection on the calling thread. `BatchWriter::write` converts
  the batch into an Arrow `RecordBatch` (the `Vec`s move into Arrow arrays without a copy) and
  appends it through an appender on `ev_<source>`. Creating an appender per batch is allowed if
  the benchmark shows no cost (it avoids storing a borrowing appender next to its connection);
  otherwise cache one appender per table with ouroboros. `close` flushes and returns flush errors.
  `finish` writes the catalog in one transaction and runs `CHECKPOINT`. Dropping the session
  without `finish` removes both `<path>.partial` and `<path>.partial.wal`.
- **SQLite**: one writer thread owns the only `rusqlite::Connection` during ingest; `create_tables`
  and `finish` are control messages to that thread. `writer()` returns a handle that
  sends batches through a bounded `std::sync::mpsc::sync_channel` (capacity 8). The thread inserts
  with one cached prepared statement per table inside a transaction, committing every 1 M rows.
  `finish` closes the channel, joins the thread (its error wins), writes the catalog, creates the
  indexes, commits, and renames the file. Pragmas: defaults except `journal_mode=OFF` and
  `synchronous=OFF` for the partial file, since a failed run deletes it anyway (measured gain is
  small but it is free).

## A5. Processing pipeline

```text
trace files ──split into work units (file, record range ≤ 1 M records)──▶ shared queue
                                                                            │
   worker threads (std::thread::scope, N = --threads, default available_parallelism)
     pread 4 MiB chunks ▶ decode record (bincode) ▶ check divider ▶ flow id (registry)
     ▶ push_row into EventBatch for the unit's table (64 k rows) ▶ BatchWriter::write
     ▶ update worker-local stats per (flow, source, dir) and column
                                                                            │
   main thread: join workers ▶ merge stats ▶ build Catalog ▶ session.finish
```

- No tokio. Workers use `std::thread::scope`; the queue is a `Vec<WorkUnit>` with an `AtomicUsize`
  index. A unit knows its file, binding type, `dir`, record range and so the `seq` of its first
  record.
- Reading uses `FileExt::read_exact_at` on 4 MiB chunks of whole records, so no `mmap`/`unsafe`.
  Decoding keeps bincode (measured not to be the bottleneck) but decodes in place from the chunk,
  without a per-record `Vec`.
- A truncated last record (file size not a multiple of `ENTRY_SIZE`) is a warning with the byte count
  in the final summary, not an error, since stopping the recorder can cut a write. A divider mismatch
  or a bincode error is an error naming the file and offset.
- `FlowRegistry`: `Mutex<HashMap<IpTuple, i64>>` behind a worker-local `HashMap` cache. New flows
  are rare, so contention does not matter.
- Memory is bounded by `(threads + channel capacity) × batch size`, plus the stats maps. There is no
  per-series buffering and nothing is deferred to the end: the tail after the last worker is the
  final flush, catalog write, SQLite index build and checkpoint.
- Errors: every worker returns `Result`. The first error sets a shared `AtomicBool`; the others
  stop at their next batch. `main` joins everything, drops the session (which deletes the partial
  file), prints the first error with context and exits with status 1. Panics in workers are joined
  and reported the same way.
- `TcpRetransmitSynack` and `TcpBadCsum` stay unsupported (logged as skipped), as today. With the
  macro, adding them later is a binding plus one `event_schema!` block.
- Progress: one indicatif bar per trace file, advanced by the workers, plus a final summary line
  (records, rows, flows, series, time, output size).

CLI (`argparse` kept): `-s/--source` and `-o/--output` as today; `-q/--sqlite`, `-d/--duckdb`; when
neither is given, the engine follows the output extension (`.sqlite`/`.db` → SQLite, `.duck`/`.duckdb`
→ DuckDB), else error. `-q`/`-d` without `-o` keep today's defaults `/tmp/db.sqlite`/`/tmp/db.duck`
(`testing/topology.py` relies on them). `-s` accepts any trace directory directly, not only names
starting with `tcbee_`; it falls back to `find_latest` only when the directory holds no trace files. New: `-t/--threads N`, `-f/--force` to replace an existing output (today the
DuckDB path silently appends into an existing file). A missing flag combination is an error with exit
status 2 (today it prints and exits 0).

## A6. Visualizer changes

- `tcbee-viz/src/backend/db.rs` wraps `Box<dyn Store>`. Bounds and point counts come from
  `SeriesInfo`, which removes the per-series count/bounds queries in `get_flow_x_bounds`,
  `get_series_y_bounds` and `flow_table.rs` stats. Flow x-bounds are min/max over the flow's series.
- Range loading keeps client-side downsampling; it only switches to `for_each_point`.
  Server-side downsampling is a follow-up, not part of this rewrite.
- Series lists show `name` with `source` and `dir` (`snd_cwnd · sock · send`), because a flow can now
  hold several series of the same name.
- Plugin input binding (`best_match_series_id`, `tab_process.rs`): keep the name matching order
  (exact, case-insensitive, alphanumeric only). When several series match, prefer raw over derived,
  then sources in the order `tcp_probe, sock, tcp4, tcp6, cwnd, cubic, bbr`, then `send` over
  `recv` over `none`. Match tiers (exact > case-insensitive > alphanumeric) take precedence over
  this preference. All inputs of one plugin run are resolved from the same `(source, dir)` when
  that group has all of them, because the plugins zip their inputs by index and only rows of one
  group are aligned. If no group has all inputs (SenderLimitation needs `SND_*` from tcp_probe
  plus `advmss` from sock), each input is resolved independently.
- `DataValue` is no longer used as a type tag: `SeriesData.val_type` becomes `ValueKind`, the
  plugins (`plugin_upper_window.rs` uses `type_equal`/`type_to_int`) match on `ValueKind`, and
  `type_display` in `series_table.rs` shows the `ColType`.
- The file dialog (`tab_home.rs`) and the usage text (`main.rs`) accept `.sqlite`, `.db`, `.duck`
  and `.duckdb`; the home tab shows `Store::engine()`.
- Saving checks for an existing **derived** series of that name (`existing_series_for_flow`) and
  replaces it through `replace_derived`; the overwrite dialog (`tab_process.rs`) lists only derived
  conflicts. Raw series cannot be overwritten.
- Opening a v1 file shows the "reprocess the trace" error from `open`.

## A7. Not in scope

Remote databases (TimescaleDB, ClickHouse, QuestDB, InfluxDB; an InfluxDB 3 draft is in
`PROCESS-INFLUXDB.md`): the `Store`/`IngestSession` split leaves room for
a third engine, but none is planned until the local contract is stable and there is a workload that
needs it. Also out: server-side downsampling, sorting event tables at finish (measured unnecessary),
multi-flow sharding of the workers, Ctrl-C handling beyond leaving a `.partial` file.

---

# Part B: work packages

Conventions for every package: branch off the current branch, one commit per logical change with a
short plain message (repo memory: no AI trailer, public repo), `cargo fmt`, `cargo clippy` clean
for touched crates, no new `unwrap`/`expect` on fallible I/O or DB paths. Code style follows the
surrounding code. When a package finishes, tick it here and adjust the open-work list in
`CLAUDE.md`.

Dependency graph (packages on one line can run in parallel):

```text
WP0 fixtures
WP1 ts-storage core types + schema renderer
WP2 bindings macro + decoder      WP3 SQLite engine      WP4 DuckDB engine      WP5 contract tests
WP6 tcbee-process pipeline  (needs WP2 + WP3 or WP4)
WP7 tcbee-viz migration     (needs WP3 or WP4; WP0 fixture DB)
WP8 cleanup, docs, examples, CI
WP9 benchmarks and acceptance
```

WP3, WP4 and WP5 only depend on the WP1 types, so they start as soon as WP1 is merged. WP2 depends on
WP1 for `EventTable`/`EventBatch`.

**Every commit keeps all three crates building.** The new storage code lives in
`ts-storage/src/v2/` (`schema.rs, batch.rs, catalog.rs, sql.rs, error.rs, sqlite.rs, duckdb.rs`) and
is re-exported at the crate root under names that do not clash with the old API (`Store`,
`IngestSession`, `StoreError`, ...). The old `TSDBInterface`, its modules and `src/error/` stay
untouched until WP6 and WP7 have moved their callers; WP8 deletes them and may then flatten `v2/`
into the crate root. In `tcbee-process`, the old `EventIndexer` path stays in place until WP6 replaces
the pipeline.

Facts agents need and must not re-derive differently:

| Binding | source | fields | `ENTRY_SIZE` (bytes) |
| --- | --- | --- | --- |
| `sock_trace_entry` | sock | 25 | 160 |
| `TcpProbe` | tcp_probe | 10 | 116 |
| `CubicEvent` | cubic | 14 | 114 |
| `BbrEvent` | bbr | 12 | 110 |
| `cwnd_trace_entry` | cwnd | 1 | 62 |
| `Tcp6Packet` | tcp6 | 4 | 59 |
| `Tcp4Packet` | tcp4 | 4 | 35 |

`ENTRY_SIZE` matches the bincode encoding. `get_struct_length()` disagrees for cubic, bbr, tcp4 and
tcp6 and is unused: never use it.

## WP0. Test fixtures (do first; the traces live in tmpfs)

- Create `tcbee-process/tests/fixtures/tcbee_small/` by copying the trace directory layout of
  `/tmp/tcbee_2026-10-05T15-01-43` (`TCBeeTrace::open` only needs a directory; `metrics.json` is
  unused and not copied) with only the
  first 2,000 records of each trace file (`head -c $((2000 * ENTRY_SIZE))`). Add the cubic file from
  `/tmp/tcbee_2026-10-05T14-49-29` the same way. Neither trace has tcp6 data (all tcp6 files are
  empty), so add a small generator test helper that writes tcp6 records with known values
  (`Serialize` on the bindings behind a `fixture-gen` dev feature) and check its output into the
  fixture. Target size below 2 MB.
- Add `tcbee-process/tests/fixtures/tcbee_truncated/`: one sock file with 10 records plus 17 extra bytes.
- Add `tcbee-process/tests/fixtures/README.md` describing the source of each fixture and the record
  counts per file.
- If the traces in `/tmp` are gone, generate every file with the same helper.

Acceptance: the fixture opens with `TCBeeTrace::open`; record counts in the README match file sizes.

## WP1. `ts-storage` core types and schema renderer

Files: new `ts-storage/src/v2/{mod.rs, schema.rs, batch.rs, catalog.rs, sql.rs, error.rs}`, re-exports
in `lib.rs`. Do not edit the old modules or `src/error/`.

- `ColType`, `Column`, `EventTable`, `Dir` (`None = 0, Send = 1, Recv = 2`), `SeriesKind`,
  `ValueKind`, the fixed tables as static `Table` definitions, `Dialect`, DDL rendering exactly as in
  A2 (types per dialect, index statements).
- `EventBatch`, `ColumnData`, typed accessors, `approx_bytes`, `validate()` (all columns same length,
  types match the table).
- `Catalog`, `SeriesInfo`, `Engine`, `impl From<ValueKind> for ColType` (Int→I64, Float→F64,
  Bool→Bool, String→Text) and `ColType::value_kind()`. `IpTuple`, `Flow`, `DataPoint` and
  `DataValue` stay where they are and are reused; `column_name` and the i16 type codes are removed
  in WP8.
- `StatsAccumulator`: per `(flow_id, source, dir)` and column, `n`, `t_min`, `t_max`, `v_min`,
  `v_max` as f64 (u64 saturated to `i64::MAX` first, A2); `observe(&EventBatch)` and `merge(other)`;
  `into_series(next_id) -> Vec<SeriesInfo>` producing deterministic IDs (sorted by flow, source,
  dir, column order). Text columns get no `v_min`/`v_max`.
- `sql.rs`: functions returning the portable statements of A3 (`range_query`, `all_points_query`,
  catalog inserts/selects, derived insert/delete, meta). Quote identifiers with `"`.
- `StoreError` (thiserror): `Sqlite(rusqlite::Error)`, `DuckDb(duckdb::Error)`, `Io`,
  `UnsupportedSchema { found: Option<String> }`, `NotDerived`, `TypeMismatch`, `Exists`,
  `UnknownEngine`, `WriterGone`.
- Traits and `create`/`open` signatures from A4 (`open`/`create` may return `todo!()` until WP3/WP4),
  with engine detection from the file header in `open`.
- Engine features `sqlite`/`duckdb` as in the decisions above, with cfg-gated engine modules.
- Cargo: add `rusqlite` (optional `bundled`), enable `duckdb` feature `appender-arrow`, keep
  `thiserror`. Update `bundled` to cover both.

Tests (unit): DDL snapshot strings for one sample table in both dialects; `EventBatch` type checks;
`StatsAccumulator` on hand-built batches including u64::MAX, negative i64, NaN-free floats, empty
groups; deterministic series IDs.

## WP2. Bindings macro and decoder (`tcbee-process`)

Files: `tcbee-process/src/bindings/*`, new `bindings/mod.rs` (the module is declared inline in
`main.rs` today), `src/event.rs`, `src/decode.rs`. Keep `EventIndexer` and `tcp_packet.rs` until WP6
(the old pipeline still uses them); the `Event` impls live next to them.

- `event_schema!` macro (declarative, `macro_rules!`) generating `Event::TABLE` and `push_row` as in A3.
  Sources: `sock`, `tcp_probe`, `cwnd`, `cubic`, `bbr`, `tcp4`, `tcp6`. Column names and order
  are exactly today's `get_field_name` strings and index order (A3). Types follow the struct field
  types (u64 fields → `U64`, not `I64`).
- `trait Event: Sized { const TABLE; const ENTRY_SIZE: usize; fn decode(buf: &[u8]) -> Result<Self, DecodeError>;
  fn flow_key(&self) -> IpTuple; fn ts_ns(&self) -> i64; fn check_divider(&self) -> bool; fn push_row(...) }`.
  `decode` returns an error instead of today's `Default` fallback on bincode failure.
- `decode.rs`: `fn decode_range<E: Event>(file: &File, records: Range<u64>, f: impl FnMut(u64 /*seq*/, E) -> Result<()>)`
  reading 4 MiB chunks with `read_exact_at`, errors with file offset; truncated-tail detection is
  done by the unit planner (WP6), not here.
- Map `TraceFile` → `(source, Dir, decoder fn)` in one table in `bindings/mod.rs` (A2).
- `flow_key()` is ported unchanged from each `get_ip_tuple` (A2).

Tests: for every binding, the schema/`push_row` consistency test from A3; decode the WP0 fixture and
compare the first record of each file against values printed by the old code (capture them before
deleting `EventIndexer`: run the old `get_field` on record 0 and paste the expected values into the
test); divider-mismatch error on a corrupted buffer.

## WP3. SQLite engine (`ts-storage/src/sqlite/`, rewritten)

File: `ts-storage/src/v2/sqlite.rs` (the old `src/sqlite/` stays until WP8).

- Implement `IngestSession`, `BatchWriter`, `Store` for SQLite as in A4, on `rusqlite`.
- Partial-file handling (`<path>.partial`, rename in `finish`, delete on drop, `force` semantics:
  without `force` an existing `path` is `StoreError::Exists` at `create` time).
- u64 bit-pattern storage and conversion back, saturation to `i64::MAX` in `DataValue::Int`.
- Writer thread, bounded channel, commit every 1 M rows, writer error returned from `finish` (and
  from the next `write` after the thread died: `WriterGone`).
- Derived edits in transactions; stats computed for derived points.
- `open`: header detection lives in `lib.rs` (WP1), the SQLite part checks `meta.schema_version`.
  A file without `meta` is `UnsupportedSchema { found: None }`.

Tests: engine-specific (partial file removed on drop, existing output without `force`, writer error
surfaces in `finish`). Shared behavior is covered by WP5.

## WP4. DuckDB engine (`ts-storage/src/duckdb/`, rewritten)

File: `ts-storage/src/v2/duckdb.rs` (the old `src/duckdb/` stays until WP8).

- Implement the same traits on `duckdb` with Arrow appends as in A4.
- Start with an `appender-arrow` lifecycle spike as a test: two writers on `try_clone` connections
  appending to two tables and to the same table concurrently from two threads, metadata inserts on
  the main connection while appenders are alive, a forced flush error (append into a table with a
  `CHECK` constraint violated) surfacing in `close`. Keep the spike as regression tests.
- Measure appender-per-batch vs. cached appender on 20 M value-equivalents; keep per-batch if
  within 5 %.
- `finish`: catalog in one transaction, `CHECKPOINT`, close all connections, rename.
- Same partial/force/open semantics as WP3.

## WP5. Shared contract tests (`ts-storage/tests/contract.rs`)

A macro instantiates every test for both engines on temp files (`tempfile` dev-dependency). Uses a
test-only `EventTable` with one column of each `ColType`.

Cases:
- Round trip of every type, including `u64::MAX` (read as `i64::MAX`), `u64` just above `i64::MAX`,
  `-1`, `-1.0`, `0`, `f64::MIN_POSITIVE`, `true/false`, empty string, quotes, unicode, NUL-free
  long text.
- Ordering by `(ts, seq)` with duplicate timestamps; inclusive range bounds; empty range; range
  outside the data.
- Several batches and several writers into one table and into different tables (DuckDB from several
  threads; SQLite through handles).
- Catalog: flows by tuple, series per flow with `source`/`dir`, stats equal to a brute-force
  computation over the read points, two series of one name differing only in `dir`.
- Derived: create, read back, replace atomically (a failed replace keeps the old series), delete,
  name collision with an existing derived series → `Exists`, replace/delete of a raw series →
  `NotDerived`, type mismatch in points → `TypeMismatch`, String series round trip.
- Failure: dropping a session without `finish` leaves no `path` and no `.partial`; `open` on a v1
  file (create one with the old DDL, inlined as a string in the test because WP8 deletes
  `queries.rs`) → `UnsupportedSchema`; `open` on a non-database
  file → `UnknownEngine`.
- Both engines return identical results for the same input (run the same script on both, compare
  everything read through `Store`).

## WP6. `tcbee-process` pipeline

Files: `tcbee-process/src/{lib.rs, main.rs, pipeline.rs, registry.rs}`; remove `db_writer.rs`,
`flow_tracker.rs`, `reader.rs`, `bindings/event_indexer.rs`, `bindings/tcp_packet.rs`; drop `tokio`
and `tokio-util` from `Cargo.toml`; keep `serde` (bincode needs `Deserialize`), `indicatif`, `log`,
`env_logger`, `argparse`, `bincode`. Add `anyhow`. `lib.rs` exposes
`pub fn run(args: Args) -> anyhow::Result<Summary>`; `main.rs` only parses arguments and maps errors
to exit codes, so the e2e tests can call `run` directly.

- Implement A5: unit planning (1 M records per unit, truncated-tail warning), worker pool, flow
  registry, per-worker `EventBatch` (64 k rows), stats accumulation and merge, catalog build,
  `finish` (with `meta` entries `writer` and `trace_dir`), error and panic propagation, exit codes,
  summary line.
- Implement the CLI of A5.
- End-to-end tests (`tcbee-process/tests/e2e.rs`, run the binary or call a `run(args)` library
  function): process the WP0 fixture into both engines and check through `Store`:
  - number of rows per `(source, dir)` equals the record count of the file;
  - flows by tuple and series names/sources/dirs are identical between engines, and every point of
    every series is identical;
  - send and receive sock data are separate series;
  - the truncated fixture processes with a warning and 10 records;
  - a corrupted fixture (divider mismatch, built in the test) exits non-zero and leaves no output;
  - existing output without `--force` exits non-zero and leaves the file untouched.

## WP7. `tcbee-viz` migration

Files: `tcbee-viz/src/{main.rs, app.rs}`, `backend/db.rs`, `ui/{tab_home, flow_table, series_table,
tab_process, tab_single_flow, tab_multi_flow}.rs`, `data/{plot_state, series_data}.rs`,
`backend/plugin/*`.

- Implement A6 on the `Store` API. Remove all uses of `TSDBInterface`, `TimeSeries`, `ts_type`
  placeholders and per-series bound/count queries.
- Opening: `ts_storage::open`; show the v1 error text in the UI.
- Plugin input resolution rule from A6, with unit tests on a synthetic series list (send/recv
  duplicates, raw vs derived, missing inputs).
- Manual check (document in the PR/commit message what was checked): open the WP0 fixture processed
  with both engines, single-flow and multi-flow tabs plot, every plugin runs and saves, saving twice
  replaces, a String series (`SENDER_LIMITATION_LABEL`) saves on SQLite.

## WP8. Cleanup, docs, examples, CI

- Delete the old `ts-storage` API and modules (`TSDBInterface`, `DBBackend`, `database_factory`,
  `Condition`, `TSBounds`, `FlowAttribute`, `DataValue`'s i16 codes and `column_name`, `src/sqlite/`,
  `src/duckdb/`, `src/error/`), `tests/{sqlite,duckdb}.rs`, `ouroboros`, the `sqlite` crate.
  Optionally flatten `src/v2/` into the crate root.
- Update `ts-storage/README.md` (schema v2, API), `tcbee-process` README/usage text, the main
  `README.md` sections on processing, and `examples/db/{README.md, list_flows.py, plot_cwnd.py}` to
  the v2 schema (`series` + `ev_*` tables; `plot_cwnd.py` reads `ev_sock`/`ev_tcp_probe` directly).
- Build time: forward the `sqlite`/`duckdb` features through `tcbee-process` and `tcbee-viz`
  (WP6/WP7 keep them building with `--no-default-features --features sqlite` and `duckdb`);
  decide on a cargo workspace with a shared `target/` and `Cargo.lock`, check that `libduckdb-sys`
  is not rebuilt when switching between crates or running `cargo test`/`clippy` after `cargo build`
  (same features and profile), document the system-libduckdb option, and add feature-matrix checks
  to CI.
- Review `testing/topology.py` and the root `tcbee` wrapper script for CLI and output-path changes.
- CI (`.github/workflows/tcbee.yml`, `release.yml`): `--features ts_storage/bundled` must still
  build both engines; add `cargo test` for `ts-storage` and `tcbee-process` (the e2e tests use the
  in-repo fixture). Check the release build links SQLite and DuckDB the same way as before.
- Update `CLAUDE.md` open work: remove finished items, add anything deferred.

## WP9. Benchmarks and acceptance

Re-run the A1 measurements (same machine, both traces if still available, otherwise the largest
trace at hand; record DuckDB/SQLite versions and core count) and add the results to A1.

Ship criteria:
- WP5 and WP6 tests pass on both engines; `cargo test` passes for all three crates.
- 300 MB trace: DuckDB and SQLite each finish in under 20 s wall time with peak RSS under 1 GB
  (today 320 s / 2.5 GB and 88 s / 2.7 GB). The time after the last worker finishes is under 10 %
  of the total for DuckDB; for SQLite report the index build separately.
- Output size at most a third of today's per engine.
- A visualizer range read of one series in the 300 MB DuckDB and SQLite outputs takes under 50 ms.
- No error path exits 0 (checked by the WP6 tests).

If a criterion is missed, profile (`perf record -g`) and record the cause here before tuning.
Candidate tunings, in order: batch size, `--threads` default, DuckDB cached appender, SQLite
`WITHOUT ROWID` or index variants, sort-on-finish for DuckDB.

## Implementation notes (deviations found while implementing)

- `rusqlite` and the old `sqlite` crate cannot be in one dependency graph (both link `sqlite3`).
  So WP1 adds the `sqlite` feature empty and a temporary `legacy` feature (default on) that gates
  the old API. WP3 must remove the old `sqlite` crate and the old SQLite backend; until WP6/WP7
  move the callers, `database_factory(Sqlite)` returns an error on this branch and the old
  tools only work with DuckDB. `legacy` is deleted in WP8.
