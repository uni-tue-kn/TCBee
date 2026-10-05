<div align="center">
 <h2>ts-storage: TCP Flow Database</h2>

 ![image](https://img.shields.io/badge/licence-MIT-blue) ![image](https://img.shields.io/badge/lang-rust-darkred) ![image](https://img.shields.io/badge/part%20of-TCBee-yellow)
</div>

Part of [TCBee](../README.md). A Rust library that reads and writes TCBee flow databases on SQLite or DuckDB behind one API. `tcbee-process` writes with it, `tcbee-viz` reads with it.

- [Database layout (schema version 2)](#database-layout-schema-version-2)
- [Features and engines](#features-and-engines)
- [Building without compiling DuckDB](#building-without-compiling-duckdb)
- [Reading](#reading)
- [Writing](#writing)
- [Errors](#errors)
- [Reading a database without this crate](#reading-a-database-without-this-crate)
- [Tests](#tests)

## Database layout (schema version 2)

One table per recorded event type, one row per record, one typed column per field. The layout is the same on both engines; only the column types differ.

| Table | Content |
|---|---|
| `meta(key, value)` | `schema_version` (`2`), `writer`, `trace_dir`, `created_at` |
| `flows(id, src, dst, sport, dport, l4proto)` | one row per TCP flow (IP 5-tuple) |
| `series(id, flow_id, kind, source, dir, name, value_type, tbl, col, n, t_min, t_max, v_min, v_max)` | catalog of all series with point count and bounds |
| `ev_sock`, `ev_tcp_probe`, `ev_cwnd`, `ev_cubic`, `ev_bbr`, `ev_tcp4`, `ev_tcp6` | the recorded events, see below |
| `derived_samples(series_id, ts, seq, v_int, v_float, v_bool, v_text)` | points of series created in the visualizer; one of the `v_*` columns is set |

Every `ev_*` table starts with `flow_id`, `dir`, `ts` and `seq`, followed by one column per field of the record (`ev_sock.snd_cwnd`, `ev_tcp_probe."SND_CWND"`, ...). Column names are the series names TCBee has always used, with their original case, so quote them in SQL.

- `ts` is the recorder's `bpf_ktime_get_ns()` value in nanoseconds since boot, stored as an exact integer.
- `dir` is 0 for sources without a direction (`tcp_probe`, `cubic`, `bbr`), 1 for send and 2 for receive files.
- `seq` is the index of the record in its trace file. Ordering by `(ts, seq)` is stable; samples with equal timestamps are all kept.
- A **series** is one column of one `(flow, source, dir)` group. `series.kind` is 0 for raw series and 1 for derived ones, `tbl` and `col` name the event table and column of a raw series, `n`, `t_min`, `t_max`, `v_min` and `v_max` describe its values, so bounds and counts need no scan. `value_type` is 0 bool, 1 u8, 2 u16, 3 u32, 4 u64, 5 i64, 6 f64, 7 text.
- There are no foreign keys and no unique keys on event tables. DuckDB files have no indexes on them; SQLite files get one on `(flow_id, dir, ts, seq)` after the load.
- Unsigned 64-bit columns (`pacing_rate`, `max_pacing_rate`, `SOCK_COOKIE`, ...) are stored as unsigned in DuckDB and as their two's complement `i64` bit pattern in SQLite, so SQLite shows `max_pacing_rate = u64::MAX` as `-1`. The read API of this crate converts back and saturates values above `i64::MAX` to `i64::MAX` on both engines.
- Databases written by older TCBee versions (`time_series`, `time_series_data`) are not supported. Opening one fails with "reprocess the trace with tcbee-process".

## Features and engines

| Feature | Default | Effect |
|---|---|---|
| `sqlite` | yes | SQLite engine (`rusqlite`) |
| `duckdb` | yes | DuckDB engine (`duckdb`, `libduckdb-sys`) |
| `bundled` | no | compile the C libraries of the enabled engines into the binary |

`tcbee-process` and `tcbee-viz` forward `sqlite`, `duckdb` and `bundled` as features of their own. Opening or creating a file of an engine that is not built in returns `StoreError::EngineDisabled`. The engine of an existing file is detected from its first bytes, not from the file name.

```toml
[dependencies]
# both engines
ts_storage = { path = "../ts-storage" }
# SQLite only: libduckdb-sys is never compiled
ts_storage = { path = "../ts-storage", default-features = false, features = ["sqlite"] }
```

The SQLite and DuckDB C libraries come from the system unless `bundled` is on:

- Without `bundled`, `rusqlite` links `libsqlite3` and `libduckdb-sys` links `libduckdb` from the system. Use a libduckdb of the same version as the `duckdb` crate in `Cargo.lock` (crate `1.10506.x` is DuckDB 1.5.6).
- With `bundled`, both are compiled from source (DuckDB takes about ten minutes). The release builds use it.

## Building without compiling DuckDB

DuckDB takes long to compile. Use `--no-default-features --features sqlite` to leave it out, and see the root README, [Building without waiting for DuckDB](../README.md#building-without-waiting-for-duckdb), for sharing one build between the crates and for linking a system libduckdb.

## Reading

```rust
let store = ts_storage::open(Path::new("flows.duck"))?;   // Box<dyn Store>

for flow in store.flows()? {                              // Vec<Flow>
    for s in store.series(flow.id)? {                     // Vec<SeriesInfo>
        println!("{} {} {:?}: {} points", flow.id, s.name, s.dir, s.n);
        // Points ordered by (ts, seq); the range is optional, inclusive, in f64 ns.
        store.for_each_point(&s, Some((0.0, 5e6)), &mut |p: DataPoint| {
            println!("{} ns  {}", p.timestamp, p.value.as_string());
        })?;
    }
}
```

`Store` (`Box<dyn Store>` is not `Send`):

| Method | |
|---|---|
| `engine()` | `Engine::Sqlite` or `Engine::DuckDb` |
| `flows()`, `flow(id)` | flows of the file |
| `series(flow_id)`, `series_by_id(id)` | catalog rows (`SeriesInfo`) with `n`, `t_min`, `t_max`, `v_min`, `v_max` |
| `for_each_point(&series, range, callback)` | stream the points of a raw or derived series |
| `create_derived(flow_id, name, kind, points)` | add a derived series (`ValueKind::{Int, Float, Bool, String}`) |
| `replace_derived(&existing, points)` | replace the points of a derived series in one transaction |
| `delete_derived(&series)` | delete a derived series |

Only derived series can be changed or deleted; raw series are read-only (`StoreError::NotDerived`). `open` checks `meta.schema_version` and returns `StoreError::UnsupportedSchema` for anything but 2.

## Writing

A database is written in one pass by an `IngestSession`. Event tables are defined as `static` Rust data, filled in column-wise batches, and the catalog (flows, series, meta) is written at the end. The data goes to `<path>.partial`, which is renamed to `path` by `finish`. A session that is dropped or fails leaves no file behind. `create` fails with `StoreError::Exists` if the file exists, unless `CreateOptions { force: true }`.

```rust
static CWND: EventTable = EventTable {
    source: "cwnd", // the table is called ev_cwnd
    columns: &[Column { name: "snd_cwnd", ty: ColType::U32 }],
};

let session = ts_storage::create(Engine::DuckDb, path, CreateOptions { force: true })?;
session.create_tables(&[&CWND])?;

let flow = Flow::new(1, IpTuple { src, dst, sport: 12345, dport: 5001, l4proto: 6 });

let mut writer = session.writer()?;        // one per thread; writers are not Send
let mut stats = StatsAccumulator::new();   // feeds the series table; merge() combines threads
let mut batch = EventBatch::new(&CWND, 1000);
for i in 0..1000i64 {
    // flow id, direction, timestamp in ns, index of the record in its trace file
    batch.push_header(flow.id, Dir::Send, 1_000_000 * i, i);
    batch.u32(0).push(10 + i as u32);      // column 0 of CWND
}
stats.observe(&batch)?;
writer.write(batch)?;
writer.close()?;

session.finish(Catalog {
    series: stats.into_series(1),          // first series id
    flows: vec![flow],
    meta: vec![("writer".into(), "my-tool".into())],
})?;
```

Batches are validated (equal column lengths, no NaN in `f64` columns) before they are written. `tcbee-process` is the reference user: it keeps one writer and one `StatsAccumulator` per worker thread.

## Errors

All fallible calls return `StoreError`:

| Variant | When |
|---|---|
| `Sqlite`, `DuckDb`, `Io` | errors of the driver or the file system |
| `UnsupportedSchema` | the file has a schema version other than 2 (or none) |
| `EngineDisabled` | the file needs an engine that is not built in |
| `UnknownEngine` | the file is neither SQLite nor DuckDB |
| `Exists` | `create` without `force` on an existing file |
| `NotDerived` | change or delete of a raw series |
| `NotFound` | a series that must exist does not |
| `TypeMismatch` | values do not fit the series or table (also invalid batches) |
| `Corrupt` | the file holds a code or value this crate never writes |
| `WriterGone` | the writer thread of an engine has died |

## Reading a database without this crate

Both engines produce plain files, so any client works; [`examples/db`](../examples/db/) has Python scripts for SQLite and DuckDB. For example, the send-side congestion window of a flow:

```sql
SELECT ts, snd_cwnd FROM ev_sock WHERE flow_id = 3 AND dir = 1 ORDER BY ts, seq;
```

Flow ids are assigned during processing and change between runs; look them up in `flows`.

## Tests

```bash
cargo test -p ts_storage                                          # both engines
cargo test -p ts_storage --no-default-features --features sqlite  # DuckDB tests are not built
cargo test -p ts_storage --no-default-features --features duckdb
```

`tests/contract` runs every case on each enabled engine against the public API, plus a script that must give identical results on both.
