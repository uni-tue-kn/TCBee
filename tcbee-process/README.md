# tcbee-process

Part of [TCBee](../README.md). Converts a raw recording of `tcbee-record` (the `*.tcp` files) into a SQLite or DuckDB database that `tcbee-viz` and your own scripts can read.

```bash
tcbee-process -o /tmp/myflow.duck                 # engine from the extension
tcbee-process -q -o /tmp/myflow.sqlite -t 4 -f    # SQLite, 4 threads, replace an existing file
tcbee-process -s ~/traces/tcbee_2026-10-05T18-16-22 -d
```

Flags, engine selection, exit codes and the output format are described in the [main README](../README.md#tcbee-process); the table layout is in [ts-storage/README.md](../ts-storage/README.md#database-layout-schema-version-2). `tcbee-process --help` prints the flags.

## How it works

The `*.tcp` files are cut into work units of up to one million records. A pool of worker threads (`--threads`) reads a unit in 4 MiB chunks, decodes the records with `bincode`, checks the divider of every record, resolves the flow id, and appends the fields to a column-wise batch of its event table (`ev_sock`, `ev_tcp_probe`, ...). Batches go to the database through `ts-storage`; per-series statistics are collected on the way, so the `series` catalog needs no second pass. The main thread merges the statistics, writes flows, series and `meta`, builds the SQLite indexes and renames `<output>.partial` to the output. The first error in any worker stops the others; nothing is left at the output path.

## Building

`tcbee-process` is part of the cargo workspace in the repository root:

```bash
cargo build --release -p tcbee-process                                            # both engines
cargo build --release -p tcbee-process --no-default-features --features sqlite    # no DuckDB
cargo build --release -p tcbee-process --features bundled                         # static SQLite and DuckDB
```

See [Building without waiting for DuckDB](../README.md#building-without-waiting-for-duckdb) for how to keep the DuckDB compile to once.

## Tests

```bash
cargo test -p tcbee-process                                          # both engines
cargo test -p tcbee-process --no-default-features --features sqlite
cargo test -p tcbee-process --no-default-features --features duckdb
```

`tests/e2e.rs` processes the traces in `tests/fixtures/` (see [its README](tests/fixtures/README.md)) into both engines and compares everything through the `ts-storage` API: row counts per file, identical flows and series on both engines, separate send and receive series, truncated and corrupt input, existing output without `--force`.

## Adding a record type

A trace record is a struct in `src/bindings/` that implements `Event`. The `event_schema!` macro in `src/event.rs` declares its table (`ev_<source>`) and one column per field and generates the code that fills a batch. Then add the trace file to `binding()` in `src/bindings/mod.rs` and to `event_tables()` there. Column names are the field names of the series in the visualizer, so they are never renamed.
