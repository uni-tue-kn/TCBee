# tcbee-process

Part of [TCBee](../README.md). Converts a raw recording of `tcbee-record` (the `*.tcp` files) into a SQLite or DuckDB database that `tcbee-viz` and your own scripts can read.

```bash
tcbee-process -o /tmp/myflow.duck                 # engine from the extension
tcbee-process -q -o /tmp/myflow.sqlite -t 4 -f    # SQLite, 4 threads, replace an existing file
tcbee-process -s ~/traces/tcbee_2026-10-05T18-16-22 -d
```

`tcbee-process --help` prints the flags. The table layout is in [ts-storage/README.md](../ts-storage/README.md#database-layout-schema-version-2).

## Usage

| Flag | Default | Description |
|---|---|---|
| `-s DIR` | `/tmp/` | Recording directory (holds the `*.tcp` files), or a directory to search for the latest `tcbee_*` recording |
| `-o FILE` | `/tmp/db.sqlite` with `-q`, `/tmp/db.duck` with `-d` | Output database file |
| `-q`, `--sqlite` | | Write SQLite |
| `-d`, `--duckdb` | | Write DuckDB |
| `-t N`, `--threads N` | number of cores | Worker threads |
| `-f`, `--force` | | Replace the output file if it exists |

Engine. `-q` or `-d` decide. Without them the extension of `-o` does: `.sqlite` and `.db` are SQLite, `.duck` and `.duckdb` DuckDB. If neither gives an engine the command fails. An engine that is not compiled in is an error too (see [Building](#building)).

Output. An existing output file is never touched without `-f`. The database is written to `<output>.partial` and renamed when everything succeeded, so a failed run leaves no half-written file. Files without a decoder (`tcp_retransmit_synack`, `tcp_bad_csum`) are skipped with a message. A truncated last record (the recorder was stopped mid-write) is dropped with a warning. Any other problem in a trace file (wrong divider, undecodable record, read error) stops the run. A summary line reports records, rows, flows, series, time and output size.

Exit codes. `0` is success (and `--help`), `1` means processing failed (unreadable or corrupt recording, existing output without `-f`, I/O or database error), `2` means wrong arguments.

Format. Databases use schema version 2: one table per record type (`ev_sock`, `ev_tcp_probe`, `ev_cwnd`, `ev_cubic`, `ev_bbr`, `ev_tcp4`, `ev_tcp6`) with one row per record and one typed column per field, plus the `flows` and `series` catalogs. Timestamps are exact integer nanoseconds. Send and receive samples of a flow are separate series. Databases written by earlier versions are not readable; process the recording again.

## How it works

The `*.tcp` files are cut into work units of up to one million records. A pool of worker threads (`--threads`) reads a unit in 4 MiB chunks, decodes the records with `bincode`, checks the divider of every record, resolves the flow id, and appends the fields to a column-wise batch of its event table (`ev_sock`, `ev_tcp_probe`, ...). Batches go to the database through `ts-storage`; per-series statistics are collected on the way, so the `series` catalog needs no second pass. The main thread merges the statistics, writes flows, series and `meta`, builds the SQLite indexes and renames `<output>.partial` to the output. The first error in any worker stops the others; nothing is left at the output path.

## Building

`tcbee-process`, `tcbee-viz` and the `ts-storage` library are one cargo workspace in the repository root with a single `target/` and `Cargo.lock`. Build from the root:

```bash
cargo build --release -p tcbee-process                                            # both engines
cargo build --release -p tcbee-process --no-default-features --features sqlite    # no DuckDB
cargo build --release -p tcbee-process --no-default-features --features duckdb    # no SQLite
cargo build --release -p tcbee-process --features bundled                         # static SQLite and DuckDB
```

`make process viz CARGO_FLAGS="--features bundled"` does the same through the Makefile. A binary built without an engine reports that when it is given a file of that engine. `bundled` compiles SQLite and DuckDB from source, which takes about ten minutes for DuckDB. Without it, `libsqlite3-dev` must be installed (Arch: `sqlite`) and DuckDB is compiled from source too, unless you point the build at a library (below).

### Without waiting for DuckDB

Use `--no-default-features --features sqlite` and DuckDB is never compiled. To keep DuckDB, link a `libduckdb` that is already there, which takes seconds. These environment variables of the `libduckdb-sys` build script choose the library:

| Variable | Effect |
|---|---|
| `DUCKDB_LIB_DIR=/opt/duckdb` | directory with `libduckdb.so` (and `duckdb.h`) |
| `DUCKDB_INCLUDE_DIR=...` | directory with `duckdb.h`, if it is elsewhere |
| `DUCKDB_STATIC=1` | link `libduckdb_static.a` |
| `DUCKDB_DOWNLOAD_LIB=1` | download the official `libduckdb` for the crate's DuckDB version into `target/` and link it |

The library version should match the `duckdb` crate in `Cargo.lock`. Set the variables for every cargo command, or put them into an uncommitted `.cargo/config.toml` in the repository root:

```toml
[env]
DUCKDB_LIB_DIR = "/opt/duckdb"
```

A binary linked to a dynamic `libduckdb` outside the standard library path must find the `.so` when it starts. `cargo run` and `cargo test` take care of that. A binary started directly from `target/` does not, so install the library to a standard path or set `LD_LIBRARY_PATH`.

### Sharing one DuckDB build

DuckDB's build script runs again (and with `bundled` recompiles all of DuckDB) when its build inputs change. In this workspace `cargo build -p`, `cargo test` and `cargo clippy` of `ts-storage`, `tcbee-process` and `tcbee-viz` share one compiled `libduckdb-sys`, as long as these stay the same:

- `bundled` or not: they are two separate builds.
- Profile: `--release` and the default debug build are separate.
- `RUSTFLAGS` and the other cargo environment, including the `DUCKDB_*` variables.

Build from the repository root; a `target/` per crate would compile DuckDB once per crate. The crate `duckdb-cache/` and the `[profile.dev.build-override]` in the root `Cargo.toml` exist so that the choice of `-p` does not change the build. If `cargo tree -p tcbee-viz -e features -i syn@3` shows `syn` features that are missing in [duckdb-cache/Cargo.toml](../duckdb-cache/Cargo.toml), add them there.

## Tests

```bash
cargo test -p tcbee-process                                          # both engines
cargo test -p tcbee-process --no-default-features --features sqlite
cargo test -p tcbee-process --no-default-features --features duckdb
```

`tests/e2e.rs` processes the traces in `tests/fixtures/` (see [its README](tests/fixtures/README.md)) into both engines and compares everything through the `ts-storage` API: row counts per file, identical flows and series on both engines, separate send and receive series, truncated and corrupt input, existing output without `--force`.

## Adding a record type

A trace record is a struct in `src/bindings/` that implements `Event`. The `event_schema!` macro in `src/event.rs` declares its table (`ev_<source>`) and one column per field and generates the code that fills a batch. Then add the trace file to `binding()` in `src/bindings/mod.rs` and to `event_tables()` there. Column names are the field names of the series in the visualizer, so they are never renamed.
