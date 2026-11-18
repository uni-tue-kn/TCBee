# Changelog

## Unreleased

### Added
- `tcbee-viz`: shades where events of a series are missing according to hook_seq, with the count on hover and a *Show gaps* toggle.
- `tcbee-viz`: *Export figure…* saves the visible plot as PDF or PNG in a figure style set under *Settings → Figure export* (kept in `~/.config/tcbee/viz.toml`); *Export data script…* saves a Python script that loads the plotted data and gaps with the tcbee package.
- `ts-storage`: `Store::seq_gaps`; Python API: `Series.gaps()`.

## 2.0.0

TCBee 2.0 replaces the eBPF stack of `tcbee-record` and `tcbee-live` with C programs loaded through libbpf (no more aya, nightly Rust or `bpf-linker`), rewrites the processing pipeline and the database format (schema version 3), and adds a Python API.

### Added
- `tcbee-record`:
  - TCP tracepoints and events (`-t`, `--tp`, including drops with reasons), socket state at timers and TCP events (`-k`, `--sock-hooks`), CUBIC, BBR and Reno internals (`-a`), MPTCP (`-m`), headers at TC or XDP (`-h`, `--headers-at`).
  - Per-CPU ring buffers with per-flow sequence numbers (`--no-hook-seq` turns them off), one writer thread per writer CPU, a raw trace format (`--writer-format`).
  - `--on-change` writes socket and cwnd records only when watched fields change; `--sock-fields` records only selected groups of socket fields.
  - The process that owns each connection, `--metadata` with the host and run context, `--duration`, a new terminal UI.
- `tcbee-process`: multithreaded ingest into DuckDB or SQLite (picked by the output extension), one typed table per event type with nanosecond timestamps, MPTCP connections, flow owners.
- `tcbee-viz`: Overview and MPTCP tabs; the flow table filters by tuple, MPTCP connection or process.
- Python API in `python/` to browse flows and read metrics as lists, batches or NumPy arrays, with plotting examples in `examples/`.
- Release assets: `.deb`, `.rpm`, a tar.gz with `install.sh`, and `SHA256SUMS`.

### Changed
- Database schema version 3; v1 databases cannot be opened, so process recordings again.
- `-m` is now MPTCP (`metrics.json` moved to `--metrics`); `-k` no longer hooks every packet by default.
- `tcbee-record` needs Linux 5.12+ with BTF; `tcbee-live` needs 5.8+.
- `make` builds into `bin/`, and `make install` installs to `$(PREFIX)/bin` (default `/usr/local`).
- Repository layout: the Rust crates are in `crates/`, the Python API in `python/`. Builds use the Rust version in `rust-toolchain.toml`.
