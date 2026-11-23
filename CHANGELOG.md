# Changelog

## Unreleased

### Added
- `tcbee-viz`: shades where events of a series are missing according to hook_seq, with the count on hover and a *Show gaps* toggle.
- `tcbee-viz`: *Export figure…* previews the visible plot as a figure, lets you adjust its style, and saves it as PDF or PNG; the default style is set under *Settings → Figure export* (kept in `~/.config/tcbee/viz.toml`).
- `tcbee-viz`: *Export data script…* saves a Python script that loads the plotted data and gaps with the tcbee package.
- `tcbee-viz`: plot groups in the Single and Multi Flow tabs. In the new *View* sidebar tab, metrics are dragged between groups, each drawn as one plot; a metric can be in several groups, groups can be hidden, and metric colours can be picked.
- `tcbee-viz`: figure export stacks the shown plot groups on one time axis.
- `ts-storage`: `Store::seq_gaps`; Python API: `Series.gaps()`.
- `tcbee-process`: stores a recording summary as `summary.*` meta rows: first and last event (also in UTC with `--metadata`), recorder start and stop, events in total and per table, discarded records, flows, connections, owners and series. `tcbee-viz` shows it in the Overview tab.
- All tools: `-V`/`--version`; `tcbee-live` and `tcbee-viz` print their help without starting (and `tcbee-live` without root).

### Changed
Command line flags, without aliases for the old names:
- `tcbee-record`: `-h IFACE` → `-H IFACE` (`-h` is the help), `-d DIR` → `-o DIR`, `-p PORT` → `--port PORT`, `-M` → `-m`. `-e`, `--drops` and `--no-timer-hook` are gone, use `--tp` and `--sock-hooks -timer`. Flags without effect (`-q` with `--tui-*`, `--headers-at` without `-H`, writer buffer flags with a sink that ignores them) and a call without arguments exit with status 2.
- `tcbee-process`: `-s DIR` → `-i DIR`, `-q` → `--sqlite`, `-d` → `--duckdb`, `-t N` → `-j N`.
- `tcbee-live`: `--select-port P` (once per port) → `--ports P,Q`; unknown flags and bad ports are errors.
- `tcbee-viz`: unknown flags and extra arguments are errors.
- Python examples: `--dir` (send/recv) → `--direction`.
- `tcbee-viz`: the *Split* and *Merge* checkboxes are replaced by the layouts of the *View* tab.

### Fixed
- `tcbee-viz`: a metric selected after deselecting another no longer takes the colour of a shown one.

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
