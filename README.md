<div align="center">
 <img src="./imgs/tcbee.png" height=200/>
 <h2>TCBee: TCP Flow Analysis with eBPF</h2>

 ![License](https://img.shields.io/github/license/uni-tue-kn/TCBee) ![image](https://img.shields.io/badge/lang-rust-darkred) ![GitHub Release](https://img.shields.io/github/v/release/uni-tue-kn/TCBee) [![TCBee build](https://github.com/uni-tue-kn/TCBee/actions/workflows/tcbee.yml/badge.svg)](https://github.com/uni-tue-kn/TCBee/actions/workflows/tcbee.yml)

 <img alt="tcbee-record while recording" width="800" src="imgs/record.png"/>
</div>

TCBee monitors TCP flows at up to 5M events/s. It captures packet headers with TC hooks, reads kernel TCP metrics with eBPF function hooks, and stores everything in a DuckDB or SQLite database for offline analysis and visualization. It runs on Linux only.

## Quick Start

You record on a live system, convert the recording into a database, and open the database in a viewer. Three tools do this: `tcbee-record`, `tcbee-process` and `tcbee-viz`.

Requirements:

- Linux on x86_64 with BTF (`/sys/kernel/btf/vmlinux`) and kernel 5.9 or newer. Root is needed to load the eBPF programs.
- Rust stable 1.82 or newer ([rustup.rs](https://rustup.rs/))
- Debian/Ubuntu packages:

```bash
sudo apt install -y clang libclang-dev libelf-dev zlib1g-dev pkg-config make \
    libsqlite3-dev fontconfig libfontconfig1-dev libgl-dev libegl-dev
```

Build and install the three tools into `install/`:

```bash
make record process viz
```

DuckDB is compiled from source on the first build, which takes about ten minutes. To skip it, add `CARGO_FLAGS="--no-default-features --features sqlite"` to the command and use `.sqlite` output files below.

Record a flow on interface `eth0`, stop with Ctrl+C, process the recording and open it:

```bash
sudo ./install/tcbee record -h eth0 -k
./install/tcbee process -o /tmp/myflow.duck
./install/tcbee viz /tmp/myflow.duck
```

The recording lands in `/tmp/tcbee_<timestamp>/`. `process` picks the newest one there. A bare `sudo tcbee` only works if `tcbee` is in root's `PATH`, so call the script by path.

## How it works

`tcbee-record` attaches eBPF programs and writes raw events to `*.tcp` files. `tcbee-process` decodes them with several threads into a database with one table per event type and nanosecond timestamps. `tcbee-viz` plots the flows and computes derived metrics with plugins. The `tcbee` script in `install/` dispatches `record`, `process`, `viz` and `live` to the matching `tcbee-*` binary.

## The tools

### tcbee-record

Written in C with libbpf. Loads the eBPF programs and writes the raw events. A source flag picks what to record: `-h IFACE` for headers, `-t` for tracepoints, `-k` for fentry hooks, `-w` for the congestion window only, `-a` for Cubic and BBR internals. Filters (`-p`, `--ports`, `--ips`) limit the recording to some flows. Flags, kernel requirements and the static release build are in [tcbee-record/README.md](tcbee-record/README.md).

```bash
sudo ./install/tcbee record -h eth0 -k -p 5001 --duration 60
```

### tcbee-process

Converts a recording into a database. The extension of `-o` picks the engine: `.duck` or `.duckdb` for DuckDB, `.sqlite` or `.db` for SQLite. Flags, exit codes and build options are in [tcbee-process/README.md](tcbee-process/README.md).

```bash
./install/tcbee process -s /tmp -o /tmp/myflow.duck -f
```

### tcbee-viz

A desktop viewer built with egui. It plots single flows, compares two flows, and runs plugins that add derived series such as retransmissions. It opens a database given as argument, or you load one from the Home tab.

```bash
./install/tcbee viz /tmp/myflow.duck
```

## Building

`make` builds record, process, viz and live. `make record process viz` builds a subset. `CARGO_FLAGS` applies to process and viz only. `tcbee-process`, `tcbee-viz` and `ts-storage` are one cargo workspace in the repository root. `tcbee-record` and `tcbee-live` have their own. Cargo features, DuckDB linking options and build caching are in the [tcbee-process Building section](tcbee-process/README.md#building).

## Reading the data yourself

The database is a plain SQLite or DuckDB file. Rust programs can use the `ts-storage` library, see [ts-storage/README.md](ts-storage/README.md), which also lists the tables and columns. [examples/db/](examples/db/) has Python scripts that list flows and plot the congestion window, and [examples/raw/](examples/raw/) reads the raw `*.tcp` files.

## tcbee-live

An optional live congestion window monitor with a GUI that writes no files. It needs a nightly toolchain and `bpf-linker`, and it is tested on Linux 6.13.6. Build it with `make live` and run `sudo ./install/tcbee live --select-port 5001`. See [tcbee-live/README.md](tcbee-live/README.md).

## Testing

[testing/](testing/) has a Mininet setup with a bottleneck topology that drives `iperf3` traffic through the tools. Start it with `python3 testing/run.py`. Prerequisites and menu options are in [testing/README.md](testing/README.md).

## Screenshots

<img alt="CWND, SSTHRESH and lost packets of one flow" style="border-radius: 10px; border: 1px solid #000;" src="imgs/visualize.png"/>
<img alt="Two flows compared in one plot" style="border-radius: 10px; border: 1px solid #000;" src="imgs/visualize_multiple_flows.png"/>

## License and credits

MIT, see [LICENSE](LICENSE). Special thanks to [Evelyn](https://github.com/ScatteredDrifter) and Lars for their support during development.

*Developed with AI coding assistance. All code reviewed and verified by human developers before inclusion.*
