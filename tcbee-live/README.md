<div align="center">
 <h2>tcbee-live: Real-Time TCP Congestion Window Monitor</h2>

 ![image](https://img.shields.io/badge/licence-Apache%202.0-blue) ![image](https://img.shields.io/badge/lang-rust-darkred) ![image](https://img.shields.io/badge/part%20of-TCBee-yellow)
</div>

Part of [TCBee](../README.md).

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Running](#running)
- [CLI Options](#cli-options)
- [Using the GUI](#using-the-gui)
- [Limitations](#limitations)

## Overview

`tcbee-live` is a real-time TCP congestion window (cwnd) monitor. It requires no post-processing step: attach it to a running system and immediately see cwnd over time for any active TCP flow. No data is written to disk.

It is useful for quickly inspecting how a running flow responds to network conditions, for example checking whether BBR or CUBIC is reacting to a bottleneck link, without needing a full TCBee recording and processing pipeline.

## How It Works

Two eBPF `fentry` probes are attached to kernel functions at startup:

- `__tcp_transmit_skb`: fires on every TCP segment sent
- `tcp_rcv_established`: fires on every segment received

Each probe reads the current `snd_cwnd` from the TCP socket and writes a timestamped event to a per-probe ring buffer. A background Tokio worker drains both ring buffers and forwards events to the GUI thread via a channel. The GUI downsamples incoming events to one point per 50 ms and plots cwnd over elapsed time.

A flow filter map in the eBPF layer ensures only selected flows generate events, so overhead scales with what you are actually watching.

## Prerequisites

*Note: tcbee-live is Linux-only and requires BTF (BPF Type Format) support in the running kernel. It is tested on Linux 6.13.6.*

- Clang and LLVM (e.g. `sudo apt install -y llvm clang libelf-dev libclang-dev`)
- Rustup (> 1.28.1), install via [rustup.rs](https://rustup.rs/)
- Stable Rust toolchain: `rustup toolchain install stable`
- Nightly Rust toolchain: `rustup toolchain install nightly --component rust-src`
- BPF linker: `cargo install bpf-linker`
- pkg-config and fontconfig (e.g. `sudo apt install -y pkg-config fontconfig libfontconfig1-dev`)

## Build

```bash
cd tcbee-live
cargo build --release
```

The build script compiles the eBPF bytecode using a nested cargo invocation and embeds it into the binary automatically.

## Running

Loading eBPF programs requires root privileges (or `CAP_BPF`/`CAP_SYS_ADMIN`):

```bash
sudo ./target/release/tcbee-live
```

To automatically display flows on a specific port at startup:

```bash
sudo ./target/release/tcbee-live --select-port 5001
```

## CLI Options

- `--select-port <PORT>` to auto-select and display any flow whose source or destination port matches `<PORT>`. The flag can be repeated for multiple ports.
- `--combined-plot` to start with all selected flows shown on a single combined chart.
- `--auto-fit-x` to start with the x-axis locked to `0 → now`, tracking the latest event in real time.

## Using the GUI

**Side panel (right)**

- **Flow list**: all active TCP flows detected on the system. Each entry shows a colour swatch, a checkbox, and the flow label (`src:port → dst:port`). Check a flow to start plotting it.
- **Filter**: type a port number or IP address fragment to narrow the flow list.
- **Flow count**: shows how many flows are currently selected out of those discovered.
- **View options**: toggle *Combined plot* (all selected flows on one chart) and *Auto fit x-axis* (locks the time axis to the full recorded range). Grouped together in a bordered box at the bottom of the panel.
- **Theme toggle**: the `☀`/`☾` button in the panel header switches between dark and light mode.

**Plot area (centre)**

Each checked flow is rendered as a coloured line. The x-axis shows time in seconds since the first observed event; the y-axis shows the congestion window in segments. In combined mode all flows share one chart; otherwise they are stacked vertically. Both axes support free pan and zoom with the mouse when auto-fit is off.

## Limitations

- Requires `root` or `CAP_BPF` to load eBPF probes.
- Requires a kernel with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`).
- Tested on Linux 6.13.6; may not work on significantly older or newer kernels without adjusting the kernel struct offsets in [`tcbee-live-common/src/tcp_sock.rs`](tcbee-live-common/src/tcp_sock.rs).
- Data is held in memory only; closing the window discards all recorded points.
