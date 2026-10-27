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

Each probe reads the current `snd_cwnd` from the TCP socket and writes a timestamped event to a ring buffer. The probes are written in C and loaded with libbpf; CO-RE resolves the kernel struct fields against the running kernel's BTF. A background thread drains the ring buffer every 33 ms and forwards events to the GUI thread via a channel. The GUI downsamples incoming events to one point per 50 ms and plots cwnd over elapsed time.

A flow filter map in the eBPF layer ensures only selected flows generate events, so overhead scales with what you are actually watching.

## Prerequisites

*Note: tcbee-live is Linux-only and requires Linux 5.8 or newer (6.0 on arm64) with BTF (BPF Type Format) support.*

- Clang, libelf and zlib (e.g. `sudo apt install -y clang libelf-dev zlib1g-dev pkg-config make`)
- Rustup (> 1.28.1), install via [rustup.rs](https://rustup.rs/)
- Stable Rust toolchain: `rustup toolchain install stable`
- pkg-config and fontconfig (e.g. `sudo apt install -y pkg-config fontconfig libfontconfig1-dev`)

## Build

```bash
cd tcbee-live
cargo build --release
```

The build script compiles the C eBPF programs in `tcbee-live/src/bpf/` with clang and embeds them into the binary. `cargo build --release --features static` links libbpf, libelf and zlib statically, as the release binaries do.

## Running

Loading eBPF programs requires root privileges:

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

- Requires `root` to load eBPF probes.
- Requires Linux 5.8 or newer (6.0 on arm64) with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`).
- The flow list keeps every flow seen since the start. On a host that opens thousands of connections per second it grows without bound.
- At most 256 flows can be selected at a time. With `--select-port`, many short flows on that port use them up.
- Data is held in memory only; closing the window discards all recorded points.
