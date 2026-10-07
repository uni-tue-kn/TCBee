# TCBee

## Prerequisites

- Rust stable (1.82 or newer): `rustup toolchain install stable`
- clang 11 or newer, to compile the eBPF programs in `tcbee/src/bpf/`
- libclang, used by bindgen for the shared record layout (`tcbee/src/bpf/records.h`)
- libelf and zlib development headers, found through pkg-config, plus make and a C compiler
  for the bundled libbpf

On Debian/Ubuntu:

```shell
sudo apt install -y clang libclang-dev libelf-dev zlib1g-dev pkg-config make
```

No nightly toolchain or `bpf-linker` is needed.

## Build & Run

```shell
cargo build --release
sudo ./target/release/tcbee-record -h eth0 -k
# or
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- -h eth0 -k
```

The build script compiles `tcbee/src/bpf/tcbee.bpf.c` with clang against the vendored
`vmlinux.h` and embeds it through a libbpf-rs skeleton. The header contains only the kernel
declarations this program uses, based on a `bpftool btf dump` of the BTF from
`7.2.6-arch2-1` on x86_64. The full generated snapshot is retained in git history at
`62d6a14` (SHA-256: `a6f878f35ad62431d24155959ec44570b7d8c3faab90f5ea796f2b75d5e28dbf`).
Builds do not need `bpftool` or the build host's kernel BTF. Kernel struct offsets are
relocated against the running kernel's BTF at load time (CO-RE), so one binary runs on
different kernels. Update the compact header when the BPF program reads new kernel fields.

By default libbpf is linked statically and libelf and zlib dynamically. Release builds use

```shell
cargo build --release --features static
```

which builds libelf and zlib from source as well and links all three statically, so the
binary only needs glibc. This additionally needs autoconf, automake, autopoint (gettext),
libtool, flex, bison and gawk:

```shell
sudo apt install -y autoconf automake autopoint gettext libtool flex bison gawk
```

## Options

At least one metric source is required.

| Flag | Description |
|---|---|
| `-h IFACE` | TCP headers via TC on the given interface |
| `-t` | `tcp_probe` and related tracepoints (most TCP metrics) |
| `-k` | fentry on `__tcp_transmit_skb` and `tcp_rcv_established` (all TCP metrics) |
| `-w` | `snd_cwnd` only (best performance, single metric) |
| `-a` | Congestion control internals (Cubic and BBR) |

| Flag | Default | Description |
|---|---|---|
| `-d DIR` | `/tmp/` | Output directory; the recording goes to `DIR/tcbee_YYYY-MM-DDTHH-MM-SS` |
| `--duration SECS` | `0` | Stop after this many seconds; 0 records until Ctrl+C |
| `-c N` | `1` | Number of CPUs used for processing |
| `-q` | | Disable the terminal UI |
| `-m` | | Write a `metrics.json` summary file |
| `--tui-update-ms N` | `100` | TUI refresh interval in milliseconds |
| `--tui-observation-window-s N` | `0` | Sliding window of the TUI graphs in seconds; 0 shows the whole recording |
| `--poll busy\|wait` | `busy` | Writer threads spin (one core per ring buffer) or block until the kernel signals records |
| `--writer-cpus LIST` | | CPU ids to pin the writer threads to, round-robin |
| `--ringbuf-size SIZE` | | Ring buffer size (K, M, G suffixes), one value or per group, see `--help` |

Raw data is written as `*.tcp` files to the recording directory. Filter flags are described under [Filtering](#filtering).

## Kernel requirements

- BTF of the running kernel (`/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF=y`)
- 5.12: every probe numbers its events per flow with a fetch-and-add atomic (`hook_seq`).
  Ring buffers (5.8), fentry programs and `bpf_skc_to_tcp_sock` (5.9) are older; the
  `tcp_bad_csum` tracepoint of `-t` appeared in 5.11.
- `-a` with CUBIC or BBR built as a module needs module BTF (5.11). BBR is only traced if
  `tcp_bbr` is loaded (or built in) when tcbee-record starts; otherwise it records CUBIC only
  and logs an error. Load it beforehand with `sudo modprobe tcp_bbr`.
- `-h` attaches with tcx on 6.6 and newer. Older kernels use a clsact qdisc, which
  tcbee-record creates through netlink (no `tc` command needed) and removes again on exit
  if it created it.

## Filtering

By default no filter is enabled, so probes only take the fast no-filter branch.

Use `-p`/`--port` for the fastest filtered mode when you only need one local or remote port:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- -k --port 443
```

For more flexible filtering, use the map-backed filter options:

```shell
--ports 80,443
--src-ports 12345
--dst-ports 443
--ips 10.0.0.1,2001:db8::1
--src-ips 10.0.0.10
--dst-ips 10.0.0.20
```

Ports and IPs are exact matches. `--ports` and `--ips` match either source or destination;
the `src`/`dst` variants require that direction. Values inside the same option are ORed.
Different dimensions are ANDed, so `--ports 80,443 --ips 10.0.0.1` records traffic where
either endpoint port is 80 or 443 and either endpoint IP is `10.0.0.1`.
