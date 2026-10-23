# TCBee

## Prerequisites

- Rust stable (1.82 or newer): `rustup toolchain install stable`
- clang 11 or newer, to compile the eBPF programs in `tcbee/src/bpf/`
- libclang, only for `cargo test`: the `records_gen` test of tcbee-common checks that the
  checked-in Rust records (`tcbee-common/src/records_gen.rs`) match `tcbee/src/bpf/records.h`.
  After changing records.h, regenerate them with
  `TCBEE_REGEN_RECORDS=1 cargo test -p tcbee-common --test records_gen`
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
| `-t` | The TCP tracepoints: `tcp_probe` (most TCP metrics at every received segment), SYN-ACK retransmissions and bad checksums, and as discrete TCP events (`tcp_events.tcp`) retransmissions, RSTs sent and received, TCP state changes, congestion state changes (Open, Disorder, CWR, Recovery, Loss), retransmission timeouts and destroyed sockets. Each event hook is optional: one the kernel lacks or rejects is left out with a warning |
| `--tp LIST` | The tracepoints of `-t` to record, implies `-t`. Names: `probe`, `synack`, `bad_csum`, `retransmit`, `rst_sent`, `rst_received`, `state`, `ca_state`, `rto`, `destroy`, and `drops`, which `-t` leaves out: the packets of TCP flows that the kernel drops (`kfree_skb`), with the drop reason, and `drop_reasons.json` with the reason names of the running kernel. `all` and `default` name the sets. A list of only `+name` and `-name` items changes the default set, e.g. `--tp +drops,-probe` |
| `-k` | fentry on `__tcp_transmit_skb` and `tcp_rcv_established` (all TCP metrics), and fexit on `tcp_write_timer_handler` (`timer_sock.tcp`, see below) |
| `-w` | `snd_cwnd` only (best performance, single metric) |
| `-a` | Congestion control internals (Cubic and BBR) |
| `-e`, `--drops` | Kept for old command lines: `-e` records the TCP events of `-t` only, `--drops` those and the drops |
| `-m` | MPTCP (`-M` works too): path manager and connection lifecycle events, stale subflows, sent MP_PRIO, data-level reinjections and the fallback to TCP in the handshake (`mptcp_pm.tcp`), and with `-k` or `-w` the token of its MPTCP connection in every record of a subflow (`conn_id`) |

| Flag | Default | Description |
|---|---|---|
| `-d DIR` | `/tmp/` | Output directory; the recording goes to `DIR/tcbee_YYYY-MM-DDTHH-MM-SS` |
| `--duration SECS` | `0` | Stop after this many seconds; 0 records until Ctrl+C |
| `-c N` | `1` | Number of CPUs used for processing |
| `-q` | | Disable the terminal UI |
| `--metrics` | | Write a `metrics.json` summary file |
| `--metadata` | | Write `metadata.json` with the host, kernel, TCP sysctls, interfaces (MTU, offloads, qdiscs), the command line, skipped hooks, clock offsets and drop counters, at start and again at stop |
| `--tui-update-ms N` | `100` | TUI refresh interval in milliseconds |
| `--tui-observation-window-s N` | `0` | Sliding window of the TUI graphs in seconds; 0 shows the whole recording |
| `--poll busy\|wait` | `busy` | Writer threads poll and sleep 50 µs when a poll returns fewer than 256 records, or block until the kernel signals records |
| `--writer-cpus LIST` | | CPU ids to pin the writer threads to, round-robin |
| `--ringbuf-size SIZE` | | Size of each CPU's ring buffer (K, M, G suffixes), one value or per group, see `--help` |
| `--mptcp-modes LIST` | `pm`, `tag` with `-k`/`-w` | What `-m` records, comma-separated: `tag`, `pm` |
| `--on-change FIELDS` | | `-k` and `-w` write a record only when a watched field changed, see [On-change mode](#on-change-mode) |
| `--on-change-hooks LIST` | `ingress,timer` | With `--on-change`: the kernel hooks to compare at, `ingress`, `timer`, `egress` |
| `--on-change-shadow` | | With `--on-change` and `-k`: write every run, with the decision in `ato` |
| `--no-timer-hook` | | With `-k`: leave out the write timer records (`timer_sock.tcp`), see [Write timer records](#write-timer-records) |

Every probe output has one ring buffer per online CPU, so a probe never waits for another
CPU to reserve space. The default sizes per CPU (tcp4 and sock 16 MiB, cwnd, cubic and bbr
8 MiB, tcp6 and tcp_probe 4 MiB, sock_timer 1 MiB) need about 40 MiB per CPU with `-h` and
110 MiB per CPU with all probes; the log at startup prints the total. Records of one flow come from several CPUs,
so their file order is not their order at the hook: every record carries `hook_seq`, its
position among the events of its flow direction at its hook.

Next to every trace file with records, `<file>.cpu` tells which CPU's ring buffer each record
came from: one 12-byte entry per run of consecutive records from the same CPU, the u64 index of
the run's first record and the u32 CPU id, little endian. A last entry with CPU id `0xFFFFFFFF`
holds the number of records; without it the file was cut short. With the per-CPU drop counters
of `metrics.json`, it places a gap in a flow's `hook_seq` on the CPU whose ring was full.

Raw data is written as `*.tcp` files to the recording directory. Filter flags are described under [Filtering](#filtering).

## On-change mode

`--on-change FIELDS` makes the sock (`-k`) and cwnd (`-w`) probes write a record only when a
watched field or the socket state changed since the connection's last record, on a flow's
first run and after a dropped record. Unchanged runs are counted as `suppressed` per ring
buffer in `metrics.json` and take no `hook_seq`, so gaps in `hook_seq` are still exactly the
dropped records. The default mode is unchanged.

- `FIELDS` is a preset or a comma-separated list of `sock_trace_entry` fields; the cwnd probe
  watches `snd_cwnd`. `cc` watches the sender's congestion control state (`snd_cwnd`,
  `snd_ssthresh`, `total_retrans`, `backoff`, `rto`, `reordering`, `rcv_mss`), `rcv` the
  receiver's (`rcv_mss`, `rcv_space`, `rcv_ssthresh`, `rcv_rtt`). Fields that change on
  almost every packet (`bytes_acked`, `bytes_received`, `segs_in`, `segs_out`, `rttvar`,
  `pacing_rate`) bring back nearly every record; tcbee-record warns about them. Quantised
  fields are not supported yet.
- `--on-change-hooks` picks the kernel hooks that compare (default `ingress,timer`):

  | Hook | Kernel hook | Runs | File |
  |------|-------------|------|------|
  | `ingress` | `fexit/tcp_rcv_established`, `fexit/tcp_rcv_state_process` | after each received segment (ESTABLISHED; the other states except LISTEN and CLOSE) | `recv_*_oc.tcp` |
  | `timer` | `fexit/tcp_write_timer_handler` | after each retransmission, loss probe, RACK reordering or zero window probe timer, also when deferred to `tcp_release_cb` | `recv_*_oc.tcp` |
  | `egress` | `fentry/__tcp_transmit_skb` | before each transmitted segment | `send_*_oc.tcp` |

  On a sender almost every change of `cc` comes from ACK processing (ingress); the timer hook
  adds what the retransmission timers change while no ACK arrives (Loss, `total_retrans`,
  `backoff`, `rto`). Changes of the send path (cwnd restart after idle, app-limited cwnd
  reduction) are seen by ingress at the next ACK; `egress` records them at once, at the cost of
  one probe run per transmitted segment. Ingress and timer records carry the state after the
  segment or timer was processed, egress records the state before the transmit. The default
  `-k`/`-w` programs use fentry on both sides and record the state before.
- The sock and cwnd probes each keep one last state per connection, which every hook
  compares with and updates, so a change is written once, by the first hook that sees it.
  Ingress and timer records share the receive file and its `hook_seq`; send and receive file
  have their own `hook_seq`, so with `egress` the order between the two files is only the
  order of their timestamps.
- The records go to `recv_sock_oc.tcp` and `recv_cwnd_oc.tcp`, with `egress` also to
  `send_sock_oc.tcp` and `send_cwnd_oc.tcp`, next to a `manifest.json` that lists the watched
  fields and the kernel hooks of every file. tcbee-process stores them as the sources
  `sock_oc` and `cwnd_oc`, and tcbee-viz draws the watched fields as steps: a value holds
  until the next record. The other columns of these files are samples taken when a watched
  field changed. With `egress`, the state of a connection is the send and receive file merged
  by time; tcbee-viz still draws each file as its own series.
- Listeners and closed sockets write no records, so neither the close nor an RST sent after
  it is recorded.
- In on-change sock records, bits 8-15 of `ato` tell the hook that wrote the record
  (1 ingress, 2 timer, 3 egress); tcbee-process stores the raw value in the `ato` column
  (256, 512, 768). cwnd records carry no hook.
- Each socket keeps the last written values in BPF socket storage (about 190 bytes, freed
  with the socket). A socket without storage writes every run and counts as `state_errors`.
- `--on-change-shadow` writes every run anyway and puts the decision into bits 0-7 of `ato`:
  1 suppressed, 2 a watched field changed, 3 first run or after a drop, 4 socket state
  changed, 5 no socket storage. A replay of such a trace checks the decisions record by
  record (`testing/onchange_smoke.sh`).

## Write timer records

`-k` also writes the socket after every run of the write timer handler
(`fexit/tcp_write_timer_handler`, also when deferred to `tcp_release_cb`) to `timer_sock.tcp`:
retransmission timeouts, loss probes, RACK reordering timeouts and zero window probes.

- The records carry the state after the timer was handled, and 2 (timer) in bits 8-15 of
  `ato`, as on-change timer records do. They do not say which timer ran: a retransmission
  timeout shows as a higher `backoff` and `total_retrans` than in the flow's previous record,
  and runs that found no timer due change nothing.
- `timer_sock.tcp` has its own ring buffer (1 MiB per CPU, size group `sock_timer`) and its own
  `hook_seq`, so its order with `send_sock.tcp` and `recv_sock.tcp` is only the order of the
  timestamps. Its `hook_seq` counters take one more entry per flow in the `HOOK_SEQ` map
  (262144 entries for all hooks).
- The hook is optional: if the kernel lacks the function or rejects the program, tcbee-record
  runs without it and lists it as skipped in the metadata. `--no-timer-hook` leaves it out on
  purpose, which the metadata lists too.
- In on-change mode the `timer` hook writes into `recv_sock_oc.tcp` instead.
- tcbee-process reads `timer_sock.tcp` into the table `sock_timer`, with the columns of
  `sock`. The TUI counts the timer runs with the receive side.

## Kernel requirements

- BTF of the running kernel (`/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF=y`)
- 5.12: every probe numbers its events per flow with a fetch-and-add atomic (`hook_seq`).
  Ring buffers (5.8), fentry programs and `bpf_skc_to_tcp_sock` (5.9) are older; the
  `tcp_bad_csum` tracepoint of `-t` appeared in 5.11.
- `--on-change` uses BPF socket storage in fentry/fexit programs (5.11). The timer hook needs
  `tcp_write_timer_handler` as a traceable (not inlined) function with BTF; checked on 6.8.
- `-a` with CUBIC or BBR built as a module needs module BTF (5.11). BBR is only traced if
  `tcp_bbr` is loaded (or built in) when tcbee-record starts; otherwise it records CUBIC only
  and logs an error. Load it beforehand with `sudo modprobe tcp_bbr`.
- The TCP events of `-t` attach BTF tracepoints (`tp_btf`) and fentry. Congestion state changes
  need the `tcp_cong_state_set` tracepoint (5.19); older kernels record CWR through `tcp_enter_cwr`
  instead, which may miss the CWR after ECN marks where the compiler inlined the call. RSTs that
  the stack sends without a socket and state changes before a socket has both ports (an active
  open entering SYN_SENT) are only recorded for flows that already have records.
- `--tp +drops` runs on every packet the kernel frees as dropped, so it costs a little on a host
  with many drops of other traffic. Drop reasons exist from 5.17 on; before, the reason is 0.
  Drops of packets without a full socket are only recorded for flows that already have a TCP
  event record, so the drops of a flow that started before the recording show up after its
  first other event (or its first drop with a socket).
- `-m` needs MPTCP in the kernel (`CONFIG_MPTCP`, 5.6). Without it, `conn_id` stays 0 and no path
  manager events are recorded. A path manager hook whose kernel function is missing or inlined
  is left out with a warning. Not recorded: a stale subflow becoming active again and the
  fallback on the server side (both run through inlined code on 6.8).
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
