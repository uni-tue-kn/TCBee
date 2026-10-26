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
The declarations of the flow owner programs (`task_struct`, `proto_accept_arg` and the
flavours `sock_common___owner` and `mptcp_subflow_context___join`) come from the BTF of
`7.2.9-arch1-1`. A flavour (libbpf matches a struct by its name up to `___`) holds fields
of a struct that exists already, so that struct, and the code of the other programs, stays
as it was. Builds do not need `bpftool` or the build host's kernel BTF. Kernel struct
offsets are relocated against the running kernel's BTF at load time (CO-RE), so one binary
runs on different kernels. Update the compact header when the BPF program reads new kernel fields.

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
| `-h IFACE` | TCP headers on the given interface, via TC by default, see [Header records](#header-records) |
| `-t` | The TCP tracepoints: `tcp_probe` (most TCP metrics at every received segment), SYN-ACK retransmissions and bad checksums, and as discrete TCP events (`tcp_events.tcp`) retransmissions, RSTs sent and received, TCP state changes, congestion state changes (Open, Disorder, CWR, Recovery, Loss), retransmission timeouts and destroyed sockets. Each event hook is optional: one the kernel lacks or rejects is left out with a warning |
| `--tp LIST` | The tracepoints of `-t` to record, implies `-t`. Names: `probe`, `synack`, `bad_csum`, `retransmit`, `rst_sent`, `rst_received`, `state`, `ca_state`, `rto`, `destroy`, and `drops`, which `-t` leaves out: the packets of TCP flows that the kernel drops (`kfree_skb`), with the drop reason, and `drop_reasons.json` with the reason names of the running kernel. `all` and `default` name the sets. The list works as described below the table, e.g. `--tp +drops,-probe` |
| `-k` | The socket (all TCP metrics) at the hooks of `--sock-hooks`: by default after every run of the write timer (`timer_sock.tcp`, see below) and at TCP events (`event_sock.tcp`), none per packet. On a sender, `--sock-hooks +ingress` adds the state after every ACK |
| `-w` | `snd_cwnd` only (best performance, single metric) |
| `-a` | Congestion control internals of CUBIC, BBR and Reno, see [Congestion control records](#congestion-control-records) |
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
| `--tui-observation-window-s N` | `0` | Start the TUI charts with a window of N seconds, rounded up to 10 s, 30 s, 1, 2, 5, 10 or 30 min; 0 starts with the whole recording, see [Terminal UI](#terminal-ui) |
| `--poll busy\|wait` | `busy` | Writer threads poll and sleep 50 µs when a poll returns fewer than 256 records, or block until the kernel signals records |
| `--writer-cpus LIST` | | CPU ids to pin the writer threads to, round-robin |
| `--ringbuf-size SIZE` | | Size of each CPU's ring buffer (K, M, G suffixes), one value or per group, see `--help` |
| `--headers-at HOOKS` | `tc` | With `-h`: where the headers are recorded, `tc`, `driver` or `tc,driver`, see [Header records](#header-records) |
| `--yes` | | Do not ask for confirmation (`--headers-at tc,driver`) |
| `--mptcp-modes LIST` | `pm`, `tag` with `-k`/`-w` | What `-m` records, comma-separated: `tag`, `pm` |
| `--on-change FIELDS` | | `-k` and `-w` write a record only when a watched field changed, see [On-change mode](#on-change-mode) |
| `--on-change-hooks LIST` | `ingress,timer` | With `--on-change`: the kernel hooks to compare at, `ingress`, `timer`, `egress`; the list works as described below the table |
| `--on-change-shadow` | | With `--on-change` and `-k`: write every run, with the decision in `ato` |
| `--sock-hooks LIST` | `timer,state,ca-state,retransmit,restart,rcvbuf` | With `-k`: the kernel hooks to record the socket at. Per packet: `egress` (`send_sock.tcp`), `ingress-entry` (`recv_sock.tcp`) and `ingress` (`ingress_sock.tcp`, the state after each received segment: fexit on `tcp_rcv_established` and `tcp_rcv_state_process`; tcbee-process table `sock_ingress`). Not per packet: `timer` (`timer_sock.tcp`) and the socket event hooks `state`, `ca-state`, `retransmit`, `restart`, `rcvbuf` (`event_sock.tcp`, see [Socket event records](#socket-event-records)). The list works as described below the table, e.g. `+ingress` on a sender. With `--on-change` and `-k` the same as `--on-change-hooks` |
| `--no-timer-hook` | | With `-k`: leave out the write timer records (`timer_sock.tcp`), see [Write timer records](#write-timer-records); same as `--sock-hooks -timer` |
| `--no-owners` | | Do not record the processes of the connections (`flow_owners.tcp`, `flow_owners.json`), see [Flow owners](#flow-owners) |

`--tp`, `--sock-hooks` and `--on-change-hooks` take the same kind of list: comma-separated
names form the set; `+name` and `-name` items add to or remove from the plain names of the
list, or from the option's default when the list has no plain names (`--tp +drops,-probe`,
`--sock-hooks +ingress`); `all` and `default` name those sets (`--tp all,-drops`); `_` and `-`
are the same in names. A list that selects nothing is an error.

Every probe output has one ring buffer per online CPU, so a probe never waits for another
CPU to reserve space. The default sizes per CPU are 16 MiB for tcp4 and sock (which also
sizes the ring of the `ingress` sock hook), 8 MiB for cwnd, cubic, bbr and reno, 4 MiB for
tcp6, tcp_probe and tcp_events, 128 KiB for owners, and 1 MiB for the rest. `-h` needs about 40 MiB per CPU, as
much again for the driver hooks, and all rings together 181.1 MiB with the 128 KiB of the owners; the log at startup prints the
total. Records of one flow come from several CPUs, so their file order is not their order at
the hook: every record carries `hook_seq`, its position among the events of its flow
direction at its hook.

Next to every trace file with records, `<file>.cpu` tells which CPU's ring buffer each record
came from: one 12-byte entry per run of consecutive records from the same CPU, the u64 index of
the run's first record and the u32 CPU id, little endian. A last entry with CPU id `0xFFFFFFFF`
holds the number of records; without it the file was cut short. With the per-CPU drop counters
of `metrics.json`, it places a gap in a flow's `hook_seq` on the CPU whose ring was full.

Raw data is written as `*.tcp` files to the recording directory. Filter flags are described under [Filtering](#filtering).

## Terminal UI

Without `-q`, tcbee-record shows what it records while it runs.

- **Left column**: the elapsed time, the recording directory, the interface and the CPUs
  with a ring buffer; *Health* with records written per second (`rec/s`), probe runs per
  second (`runs/s`: written, dropped, failed and, in on-change mode, suppressed runs),
  dropped records per second and in total, the dropped share of all records (`drop %`,
  dropped / (written + dropped), since the start and in the last update), disk write rate
  and size, and a red line for state errors (on-change runs without socket storage) and
  failed kernel reads. Below, *Probe groups*: one row per group of ring buffers that records
  (`headers`, `sock`, `cc`, `tracept`, `tcp_ev`, `mptcp`, `owners`) with runs/s, rec/s and
  drops; `agg` is the share of header hook packets that stand for several segments (GSO,
  GRO, LRO), `supp` the share of runs suppressed in on-change mode. A group without a
  chart on screen shows a sparkline of its runs/s. *Skipped* lists the requested hooks
  that do not record, with the reason.
- **Charts**: up to four, in a fixed order: the events (records and drops per second, with
  a red sparkline of the dropped share from 0 to 1 % below), then headers (packets per
  second in and out, per hook), socket hooks, congestion control internals and the
  remaining groups. Each series is named in its colour in the chart title. The charts show
  the whole recording or a window of the last 10 s to 30 min at full resolution; the whole
  recording keeps the peak of each interval.
- **Flows**: the flows the probes saw (at most 100, the title says when the map is full),
  in the order they were first seen. With the owner programs (see [Flow owners](#flow-owners))
  a flow shows its local side first and the process that opened it (`comm[pid]`, `[kernel]`
  for a kernel thread); `svc` marks the local port of a connection the process accepted.
  Flows without a known owner are dimmed, show `?` as process and their endpoints in
  address order.
- **Small terminals**: below 120x30 the left column narrows and two charts are shown,
  below 80x24 no charts and every group gets a sparkline; below 40x12 only a hint.

| Key | Action |
|---|---|
| `q` | Stop recording and quit |
| `1`-`4` | Show that chart alone; `Esc` returns to all charts |
| `w` | Switch the charts between the whole recording and the window |
| `+` / `=`, `-` | Lengthen or shorten the window (and show it) |
| `e` | List the ring buffers of each probe group |
| `↑` `↓`, `PgUp` `PgDn`, `Home` `End` | Select a flow |

With the mouse, a click on a chart zooms it (a second click returns), the wheel scrolls the
flows and a click selects one.

## Header records

`-h IFACE` records the headers of the TCP packets on one interface: addresses, ports, sequence
and ACK numbers, window, flags, the ECN codepoint of the IP header (`ecn`) and, for sent
packets, `skb->tstamp` (`tstamp`), the earliest departure time that TCP or the qdisc (fq) set,
in CLOCK_MONOTONIC like the record time; 0 if none was set and for received packets.

`--headers-at` picks the hooks:

| Hook | Received packets | Sent packets | Files (tcbee-process table) |
|------|------------------|--------------|-------|
| `tc` (default) | TC ingress, after GRO | TC egress, before the qdisc and GSO | `tcp{4,6}_receive.tcp`, `tcp{4,6}_send.tcp` (`tcp4`, `tcp6`) |
| `driver` | native XDP, before GRO | `tp_btf/net_dev_start_xmit`, after the qdisc and software GSO | `tcp{4,6}_driver_receive.tcp`, `tcp{4,6}_driver_send.tcp` (`tcp4_driver`, `tcp6_driver`) |

- `tc,driver` records at both hooks into their own files, for instance to see per packet how
  long it waited in the qdisc or for its pacing time (`tcp4_send` against `tcp4_driver` with
  the same sequence number). Each hook costs time per packet, and XDP is attached, so
  tcbee-record asks for confirmation first; `--yes` skips the question, and without a
  terminal and without `--yes` it refuses to start.
- TC sees the packets as the stack handles them: with GSO or TSO a sent record can stand for
  several segments, with GRO a received one. tcbee-record logs this at the start.
- `driver` attaches an XDP program in native mode, which needs a driver with XDP support; it
  never uses generic XDP (which runs where TC does) and never replaces an XDP program that is
  already attached. The program passes every frame on and is detached on exit. Attaching XDP
  makes some drivers reset their rings, a short interruption of the traffic.
- `net_dev_start_xmit` runs for every device on the host; the program compares the device
  (ifindex and network namespace) first. With TSO on, the NIC segments after this hook, so a
  sent record can still stand for several segments; tcbee-record warns, `ethtool -K IFACE tso
  off` gives one record per segment. A packet the driver refuses for a full queue
  (`NETDEV_TX_BUSY`) passes the hook again when it is retried.
- Every header hook counts the packets that stand for several segments: GSO packets at TC
  egress and `net_dev_start_xmit` (`gso_segs` > 1), GRO packets at TC ingress, frames longer
  than the MTU at XDP. `metrics.json` has them as `aggregated` per ring buffer and in total,
  and tcbee-record prints a warning per hook at the end of a run that saw any.
- With LRO or hardware GRO (`rx-gro-hw`) the NIC merges received packets before any hook, and
  mlx5 refuses XDP then: `driver` stops with the hint `ethtool -K IFACE lro off rx-gro-hw off`.
  With `tc`, tcbee-record warns. The metadata lists `gro_hw` with the other offloads.

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
  segment or timer was processed, egress records the state before the transmit. The `egress`
  and `ingress-entry` hooks of `-k` and the `-w` programs use fentry and record the state
  before.
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

`-k` writes the socket after every run of the write timer handler
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
  `sock`. The TUI counts the timer runs with the socket events (`timer+ev`).

## Socket event records

The socket event hooks of `--sock-hooks` write the socket at TCP events, not per packet, to
`event_sock.tcp` (tcbee-process table `sock_event`):

| Hook | Kernel hook | Runs |
|------|-------------|------|
| `state` | `tp_btf/inet_sock_set_state` | at each TCP state change |
| `ca-state` | `tp_btf/tcp_cong_state_set` (5.19) | at each congestion state change (Open, Disorder, CWR, Recovery, Loss) |
| `retransmit` | `tp_btf/tcp_retransmit_skb` | at each retransmitted segment |
| `restart` | `fexit/tcp_cwnd_restart` | after the cwnd was cut for an idle period |
| `rcvbuf` | `tp_btf/tcp_rcvbuf_grow` (newer kernels, 7.2 has it) | when receive autotuning grows the buffer |

- Bits 8-15 of `ato` tell the hook (4 state, 5 ca-state, 6 retransmit, 7 restart, 8 rcvbuf).
  The state tracepoints run before the change, so the record still holds the old state and
  carries the new one in bits 16-23 of `ato`.
- All hooks share one ring buffer (1 MiB per CPU, size group `sock_event`) and one `hook_seq`
  series per flow, so their records are in order with each other.
- Each hook is optional: one the kernel lacks or rejects is left out with a warning and listed
  as skipped in the metadata.

## Congestion control records

`-a` writes the private state of CUBIC (`struct bictcp`, `cubic.tcp`) and BBR (`struct bbr`,
`bbr.tcp`) of every socket that uses them, before (fentry) or after (fexit) the hooked function:

| Hook | Kernel hook | Runs | `hook` |
|------|-------------|------|--------|
| ACK | `fentry/cubictcp_cong_avoid`, `fentry/bbr_main` | at each ACK that may grow the cwnd (CUBIC), at each ACK (BBR) | 1 |
| cwnd event | `fentry/cubictcp_cwnd_event_tx_start`, `fentry/bbr_cwnd_event_tx_start` (before 7.2 `*_cwnd_event`) | at the first transmission after idle (before 7.2 at every congestion avoidance event) | 2 |
| ssthresh | `fexit/cubictcp_recalc_ssthresh` | after CUBIC's loss reaction (entering Recovery, CWR or Loss): `last_max_cwnd` with fast convergence, the epoch ended | 3 |
| state | `fexit/cubictcp_state` | after each congestion state change, with the state entered in `new_state` (`TCP_CA_*`, 0 at the other hooks); entering Loss resets the CUBIC state. The state before the reset is in the ssthresh record just before if the RTO recalculated ssthresh (from Open or Disorder, after `high_seq` was acknowledged, or in Loss without retransmissions); after an RTO in CWR or Recovery before `high_seq` was acknowledged, or a repeated RTO, it is only in the last ACK record | 4 |

- The CUBIC ssthresh and state hooks are optional: one the kernel lacks or rejects is left out
  with a warning and listed as skipped in the metadata. The new `snd_ssthresh` is set by the
  caller after the ssthresh hook; `-k` or `-t` record it.

- The hooks of one algorithm share its ring buffer and one `hook_seq` series per flow, so their
  records are in order with each other.
- BBR records carry the state machine (`mode`: 0 STARTUP, 1 DRAIN, 2 PROBE_BW, 3 PROBE_RTT;
  `cycle_idx`, `pacing_gain` and `cwnd_gain` in units of 1/256, `full_bw_reached`,
  `full_bw_cnt`, `round_start`, `packet_conservation`, `idle_restart`), the maximum of the
  bandwidth filter (`max_bw`, packets per µs << 24) and the long-term (policer) estimate. ACK
  records also carry the rate sample that BBR's model is updated with (`rs_delivered` packets
  over `rs_interval_us`, `rs_rtt_us`, `rs_losses`, `rs_is_app_limited`; -1 marks a missing
  sample, 0 on kernels before 5.17). Fields that only BBRv1 has (`max_bw`, the `lt_*` fields,
  `packet_conservation`) are 0 with other BBR versions.

Reno keeps no private state. `-a` writes the socket's `snd_cwnd`, `snd_ssthresh`,
`snd_cwnd_cnt` and congestion state after Reno's functions to `reno.tcp` (tcbee-process table
`reno`), with their own ring buffer (8 MiB per CPU, size group `reno`) and `hook_seq`:

| Hook | Kernel hook | Runs | `hook` |
|------|-------------|------|--------|
| ACK | `fexit/tcp_reno_cong_avoid` | after each ACK that may grow the cwnd; `acked` is the number of packets it acknowledged | 1 |
| ssthresh | `fexit/tcp_reno_ssthresh` | after the loss reaction; `new_ssthresh` is the threshold the caller sets next | 3 |

- Other algorithms call these functions too (DCTCP, Vegas, Veno and others for their Reno
  phases), so `ca_name` holds the first 8 bytes of the socket's algorithm name as a
  little-endian u64 (`reno` is `0x6f6e6572`). DCTCP has its own ssthresh function, which is
  not hooked: its cwnd cut on ECN marks shows in `-k` or `-t` records only.
- Both hooks are optional together: if the kernel lacks or rejects one, `-a` records without
  Reno and lists it as skipped in the metadata.

## Flow owners

Every recording notes the process that opened each connection, unless `--no-owners` is given.
It never counts as something to record on its own: at least one of the flags above is still
needed. Nothing runs per packet.

- `flow_owners.tcp` (`struct flow_owner_entry`): one record per connect (fexit on
  `tcp_v4_connect` and `tcp_v6_connect`, when the connect started) and per accepted
  connection (fexit on `inet_csk_accept`), written in the context of the calling process. It
  holds the tuple local -> remote, `kind` (1 connect, 2 accept), the pid (tgid), the uid, the
  name and start time (ns since boot, as `/proc/<pid>/stat` shows it in ticks) of the
  process's thread group leader, the network namespace inode of the socket and the cgroup v2
  id. A worker thread (a thread pool, io_uring) names its process. The filter applies as to
  every other record. `hook_seq` is always 1: owner records take no `hook_seq` counter, the
  ring's drop counters account for losses, and a reused tuple has one record per connection,
  which time orders. Their counters follow the aggregated ones in `STATS`, so the slots of the
  other rings are the same as before; `metrics.json` lists the ring `FLOW_OWNERS` without
  `hook_seq_issued`.
- The IPv4 program leaves dual-stack sockets to the IPv6 one, which records a connect to an
  IPv4 peer once, with v4-mapped addresses. MPTCP subflows that the path manager adds are left
  out, tcbee-process gives them the owner of their connection. A connection that a kernel thread
  opens (NFS, an in-kernel server) keeps the thread, with `flags` 1 (`TCBEE_OWNER_KTHREAD`).
- `flow_owners.json`: once the programs run, a thread reads `/proc` as `netstat -p` does,
  the TCP tables of each network namespace once and the socket inodes of every process's file
  descriptors, and writes the connections that existed then (listeners and sockets without an
  inode left out) with every process that held them, at the start and again at stop. While
  recording, the writer of the owner ring hands each record to a thread that reads the
  command line of its process once, and keeps it only if the start time in
  `/proc/<pid>/stat` still matches the record's (pids are reused). At stop these processes are
  added to the file. A process that exits before it is looked at keeps its name only. The
  filter flags apply to the snapshot as to the records: it holds the connections they keep and
  only the processes of those.
- The recording holds the names and the command lines of these processes. Command lines can
  carry secrets (a token in an argument, a password in a URL); `--no-owners` leaves all of it
  out.
- An MPTCP connection that existed before the start has no owner: the process holds the
  MPTCP socket, which `/proc/net/tcp` does not list, and its subflows are sockets of the
  kernel without a file descriptor.
- The owner is the process that connected or accepted. A socket passed to another process,
  or inherited by a child, still names that one; for the connections of the snapshot every
  holder is listed. Names are cut to 15 characters by the kernel.
- The pids are those of the pid namespace tcbee-record sees in `/proc`, the owner records
  those of the initial one. Run tcbee-record in the pid namespace of the host (not in a
  container with a pid namespace of its own). Elsewhere it records the owners without the
  snapshot and the command lines, which would name other processes, and says so in a warning
  and in the skipped hooks of `metadata.json`.
- Each of the three programs is optional: one the kernel lacks or rejects is left out with a
  warning and listed as skipped in `metadata.json`, whose groups name `owners` when they
  record. `inet_csk_accept` takes its arguments differently from 6.10 on, the program reads
  the return value for both. `tcp_v6_connect` is in the module BTF when IPv6 is a module.

## Kernel requirements

- BTF of the running kernel (`/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF=y`)
- 5.12: every probe numbers its events per flow with a fetch-and-add atomic (`hook_seq`).
  Ring buffers (5.8), fentry programs and `bpf_skc_to_tcp_sock` (5.9) are older; the
  `tcp_bad_csum` tracepoint of `-t` appeared in 5.11.
- `--on-change` uses BPF socket storage in fentry/fexit programs (5.11). The timer hook needs
  `tcp_write_timer_handler` as a traceable (not inlined) function with BTF; checked on 6.8.
- `-a` with CUBIC or BBR built as a module needs module BTF (5.11). CUBIC and BBR are only
  traced if `tcp_cubic` or `tcp_bbr` is loaded (or built in) when tcbee-record starts;
  otherwise `-a` records the other algorithms, logs the missing one and lists it as skipped in
  the metadata. Load them beforehand with `sudo modprobe tcp_bbr`. `-a` fails only
  if the kernel has none of CUBIC, BBR and Reno and nothing else is recorded.
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
- `--headers-at driver` uses XDP with multi-buffer support (`xdp.frags`, 5.18) in native mode.
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

Ports and IPs are exact matches. An IPv4 address also matches its v4-mapped form
(`::ffff:10.0.0.1`), the address a dual-stack socket uses for an IPv4 peer, so it takes two of
the 1024 entries of a filter map. `--ports` and `--ips` match either source or destination;
the `src`/`dst` variants require that direction. Values inside the same option are ORed.
Different dimensions are ANDed, so `--ports 80,443 --ips 10.0.0.1` records traffic where
either endpoint port is 80 or 443 and either endpoint IP is `10.0.0.1`.
