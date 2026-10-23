# Testing Environment

Emulates a bottleneck topology using [Mininet](http://mininet.org) to test `tcbee-live`, `tcbee-record`, and the full record/process/visualize flow under controlled congestion.

## Topology

```
TCBeeHost ──100 Mbps── s1 ──10 Mbps── s2 ──100 Mbps── ReceivingHost
10.0.0.1                    ↑ bottleneck               10.0.0.2
```

`iperf3` drives a long-lived TCP flow from TCBeeHost through the bottleneck.

## Prerequisites

Python 3, Mininet, Open vSwitch and iperf3, and root privileges for Mininet and eBPF.

### Arch Linux
```bash
sudo pacman -S mininet openvswitch iperf3
sudo systemctl start ovsdb-server ovs-vswitchd
```

### Debian / Ubuntu
```bash
sudo apt install mininet openvswitch-switch iperf3 python3
```

## Build

From the repo root, build whichever tool you want to test:

```bash
make           # build record, process, viz, and live
# or individually:
make record
make process
make viz
make live
```

The interactive launcher also has a rebuild menu with per-tool options and an `all` option.

## Running

```bash
python3 testing/run.py
```

The interactive menu lets you pick the tool, congestion algorithm (CUBIC / BBR), single or double stream or the MPTCP scenario (below), and (for `tcbee-record`/`tcbee-full`) which probes to enable.

- **tcbee-live** opens as a GUI window; the Mininet CLI stays in the terminal. Type `exit` to stop.
- **tcbee-record** runs as a TUI in the current terminal. Quit with `q` or `Ctrl-C` to stop the topology.
- **tcbee-full** first runs `tcbee-record` exactly like the record mode. Quit the recorder with `q` when you have captured enough data; the launcher then stops Mininet, runs `tcbee-process --duckdb --force` to create (or replace) `/tmp/db.duck`, and opens `tcbee-viz /tmp/db.duck`.

In double-stream mode a second iperf3 flow starts 30 s after the first.

### Headless

```bash
python3 testing/run.py --headless [--duration SECONDS]
```

runs tcbee-full without the recorder's terminal UI: `tcbee-record -q --duration SECONDS` stops by itself (default 30 s, 60 s with two streams), then the launcher stops Mininet, processes the recording and opens it in tcbee-viz, as in tcbee-full. The tool menu is skipped; scenario and recording profile are still asked. `topology.py --tool full --headless [--duration SECONDS]` does the same without menus.

In record/full mode the topology passes map-backed filters to `tcbee-record` so recordings are limited to the test flow(s): port `5001` for single-stream runs, ports `5001,5002` for double-stream runs, `5003` for the MPTCP scenario, and traffic whose source and destination endpoints are the two Mininet test hosts.

### MPTCP scenario

The MPTCP scenario (tcbee-record and tcbee-full only) shows the MPTCP tab of tcbee-viz. It adds a second path to the topology and runs one MPTCP connection over both:

```
TCBeeHost ──100 Mbps── s1 ──10 Mbps, 40 ms── ReceivingHost     path 1, 10.0.0.1 ↔ 10.0.0.2
          ──100 Mbps── s2 ──20 Mbps, 10 ms──                   path 2, 10.0.1.1 ↔ 10.0.1.2
```

The connection opens over path 1 three seconds after the recorder starts and sends as fast as it can for 40 s. From its start:

| Time | Action | What tcbee-viz shows |
|------|--------|----------------------|
| 5 s | TCBeeHost adds an MPTCP endpoint on path 2 | a second subflow joins and takes most of the data (shorter RTT) |
| 15 s | path 2 drops every packet | the subflow goes stale, its data is reinjected on path 1 |
| 22 s | path 2 works again | data flows over path 2 again after the next retransmission timeout (the recovery itself is not an event) |
| 28 s | the path 2 endpoint becomes backup | MP_PRIO; the data moves to path 1 |
| 34 s | the path 2 endpoint is deleted | the subflow closes |
| 40 s | the transfer ends | the connection closes |

The launcher adds `-m` to the recording flags; record with `-k` (kernel functions, or the full trace) to get the metrics of every subflow. While the recorder's terminal UI runs, the steps are logged to `/tmp/tcbee-mptcp.log`. A headless run records 48 s. The scenario needs a kernel with MPTCP and tc ingress filters (`sch_ingress`, `cls_matchall`, `act_gact`), which drop the packets of path 2. `mptcp/traffic.py` generates the traffic, so iperf3 needs no MPTCP support.

## Tuning

Edit the constants at the top of `topology.py`:

| Variable | Default | Meaning |
|----------|---------|---------|
| `UPLINK_BW` | 100 Mbps | Bandwidth on access links |
| `BOTTLENECK_BW` | 10 Mbps | Bottleneck bandwidth |
| `BOTTLENECK_DELAY` | 40 ms | One-way delay on the bottleneck link |
| `QUEUE_SIZE` | 150 pkts | Bottleneck queue depth |

## MPTCP

The scripts in `mptcp/` test MPTCP recording without Mininet. `mptcp/run.sh` checks one short recording. It builds two network namespaces joined
by two veth pairs, so an MPTCP connection gets one subflow per path, records it next to a plain
TCP connection with `tcbee-record -k -m`, and checks the recording with `mptcp/check_trace.py`.
If a SQLite build of `tcbee-process` exists (`TCBEE_PROCESS`, default
`target/release/tcbee-process`), it also processes the recording and checks the connections in
the database. It needs root, iproute2 with `ip mptcp` and an MPTCP kernel, and uses the release
build of `tcbee-record` (`TCBEE_RECORD` overrides it):

```bash
sudo testing/mptcp/run.sh [SECONDS]
```

`mptcp/eval.py` repeats such runs with independent oracles: the applications' own view of
their connections (token and subflows from `MPTCP_INFO` and `MPTCP_SUBFLOW_ADDRS`), `ip mptcp
monitor` and the MPTcpExt counters of each namespace, and bpftrace counters on the same hooks.
Scenarios: `static`, `churn` (many short connections), `dynamic` (endpoints added, changed and
removed mid-connection), `e6` and `stale` (a path that fails silently), `fallback` (the
MPTCP option stripped from the SYNs). `mptcp/verify.py` checks one repetition and writes
`verify.json`:

```bash
sudo testing/mptcp/eval.py dynamic --reps 3 --out /tmp/mptcp-runs
```
