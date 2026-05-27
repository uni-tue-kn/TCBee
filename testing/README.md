# Testing Environment

Emulates a bottleneck topology using [Mininet](http://mininet.org) to test `tcbee-live`, `tcbee-record`, and the full record/process/visualize flow under controlled congestion.

## Topology

```
TCBeeHost ──100 Mbps── s1 ──10 Mbps── s2 ──100 Mbps── ReceivingHost
10.0.0.1                    ↑ bottleneck               10.0.0.2
```

`iperf3` drives a long-lived TCP flow from TCBeeHost through the bottleneck.

## Prerequisites

### Arch Linux
```bash
sudo pacman -S mininet openvswitch iperf3
sudo systemctl start ovsdb-server ovs-vswitchd
```

### Debian / Ubuntu
```bash
sudo apt install mininet iperf3
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

The interactive menu lets you pick the tool, congestion algorithm (CUBIC / BBR), single or double stream, and (for `tcbee-record`/`tcbee-full`) which probes to enable.

- **tcbee-live** opens as a GUI window; the Mininet CLI stays in the terminal. Type `exit` to stop.
- **tcbee-record** runs as a TUI in the current terminal. Quit with `q` or `Ctrl-C` to stop the topology.
- **tcbee-full** first runs `tcbee-record` exactly like the record mode. Quit the recorder with `q` when you have captured enough data; the launcher then stops Mininet, runs `tcbee-process --duckdb` to create `/tmp/db.duck`, and opens `tcbee-viz /tmp/db.duck`.

In double-stream mode a second iperf3 flow starts 30 s after the first.

In record/full mode the topology passes map-backed filters to `tcbee-record` so recordings are limited to the test flow(s): port `5001` for single-stream runs, ports `5001,5002` for double-stream runs, and traffic whose source and destination endpoints are the two Mininet test hosts.

## Tuning

Edit the constants at the top of `topology.py`:

| Variable | Default | Meaning |
|----------|---------|---------|
| `UPLINK_BW` | 100 Mbps | Bandwidth on access links |
| `BOTTLENECK_BW` | 10 Mbps | Bottleneck bandwidth |
| `BOTTLENECK_DELAY` | 40 ms | One-way delay on the bottleneck link |
| `QUEUE_SIZE` | 150 pkts | Bottleneck queue depth |
