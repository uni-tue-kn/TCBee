# Testing Environment

Emulates a bottleneck topology using [Mininet](http://mininet.org) to test `tcbee-live` and `tcbee-record` under controlled congestion.

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
cd tcbee-live   && cargo build
cd tcbee-record && cargo build
```

## Running

```bash
python3 testing/run.py
```

The interactive menu lets you pick the tool, congestion algorithm (CUBIC / BBR), single or double stream, and (for `tcbee-record`) which probes to enable.

- **tcbee-live** opens as a GUI window; the Mininet CLI stays in the terminal. Type `exit` to stop.
- **tcbee-record** runs as a TUI in the current terminal. Quit with `q` or `Ctrl-C` to stop the topology.

In double-stream mode a second iperf3 flow starts 30 s after the first.

## Tuning

Edit the constants at the top of `topology.py`:

| Variable | Default | Meaning |
|----------|---------|---------|
| `UPLINK_BW` | 100 Mbps | Bandwidth on access links |
| `BOTTLENECK_BW` | 10 Mbps | Bottleneck bandwidth |
| `BOTTLENECK_DELAY` | 40 ms | One-way delay on the bottleneck link |
| `QUEUE_SIZE` | 150 pkts | Bottleneck queue depth |
