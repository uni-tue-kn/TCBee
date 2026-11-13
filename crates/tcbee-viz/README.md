# tcbee-viz

Part of [TCBee](../README.md). A desktop viewer for the databases that `tcbee-process` writes.

```bash
tcbee-viz /tmp/myflow.duck     # or start without an argument and open a file from Home
```

It takes one database path (`.duck`, `.duckdb`, `.sqlite`, `.db`) or `-h` for help.

## Tabs

| Tab | Shows |
|---|---|
| Home | Opens a database. If the open button is not visible, enlarge the window. |
| Overview | What wrote the database. For recordings made with `tcbee-record --metadata` also the host, kernel, probes, clocks, TCP sysctls, interfaces and the counters that changed during the recording. |
| Single Flow | Pick a flow under *Flow Selection*, tick metrics (e.g. `snd_cwnd`) under *Metrics*. *Split into separate plots* gives each metric its own plot. |
| Multi Flow | Two flows (*Flow A*, *Flow B*) on one time axis. |
| MPTCP | Only for recordings made with `tcbee-record -m`. Lists the connections with their side, plots chosen metrics of all subflows of one connection stacked on one time axis below a lane of its path manager events, and lists the subflows with their bytes and share and a filterable list of the events. |
| Process | Plugins that compute derived series from a flow: bytes in flight, usable send window, duplicate ACKs, retransmissions, sender limitation, loss episodes, upper TCP window. *Load & Preview* plots the result, *Save to database* stores it as new series of the flow. |
| Settings | Text size, downsampling, time granularity, dark mode. |

## Flow filter

The flow table names the process of each flow as `name[pid]`, with the command line on hover, and the MPTCP connection of each subflow.
Plain text in its filter searches all columns and the process names.
`column:value` limits a term, and terms separated by spaces must all match:

```
src:10.0.0.1 dport:5201      id:52   sport:443   port:443   dst:192.168
conn:3      (flows of MPTCP connection 3)
proc:curl   pid:4242   uid:1000   cmd:https   (process name, PID, user, command line)
```

## Runtime requirements

`tcbee-viz` needs a display with OpenGL. It loads the GL, EGL, X11 or Wayland libraries at runtime; on Debian/Ubuntu these are:

```bash
sudo apt install libgl1 libegl1 libxkbcommon0 libxkbcommon-x11-0 libwayland-client0 \
    libx11-6 libxcursor1 libxi6 libxrandr2
```

The Open dialog uses `xdg-desktop-portal` with a desktop backend, or `zenity` if no portal answers.

## Building

`make viz` in the repository root builds it into `bin/`, `sudo make install` installs it. Without DuckDB: `make viz CARGO_FLAGS="--no-default-features --features sqlite"`; opening a `.duck` file then shows an error.
Cargo features and DuckDB linking are described in the [tcbee-process Building section](../tcbee-process/README.md#building).
