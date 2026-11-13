# TCBee Database Access Examples

Examples for reading flow databases written by `tcbee-process`. The scripts use
[the Python API](../../tcbee-python/README.md) to browse flows and load metrics.
Install from the repository root:

```bash
python -m pip install './tcbee-python[duckdb,plot]'
```

The files are ordinary SQLite or DuckDB databases (schema version 3), so any SQL
client also works. The query examples below remain usable directly.

To try them without a recording, process the test traces of the repository:

```bash
tcbee-process -s tcbee-process/tests/fixtures/tcbee_small -o /tmp/small.sqlite
python examples/db/list_flows.py /tmp/small.sqlite
python examples/db/plot_cwnd.py /tmp/small.sqlite        # lists the flows; pass the id of one of them to plot it
```

Databases from earlier TCBee versions (`time_series` and `time_series_data` tables) cannot be read; process the recording again.

## Plotting cookbook

Run commands from the repository root. Every script accepts `--help`, works
with SQLite or DuckDB, and exports PNG, SVG or PDF with `--output`. Without
`--output` it opens an interactive Matplotlib window. For a server or notebook
runner without a display, prefix commands with `MPLBACKEND=Agg`.

| Script | Use it for |
|---|---|
| [plot_metrics.py](plot_metrics.py) | One flow, one panel per metric; shared time axis and independent value axes |
| [compare_flows.py](compare_flows.py) | Overlay one metric from several flows with explicit time alignment |
| [plot_large_metric.py](plot_large_metric.py) | Millions of samples rendered as a bounded min/max envelope |
| [plot_cwnd.py](plot_cwnd.py) | A small full-resolution congestion-window example |
| [list_flows.py](list_flows.py) | Find IDs, filter tuples/processes, and inspect available metrics |

### 1. Discover what was recorded

```bash
python examples/db/list_flows.py /tmp/small.sqlite --metric sock.snd_cwnd --limit 10 --verbose
```

Choose a flow ID from that output. IDs vary between processing runs. For the
commands below, set `FLOW_ID` to that ID:

```bash
FLOW_ID=3  # replace 3 with an ID from your own database
```

The API can also discover one automatically, without guessing an ID:

```python
import tcbee

with tcbee.open("/tmp/small.sqlite") as db:
    flows = db.flows().with_series(source="sock", name="snd_cwnd", direction="send")
    for flow in flows.top(size=5):
        print(flow.id, str(flow), flow.sample_count)
```

The metric catalog reflects the recording flags and selected fields. A
recording made with `-w` may provide `cwnd.snd_cwnd`, while `-k` provides
`sock.snd_cwnd`. Inspect available sources and names before changing a script.
Metric names retain their original case.

### 2. Plot several metrics on separate panels

```bash
python examples/db/plot_metrics.py /tmp/small.sqlite "$FLOW_ID" \
    --metric sock.snd_cwnd --metric sock.bytes_acked --output metrics.png
```

Each `--metric SOURCE.NAME` adds a panel. Omitting it selects `sock.snd_cwnd`
and `sock.bytes_acked`. Every panel uses the same flow-relative clock; metrics
with different sample times remain independent. Value axes use raw stored
units, so counters and window sizes do not share an axis.

Zoom without loading the rest of the recording:

```bash
python examples/db/plot_metrics.py recording.duck "$FLOW_ID" \
    --metric sock.snd_cwnd --start 1.5 --end 3 --output zoom.pdf
```

The window is [1.5, 3) seconds since the flow's earliest catalog sample. A
missing metric or empty window produces an error with guidance; there is no
silent substitution. Use `--dir recv` for receive-side metrics. Sources that
have no direction (`tcp_probe`, `cubic`, `bbr`, `derived`) explicitly use
`"none"` in these examples.

### 3. Compare flows

Automatic selection chooses up to four matching flows, ranked by their total
catalog sample-value count. This runs without selecting IDs first:

```bash
python examples/db/compare_flows.py /tmp/small.sqlite \
    --metric sock.bytes_acked --limit 3 --align flow --output comparison.svg
```

Filter automatic selection by either endpoint and port:

```bash
python examples/db/compare_flows.py recording.duck \
    --host 10.0.0.1 --port 5201 --limit 4 --output comparison.png
```

Or pass explicit IDs from the same database:

```bash
python examples/db/compare_flows.py recording.duck 12 18 27 \
    --metric sock.snd_cwnd --align recording --ylabel "Congestion window (segments)" \
    --output windows.pdf
```

Choose alignment deliberately:

- `--align recording` (default) preserves when flows occurred relative to each
  other. Zero is the earliest selected flow's start; this is not Unix time.
- `--align flow` gives each flow its own zero at its first catalog sample,
  useful for comparing evolution after startup. It does not imply simultaneity.

`--start` and `--end` use the chosen origin: one shared recording-relative
window, or the same elapsed interval separately for each flow. Every selected
flow must contain finite samples of that metric in the chosen window. Flow
filters apply only to automatic selection; explicit IDs select those flows.
The legend retains IDs and endpoints so the overlay is traceable.

### 4. Plot a metric containing millions of samples

```bash
python examples/db/plot_large_metric.py recording.duck "$FLOW_ID" \
    --metric sock.snd_cwnd --bins 2000 --batch-size 65536 --output overview.svg
```

This streams every selected sample through `iter_batches()` and retains only
the minimum and maximum per time bin. A short spike remains visible in its
bin; taking every Nth sample could miss it. Empty bins remain gaps. NULL,
NaN and infinite values do not contribute to extrema. The script reports
the number of finite samples it processed.

`--bins` sets a maximum: intervals shorter than that many nanoseconds use
fewer bins. `--start` and `--end` optionally restrict the SQL read, in seconds
since flow start. With no window, the final recorded sample is included.

Python result memory is O(batch size + bins), and the figure has O(bins)
vertices. Database scan/sort workspace is separate. This is an explicit
visual summary: it does not preserve the order of changes within each bin,
sample counts per bin, or a time-weighted average. Use the full-resolution
scripts or zoom into a shorter window when individual transitions matter.
The library itself never downsamples.

### Appearance, export and customization

The new examples share [\_plotting.py](_plotting.py), a short helper with a
blue/teal/orange palette, light grid, readable labels and export settings.
Change `COLORS` or `style()` there to match your paper or presentation.
`--title`, `--dpi` and `--output` are available on all three new scripts.
PNG defaults to 180 DPI. SVG/PDF preserve text and axes as vector content;
the full-resolution scripts rasterize dense data lines to keep exports
manageable. The bounded envelope remains vector content.

Values are raw: the examples do not guess kernel-specific scaling or turn
cumulative byte counters into rates. Set a suitable `--ylabel` in comparison
and envelope plots, or edit the panel label. Plotting converts values to
floating point, so adjacent very large integers may look identical; retain
the API's original integer samples for exact counter calculations.

For your own script, start with this small core:

```python
import matplotlib.pyplot as plt
import tcbee

with tcbee.open("recording.duck") as db:
    flow = (
        db.flows().with_series(source="sock", name="snd_cwnd", direction="send").first()
    )
    if flow is None:
        raise RuntimeError("No send-side sock.snd_cwnd metric was recorded")
    metric = flow.series().one(source="sock", name="snd_cwnd", direction="send")
    data = metric.read_numpy()
    time_s = (data["ts_ns"] - flow.start_ns) / 1e9

plt.step(time_s, data["value"], where="post")
plt.xlabel("Time since flow start (seconds)")
plt.ylabel("Congestion window (segments)")
plt.savefig("cwnd.png", dpi=180, bbox_inches="tight")
```

Subtract the integer origin before converting to floating seconds. Compare
metrics by their timestamps, not by row index. The [API reference](../../tcbee-python/API.md)
lists all query and read methods; the [performance guide](../../tcbee-python/README.md#large-metrics)
explains full-resolution NumPy reads versus streaming batches.

## Database schema

Besides the catalog tables there is one table per kind of recorded event, with one row per record. The complete description is in [ts-storage/README.md](../../ts-storage/README.md#database-layout-schema-version-3).

| Table | Content |
|---|---|
| `meta(key, value)` | `schema_version` is `'3'`; also `writer`, `trace_dir`, `created_at` |
| `flows(id, src, dst, sport, dport, l4proto)` | one row per flow; ports are in host byte order |
| `connections`, `connection_flows` | connection groups and time-scoped subflow memberships |
| `flow_owners` | optional timestamped process-owner observations |
| `series(id, flow_id, kind, source, dir, name, value_type, tbl, col, n, t_min, t_max, v_min, v_max)` | one row per series: a column of an event table for one flow and direction, or a series computed in `tcbee-viz` |
| `ev_sock`, `ev_tcp_probe`, `ev_cwnd`, `ev_cubic`, `ev_bbr`, `ev_tcp4`, `ev_tcp6`, `ev_mptcp_pm`, `ev_tcp_event` | the events: `flow_id`, `dir`, `ts`, `seq`, then one column per field |
| `derived_samples(series_id, ts, seq, v_int, v_float, v_bool, v_text)` | the points of derived series |

- `ts` is nanoseconds since boot (the recorder's `bpf_ktime_get_ns()`), `seq` the index of the record in its file. Sort by `ts, seq`.
- `dir` is 0 (no direction: `tcp_probe`, `cubic`, `bbr`), 1 (send) or 2 (receive). `sock`, `cwnd`, `tcp4` and `tcp6` have both.
- `series.kind` is 0 for series of the `ev_*` tables (`tbl` and `col` say where) and 1 for derived series. `n`, `t_min`, `t_max`, `v_min` and `v_max` are precomputed.
- Column names keep their original case (`SND_CWND`, `perf_snd_cwnd`, `bic_K`), so quote them in SQL.
- SQLite stores unsigned 64-bit values as signed integers: `max_pacing_rate` of `u64::MAX` reads as `-1`. DuckDB has unsigned columns.

## Scripts

### `list_flows.py`

Lists the flows with their number of series and values.

```bash
python examples/db/list_flows.py <database>              # first 50 flows, in ID order
python examples/db/list_flows.py <database> --verbose    # and the series of each flow
python examples/db/list_flows.py <database> --port 5201 --process iperf3
python examples/db/list_flows.py <database> --metric sock.snd_cwnd --limit 20
python examples/db/list_flows.py <database> --all        # explicitly display all matches
```

### `plot_cwnd.py`

Plots the congestion window of a flow, loaded through the Python API: `ev_sock.snd_cwnd` (send side) and `ev_tcp_probe.SND_CWND`. Other columns work too, as `<source>.<column>`.

```bash
python examples/db/plot_cwnd.py <database>                       # list the flows
python examples/db/plot_cwnd.py <database> 3                     # plot flow 3
python examples/db/plot_cwnd.py <database> 3 --series sock.snd_cwnd,sock.snd_ssthresh,tcp_probe.SRTT
python examples/db/plot_cwnd.py <database> 3 --dir recv          # receive side of sock, cwnd, tcp4, tcp6
python examples/db/plot_cwnd.py <database> 3 --output cwnd.png
python examples/db/plot_cwnd.py <database> 3 --start 1 --end 5 # seconds since flow start, [1, 5)
```

## Queries

`SELECT` statements for `sqlite3` or the `duckdb` shell. Flow ids are assigned while processing and differ from run to run: look yours up in `flows` (or with `list_flows.py`) and replace the `3` below. Use IDs from your own catalog.

The send-side congestion window of flow 3 over time:

```sql
SELECT ts, snd_cwnd FROM ev_sock WHERE flow_id = 3 AND dir = 1 ORDER BY ts, seq;
```

Several fields of the same record at once, with time in seconds since the flow's first sample:

```sql
SELECT (ts - MIN(ts) OVER ()) / 1e9 AS t, "SND_CWND", "SSTRESH", "SRTT"
FROM ev_tcp_probe WHERE flow_id = 3 ORDER BY ts, seq;
```

Which series does a flow have, and how long are they:

```sql
SELECT source, dir, name, n, t_min, t_max, v_min, v_max
FROM series WHERE flow_id = 3 ORDER BY source, dir, name;
```

The three flows with the most `sock` rows:

```sql
SELECT flow_id, COUNT(*) AS rows FROM ev_sock WHERE dir = 1
GROUP BY flow_id ORDER BY rows DESC LIMIT 3;
```

A series computed in `tcbee-viz` (the point value is in `v_int`, `v_float`, `v_bool` or `v_text`, depending on `series.value_type`):

```sql
SELECT d.ts, d.v_float FROM derived_samples d JOIN series s ON s.id = d.series_id
WHERE s.flow_id = 3 AND s.name = 'my_metric' ORDER BY d.ts, d.seq;
```

## Python

```python
import sqlite3  # for DuckDB: import duckdb; db = duckdb.connect(path, read_only=True)

db = sqlite3.connect("/tmp/small.sqlite")
for fid, src, dst, sport, dport in db.execute(
    "SELECT id, src, dst, sport, dport FROM flows"
):
    print(f"flow {fid}: {src}:{sport} -> {dst}:{dport}")

rows = db.execute(
    "SELECT ts, snd_cwnd FROM ev_sock WHERE flow_id = ? AND dir = 1 ORDER BY ts, seq",
    (3,),
).fetchall()
t0 = rows[0][0]
for ts, cwnd in rows[:5]:
    print(f"t={(ts - t0) / 1e9:.6f}s cwnd={cwnd}")
```

Both modules use `?` placeholders, so the same code runs on both engines.
