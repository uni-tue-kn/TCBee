# TCBee Database Access Examples

Examples for reading the flow databases written by `tcbee-process` with plain SQL. The files are ordinary SQLite or DuckDB databases (schema version 2), so any client works. The scripts here need only Python 3; DuckDB files need `pip install duckdb` and plotting needs `pip install matplotlib`.

To try them without a recording, process the test traces of the repository:

```bash
tcbee-process -s tcbee-process/tests/fixtures/tcbee_small -o /tmp/small.sqlite
./list_flows.py /tmp/small.sqlite
./plot_cwnd.py /tmp/small.sqlite        # lists the flows; pass the id of one of them to plot it
```

Databases from earlier TCBee versions (`time_series` and `time_series_data` tables) cannot be read; process the recording again.

## Database schema

Besides the catalog tables there is one table per kind of recorded event, with one row per record. The complete description is in [ts-storage/README.md](../../ts-storage/README.md#database-layout-schema-version-2).

| Table | Content |
|---|---|
| `meta(key, value)` | `schema_version` is `'2'`; also `writer`, `trace_dir`, `created_at` |
| `flows(id, src, dst, sport, dport, l4proto)` | one row per flow; ports are in host byte order |
| `series(id, flow_id, kind, source, dir, name, value_type, tbl, col, n, t_min, t_max, v_min, v_max)` | one row per series: a column of an event table for one flow and direction, or a series computed in `tcbee-viz` |
| `ev_sock`, `ev_tcp_probe`, `ev_cwnd`, `ev_cubic`, `ev_bbr`, `ev_tcp4`, `ev_tcp6` | the events: `flow_id`, `dir`, `ts`, `seq`, then one column per field |
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
./list_flows.py <database>              # one line per flow
./list_flows.py <database> --verbose    # and the series of each flow
```

```
Found 83 flows in /tmp/small.sqlite

ID     Flow                                                     Series   Values
==================================================================================
37     192.168.1.22:52668 -> 85.115.13.250:8080 (TCP)           78       45408
35     192.168.1.22:37806 -> 37.51.193.149:8080 (TCP)           78       30685
```

### `plot_cwnd.py`

Plots the congestion window of a flow, read straight from the event tables: `ev_sock.snd_cwnd` (send side) and `ev_tcp_probe.SND_CWND`. Other columns work too, as `<source>.<column>`.

```bash
./plot_cwnd.py <database>                       # list the flows
./plot_cwnd.py <database> 3                     # plot flow 3
./plot_cwnd.py <database> 3 --series sock.snd_cwnd,sock.snd_ssthresh,tcp_probe.SRTT
./plot_cwnd.py <database> 3 --dir recv          # receive side of sock, cwnd, tcp4, tcp6
./plot_cwnd.py <database> 3 --output cwnd.png
```

## Queries

`SELECT` statements for `sqlite3` or the `duckdb` shell. Flow ids are assigned while processing and differ from run to run: look yours up in `flows` (or with `list_flows.py`) and replace the `3` below. The same goes for the ids in the sample output above.

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
import sqlite3          # for DuckDB: import duckdb; db = duckdb.connect(path, read_only=True)

db = sqlite3.connect("/tmp/small.sqlite")
for fid, src, dst, sport, dport in db.execute("SELECT id, src, dst, sport, dport FROM flows"):
    print(f"flow {fid}: {src}:{sport} -> {dst}:{dport}")

rows = db.execute(
    "SELECT ts, snd_cwnd FROM ev_sock WHERE flow_id = ? AND dir = 1 ORDER BY ts, seq", (3,)
).fetchall()
t0 = rows[0][0]
for ts, cwnd in rows[:5]:
    print(f"t={(ts - t0) / 1e9:.6f}s cwnd={cwnd}")
```

Both modules use `?` placeholders, so the same code runs on both engines.
