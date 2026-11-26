# SQL access

The databases written by `tcbee-process` are plain SQLite or DuckDB files.
This page describes their tables and gives queries for any SQL client.
For the Python library and plots, see [examples/README.md](../README.md).

## Database schema

Besides the catalog tables there is one table per kind of recorded event, with one row per record. The complete description is in [crates/ts-storage/README.md](../../crates/ts-storage/README.md#database-layout-schema-version-3).

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

## Queries

`SELECT` statements for `sqlite3` or the `duckdb` shell. Flow ids are assigned while processing and differ from run to run: look yours up in `flows` (or with `examples/python/list_flows.py`) and replace the `3` below.

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
