# TCBee Python API

Read and explore completed TCBee SQLite or DuckDB databases (schema version 3).
Install from the repository with `python -m pip install ./tcbee-python`.
SQLite needs no additional dependencies; DuckDB support is available through
`python -m pip install './tcbee-python[duckdb]'`.

## Find flows and metrics

```python
import tcbee

with tcbee.open("recording.sqlite") as db:  # also accepts DuckDB; detects the file header
    flows = db.flows().filter(host="10.0.0.1", port=5201)
    flows = flows.with_series(source="sock", name="snd_cwnd", direction="send")
    flows.show(limit=20)

    page = flows.page(size=50)
    if page.next_cursor is not None:
        next_page = flows.page(size=50, after=page.next_cursor)

    flow = flows.first()  # None if empty; one() instead requires exactly one match
    if flow is not None:
        flow.series().show()
        metric = flow.series().one(source="sock", name="snd_cwnd", direction="send")
        samples = metric.read()
```

`db.flow(id)` and `db.series(id)` look up database-local IDs. IDs can differ
between processing runs. A flow describes a five-tuple, which can be reused
across connection lifetimes; it does not necessarily describe one socket.
IPv6 filters accept either compressed or expanded addresses.

Queries are immutable and filter in SQL. `filter()` combines fields with AND:
`id`, `src`, `dst`, `sport`, `dport`, `l4proto`, `host` (either address), `port`
(either port), `start_ns`, `end_ns` and `min_duration_ns`. Time filters match
catalog spans, which can contain gaps. `with_series()` filters metric
availability. There is no sample-value predicate or arbitrary filter language.

`page(size=50, after=...)` uses stable ID order without OFFSET. Its continuation
token belongs to the same database connection and equivalent query, and is
not a persistent bookmark. `for flow in flows` traverses bounded pages.
`count()` explicitly counts matches. `top(size=20, by="sample_count")` and
`top(size=20, by="duration_ns")` return a bounded tuple of ranked flows,
with ID as the tie breaker. Ranking and time/duration filters can scan the entire catalog. Ordinary
pages select IDs first, then summarize only those flows.
`show()` prints a bounded table without counting all matches.

Browsing reads catalog metadata, not event samples. `sample_count` sums
metric values: several fields of one event count as several samples. It is
not a packet count. Series `minimum` and `maximum` are approximate stored
catalog summaries; unsigned values above i64::MAX were saturated by the
catalog writer. Actual sample reads preserve the full unsigned value.

## Load metrics for a custom plot

```python
import matplotlib.pyplot as plt
import tcbee

with tcbee.open("recording.sqlite") as db:
    flow = (
        db.flows()
        .filter(dport=5201)
        .with_series(source="sock", name="snd_cwnd", direction="send")
        .first()
    )
    if flow is None:
        raise RuntimeError("No matching flow")
    metric = flow.series().one(source="sock", name="snd_cwnd", direction="send")
    samples = metric.read()

# Loaded samples remain usable after closing the database.
plt.step(samples.seconds(origin_ns=flow.start_ns), samples.values, where="post")
plt.xlabel("Time since flow start (seconds)")
plt.ylabel("Congestion window")
plt.show()
```

`Samples` contains three lists: `ts_ns`, `seq`, and `values`, plus `value_type`.
Raw and derived series have the same read API, including bool, integer, float
and text values. `metric.read(start_ns=..., end_ns=...)` selects a half-open
**[start_ns, end_ns)** interval. This differs from the Rust reader's inclusive
ranges. Equal timestamps are retained and ordered by `(ts, seq)`; completely
equal ordering keys have no defined order among themselves.

Timestamps are exact integer nanoseconds since boot, not Unix time. Use one
explicit origin for all metrics being compared. Subtract integer timestamps
before converting to seconds to avoid losing precision. `created_at` is the
database creation time and cannot anchor samples to wall-clock time.

Directions are `"send"`, `"recv"` and `"none"`. Omitting direction selects a
series only if the remaining filters uniquely identify it; otherwise `one()`
raises `AmbiguousSelection` with candidate details. A missing selection raises
`NotFound`. Directionless sources such as `tcp_probe` use `"none"`; the library
does not silently substitute another direction. `flow.series().filter(...)`
returns an iterable catalog query. Each metric retains its own sample times;
reads do not join, interpolate or resample different metrics.

## Large metrics

For millions of samples, limit the time window or process bounded batches:

```python
with tcbee.open("recording.sqlite") as db:
    metric = db.series(123)  # use an ID from your own catalog
    for batch in metric.iter_batches(batch_size=65_536):
        consume(batch.ts_ns, batch.values)  # your own processing function
```

Streaming performs one SQL query and fetches batches through an independent
cursor, without repeated scans or OFFSET pagination. Stop early with
`iterator.close()` (or `contextlib.closing`) to release its cursor. Closing the
database also closes all active cursors; further reads raise `ClosedDatabase`.
The database must stay open throughout iteration and be used from one thread.
Only completed files are supported; live external modification is outside the
API contract.

For plotting with NumPy, install `./tcbee-python[numpy,duckdb]` and use:

```python
with tcbee.open("recording.duck") as db:
    arrays = db.series(123).read_numpy()  # eager dict: ts_ns, seq, value
    # DuckDB exports directly to NumPy without Python row materialization.
    # SQLite uses the batched reader and converts the result to arrays.
```

`samples.to_numpy()` converts an existing `Samples` batch. NumPy arrays keep
integer timestamps and unsigned counters exact. Nullable values use object
dtype with `None`. With `./tcbee-python[pandas]`, `samples.to_frame()` returns
`ts_ns`, `seq` and `value` columns with explicit nullable integer dtypes.
Stored NULL stays `None` in list reads; floating NaN stays NaN where the engine
preserves it. SQLite stores NaN as NULL, so it cannot be recovered there.
Dataframe float columns containing NULL use object dtype to retain the
NULL/NaN distinction.

Only requested columns, flows, directions and time ranges are read. SQLite
uses the event indexes created by `tcbee-process`; DuckDB handles its own
scans and sorts. Batching bounds Python result memory, not the database
engine's buffers or sort workspace. Eager reads require memory proportional
to the selected sample count. No downsampling or truncation is implicit.

The reproducible synthetic benchmark is:

```bash
python tcbee-python/benchmarks/read_metric.py --samples 1000000
```

Example local results for one million samples, warm-cache median of three
reads, including result conversion and checksum validation:

| Backend | List read | Streaming batches | NumPy read |
|---|---:|---:|---:|
| SQLite | 1.16 s | 0.96 s | 1.20 s |
| DuckDB | 0.72 s | 0.62 s | 0.055 s |

SQLite peak process RSS was about 172 MiB for the list read and 56 MiB for
streaming; DuckDB used about 369 MiB and 275 MiB respectively, including engine
buffers. These are illustrative local measurements, not performance
guarantees. Use the benchmark on your hardware and representative recordings.

The many-flow benchmark separately checks navigation without any event data:

```bash
python tcbee-python/benchmarks/browse_flows.py --flows 20000 --metrics 20
```

With 20,000 flows and 400,000 catalog entries, a 50-flow page took about 1 ms
on SQLite and 6.5 ms on DuckDB locally. Traversing all flows took about 0.44 s
and 0.56 s respectively. Actual costs depend on filters, layout and hardware.

## Owners and MPTCP connections

```python
with tcbee.open("recording.sqlite") as db:
    flows = db.flows().owned_by(comm="iperf3")  # exact process name
    flows = flows.owned_by(pid=1234)  # additional owner condition
    flows.show()
    for owner in db.flow(1).owners():
        print(owner.ts_ns, owner.pid, owner.comm, owner.cmdline)
    for connection in db.flow(1).connections():
        connection.subflows().show()
        print(connection.memberships())  # retains subflow IDs and intervals
```

`owned_by(pid=..., uid=..., comm=..., cmdline_contains=...)` requires supplied
fields to match the same owner observation. Chained calls are independent
historical conditions: each may match a different observation. Owner and time
filters do not infer ownership of particular metric samples. Owners are
plural and timestamped; PID alone is not a permanent process identity.

Older schema-v3 databases may lack optional owner/connection tables.
`flow.owners()` and `flow.connections()` return empty tuples when unavailable;
inspect `db.tables` to distinguish unavailable metadata. Filters requiring
absent tables raise `MissingCapability`, rather than returning misleading
empty results.

`db.connection(id)` returns connection metadata and navigation methods.
`connection.flows()` includes its own metric flow and member flows;
`connection.subflows()` includes only member flows. `connection.memberships()`
returns recorded intervals with inclusive last-observation timestamps.
`db.flows().with_connection(id)` filters directly by connection membership.

## Errors and tests

`TCBeeError` covers library selection, schema and capability errors.
File-system and driver errors retain their original types. Missing paths are
never created; old schemas require reprocessing with `tcbee-process`. Install
`duckdb` to read DuckDB files; missing optional imports raise `ImportError`.

```bash
python -m pip install './tcbee-python[test]'
python -m unittest discover -s tcbee-python/tests -v
ruff check tcbee-python
ruff format --check tcbee-python
```

Both backends use the same contract tests. Optional adapter/backend tests
are skipped when dependencies are missing. Set `TCBEE_PROCESS` to a built
`tcbee-process` executable to also run the repository trace integration test.
Set `TCBEE_TEST_ENGINES=sqlite,duckdb` to exercise both processor backends.
