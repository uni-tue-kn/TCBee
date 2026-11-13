# Python API reference

Import the public API with `import tcbee`. Python 3.10 or newer is required.
SQLite uses the standard library. DuckDB, NumPy and pandas are optional;
see [installation and the user guide](README.md) and the
[plotting examples](../examples/db/README.md#plots).

## Database

```python
with tcbee.open("recording.sqlite") as db:
    print(db.engine, db.metadata)
    db.flows().show()
```

Files open read-only and are detected by their header, regardless of extension.
Only completed schema-v3 files are supported. Missing paths are never created.

| Member | Result |
|---|---|
| `tcbee.open(path)` | Context-managed `Database`; accepts a string or path-like object |
| `db.path` | Resolved `pathlib.Path` |
| `db.engine` | `"sqlite"` or `"duckdb"` |
| `db.metadata` | `dict[str, str]` from `meta`, including available `run.*` metadata |
| `db.tables` | Frozen set of table names, useful for detecting optional metadata |
| `db.flows()` | Lazy, immutable `FlowQuery` |
| `db.flow(id)` | One `Flow`, or `NotFound` |
| `db.series(id)` | One `Series`, or `NotFound` |
| `db.connection(id)` | One `Connection`; requires connection metadata |
| `db.close()` | Close active cursors and the connection; repeated calls are safe |

Use one database instance per thread. Keep it open while evaluating queries
or iterators. Loaded `Flow`/`Series` metadata, `Samples` and NumPy arrays are
ordinary Python data; database-backed navigation and reads require the open
connection. A continuation token cannot be saved and reused after reopening.

## FlowQuery

```python
flows = (
    db.flows()
    .filter(host="192.0.2.10", port=5201)
    .with_series(source="sock", name="snd_cwnd", direction="send")
)
page = flows.page(size=50)
for flow in page.items:
    print(flow.id, flow.sample_count)
if page.next_cursor is not None:
    next_page = flows.page(size=50, after=page.next_cursor)
```

Each filter returns a new query; it leaves the original unchanged. Filters
compose with AND and are evaluated in SQL. `filter()` accepts:

| Keyword | Meaning |
|---|---|
| `id` | Database-local integer flow ID |
| `src`, `dst` | Exact IP address; IPv6 spellings are normalized |
| `sport`, `dport` | Exact port, 0–65535 |
| `l4proto` | Numeric IP protocol, 0–255; TCP is 6 |
| `host` | Either endpoint has this IP address |
| `port` | Either endpoint has this port |
| `start_ns`, `end_ns` | Observed catalog span overlaps the half-open boot-ns interval |
| `min_duration_ns` | Observed span is at least this many nanoseconds |

Omitted keywords impose no condition. Time bounds are nonnegative integers.
Span matching does not guarantee samples inside a gap in that span.

| Method | Result / behavior |
|---|---|
| `with_series(source=None, name=None, direction=None)` | Require a matching catalog metric |
| `owned_by(pid=None, uid=None, comm=None, cmdline_contains=None)` | Require an owner observation; supplied fields match the same observation |
| `with_connection(id, include_connection_flow=True)` | Require membership or the connection's own metric flow |
| `show(limit=20, file=None)` | Print at most `limit` flows, without a full count |
| `page(size=50, after=None)` | `FlowPage(items=tuple[Flow, ...], next_cursor=token_or_None)` in ID order |
| `count()` | Explicit integer match count |
| `first()` | First ID-ordered `Flow`, or `None` |
| `one()` | Exactly one match; raises `NotFound` or `AmbiguousSelection` |
| `top(size=20, by="sample_count")` | Bounded tuple ranked by sample count or `"duration_ns"`, ties by ID |
| `iter(flows)` | Iterate bounded ID-ordered pages |

Ordinary pages summarize only selected flows. Time filters and rankings may
aggregate the whole catalog. Browsing and availability filters never read
metric samples. Process/connection filters use existence checks and do not
duplicate flows. Historical owner filtering is independent of time filtering;
it does not assign individual metric samples to a process.

## Flow

| Attribute | Meaning |
|---|---|
| `id` | Database-local tuple ID; not a permanent connection or socket ID |
| `src`, `dst`, `sport`, `dport`, `l4proto` | Recorded five-tuple |
| `series_count` | Number of catalog metrics |
| `sample_count` | Sum of metric sample counts, not packets or distinct events |
| `start_ns`, `end_ns` | Earliest/latest catalog timestamp, or `None` without samples |
| `duration_ns` | `end_ns - start_ns`, or `None` |

`str(flow)` formats the ID and endpoints, including IPv6 brackets.
`flow.series()` returns a `SeriesQuery`. `flow.owners()` returns a tuple of
`FlowOwner` observations; `flow.connections()` returns a tuple of connections.
These return empty tuples if the respective optional tables are absent.

## SeriesQuery and Series

```python
catalog = flow.series()
catalog.show(limit=30)
for metric in catalog.filter(source="sock", direction="send"):
    print(metric.id, metric.name, metric.value_type, metric.sample_count)
metric = catalog.one(source="sock", name="snd_cwnd", direction="send")
```

`SeriesQuery.filter(source=None, name=None, direction=None, kind=None)` returns
a new query. `kind` is `"raw"` or `"derived"`. `one(**filters)` requires exactly
one match; `first()` returns a match or `None`. Iteration streams catalog rows.
`show(limit=30, file=None)` prints a bounded preview.

Directions are `"send"`, `"recv"` and `"none"`; `"none"` is direction zero,
not a wildcard. Omitting direction in `one()` succeeds only if unique. Names
are case-sensitive, for example `sock.snd_cwnd` versus `tcp_probe.SND_CWND`.
Inspect the catalog rather than assuming a recording contains every metric.

| Series attribute | Meaning |
|---|---|
| `id`, `flow_id` | Database-local catalog and flow IDs |
| `kind`, `source`, `name`, `direction` | Metric identity |
| `value_type` | `"bool"`, `"u8"`, `"u16"`, `"u32"`, `"u64"`, `"i64"`, `"f64"` or `"text"` |
| `sample_count` | Stored number of values |
| `start_ns`, `end_ns` | Exact stored integer bounds, or `None` |
| `minimum`, `maximum` | Approximate catalog bounds, or `None`; u64 bounds may be saturated |

| Read method | Result |
|---|---|
| `metric.read(start_ns=None, end_ns=None)` | Eager `Samples` containing lists |
| `metric.iter_batches(batch_size=65536, start_ns=None, end_ns=None)` | Iterator of `Samples`, one SQL query and independent cursor |
| `metric.read_numpy(start_ns=None, end_ns=None)` | Eager dict of NumPy arrays: `ts_ns`, `seq`, `value` |

Every time window is **[start_ns, end_ns)**, in nanoseconds since boot. Omitted
bounds are unbounded. Reads order by `(ts, seq)` and retain duplicate keys;
order among completely equal keys is unspecified. Raw and derived metrics
use the same interface. No read changes units, joins sources, resamples or
silently truncates results. A stale catalog with a missing event column
raises a database driver error.

NumPy export uses DuckDB's native column export; SQLite converts batched list
reads. Nullable arrays use object dtype with `None`. Stop a batch iterator
early with `iterator.close()` or `contextlib.closing(iterator)`. Python result
memory is bounded by batch size; engine scans and sorting may use more memory.

## Samples

| Member | Meaning |
|---|---|
| `ts_ns`, `seq`, `values` | Equally sized lists of timestamps, sequence numbers and values |
| `value_type` | Same type label as the originating series |
| `len(samples)` | Number of samples |
| `samples.seconds(origin_ns=...)` | List of floating seconds after exact integer subtraction |
| `samples.to_numpy()` | Dict with `ts_ns`, `seq` and singular `value` keys |
| `samples.to_frame()` | pandas DataFrame with `ts_ns`, `seq`, `value` columns |

Python list reads restore the full unsigned 64-bit value on SQLite as well as
DuckDB. Arrays/dataframes use integer or nullable integer dtypes. Plotting
usually converts values to float, which cannot distinguish every adjacent
large integer. Keep the original samples for exact counter calculations.

Stored NULL becomes `None`. tcbee-process never writes NaN. Nullable NumPy
arrays and nullable floating dataframe columns use object dtype, so NULL stays
`None`. No adapter aligns different metrics by row number.

## Owners and connections

`FlowOwner` retains `flow_id`, `ts_ns`, `source`, `pid`, nullable `uid`, `comm`,
nullable `cmdline`, `start_time_ns`, `cgroup_id`, `cgroup`, `netns`, and boolean
`kthread`. Ownership observations are plural and timestamped; tuple reuse or
shared sockets can produce several records. PID plus available process start
time identifies a process more reliably than PID alone.

`Connection` retains `id`, `kind`, `key`, nullable `flow_id`, `start_ns` and
`end_ns`. Its methods are:

- `flows()`: lazy `FlowQuery` including members and its own metric flow.
- `subflows()`: lazy query of members only.
- `memberships()`: tuple of `ConnectionMembership` with `connection_id`,
  `flow_id`, nullable `subflow_id`, `first_ns`, and inclusive `last_ns`.

A flow may belong to several connections over different intervals. Membership
metadata does not automatically crop metric reads to those intervals.

## Exceptions

| Exception | When |
|---|---|
| `NotFound` | Required flow, connection or metric has no match |
| `AmbiguousSelection` | `one()` has multiple matches |
| `MissingCapability` | A requested filter/connection lookup needs absent optional tables |
| `UnsupportedDatabase` | Unrecognized file header |
| `UnsupportedSchema` | Missing/unsupported schema version; reprocess the recording |
| `ClosedDatabase` | Evaluating a query or iterator after closure |

These inherit from `TCBeeError`. Invalid arguments raise `ValueError`;
file-system and driver exceptions retain their original types. Missing
optional packages raise `ImportError` when their feature is used.
