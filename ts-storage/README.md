<div align="center">
 <h2>ts-storage: TCP Flow Database Interface</h2>

 ![image](https://img.shields.io/badge/licence-Apache%202.0-blue) ![image](https://img.shields.io/badge/lang-rust-darkred) ![image](https://img.shields.io/badge/part%20of-TCBee-yellow)
</div>

Part of [TCBee](../README.md). A Rust library that provides a unified interface for reading and writing TCP flow data to either a SQLite or DuckDB database.

- [Data Model](#data-model)
- [Setup](#setup)
- [Opening a Database](#opening-a-database)
- [Example](#example)
- [API Reference](#api-reference)
  - [Flows](#flows)
  - [Flow Attributes](#flow-attributes)
  - [Time Series](#time-series)
  - [Data Points](#data-points)
- [Error Handling](#error-handling)
- [Choosing a Backend](#choosing-a-backend)

## Data Model

<img src="doc/functions.png" alt="Data model" style="border-radius: 10px; border: 1px solid #000;"/>

A **Flow** represents a TCP connection, identified by its IP 5-tuple (source/destination address, source/destination port, protocol).

Each flow can have any number of **time series**, each holding measurements of a single typed metric over time. For example, a flow recorded with `-k`/`--kernel` will have separate time series for SEQ, ACK, cwnd, RTT, and so on.

A **time series** is typed at creation (`Int`, `Float`, `Boolean`, or `String`) and contains **data points**, each consisting of a timestamp (`f64`) and a value of the matching type.

**Flow attributes** are optional string-keyed metadata attached to a flow, useful for storing computed values or annotations that do not have a time dimension.

## Setup

Add `ts_storage` as a dependency in your `Cargo.toml`:

```toml
[dependencies]
ts_storage = { path = "../ts-storage" }
```

Both SQLite and DuckDB backends are compiled by default. SQLite is bundled. DuckDB requires a system installation of `libduckdb` — download the matching version from the [DuckDB releases page](https://github.com/duckdb/duckdb/releases).

## Opening a Database

Use `database_factory` to open or create a database file. The returned value implements `TSDBInterface`.

```rust
use ts_storage::{database_factory, DBBackend};

// DuckDB (recommended for analysis)
let db = database_factory(DBBackend::DuckDB("flows.duck".into()))?;

// SQLite
let db = database_factory(DBBackend::SQLite("flows.sqlite".into()))?;
```

The path is created if it does not exist. Tables are set up automatically on first open.

## Example

The following records two data points for a single flow and reads them back.

```rust
use std::net::IpAddr;
use ts_storage::{database_factory, DBBackend, DataPoint, DataValue, IpTuple};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = database_factory(DBBackend::DuckDB("flows.duck".into()))?;

    // Register a flow
    let tuple = IpTuple {
        src: "10.0.0.1".parse::<IpAddr>()?,
        dst: "10.0.0.2".parse::<IpAddr>()?,
        sport: 12345,
        dport: 5001,
        l4proto: 6,
    };
    let flow = db.create_flow(&tuple)?;

    // Create a typed time series for the congestion window
    let cwnd = db.create_time_series(&flow, "snd_cwnd", DataValue::Int(0))?;

    // Insert individual points
    db.insert_data_point(&cwnd, &DataPoint { timestamp: 0.0,  value: DataValue::Int(10) })?;
    db.insert_data_point(&cwnd, &DataPoint { timestamp: 0.05, value: DataValue::Int(12) })?;

    // Or insert in bulk (much faster for large recordings)
    let points: Vec<DataPoint> = (0..1000)
        .map(|i| DataPoint {
            timestamp: i as f64 * 0.001,
            value: DataValue::Int(10 + i),
        })
        .collect();
    db.insert_multiple_points(&cwnd, &points)?;

    // Iterate over all points
    for point in db.get_data_points(&cwnd)? {
        println!("{:.3}s  {}", point.timestamp, point.value.as_string());
    }

    // Query a time window
    for point in db.get_data_points_in_range(&cwnd, 0.2, 0.5)? {
        println!("{:.3}s  {}", point.timestamp, point.value.as_string());
    }

    // Get the time and value range without reading all points
    let bounds = db.get_time_series_bounds(&cwnd)?;
    println!(
        "t: {:.3} to {:.3},  cwnd min/max: {} / {}",
        bounds.xmin,
        bounds.xmax,
        bounds.ymin.as_ref().map(|v| v.as_string()).unwrap_or_default(),
        bounds.ymax.as_ref().map(|v| v.as_string()).unwrap_or_default(),
    );

    Ok(())
}
```

## API Reference

All methods return `Result<_, TSDBError>`.

### Flows

```rust
// Create a flow from an IP 5-tuple (insert-or-fail if it already exists)
let flow = db.create_flow(&tuple)?;

// Look up an existing flow
let flow = db.get_flow(&tuple)?;          // Option<Flow>
let flow = db.get_flow_by_id(id)?;        // Option<Flow>

// Iterate over all flows in the database
for flow in db.list_flows()? { ... }

// Remove a flow and all its time series
db.delete_flow(&flow)?;
```

### Flow Attributes

Key-value metadata stored per flow. Values can be any `DataValue` variant.

```rust
use ts_storage::FlowAttribute;

db.add_flow_attribute(&flow, &FlowAttribute {
    name: "algorithm".into(),
    value: DataValue::String("BBR".into()),
})?;

// Update or create
db.set_flow_attribute(&flow, &FlowAttribute {
    name: "algorithm".into(),
    value: DataValue::String("CUBIC".into()),
})?;

let attr = db.get_flow_attribute(&flow, "algorithm")?;
println!("{}", attr.value.as_string());

for attr in db.list_flow_attributes(&flow)? { ... }

db.delete_flow_attribute(&flow, "algorithm")?;
```

### Time Series

A time series belongs to a flow and holds a sequence of data points all of the same type. The type is set at creation and cannot be changed. Pass any `DataValue` as the `ts_type` argument; only its variant matters, not its value.

```rust
// Create
let rtt = db.create_time_series(&flow, "rtt_us", DataValue::Int(0))?;
let loss = db.create_time_series(&flow, "loss_rate", DataValue::Float(0.0))?;

// List all series for a flow
for ts in db.list_time_series(&flow)? { ... }

// Look up by ID
let ts = db.get_time_series_by_id(id)?;    // Option<TimeSeries>

// Get time range and min/max value without scanning all points
// ymin/ymax are None for Boolean and String series
let bounds = db.get_time_series_bounds(&rtt)?;

// Get the combined time range across all series in a flow
let bounds = db.get_flow_bounds(&flow)?;

// Remove a series and all its data points
db.delete_time_series(&flow, &rtt)?;
```

### Data Points

```rust
// Single insert
db.insert_data_point(&rtt, &DataPoint {
    timestamp: 1.234,
    value: DataValue::Int(4200),
})?;

// Batch insert (preferred for large datasets)
db.insert_multiple_points(&rtt, &points)?;

// Read all points
for dp in db.get_data_points(&rtt)? { ... }

// Read a time window [t_start, t_end]
for dp in db.get_data_points_in_range(&rtt, 1.0, 5.0)? { ... }

// Count without fetching
let n = db.get_data_points_count(&rtt)?;
```

*Note: the value type of each `DataPoint` must match the type the series was created with, otherwise `insert_data_point` returns `TSDBError::DataPointTypeMismatchError`.*

## Error Handling

All errors are variants of `TSDBError` (from `ts_storage::error`):

| Variant | When it occurs |
|---------|----------------|
| `SetupError` | Database tables could not be created on open |
| `NoAttributeError` | `get_flow_attribute` called for a name that does not exist |
| `DataPointTypeMismatchError` | Inserting a point whose type differs from the series type |
| `TimeSeriesNotFoundError` | Series ID does not exist in the database |
| `TimeSeriesNoValue` | `get_time_series_bounds` called on an empty series |
| `SqliteError` / `DuckDBError` | Propagated driver errors |

## Choosing a Backend

Both backends implement the same `TSDBInterface` and produce files that can be opened with any compatible SQLite or DuckDB client.

- **SQLite**: lower memory use, single-writer, good for smaller recordings or when tooling for DuckDB is not available.
- **DuckDB**: columnar storage, faster analytical queries, better throughput for bulk inserts. Recommended for recordings with many flows or long durations.

The database file extension (`.sqlite` / `.duck`) is just a convention; the backend is selected by the `DBBackend` variant, not the filename.
