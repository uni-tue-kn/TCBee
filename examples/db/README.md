# TCBee Database Access Examples

This directory contains examples for accessing TCP flow data from TCBee's SQLite database.

## Database Schema

The TCBee database follows a relational structure with four main tables:

### 1. `flows` - Flow Identification
```sql
CREATE TABLE flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src TEXT NOT NULL,              -- Source IP address
    dst TEXT NOT NULL,              -- Destination IP address
    sport INTEGER NOT NULL,         -- Source port (network byte order)
    dport INTEGER NOT NULL,         -- Destination port (network byte order)
    l4proto INTEGER NOT NULL,       -- Layer 4 protocol
    UNIQUE (src, dst, sport, dport, l4proto)
);
```

### 2. `flow_attributes` - Flow-Level Metadata
```sql
CREATE TABLE flow_attributes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER,                -- References flows(id)
    name TEXT NOT NULL,             -- Attribute name (e.g., "congestion_algorithm")
    value_boolean INTEGER DEFAULT -1,
    value_text TEXT,
    value_integer INTEGER DEFAULT -1,
    value_float REAL DEFAULT -1,
    UNIQUE (flow_id, name),
    FOREIGN KEY (flow_id) REFERENCES flows(id)
);
```

Stores flow-level attributes like congestion control algorithm, initial RTT, etc.

### 3. `time_series` - Time Series Metadata
```sql
CREATE TABLE time_series (
    time_series_id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,       -- References flows(id)
    name TEXT NOT NULL,             -- Series name (e.g., "tcp_cwnd", "tcp_srtt")
    type INTEGER NOT NULL,          -- Data type identifier
    UNIQUE (flow_id, name),
    FOREIGN KEY (flow_id) REFERENCES flows(id)
);
```

Links time series to flows and defines what metric is being tracked.
Types:
- 0 -> Integer
- 1 -> Float
- 2 -> Boolean
- 3 -> Text

### 4. `time_series_data` - Actual Time Series Data Points
```sql
CREATE TABLE time_series_data (
    time_series_id INTEGER NOT NULL,    -- References time_series(time_series_id)
    timestamp FLOAT NOT NULL,           -- Timestamp (seconds since epoch)
    value_boolean INTEGER DEFAULT -1,
    value_text TEXT,
    value_integer INTEGER DEFAULT -1,
    value_float REAL DEFAULT -1,
    PRIMARY KEY (time_series_id, timestamp),
    FOREIGN KEY (time_series_id) REFERENCES time_series(time_series_id) ON DELETE CASCADE
);
```

Stores the actual data points. Each row contains one timestamp-value pair. 
---

## Available Example Scripts

### 1. List Flows: `list_flows.py`

Lists all TCP flows in the database with statistics.

**Usage:**
```bash
./list_flows.py <database.sqlite>           # Basic list
./list_flows.py <database.sqlite> --verbose # Show time series info
```

**Example output:**
```
Found 3 flows:

ID    Flow                                                      Points
================================================================================
1     192.168.1.10:45678 -> 93.184.216.34:80 (TCP)             15234
2     192.168.1.10:45679 -> 93.184.216.34:80 (TCP)             8921
3     192.168.1.10:45680 -> 93.184.216.34:443 (TCP)            12456
```

### 2. Plot Time Series: `plot_cwnd.py`

Plots time series data for a specific flow.

**Usage:**
```bash
./plot_cwnd.py <database.sqlite>                                    # List flows
./plot_cwnd.py <database.sqlite> <flow-id>                         # Plot tcp_cwnd
./plot_cwnd.py <database.sqlite> <flow-id> --series tcp_cwnd,tcp_ssthresh
./plot_cwnd.py <database.sqlite> <flow-id> --output plot.png
```

**Examples:**
```bash
# List available flows
./plot_cwnd.py db.sqlite

# Plot congestion window for flow 1
./plot_cwnd.py db.sqlite 1

# Plot multiple metrics
./plot_cwnd.py db.sqlite 1 --series tcp_cwnd,tcp_ssthresh,tcp_srtt_us

# Save to file
./plot_cwnd.py db.sqlite 1 --output cwnd_plot.png
```

---

## Reading Time Series Data: Code Examples

### Example 1: Get All Flows

```python
import sqlite3

def get_all_flows(db_path):
    """Retrieve all TCP flows from database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, src, dst, sport, dport, l4proto FROM flows")
    flows = cursor.fetchall()

    conn.close()
    return flows

# Usage
flows = get_all_flows("db.sqlite")
for flow_id, src, dst, sport, dport, proto in flows:
    print(f"Flow {flow_id}: {src}:{sport} -> {dst}:{dport}")
```

### Example 2: Read a Single Time Series

```python
import sqlite3

def get_time_series(db_path, flow_id, series_name="tcp_cwnd"):
    """
    Read time series data for a specific flow.

    Args:
        db_path: Path to SQLite database
        flow_id: Flow ID from flows table
        series_name: Name of the time series (e.g., "tcp_cwnd", "tcp_srtt_us")

    Returns:
        List of (timestamp, value) tuples
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Join time_series and time_series_data tables
    query = """
        SELECT tsd.timestamp, tsd.value_integer, tsd.value_float
        FROM time_series_data tsd
        JOIN time_series ts ON ts.time_series_id = tsd.time_series_id
        WHERE ts.flow_id = ? AND ts.name = ?
        ORDER BY tsd.timestamp
    """

    cursor.execute(query, (flow_id, series_name))

    # Extract data, choosing integer or float value as appropriate
    data = []
    for row in cursor.fetchall():
        timestamp = row[0]
        value = row[1] if row[1] != -1 else row[2]
        data.append((timestamp, value))

    conn.close()
    return data

# Usage
cwnd_data = get_time_series("db.sqlite", flow_id=1, series_name="tcp_cwnd")

print(f"Retrieved {len(cwnd_data)} data points")
for timestamp, cwnd in cwnd_data[:5]:  # First 5 points
    print(f"  t={timestamp:.6f}s, cwnd={cwnd}")
```

### Example 3: Get Available Time Series for a Flow

```python
import sqlite3

def get_available_series(db_path, flow_id):
    """Get list of available time series for a flow."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ts.name, COUNT(tsd.timestamp) as point_count
        FROM time_series ts
        LEFT JOIN time_series_data tsd ON tsd.time_series_id = ts.time_series_id
        WHERE ts.flow_id = ?
        GROUP BY ts.name
        ORDER BY ts.name
    """, (flow_id,))

    series = cursor.fetchall()
    conn.close()
    return series

# Usage
series_list = get_available_series("db.sqlite", flow_id=1)
print("Available time series:")
for name, count in series_list:
    print(f"  {name}: {count} data points")
```

### Example 4: Read Multiple Time Series Together

```python
import sqlite3

def get_multiple_series(db_path, flow_id, series_names):
    """
    Read multiple time series for a flow.

    Returns:
        Dictionary mapping series names to list of (timestamp, value) tuples
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    result = {}
    for series_name in series_names:
        cursor.execute("""
            SELECT tsd.timestamp, tsd.value_integer, tsd.value_float
            FROM time_series_data tsd
            JOIN time_series ts ON ts.time_series_id = tsd.time_series_id
            WHERE ts.flow_id = ? AND ts.name = ?
            ORDER BY tsd.timestamp
        """, (flow_id, series_name))

        data = []
        for row in cursor.fetchall():
            timestamp = row[0]
            value = row[1] if row[1] != -1 else row[2]
            data.append((timestamp, value))

        result[series_name] = data

    conn.close()
    return result

# Usage
metrics = get_multiple_series("db.sqlite", flow_id=1,
                              series_names=["tcp_cwnd", "tcp_ssthresh", "tcp_srtt_us"])

for metric_name, data in metrics.items():
    print(f"{metric_name}: {len(data)} points")
```