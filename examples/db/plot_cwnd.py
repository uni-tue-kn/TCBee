#!/usr/bin/env python3
"""
Plots the congestion window of a flow from a database written by tcbee-process (schema version 2).

The values come straight from the event tables: `ev_sock.snd_cwnd` (send side) and
`ev_tcp_probe.SND_CWND`. Any other column of an event table can be plotted with
--series <source>.<column>, for example sock.snd_ssthresh or tcp_probe.SRTT.

Works on SQLite files with the standard library. DuckDB files need `pip install duckdb`.
Plotting needs matplotlib.

Usage:
    ./plot_cwnd.py <database> [flow-id] [--series sock.snd_cwnd,tcp_probe.SND_CWND]
                   [--dir send|recv] [--output plot.png]
"""

import sqlite3
import sys
from pathlib import Path

DEFAULT_SERIES = ["sock.snd_cwnd", "tcp_probe.SND_CWND"]
DIRS = {"none": 0, "send": 1, "recv": 2}


def connect(path: Path):
    """Opens a SQLite or DuckDB file, whichever it is (read from the file header)."""
    with open(path, "rb") as f:
        header = f.read(16)
    if header.startswith(b"SQLite format 3\0"):
        return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    if header[8:12] == b"DUCK":
        try:
            import duckdb
        except ImportError:
            sys.exit("Error: reading DuckDB files needs the duckdb package (pip install duckdb)")
        return duckdb.connect(str(path), read_only=True)
    sys.exit(f"Error: {path} is neither a SQLite nor a DuckDB file")


def check_schema(db, path: Path):
    try:
        version = db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    except Exception:
        version = None
    if version is None or version[0] != "2":
        sys.exit(
            f"Error: {path} is not a schema version 2 database; "
            "reprocess the recording with tcbee-process"
        )


def get_flows(db):
    return db.execute(
        """
        SELECT f.id, f.src, f.dst, f.sport, f.dport, COUNT(s.id)
        FROM flows f LEFT JOIN series s ON s.flow_id = f.id
        GROUP BY f.id, f.src, f.dst, f.sport, f.dport
        ORDER BY f.id
        """
    ).fetchall()


def find_series(db, flow_id: int, spec: str, direction: str):
    """
    Looks up `<source>.<column>` in the series catalog of the flow and returns
    (event table, column, dir code). The identifiers come from the catalog, never from the
    command line, so they are safe to put into the query.
    """
    source, _, column = spec.partition(".")
    rows = db.execute(
        """
        SELECT dir, tbl, col FROM series
        WHERE flow_id = ? AND kind = 0 AND source = ? AND name = ?
        """,
        (flow_id, source, column),
    ).fetchall()
    if not rows:
        return None
    # Sources without a direction (tcp_probe, cubic, bbr) have one row with dir 0. For sock, cwnd,
    # tcp4 and tcp6 there is one per direction.
    wanted = DIRS[direction]
    for d, tbl, col in rows:
        if d == wanted or d == 0:
            return tbl, col, d
    return None


def read_series(db, flow_id: int, tbl: str, col: str, d: int):
    """Returns (ts, value) rows in time order; ts is in nanoseconds since boot."""
    return db.execute(
        f'SELECT ts, "{col}" FROM "{tbl}" WHERE flow_id = ? AND dir = ? ORDER BY ts, seq',
        (flow_id, d),
    ).fetchall()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        sys.exit(f"Error: database not found: {path}")

    flow_id = None
    series = DEFAULT_SERIES
    direction = "send"
    output = None
    argv = sys.argv[2:]
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.isdigit():
            flow_id = int(arg)
        elif arg in ("--series", "--dir", "--output") and i + 1 < len(argv):
            i += 1
            if arg == "--series":
                series = argv[i].split(",")
            elif arg == "--dir":
                direction = argv[i]
            else:
                output = Path(argv[i])
        else:
            sys.exit(f"Error: unknown argument {arg}")
        i += 1
    if direction not in ("send", "recv"):
        sys.exit("Error: --dir is send or recv")

    db = connect(path)
    check_schema(db, path)
    flows = get_flows(db)

    if flow_id is None:
        print(f"Found {len(flows)} flows in {path}\n")
        print(f"{'ID':<6} {'Flow':<56} {'Series':<8}")
        print("=" * 72)
        for fid, src, dst, sport, dport, n in flows:
            print(f"{fid:<6} {f'{src}:{sport} -> {dst}:{dport}':<56} {n:<8}")
        print(f"\nUsage: {sys.argv[0]} {path} <flow-id>")
        return

    flow = next((f for f in flows if f[0] == flow_id), None)
    if flow is None:
        sys.exit(f"Error: flow {flow_id} not found")

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        sys.exit("Error: matplotlib is required for plotting (pip install matplotlib)")

    data = {}
    for spec in series:
        found = find_series(db, flow_id, spec, direction)
        if found is None:
            print(f"Warning: flow {flow_id} has no series {spec} ({direction})", file=sys.stderr)
            continue
        rows = read_series(db, flow_id, *found)
        if rows:
            data[spec] = rows
            print(f"Loaded {len(rows)} values for {spec}")
    if not data:
        sys.exit("Error: nothing to plot")

    # One time axis for all series: seconds since the earliest sample.
    t0 = min(rows[0][0] for rows in data.values())
    fig, ax = plt.subplots(figsize=(12, 6))
    for spec, rows in data.items():
        ax.step([(t - t0) / 1e9 for t, _ in rows], [v for _, v in rows], where="post", label=spec)

    _, src, dst, sport, dport, _ = flow
    ax.set_xlabel("Time (seconds)")
    ax.set_ylabel("Value")
    ax.set_title(f"Flow {flow_id}: {src}:{sport} -> {dst}:{dport}")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")
    fig.tight_layout()

    if output:
        fig.savefig(output, dpi=150)
        print(f"Plot saved to {output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
