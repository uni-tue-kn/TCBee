#!/usr/bin/env python3
"""
Lists the TCP flows of a database written by tcbee-process (schema version 2).

Works on SQLite files with the standard library. DuckDB files need `pip install duckdb`.

Usage:
    ./list_flows.py <database> [--verbose]
"""

import sqlite3
import sys
from pathlib import Path


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


def list_flows(db):
    """Returns (id, src, dst, sport, dport, l4proto, series count, number of values) per flow."""
    return db.execute(
        """
        SELECT f.id, f.src, f.dst, f.sport, f.dport, f.l4proto,
               COUNT(s.id), COALESCE(SUM(s.n), 0)
        FROM flows f LEFT JOIN series s ON s.flow_id = f.id
        GROUP BY f.id, f.src, f.dst, f.sport, f.dport, f.l4proto
        ORDER BY 8 DESC, f.id
        """
    ).fetchall()


def list_series(db, flow_id: int):
    """Returns (source, dir, name, kind, n) of the series of one flow."""
    return db.execute(
        """
        SELECT source, dir, name, kind, n FROM series
        WHERE flow_id = ? ORDER BY source, dir, name
        """,
        (flow_id,),
    ).fetchall()


DIRS = {0: "", 1: "send", 2: "recv"}
PROTOS = {6: "TCP", 17: "UDP"}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    if len(args) != 1:
        print(f"Usage: {sys.argv[0]} <database> [--verbose]")
        sys.exit(1)
    path = Path(args[0])
    if not path.exists():
        sys.exit(f"Error: database not found: {path}")

    db = connect(path)
    check_schema(db, path)
    flows = list_flows(db)

    print(f"Found {len(flows)} flows in {path}\n")
    print(f"{'ID':<6} {'Flow':<56} {'Series':<8} {'Values':<10}")
    print("=" * 82)
    for fid, src, dst, sport, dport, proto, nseries, nvalues in flows:
        name = PROTOS.get(proto, f"proto {proto}")
        flow = f"{src}:{sport} -> {dst}:{dport} ({name})"
        print(f"{fid:<6} {flow:<56} {nseries:<8} {nvalues:<10}")
        if verbose:
            for source, direction, sname, kind, n in list_series(db, fid):
                where = f"{source} {DIRS.get(direction, '')}".strip()
                label = "derived" if kind == 1 else where
                print(f"         {sname:<24} {label:<18} {n} values")

    if not verbose:
        print("\nUse --verbose to list the series of each flow")


if __name__ == "__main__":
    main()
