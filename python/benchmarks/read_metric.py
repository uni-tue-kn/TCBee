#!/usr/bin/env python3
"""Measure a single large metric in isolated processes (no timing assertions).

Run after installing tcbee, duckdb and numpy:
    python tcbee-python/benchmarks/read_metric.py --samples 1000000

Files are temporary. Results are warm-cache medians of three reads, including
SQL execution and result conversion, excluding imports and metadata discovery.
Peak RSS includes the Python process, drivers, database buffers and results.
"""

import argparse
import gc
import json
import resource
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import tcbee


def create(path, engine, count):
    if engine == "duckdb":
        import duckdb

        db = duckdb.connect(str(path))
    else:
        db = sqlite3.connect(path)
    db.execute("CREATE TABLE meta (key TEXT, value TEXT)")
    db.execute("INSERT INTO meta VALUES ('schema_version', '3')")
    db.execute(
        "CREATE TABLE flows (id BIGINT, src TEXT, dst TEXT, sport INTEGER, dport INTEGER, l4proto INTEGER)"
    )
    db.execute("INSERT INTO flows VALUES (1, '10.0.0.1', '10.0.0.2', 40000, 5201, 6)")
    db.execute("""CREATE TABLE series (id BIGINT, flow_id BIGINT, kind INTEGER, source TEXT,
        dir INTEGER, name TEXT, value_type INTEGER, tbl TEXT, col TEXT, n BIGINT,
        t_min BIGINT, t_max BIGINT, v_min DOUBLE, v_max DOUBLE)""")
    base = 10_000_000_000_000_001
    db.execute(
        "INSERT INTO series VALUES (1, 1, 0, 'sock', 1, 'snd_cwnd', 3, 'ev_sock', 'snd_cwnd', ?, ?, ?, 0, ?)",
        (count, base, base + (count - 1) * 1000, count - 1),
    )
    db.execute(
        "CREATE TABLE ev_sock (flow_id BIGINT, dir INTEGER, ts BIGINT, seq BIGINT, snd_cwnd INTEGER)"
    )
    if engine == "duckdb":
        db.execute(
            "INSERT INTO ev_sock SELECT 1, 1, ? + i * 1000, i, CAST(i AS INTEGER) FROM range(?) t(i)",
            (base, count),
        )
    else:
        for start in range(0, count, 65536):
            db.executemany(
                "INSERT INTO ev_sock VALUES (?, ?, ?, ?, ?)",
                ((1, 1, base + i * 1000, i, i) for i in range(start, min(start + 65536, count))),
            )
        db.execute("CREATE INDEX ev_sock_idx ON ev_sock(flow_id, dir, ts, seq)")
    db.commit()
    db.close()


def worker(path, mode, count):
    if mode == "numpy":
        import numpy  # noqa: F401 -- exclude optional dependency import from the timed read
    with tcbee.open(path) as db:
        series = db.series(1)
        times = []
        for _ in range(3):
            gc.collect()
            started = time.perf_counter()
            if mode == "stream":
                size, checksum = 0, 0
                for batch in series.iter_batches():
                    size += len(batch)
                    checksum += sum(batch.values)
            elif mode == "numpy":
                result = series.read_numpy()
                size, checksum = len(result["value"]), int(result["value"].sum())
                del result
            elif mode == "rows":
                sql, params = series._sample_query(None, None)
                result = db._rows(sql, params)
                size, checksum = len(result), sum(row[2] for row in result)
                del result
            else:
                result = series.read()
                size, checksum = len(result), sum(result.values)
                del result
            times.append(time.perf_counter() - started)
            assert size == count and checksum == count * (count - 1) // 2
        print(
            json.dumps(
                {
                    "engine": db.engine,
                    "mode": mode,
                    "seconds": round(statistics.median(times), 3),
                    "peak_rss_mib": round(
                        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1
                    ),
                }
            )
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=1_000_000)
    parser.add_argument(
        "--engines", nargs="+", choices=("sqlite", "duckdb"), default=["sqlite", "duckdb"]
    )
    parser.add_argument("--worker", nargs=2, metavar=("PATH", "MODE"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")
    if args.worker:
        worker(*args.worker, args.samples)
        return
    with tempfile.TemporaryDirectory(prefix="tcbee-bench-") as directory:
        for engine in args.engines:
            path = Path(directory) / engine
            create(path, engine, args.samples)
            for mode in ("rows", "read", "stream", "numpy"):
                subprocess.run(
                    [
                        sys.executable,
                        __file__,
                        "--samples",
                        str(args.samples),
                        "--worker",
                        str(path),
                        mode,
                    ],
                    check=True,
                )


if __name__ == "__main__":
    main()
