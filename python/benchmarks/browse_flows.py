#!/usr/bin/env python3
"""Time catalog browsing independently of metric sample count.

    python tcbee-python/benchmarks/browse_flows.py --flows 20000 --metrics 20

Temporary files contain only metadata: millions of sample values per metric
are represented by catalog counts, without creating or reading event tables.
"""

import argparse
import sqlite3
import statistics
import tempfile
import time
from pathlib import Path

import tcbee


def create(path, engine, flow_count, metrics):
    if engine == "duckdb":
        import duckdb

        db = duckdb.connect(str(path))
    else:
        db = sqlite3.connect(path)
    db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    db.execute("INSERT INTO meta VALUES ('schema_version', '3')")
    db.execute(
        "CREATE TABLE flows (id BIGINT PRIMARY KEY, src TEXT, dst TEXT, sport INTEGER, dport INTEGER, l4proto INTEGER)"
    )
    db.execute("""CREATE TABLE series (id BIGINT PRIMARY KEY, flow_id BIGINT, kind INTEGER,
        source TEXT, dir INTEGER, name TEXT, value_type INTEGER, tbl TEXT, col TEXT,
        n BIGINT, t_min BIGINT, t_max BIGINT, v_min DOUBLE, v_max DOUBLE,
        UNIQUE(flow_id, source, dir, name))""")
    if engine == "duckdb":
        db.execute(
            "INSERT INTO flows SELECT i, '10.0.0.1', '10.0.0.2', CAST(i % 65536 AS INTEGER), 5201, 6 FROM range(1, ?) t(i)",
            (flow_count + 1,),
        )
        db.execute(
            """INSERT INTO series SELECT (f.i - 1) * ? + m.i, f.i, 0, 'sock', 1,
            'metric_' || CAST(m.i AS VARCHAR), 3, 'ev_sock', 'snd_cwnd',
            1000000, 100, 1000000000, 0, 1000
            FROM range(1, ?) f(i) CROSS JOIN range(?) m(i)""",
            (metrics, flow_count + 1, metrics),
        )
    else:
        db.executemany(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)",
            ((i, "10.0.0.1", "10.0.0.2", i % 65536, 5201, 6) for i in range(1, flow_count + 1)),
        )
        db.executemany(
            "INSERT INTO series VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                (
                    (fid - 1) * metrics + metric,
                    fid,
                    0,
                    "sock",
                    1,
                    f"metric_{metric}",
                    3,
                    "ev_sock",
                    "snd_cwnd",
                    1_000_000,
                    100,
                    1_000_000_000,
                    0,
                    1000,
                )
                for fid in range(1, flow_count + 1)
                for metric in range(metrics)
            ),
        )
    db.commit()
    db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", type=int, default=20_000)
    parser.add_argument("--metrics", type=int, default=20)
    parser.add_argument(
        "--engines", nargs="+", choices=("sqlite", "duckdb"), default=["sqlite", "duckdb"]
    )
    args = parser.parse_args()
    if args.flows < 1 or args.metrics < 1:
        parser.error("flow and metric counts must be positive")
    with tempfile.TemporaryDirectory(prefix="tcbee-browse-") as directory:
        for engine in args.engines:
            path = Path(directory) / engine
            create(path, engine, args.flows, args.metrics)
            with tcbee.open(path) as db:
                query = db.flows()
                durations = []
                for _ in range(5):
                    start = time.perf_counter()
                    page = query.page(size=50)
                    durations.append(time.perf_counter() - start)
                    assert len(page.items) == min(50, args.flows)
                    assert page.items[0].sample_count == args.metrics * 1_000_000
                start = time.perf_counter()
                assert sum(1 for _ in query) == args.flows
                elapsed = time.perf_counter() - start
                print(
                    f"{engine}: flows={args.flows}, catalog_rows={args.flows * args.metrics}, "
                    f"page50_median_ms={statistics.median(durations) * 1000:.2f}, "
                    f"all_flows_seconds={elapsed:.3f}"
                )


if __name__ == "__main__":
    main()
