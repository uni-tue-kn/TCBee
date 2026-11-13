#!/usr/bin/env python3
"""List the flows in a TCBee database, optionally with their metrics."""

import argparse

from _plotting import parse_spec, positive, run

import tcbee


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument("--verbose", "-v", action="store_true", help="show each flow's metrics")
    parser.add_argument(
        "--limit", type=positive, default=50, help="maximum displayed flows (default: 50)"
    )
    parser.add_argument("--all", action="store_true", help="iterate all matching flows")
    for flag in ("src", "dst", "host"):
        parser.add_argument("--" + flag)
    for flag in ("sport", "dport", "port", "pid"):
        parser.add_argument("--" + flag, type=int)
    parser.add_argument("--process", help="exact process name")
    parser.add_argument("--metric", metavar="SOURCE.NAME", help="require a recorded metric")
    args = parser.parse_args()
    with tcbee.open(args.database) as db:
        flows = db.flows().filter(
            src=args.src,
            dst=args.dst,
            host=args.host,
            sport=args.sport,
            dport=args.dport,
            port=args.port,
        )
        if args.pid is not None or args.process is not None:
            flows = flows.owned_by(pid=args.pid, comm=args.process)
        if args.metric:
            source, name = parse_spec(args.metric)
            flows = flows.with_series(source=source, name=name)
        print(f"Found {flows.count()} matching flows in {db.path}\n")
        page = None if args.all else flows.page(size=args.limit)
        for flow in flows if args.all else page.items:
            print(f"{flow} | {flow.series_count} series | {flow.sample_count} sample values")
            if args.verbose:
                flow.series().show(limit=100)
        if page is not None and page.next_cursor is not None:
            print("More flows available; narrow the filters or use --all")


if __name__ == "__main__":
    run(main)
