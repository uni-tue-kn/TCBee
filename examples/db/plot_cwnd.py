#!/usr/bin/env python3
"""Plot flow metrics using tcbee; install ./tcbee-python[duckdb,numpy] and matplotlib."""

import argparse
import sys

import tcbee


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument("flow_id", nargs="?", type=int)
    parser.add_argument("--series", default="sock.snd_cwnd,tcp_probe.SND_CWND")
    parser.add_argument("--dir", choices=("send", "recv", "none"), default="send")
    parser.add_argument(
        "--start", type=float, help="inclusive seconds from the flow's first sample"
    )
    parser.add_argument(
        "--end", type=float, help="exclusive seconds from the flow's first sample"
    )
    parser.add_argument("--output")
    args = parser.parse_args()
    with tcbee.open(args.database) as db:
        if args.flow_id is None:
            db.flows().show(limit=50)
            print(f"\nUsage: {sys.argv[0]} {args.database} <flow-id>")
            return
        flow = db.flow(args.flow_id)
        if flow.start_ns is None:
            sys.exit(f"Error: flow {flow.id} has no samples")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(12, 6))
        plotted = False
        for spec in args.series.split(","):
            source, separator, name = spec.partition(".")
            if not separator or not source or not name:
                parser.error("--series entries must be SOURCE.NAME")
            # These event sources (and derived metrics) are explicitly directionless.
            direction = (
                "none"
                if source in ("tcp_probe", "cubic", "bbr", "derived")
                else args.dir
            )
            try:
                series = flow.series().one(
                    source=source, name=name, direction=direction
                )
            except tcbee.NotFound as error:
                print(f"Warning: {spec}: {error}", file=sys.stderr)
                continue
            data = series.read_numpy(
                start_ns=None
                if args.start is None
                else flow.start_ns + round(args.start * 1e9),
                end_ns=None
                if args.end is None
                else flow.start_ns + round(args.end * 1e9),
            )
            if len(data["value"]):
                # Subtract the shared integer origin before converting to float seconds.
                ax.step(
                    (data["ts_ns"] - flow.start_ns) / 1e9,
                    data["value"],
                    where="post",
                    label=spec,
                )
                plotted = True
        if not plotted:
            sys.exit("Error: no matching samples to plot")
        ax.set(
            xlabel="Time since flow start (seconds)", ylabel="Value", title=str(flow)
        )
        ax.grid(True, alpha=0.3)
        ax.legend(loc="best")
        fig.tight_layout()
        if args.output:
            fig.savefig(args.output, dpi=150)
            print(f"Plot saved to {args.output}")
        else:
            plt.show()


if __name__ == "__main__":
    try:
        main()
    except (tcbee.TCBeeError, OSError, ValueError, ImportError) as error:
        sys.exit(f"Error: {error}")
