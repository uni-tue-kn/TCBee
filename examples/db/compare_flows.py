#!/usr/bin/env python3
"""Compare a metric across selected flows, aligned in recording time or by flow start."""

import argparse

import tcbee
from _plotting import (
    add_output_options,
    arrays_for_plot,
    decorate,
    finish,
    run,
    select_metric,
    style,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument(
        "flow_ids",
        nargs="*",
        type=int,
        help="omit to choose matching flows by sample count",
    )
    parser.add_argument("--metric", default="sock.snd_cwnd", metavar="SOURCE.NAME")
    parser.add_argument("--dir", choices=("send", "recv", "none"), default="send")
    parser.add_argument("--host", help="automatic selection: either endpoint")
    parser.add_argument("--port", type=int, help="automatic selection: either port")
    parser.add_argument(
        "--limit",
        type=int,
        default=4,
        help="automatic selection: maximum flows (default: 4)",
    )
    parser.add_argument(
        "--align",
        choices=("recording", "flow"),
        default="recording",
        help="shared recording time or each flow's start (default: recording)",
    )
    parser.add_argument("--ylabel", default="Raw value")
    add_output_options(parser)
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")
    if args.flow_ids and (args.host is not None or args.port is not None):
        parser.error(
            "--host and --port apply to automatic selection; omit explicit flow IDs"
        )
    source, separator, name = args.metric.partition(".")
    if not separator or not source or not name:
        parser.error("--metric must be SOURCE.NAME")
    direction = (
        "none" if source in ("tcp_probe", "cubic", "bbr", "derived") else args.dir
    )
    style()
    import matplotlib.pyplot as plt

    with tcbee.open(args.database) as db:
        if args.flow_ids:
            flows = tuple(db.flow(fid) for fid in dict.fromkeys(args.flow_ids))
        else:
            flows = (
                db.flows()
                .filter(host=args.host, port=args.port)
                .with_series(source=source, name=name, direction=direction)
                .top(size=args.limit)
            )
        if not flows or any(flow.start_ns is None for flow in flows):
            raise ValueError(
                "No flows with recorded samples match; use list_flows.py to inspect the database"
            )
        shared_origin = min(flow.start_ns for flow in flows)
        fig, ax = plt.subplots(figsize=(11, 5.2), layout="constrained")
        for index, flow in enumerate(flows):
            metric = select_metric(flow, args.metric, args.dir)
            origin = flow.start_ns if args.align == "flow" else shared_origin
            times, values = arrays_for_plot(metric, args, origin)
            ax.step(
                times,
                values,
                where="post",
                linestyle=("-", "--", "-.", ":")[index % 4],
                label=str(flow),
                rasterized=True,
            )
        ax.set_title(
            args.title or f"{args.metric} · {direction}", loc="left", fontsize=14
        )
        ax.set_xlabel(
            "Time since each flow started (seconds)"
            if args.align == "flow"
            else "Time since earliest selected flow (seconds)"
        )
        ax.set_ylabel(args.ylabel)
        decorate(ax)
        ax.legend(loc="upper left", bbox_to_anchor=(0, -0.18), fontsize=8)
        finish(fig, args)


if __name__ == "__main__":
    run(main)
