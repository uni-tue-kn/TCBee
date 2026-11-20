#!/usr/bin/env python3
"""Compare one metric across flows, for example how two flows share a bottleneck."""

import argparse

import numpy as np

import tcbee
from _plotting import (
    GOODPUT,
    GOODPUT_SOURCE,
    add_output_options,
    decorate,
    finish,
    label,
    parse_spec,
    positive,
    read_metric,
    run,
    select_metric,
    style,
)


def bulk_flows(db, args):
    """Pick the flows that sent the most data, skipping their ACK directions.

    Only the 4 * limit flows with the most samples are considered.
    """
    source, name = GOODPUT_SOURCE
    candidates = (
        db.flows()
        .filter(host=args.host, port=args.port)
        .with_series(source=source, name=name)
        .top(size=4 * args.limit)
    )
    sent = {}
    for flow in candidates:
        snd_una = select_metric(flow, GOODPUT).read_numpy()["value"].astype("int64")
        sent[flow] = int((np.diff(snd_una) % 2**32).sum())
    flows = sorted((f for f in sent if sent[f] > 0), key=sent.get, reverse=True)
    return flows[: args.limit]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument(
        "flow_ids",
        nargs="*",
        type=int,
        help="flows to plot (default: the flows that sent the most data)",
    )
    parser.add_argument(
        "--metric",
        default=GOODPUT,
        metavar="SOURCE.NAME",
        help="metric to compare; 'goodput' is computed (default)",
    )
    parser.add_argument("--host", help="automatic selection: either endpoint")
    parser.add_argument("--port", type=int, help="automatic selection: either port")
    parser.add_argument(
        "--limit", type=positive, default=2, help="automatic selection: flows (default: 2)"
    )
    parser.add_argument(
        "--align",
        choices=("recording", "flow"),
        default="recording",
        help="start the time axis at the first flow or at each flow's start",
    )
    add_output_options(parser)
    args = parser.parse_args()
    if args.flow_ids and (args.host or args.port):
        parser.error("--host and --port select flows automatically; omit flow IDs")
    if args.metric != GOODPUT:
        parse_spec(args.metric)
    style()
    import matplotlib.pyplot as plt

    with tcbee.open(args.database) as db:
        if args.flow_ids:
            flows = [db.flow(fid) for fid in dict.fromkeys(args.flow_ids)]
        else:
            flows = bulk_flows(db, args)
        if not flows or any(flow.start_ns is None for flow in flows):
            raise ValueError("No flows with samples match; see list_flows.py")
        first_ns = min(flow.start_ns for flow in flows)
        lines = []
        for flow in sorted(flows, key=lambda flow: flow.start_ns):
            origin = flow.start_ns if args.align == "flow" else first_ns
            lines.append((flow, *read_metric(flow, args.metric, args, origin)))
        fig, ax = plt.subplots(figsize=(7, 3), layout="constrained")
        for flow, times, values in lines:
            ax.step(times, values, where="post", label=f"Flow {flow.id} (port {flow.dport})")
        ax.set_xlabel("Time since flow start (s)" if args.align == "flow" else "Time (s)")
        ax.set_ylabel(label(args.metric))
        if args.title:
            ax.set_title(args.title, loc="left")
        decorate(ax)
        ax.legend(loc="lower right", bbox_to_anchor=(1, 1), ncols=len(lines))
        finish(fig, args)


if __name__ == "__main__":
    run(main)
