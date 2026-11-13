#!/usr/bin/env python3
"""Plot one flow's metrics on separate panels with a shared time axis."""

import argparse

import tcbee
from _plotting import (
    COLORS,
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
    parser.add_argument("flow_id", type=int)
    parser.add_argument(
        "--metric",
        action="append",
        metavar="SOURCE.NAME",
        help="repeat for multiple panels (default: sock.snd_cwnd and sock.bytes_acked)",
    )
    parser.add_argument("--dir", choices=("send", "recv", "none"), default="send")
    add_output_options(parser)
    args = parser.parse_args()
    style()
    import matplotlib.pyplot as plt

    specs = args.metric or ["sock.snd_cwnd", "sock.bytes_acked"]
    with tcbee.open(args.database) as db:
        flow = db.flow(args.flow_id)
        if flow.start_ns is None:
            raise ValueError(f"Flow {flow.id} has no recorded samples")
        fig, axes = plt.subplots(
            len(specs),
            1,
            sharex=True,
            squeeze=False,
            figsize=(11, 2.6 * len(specs) + 0.8),
            layout="constrained",
        )
        for index, (spec, row) in enumerate(zip(specs, axes)):
            metric = select_metric(flow, spec, args.dir)
            times, values = arrays_for_plot(metric, args, flow.start_ns)
            ax = row[0]
            ax.step(
                times,
                values,
                where="post",
                color=COLORS[index % len(COLORS)],
                rasterized=True,
            )
            ax.set_title(f"{spec} · {metric.direction}", loc="left")
            ax.set_ylabel("Raw value")
            decorate(ax)
        axes[-1, 0].set_xlabel("Time since flow start (seconds)")
        fig.suptitle(args.title or str(flow), fontsize=13, fontweight="bold")
        finish(fig, args)


if __name__ == "__main__":
    run(main)
