#!/usr/bin/env python3
"""Plot one flow's metrics on stacked panels with a shared time axis."""

import argparse

from _plotting import COLORS, add_output_options, decorate, finish, label, read_metric, run, style

import tcbee

DEFAULT = ["tcp_probe.SND_CWND", "tcp_probe.SRTT", "goodput"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument("flow_id", type=int)
    parser.add_argument(
        "--metric",
        action="append",
        metavar="SOURCE.NAME",
        help="one panel each; 'goodput' is computed (default: cwnd, RTT, goodput)",
    )
    add_output_options(parser)
    args = parser.parse_args()
    style()
    import matplotlib.pyplot as plt

    specs = args.metric or DEFAULT
    with tcbee.open(args.database) as db:
        flow = db.flow(args.flow_id)
        if flow.start_ns is None:
            raise ValueError(f"Flow {flow.id} has no samples")
        fig, axes = plt.subplots(
            len(specs),
            1,
            sharex=True,
            squeeze=False,
            figsize=(7, 1.9 * len(specs) + 0.4),
            layout="constrained",
        )
        for index, (spec, (ax,)) in enumerate(zip(specs, axes)):
            times, values = read_metric(flow, spec, args, flow.start_ns)
            ax.step(times, values, where="post", color=COLORS[index % len(COLORS)])
            ax.set_ylabel(label(spec))
            decorate(ax)
        axes[-1, 0].set_xlabel("Time (s)")
        fig.align_ylabels(axes[:, 0])
        fig.suptitle(args.title or str(flow))
        finish(fig, args)


if __name__ == "__main__":
    run(main)
