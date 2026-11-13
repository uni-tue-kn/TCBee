#!/usr/bin/env python3
"""Stream a large metric into a fixed-size time-bin min/max envelope, preserving spikes."""

import argparse

import numpy as np
import tcbee
from _plotting import (
    COLORS,
    add_output_options,
    decorate,
    finish,
    positive,
    run,
    select_metric,
    style,
    time_window,
)


def envelope(series, *, start_ns, end_ns, bins=2000, batch_size=65_536):
    """Keep min/max per time bin in O(bins + batch_size) Python result memory.

    Plotting converts values to float. No interpolation or averaging is applied;
    empty bins stay NaN. Integer arithmetic assigns exact timestamps to bins.
    """
    if end_ns <= start_ns or bins < 1 or batch_size < 1:
        raise ValueError(
            "Need a nonempty time interval, positive bins and positive batch size"
        )
    width_ns = (end_ns - start_ns + bins - 1) // bins
    bin_count = (end_ns - start_ns + width_ns - 1) // width_ns
    low, high = np.full(bin_count, np.inf), np.full(bin_count, -np.inf)
    seen = 0
    for batch in series.iter_batches(
        batch_size=batch_size, start_ns=start_ns, end_ns=end_ns
    ):
        timestamps = np.asarray(batch.ts_ns, dtype=np.int64)
        values = np.asarray(batch.values, dtype=float)
        finite = np.isfinite(values)
        indices = (timestamps[finite] - start_ns) // width_ns
        np.minimum.at(low, indices, values[finite])
        np.maximum.at(high, indices, values[finite])
        seen += int(np.count_nonzero(finite))
    empty = ~np.isfinite(low)
    low[empty], high[empty] = np.nan, np.nan
    edges_ns = [min(start_ns + i * width_ns, end_ns) for i in range(bin_count + 1)]
    return edges_ns, low, high, seen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument("flow_id", type=int)
    parser.add_argument("--metric", default="sock.snd_cwnd", metavar="SOURCE.NAME")
    parser.add_argument("--dir", choices=("send", "recv", "none"), default="send")
    parser.add_argument(
        "--bins", type=positive, default=2000, help="maximum time bins (default: 2000)"
    )
    parser.add_argument("--batch-size", type=positive, default=65_536)
    parser.add_argument("--ylabel", default="Raw value")
    add_output_options(parser)
    args = parser.parse_args()
    style()
    import matplotlib.pyplot as plt

    with tcbee.open(args.database) as db:
        flow = db.flow(args.flow_id)
        series = select_metric(flow, args.metric, args.dir)
        if flow.start_ns is None or series.start_ns is None or series.end_ns is None:
            raise ValueError("The selected metric has no recorded samples")
        requested_start, requested_end = time_window(args, flow.start_ns)
        start = max(
            series.start_ns,
            requested_start if requested_start is not None else series.start_ns,
        )
        # Include the final catalog timestamp while retaining half-open read windows.
        end = min(
            series.end_ns + 1,
            requested_end if requested_end is not None else series.end_ns + 1,
        )
        edges_ns, low, high, seen = envelope(
            series,
            start_ns=start,
            end_ns=end,
            bins=args.bins,
            batch_size=args.batch_size,
        )
        if not seen:
            raise ValueError("No finite samples in the selected time window")
        edges = np.asarray(
            [(timestamp - flow.start_ns) / 1e9 for timestamp in edges_ns]
        )
        fig, ax = plt.subplots(figsize=(11, 5), layout="constrained")
        ax.stairs(
            high,
            edges,
            baseline=low,
            fill=True,
            alpha=0.25,
            color=COLORS[0],
            label=f"Min–max envelope · {len(low):,} time bins",
        )
        ax.stairs(high, edges, baseline=None, color=COLORS[0], linewidth=0.8)
        ax.stairs(low, edges, baseline=None, color=COLORS[0], linewidth=0.8)
        ax.set_title(
            args.title or f"{args.metric} · flow {flow.id}", loc="left", fontsize=14
        )
        ax.set_xlabel("Time since flow start (seconds)")
        ax.set_ylabel(args.ylabel)
        decorate(ax)
        ax.legend(loc="upper left", bbox_to_anchor=(0, -0.15))
        print(
            f"Read {seen:,} finite samples into {len(low):,} bins (batch size {args.batch_size:,})"
        )
        finish(fig, args)


if __name__ == "__main__":
    run(main)
