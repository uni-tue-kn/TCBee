#!/usr/bin/env python3
"""Plot a metric of any size as a min/max envelope, read in batches with bounded memory."""

import argparse

import numpy as np
from _plotting import (
    COLORS,
    GOODPUT,
    LABELS,
    add_output_options,
    decorate,
    finish,
    label,
    positive,
    run,
    select_metric,
    style,
    time_window,
)

import tcbee


def envelope(series, *, start_ns, end_ns, bins=2000, batch_size=65_536):
    """Keep min/max per time bin in O(bins + batch_size) Python result memory.

    A bin without samples repeats the previous bin's last value, since a
    metric keeps its value until the next sample.
    """
    if end_ns <= start_ns or bins < 1 or batch_size < 1:
        raise ValueError("Need a nonempty time interval, positive bins and positive batch size")
    width_ns = (end_ns - start_ns + bins - 1) // bins
    bin_count = (end_ns - start_ns + width_ns - 1) // width_ns
    low, high = np.full(bin_count, np.inf), np.full(bin_count, -np.inf)
    last = np.full(bin_count, np.nan)
    seen = 0
    for batch in series.iter_batches(batch_size=batch_size, start_ns=start_ns, end_ns=end_ns):
        timestamps = np.asarray(batch.ts_ns, dtype=np.int64)
        values = np.asarray(batch.values, dtype=float)
        finite = np.isfinite(values)
        indices = (timestamps[finite] - start_ns) // width_ns
        np.minimum.at(low, indices, values[finite])
        np.maximum.at(high, indices, values[finite])
        last[indices] = values[finite]  # later samples overwrite earlier ones
        seen += int(np.count_nonzero(finite))
    empty = ~np.isfinite(low)
    filled = np.where(np.isnan(last), -1, np.arange(bin_count))
    carried = last[np.maximum.accumulate(filled)]
    carried[np.maximum.accumulate(filled) < 0] = np.nan
    low[empty], high[empty] = carried[empty], carried[empty]
    edges_ns = [min(start_ns + i * width_ns, end_ns) for i in range(bin_count + 1)]
    return edges_ns, low, high, seen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument("flow_id", type=int)
    parser.add_argument("--metric", default="tcp_probe.SRTT", metavar="SOURCE.NAME")
    parser.add_argument(
        "--bins", type=positive, default=2000, help="maximum time bins (default: 2000)"
    )
    parser.add_argument("--batch-size", type=positive, default=65_536)
    add_output_options(parser)
    args = parser.parse_args()
    if args.metric == GOODPUT:
        parser.error("goodput needs whole flows; use plot_metrics.py")
    style()
    import matplotlib.pyplot as plt

    with tcbee.open(args.database) as db:
        flow = db.flow(args.flow_id)
        series = select_metric(flow, args.metric, args.dir)
        scale = LABELS.get(args.metric, (None, 1))[1]
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
        if start >= end:
            raise ValueError(
                f"The window holds no samples; {args.metric} spans "
                f"{(series.start_ns - flow.start_ns) / 1e9:.1f} to "
                f"{(series.end_ns - flow.start_ns) / 1e9:.1f} s"
            )
        edges_ns, low, high, seen = envelope(
            series,
            start_ns=start,
            end_ns=end,
            bins=args.bins,
            batch_size=args.batch_size,
        )
        low, high = low * scale, high * scale
        if not seen:
            raise ValueError("No finite samples in the selected time window")
        edges = np.asarray([(timestamp - flow.start_ns) / 1e9 for timestamp in edges_ns])
        fig, ax = plt.subplots(figsize=(7, 3), layout="constrained")
        ax.stairs(
            high,
            edges,
            baseline=low,
            fill=True,
            alpha=0.25,
            color=COLORS[0],
            label=f"Min–max over {len(low):,} time bins",
        )
        ax.stairs(high, edges, baseline=None, color=COLORS[0], linewidth=0.8)
        ax.stairs(low, edges, baseline=None, color=COLORS[0], linewidth=0.8)
        ax.set_title(args.title or str(flow), loc="left")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel(label(args.metric))
        decorate(ax)
        ax.legend(loc="lower right", bbox_to_anchor=(1, 1))
        print(
            f"Read {seen:,} finite samples into {len(low):,} bins (batch size {args.batch_size:,})"
        )
        finish(fig, args)


if __name__ == "__main__":
    run(main)
