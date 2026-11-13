"""Shared helpers for the plotting examples; edit these to change the style."""

import argparse
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

import tcbee

COLORS = ("#1f77b4", "#e6550d", "#2ca02c", "#9467bd", "#8c564b", "#7f7f7f")

# Axis label and scale for metrics with a known unit; others are plotted raw.
LABELS = {
    "tcp_probe.SND_CWND": ("Congestion window (segments)", 1),
    "tcp_probe.SSTRESH": ("Slow start threshold (segments)", 1),
    "tcp_probe.SRTT": ("Smoothed RTT (ms)", 1e-3),
    "tcp_probe.SND_WND": ("Send window (bytes)", 1),
    "cwnd.perf_snd_cwnd": ("Congestion window (segments)", 1),
    "bbr.min_rtt_us": ("BBR min RTT (ms)", 1e-3),
    "bbr.pacing_gain": ("BBR pacing gain", 1 / 256),
    "bbr.cwnd_gain": ("BBR cwnd gain", 1 / 256),
}

# Not a stored metric: computed from the acknowledged sequence number
GOODPUT = "goodput"
GOODPUT_SOURCE = ("tcp_probe", "SND_UNA")


def seconds(value):
    try:
        result = Decimal(value)
    except InvalidOperation:
        raise argparse.ArgumentTypeError("expected seconds, for example 0.25") from None
    if not result.is_finite() or result < 0:
        raise argparse.ArgumentTypeError("seconds must be finite and nonnegative")
    return result


def positive(value):
    try:
        result = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive integer") from None
    if result < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return result


def add_output_options(parser):
    parser.add_argument("--start", type=seconds, help="first second to plot")
    parser.add_argument("--end", type=seconds, help="last second to plot (exclusive)")
    parser.add_argument(
        "--dir",
        choices=("send", "recv", "none"),
        help="direction, only needed when a metric is recorded in several",
    )
    parser.add_argument(
        "--bin",
        type=seconds,
        default=Decimal("0.5"),
        help="goodput bin width in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--output", type=Path, help="save PNG, SVG or PDF instead of opening a window"
    )
    parser.add_argument("--title", help="figure title")
    parser.add_argument("--dpi", type=positive, default=150, help="PNG resolution")


def parse_spec(spec):
    source, separator, name = spec.partition(".")
    if not separator or not source or not name:
        raise ValueError(f"Expected SOURCE.NAME or {GOODPUT}, got {spec!r}")
    return source, name


def select_metric(flow, spec, direction=None):
    source, name = GOODPUT_SOURCE if spec == GOODPUT else parse_spec(spec)
    try:
        series = flow.series().one(source=source, name=name, direction=direction)
    except tcbee.NotFound:
        raise ValueError(
            f"Flow {flow.id} has no {source}.{name}; list its metrics with list_flows.py -v"
        ) from None
    except tcbee.AmbiguousSelection:
        raise ValueError(f"{spec} is recorded in several directions; pass --dir") from None
    if series.value_type == "text":
        raise ValueError(f"{spec} is text; choose a numeric metric")
    return series


def label(spec):
    if spec == GOODPUT:
        return "Goodput (Mb/s)"
    return LABELS.get(spec, (spec, 1))[0]


def time_window(args, origin_ns):
    if args.start is not None and args.end is not None and args.start >= args.end:
        raise ValueError("--start must precede --end")
    start_ns = None if args.start is None else origin_ns + int(args.start * 10**9)
    end_ns = None if args.end is None else origin_ns + int(args.end * 10**9)
    return start_ns, end_ns


def read_metric(flow, spec, args, origin_ns):
    """Return times in seconds since origin_ns and scaled values for one metric."""
    import numpy as np

    series = select_metric(flow, spec, args.dir)
    start_ns, end_ns = time_window(args, origin_ns)
    data = series.read_numpy(start_ns=start_ns, end_ns=end_ns)
    if len(data["ts_ns"]) < (2 if spec == GOODPUT else 1):
        raise ValueError(f"Too few samples of {spec} for flow {flow.id} in this window")
    times = (data["ts_ns"] - origin_ns) / 1e9
    if spec == GOODPUT:
        return goodput(times, data["value"], float(args.bin))
    return times, np.asarray(data["value"], dtype=float) * LABELS.get(spec, (spec, 1))[1]


def goodput(times, snd_una, bin_s):
    """Bin the newly acknowledged bytes into Mb/s; SND_UNA is a wrapping u32."""
    import numpy as np

    acked = np.diff(np.asarray(snd_una, dtype=np.int64)) % 2**32
    edges = np.arange(times[0], times[-1] + bin_s, bin_s)
    sums, _ = np.histogram(times[1:], bins=edges, weights=acked)
    return edges[:-1], sums * 8 / bin_s / 1e6


def style():
    import matplotlib.pyplot as plt
    from cycler import cycler

    plt.rcParams.update(
        {
            "axes.prop_cycle": cycler(color=COLORS),
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "axes.axisbelow": True,
            "grid.color": "#dddddd",
            "grid.linewidth": 0.6,
            "font.size": 10,
            "legend.frameon": False,
            "lines.linewidth": 1.2,
            "svg.fonttype": "none",
            "pdf.fonttype": 42,
        }
    )


def decorate(ax):
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    ax.margins(x=0)
    ax.set_ylim(bottom=0)


def finish(fig, args):
    import matplotlib.pyplot as plt

    if args.output:
        if args.output.suffix.lower() not in (".png", ".svg", ".pdf"):
            raise ValueError("--output must end in .png, .svg or .pdf")
        fig.savefig(args.output, dpi=args.dpi, bbox_inches="tight")
        print(f"Saved {args.output}")
    else:
        plt.show()
    plt.close(fig)


def run(main):
    try:
        main()
    except (tcbee.TCBeeError, OSError, ValueError, ImportError) as error:
        sys.exit(f"Error: {error}")
