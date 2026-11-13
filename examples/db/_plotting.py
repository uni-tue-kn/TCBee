"""Small shared helpers for the plotting examples; edit these to change the style."""

import argparse
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

import tcbee

COLORS = ("#2563eb", "#0d9488", "#ea580c", "#9333ea", "#db2777", "#64748b")


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
    parser.add_argument(
        "--start", type=seconds, help="inclusive seconds from the plotted time origin"
    )
    parser.add_argument(
        "--end", type=seconds, help="exclusive seconds from the plotted time origin"
    )
    parser.add_argument(
        "--output", type=Path, help="save PNG, SVG or PDF instead of opening a window"
    )
    parser.add_argument("--title", help="replace the figure title")
    parser.add_argument(
        "--dpi",
        type=positive,
        default=180,
        help="raster export resolution (default: 180)",
    )


def select_metric(flow, spec, direction):
    source, separator, name = spec.partition(".")
    if not separator or not source or not name:
        raise ValueError(f"Expected SOURCE.NAME, got {spec!r}")
    # The API itself has no implicit fallback. These sources explicitly use dir=0.
    if source in ("tcp_probe", "cubic", "bbr", "derived"):
        direction = "none"
    series = flow.series().one(source=source, name=name, direction=direction)
    if series.value_type == "text":
        raise ValueError(
            f"{spec} is text; choose a numeric metric from flow.series().show()"
        )
    return series


def time_window(args, origin_ns):
    if args.start is not None and args.end is not None and args.start >= args.end:
        raise ValueError("--start must precede --end")
    start_ns = (
        None if args.start is None else origin_ns + int(args.start * 1_000_000_000)
    )
    end_ns = None if args.end is None else origin_ns + int(args.end * 1_000_000_000)
    return start_ns, end_ns


def arrays_for_plot(series, args, origin_ns):
    import numpy as np

    start_ns, end_ns = time_window(args, origin_ns)
    data = series.read_numpy(start_ns=start_ns, end_ns=end_ns)
    values = np.asarray(data["value"], dtype=float)
    if not np.isfinite(values).any():
        raise ValueError(
            f"No finite samples in the selected window for {series.source}.{series.name}"
        )
    # Keep invalid samples as gaps, not zeroes or lines joining their neighbors.
    values[~np.isfinite(values)] = np.nan
    return (data["ts_ns"] - origin_ns) / 1e9, values


def style():
    import matplotlib.pyplot as plt
    from cycler import cycler

    plt.rcParams.update(
        {
            "axes.prop_cycle": cycler(color=COLORS),
            "figure.facecolor": "#f8fafc",
            "axes.facecolor": "white",
            "axes.edgecolor": "#cbd5e1",
            "axes.labelcolor": "#334155",
            "text.color": "#0f172a",
            "xtick.color": "#475569",
            "ytick.color": "#475569",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.titleweight": "bold",
            "axes.titlesize": 11,
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "grid.color": "#e2e8f0",
            "grid.linewidth": 0.8,
            "legend.frameon": False,
            "lines.linewidth": 1.6,
            "svg.fonttype": "none",
            "pdf.fonttype": 42,
        }
    )


def decorate(ax):
    ax.grid(axis="y")
    ax.set_axisbelow(True)
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    ax.margins(x=0.01)


def finish(fig, args):
    import matplotlib.pyplot as plt

    if args.output:
        if args.output.suffix.lower() not in (".png", ".svg", ".pdf"):
            raise ValueError("--output must end in .png, .svg or .pdf")
        fig.savefig(
            args.output,
            dpi=args.dpi,
            bbox_inches="tight",
            facecolor=fig.get_facecolor(),
        )
        print(f"Saved {args.output}")
    else:
        plt.show()
    plt.close(fig)


def run(main):
    try:
        main()
    except (tcbee.TCBeeError, OSError, ValueError, ImportError) as error:
        sys.exit(f"Error: {error}")
