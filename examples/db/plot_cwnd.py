#!/usr/bin/env python3
"""
Plots TCP congestion window (CWND) over time from the TCBee SQLite database.

Usage:
    ./plot_cwnd.py <database.sqlite> [flow-id] [--series <name>]

If flow-id is not provided, lists available flows.
Default series is 'tcp_cwnd', but you can specify others like 'last_max_cwnd', 'cnt', etc.
"""

import sqlite3
import sys
from pathlib import Path

try:
    import matplotlib.pyplot as plt
except ImportError:
    print("Error: matplotlib is required for plotting.", file=sys.stderr)
    print("Install with: pip install matplotlib", file=sys.stderr)
    sys.exit(1)


def swap_port_bytes(port: int) -> int:
    """Swap bytes in port number (convert between network and host byte order)."""
    return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)


def get_flows(db_path: Path):
    """Get all flows from database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            f.id, f.src, f.dst, f.sport, f.dport, f.l4proto,
            COUNT(DISTINCT ts.time_series_id) as series_count
        FROM flows f
        LEFT JOIN time_series ts ON ts.flow_id = f.id
        GROUP BY f.id
        ORDER BY f.id
    """)

    flows = []
    for row in cursor.fetchall():
        sport = swap_port_bytes(row['sport'])
        dport = swap_port_bytes(row['dport'])
        flows.append({
            'id': row['id'],
            'src': row['src'],
            'dst': row['dst'],
            'sport': sport,
            'dport': dport,
            'l4proto': row['l4proto'],
            'series_count': row['series_count']
        })

    conn.close()
    return flows


def get_time_series_names(db_path: Path, flow_id: int):
    """Get available time series for a flow."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT name
        FROM time_series
        WHERE flow_id = ?
        ORDER BY name
    """, (flow_id,))

    names = [row[0] for row in cursor.fetchall()]
    conn.close()
    return names


def get_time_series_data(db_path: Path, flow_id: int, series_name: str):
    """Get time series data for a specific flow and series."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT tsd.timestamp, tsd.value_integer, tsd.value_float
        FROM time_series_data tsd
        JOIN time_series ts ON ts.time_series_id = tsd.time_series_id
        WHERE ts.flow_id = ? AND ts.name = ?
        ORDER BY tsd.timestamp
    """, (flow_id, series_name))

    data = []
    for row in cursor.fetchall():
        timestamp = row[0]
        # Use integer value if available, otherwise float
        value = row[1] if row[1] != -1 else row[2]
        data.append((timestamp, value))

    conn.close()
    return data


def plot_time_series(flow_info: dict, series_data: dict, output_file: Path = None):
    """
    Plot time series data for a flow.

    Args:
        flow_info: Dictionary with flow information
        series_data: Dictionary mapping series names to (timestamp, value) lists
        output_file: Optional path to save the plot
    """
    if not series_data:
        print("No data to plot!")
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    # Convert to relative time (seconds from first data point)
    first_time = None
    for series_name, data in series_data.items():
        if data:
            times = [d[0] for d in data]
            values = [d[1] for d in data]

            if first_time is None:
                first_time = times[0]

            # Convert to seconds relative to first point
            times_sec = [(t - first_time) for t in times]

            # Plot with different styles
            if series_name == 'tcp_cwnd':
                ax.plot(times_sec, values, label=series_name, linewidth=1.5, color='blue')
            elif series_name == 'last_max_cwnd':
                ax.plot(times_sec, values, label=series_name,
                       linewidth=1, linestyle='--', color='red', alpha=0.7)
            else:
                ax.plot(times_sec, values, label=series_name, linewidth=1, alpha=0.8)

    flow_str = f"{flow_info['src']}:{flow_info['sport']} -> {flow_info['dst']}:{flow_info['dport']}"

    ax.set_xlabel('Time (seconds)', fontsize=12)
    ax.set_ylabel('Value', fontsize=12)
    ax.set_title(f'TCP Flow Time Series (Flow #{flow_info["id"]})\n{flow_str}', fontsize=14)
    ax.grid(True, alpha=0.3)
    ax.legend(loc='best')

    plt.tight_layout()

    if output_file:
        plt.savefig(output_file, dpi=150)
        print(f"Plot saved to: {output_file}")
    else:
        plt.show()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <database.sqlite> [flow-id] [--series <name1,name2,...>] [--output <file.png>]")
        print("\nExamples:")
        print(f"  {sys.argv[0]} db.sqlite                          # List flows")
        print(f"  {sys.argv[0]} db.sqlite 1                        # Plot tcp_cwnd for flow 1")
        print(f"  {sys.argv[0]} db.sqlite 1 --series tcp_cwnd,last_max_cwnd")
        print(f"  {sys.argv[0]} db.sqlite 1 --output plot.png")
        sys.exit(1)

    db_path = Path(sys.argv[1])

    if not db_path.exists():
        print(f"Error: Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    # Parse arguments
    flow_id = None
    series_names = ['tcp_cwnd']  # Default series
    output_file = None

    for i, arg in enumerate(sys.argv[2:], start=2):
        if arg.isdigit():
            flow_id = int(arg)
        elif arg == "--series" and i + 1 < len(sys.argv):
            series_names = sys.argv[i + 1].split(',')
        elif arg == "--output" and i + 1 < len(sys.argv):
            output_file = Path(sys.argv[i + 1])

    # Get flows
    flows = get_flows(db_path)

    if flow_id is None:
        # List flows
        print(f"Found {len(flows)} flows in database:\n")
        print(f"{'ID':<5} {'Flow':<60} {'Series':<10}")
        print("=" * 80)

        for flow in flows:
            flow_str = f"{flow['src']}:{flow['sport']} -> {flow['dst']}:{flow['dport']} (TCP)"
            print(f"{flow['id']:<5} {flow_str:<60} {flow['series_count']:<10}")

        print(f"\nUsage: {sys.argv[0]} <database.sqlite> <flow-id> [--series <names>]")
        sys.exit(0)

    # Find the selected flow
    selected_flow = next((f for f in flows if f['id'] == flow_id), None)

    if selected_flow is None:
        print(f"Error: Flow ID {flow_id} not found in database", file=sys.stderr)
        sys.exit(1)

    # Get available series for this flow
    available_series = get_time_series_names(db_path, flow_id)

    if not available_series:
        print(f"Error: No time series data found for flow {flow_id}", file=sys.stderr)
        sys.exit(1)

    # Validate requested series
    invalid_series = [s for s in series_names if s not in available_series]
    if invalid_series:
        print(f"Warning: Series not found: {', '.join(invalid_series)}", file=sys.stderr)
        print(f"Available series: {', '.join(available_series)}", file=sys.stderr)
        series_names = [s for s in series_names if s in available_series]

    if not series_names:
        print("Error: No valid series to plot", file=sys.stderr)
        sys.exit(1)

    # Fetch data for all requested series
    series_data = {}
    for series_name in series_names:
        data = get_time_series_data(db_path, flow_id, series_name)
        if data:
            series_data[series_name] = data
            print(f"Loaded {len(data)} data points for '{series_name}'")

    flow_str = f"{selected_flow['src']}:{selected_flow['sport']} -> {selected_flow['dst']}:{selected_flow['dport']}"
    print(f"\nPlotting flow #{flow_id}: {flow_str}")

    plot_time_series(selected_flow, series_data, output_file)


if __name__ == "__main__":
    main()
