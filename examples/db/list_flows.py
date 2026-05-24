#!/usr/bin/env python3
"""
Lists TCP flows from the TCBee SQLite database.

The database is created by tcbee-process and contains flows and time series data.
"""

import sqlite3
import sys
from pathlib import Path
from typing import NamedTuple


class Flow(NamedTuple):
    """Flow information from database."""
    id: int
    src: str
    dst: str
    sport: int
    dport: int
    l4proto: int
    data_points: int = 0

    def __str__(self):
        proto_name = {6: "TCP", 17: "UDP"}.get(self.l4proto, f"Proto{self.l4proto}")
        return f"{self.src}:{self.sport} -> {self.dst}:{self.dport} ({proto_name})"


def swap_port_bytes(port: int) -> int:
    """
    Swap bytes in port number (convert between network and host byte order).

    The database stores ports in network byte order, so we need to swap them
    to display correctly.
    """
    return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)


def list_flows(db_path: Path, show_stats: bool = True):
    """List all flows from the database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get flows with optional data point counts
    if show_stats:
        query = """
            SELECT
                f.id, f.src, f.dst, f.sport, f.dport, f.l4proto,
                COUNT(DISTINCT ts.time_series_id) as series_count,
                (SELECT COUNT(*) FROM time_series_data tsd
                 JOIN time_series ts2 ON ts2.time_series_id = tsd.time_series_id
                 WHERE ts2.flow_id = f.id) as total_points
            FROM flows f
            LEFT JOIN time_series ts ON ts.flow_id = f.id
            GROUP BY f.id
            ORDER BY total_points DESC, f.id
        """
    else:
        query = "SELECT id, src, dst, sport, dport, l4proto FROM flows ORDER BY id"

    cursor.execute(query)
    flows = []

    for row in cursor.fetchall():
        # Swap port bytes to correct byte order
        sport_corrected = swap_port_bytes(row['sport'])
        dport_corrected = swap_port_bytes(row['dport'])

        if show_stats:
            flow = Flow(
                id=row['id'],
                src=row['src'],
                dst=row['dst'],
                sport=sport_corrected,
                dport=dport_corrected,
                l4proto=row['l4proto'],
                data_points=row['total_points']
            )
        else:
            flow = Flow(
                id=row['id'],
                src=row['src'],
                dst=row['dst'],
                sport=sport_corrected,
                dport=dport_corrected,
                l4proto=row['l4proto']
            )
        flows.append(flow)

    conn.close()
    return flows


def get_time_series_info(db_path: Path, flow_id: int):
    """Get available time series for a flow."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ts.name, COUNT(tsd.timestamp) as point_count
        FROM time_series ts
        LEFT JOIN time_series_data tsd ON tsd.time_series_id = ts.time_series_id
        WHERE ts.flow_id = ?
        GROUP BY ts.name
        ORDER BY ts.name
    """, (flow_id,))

    series = cursor.fetchall()
    conn.close()
    return series


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-database.sqlite> [--verbose]")
        sys.exit(1)

    db_path = Path(sys.argv[1])

    if not db_path.exists():
        print(f"Error: Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print(f"Reading flows from: {db_path}\n")

    flows = list_flows(db_path)

    print(f"Found {len(flows)} flows:\n")

    if verbose:
        print(f"{'ID':<5} {'Flow':<60} {'Series':<8} {'Points':<10}")
        print("=" * 90)

        for flow in flows:
            series_count = len(get_time_series_info(db_path, flow.id))
            print(f"{flow.id:<5} {str(flow):<60} {series_count:<8} {flow.data_points:<10}")

            if series_count > 0:
                series = get_time_series_info(db_path, flow.id)
                series_names = ", ".join([s[0] for s in series[:5]])
                if len(series) > 5:
                    series_names += f", ... (+{len(series)-5} more)"
                print(f"      Available series: {series_names}")
    else:
        print(f"{'ID':<5} {'Flow':<60} {'Points':<10}")
        print("=" * 80)

        for flow in flows:
            print(f"{flow.id:<5} {str(flow):<60} {flow.data_points:<10}")

    print(f"\nUse --verbose to see available time series for each flow")


if __name__ == "__main__":
    main()
