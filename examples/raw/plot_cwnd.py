#!/usr/bin/env python3
"""
Plots TCP congestion window (CWND) over time for a selected flow.

Usage:
    ./plot_cwnd.py <cubic-events-file> [flow-index]

If flow-index is not provided, lists available flows and prompts for selection.
"""

import struct
import sys
from pathlib import Path
from collections import defaultdict
from typing import NamedTuple
import ipaddress

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from datetime import datetime, timedelta
except ImportError:
    print("Error: matplotlib is required for plotting.", file=sys.stderr)
    print("Install with: pip install matplotlib", file=sys.stderr)
    sys.exit(1)


class FlowKey(NamedTuple):
    """Unique identifier for a TCP flow."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    family: int

    def __str__(self):
        if self.family == 2:  # IPv4
            return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
        else:  # IPv6
            return f"[{self.src_ip}]:{self.src_port} -> [{self.dst_ip}]:{self.dst_port}"


class CwndDataPoint(NamedTuple):
    """A single CWND measurement."""
    time_ns: int
    cwnd: int
    cnt: int
    last_max_cwnd: int
    curr_rtt: int


def unpack_ipv4_pair(packed: int) -> tuple[str, str]:
    """Unpack IPv4 addresses from u64 (big-endian network order)."""
    src_be = (packed >> 32) & 0xFFFFFFFF
    dst_be = packed & 0xFFFFFFFF

    # Convert from big-endian to native byte order (equivalent to Rust's u32::from_be)
    # The IP addresses are stored as big-endian u32s, need to convert to native
    src_native = int.from_bytes(src_be.to_bytes(4, 'big'), 'little')
    dst_native = int.from_bytes(dst_be.to_bytes(4, 'big'), 'little')

    src_ip = ipaddress.IPv4Address(src_native)
    dst_ip = ipaddress.IPv4Address(dst_native)

    return str(src_ip), str(dst_ip)


def unpack_ports(packed: int) -> tuple[int, int]:
    """Unpack source and destination ports from u32."""
    src_port_be = (packed >> 16) & 0xFFFF
    dst_port_be = packed & 0xFFFF

    # Ports are stored in network byte order (big-endian), need to swap
    src_port = ((src_port_be & 0xFF) << 8) | ((src_port_be >> 8) & 0xFF)
    dst_port = ((dst_port_be & 0xFF) << 8) | ((dst_port_be >> 8) & 0xFF)

    return src_port, dst_port


def read_flow_data(file_path: Path) -> dict[FlowKey, list[CwndDataPoint]]:
    """Read all events and group by flow."""
    CUBIC_EVENT_FORMAT = "<QQ16s16sIHIIIIIIIIIIIIII4s"
    CUBIC_EVENT_SIZE = 114

    flow_data = defaultdict(list)

    with open(file_path, 'rb') as f:
        while True:
            data = f.read(CUBIC_EVENT_SIZE)
            if len(data) == 0:
                break
            if len(data) < CUBIC_EVENT_SIZE:
                break

            # Validate div field
            if data[-4:] != b'\xff\xff\xff\xff':
                continue

            # Unpack event
            unpacked = struct.unpack(CUBIC_EVENT_FORMAT, data)
            time, addr_v4, src_v6, dst_v6, ports, family, \
                cnt, last_max_cwnd, last_cwnd, last_time, \
                bic_origin_point, bic_K, delay_min, epoch_start, \
                ack_cnt, tcp_cwnd, round_start, end_seq, \
                last_ack, curr_rtt, div = unpacked

            # Extract flow key
            if family == 2:  # IPv4
                src_ip, dst_ip = unpack_ipv4_pair(addr_v4)
            else:  # IPv6
                src_ip = str(ipaddress.IPv6Address(src_v6))
                dst_ip = str(ipaddress.IPv6Address(dst_v6))

            src_port, dst_port = unpack_ports(ports)
            flow_key = FlowKey(src_ip, dst_ip, src_port, dst_port, family)

            # Store data point
            data_point = CwndDataPoint(time, tcp_cwnd, cnt, last_max_cwnd, curr_rtt)
            flow_data[flow_key].append(data_point)

    return flow_data


def plot_cwnd(flow: FlowKey, data: list[CwndDataPoint], output_file: Path = None):
    """Plot CWND over time for a flow."""
    if not data:
        print("No data to plot!")
        return

    # Sort by time
    data = sorted(data, key=lambda x: x.time_ns)

    # Extract times and cwnd values
    times_ns = [d.time_ns for d in data]
    cwnds = [d.cwnd for d in data]
    last_max_cwnds = [d.last_max_cwnd for d in data]

    # Convert nanosecond timestamps to seconds relative to first event
    start_time_ns = times_ns[0]
    times_sec = [(t - start_time_ns) / 1_000_000_000 for t in times_ns]

    # Create plot
    fig, ax = plt.subplots(figsize=(12, 6))

    # Plot CWND
    ax.plot(times_sec, cwnds, label='CWND', linewidth=1.5, color='blue')
    ax.plot(times_sec, last_max_cwnds, label='Last Max CWND',
            linewidth=1, linestyle='--', color='red', alpha=0.7)

    ax.set_xlabel('Time (seconds)', fontsize=12)
    ax.set_ylabel('Congestion Window (packets)', fontsize=12)
    ax.set_title(f'TCP CUBIC Congestion Window Over Time\n{flow}', fontsize=14)
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
        print(f"Usage: {sys.argv[0]} <cubic-events-file> [flow-index] [--output <filename.png>]")
        print("\nIf flow-index is not provided, lists available flows.")
        sys.exit(1)

    file_path = Path(sys.argv[1])

    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    # Parse optional output file
    output_file = None
    if "--output" in sys.argv:
        output_idx = sys.argv.index("--output")
        if output_idx + 1 < len(sys.argv):
            output_file = Path(sys.argv[output_idx + 1])

    print(f"Reading flows from: {file_path}")
    flow_data = read_flow_data(file_path)

    # Sort flows by event count
    sorted_flows = sorted(flow_data.items(), key=lambda x: len(x[1]), reverse=True)

    # Check if flow index was provided
    flow_index = None
    for arg in sys.argv[2:]:
        if arg.isdigit():
            flow_index = int(arg)
            break

    if flow_index is None:
        # List flows and prompt for selection
        print(f"\nFound {len(sorted_flows)} flows:\n")
        print(f"{'#':<4} {'Flow':<60} {'Events':<10}")
        print("=" * 80)

        for idx, (flow, data) in enumerate(sorted_flows, 1):
            print(f"{idx:<4} {str(flow):<60} {len(data):<10}")

        print("\nUsage: ./plot_cwnd.py <file> <flow-index> [--output plot.png]")
        sys.exit(0)

    # Validate flow index
    if flow_index < 1 or flow_index > len(sorted_flows):
        print(f"Error: Invalid flow index {flow_index}. Must be 1-{len(sorted_flows)}",
              file=sys.stderr)
        sys.exit(1)

    # Get selected flow
    selected_flow, selected_data = sorted_flows[flow_index - 1]

    print(f"\nPlotting flow #{flow_index}: {selected_flow}")
    print(f"Events: {len(selected_data)}")

    plot_cwnd(selected_flow, selected_data, output_file)


if __name__ == "__main__":
    main()
