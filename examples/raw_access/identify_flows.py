#!/usr/bin/env python3
"""
Identifies unique TCP flows in a CubicEvent trace file.

Extracts flow information (IP addresses, ports) and counts events per flow.
"""

import struct
import sys
from pathlib import Path
from collections import defaultdict
from typing import NamedTuple
import ipaddress


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


class FlowStats(NamedTuple):
    """Statistics for a flow."""
    flow: FlowKey
    event_count: int
    first_time: int
    last_time: int

    def duration_ns(self):
        return self.last_time - self.first_time

    def duration_ms(self):
        return self.duration_ns() / 1_000_000


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


def extract_flow_key(event_data: bytes) -> FlowKey:
    """Extract flow key from a CubicEvent binary data."""
    # Unpack just the fields we need for flow identification
    # Format: <QQ16s16sIH...
    header_format = "<QQ16s16sIH"
    header_size = struct.calcsize(header_format)

    time, addr_v4, src_v6, dst_v6, ports, family = struct.unpack(
        header_format, event_data[:header_size]
    )

    if family == 2:  # IPv4
        src_ip, dst_ip = unpack_ipv4_pair(addr_v4)
    else:  # IPv6
        src_ip = str(ipaddress.IPv6Address(src_v6))
        dst_ip = str(ipaddress.IPv6Address(dst_v6))

    src_port, dst_port = unpack_ports(ports)

    return FlowKey(src_ip, dst_ip, src_port, dst_port, family), time


def identify_flows(file_path: Path) -> dict[FlowKey, FlowStats]:
    """Identify all unique flows in the trace file."""
    CUBIC_EVENT_SIZE = 114
    flows = {}
    flow_counts = defaultdict(int)
    flow_first_time = {}
    flow_last_time = {}

    with open(file_path, 'rb') as f:
        while True:
            data = f.read(CUBIC_EVENT_SIZE)
            if len(data) == 0:
                break
            if len(data) < CUBIC_EVENT_SIZE:
                print(f"Warning: Incomplete event at end of file", file=sys.stderr)
                break

            # Validate div field (last 4 bytes should be 0xFF)
            if data[-4:] != b'\xff\xff\xff\xff':
                print(f"Warning: Invalid div field, skipping event", file=sys.stderr)
                continue

            flow_key, timestamp = extract_flow_key(data)
            flow_counts[flow_key] += 1

            if flow_key not in flow_first_time:
                flow_first_time[flow_key] = timestamp
            flow_last_time[flow_key] = timestamp

    # Build flow stats
    for flow_key, count in flow_counts.items():
        flows[flow_key] = FlowStats(
            flow=flow_key,
            event_count=count,
            first_time=flow_first_time[flow_key],
            last_time=flow_last_time[flow_key]
        )

    return flows


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-cubic-events-file>")
        sys.exit(1)

    file_path = Path(sys.argv[1])

    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing flows in: {file_path}\n")

    flows = identify_flows(file_path)

    print(f"Found {len(flows)} unique TCP flows:\n")
    print(f"{'#':<4} {'Flow':<60} {'Events':<10} {'Duration (ms)':<15}")
    print("=" * 95)

    # Sort by event count (descending)
    sorted_flows = sorted(flows.values(), key=lambda x: x.event_count, reverse=True)

    for idx, stats in enumerate(sorted_flows, 1):
        duration_ms = stats.duration_ms()
        print(f"{idx:<4} {str(stats.flow):<60} {stats.event_count:<10} {duration_ms:<15.2f}")


if __name__ == "__main__":
    main()
