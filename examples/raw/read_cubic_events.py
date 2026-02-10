#!/usr/bin/env python3
"""
Deserializes CubicEvent structs from a bincode-serialized binary file.

The CubicEvent struct is serialized using Rust's bincode format:
- Total size: 114 bytes per entry (bincode serialization)
- Little-endian byte order
"""

import struct
import sys
from pathlib import Path
from typing import NamedTuple


class CubicEvent(NamedTuple):
    """CubicEvent struct matching the Rust definition."""
    # Shared ID fields
    time: int              # u64
    addr_v4: int          # u64
    src_v6: bytes         # [u8; 16]
    dst_v6: bytes         # [u8; 16]
    ports: int            # u32
    family: int           # u16

    # Cubic fields
    cnt: int              # u32
    last_max_cwnd: int    # u32
    last_cwnd: int        # u32
    last_time: int        # u32
    bic_origin_point: int # u32
    bic_K: int            # u32
    delay_min: int        # u32
    epoch_start: int      # u32
    ack_cnt: int          # u32
    tcp_cwnd: int         # u32
    round_start: int      # u32
    end_seq: int          # u32
    last_ack: int         # u32
    curr_rtt: int         # u32
    div: bytes            # [u8; 4]

    def __str__(self):
        """Format the event for readable output."""
        return (
            f"CubicEvent(\n"
            f"  time={self.time},\n"
            f"  addr_v4=0x{self.addr_v4:016x},\n"
            f"  ports=0x{self.ports:08x},\n"
            f"  family={self.family},\n"
            f"  cwnd={self.tcp_cwnd},\n"
            f"  cnt={self.cnt},\n"
            f"  last_max_cwnd={self.last_max_cwnd},\n"
            f"  bic_K={self.bic_K},\n"
            f"  curr_rtt={self.curr_rtt}\n"
            f")"
        )


# Bincode serialization format (little-endian, no padding)
# < = little-endian
# QQ = 2x u64 (time, addr_v4)
# 16s16s = 2x [u8; 16] (src_v6, dst_v6)
# I = u32 (ports)
# H = u16 (family)
# IIIIIIIIIIIIII = 14x u32 (cnt through curr_rtt)
# 4s = [u8; 4] (div)
CUBIC_EVENT_FORMAT = "<QQ16s16sIHIIIIIIIIIIIIII4s"
CUBIC_EVENT_SIZE = struct.calcsize(CUBIC_EVENT_FORMAT)  # Should be 114 bytes

def read_cubic_events(file_path: Path):
    """
    Read and deserialize CubicEvent structs from a binary file.

    Yields CubicEvent objects until the file is exhausted.
    """
    with open(file_path, 'rb') as f:
        event_num = 0
        while True:
            # Read one struct worth of data
            data = f.read(CUBIC_EVENT_SIZE)

            # End of file
            if len(data) == 0:
                break

            # Incomplete struct at end of file
            if len(data) < CUBIC_EVENT_SIZE:
                print(f"Warning: Incomplete event at end of file (got {len(data)} bytes, expected {CUBIC_EVENT_SIZE})",
                      file=sys.stderr)
                break

            # Unpack the binary data
            unpacked = struct.unpack(CUBIC_EVENT_FORMAT, data)

            # Create CubicEvent from unpacked data
            event = CubicEvent(*unpacked)

            # Validate div field (should contain four 0xFF bytes)
            expected_div = b'\xff\xff\xff\xff'
            if event.div != expected_div:
                print(f"Error: Invalid div field at event {event_num + 1}! "
                      f"Expected {expected_div.hex()}, got {event.div.hex()}. "
                      f"Struct alignment/size may be incorrect.",
                      file=sys.stderr)
                print(f"This indicates the binary data is not being read correctly.", file=sys.stderr)
                continue

            event_num += 1

            yield event_num, event


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-cubic-events-file>")
        print(f"\nStruct size: {CUBIC_EVENT_SIZE} bytes")
        sys.exit(1)

    file_path = Path(sys.argv[1])

    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading CubicEvent structs from: {file_path}")
    print(f"Struct size: {CUBIC_EVENT_SIZE} bytes\n")

    # Read and print all events
    for event_num, event in read_cubic_events(file_path):
        print(f"Event #{event_num}:")
        print(event)
        print()


if __name__ == "__main__":
    main()
