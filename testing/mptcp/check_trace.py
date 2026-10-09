#!/usr/bin/env python3
"""Checks the sock records of a recording made by run.sh.

    check_trace.py TRACE_DIR MPTCP_PORT TCP_PORT

Every MPTCP connection must show up with two subflows on each side under one conn_id, and the
plain TCP connection must have conn_id 0. Exits with 1 on a failed check.
"""

import collections
import ipaddress
import struct
import sys
from pathlib import Path

# sock_trace_entry on disk (bincode, see tcbee-record/tcbee/src/bpf/records.h): the header
# (time, hook_seq, addr_v4, src_v6, dst_v6, sport, dport, family), the socket fields, conn_id
# last, then the 4 byte divider.
SOCK_RECORD = 172
PORTS = struct.Struct("<HHH")
PORTS_OFFSET = 56
ADDR_V4_OFFSET = 16
CONN_ID_OFFSET = SOCK_RECORD - 8


def records(path: Path):
    data = path.read_bytes()
    if len(data) % SOCK_RECORD:
        sys.exit(f"{path}: {len(data)} bytes is no whole number of sock records")
    for i in range(0, len(data), SOCK_RECORD):
        rec = data[i : i + SOCK_RECORD]
        sport, dport, _family = PORTS.unpack_from(rec, PORTS_OFFSET)
        (addr_v4,) = struct.unpack_from("<Q", rec, ADDR_V4_OFFSET)
        # skc_addrpair: remote address in the low half, local in the high half
        local = ipaddress.IPv4Address((addr_v4 >> 32).to_bytes(4, "little"))
        remote = ipaddress.IPv4Address((addr_v4 & 0xFFFFFFFF).to_bytes(4, "little"))
        (conn_id,) = struct.unpack_from("<I", rec, CONN_ID_OFFSET)
        yield (str(local), sport, str(remote), dport), conn_id


def main() -> int:
    trace, mptcp_port, tcp_port = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    failed = False

    def check(ok: bool, msg: str) -> None:
        nonlocal failed
        print(("ok    " if ok else "FAIL  ") + msg)
        failed |= not ok

    subflows = collections.defaultdict(set)
    untagged = collections.Counter()
    tcp_tags = collections.Counter()
    for name in ["send_sock.tcp", "recv_sock.tcp"]:
        for flow, conn_id in records(trace / name):
            ports = (flow[1], flow[3])
            if mptcp_port in ports:
                if conn_id:
                    subflows[conn_id].add(flow)
                else:
                    untagged[flow] += 1
            elif tcp_port in ports:
                tcp_tags[conn_id] += 1

    for conn_id, flows in sorted(subflows.items()):
        print(f"      conn_id {conn_id:#010x}: " + ", ".join(f"{a}:{b}->{c}:{d}" for a, b, c, d in sorted(flows)))
    check(len(subflows) == 2, f"two MPTCP conn_ids (one per side), got {len(subflows)}")
    check(all(len(f) == 2 for f in subflows.values()), "two subflows per conn_id")
    # The first segments of a subflow may leave before the kernel links it to its connection
    check(all(n <= 2 for n in untagged.values()), f"at most 2 untagged records per subflow: {dict(untagged)}")
    check(set(tcp_tags) == {0}, f"plain TCP records have conn_id 0: {dict(tcp_tags)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
