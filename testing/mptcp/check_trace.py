#!/usr/bin/env python3
"""Checks a recording made by run.sh: sock records, path manager events and the database.

    check_trace.py TRACE_DIR MPTCP_PORT TCP_PORT [DB]

DB is the recording processed into a SQLite database; its MPTCP connections are checked too.

Every MPTCP connection must show up with two subflows on each side under one conn_id, the plain
TCP connection must have conn_id 0, and the path manager events of each side must describe the
connection's life. Exits with 1 on a failed check.
"""

import collections
import ipaddress
import sqlite3
import struct
import sys
from pathlib import Path

# The layouts below mirror sock_trace_entry and mptcp_pm_entry in
# tcbee-record/tcbee/src/bpf/records.h (bincode, no padding). Update them together with the
# size asserts in tcbee-record/tcbee-common/src/records.rs.
#
# sock_trace_entry on disk: the header
# (time, hook_seq, addr_v4, src_v6, dst_v6, sport, dport, family), the socket fields, conn_id
# last, then the 4 byte divider.
SOCK_RECORD = 262
PORTS = struct.Struct("<HHH")
PORTS_OFFSET = 56
ADDR_V4_OFFSET = 16
CONN_ID_OFFSET = SOCK_RECORD - 8

# mptcp_pm_entry on disk: the same header, then the path manager fields
PM_RECORD = struct.Struct("<QQQ16s16sHHHIIIqBBBBBHHIIIIQI")
PmRecord = collections.namedtuple(
    "PmRecord",
    "time hook_seq addr_v4 src_v6 dst_v6 sport dport family token remote_token subflow_id "
    "error event local_id remote_id backup addr_id addr_family addr_port addr_0 addr_1 addr_2 "
    "addr_3 data_seq data_len",
)
CREATED, ESTABLISHED, CLOSED, SUB_ESTABLISHED = 1, 2, 3, 10
TOKEN_DESTROYED, SUBFLOW_CONNECT = 100, 101


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


def pm_events(path: Path):
    """(event, token, subflow_id, error) per record, in recording order"""
    data = path.read_bytes()
    size = PM_RECORD.size + 4
    if len(data) % size:
        sys.exit(f"{path}: {len(data)} bytes is no whole number of mptcp_pm records")
    events = []
    for i in range(0, len(data), size):
        r = PmRecord(*PM_RECORD.unpack_from(data, i))
        events.append((r.time, r.event, r.token, r.subflow_id, r.error))
    return [e[1:] for e in sorted(events)]


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
        names = ", ".join(f"{a}:{b}->{c}:{d}" for a, b, c, d in sorted(flows))
        print(f"      conn_id {conn_id:#010x}: {names}")
    check(len(subflows) == 2, f"two MPTCP conn_ids (one per side), got {len(subflows)}")
    check(all(len(f) == 2 for f in subflows.values()), "two subflows per conn_id")
    # The first segments of a subflow may leave before the kernel links it to its connection
    check(
        all(n <= 2 for n in untagged.values()),
        f"at most 2 untagged records per subflow: {dict(untagged)}",
    )
    check(set(tcp_tags) == {0}, f"plain TCP records have conn_id 0: {dict(tcp_tags)}")

    events = pm_events(trace / "mptcp_pm.tcp")
    by_token = collections.defaultdict(list)
    for event, token, _subflow_id, error in events:
        by_token[token].append(event)
        if event == SUBFLOW_CONNECT:
            check(error == 0, f"subflow connect of {token:#010x} succeeded: {error}")
    for token, seq in sorted(by_token.items()):
        print(f"      pm {token:#010x}: {seq}")
    check(set(by_token) == set(subflows), "path manager tokens are the conn_ids")
    for token, seq in by_token.items():
        life = [e for e in seq if e in (CREATED, ESTABLISHED, CLOSED, TOKEN_DESTROYED)]
        lifecycle = [CREATED, ESTABLISHED, CLOSED, TOKEN_DESTROYED]
        check(life == lifecycle, f"{token:#010x} lifecycle in order")
        check(seq.count(SUB_ESTABLISHED) == 1, f"{token:#010x} established its second subflow")

    if len(sys.argv) > 4:
        db = sqlite3.connect(sys.argv[4])
        conns = dict(db.execute("SELECT key, id FROM connections WHERE kind = 'mptcp'").fetchall())
        check(set(conns) == set(subflows), f"database has one connection per conn_id: {len(conns)}")
        for token, db_id in conns.items():
            rows = db.execute(
                "SELECT f.src, f.sport, f.dst, f.dport FROM connection_flows c "
                "JOIN flows f ON f.id = c.flow_id WHERE c.connection_id = ?",
                (db_id,),
            ).fetchall()
            ok = set(rows) == subflows[token]
            check(ok, f"database connection {token:#010x} has its subflows")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
