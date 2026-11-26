#!/usr/bin/env python3
"""Test traffic for the MPTCP namespace tests: a receiver that discards, senders at a fixed rate.

    traffic.py serve PORT {mptcp,tcp} [--log FILE]
    traffic.py send ADDR PORT {mptcp,tcp} SECONDS [--log FILE] [--conns N] [--spread S]
                    [--hold-min S] [--bulk]

With --log, every connection appends one JSON line when it closes: its side, protocol, local
and remote address of its first subflow and, for MPTCP, its local token, whether it fell back
to TCP, and every subflow 4-tuple seen while it ran. The subflows come from
getsockopt(SOL_MPTCP, MPTCP_SUBFLOW_ADDRS), read every 50 ms and once more before close, so the
log is the application's own view of the connection (the oracle of the grouping checks).

send opens N connections, started evenly over --spread seconds. Each sends for SECONDS (or,
with --hold-min, for a random time between hold-min and SECONDS) at about 130 Mb/s (16 KiB per
millisecond), or as fast as it can with --bulk.
"""

import argparse
import ctypes
import json
import random
import socket
import struct
import threading
import time

IPPROTO_MPTCP = 262
SOL_MPTCP = 284
MPTCP_INFO = 1
MPTCP_SUBFLOW_ADDRS = 3
CHUNK = 16384
SAMPLE_S = 0.05

# struct mptcp_info: 6 x u8, then u32 flags at 8 and u32 token at 12; u32 retransmits at 44 and
# u64 bytes_retrans at 48 (6.5 and newer)
MPTCP_INFO_HEAD = struct.Struct("<6B2xII")
MPTCP_INFO_RETRANS = struct.Struct("<IQ")
MPTCP_INFO_RETRANS_OFFSET = 44
MPTCP_INFO_FLAG_FALLBACK = 1
# struct mptcp_subflow_data (4 x u32), then struct mptcp_subflow_addrs per subflow: the local
# and the remote address, each a sockaddr_storage (128 bytes)
SUBFLOW_DATA = struct.Struct("<IIII")
SUBFLOW_ADDRS_SIZE = 256
MAX_SUBFLOWS = 16

_libc = ctypes.CDLL(None, use_errno=True)
_log_lock = threading.Lock()


def protocol(name: str) -> int:
    return IPPROTO_MPTCP if name == "mptcp" else 0


def mptcp_info(sock: socket.socket):
    """(token, fallback, bytes_retrans) or None if the socket answers no MPTCP_INFO (plain TCP,
    fallback); bytes_retrans is None on kernels whose mptcp_info ends earlier"""
    try:
        raw = sock.getsockopt(SOL_MPTCP, MPTCP_INFO, 256)
    except OSError:
        return None
    *_, flags, token = MPTCP_INFO_HEAD.unpack_from(raw)
    bytes_retrans = None
    if len(raw) >= MPTCP_INFO_RETRANS_OFFSET + MPTCP_INFO_RETRANS.size:
        _, bytes_retrans = MPTCP_INFO_RETRANS.unpack_from(raw, MPTCP_INFO_RETRANS_OFFSET)
    return token, bool(flags & MPTCP_INFO_FLAG_FALLBACK), bytes_retrans


def _sockaddr_in(raw: bytes, off: int):
    family, port = struct.unpack_from("<HH", raw, off)
    if family != socket.AF_INET:
        return None
    return socket.inet_ntoa(raw[off + 4 : off + 8]), socket.ntohs(port)


def subflow_addrs(sock: socket.socket) -> list:
    """[(local addr, local port, remote addr, remote port)] of the current subflows. The
    kernel reads the header from the buffer, which Python's getsockopt cannot pass in."""
    size = SUBFLOW_DATA.size + MAX_SUBFLOWS * SUBFLOW_ADDRS_SIZE
    buf = ctypes.create_string_buffer(size)
    SUBFLOW_DATA.pack_into(buf, 0, SUBFLOW_DATA.size, 0, 0, SUBFLOW_ADDRS_SIZE)
    optlen = ctypes.c_uint32(size)
    if _libc.getsockopt(sock.fileno(), SOL_MPTCP, MPTCP_SUBFLOW_ADDRS, buf, ctypes.byref(optlen)):
        return []
    raw = buf.raw
    _, num, size_kernel, _ = SUBFLOW_DATA.unpack_from(raw)
    stride = min(size_kernel, SUBFLOW_ADDRS_SIZE)
    out = []
    for i in range(min(num, MAX_SUBFLOWS)):
        off = SUBFLOW_DATA.size + i * stride
        local, remote = _sockaddr_in(raw, off), _sockaddr_in(raw, off + 128)
        if local and remote:
            out.append((*local, *remote))
    return out


class ConnLog:
    """What one connection saw of itself, written as one JSON line at close"""

    def __init__(self, sock: socket.socket, side: str, proto: str):
        self.sock, self.side, self.proto = sock, side, proto
        self.start = time.monotonic_ns()
        local, remote = sock.getsockname(), sock.getpeername()
        self.first = (local[0], local[1], remote[0], remote[1])
        self.token = None
        self.fallback = None
        self.bytes_retrans = None
        self.info_error = False
        self.subflows = set()
        self.next_sample = 0.0

    def sample(self, force: bool = False) -> None:
        if self.proto != "mptcp":
            return
        now = time.monotonic()
        if not force and now < self.next_sample:
            return
        self.next_sample = now + SAMPLE_S
        info = mptcp_info(self.sock)
        if info is None:
            self.info_error = True
            return
        self.token, self.fallback, self.bytes_retrans = info
        self.subflows.update(subflow_addrs(self.sock))

    def write(self, path: str | None) -> None:
        if not path:
            return
        line = json.dumps({
            "side": self.side, "proto": self.proto, "first": self.first,
            "token": self.token, "fallback": self.fallback, "info_error": self.info_error,
            "bytes_retrans": self.bytes_retrans,
            "subflows": sorted(self.subflows), "start_ns": self.start,
            "end_ns": time.monotonic_ns(),
        })
        with _log_lock, open(path, "a") as f:
            f.write(line + "\n")


def serve(port: int, proto: str, log: str | None) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, protocol(proto))
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(128)

    def handle(conn: socket.socket) -> None:
        cl = ConnLog(conn, "server", proto)
        conn.settimeout(SAMPLE_S)
        cl.sample(force=True)
        while True:
            try:
                if not conn.recv(65536):
                    break
            except socket.timeout:
                pass
            except OSError:
                break
            cl.sample()
        cl.sample(force=True)
        cl.write(log)
        conn.close()

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def send_one(addr: str, port: int, proto: str, seconds: float, bulk: bool, log: str | None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, protocol(proto))
    sock.connect((addr, port))
    cl = ConnLog(sock, "client", proto)
    cl.sample(force=True)
    data = b"x" * CHUNK
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        sock.sendall(data)
        cl.sample()
        if not bulk:
            time.sleep(0.001)
    cl.sample(force=True)
    sock.shutdown(socket.SHUT_WR)
    # Wait for the server to close, so that both sides see the whole connection
    sock.settimeout(10)
    try:
        while sock.recv(65536):
            pass
    except OSError:
        pass
    cl.write(log)
    sock.close()


def send(args) -> None:
    threads = []
    for i in range(args.conns):
        seconds = args.seconds
        if args.hold_min is not None:
            seconds = random.uniform(args.hold_min, args.seconds)
        t = threading.Thread(
            target=send_one,
            args=(args.addr, args.port, args.proto, seconds, args.bulk, args.log),
        )
        t.start()
        threads.append(t)
        if args.conns > 1 and i < args.conns - 1:
            time.sleep(args.spread / (args.conns - 1))
    for t in threads:
        t.join()


def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("port", type=int)
    s.add_argument("proto", choices=["mptcp", "tcp"])
    s.add_argument("--log")
    c = sub.add_parser("send")
    c.add_argument("addr")
    c.add_argument("port", type=int)
    c.add_argument("proto", choices=["mptcp", "tcp"])
    c.add_argument("seconds", type=float)
    c.add_argument("--log")
    c.add_argument("--conns", type=int, default=1)
    c.add_argument("--spread", type=float, default=0.0)
    c.add_argument("--hold-min", type=float)
    c.add_argument("--bulk", action="store_true")
    args = p.parse_args()
    if args.cmd == "serve":
        serve(args.port, args.proto, args.log)
    else:
        send(args)


if __name__ == "__main__":
    main()
