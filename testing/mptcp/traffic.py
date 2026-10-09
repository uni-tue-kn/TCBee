#!/usr/bin/env python3
"""Test traffic for the MPTCP namespace test: a receiver that discards, a sender at a fixed rate.

    traffic.py serve PORT {mptcp,tcp}
    traffic.py send ADDR PORT {mptcp,tcp} SECONDS
"""

import socket
import sys
import time

IPPROTO_MPTCP = 262
CHUNK = 16384


def protocol(name: str) -> int:
    return IPPROTO_MPTCP if name == "mptcp" else 0


def serve(port: int, proto: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    while True:
        conn, _ = srv.accept()
        while conn.recv(65536):
            pass
        conn.close()


def send(addr: str, port: int, proto: int, seconds: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
    sock.connect((addr, port))
    data = b"x" * CHUNK
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        sock.sendall(data)
        time.sleep(0.001)
    sock.close()


def main() -> None:
    if sys.argv[1] == "serve":
        serve(int(sys.argv[2]), protocol(sys.argv[3]))
    else:
        send(sys.argv[2], int(sys.argv[3]), protocol(sys.argv[4]), float(sys.argv[5]))


if __name__ == "__main__":
    main()
