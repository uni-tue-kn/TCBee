#!/usr/bin/env python3
"""
Bottleneck topology for tcbee-live cwnd testing.

    TCBeeHost --100M-- s1 --10M(bottleneck)-- s2 --100M-- ReceivingHost

With --mptcp, two paths and one MPTCP connection whose subflows join, fail, turn backup and
leave (MPTCP_STEPS):

    TCBeeHost --100M-- s1 --10M, 40 ms-- ReceivingHost     path 1, 10.0.0.0/24
              --100M-- s2 --20M, 10 ms--                   path 2, 10.0.1.0/24

Usage via the run scripts in this directory:
    ./testing/run_cubic_single.sh
    ./testing/run_cubic_double.sh
    ./testing/run_bbr_single.sh
    ./testing/run_bbr_double.sh

Or directly:
    sudo -E python3 testing/topology.py [--cc cubic|bbr] [--double | --mptcp]
                                        [--tool full --headless [--duration S]]
"""
import argparse
import os
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.topo import Topo

UPLINK_BW = 100      # Mbps  — TCBeeHost↔s1 and s2↔RecvHost
BOTTLENECK_BW = 10   # Mbps  — s1↔s2 (the constrained link)
BOTTLENECK_DELAY = "40ms"
QUEUE_SIZE = 150     # packets — ~1.5× BDP for 10 Mbps / 82 ms RTT

TCBEE_IP = "10.0.0.1"
RECV_IP = "10.0.0.2"
PORT1 = 5001
PORT2 = 5002         # used only for the second stream in --double mode

_LIVE_BASE    = Path(__file__).parent.parent / "tcbee-live"   / "target"
_RECORD_BASE  = Path(__file__).parent.parent / "tcbee-record" / "target"
# tcbee-process and tcbee-viz are members of the cargo workspace in the repository root
_PROCESS_BASE = Path(__file__).parent.parent / "target"
_VIZ_BASE     = Path(__file__).parent.parent / "target"

LIVE_BINARY = (
    _LIVE_BASE / "release" / "tcbee-live"
    if (_LIVE_BASE / "release" / "tcbee-live").exists()
    else _LIVE_BASE / "debug" / "tcbee-live"
)
RECORD_BINARY = (
    _RECORD_BASE / "release" / "tcbee-record"
    if (_RECORD_BASE / "release" / "tcbee-record").exists()
    else _RECORD_BASE / "debug" / "tcbee-record"
)
PROCESS_BINARY = (
    _PROCESS_BASE / "release" / "tcbee-process"
    if (_PROCESS_BASE / "release" / "tcbee-process").exists()
    else _PROCESS_BASE / "debug" / "tcbee-process"
)
VIZ_BINARY = (
    _VIZ_BASE / "release" / "tcbee-viz"
    if (_VIZ_BASE / "release" / "tcbee-viz").exists()
    else _VIZ_BASE / "debug" / "tcbee-viz"
)

# MPTCP scenario: path 1 is the bottleneck above, path 2 is faster and shorter
MPTCP_PORT = 5003
PATH2_BW = 20        # Mbps
PATH2_DELAY = "10ms"
PATH2_QUEUE = 60     # packets — ~1.5× BDP for 20 Mbps / 22 ms RTT
TCBEE_IP2 = "10.0.1.1"
RECV_IP2 = "10.0.1.2"
TRAFFIC = Path(__file__).parent / "mptcp" / "traffic.py"
# The recorder attaches before the MPTCP connection opens, so that its handshake is recorded
MPTCP_START_DELAY = 3
MPTCP_SECONDS = 40
MPTCP_LOG = "/tmp/tcbee-mptcp.log"

DUCKDB_PATH = "/tmp/db.duck"


def headless_seconds(double: bool, mptcp: bool) -> int:
    """Recording time of a headless run unless --duration is given: the second stream of a
    double run starts at 30 s; the MPTCP connection needs a moment to close"""
    if mptcp:
        return MPTCP_START_DELAY + MPTCP_SECONDS + 5
    return 60 if double else 30


class BottleneckTopo(Topo):
    def build(self):
        tcbee = self.addHost("tcbee", ip=f"{TCBEE_IP}/24")
        recv  = self.addHost("recv",  ip=f"{RECV_IP}/24")
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")

        self.addLink(tcbee, s1, bw=UPLINK_BW,      delay="1ms",           use_htb=True)
        self.addLink(s1,    s2, bw=BOTTLENECK_BW,  delay=BOTTLENECK_DELAY,
                     use_htb=True, max_queue_size=QUEUE_SIZE)
        self.addLink(s2,    recv, bw=UPLINK_BW,    delay="1ms",           use_htb=True)


class TwoPathTopo(Topo):
    """Path 1 (tcbee-eth0, recv-eth0) is the bottleneck of BottleneckTopo, path 2 (tcbee-eth1,
    recv-eth1) gets its addresses in setup_mptcp"""

    def build(self):
        tcbee = self.addHost("tcbee", ip=f"{TCBEE_IP}/24")
        recv  = self.addHost("recv",  ip=f"{RECV_IP}/24")
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")

        # The order of the links decides the interface names
        self.addLink(tcbee, s1, bw=UPLINK_BW,     delay="1ms",           use_htb=True)
        self.addLink(s1,    recv, bw=BOTTLENECK_BW, delay=BOTTLENECK_DELAY,
                     use_htb=True, max_queue_size=QUEUE_SIZE)
        self.addLink(tcbee, s2, bw=UPLINK_BW,     delay="1ms",           use_htb=True)
        self.addLink(s2,    recv, bw=PATH2_BW,    delay=PATH2_DELAY,
                     use_htb=True, max_queue_size=PATH2_QUEUE)


def setup_mptcp(tcbee, recv):
    """Addresses of path 2, MPTCP on both hosts and the MPTCP server on recv"""
    tcbee.setIP(TCBEE_IP2, 24, intf="tcbee-eth1")
    recv.setIP(RECV_IP2, 24, intf="recv-eth1")
    for host in (tcbee, recv):
        host.cmd("sysctl -w net.mptcp.enabled=1")
        host.cmd("ip mptcp limits set subflow 2 add_addr_accepted 2")
    # The subflow from TCBEE_IP2 goes to RECV_IP, the address of the first subflow, over path 2
    tcbee.cmd(f"ip rule add from {TCBEE_IP2} table 102")
    tcbee.cmd(f"ip route add {RECV_IP}/32 dev tcbee-eth1 table 102")
    recv.cmd(f"nohup {sys.executable} {TRAFFIC} serve {MPTCP_PORT} mptcp > /dev/null 2>&1 &")
    info(f"*** MPTCP enabled, server started on recv:{MPTCP_PORT}\n")


def path2_blackhole(tcbee, recv, on: bool):
    """Drop everything that arrives over path 2, in both directions"""
    for host, dev in ((tcbee, "tcbee-eth1"), (recv, "recv-eth1")):
        if on:
            host.cmd(f"tc qdisc add dev {dev} ingress")
            host.cmd(f"tc filter add dev {dev} ingress matchall action drop")
        else:
            host.cmd(f"tc qdisc del dev {dev} ingress")


# Seconds after the connection opens, what happens, and how
MPTCP_STEPS = [
    (5, f"path 2 endpoint {TCBEE_IP2} added: a second subflow joins",
     lambda t, r: t.cmd(f"ip mptcp endpoint add {TCBEE_IP2} dev tcbee-eth1 id 1 subflow")),
    (15, "path 2 blackholed: its subflow goes stale, data is reinjected on path 1",
     lambda t, r: path2_blackhole(t, r, True)),
    (22, "path 2 restored", lambda t, r: path2_blackhole(t, r, False)),
    (28, "path 2 endpoint marked backup: MP_PRIO, data moves to path 1",
     lambda t, r: t.cmd("ip mptcp endpoint change id 1 backup")),
    (34, "path 2 endpoint deleted: its subflow closes",
     lambda t, r: t.cmd("ip mptcp endpoint delete id 1")),
]


def run_mptcp_steps(tcbee, recv, say, stop: threading.Event):
    """Opens the MPTCP connection after MPTCP_START_DELAY and works through MPTCP_STEPS until
    `stop` is set, when the recorder has quit and the topology goes down"""
    if stop.wait(MPTCP_START_DELAY):
        return
    t0 = time.monotonic()
    say(f"MPTCP connection opens: tcbee → recv:{MPTCP_PORT} over path 1, {MPTCP_SECONDS} s")
    tcbee.cmd(f"nohup {sys.executable} {TRAFFIC} send {RECV_IP} {MPTCP_PORT} mptcp"
              f" {MPTCP_SECONDS} --bulk > /tmp/tcbee-mptcp-send.log 2>&1 &")
    for at, what, action in MPTCP_STEPS:
        if stop.wait(max(0.0, t0 + at - time.monotonic())):
            return
        say(f"t={at:>2} s  {what}")
        action(tcbee, recv)
    if stop.wait(max(0.0, t0 + MPTCP_SECONDS - time.monotonic())):
        return
    say(f"t={MPTCP_SECONDS} s  transfer ends, the connection closes")


def run(cc: str, double: bool, tool: str = "live", record_args: str = "",
        headless: bool = False, duration: int | None = None, mptcp: bool = False):
    setLogLevel("info")

    if mptcp and tool == "live":
        sys.exit("Error: the MPTCP scenario needs tcbee-record (--tool record or full)")
    if mptcp and not Path("/proc/sys/net/mptcp/enabled").exists():
        sys.exit("Error: the kernel has no MPTCP (CONFIG_MPTCP)")

    if tool == "live" and not LIVE_BINARY.exists():
        sys.exit(f"Error: tcbee-live binary not found.\nBuild: cd tcbee-live && cargo build --release")
    if tool in ("record", "full") and not RECORD_BINARY.exists():
        sys.exit(f"Error: tcbee-record binary not found.\nBuild: cd tcbee-record && cargo build --release")
    if tool == "full" and not PROCESS_BINARY.exists():
        sys.exit(f"Error: tcbee-process binary not found.\nBuild: cargo build --release -p tcbee-process (in the repository root)")
    if tool == "full" and not VIZ_BINARY.exists():
        sys.exit(f"Error: tcbee-viz binary not found.\nBuild: cargo build --release -p tcbee-viz (in the repository root)")

    display = os.environ.get("DISPLAY", ":0")

    topo = TwoPathTopo() if mptcp else BottleneckTopo()
    net  = Mininet(topo=topo, link=TCLink, switch=OVSKernelSwitch)
    net.start()

    tcbee = net.get("tcbee")
    recv  = net.get("recv")

    # Set congestion control on both hosts.
    for host in (tcbee, recv):
        host.cmd(f"sysctl -w net.ipv4.tcp_congestion_control={cc}")
    info(f"*** Congestion control set to {cc}\n")

    if mptcp:
        setup_mptcp(tcbee, recv)
    else:
        # Start iperf3 server(s) on recv.
        recv.cmd(f"nohup iperf3 -s -p {PORT1} > /dev/null 2>&1 &")
        if double:
            recv.cmd(f"nohup iperf3 -s -p {PORT2} > /dev/null 2>&1 &")
        info(f"*** iperf3 server(s) started on recv\n")

    # Launch the selected tool.
    if tool == "live":
        select_arg = (
            f"--select-port {PORT1} --select-port {PORT2} --combined-plot --auto-fit-x"
            if double else
            f"--select-port {PORT1}"
        )
        info(f"*** Launching tcbee-live ({select_arg}, logs → /tmp/tcbee-live.log)\n")
        tcbee.cmd(
            f"RUST_LOG=info DISPLAY={display} {LIVE_BINARY} {select_arg}"
            f" > /tmp/tcbee-live.log 2>&1 &"
        )
    if not mptcp:
        # The MPTCP connection opens once the recorder runs (run_mptcp_steps)
        info("*** Waiting for tool to initialise...\n")
        time.sleep(2.0)

        # First bulk transfer.
        info(f"*** Stream 1: tcbee:{PORT1} → recv:{PORT1}\n")
        tcbee.cmd(
            f"nohup iperf3 -c {recv.IP()} -p {PORT1} -t 3600"
            f" > /tmp/iperf3_1.log 2>&1 &"
        )

        if double:
            def _start_stream2():
                time.sleep(30)
                info(f"*** Stream 2: tcbee:{PORT2} → recv:{PORT2} (starting now)\n")
                tcbee.cmd(
                    f"nohup iperf3 -c {recv.IP()} -p {PORT2} -t 3600"
                    f" > /tmp/iperf3_2.log 2>&1 &"
                )
            threading.Thread(target=_start_stream2, daemon=True).start()

    binary = LIVE_BINARY if tool == "live" else RECORD_BINARY
    log    = "/tmp/tcbee-live.log" if tool == "live" else "/tmp/tcbee-record.log"
    info("\n")
    scenario = ("  (MPTCP over two paths)" if mptcp else
                "  (two streams, second starts in 30 s)" if double else "")
    info(f"=== Tool: {tool}  |  CC: {cc}{scenario} ===\n")
    info(f"    Binary: {binary}\n")
    info(f"    Logs:   tail -f {log}\n")

    if tool == "live":
        info("    Type 'exit' or Ctrl-D to stop.\n\n")
        CLI(net)
    else:
        # tcbee-record is a TUI — run it in the foreground of this terminal so
        # it gets the real PTY it needs.  No second terminal required.
        if mptcp:
            test_ports = str(MPTCP_PORT)
            test_hosts = f"{TCBEE_IP},{RECV_IP},{TCBEE_IP2},{RECV_IP2}"
            # Path manager events and the connection of every subflow record
            if not any(arg in ("-m", "-M", "--mptcp") for arg in shlex.split(record_args)):
                record_args = f"{record_args} -m"
        else:
            test_ports = f"{PORT1},{PORT2}" if double else str(PORT1)
            test_hosts = f"{TCBEE_IP},{RECV_IP}"
        test_filter_args = (
            f"--ports {test_ports} "
            f"--src-ips {test_hosts} "
            f"--dst-ips {test_hosts}"
        )
        full_args = shlex.split(" ".join(filter(None, [record_args, test_filter_args])))
        if headless:
            # No terminal UI; the recorder stops by itself
            full_args += ["-q", "--duration", str(duration or headless_seconds(double, mptcp))]
        cmd = [str(RECORD_BINARY)] + full_args
        uses_headers = any(arg == "-h" or arg == "--headers" or arg.startswith("--headers=")
                           for arg in full_args)
        run_cmd = ["nsenter", f"--net=/proc/{tcbee.pid}/ns/net"] + cmd if uses_headers else cmd
        info(f"    Running: {' '.join(run_cmd)}\n")
        if headless:
            info(f"    Recording for {full_args[-1]} s without the terminal UI.\n")
            info("    The launcher will then process /tmp/db.duck and open tcbee-viz.\n\n")
        elif tool == "full":
            info("    Quit tcbee-record with q when the capture is complete.\n")
            info("    The launcher will then process /tmp/db.duck and open tcbee-viz.\n\n")
        else:
            info("    Quit tcbee-record (q / Ctrl-C) to stop the topology.\n\n")
        stop = threading.Event()
        if mptcp:
            # The terminal belongs to the recorder's UI unless headless: log the steps to a file
            open(MPTCP_LOG, "w").close()

            def say(line):
                with open(MPTCP_LOG, "a") as f:
                    f.write(f"{time.strftime('%H:%M:%S')}  {line}\n")
                if headless:
                    info(f"*** {line}\n")

            info(f"    MPTCP steps (logged to {MPTCP_LOG}), from the connection's start:\n")
            for at, what, _ in MPTCP_STEPS:
                info(f"      t={at:>2} s  {what}\n")
            info(f"      t={MPTCP_SECONDS} s  transfer ends\n\n")
            steps = threading.Thread(target=run_mptcp_steps, args=(tcbee, recv, say, stop),
                                     daemon=True)
            steps.start()
        try:
            subprocess.run(run_cmd)
        except KeyboardInterrupt:
            pass
        stop.set()
        if mptcp:
            # A step may be running a command in a host
            steps.join()

        if tool == "full":
            info("*** Stopping topology before processing trace data...\n")
            net.stop()

            # -f replaces the database of an earlier run
            process_cmd = [str(PROCESS_BINARY), "--duckdb", "-o", DUCKDB_PATH, "--force"]
            info(f"*** Processing latest recording: {' '.join(process_cmd)}\n")
            result = subprocess.run(process_cmd)
            if result.returncode != 0:
                sys.exit(f"Error: tcbee-process failed with exit code {result.returncode}")

            viz_cmd = [str(VIZ_BINARY), DUCKDB_PATH]
            info(f"*** Launching tcbee-viz: {' '.join(viz_cmd)}\n")
            subprocess.run(viz_cmd)
            return

    net.stop()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Error: must be run as root — use run.py or one of the run_*.sh scripts")

    parser = argparse.ArgumentParser(description="TCBee bottleneck topology")
    parser.add_argument("--cc", choices=["cubic", "bbr"], default="cubic")
    scenario = parser.add_mutually_exclusive_group()
    scenario.add_argument("--double", action="store_true",
                          help="Start a second stream 30 s after the first")
    scenario.add_argument("--mptcp", action="store_true",
                          help="One MPTCP connection over two paths (needs --tool record "
                               "or full)")
    parser.add_argument("--tool", choices=["live", "record", "full"], default="live")
    parser.add_argument("--record-args", default="",
                        help="Extra flags forwarded verbatim to tcbee-record")
    parser.add_argument("--headless", action="store_true",
                        help="With --tool full: record without the terminal UI, stop after "
                             "--duration seconds, then process and open tcbee-viz")
    parser.add_argument("--duration", type=int,
                        help="Seconds a headless run records (default: 30, 60 with "
                             "--double, 48 with --mptcp)")
    args = parser.parse_args()
    if args.headless and args.tool != "full":
        parser.error("--headless needs --tool full")

    run(cc=args.cc, double=args.double, tool=args.tool, record_args=args.record_args,
        headless=args.headless, duration=args.duration, mptcp=args.mptcp)
