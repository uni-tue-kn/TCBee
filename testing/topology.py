#!/usr/bin/env python3
"""
Bottleneck topology for tcbee-live cwnd testing.

    TCBeeHost --100M-- s1 --10M(bottleneck)-- s2 --100M-- ReceivingHost

Usage via the run scripts in this directory:
    ./testing/run_cubic_single.sh
    ./testing/run_cubic_double.sh
    ./testing/run_bbr_single.sh
    ./testing/run_bbr_double.sh

Or directly:
    sudo -E python3 testing/topology.py [--cc cubic|bbr] [--double]
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
_PROCESS_BASE = Path(__file__).parent.parent / "tcbee-process" / "target"
_VIZ_BASE     = Path(__file__).parent.parent / "tcbee-viz" / "target"

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

DUCKDB_PATH = "/tmp/db.duck"


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


def run(cc: str, double: bool, tool: str = "live", record_args: str = ""):
    setLogLevel("info")

    if tool == "live" and not LIVE_BINARY.exists():
        sys.exit(f"Error: tcbee-live binary not found.\nBuild: cd tcbee-live && cargo build --release")
    if tool in ("record", "full") and not RECORD_BINARY.exists():
        sys.exit(f"Error: tcbee-record binary not found.\nBuild: cd tcbee-record && cargo build --release")
    if tool == "full" and not PROCESS_BINARY.exists():
        sys.exit(f"Error: tcbee-process binary not found.\nBuild: cd tcbee-process && cargo build --release")
    if tool == "full" and not VIZ_BINARY.exists():
        sys.exit(f"Error: tcbee-viz binary not found.\nBuild: cd tcbee-viz && cargo build --release")

    display = os.environ.get("DISPLAY", ":0")

    topo = BottleneckTopo()
    net  = Mininet(topo=topo, link=TCLink, switch=OVSKernelSwitch)
    net.start()

    tcbee = net.get("tcbee")
    recv  = net.get("recv")

    # Set congestion control on both hosts.
    for host in (tcbee, recv):
        host.cmd(f"sysctl -w net.ipv4.tcp_congestion_control={cc}")
    info(f"*** Congestion control set to {cc}\n")

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
    info(f"=== Tool: {tool}  |  CC: {cc}"
         f"{'  (two streams, second starts in 30 s)' if double else ''} ===\n")
    info(f"    Binary: {binary}\n")
    info(f"    Logs:   tail -f {log}\n")

    if tool == "live":
        info("    Type 'exit' or Ctrl-D to stop.\n\n")
        CLI(net)
    else:
        # tcbee-record is a TUI — run it in the foreground of this terminal so
        # it gets the real PTY it needs.  No second terminal required.
        test_ports = f"{PORT1},{PORT2}" if double else str(PORT1)
        test_hosts = f"{TCBEE_IP},{RECV_IP}"
        test_filter_args = (
            f"--ports {test_ports} "
            f"--src-ips {test_hosts} "
            f"--dst-ips {test_hosts}"
        )
        full_args = shlex.split(" ".join(filter(None, [record_args, test_filter_args])))
        cmd = [str(RECORD_BINARY)] + full_args
        uses_headers = any(arg == "-h" or arg == "--headers" or arg.startswith("--headers=")
                           for arg in full_args)
        run_cmd = ["nsenter", f"--net=/proc/{tcbee.pid}/ns/net"] + cmd if uses_headers else cmd
        info(f"    Running: {' '.join(run_cmd)}\n")
        if tool == "full":
            info("    Quit tcbee-record with q when the capture is complete.\n")
            info("    The launcher will then process /tmp/db.duck and open tcbee-viz.\n\n")
        else:
            info("    Quit tcbee-record (q / Ctrl-C) to stop the topology.\n\n")
        try:
            subprocess.run(run_cmd)
        except KeyboardInterrupt:
            pass

        if tool == "full":
            info("*** Stopping topology before processing trace data...\n")
            net.stop()

            duckdb = Path(DUCKDB_PATH)
            duckdb.unlink(missing_ok=True)

            process_cmd = [str(PROCESS_BINARY), "--duckdb"]
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
    parser.add_argument("--double", action="store_true",
                        help="Start a second stream 30 s after the first")
    parser.add_argument("--tool", choices=["live", "record", "full"], default="live")
    parser.add_argument("--record-args", default="",
                        help="Extra flags forwarded verbatim to tcbee-record")
    args = parser.parse_args()

    run(cc=args.cc, double=args.double, tool=args.tool, record_args=args.record_args)
