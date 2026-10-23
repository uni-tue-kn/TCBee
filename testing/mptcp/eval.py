#!/usr/bin/env python3
"""Repeated MPTCP namespace runs of tcbee-record with independent oracles (needs root).

    eval.py SCENARIO --reps N --out DIR [--sigstop] [--seconds S] [--pm-ring SIZE]

Each repetition builds fresh client and server namespaces joined by two veth pairs (paths
10.31.1.0/24 and 10.31.2.0/24), records with -k -w -M, and keeps everything in
DIR/SCENARIO-repNN/:
  trace/tcbee_*/      the recording (metrics.json included)
  record.log          tcbee-record output
  app-*.jsonl         the applications' view of each connection (traffic.py --log)
  monitor-*.txt       `ip -ts mptcp monitor` per namespace, stderr in monitor-*.err
  netstat-*-{pre,post}.txt   /proc/net/netstat of each namespace before and after
  truth.json          bpftrace counts of the path manager hooks, with TCBee's filter
  progs.json          bpf_stats of TCBee's and bpftrace's programs
  ss-client.txt       `ss -tni` samples every 100 ms (scenario e6)
  actions.json        operator actions with CLOCK_MONOTONIC ns (the clock of the records)
  run.json            scenario, parameters, binaries and their sha256, timestamps
  db.sqlite           the recording processed by tcbee-process
  verify.json         result of verify.py

Scenarios:
  static    one MPTCP connection (2 subflows) and one TCP connection, 5 s       (E1 a)
  churn     50 MPTCP and 50 TCP connections over 5 s, each held 1-3 s,
            paths with 5 and 15 ms delay                                        (E1 c, E3)
  dynamic   one MPTCP connection; mid-connection: client subflow endpoint added,
            server signal endpoint (ADD_ADDR), backup toggle, join to an
            unreachable announced address, both endpoints deleted              (E2, E3)
  e6        one bulk connection over 10/40 ms paths at 1 Gb/s each; t=5 s path 2
            blackholed, t=10 s its endpoint deleted, t=13 s restored and re-added (E6)
  fallback  10 MPTCP connections whose SYNs lose the MPTCP option at the server's
            ingress (nft), plus one TCP connection                             (E8)
  stale     as e6 without the operator: path 2 blackholed from t=5 s to t=11 s, so its
            subflow is marked stale (and recovers, which TCBee does not record)

--sigstop stops tcbee-record (SIGSTOP) while the traffic runs and continues it afterwards; with
a small --pm-ring this forces drops on the path manager ring (E3, D > 0).
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CLIENT, SERVER = "tcbee-mp-c", "tcbee-mp-s"
MPTCP_PORT, TCP_PORT = 5501, 5502
SERVER_ADDR = "10.31.1.2"
# Announced by the server in the dynamic scenario: configured on its loopback, no route from the
# client, so the client's join fails at once with an error
UNREACHABLE = "10.31.9.2"

PM_HOOKS = ["mptcp_event", "mptcp_event_addr_announced", "mptcp_event_addr_removed",
            "mptcp_token_destroy", "__mptcp_subflow_connect", "mptcp_pm_mp_fail_received"]


def sh(*cmd, check=True, **kw):
    return subprocess.run([str(c) for c in cmd], check=check, text=True,
                          capture_output=True, **kw)


def ns(name, *cmd, check=True):
    return sh("ip", "netns", "exec", name, *cmd, check=check)


def now_ns() -> int:
    return time.monotonic_ns()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Rep:
    def __init__(self, args, rep_dir: Path):
        self.args = args
        self.dir = rep_dir
        self.procs: list[subprocess.Popen] = []
        self.actions: list[dict] = []

    # ---- namespaces --------------------------------------------------------------------
    def teardown(self):
        for p in reversed(self.procs):
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
        for p in reversed(self.procs):
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        for n in (CLIENT, SERVER):
            pids = sh("ip", "netns", "pids", n, check=False).stdout.split()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
            sh("ip", "netns", "del", n, check=False)

    def setup(self, delays=(0, 0), rate=None):
        self.teardown()
        sh("ip", "netns", "add", CLIENT)
        sh("ip", "netns", "add", SERVER)
        for path in (1, 2):
            sh("ip", "link", "add", f"c{path}", "netns", CLIENT, "type", "veth",
               "peer", "name", f"s{path}", "netns", SERVER)
            ns(CLIENT, "ip", "addr", "add", f"10.31.{path}.1/24", "dev", f"c{path}")
            ns(SERVER, "ip", "addr", "add", f"10.31.{path}.2/24", "dev", f"s{path}")
            ns(CLIENT, "ip", "link", "set", f"c{path}", "up")
            ns(SERVER, "ip", "link", "set", f"s{path}", "up")
            delay = delays[path - 1]
            if delay or rate:
                # One-way delay on both ends gives an RTT of 2 x delay
                for name, dev in ((CLIENT, f"c{path}"), (SERVER, f"s{path}")):
                    q = ["netem", "limit", str(netem_limit(delay, rate))]
                    if delay:
                        q += ["delay", f"{delay}ms"]
                    if rate:
                        q += ["rate", rate]
                    ns(name, "tc", "qdisc", "add", "dev", dev, "root", "handle", "1:", *q)
        for n in (CLIENT, SERVER):
            ns(n, "ip", "link", "set", "lo", "up")
            ns(n, "sysctl", "-q", "net.mptcp.enabled=1")
            ns(n, "ip", "mptcp", "limits", "set", "subflow", "4", "add_addr_accepted", "4")
        # Subflows from 10.31.2.1 reach the server address of path 1 over path 2
        ns(CLIENT, "ip", "rule", "add", "from", "10.31.2.1", "table", "102")
        ns(CLIENT, "ip", "route", "add", "10.31.1.0/24", "dev", "c2", "table", "102")
        assert "10.31.1.1" in ns(CLIENT, "ip", "-4", "addr").stdout

    def act(self, what: str, fn):
        t = now_ns()
        fn()
        self.actions.append({"t_ns": t, "what": what})

    # ---- oracles and recorder -----------------------------------------------------------
    def netstat(self, tag: str):
        for side, n in (("client", CLIENT), ("server", SERVER)):
            (self.dir / f"netstat-{side}-{tag}.txt").write_text(
                ns(n, "cat", "/proc/net/netstat").stdout)

    def bg(self, name: str, cmd: list, netns: str | None = None) -> subprocess.Popen:
        if netns:
            cmd = ["ip", "netns", "exec", netns, *cmd]
        p = subprocess.Popen([str(c) for c in cmd], stdout=open(self.dir / f"{name}.txt", "w"),
                             stderr=open(self.dir / f"{name}.err", "w"))
        self.procs.append(p)
        return p

    def start_monitors(self):
        for side, n in (("client", CLIENT), ("server", SERVER)):
            self.bg(f"monitor-{side}", ["ip", "-ts", "mptcp", "monitor"], n)

    def start_truth(self) -> subprocess.Popen:
        script = self.dir / "truth.bt"
        script.write_text(truth_script([MPTCP_PORT, TCP_PORT]))
        p = self.bg("truth", ["bpftrace", "-f", "json", script])
        self.truth = p
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if p.poll() is not None:
                sys.exit(f"bpftrace exited: {(self.dir / 'truth.err').read_text()[-2000:]}")
            if '"attached_probes"' in (self.dir / "truth.txt").read_text(errors="replace"):
                return p
            time.sleep(0.2)
        sys.exit("bpftrace did not attach")

    def start_record(self, seconds: float):
        out = self.dir / "trace"
        out.mkdir()
        # verify.py reads the per-packet sock files
        cmd = [self.args.record, "-q", "--metrics", "-k", "--sock-hooks", "+egress,+ingress-entry",
               "-w", "-m", "--ports", f"{MPTCP_PORT},{TCP_PORT}", "--poll", "wait", "-d", f"{out}/",
               "--duration", f"{seconds:.0f}"]
        if self.args.pm_ring:
            cmd += ["--ringbuf-size", f"mptcp_pm={self.args.pm_ring}"]
        self.record = self.bg("record", cmd)
        self.record_cmd = cmd
        wait_attached(self.record.pid, self.dir)

    def start_servers(self):
        for port, proto in ((MPTCP_PORT, "mptcp"), (TCP_PORT, "tcp")):
            self.bg(f"server-{proto}", ["python3", HERE / "traffic.py", "serve", port, proto,
                                        "--log", self.dir / "app-server.jsonl"], SERVER)
        time.sleep(0.5)

    def send(self, proto: str, seconds: float, *extra, wait=True, addr=SERVER_ADDR):
        port = MPTCP_PORT if proto == "mptcp" else TCP_PORT
        cmd = ["ip", "netns", "exec", CLIENT, "python3", HERE / "traffic.py", "send", addr,
               port, proto, seconds, "--log", self.dir / "app-client.jsonl", *extra]
        p = subprocess.Popen([str(c) for c in cmd],
                             stderr=open(self.dir / f"send-{proto}.err", "a"))
        if wait:
            p.wait()
        return p

    def ss_sampler(self, seconds: float):
        """ss -tni in the client namespace every 100 ms, each sample headed by its
        CLOCK_MONOTONIC time"""
        code = (
            "import subprocess,sys,time\n"
            "end=time.monotonic()+float(sys.argv[1])\n"
            "while time.monotonic()<end:\n"
            "  t=time.monotonic_ns()\n"
            "  o=subprocess.run(['ss','-tniH','sport = :5501 or dport = :5501'],"
            "capture_output=True,text=True).stdout\n"
            "  print(f'@ {t}',flush=True); print(o,flush=True)\n"
            "  time.sleep(max(0,0.1-(time.monotonic_ns()-t)/1e9))\n"
        )
        return self.bg("ss-client", ["python3", "-c", code, seconds], CLIENT)

    # ---- scenarios ------------------------------------------------------------------------
    def traffic(self, scenario: str):
        a = self.args
        if scenario == "static":
            ns(CLIENT, "ip", "mptcp", "endpoint", "add", "10.31.2.1", "dev", "c2", "subflow")
            p = self.send("mptcp", a.seconds or 5, wait=False)
            self.send("tcp", a.seconds or 5)
            p.wait()
        elif scenario == "churn":
            ns(CLIENT, "ip", "mptcp", "endpoint", "add", "10.31.2.1", "dev", "c2", "subflow")
            hold = ["--conns", "50", "--spread", "5", "--hold-min", "1"]
            p = self.send("mptcp", 3, *hold, wait=False)
            self.send("tcp", 3, *hold)
            p.wait()
        elif scenario == "dynamic":
            self.dynamic()
        elif scenario == "e6":
            self.e6()
        elif scenario == "stale":
            self.e6(operator=False)
        elif scenario == "fallback":
            ns(CLIENT, "ip", "mptcp", "endpoint", "add", "10.31.2.1", "dev", "c2", "subflow")
            # nft 1.0.9 rejects this on one line
            nft = ("table netdev tcbee_fb {\n chain in {\n"
                   "  type filter hook ingress device \"s1\" priority 0;\n"
                   "  tcp dport 5501 tcp flags & (syn | ack) == syn reset tcp option mptcp\n"
                   " }\n}")
            (self.dir / "nft.txt").write_text(nft + "\n")
            ns(SERVER, "nft", "-f", self.dir / "nft.txt")
            p = self.send("mptcp", 2, "--conns", "10", "--spread", "2", wait=False)
            self.send("tcp", 2)
            p.wait()
            (self.dir / "nft-after.txt").write_text(ns(SERVER, "nft", "list", "ruleset").stdout)

    def dynamic(self):
        steps = [
            (2, "client adds subflow endpoint 10.31.2.1",
             lambda: ns(CLIENT, "ip", "mptcp", "endpoint", "add", "10.31.2.1", "dev", "c2",
                        "id", "1", "subflow")),
            (4, "server adds signal endpoint 10.31.2.2",
             lambda: ns(SERVER, "ip", "mptcp", "endpoint", "add", "10.31.2.2", "dev", "s2",
                        "id", "2", "signal")),
            (6, "client marks endpoint 1 backup",
             lambda: ns(CLIENT, "ip", "mptcp", "endpoint", "change", "id", "1", "backup")),
            (7, f"server announces unreachable {UNREACHABLE}",
             lambda: ns(SERVER, "ip", "mptcp", "endpoint", "add", UNREACHABLE, "dev", "lo",
                        "id", "3", "signal")),
            (9, "client deletes endpoint 1",
             lambda: ns(CLIENT, "ip", "mptcp", "endpoint", "delete", "id", "1")),
            (10, "server deletes endpoint 2",
             lambda: ns(SERVER, "ip", "mptcp", "endpoint", "delete", "id", "2")),
        ]
        ns(SERVER, "ip", "addr", "add", f"{UNREACHABLE}/32", "dev", "lo")
        t0 = time.monotonic()
        p = self.send("mptcp", 12, wait=False)
        self.actions.append({"t_ns": now_ns(), "what": "client connects"})
        for at, what, fn in steps:
            time.sleep(max(0, t0 + at - time.monotonic()))
            self.act(what, fn)
        p.wait()

    def e6(self, operator: bool = True):
        ns(CLIENT, "ip", "mptcp", "endpoint", "add", "10.31.2.1", "dev", "c2", "id", "1",
           "subflow")
        t0 = time.monotonic()
        sampler = self.ss_sampler(21)
        p = self.send("mptcp", 20, "--bulk", wait=False)
        self.actions.append({"t_ns": now_ns(), "what": "client connects"})

        def loss(pct):
            for name, dev in ((CLIENT, "c2"), (SERVER, "s2")):
                ns(name, "tc", "qdisc", "change", "dev", dev, "root", "handle", "1:", "netem",
                   "limit", str(netem_limit(40, "1gbit")), "delay", "40ms", "rate", "1gbit",
                   "loss", f"{pct}%")

        steps = [
            (5, "path 2 blackholed (both directions)", lambda: loss(100)),
            (10, "operator deletes endpoint 1 (path 2)",
             lambda: ns(CLIENT, "ip", "mptcp", "endpoint", "delete", "id", "1")),
            (13, "path 2 restored", lambda: loss(0)),
            (13, "operator re-adds endpoint 10.31.2.1",
             lambda: ns(CLIENT, "ip", "mptcp", "endpoint", "add", "10.31.2.1", "dev", "c2",
                        "id", "1", "subflow")),
        ]
        if not operator:
            steps = [(5, "path 2 blackholed (both directions)", lambda: loss(100)),
                     (11, "path 2 restored", lambda: loss(0))]
        for at, what, fn in steps:
            time.sleep(max(0, t0 + at - time.monotonic()))
            self.act(what, fn)
        p.wait()
        sampler.wait()

    # ---- one repetition -------------------------------------------------------------------
    def run(self, scenario: str):
        a = self.args
        self.dir.mkdir(parents=True)
        delays, rate = (0, 0), None
        if scenario == "churn":
            delays = (5, 15)
        elif scenario in ("e6", "stale"):
            delays, rate = (10, 40), "1gbit"
        info = {
            "scenario": scenario, "args": vars(a), "start": time.time(),
            "record": a.record, "record_sha256": sha256(Path(a.record)),
            "process": a.process, "process_sha256": sha256(Path(a.process)),
            "git": sh("git", "-C", ROOT, "describe", "--always", "--dirty", check=False).stdout.strip(),
            "kernel": os.uname().release, "delays_ms": delays, "rate": rate,
            "bpf_stats_enabled": Path("/proc/sys/kernel/bpf_stats_enabled").read_text().strip(),
        }
        try:
            self.setup(delays, rate)
            self.start_monitors()
            truth = self.start_truth() if not a.no_truth else None
            self.netstat("pre")
            duration = {"static": 5, "churn": 8, "dynamic": 12, "e6": 20, "stale": 20,
                        "fallback": 4}[scenario]
            # A safety net only: the recorder is stopped with SIGINT once the connections are
            # closed and the program statistics are read
            duration = (a.seconds or duration) + 30
            self.start_record(duration)
            info["record_cmd"] = self.record_cmd
            self.start_servers()
            if a.sigstop:
                self.record.send_signal(signal.SIGSTOP)
                self.actions.append({"t_ns": now_ns(), "what": "SIGSTOP tcbee-record"})
            self.actions.append({"t_ns": now_ns(), "what": "traffic starts"})
            self.traffic(scenario)
            self.actions.append({"t_ns": now_ns(), "what": "traffic ends"})
            if a.sigstop:
                self.record.send_signal(signal.SIGCONT)
                self.actions.append({"t_ns": now_ns(), "what": "SIGCONT tcbee-record"})
            # Connections close after the traffic: give TOKEN_DESTROYED and the last subflow
            # records time to arrive before the stop
            time.sleep(2)
            self.netstat("post")
            progs = {"tcbee": prog_stats(self.record.pid)}
            if truth:
                progs["truth"] = prog_stats(truth.pid)
            (self.dir / "progs.json").write_text(json.dumps(progs, indent=1))
            # The recorder stops first (SIGINT, as at the end of --duration), then the truth
            # counter, so that no event reaches the truth counter alone
            self.record.send_signal(signal.SIGINT)
            self.record.wait(timeout=60)
            info["record_rc"] = self.record.returncode
            if truth:
                truth.send_signal(signal.SIGINT)
                truth.wait(timeout=30)
        finally:
            info["end"] = time.time()
            (self.dir / "actions.json").write_text(json.dumps(self.actions, indent=1))
            (self.dir / "run.json").write_text(json.dumps(info, indent=1))
            self.teardown()
        trace = next((self.dir / "trace").glob("tcbee_*"))
        r = sh(a.process, "-s", trace, "-o", self.dir / "db.sqlite", "-f", check=False)
        (self.dir / "process.log").write_text(r.stdout + r.stderr)
        v = sh(sys.executable, HERE / "verify.py", self.dir, check=False)
        (self.dir / "verify.log").write_text(v.stdout + v.stderr)
        return v.returncode


def netem_limit(delay_ms: float, rate: str | None) -> int:
    """Queue of a path in packets: twice its bandwidth-delay product with a rate (netem's limit
    covers the delay line too), so that the rate limit does not add seconds of queueing;
    without a rate no queue builds up"""
    if not rate:
        return 100000
    bps = float(rate.rstrip("gbit")) * 1e9 if rate.endswith("gbit") else float(rate.rstrip("mbit")) * 1e6
    return max(1000, int(2 * bps * 2 * delay_ms / 1000 / (1500 * 8)))


def wait_attached(pid: int, rep_dir: Path, timeout=60):
    """Ready = the number of bpf-map and bpf_link fds unchanged for 2 s after at least one
    ring per CPU exists (as evalkit/tracers.py)"""
    ncpu = os.cpu_count() or 1
    deadline = time.monotonic() + timeout
    last, since = None, time.monotonic()
    while time.monotonic() < deadline:
        kinds = {"anon_inode:bpf-map": 0, "anon_inode:bpf_link": 0}
        try:
            for fd in Path(f"/proc/{pid}/fd").iterdir():
                try:
                    k = os.readlink(fd)
                except OSError:
                    continue
                if k in kinds:
                    kinds[k] += 1
        except FileNotFoundError:
            sys.exit(f"tcbee-record exited: {(rep_dir / 'record.err').read_text()[-2000:]}")
        cur = tuple(kinds.values())
        if cur != last or cur[0] <= ncpu or cur[1] == 0:
            last, since = cur, time.monotonic()
        elif time.monotonic() - since >= 2:
            return
        time.sleep(0.25)
    sys.exit("tcbee-record did not finish attaching")


def prog_stats(pid: int) -> list:
    """bpftool prog show for the programs pid holds (run_cnt/run_time_ns need
    kernel.bpf_stats_enabled=1)"""
    ids = set()
    for f in Path(f"/proc/{pid}/fdinfo").iterdir():
        try:
            for line in f.read_text().splitlines():
                if line.startswith("prog_id:"):
                    ids.add(int(line.split()[1]))
        except OSError:
            pass
    progs = json.loads(sh("bpftool", "-j", "prog", "show").stdout or "[]")
    return [p for p in progs if p.get("id") in ids]


# bpftrace counters on TCBee's path manager hooks, with TCBee's conditions: the socket is the
# subflow if the hook has one, else the connection; COND is TCBee's filter on $sk (cond()).
# Hooks with an entry and an exit program count only what TCBee records: a new stale
# transition, a retransmission that resent bytes (+1: a map value of 0 means unset), the SYN-ACK
# of a subflow that requested MPTCP and fell back.
TRUTH_SCRIPT = """// truth for tcbee -m pm: same hooks, separate programs, count() only
fentry:vmlinux:mptcp_event {
  $sk = (struct sock *)args.msk;
  if (args.ssk != 0) { $sk = (struct sock *)args.ssk; }
  if ($sk == 0) { return; }
  COND { @ev[args.type] = count(); }
}
fentry:vmlinux:mptcp_event_addr_announced {
  $sk = (struct sock *)args.ssk;
  COND { @announced = count(); }
}
fentry:vmlinux:mptcp_event_addr_removed {
  $sk = (struct sock *)args.msk;
  COND { @removed = count(); }
}
fentry:vmlinux:mptcp_token_destroy {
  if (args.msk->token == 0) { return; }
  $sk = (struct sock *)args.msk;
  COND { @token_destroyed = count(); }
}
fexit:vmlinux:__mptcp_subflow_connect {
  $sk = (struct sock *)args.sk;
  COND { @subflow_connect = count(); }
}
fentry:vmlinux:mptcp_pm_mp_fail_received {
  $sk = (struct sock *)args.sk;
  COND { @mp_fail = count(); }
}
fexit:vmlinux:mptcp_pm_nl_mp_prio_send_ack {
  $sk = (struct sock *)args.msk;
  COND { @prio_sent = count(); }
}
fentry:vmlinux:mptcp_pm_nl_subflow_chk_stale {
  $sf = (struct mptcp_subflow_context *)((struct inet_connection_sock *)args.ssk)->icsk_ulp_data;
  if ($sf != 0 && $sf->stale == 0) { @stalecheck[args.ssk] = 1; }
}
fexit:vmlinux:mptcp_pm_nl_subflow_chk_stale {
  if (@stalecheck[args.ssk] == 1) {
    delete(@stalecheck[args.ssk]);
    $sf = (struct mptcp_subflow_context *)((struct inet_connection_sock *)args.ssk)->icsk_ulp_data;
    $sk = (struct sock *)args.ssk;
    if ($sf->stale) { COND { @stale = count(); } }
  }
}
fentry:vmlinux:__mptcp_retrans {
  @rtxstart[args.sk] = ((struct mptcp_sock *)args.sk)->bytes_retrans + 1;
}
fexit:vmlinux:__mptcp_retrans {
  $start = @rtxstart[args.sk];
  if ($start != 0) {
    delete(@rtxstart[args.sk]);
    $sk = (struct sock *)args.sk;
    if (((struct mptcp_sock *)args.sk)->bytes_retrans + 1 > $start) { COND { @reinjected = count(); } }
  }
}
fexit:vmlinux:__mptcp_retransmit_pending_data {
  $sk = (struct sock *)args.sk;
  if (retval) { COND { @requeued = count(); } }
}
fentry:vmlinux:subflow_finish_connect {
  $sf = (struct mptcp_subflow_context *)((struct inet_connection_sock *)args.sk)->icsk_ulp_data;
  if ($sf != 0 && $sf->request_mptcp && !$sf->conn_finished) { @connectcheck[args.sk] = 1; }
}
fexit:vmlinux:subflow_finish_connect {
  if (@connectcheck[args.sk] == 1) {
    delete(@connectcheck[args.sk]);
    $sf = (struct mptcp_subflow_context *)((struct inet_connection_sock *)args.sk)->icsk_ulp_data;
    $sk = (struct sock *)args.sk;
    if (!$sf->mp_capable) { COND { @fallback = count(); } }
  }
}
"""


def truth_script(ports: list[int]) -> str:
    """TRUTH_SCRIPT with TCBee's port filter: no record for a socket without ports, sport or
    dport in the port list (tcbee.bpf.c trace_mptcp_pm)"""
    # skc_dport is in network order: compare with the byte-swapped port
    ports_c = " || ".join(f"$sp == {p} || $dp == {((p & 0xFF) << 8) | (p >> 8)}" for p in ports)
    cond = ("$sp = (uint16)$sk->__sk_common.skc_num; $dp = (uint16)$sk->__sk_common.skc_dport;\n"
            f"  if (($sp != 0 || $dp != 0) && ({ports_c}))")
    return TRUTH_SCRIPT.replace("COND", cond)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("scenario", choices=["static", "churn", "dynamic", "e6", "stale", "fallback"])
    p.add_argument("--reps", type=int, default=1)
    p.add_argument("--first", type=int, default=0, help="number of the first repetition")
    p.add_argument("--out", required=True)
    p.add_argument("--seconds", type=float)
    p.add_argument("--sigstop", action="store_true")
    p.add_argument("--pm-ring", help="per-CPU size of the mptcp_pm ring, e.g. 4K")
    p.add_argument("--no-truth", action="store_true")
    p.add_argument("--record", default=str(ROOT / "install" / "tcbee-record"))
    # tcbee-process with "Keep plain TCP sockets out of the connection of their reversed tuple"
    # (194661a), frozen for the campaign
    p.add_argument("--process", default=str(ROOT.parent / "mptcp-eval" / "bin" / "tcbee-process-194661a"))
    a = p.parse_args()
    if os.geteuid():
        sys.exit("needs root")
    if shutil.which("bpftrace") is None and not a.no_truth:
        sys.exit("bpftrace not found")
    out = Path(a.out)
    failed = 0
    # bpf_stats for the ns per run of the path manager programs; the previous value comes back
    stats = Path("/proc/sys/kernel/bpf_stats_enabled")
    stats_before = stats.read_text().strip()
    stats.write_text("1\n")
    try:
        failed = run_reps(a, out)
    finally:
        stats.write_text(stats_before + "\n")
    return 1 if failed else 0


def run_reps(a, out: Path) -> int:
    failed = 0
    for i in range(a.first, a.first + a.reps):
        rep_dir = out / f"{a.scenario}-rep{i:02d}"
        if rep_dir.exists():
            sys.exit(f"{rep_dir} exists, results are never overwritten")
        rc = Rep(a, rep_dir).run(a.scenario)
        print(f"{rep_dir.name}: {['ok', 'FAIL', 'INVALID'][min(rc, 2)]}", flush=True)
        (rep_dir / "DONE").write_text(f"{rc}\n")
        # Hand the results to the user who ran sudo
        if os.environ.get("SUDO_UID"):
            sh("chown", "-R", f"{os.environ['SUDO_UID']}:{os.environ['SUDO_GID']}", out)
        failed += rc != 0
    return failed


if __name__ == "__main__":
    sys.exit(main())
