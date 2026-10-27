#!/usr/bin/env bash
# Smoke test of the on-change mode on loopback (root: loads the eBPF programs).
#
#   sudo testing/onchange_smoke.sh [TCBEE_RECORD]
#
# Records iperf3 on lo with -k -w and checks:
#   1. default mode: the usual file names, no manifest, no on-change program loaded,
#      no suppressed runs;
#   2. --on-change cc with the default hooks (ingress, timer) and with all hooks: the files
#      of the hooks and a manifest; per ring, the STATS invocations equal the bpf_stats run
#      count summed over the programs writing it (no filter; the run count is read just
#      before the programs are detached, so other TCP traffic of the host may add a few
#      runs to STATS); hook_seq has no gaps without drops; the hook tag in ato;
#   3. --on-change cc with tiny ring buffers: hook_seq gaps + drops at flow ends = dropped;
#   4. --on-change-shadow: every reason code in ato matches a replay of the trace (default
#      hooks: one file holds every run of the connection), and with all hooks a replay of the
#      send and receive files merged by time (one state per connection);
#   5. an outage (all packets to the server port dropped for 1.5 s): the timer hook records a
#      backoff that an ingress-only run does not see.
# Needs iperf3, iptables and python3. Sets kernel.bpf_stats_enabled=1 and restores it.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
bin=${1:-$repo/tcbee-record/target/release/tcbee-record}
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ -x $bin ]] || { echo "no $bin, build tcbee-record first" >&2; exit 2; }

tmp=$(mktemp -d)
stats_before=$(sysctl -n kernel.bpf_stats_enabled)
port=5299
drop_rule=(INPUT -i lo -p tcp --dport $port -j DROP)
cleanup() {
	sysctl -qw kernel.bpf_stats_enabled="$stats_before"
	iptables -D "${drop_rule[@]}" 2>/dev/null || true
	pkill -f "iperf3 -s -p $port" 2>/dev/null || true
	rm -rf "$tmp"
}
trap cleanup EXIT
sysctl -qw kernel.bpf_stats_enabled=1
iperf3 -s -p $port -D

# record NAME ARGS...: 4 paced flows for 4 s while tcbee-record runs 6 s
record() {
	local name=$1
	shift
	mkdir -p "$tmp/$name"
	"$bin" -q --metrics -k -w --duration 6 -d "$tmp/$name" "$@" >"$tmp/$name.log" 2>&1 &
	local pid=$!
	sleep 1
	iperf3 -c 127.0.0.1 -p $port -t 4 -P 4 -b 500M >/dev/null
	wait $pid
	ls -d "$tmp/$name"/tcbee_*
}

# outage NAME ARGS...: one flow for 6 s, its packets dropped from 2 s to 3.5 s
outage() {
	local name=$1
	shift
	mkdir -p "$tmp/$name"
	"$bin" -q --metrics -k -w --duration 8 -d "$tmp/$name" "$@" >"$tmp/$name.log" 2>&1 &
	local pid=$!
	sleep 1
	iperf3 -c 127.0.0.1 -p $port -t 6 -b 100M >/dev/null &
	local client=$!
	sleep 2
	iptables -I "${drop_rule[@]}"
	sleep 1.5
	iptables -D "${drop_rule[@]}"
	wait $client || true
	wait $pid
	ls -d "$tmp/$name"/tcbee_*
}

all=ingress,timer,egress
default=$(record default)
oc=$(record onchange --on-change cc)
oc_all=$(record onchange-all --on-change cc --on-change-hooks $all)
drops=$(record drops --on-change cc --on-change-hooks $all --ringbuf-size sock=4K,cwnd=4K)
shadow=$(record shadow --on-change cc --on-change-shadow)
shadow_all=$(record shadow-all --on-change cc --on-change-hooks $all --on-change-shadow)
rto=$(outage rto --on-change cc)
rto_ingress=$(outage rto-ingress --on-change cc --on-change-hooks ingress)

python3 - "$default" "$oc" "$oc_all" "$drops" "$shadow" "$shadow_all" "$rto" "$rto_ingress" <<'PY'
import json, sys
from collections import defaultdict
from pathlib import Path

default, oc, oc_all, drops, shadow, shadow_all, rto, rto_ingress = map(Path, sys.argv[1:])
# Record layout as in tcbee-common/src/records.rs (size asserts) and the process bindings
HDR = 62
SIZES = {"sock": 262, "cwnd": 74}
RINGS = {"send_sock": "TCP_SEND_SOCK_EVENTS", "recv_sock": "TCP_RECV_SOCK_EVENTS",
         "send_cwnd": "TCP_SEND_CWND_EVENTS", "recv_cwnd": "TCP_RECEIVE_CWND_EVENTS"}
# The programs writing each file, by hook
PROGS = {"send_sock": {"egress": ["sock_oc_sendmsg"]},
         "recv_sock": {"ingress": ["sock_oc_recvmsg", "sock_oc_rcv_state"], "timer": ["sock_oc_timer"]},
         "send_cwnd": {"egress": ["cwnd_oc_sendmsg"]},
         "recv_cwnd": {"ingress": ["cwnd_oc_recvmsg", "cwnd_oc_rcv_state"], "timer": ["cwnd_oc_timer"]}}
TAGS = {"ingress": 1, "timer": 2, "egress": 3}
# packed offsets in sock_trace_entry of the cc fields and ato
CC = [("backoff", HDR + 16, 1), ("rto", HDR + 17, 4), ("rcv_mss", HDR + 25, 2),
      ("snd_cwnd", HDR + 27, 4), ("snd_ssthresh", HDR + 39, 4), ("total_retrans", HDR + 43, 4),
      ("reordering", HDR + 70, 4)]
BACKOFF = CC[0][1:]
ATO = (HDR + 21, 4)
failed = []

def check(ok, msg):
    print(("ok   " if ok else "FAIL ") + msg)
    if not ok:
        failed.append(msg)

def records(path, size):
    data = path.read_bytes() if path.exists() else b""
    for i in range(0, len(data) - size + 1, size):
        r = data[i:i + size]
        assert r[-4:] == b"\xff" * 4, f"{path}: bad delimiter"
        yield r

def num(r, off, width):
    return int.from_bytes(r[off:off + width], "little")

def key_of(r):
    return num(r, HDR - 6, 2), num(r, HDR - 4, 2)

def tag(r):
    return num(r, *ATO) >> 8

def reason(r):
    return num(r, *ATO) & 0xFF

def metrics(d):
    m = json.loads((d / "metrics.json").read_text())
    return {r["name"]: r for r in m["ringbufs"]}, {p["name"]: p for p in m["programs"]}, m

def hook_seq_gaps(path, size):
    """(missing numbers inside each key's range, sum of each key's highest number)"""
    seqs = defaultdict(list)
    for r in records(path, size):
        seqs[key_of(r)].append(num(r, 8, 8))
    missing = sum(max(s) - len(s) for s in seqs.values())
    return missing, sum(max(s) for s in seqs.values())

def files_of(hooks):
    return [f for f, progs in PROGS.items() if any(h in hooks for h in progs)]

# 1. default mode
rings, progs, m = metrics(default)
names = sorted(p.name for p in default.iterdir())
check(not any("_oc" in n for n in names) and "manifest.json" not in names,
      f"default: files {names}")
check(not any("_oc_" in p for p in progs), f"default: programs {sorted(progs)}")
check(m["suppressed"] == 0 and m["state_errors"] == 0, "default: no suppressed runs")

# 2. on-change, default hooks and all hooks
for name, d, hooks in (("on-change", oc, ("ingress", "timer")),
                       ("on-change all hooks", oc_all, tuple(TAGS))):
    rings, progs, m = metrics(d)
    names = sorted(p.name for p in d.iterdir())
    want = files_of(hooks)
    check("manifest.json" in names and sorted(f"{f}_oc.tcp" for f in want)
          == sorted(n for n in names if n.endswith("_oc.tcp")), f"{name}: files {names}")
    manifest = json.loads((d / "manifest.json").read_text())
    check(sorted(s["file"] for s in manifest["sources"]) == sorted(f"{f}_oc.tcp" for f in want),
          f"{name}: manifest lists the files")
    check(not any(p in progs for f in PROGS for h, ps in PROGS[f].items() if h not in hooks
                  for p in ps), f"{name}: no program of another hook loaded")
    for f in want:
        r = rings[RINGS[f]]
        ps = [progs[p] for h, names in PROGS[f].items() if h in hooks for p in names]
        if "ingress" in hooks and "ingress" in PROGS[f]:
            # the flows' handshakes and FINs go through tcp_rcv_state_process
            state = progs[PROGS[f]["ingress"][1]]["run_cnt"]
            check(state > 0, f"{name} {f}: {state} runs outside ESTABLISHED")
        run_cnt = sum(p["run_cnt"] for p in ps)
        misses = sum(p["recursion_misses"] for p in ps)
        extra = r["attempted"] - run_cnt
        # runs for listeners (tcp_rcv_state_process, one per SYN) and closed sockets are
        # skipped like filtered events
        skipped = 20
        check(-skipped <= extra <= 50 + run_cnt // 1000,
              f"{name} {f}: invocations {r['attempted']} = run_cnt {run_cnt} (+{extra}) "
              f"(handled {r['handled']}, suppressed {r['suppressed']}, dropped {r['dropped']}, "
              f"recursion misses {misses})")
        path = d / f"{f}_oc.tcp"
        missing, _ = hook_seq_gaps(path, SIZES[f.split("_")[1]])
        if r["dropped"] == 0:
            check(missing == 0, f"{name} {f}: no hook_seq gaps")
        if f.endswith("sock"):
            tags = defaultdict(int)
            for rec in records(path, SIZES["sock"]):
                tags[tag(rec)] += 1
            allowed = {TAGS[h] for h in PROGS[f] if h in hooks}
            check(set(tags) <= allowed, f"{name} {f}: hook tags {dict(tags)} in {sorted(allowed)}")
    total = sum(rings[RINGS[f]]["attempted"] for f in want)
    written = sum(rings[RINGS[f]]["handled"] for f in want)
    print(f"     {name} wrote {written} of {total} runs ({100 * written / max(total, 1):.1f} %)")

# 3. forced drops
rings, progs, m = metrics(drops)
for f, ring in RINGS.items():
    r = rings[ring]
    missing, top = hook_seq_gaps(drops / f"{f}_oc.tcp", SIZES[f.split("_")[1]])
    tail = r["hook_seq_issued"] - top
    check(missing + tail == r["dropped"],
          f"drops {f}: gaps {missing} + at flow ends {tail} = dropped {r['dropped']}")

# 4. shadow mode: replay the decision of every sock record. A record is forced (3) when its
# file's hook_seq skips, and compared with the last record of the connection in any file.
def replay(d, files, by_time):
    recs = [(f, r) for f in files for r in records(d / f"{f}_oc.tcp", SIZES["sock"])]
    order = (lambda x: (key_of(x[1]), num(x[1], 0, 8), x[0] != "send_sock")) if by_time \
        else (lambda x: (key_of(x[1]), num(x[1], 8, 8)))
    last, prev_seq, n, agree, reasons = {}, {}, 0, 0, defaultdict(int)
    for f, r in sorted(recs, key=order):
        k, seq, why = key_of(r), num(r, 8, 8), reason(r)
        vals = tuple(num(r, off, w) for _, off, w in CC)
        if k not in last or (f, k) in prev_seq and seq != prev_seq[f, k] + 1:
            want = {3}
        elif vals != last[k]:
            want = {2, 4}  # a state change may come with it
        else:
            want = {1, 4}
        # always possible: no socket storage (5); a new socket on a reused port (3)
        want |= {3, 5}
        n += 1
        agree += why in want
        reasons[why] += 1
        prev_seq[f, k] = seq
        if why != 5:  # without storage the probe keeps no last values
            last[k] = vals
    return n, agree, reasons

n, agree, reasons = replay(shadow, ["recv_sock"], by_time=False)
check(n > 0 and agree == n, f"shadow: {agree}/{n} reason codes match the replay {dict(reasons)}")
print(f"     shadow: on-change would write {n - reasons[1]} of {n} runs")
n, agree, reasons = replay(shadow_all, ["send_sock", "recv_sock"], by_time=True)
check(n > 0 and agree == n,
      f"shadow all hooks: {agree}/{n} reason codes match the merged replay {dict(reasons)}")
print(f"     shadow all hooks: on-change would write {n - reasons[1]} of {n} runs")

# 5. outage: retransmission timeouts without ACKs. ACK processing resets the backoff before
# the ingress hook runs, so only the timer hook sees it.
max_backoff = {}
for name, d in (("outage", rto), ("outage ingress only", rto_ingress)):
    recs = list(records(d / "recv_sock_oc.tcp", SIZES["sock"]))
    timer_recs = [r for r in recs if tag(r) == TAGS["timer"]]
    max_backoff[name] = max((num(r, *BACKOFF) for r in recs), default=0)
    print(f"     {name}: {len(recs)} records, {len(timer_recs)} from the timer, "
          f"backoffs {sorted({num(r, *BACKOFF) for r in timer_recs})}, max {max_backoff[name]}")
check(max_backoff["outage"] > max_backoff["outage ingress only"],
      f"outage: the timer hook records a backoff the ingress hook does not see {max_backoff}")

sys.exit(1 if failed else 0)
PY
