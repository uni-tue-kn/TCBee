#!/usr/bin/env bash
# Smoke test of the on-change mode on loopback (root: loads the eBPF programs).
#
#   sudo testing/onchange_smoke.sh [TCBEE_RECORD]
#
# Records iperf3 on lo four times with -k -w and checks:
#   1. default mode: the usual file names, no manifest, no on-change program loaded,
#      no suppressed runs;
#   2. --on-change cc: *_oc files and a manifest; per ring, the STATS invocations equal the
#      program's bpf_stats run count (no filter; the run count is read just before the
#      programs are detached, so other TCP traffic of the host may add a few runs to STATS);
#      hook_seq has no gaps without drops;
#   3. --on-change cc with tiny ring buffers: hook_seq gaps + drops at flow ends = dropped;
#   4. --on-change-shadow: every reason code in ato matches a replay of the trace.
# Needs iperf3 and python3. Sets kernel.bpf_stats_enabled=1 and restores it.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
bin=${1:-$repo/tcbee-record/target/release/tcbee-record}
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ -x $bin ]] || { echo "no $bin, build tcbee-record first" >&2; exit 2; }

tmp=$(mktemp -d)
stats_before=$(sysctl -n kernel.bpf_stats_enabled)
port=5299
cleanup() {
	sysctl -qw kernel.bpf_stats_enabled="$stats_before"
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
	"$bin" -q -m -k -w --duration 6 -d "$tmp/$name" "$@" >"$tmp/$name.log" 2>&1 &
	local pid=$!
	sleep 1
	iperf3 -c 127.0.0.1 -p $port -t 4 -P 4 -b 500M >/dev/null
	wait $pid
	ls -d "$tmp/$name"/tcbee_*
}

default=$(record default)
oc=$(record onchange --on-change cc)
drops=$(record drops --on-change cc --ringbuf-size sock=4K,cwnd=4K)
shadow=$(record shadow --on-change cc --on-change-shadow)

python3 - "$default" "$oc" "$drops" "$shadow" <<'PY'
import json, struct, sys
from collections import defaultdict
from pathlib import Path

default, oc, drops, shadow = map(Path, sys.argv[1:])
# Record layout as in tcbee-common/src/records.rs (size asserts) and the process bindings
HDR = 62
SIZES = {"sock": 168, "cwnd": 70}
RINGS = {"send_sock": "TCP_SEND_SOCK_EVENTS", "recv_sock": "TCP_RECV_SOCK_EVENTS",
         "send_cwnd": "TCP_SEND_CWND_EVENTS", "recv_cwnd": "TCP_RECEIVE_CWND_EVENTS"}
PROGS = {"send_sock": "sock_oc_sendmsg", "recv_sock": "sock_oc_recvmsg",
         "send_cwnd": "cwnd_oc_sendmsg", "recv_cwnd": "cwnd_oc_recvmsg"}
# packed offsets in sock_trace_entry of the cc fields and ato
CC = [("backoff", HDR + 16, 1), ("rto", HDR + 17, 4), ("rcv_mss", HDR + 25, 2),
      ("snd_cwnd", HDR + 27, 4), ("snd_ssthresh", HDR + 39, 4), ("total_retrans", HDR + 43, 4),
      ("reordering", HDR + 70, 4)]
ATO = (HDR + 21, 4)
failed = []

def check(ok, msg):
    print(("ok   " if ok else "FAIL ") + msg)
    if not ok:
        failed.append(msg)

def records(path, size):
    data = path.read_bytes()
    for i in range(0, len(data) - size + 1, size):
        r = data[i:i + size]
        assert r[-4:] == b"\xff" * 4, f"{path}: bad delimiter"
        yield r

def num(r, off, width):
    return int.from_bytes(r[off:off + width], "little")

def key_of(r):
    return num(r, HDR - 6, 2), num(r, HDR - 4, 2)

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

# 1. default mode
rings, progs, m = metrics(default)
names = sorted(p.name for p in default.iterdir())
check(not any("_oc" in n for n in names) and "manifest.json" not in names,
      f"default: files {names}")
check(not any("_oc_" in p for p in progs), f"default: programs {sorted(progs)}")
check(m["suppressed"] == 0 and m["state_errors"] == 0, "default: no suppressed runs")

# 2. on-change
rings, progs, m = metrics(oc)
names = sorted(p.name for p in oc.iterdir())
check("manifest.json" in names and all(f"{f}_oc.tcp" in names for f in RINGS), f"on-change: files {names}")
for f, ring in RINGS.items():
    r, p = rings[ring], progs[PROGS[f]]
    extra = r["attempted"] - p["run_cnt"]
    check(0 <= extra <= 50 + p["run_cnt"] // 1000,
          f"on-change {f}: invocations {r['attempted']} = run_cnt {p['run_cnt']} (+{extra}) "
          f"(handled {r['handled']}, suppressed {r['suppressed']}, dropped {r['dropped']})")
    missing, _ = hook_seq_gaps(oc / f"{f}_oc.tcp", SIZES[f.split('_')[1]])
    if r["dropped"] == 0:
        check(missing == 0, f"on-change {f}: no hook_seq gaps")
total = sum(rings[r]["attempted"] for r in RINGS.values())
written = sum(rings[r]["handled"] for r in RINGS.values())
print(f"     on-change wrote {written} of {total} runs ({100 * written / max(total, 1):.1f} %)")

# 3. forced drops
rings, progs, m = metrics(drops)
for f, ring in RINGS.items():
    r = rings[ring]
    missing, top = hook_seq_gaps(drops / f"{f}_oc.tcp", SIZES[f.split('_')[1]])
    tail = r["hook_seq_issued"] - top
    check(missing + tail == r["dropped"],
          f"drops {f}: gaps {missing} + at flow ends {tail} = dropped {r['dropped']}")

# 4. shadow mode: replay the decision of every sock record
for f in ("send_sock", "recv_sock"):
    last, prev_seq, n, agree, reasons = {}, {}, 0, 0, defaultdict(int)
    for r in sorted(records(shadow / f"{f}_oc.tcp", 168), key=lambda r: (key_of(r), num(r, 8, 8))):
        k, seq, reason = key_of(r), num(r, 8, 8), num(r, *ATO)
        vals = tuple(num(r, off, w) for _, off, w in CC)
        if k not in last or seq != prev_seq[k] + 1:
            want = {3}
        elif vals != last[k]:
            want = {2, 4}  # a state change may come with it
        else:
            want = {1, 4}
        # always possible: no socket storage (5); a new socket on a reused port (3)
        want |= {3, 5}
        n += 1
        agree += reason in want
        reasons[reason] += 1
        prev_seq[k] = seq
        if reason != 5:  # without storage the probe keeps no last values
            last[k] = vals
    check(n > 0 and agree == n, f"shadow {f}: {agree}/{n} reason codes match the replay {dict(reasons)}")
    print(f"     shadow {f}: on-change would write {n - reasons[1]} of {n} runs")

sys.exit(1 if failed else 0)
PY
