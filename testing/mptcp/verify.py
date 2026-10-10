#!/usr/bin/env python3
"""Checks one repetition of eval.py against its oracles and writes verify.json.

    verify.py REP_DIR

Invariants (any failure makes the run fail):
  grouping       every subflow the applications saw carries only its own side's token
  known_tokens   every non-zero conn_id in the records is a token an application saw
  tcp_untagged   plain TCP records have conn_id 0
  db             the database has one MPTCP connection per recorded token, with its subflows
  monitor_diff   per token and event type, TCBee's path manager records equal the events of
                 `ip mptcp monitor` in that token's namespace
  token_destroy  one TOKEN_DESTROYED per CREATED
  causal_order   per token by ktime: CREATED first, TOKEN_DESTROYED last, ESTABLISHED before
                 every SUB_ESTABLISHED
  identity       U = (T + M_truth) - (R + D + E + M_tcbee) = 0 for the mptcp_pm ring
  no_drops       D = 0 (not checked in --sigstop runs)
  ipv4           every record is AF_INET
  recorder       tcbee-record exited with 0, no writer error, records on disk = handled
Scenario-specific invariants: dynamic (failed join reported with an error, ANNOUNCED and
REMOVED on the client side). Fallback and e6 runs report their facts as characteristics.

A run whose oracle is broken (monitor ENOBUFS, an application without logs) is invalid
(exit 2), not failed (exit 1).
"""

import collections
import hashlib
import json
import re
import sqlite3
import struct
import sys
from pathlib import Path

# On-disk layouts (bincode, no padding), see tcbee-record/tcbee/src/bpf/records.h and
# check_trace.py. Header: time, hook_seq, addr_v4, src_v6, dst_v6, sport, dport, family.
HEADER = "<QQQ16s16sHHH"
SOCK = struct.Struct(HEADER + "QQBIIHIQIIBIIIIIHIIIQIIHHI")
SOCK_FIELDS = (
    "time hook_seq addr_v4 src_v6 dst_v6 sport dport family pacing_rate max_pacing_rate "
    "backoff rto ato rcv_mss snd_cwnd bytes_acked snd_ssthresh total_retrans probes lost "
    "sacked_out retrans rcv_ssthresh rttvar advmss reordering rcv_rtt rcv_space "
    "bytes_received segs_out segs_in snd_wscale rcv_wscale conn_id"
).split()
CWND = struct.Struct(HEADER + "II")
PM = struct.Struct("<QQQ16s16sHHHIIIqBBBBBHHIIIIQ")
PM_FIELDS = (
    "time hook_seq addr_v4 src_v6 dst_v6 sport dport family token remote_token subflow_id "
    "error event local_id remote_id backup addr_id addr_family addr_port addr_0 addr_1 addr_2 "
    "addr_3 data_seq"
).split()
DELIM = 4
AF_INET = 2
MPTCP_PORT, TCP_PORT = 5501, 5502
# Connections each scenario of eval.py opens: (MPTCP client, MPTCP server, TCP client). A
# different count in the application logs means the oracle is incomplete: the run is invalid.
EXPECTED_APPS = {"static": (1, 1, 1), "churn": (50, 50, 50), "dynamic": (1, 1, 0),
                 "e6": (1, 1, 0), "stale": (1, 1, 0), "fallback": (10, 10, 1)}

CREATED, ESTABLISHED, CLOSED, ANNOUNCED, REMOVED = 1, 2, 3, 6, 7
SUB_ESTABLISHED, SUB_CLOSED, SUB_PRIORITY = 10, 11, 13
TOKEN_DESTROYED, SUBFLOW_CONNECT, MP_FAIL = 100, 101, 102
SUBFLOW_STALE = 103
MONITOR_TYPES = {
    "CREATED": CREATED, "ESTABLISHED": ESTABLISHED, "CLOSED": CLOSED,
    "ANNOUNCED": ANNOUNCED, "REMOVED": REMOVED, "SF_ESTABLISHED": SUB_ESTABLISHED,
    "SF_CLOSED": SUB_CLOSED, "SF_PRIO": SUB_PRIORITY,
}
NAMES = {v: k for k, v in MONITOR_TYPES.items()} | {
    TOKEN_DESTROYED: "TOKEN_DESTROYED", SUBFLOW_CONNECT: "SUBFLOW_CONNECT", MP_FAIL: "MP_FAIL",
    SUBFLOW_STALE: "SUBFLOW_STALE"}
# TCBee event types that a kernel MIB counter (MPTcpExt) counts exactly, per namespace
MIB_EXACT = {SUBFLOW_STALE: "SubflowStale"}


def ipv4(word: int) -> str:
    return ".".join(str(b) for b in word.to_bytes(4, "little"))


def tuple_of(addr_v4: int, sport: int, dport: int):
    # skc_addrpair: remote address in the low half, local in the high half
    return (ipv4(addr_v4 >> 32), sport, ipv4(addr_v4 & 0xFFFFFFFF), dport)


def read_records(path: Path, st: struct.Struct, fields=None):
    if not path.exists():
        return []
    data = path.read_bytes()
    size = st.size + DELIM
    if len(data) % size:
        raise SystemExit(f"{path}: {len(data)} bytes is no whole number of {size} B records")
    out = []
    for i in range(0, len(data), size):
        v = st.unpack_from(data, i)
        out.append(dict(zip(fields, v)) if fields else v)
    return out


def sock_like(trace: Path):
    """(tuple, conn_id, family, time, file) of every sock and cwnd record"""
    for name in ("send_sock.tcp", "recv_sock.tcp"):
        for r in read_records(trace / name, SOCK, SOCK_FIELDS):
            yield tuple_of(r["addr_v4"], r["sport"], r["dport"]), r["conn_id"], r["family"], r["time"], name
    for name in ("send_cwnd.tcp", "recv_cwnd.tcp"):
        for v in read_records(trace / name, CWND):
            yield tuple_of(v[2], v[5], v[6]), v[9], v[7], v[0], name


def pm_records(trace: Path):
    return read_records(trace / "mptcp_pm.tcp", PM, PM_FIELDS)


def parse_monitor(path: Path):
    """[(type, token)] in output order. Lines look like
    `[       SF_ESTABLISHED] token=1a2b3c4d remid=1 locid=0 saddr4=... ...`, with -ts prefixed
    by a timestamp."""
    out = []
    for line in path.read_text(errors="replace").splitlines():
        m = re.search(r"\[\s*([A-Z_]+)\]\s*token=([0-9a-fA-F]+)", line)
        if m and m.group(1) in MONITOR_TYPES:
            out.append((MONITOR_TYPES[m.group(1)], int(m.group(2), 16)))
    return out


def netstat_mptcp(path: Path) -> dict:
    lines = path.read_text().splitlines()
    for names, values in zip(lines[::2], lines[1::2]):
        if names.startswith("MPTcpExt:"):
            return dict(zip(names.split()[1:], map(int, values.split()[1:])))
    return {}


def truth_counts(path: Path) -> dict:
    """{tcbee event type: count} from bpftrace -f json output"""
    counts = collections.Counter()
    single = {"@announced": ANNOUNCED, "@removed": REMOVED, "@token_destroyed": TOKEN_DESTROYED,
              "@subflow_connect": SUBFLOW_CONNECT, "@mp_fail": MP_FAIL,
              "@stale": SUBFLOW_STALE}
    for line in path.read_text(errors="replace").splitlines():
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("type") != "map":
            continue
        for name, val in o["data"].items():
            if name == "@ev":
                for k, n in val.items():
                    counts[int(k)] += n
            elif name in single:
                counts[single[name]] += val
    return dict(counts)


def main() -> int:
    rep = Path(sys.argv[1])
    run = json.loads((rep / "run.json").read_text())
    scenario = run["scenario"]
    sigstop = run["args"].get("sigstop")
    trace = next((rep / "trace").glob("tcbee_*"))
    inv: dict = {}
    chars: dict = {}
    invalid: list = []

    def check(name, ok, value=None):
        inv[name] = {"ok": bool(ok), "value": value}

    # ---- applications (oracle) -------------------------------------------------------------
    apps = []
    for side in ("client", "server"):
        p = rep / f"app-{side}.jsonl"
        if p.exists():
            apps += [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    mp_apps = [a for a in apps if a["proto"] == "mptcp"]
    tcp_apps = [a for a in apps if a["proto"] == "tcp"]
    for side in ("client", "server"):
        if not (rep / f"app-{side}.jsonl").exists():
            invalid.append(f"no {side} application log")
    oracle_sub = {}  # subflow tuple -> (token, side)
    tokens_side = {}
    for a in mp_apps:
        if a["token"] and not a["fallback"]:
            tokens_side[a["token"]] = a["side"]
            for s in a["subflows"]:
                oracle_sub[tuple(s)] = a["token"]
    chars["app_connections"] = {
        "mptcp_client": sum(a["side"] == "client" for a in mp_apps),
        "mptcp_server": sum(a["side"] == "server" for a in mp_apps),
        "tcp_client": sum(a["side"] == "client" for a in tcp_apps),
        "fallback": sum(bool(a["fallback"]) for a in mp_apps),
        "info_error": sum(bool(a["info_error"]) for a in mp_apps),
    }
    got = tuple(chars["app_connections"][k] for k in ("mptcp_client", "mptcp_server", "tcp_client"))
    if got != EXPECTED_APPS[scenario]:
        invalid.append(f"application connections {got}, expected {EXPECTED_APPS[scenario]}")
    nsub = [len(a["subflows"]) for a in mp_apps if a["side"] == "client" and not a["fallback"]]
    if nsub:
        chars["client_conns_with_2plus_subflows"] = f"{sum(n >= 2 for n in nsub)}/{len(nsub)}"

    # ---- sock and cwnd records --------------------------------------------------------------
    by_flow = collections.defaultdict(collections.Counter)  # tuple -> conn_id -> n
    families = collections.Counter()
    tcp_tagged = 0
    n_rec = 0
    for t, conn_id, family, _time, _f in sock_like(trace):
        n_rec += 1
        families[family] += 1
        if MPTCP_PORT in (t[1], t[3]):
            by_flow[t][conn_id] += 1
        elif TCP_PORT in (t[1], t[3]) and conn_id:
            tcp_tagged += 1
    pm = pm_records(trace)
    for r in pm:
        families[r["family"]] += 1
    chars["records_sock_cwnd"] = n_rec
    check("records", n_rec > 0 and len(pm) > 0, {"sock_cwnd": n_rec, "pm": len(pm)})
    check("ipv4", set(families) <= {AF_INET}, dict(families))
    check("tcp_untagged", tcp_tagged == 0, tcp_tagged)

    fallback_mode = scenario == "fallback"
    # A connection that fell back on the server only: the server's socket is plain TCP
    # (MPTCP_INFO fails), its records must carry no token
    server_plain = {tuple(a["first"]) for a in mp_apps if a["side"] == "server" and a["info_error"]}
    plain_tagged = {str(t): dict(by_flow[t]) for t in server_plain if set(by_flow.get(t, {})) - {0}}
    if not fallback_mode:
        check("server_fallback_untagged", not plain_tagged, plain_tagged)
    chars["server_fallback_connections"] = len(server_plain)
    misgrouped, unverified, untagged = [], [], {}
    for t, ids in by_flow.items():
        if t in server_plain:
            continue
        tags = {c for c in ids if c}
        if ids.get(0):
            untagged[t] = ids[0]
        if t in oracle_sub:
            if tags and tags != {oracle_sub[t]}:
                misgrouped.append({"flow": t, "tags": sorted(tags), "oracle": oracle_sub[t]})
        elif tags:
            unverified.append({"flow": t, "tags": sorted(tags)})
    recorded_tokens = {c for ids in by_flow.values() for c in ids if c}
    # Every subflow the applications saw is recorded and carries its own token
    missing = sorted(str(t) for t in oracle_sub if t not in by_flow)
    untagged_only = sorted(str(t) for t in oracle_sub if t in by_flow and not set(by_flow[t]) - {0})
    if not fallback_mode:
        check("grouping", oracle_sub and not misgrouped and not missing and not untagged_only,
              {"misgrouped": misgrouped[:10], "not_recorded": missing[:10],
               "untagged_only": untagged_only[:10], "oracle_subflows": len(oracle_sub)})
        check("known_tokens", recorded_tokens == set(tokens_side),
              {"recorded_not_app": sorted(f"{c:#010x}" for c in recorded_tokens - set(tokens_side)),
               "app_not_recorded": sorted(f"{c:#010x}" for c in set(tokens_side) - recorded_tokens)})
    chars["subflows_recorded"] = len(by_flow)
    chars["subflows_tagged_not_seen_by_app"] = unverified[:10]
    chars["oracle_subflows_not_recorded"] = sorted(
        str(t) for t in set(oracle_sub) - set(by_flow))[:10]
    chars["untagged_records_per_subflow_max"] = max(untagged.values(), default=0)
    chars["subflows_with_untagged_records"] = len(untagged)

    # ---- database ---------------------------------------------------------------------------
    dbp = rep / "db.sqlite"
    if dbp.exists() and not fallback_mode:
        db = sqlite3.connect(dbp)
        conns = dict(db.execute("SELECT key, id FROM connections WHERE kind = 'mptcp'").fetchall())
        conns = {int(k): v for k, v in conns.items()}
        bad = []
        for token in recorded_tokens:
            if token not in conns:
                bad.append(f"{token:#010x} missing")
                continue
            rows = db.execute(
                "SELECT f.src, f.sport, f.dst, f.dport FROM connection_flows c "
                "JOIN flows f ON f.id = c.flow_id WHERE c.connection_id = ?", (conns[token],),
            ).fetchall()
            want = {t for t, ids in by_flow.items() if token in ids}
            if set(map(tuple, rows)) != want:
                bad.append(f"{token:#010x}: db {sorted(rows)} records {sorted(want)}")
        if set(conns) != set(tokens_side):
            bad.append(f"db tokens != app tokens: db-only {sorted(hex(x) for x in set(conns) - set(tokens_side))}, "
                       f"app-only {sorted(hex(x) for x in set(tokens_side) - set(conns))}")
        check("db", not bad, bad[:10])
        chars["db_connections"] = len(conns)
    elif not fallback_mode:
        check("db", False, "no database")

    # ---- path manager events vs monitor -----------------------------------------------------
    # Where the untagged records of subflows lie: after their token's TOKEN_DESTROYED (the last
    # segments of a closing subflow) or elsewhere (before the subflow was linked)
    destroyed_at = {r["token"]: r["time"] for r in pm if r["event"] == TOKEN_DESTROYED}
    where = collections.Counter()
    for t, conn_id, _fam, tm, _f in sock_like(trace):
        if conn_id or t not in untagged:
            continue
        tok = next(iter(set(by_flow[t]) - {0}), None)
        where["after_token_destroyed" if tok in destroyed_at and tm > destroyed_at[tok] else "elsewhere"] += 1
    chars["untagged_subflow_records"] = dict(where)
    tb = collections.defaultdict(list)  # token -> [(time, event, error, record)]
    for r in pm:
        tb[r["token"]].append((r["time"], r["event"], r["error"], r))
    for v in tb.values():
        v.sort(key=lambda x: x[0])
    mon = {}
    for side in ("client", "server"):
        err = (rep / f"monitor-{side}.err")
        if err.exists() and re.search(r"No buffer space|ENOBUFS", err.read_text()):
            invalid.append(f"monitor {side} ENOBUFS")
        mon[side] = parse_monitor(rep / f"monitor-{side}.txt")
    mon_counts = collections.Counter((tok, typ) for side in mon for typ, tok in mon[side])
    tb_counts = collections.Counter(
        (tok, ev) for tok, v in tb.items() for _, ev, _, _ in v if ev in NAMES and ev in MONITOR_TYPES.values())
    diff = {f"{tok:#010x} {NAMES[typ]}": tb_counts[(tok, typ)] - mon_counts[(tok, typ)]
            for tok, typ in set(mon_counts) | set(tb_counts)
            if tb_counts[(tok, typ)] != mon_counts[(tok, typ)]}
    # The client's token, as seen by the server's monitor (and the other way round), is a
    # different token; both monitors only report their own namespace's connections
    if sigstop:
        chars["monitor_diff"] = diff
    else:
        check("monitor_diff", not diff, diff)
    chars["monitor_events"] = sum(mon_counts.values())
    chars["pm_records"] = len(pm)
    chars["pm_by_type"] = dict(collections.Counter(NAMES.get(r["event"], r["event"]) for r in pm))
    seq_equal = 0
    for side in mon:
        for tok in {t for _, t in mon[side]}:
            m_seq = [typ for typ, t in mon[side] if t == tok]
            t_seq = [ev for _, ev, _, _ in tb.get(tok, []) if ev in MONITOR_TYPES.values()]
            seq_equal += m_seq == t_seq
    n_mon_tokens = len({t for s in mon for _, t in mon[s]})
    chars["tokens_with_identical_sequence"] = f"{seq_equal}/{n_mon_tokens}"
    check("monitor_events", sum(mon_counts.values()) > 0, sum(mon_counts.values()))
    if not sigstop:
        # E2: TCBee's events of a token in ktime order equal the monitor's sequence
        check("monitor_order", seq_equal == n_mon_tokens, chars["tokens_with_identical_sequence"])

    created = collections.Counter(t for t, v in tb.items() for _, ev, _, _ in v if ev == CREATED)
    destroyed = collections.Counter(t for t, v in tb.items() for _, ev, _, _ in v if ev == TOKEN_DESTROYED)
    bad_td = {f"{t:#010x}": (created[t], destroyed[t]) for t in set(created) | set(destroyed)
              if created[t] != destroyed[t] or created[t] != 1}
    if not sigstop and not fallback_mode:
        check("token_destroy", not bad_td, bad_td)
    order_bad = []
    for tok, v in tb.items():
        evs = [ev for _, ev, _, _ in v]
        if CREATED in evs and evs[0] != CREATED:
            order_bad.append(f"{tok:#010x}: first {NAMES.get(evs[0])}")
        if TOKEN_DESTROYED in evs and evs[-1] != TOKEN_DESTROYED:
            order_bad.append(f"{tok:#010x}: last {NAMES.get(evs[-1])}")
        if ESTABLISHED in evs:
            i = evs.index(ESTABLISHED)
            if SUB_ESTABLISHED in evs[:i]:
                order_bad.append(f"{tok:#010x}: SUB_ESTABLISHED before ESTABLISHED")
    check("causal_order", not order_bad, order_bad[:10])
    connects = [(f"{tok:#010x}", err) for tok, v in tb.items() for _, ev, err, _ in v if ev == SUBFLOW_CONNECT]
    chars["subflow_connect_errors"] = [c for c in connects if c[1]]
    chars["subflow_connects"] = len(connects)

    if scenario == "dynamic":
        client_tokens = {t for t, s in tokens_side.items() if s == "client"}
        cev = collections.Counter(ev for t in client_tokens for _, ev, _, _ in tb.get(t, []))
        check("failed_join_reported", any(err for _, err in connects), chars["subflow_connect_errors"])
        check("client_announced", cev[ANNOUNCED] >= 2, cev[ANNOUNCED])
        check("client_removed", cev[REMOVED] >= 1, cev[REMOVED])
        chars["client_events"] = {NAMES.get(k, k): n for k, n in cev.items()}
        server_tokens = {t for t, s in tokens_side.items() if s == "server"}
        sev = collections.Counter(ev for t in server_tokens for _, ev, _, _ in tb.get(t, []))
        chars["server_events"] = {NAMES.get(k, k): n for k, n in sev.items()}

    # ---- identity for the mptcp_pm ring ------------------------------------------------------
    metrics = json.loads((trace / "metrics.json").read_text())
    ring = next(r for r in metrics["ringbufs"] if r["name"] == "MPTCP_PM_EVENTS")
    R, D, E = len(pm), ring["dropped"], ring["error"]
    progs = json.loads((rep / "progs.json").read_text()) if (rep / "progs.json").exists() else {}
    m_tcbee = sum((p.get("recursion_misses") or 0) for p in progs.get("tcbee", [])
                  if p.get("name", "").startswith("mptcp_pm"))
    m_truth = sum((p.get("recursion_misses") or 0) for p in progs.get("truth", []))
    truth_p = rep / "truth.txt"
    if truth_p.exists():
        tc = truth_counts(truth_p)
        T = sum(tc.values())
        U = (T + m_truth) - (R + D + E + m_tcbee)
        check("identity", U == 0 and T > 0, {"T": T, "R": R, "D": D, "E": E, "M_tcbee": m_tcbee,
                                             "M_truth": m_truth, "U": U})
        rec_by_type = collections.Counter(r["event"] for r in pm)
        by_type = {NAMES.get(k, k): tc.get(k, 0) - rec_by_type.get(k, 0)
                   for k in set(tc) | set(rec_by_type) if tc.get(k, 0) != rec_by_type.get(k, 0)}
        chars["truth_minus_records_by_type"] = by_type
        if D == 0 and E == 0:
            check("identity_by_type", not by_type, by_type)
    elif not run["args"].get("no_truth"):
        invalid.append("no truth counter output")
    chars["pm_ring"] = {"handled": ring["handled"], "dropped": D, "error": E,
                        "records_written": ring["records_written"],
                        "size_per_cpu_bytes": ring["size_per_cpu_bytes"]}
    if sigstop:
        chars["pm_dropped"] = D
    else:
        check("no_drops", metrics["dropped"] == 0, {"all_rings": metrics["dropped"], "pm": D})
    rec_bad = []
    if run.get("record_rc") != 0:
        rec_bad.append(f"rc {run.get('record_rc')}")
    # tcbee-record goes on without a probe group that fails to load or attach, with a warning
    err = rep / "record.err"
    for line in (err.read_text(errors="replace").splitlines() if err.exists() else []):
        if re.search(r"Retrying without|not recorded|Could not load|failed to load", line):
            rec_bad.append(line.strip()[:200])
    for r in metrics["ringbufs"]:
        if r.get("writer_error"):
            rec_bad.append(f"{r['name']}: {r['writer_error']}")
        if r.get("file") and r["records_written"] != r["handled"]:
            rec_bad.append(f"{r['name']}: written {r['records_written']} handled {r['handled']}")
    check("recorder", not rec_bad, rec_bad)
    # bpf_stats of the path manager programs (needs kernel.bpf_stats_enabled=1)
    pm_progs = [p for p in progs.get("tcbee", []) if p.get("name", "").startswith("mptcp_pm")]
    cnt = sum(p.get("run_cnt", 0) for p in pm_progs)
    ns_ = sum(p.get("run_time_ns", 0) for p in pm_progs)
    chars["pm_prog_runs"] = cnt
    chars["pm_prog_ns_per_run"] = round(ns_ / cnt, 1) if cnt else None

    # ---- MIB deltas per namespace -----------------------------------------------------------
    for side in ("client", "server"):
        pre, post = rep / f"netstat-{side}-pre.txt", rep / f"netstat-{side}-post.txt"
        if pre.exists() and post.exists():
            a, b = netstat_mptcp(pre), netstat_mptcp(post)
            chars[f"mib_{side}"] = {k: b[k] - a.get(k, 0) for k in b if b[k] - a.get(k, 0)}

    # Events that a MIB counter counts exactly: per side, TCBee's count equals the counter delta
    mib_bad, mib_seen = {}, {}
    for typ, mib in MIB_EXACT.items():
        for side in ("client", "server"):
            got = sum(1 for t, s in tokens_side.items() if s == side for _, ev, _, _ in tb.get(t, [])
                      if ev == typ)
            want = chars.get(f"mib_{side}", {}).get(mib, 0)
            mib_seen[f"{side} {mib}"] = (got, want)
            if got != want:
                mib_bad[f"{side} {mib}"] = (got, want)
    if not sigstop:
        check("events_vs_mib", not mib_bad, mib_bad)
    chars["events_vs_mib"] = mib_seen
    if scenario in ("e6", "stale"):
        # the blackholed path must be marked stale on the client
        check("stale_seen", mib_seen["client SubflowStale"][1] > 0, mib_seen["client SubflowStale"])

    if fallback_mode:
        chars["fallback_facts"] = fallback_facts(by_flow, tb, mp_apps)
        fallback_checks(check, by_flow, tb, pm, mp_apps, chars, dbp)

    failed = [k for k, v in inv.items() if not v["ok"]]
    status = "invalid" if invalid else ("fail" if failed else "ok")
    out = {"status": status, "failed": failed, "invalid": invalid, "invariants": inv,
           "characteristics": chars,
           "verify_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (rep / "verify.json").write_text(json.dumps(out, indent=1, default=str))
    for k, v in inv.items():
        print(("ok    " if v["ok"] else "FAIL  ") + k + ("" if v["ok"] else f": {v['value']}"))
    for k in invalid:
        print("INVALID " + k)
    print(f"status: {status}")
    return {"ok": 0, "fail": 1, "invalid": 2}[status]


def fallback_checks(check, by_flow, tb, pm, mp_apps, chars, dbp):
    """E8 expectation, fixed after the pilot of 2026-10-09: the server's SYN lost its MPTCP
    option, so the server has a plain TCP socket (conn_id 0, no path manager records); the
    client falls back at the SYN-ACK and keeps its token: one flow tagged with it, path
    manager records CLOSED and TOKEN_DESTROYED only."""
    server = [tuple(a["first"]) for a in mp_apps if a["side"] == "server"]
    client = [tuple(a["first"]) for a in mp_apps if a["side"] == "client"]
    bad = {str(t): dict(by_flow.get(t, {})) for t in server if set(by_flow.get(t, {})) - {0}}
    server_pm = [r for r in pm if r["sport"] == MPTCP_PORT]
    check("e8_server_plain", not bad and not server_pm, {"tagged": bad, "pm": len(server_pm)})
    tokens, bad = {}, []
    for t in client:
        tags = set(by_flow.get(t, {})) - {0}
        if len(tags) != 1:
            bad.append(f"{t}: tokens {sorted(tags)}")
            continue
        tokens[t] = tags.pop()
    shared = {tok for tok in tokens.values() if list(tokens.values()).count(tok) > 1}
    others = {f for f, ids in by_flow.items() if set(ids) & set(tokens.values()) and f not in client}
    check("e8_client_one_token_one_flow", not bad and not shared and not others,
          {"bad": bad, "shared": sorted(shared), "other_flows": sorted(map(str, others))})
    ev_bad = {f"{tok:#010x}": [NAMES.get(ev, ev) for _, ev, _, _ in tb.get(tok, [])]
              for tok in tokens.values()
              if [ev for _, ev, _, _ in tb.get(tok, [])] != [CLOSED, TOKEN_DESTROYED]}
    check("e8_client_events", not ev_bad, ev_bad)
    fb = chars.get("mib_client", {}).get("MPCapableFallbackSYNACK", 0)
    check("e8_mib_fallback", fb == len(client) == 10, {"MPCapableFallbackSYNACK": fb, "conns": len(client)})
    if dbp.exists():
        db = sqlite3.connect(dbp)
        conns = {int(k): v for k, v in db.execute(
            "SELECT key, id FROM connections WHERE kind = 'mptcp'").fetchall()}
        bad = []
        for t, tok in tokens.items():
            rows = db.execute(
                "SELECT f.src, f.sport, f.dst, f.dport FROM connection_flows c "
                "JOIN flows f ON f.id = c.flow_id WHERE c.connection_id = ?", (conns.get(tok),),
            ).fetchall()
            if set(map(tuple, rows)) != {t}:
                bad.append(f"{tok:#010x}: {rows}")
        if set(conns) != set(tokens.values()):
            bad.append(f"connections {len(conns)} vs client tokens {len(tokens)}")
        check("e8_db", not bad, bad)
    else:
        check("e8_db", False, "no database")


def fallback_facts(by_flow, tb, mp_apps):
    """What each side of a fallback connection looks like in the recording"""
    facts = {"client": [], "server": []}
    for a in mp_apps:
        t = tuple(a["first"])
        ids = dict(by_flow.get(t, {}))
        facts[a["side"]].append({
            "first": t, "app_token": a["token"], "app_fallback": a["fallback"],
            "app_info_error": a["info_error"],
            "record_conn_ids": {f"{k:#010x}": n for k, n in ids.items()},
            "pm_events": [NAMES.get(ev, ev) for k in ids if k for _, ev, _, _ in tb.get(k, [])],
        })
    return facts


if __name__ == "__main__":
    sys.exit(main())
