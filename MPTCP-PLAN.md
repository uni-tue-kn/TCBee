# MPTCP support for TCBee: research summary and implementation plan

Status: plan for discussion. Nothing is implemented. Written 2026-10-09 from three agent investigations: a literature/community survey, a fact check against primary sources, and a code + local-kernel (6.8.0-146) study. Supersedes the rough MPTCP section in `EXTENSION.md` §1. Scratch artifacts from the kernel study (struct dumps for 6.8 and 7.2.6, list of attachable functions) live in the session scratchpad and are not part of the repo. The facts they gave are copied in here.

**Framing constraint.** TCBee is a *general* TCP analysis tool. MPTCP is the first user of two general mechanisms: (a) grouping flows under a parent connection, and (b) protocol-level record types next to the TCP socket records. The paper should present MPTCP as a case study of extensibility, not as the headline.

**Hook policy.** We are not limited to tracepoints. fentry/fexit can attach to any function that is not inlined and has BTF, without performance problems. The limits are about portability:
- Functions may be inlined on some kernels. Every hook therefore lists a fallback, chosen with `retarget()` (`tcbee-record/tcbee/src/eBPF/probes/mod.rs:36-61`).
- Arguments change between kernels, while struct fields are CO-RE relocated. Prefer reading state from the socket structs over relying on argument layouts.

---

## 1. Why MPTCP is worth recording (research motivation)

### Gap in the literature
- Almost all MPTCP evaluations use the out-of-tree mptcp.org kernel (v0.9x) or emulation, measured with pcap/iperf/goodput.
  - Examples: Dimopoulos et al., arXiv 2511.14550 (2025); Weber et al., LCN 2023; most ATSSS work, e.g. Kudo et al., MITA 2024 and Quadrini et al., ISNCC 2023.
- Metrics those papers need, such as out-of-order (OFO) queue occupancy, come from patched kernels. Upstream `net/mptcp` (5.6+) has barely been evaluated systematically.
- Weber et al. (LCN 2023) found that the kernel version mattered more than the scheduler. Scheduler effects should therefore be recorded together with kernel-internal TCP state, which is exactly what TCBee does.

### The upstream community asks for this
Issues are in github.com/multipath-tcp/mptcp_net-next.
- **#635** (Sep 2026): 4xLTE + 2xStarlink + fiber, throughput drops to 0 after 2–5 s. Maintainer (Baerts): *"we will need to reproduce the issue locally first and debug using tracepoints."*
- **#592** (Oct 2025): MPTCP reaches 10–30 Gb/s vs 43 Gb/s for TCP on 2x100G. Debugging stalled at "where is the bottleneck", using `ss` snapshots. This matches the 400G testbed.
- **#581**: after a fail-back, the scheduler under-uses the restored subflow for minutes ("someone should analyse why the packet scheduler doesn't try to push on the subflow").
- **#180**: no runtime notification of fallback to TCP.
- **#343, #345, #348, #349**: scheduler and stale-subflow roadmap.
- The official debugging guide (https://www.mptcp.dev/debugging.html) lists only `ss`, `ip mptcp monitor`, `nstat` and tcpdump. All of these are snapshots or wire-level views.

### Existing tools
- Wire-only:
  - mptcptrace (SIGCOMM 2014 demo)
  - mptcpanalyzer (pcap via tshark)
  - Wireshark
- Snapshot: `ss -M` / `MPTCP_INFO`.
- The 6 upstream tracepoints are single-point event dumps that nobody consumes systematically. `ack_update_msk` carries no msk identity.
- No eBPF recorder of upstream MPTCP time series was found.

### What to record, by research value
| Prio | What | Research question / issue |
|---|---|---|
| 1 | Per-subflow TCP state (already recorded) **grouped by connection** | Fairness of uncoupled per-subflow CC (no LIA/OLIA/BALIA upstream, issue #528). Kernel vs scheduler effects (LCN'23). #592 |
| 1 | Scheduler decision stream (chosen subflow per push, optionally per-candidate metrics) | Path under-use (#581, LEO ECMP study 2026). Behaviour of the BLEST-like HoL estimate upstream (commit 3ce0852c86b9). Training data for learned schedulers (ReLeS, FALCON) |
| 1 | Connection-level ACK/window: msk `snd_una`, `wnd_end` vs subflow `snd_una` | MPTCP-window-limited vs cwnd-limited periods. Stalls (#635, #343, #345) |
| 1 | Receive-side OFO queue span and **HoL delay** | #635 Recv-Q blow-up. Upstream equivalent of the OFO metric in arXiv 2511.14550. Abeni's msk autotuning fixes (before/after) |
| 2 | Path-manager / lifecycle events (subflow created/established/closed, ADD_ADDR, RM_ADDR, backup/prio change, join failures) | ADD_ADDR→subflow latency, join failure causes (MIBs have no timing), PM behaviour (#440, #552, #587) |
| 2 | Data-level retransmission/reinjection (trigger, DSN range, source→target subflow) | "Excessive MPTCP retransmissions due to HoL" (Baltaci et al., IEEE Access 2023) measured directly instead of inferred. #177, #332 |
| 3 | Stale/backup failover timing (`stale`, `stale_count`, MP_PRIO) | Switch-over latency vs `stale_loss_cnt`. ATSSS steering-mode switching |
| 3 | Fallback / MP_FAIL / DSS mapping status | Middlebox interference (#180) |

---

## 2. Verified kernel facts the design relies on

Sources are primary (mainline at tags, read from raw.githubusercontent). Locally checked means BTF + kallsyms on this host's 6.8.

- Subflows are ordinary `tcp_sock`s. TCBee's fentry hooks and `tcp:tcp_probe` fire for subflows and never for the msk. **[inferred from code; confirm in a test]**
- `tcp_sock.is_mptcp` is a plain `bool` (under `CONFIG_MPTCP`). `sk_is_mptcp()` and `mptcp_subflow_ctx()` are `static inline`, so they are not callable. The subflow ctx is in `inet_csk(sk)->icsk_ulp_data`, and `ctx->conn` points to the msk.
- Helper `bpf_skc_to_mptcp_sock`: since **5.19**, allowed for tracing programs. Wraps `bpf_mptcp_sock_from_subflow`, which is NULL unless the socket is an MPTCP subflow.
- Not in mainline as of 7.3-rc6:
  - MPTCP kfuncs and the subflow iterator
  - BPF schedulers (`bpf_mptcp_sched_ops`)
  - BPF path managers (`mptcp_pm_ops` exists since 6.15, but only as an in-kernel abstraction)
  - coupled CCAs

  **The design must not depend on any of these.**
- `mptcp_sched_ops` since 6.6. The scheduler API differs across kernels:
  - 6.8: `get_subflow(msk, mptcp_sched_data*)`
  - 7.x: `get_send(msk)` / `get_retrans(msk)`
- Tracepoints (`include/trace/events/mptcp.h`):
  - 5.13: `mptcp_subflow_get_send`, `get_mapping_status`, `ack_update_msk`, `subflow_check_data_avail`
  - 5.18: `mptcp_sendmsg_frag`
  - 7.0: `mptcp_rcvbuf_grow`
- `subflow_id` in `mptcp_subflow_context` since **6.5**. `mptcp_info` gained `bytes_*` in 6.5, `subflows_total` in 6.8 and `last_data_*` in 6.10. `MPTCP_FULL_INFO` since 6.5.
- 6.8 → 7.2.6 struct drift (relevant subset):
  - `mptcp_pm_data.subflows` is renamed to `extra_subflows` in 7.2.
  - `rcvq_space` changed.
  - `receive_queue` and `rmem_*` were removed from the msk.

  Stable across both:
  - msk: `token`, `snd_una`, `snd_nxt`, `write_seq`, `wnd_end`, `ack_seq`, `ooo_last_skb`, `bytes_*`
  - subflow ctx: `subflow_id`, `conn`, `backup`, `local_id`, `remote_id`, `stale_count`, `avg_pacing_rate`
- The msk OFO queue has no length counter. It is non-empty iff `ooo_last_skb != NULL`. Its span is `MPTCP_SKB_CB(ooo_last_skb)->end_seq - ack_seq`, with `mptcp_skb_cb` stored in `skb->cb`.
- Fallback has no hook: `mptcp_do_fallback` / `__mptcp_set_fallback` are inlined. The `MPTCP_FALLBACK_DONE` bit in `msk->flags` is a `#define`, so its bit number is not in BTF. **[bit number unverified per kernel; and 6.16+ reworked fallback (`fallback_lock`): check]**

### Attachable on 6.8 (BTF FUNC + text symbol)
- **Scheduler:**
  - `mptcp_subflow_get_send` T
  - `mptcp_sched_get_send` / `_retrans` T
  - `mptcp_subflow_set_scheduled(subflow, bool)` T
- **Send:**
  - `__mptcp_push_pending` T
  - `__mptcp_subflow_push_pending` t
  - `mptcp_sendmsg_frag` t
  - `__mptcp_retrans` t
  - `__mptcp_retransmit_pending_data` T
- **ACK/receive:**
  - `ack_update_msk` t
  - `mptcp_incoming_options` T
  - `__mptcp_clean_una` t
  - `__mptcp_data_acked` T
  - `mptcp_data_ready` T
  - `__mptcp_move_skbs_from_subflow` t
  - `mptcp_data_queue_ofo` t
  - `__mptcp_ofo_queue` t
  - `mptcp_rcv_space_adjust` t
- **Lifecycle/PM:**
  - `mptcp_event(type,msk,ssk,gfp)` T
  - `mptcp_event_addr_announced` / `_removed` T
  - `mptcp_pm_add_addr_received` T
  - `mptcp_pm_announce_addr` T
  - `mptcp_pm_rm_addr_received` T
  - `mptcp_pm_mp_prio_received` T
  - `mptcp_pm_nl_mp_prio_send_ack` T
  - `mptcp_pm_mp_fail_received` T
  - `mptcp_pm_nl_subflow_chk_stale` T
  - `__mptcp_subflow_connect` T
  - `mptcp_finish_join` T
  - `__mptcp_close_ssk` t
  - `mptcp_subflow_reset` T
  - `subflow_finish_connect` t
  - `subflow_syn_recv_sock` t

(T = global, t = static but out of line. Static functions are the ones most at risk of being inlined on other kernels.)

---

## 3. Design

### 3.1 General mechanism A: parent-connection grouping (MPTCP = first user)

**BPF.** In `trace_sock` / `trace_cwnd` (`tcbee.bpf.c:413-486`), only when the new rodata flag `MPTCP_TAG` is set:
```c
if (MPTCP_TAG && bpf_core_field_exists(tp->is_mptcp) && BPF_CORE_READ(tp, is_mptcp)) {
	struct mptcp_subflow_context *ctx = BPF_CORE_READ(icsk, icsk_ulp_data);
	struct sock *msk = BPF_CORE_READ(ctx, conn);
	rec->conn_id = BPF_CORE_READ((struct mptcp_sock *)msk, token);
}
```
- **Cost.** With `-M` off, the verifier prunes the branch. With `-M` on, plain TCP pays one bool load and one branch. MPTCP subflows pay two or three probe reads.
- **Why not the helper.** The manual CO-RE chain works on every MPTCP kernel (5.6+), whereas `bpf_skc_to_mptcp_sock` needs 5.19+. It also reaches the subflow ctx, so `subflow_id`/`backup` can be read when needed.
- **Record layout.** `conn_id` (u32) goes into the existing 4-byte tail padding of `sock_trace_entry` (offset 172) and `cwnd_trace_entry` (offset 60). In-memory sizes stay the same (176/64). The on-disk size grows by 4 B because bincode drops padding.
  - Process schema sizes: sock 160→164, cwnd accordingly.
- **Generic naming.** Name it `conn_id` in records and storage, not `mptcp_token`. The kind of parent is stored once per connection in storage.

**Identity caveats** (to discuss, D2):
- `msk->token` is the *local* token. The peer's records carry a different token, the one we see as `remote_token`. Joining both hosts' traces needs the key/token pair from the PM events (3.3).
- Tokens can be reused after close. The processor scopes a token to the lifetime between the CREATED and CLOSED events, and falls back to time-gap heuristics if PM events were not recorded.

**Storage** (`ts-storage/src/schema.rs`, `SCHEMA_VERSION` 2→3):
- `connections(conn_pk, kind TEXT, local_token, remote_token, created_ts, closed_ts, fallback BOOL, ...)`
- `flow_parent(flow_id, conn_pk, subflow_id, local_id, remote_id, backup)`
- Optionally, a connection-level pseudo-flow for msk records: `flows` row with `l4proto = 262` (IPPROTO_MPTCP, used as a sentinel) and the initial subflow's tuple. The existing `UNIQUE(src,dst,sport,dport,l4proto)` and all per-flow series code keep working unchanged.

### 3.2 General mechanism B: protocol-level record types

Connection-level records, each on its own ring buffer and each under 256 B (the `PackedLayout` limit, `writer.rs:532`):

| Record | Hook (primary → fallback) | Fields |
|---|---|---|
| `mptcp_ack_entry` | fexit `ack_update_msk` → fentry `mptcp_incoming_options` (global, reads msk state after the fact) | time, conn_id, ssk sport/dport (or subflow_id), msk `snd_una`, `snd_nxt`, `write_seq`, `wnd_end`, `bytes_acked`, `bytes_retrans` |
| `mptcp_sched_entry` | fentry `mptcp_subflow_set_scheduled(subflow, true)` (works with any scheduler) → fexit `mptcp_subflow_get_send`; optional detail mode: tp_btf `mptcp_subflow_get_send` per candidate | time, conn_id, chosen subflow_id/sport, chosen subflow cwnd/inflight/pacing (+ in detail mode: per-candidate active, backup, snd_wnd, pace, ratio) |
| `mptcp_rcv_entry` | fentry `mptcp_data_queue_ofo` + fexit `__mptcp_move_skbs_from_subflow` | time, conn_id, ssk, `ack_seq`, OFO non-empty, OFO end_seq (span), inserted skb's map_seq/end_seq |
| `mptcp_retrans_entry` | fentry `__mptcp_retrans` / `__mptcp_retransmit_pending_data` (+ which subflow is chosen through `mptcp_sched_get_retrans` fexit) | time, conn_id, trigger, DSN range, target subflow |

**Derived metrics** are computed in the processor or as viz plugins, not in BPF:
- **HoL delay:** time from an OFO insertion until `ack_seq` passes its end_seq.
- **Per-subflow traffic share.**
- **Window-limited vs cwnd-limited periods:** msk `wnd_end - snd_nxt` against the subflows' cwnd.

**Rates.** ack and rcv records fire about once per incoming DSS packet, the same order as `sock_trace_entry`. sched records fire once per push. All of them stay opt-in sub-modes so the 400G overhead story stays clean.

### 3.3 Path-manager / lifecycle events: `mptcp_pm_entry` (small ring buffer)

- **Primary hook:** fentry `mptcp_event(type, msk, ssk)`. It covers CREATED, ESTABLISHED, CLOSED, SUB_ESTABLISHED, SUB_CLOSED and SUB_PRIORITY, and fires even when no netlink listener is attached. `enum mptcp_event_type` is identical on 6.8 and 7.2.
- **Additional hooks:**
  - `mptcp_pm_add_addr_received`, `mptcp_pm_announce_addr`, `mptcp_pm_rm_addr_received`
  - `mptcp_pm_mp_prio_received`
  - fexit `__mptcp_subflow_connect` (join attempt + return code)
  - `__mptcp_close_ssk`, `mptcp_subflow_reset`
  - `mptcp_pm_mp_fail_received`
  - `mptcp_pm_nl_subflow_chk_stale`
- **Fallback:** fexit `subflow_finish_connect` / `subflow_syn_recv_sock`, checking `!mp_capable`. A later fallback is detected from a `msk->flags` snapshot in the ack records (bit number to be verified per kernel).
- **Fields:** time, event type, conn_id (local token), remote token, ssk tuple, subflow_id, local_id, remote_id, backup, addr_info (for ADD/RM_ADDR), error code.
- **Processor use.** Fills `connections` and `flow_parent`, and scopes token lifetimes. That makes this record the backbone of the grouping, so it should come early.

### 3.4 Userspace and pipeline changes (touch list)

Code-agent findings with file:line:
- **record**:
  - `records.h` (51-98, 192-204): new fields/records and size asserts.
  - `config.h`: `MPTCP_TAG` and sub-mode rodata flags.
  - vmlinux compact header: add `is_mptcp`, `icsk_ulp_data`, `mptcp_sock`, `mptcp_subflow_context`, `mptcp_addr_info`, `mptcp_skb_cb`, plus the `mptcp_pm_data` subset with an `___old` flavor for `subflows` / `extra_subflows`.
  - `maps.h` and `counters.h`: ring buffers, `RB_*`, `RB_COUNT`, `rb_owned`, `TCBEE_STATS_LEN`.
  - `stats.rs` (`RINGBUFS`).
  - `tcbee-common/build.rs` RECORDS and `prog_bindings.rs`.
  - `tcbee-trace` `TraceFile`.
  - New `probes/mptcp.rs` modelled on `bbr.rs`, with `retarget()` candidates and autoload toggles. One rejected program fails the whole skeleton load, so add a retry path like BBR's (`ebpf_runner.rs:318-335`).
  - `main.rs` flag `-M/--mptcp[=tag,pm,ack,sched,rcv,retrans]`.
- **process**:
  - `bindings/sock.rs`, `cwnd.rs` (+4 B).
  - New `bindings/mptcp_*.rs` and `bindings/mod.rs` (46-74).
  - Connection assembly pass.
  - Fixtures/tests.
- **ts-storage**: the schema above; `Store` API for connections and `flows_of(conn)`.
- **viz**:
  - Connection grouping in `flow_table.rs`.
  - N-flow connection view (`tab_multi_flow.rs` is hard-coded to two flows).
  - Plugin API extended to multi-flow inputs. Today `compute(&[SeriesData])` is scoped to one flow.

**Observation relevant to the paper's extensibility claim.** Adding one record type currently touches about 12 places, including a *hand-copied* struct in tcbee-process (FIXME at `prog_bindings.rs:6-7`) with a hard-coded on-disk size. Before or alongside MPTCP, a refactor would let a single record declaration drive bindgen, the process decoder and the schema. That refactor makes "adding a mechanism = one record + one hook + one decoder" true, and the MPTCP diff then becomes the evidence for it. See D1.

---

## 4. Testing and validation (single 400G link, no heterogeneous hardware)

Correctness needs several subflows and deterministic triggers. Heterogeneous hardware is not required.

1. **Functional tests in network namespaces / Mininet.**
   - Add `TwoPathTopo` to `testing/topology.py`: two links, two IPs per host, `ip mptcp endpoint add <ip2> dev <if> subflow`, `ip mptcp limits set subflow 2 add_addr_accepted 2`.
   - Per-path `tc` (HTB rate, netem delay/loss) to make the paths heterogeneous.
   - Traffic generator: local iperf3 3.16 has no MPTCP option. Use `mptcpize` (mptcpd package), a newer iperf3 **[≥3.17 has `--mptcp`: verify]**, or a small Python sender with `socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)`.
2. **Deterministic triggers**, each expected to appear exactly once at the right time:
   - add or remove an endpoint
   - toggle backup
   - 100% netem loss on one path, to force reinjection, stale detection and switch-over
   - strip MPTCP options with nft, to force a fallback
3. **Truth sources**, in the style of E1 (`evaluation/evalkit/truth.py`):
   - `ip -ts mptcp monitor` against PM events
   - `nstat` MPTcpExt counters (MPJoin*, AddAddr, MPPrio, MPFallback*, MPTCPRetrans, OFOQueue) against event counts
   - `MPTCP_INFO` / `MPTCP_FULL_INFO` / `ss -tiM` samples against ack-record values
   - TCBee `-h` headers (DSS options on the wire)
4. **Kernel selftests** (`tools/testing/selftests/net/mptcp/{mptcp_join,simult_flows,mptcp_connect}.sh`), run with TCBee attached. They provide many PM edge cases and asymmetric netns topologies for free, and reviewers recognise them.
5. **400G testbed** (scalability, homogeneous paths):
   - Secondary IPs, VLAN subinterfaces or VFs on the one link, so each subflow gets its own 4-tuple and is spread by RSS. If the two Pennywise ports in `notes.md` are separate physical ports, that gives two real paths.
   - Metrics:
     - overhead of `-k` vs `-k -M` on **plain TCP** (should be about 0)
     - overhead on MPTCP with N subflows and M connections
     - per-program `run_time_ns/run_cnt` (`evalkit/counters.py:186`)
     - drops per ring buffer
   - Bonus result: upstream MPTCP vs TCP at 400G (relates to #592).
6. **Case study** (emulated heterogeneous paths, lower rate): reproduce the default scheduler's HoL blocking under asymmetric RTT. Show from inside the kernel which subflow was chosen, how the OFO span grows, what HoL delay results, and when reinjection happens. Optionally reproduce #581 (fail-back under-use).

Kernel matrix: 6.8 (testbed, Ubuntu 24.04) and 7.x (compact header source). Optionally an older 5.15 to show CO-RE portability (no `subflow_id` before 6.5, so fall back to (conn_id, 4-tuple)).

---

## 5. Phases

| Phase | Content | Paper value |
|---|---|---|
| 0 | (Optional, recommended) record-registry refactor: one declaration drives bindgen + process decoder + schema | Makes the extensibility claim concrete and measurable |
| 1 | Grouping: `conn_id` tag + PM/lifecycle events + `connections`/`flow_parent` tables + netns test topology | Minimum for "TCBee groups MPTCP subflows" and correct lifetimes |
| 2 | Connection-level ack + rcv/OFO records + derived HoL delay | Supports the HoL case study, #635 |
| 3 | Scheduler decision stream (+ detail mode), retrans records | #581 / scheduler analysis, learned-scheduler data |
| 4 | Viz: connection view, multi-flow plugins | Figures |
| 5 | Evaluation: plain-TCP overhead delta, MPTCP scaling at 400G, validation against nstat/monitor/selftests, case study | Evaluation section |

---

## 6. Decisions to discuss

- **D1 – Refactor first?** Unifying record declarations (phase 0) costs time but turns "extensible" from a claim into a measurable property (files/lines touched per new mechanism). Recommendation: yes. Do at least the tcbee-process half (drop the hand-copied structs).
- **D2 – Connection identity.** Options:
  - (a) local token (u32) plus processor-side lifetime scoping from PM events (recommended)
  - (b) msk pointer hash (unique while alive, but meaningless across hosts)
  - (c) the 64-bit keys

  Cross-host joining of client and server traces would use local/remote token pairs from PM events.
- **D3 – Subflow identity in hot-path records.** Recommendation: keep only `conn_id` in `sock_trace_entry` (it fits in padding at zero memory cost) and take `subflow_id`/`local_id`/`remote_id`/`backup` from PM events via `flow_parent`. Alternative: a `u16 subflow_id` in the 2 free header bytes, which costs one more probe read per subflow event.
- **D4 – Granularity of `-M`.** One flag with sub-modes (`tag,pm` default; `ack,rcv,sched,retrans` opt-in) so the overhead of each part can be measured separately.
- **D5 – Kernel floor.** The manual CO-RE chain works on all MPTCP kernels. Is 5.15 worth testing, or are 6.8 + 7.x enough?
- **D6 – msk as pseudo-flow (`l4proto=262`)** vs a separate `connections`-keyed series table. The pseudo-flow reuses all existing series and plot code, at the price of a sentinel protocol number.

---

## 7. Remaining open items to verify during implementation
- That `tcp_rcv_established` / `__tcp_transmit_skb` fentry fire for subflows (expected yes) and that `tcp_probe` does too.
- The `MPTCP_FALLBACK_DONE` bit index on 6.8 vs 7.x, and the 6.16+ fallback rework.
- Whether the verifier accepts direct loads from `skb->cb` for `mptcp_skb_cb` in fentry (fallback: `bpf_probe_read_kernel`).
- Whether `ack_update_msk`, `mptcp_data_queue_ofo` and `__mptcp_move_skbs_from_subflow` (static) are still out of line on the 7.x kernel. Choose `retarget()` fallbacks if not.
- Whether `mptcp_event()` is reached for all event types when no netlink listener exists, i.e. the listener check is inside the function, not at the call sites. Check per kernel.
- The iperf3 version that has `--mptcp`.
