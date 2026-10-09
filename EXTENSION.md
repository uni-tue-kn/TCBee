# TCBee extension research: MPTCP, other TCP mechanisms, research fit

> **Update:** the MPTCP part is superseded by `MPTCP-PLAN.md`, which carries verified facts. Corrections to the claims below: `bpf_skc_to_mptcp_sock` exists since 5.19 and can be called from tracing programs. `mptcp_pm_ops` landed in 6.15, but only as an in-kernel abstraction (no BPF path managers in mainline). No coupled CCAs, BPF schedulers or MPTCP kfuncs are in mainline. `is_mptcp` is a plain bool, not a bitfield. The LeoCC venue (SIGCOMM 2025) is confirmed. The tcp_probe module removal in 4.16 and the `tcp_bbr_info` contents are confirmed.

Purpose: handover for an agent who extends TCBee, or who writes the novelty and use-case part of the TCBee paper. Collected 2026-10-09. The research combines a web search with a reading of `tcbee-record`.

**Confidence markers.** Every claim carries one:
- **[V]** verified against a source during the research (URL given)
- **[M]** from model memory and not re-checked; verify it before citing it or depending on it

## 0. What TCBee records today (read from the code)

eBPF code: `tcbee-record/tcbee/src/bpf/tcbee.bpf.c`. Record layouts: `tcbee-record/tcbee/src/bpf/records.h`. Private CCA structs: `tcbee-record/tcbee/src/bpf/cc_structs.h`. The Rust mirror of the records is `tcbee-record/tcbee-common/src/records.rs`. Changing a record means also changing `tcbee-process` and `ts-storage`.

| Flag | Hooks | Record |
|---|---|---|
| `-h` | `tc` ingress/egress | `tcp4/6_packet_trace` (seq, ack, window, flags) |
| `-t` | `tracepoint/tcp/tcp_probe`, `tcp_retransmit_synack`, `tcp_bad_csum` | `tcp_probe_entry` etc. |
| `-k` | `fentry/__tcp_transmit_skb`, `fentry/tcp_rcv_established` | `sock_trace_entry` |
| `-w` | same as `-k` | `cwnd_trace_entry` (snd_cwnd only) |
| `-a` | `fentry/cubictcp_cong_avoid`, `cubictcp_cwnd_event`, `bbr_main`, `bbr_cwnd_event` | `cubic_trace_entry`, `bbr_trace_entry` |

Every socket record starts with `TCBEE_SOCK_HEADER`, filled by `fill_header()`. The header holds time, the v4 addr pair or the v6 addresses, sport, dport and family.

### Gaps in the current records

These matter for the research topics in section 3.

- `sock_trace_entry` has no `srtt`. Only `tcp_probe_entry` has it.
- `sock_trace_entry` also lacks:
  - `delivered` / `delivered_ce` and the delivery rate
  - `icsk_ca_state` (Open/Disorder/CWR/Recovery/Loss)
  - `app_limited`
  - the chrono stats (`chrono_type`, `chrono_stat[]`), which show busy, rwnd-limited and sndbuf-limited time
  - `packets_out`, i.e. inflight
  - ECN and AccECN fields
  - `tcp_wstamp_ns` (EDT pacing)
- `bbr_trace_entry` has no `mode` (STARTUP/DRAIN/PROBE_BW/PROBE_RTT), `pacing_gain`, `cwnd_gain`, `cycle_idx` or bandwidth estimate. Most of these are bitfields in `struct bbr`, so they need `BPF_CORE_READ_BITFIELD*`. The BBR evaluation papers are missing exactly the phase.
- The only CCAs covered are CUBIC and BBR (v1, mainline). Nothing records DCTCP, Prague, BBRv3 or struct_ops BPF CCAs.
- MPTCP subflows are recorded as unrelated TCP flows. Nothing links them to their MPTCP connection.

## 1. MPTCP

### Kernel facts
- **[V]** Upstream MPTCP (since 5.6) runs each subflow as an ordinary `tcp_sock`. The connection-level socket is `struct mptcp_sock` (msk), which holds DSN, data ACK, `snd_una`, `wnd_end` and the receive out-of-order queue. Each subflow has a `struct mptcp_subflow_context`, reached from the subflow via `icsk_ulp_data`; its `conn` field points to the msk. Both structs are in `net/mptcp/protocol.h`.
- **[V]** `include/trace/events/mptcp.h` (Geliang Tang, 2021) defines these tracepoints:
  - `mptcp_subflow_get_send`: active, free, snd_wnd, pace, backup, ratio
  - `mptcp_sendmsg_frag` and `get_mapping_status`: DSS mapping dumps
  - `ack_update_msk`: data_ack, old/new snd_una, new_wnd_end, msk_wnd_end
  - `subflow_check_data_avail`

  These are single-point event dumps. They do not join connection-level state to subflow `tcp_sock` state.
  - Header: https://code.amethyst.name/public-mirrors/linux/src/branch/master/include/trace/events/mptcp.h
  - Series: https://patchwork.kernel.org/comment/24121639
  - A 2024 fix changed the backup computation: https://lkml.iu.edu/hypermail/linux/kernel/2407.3/03441.html
- **[V]** `struct mptcp_sched_ops` with `get_subflow` is upstream, along with the `net.mptcp.available_schedulers` sysctl. The `bpf_mptcp_sched_ops` series (first, rr, bkup, red, burst) was still iterating in mptcp-next as of June 2026 and is not in mainline.
  - https://patchew.org/MPTCP/cover.1782120674.git.tanggeliang@kylinos.cn/
  - https://patchew.org/MPTCP/cover.1739788598.git.tanggeliang@kylinos.cn/
- **[V]** `struct mptcp_pm_ops` (BPF path managers via struct_ops) and the `net.mptcp.available_path_managers` sysctl were merged in net-next in March 2025. The release is probably 6.15 but unconfirmed. https://lkml.iu.edu/hypermail/linux/kernel/2503.1/06864.html
- **[M]** A `bpf_skc_to_mptcp_sock` helper exists since about 5.19. `sk_is_mptcp(sk)` checks `tcp_sk(sk)->is_mptcp`.
- **[M]** Coupled CCAs (LIA, OLIA, BALIA) are not upstream. Upstream subflows run uncoupled CCAs.

### Existing tools and their limits
- **[V]** mptcpanalyzer works offline on pcaps via tshark and plots DSN/DACK and one-way delay. The Haskell version is stale.
  - https://pypi.org/project/mptcpanalyzer/0.2.dev0
  - https://hackage.haskell.org/package/mptcpanalyzer
- **[M]** mptcptrace (Hesmans & Bonaventure, ca. 2014) works offline on pcaps.
- **[M]** `ss -tiM` shows `mptcp_info` snapshots.
- **[M]** `ip mptcp monitor` shows path-manager netlink events only.
- **[M]** mptcpd is a userspace path manager.
- None of these shows kernel-internal subflow state over time.

### Implementation plan
1. **Grouping (smallest useful step).** In the existing `-k`/`-w` hooks, when the socket is an MPTCP subflow:
   - Read `mptcp_subflow_context` from `icsk_ulp_data`.
   - Record the msk token, or `conn` as a cookie, and the subflow id.
   - Add those fields to the socket record, either as a new MPTCP-only record type or as optional header fields. Keep v4/v6 size discipline (see commit c246c20).
   - In `tcbee-process`, add a table that maps subflow flows to an MPTCP connection.
   - In `tcbee-viz`, plot subflows of one connection together.
   - Check that `bpf_core_field_exists` and type existence handle kernels without MPTCP.
2. **Connection-level record.** Hook the send scheduler and the data-ACK path. One option is the existing tracepoints `mptcp:mptcp_subflow_get_send` and `mptcp:ack_update_msk`; their fields are stable, but they may be compiled out. The other is fentry on the matching functions; check for inlining on the target kernel.
   - Record the msk fields `snd_una`, `snd_nxt`, `write_seq`, `wnd_end` and `bytes_acked/received`, the rcv out-of-order queue length, and the chosen subflow.
3. **Path-manager events.** Record subflow established and closed, ADD_ADDR/RM_ADDR, and backup-flag changes.
4. **Testing.** Extend the Mininet setup in `testing/` with a two-path topology, `sysctl net.mptcp.enabled=1`, `ip mptcp endpoint add ... subflow` and `mptcpize run iperf3`.

### Research use cases
- **Evaluation harness for BPF schedulers and path managers** as they land. They are in development now, and nobody has a tool for this.
- **Scheduler head-of-line blocking and receive-side reordering over heterogeneous paths.** BLEST (Ferlin et al., IFIP Networking 2016, https://dl.ifip.org/db/conf/networking/networking2016/1570234725.pdf) and similar work used the out-of-tree kernel. Little exists for upstream MPTCP. [V]
- **Fairness of uncoupled subflow CCAs** at shared bottlenecks.
- **5G ATSSS (MPTCP proxy at the UPF)**. Many ATSSS studies still use the legacy v0.9x kernel. [V]
  - "An Implementation and Evaluation of MPTCP-based 5G ATSSS", MITA 2024: https://www.s-lab.nd.chiba-u.jp/achievements/abst.php?paper=917
  - Amend & Rakocevic, "Cost-efficient multipath scheduling of VoD traffic for the 5G ATSSS splitting function", Computer Networks 242, 2024: https://openaccess.city.ac.uk/id/eprint/32424/

## 2. Other TCP mechanisms worth tracing

| Mechanism | Status | What to record | Confidence |
|---|---|---|---|
| BBRv3 | Not in mainline; github.com/google/bbr v3 branch (Cardwell, bbr-dev, Mar 2025) | mode, gains, `bw_hi/lo`, `inflight_hi/lo`. `tcp_info`/BBRINFO exposes only bw, min_rtt and gains. | [V] https://groups.google.com/g/bbr-dev/c/4vwZGw0nxdQ/m/zb-hfJjuAwAJ, https://github.com/google/bbr/blob/v3/README.md; BBRINFO contents [M] |
| AccECN (RFC 9768) | Core merged into net-next around Sep 2025, so Linux 6.18 | AccECN negotiation result, received CE/ECT byte and packet counters | [V] https://lwn.net/Articles/1037055 |
| L4S | DualPI2 qdisc in 6.17; TCP Prague out of tree (github.com/L4STeam/linux) | Prague `alpha`, CE fraction, cwnd reductions | [V] https://datatracker.ietf.org/meeting/124/materials/slides-124-iccrg-l4s-and-prague-update-00 |
| struct_ops BPF CCAs | Since 5.6 (bpf_cubic and bpf_dctcp in selftests); Meta extended `cong_control` in 2024 | Same state as the native CCAs, to compare BPF and native implementations | [V] https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/tcp_congestion_ops, https://yhbt.net/lore/bpf/20240501074338.362361-1-miaxu@meta.com/T |
| Loss recovery: RACK-TLP (RFC 8985), PRR, ca_state | Mainline | `rack.*` fields, `prr_delivered/out`, ca_state transitions | [M] |
| Pacing / EDT, TSO autosizing | Mainline | `tcp_wstamp_ns`, `sk_pacing_rate`, `gso_segs` | [M] |
| Receive autotuning | Mainline. Tracepoint `tcp:tcp_rcvbuf_grow` (Dumazet); rcv_ssthresh, window_clamp and rcv_wnd added Oct 2025 | `rcvq_space`, `window_clamp`, `rcv_ssthresh` | [V] https://lkml.iu.edu/2510.3/12469.html |
| Devmem TCP | 6.12 | The TCP angle on AI/ML traffic (GPU/TPU payloads) | [V] https://docs.kernel.org/6.12/networking/devmem.html |
| PLB | 6.2 (IPv6, off by default) | Flowlabel repath events | [V] https://github.com/google/plb |
| TCP-AO | 6.7 | Niche | [V] https://www.phoronix.com/news/Linux-6.7-Networking |

**Generic idea with more novelty than per-CCA code.** Dump the CA-private area of `inet_connection_sock`, `icsk_ca_priv`, as raw bytes. Key the dump by `icsk_ca_ops->name`. Decode it in `tcbee-process` with the kernel or module BTF. That covers BBRv3, Prague, DCTCP and struct_ops CCAs without new eBPF code for each one.

**Motivation to cite.** [V] Breno Leitao (Meta) proposed a `tcp_cwnd_reduction_tp` tracepoint in 2025 because "Meta had been hooking this function with BPF, which breaks with inlining" (https://lkml.iu.edu/hypermail/linux/kernel/2502.1/10328.html). Hyperscalers already trace TCP internals with eBPF, and hooking functions directly is fragile. A note for the implementation: prefer stable hook points and use CO-RE field-existence checks.

## 3. Current research topics and how TCBee fits

- **BBRv3 fairness and RTT bias.** These papers infer BBR phases from outside the host. TCBee could provide kernel phase traces, which first needs the BBR record fix in section 0. [V]
  - Zeynali et al., "Promises and Potential of BBRv3", PAM 2024 best paper: https://inet-bbrv3eval.mpi-inf.mpg.de/
  - Bless, Lihotzki & Zitterbart, IFIP Networking 2025: https://dl.ifip.org/db/conf/networking/networking2025/1571125683.pdf
  - arXiv 2505.07741 and arXiv 2510.22461.
- **Identifying CCAs in the wild.** These tools need sender-side ground truth for training and validation, which TCBee can already provide. [V]
  - CCAnalyzer, Ware et al., SIGCOMM 2024: https://par.nsf.gov/servlets/purl/10545455
  - Nebby, SIGCOMM 2024 poster: https://comp.nus.edu.sg/~ayush/pdfs/sigcomm24-poster-nebby.pdf
  - VCCAnalyzer, CoNEXT 2025: https://www.cs.swarthmore.edu/~rware/assets/pdf/kaneria-conext2025.pdf
- **Learned congestion control.** TCBee could serve as a training-data recorder; Sage learns offline from kernel traces of existing CCAs. TCBee covers this today.
  - Sage, SIGCOMM 2023 [M]
  - Orca, SIGCOMM 2020 [M]
  - Mutant, NSDI 2025 [V]
  - PolicyCache, NSDI 2026 (per an HKUST page) [V]
- **L4S deployment.** TCBee needs ECN and AccECN fields first. [V]
  - Comcast field trials: https://datatracker.ietf.org/meeting/119/materials/slides-119-maprg-l4snqb-field-trial-measurements-livingood-00
  - Apple L4S results, IETF 123: https://datatracker.ietf.org/meeting/123/materials/slides-123-tsvwg-l4s-with-apple-devices-00
  - Partial-deployment study, arXiv 2411.10952.
- **LEO/Starlink congestion control.**
  - Lai et al., HotNets 2024: https://conferences.sigcomm.org/hotnets/2024/papers/hotnets24-79.pdf [V]
  - LeoCC: venue said to be SIGCOMM 2025, unconfirmed. APNIC blog: https://blog.apnic.net/2025/12/03/mind-your-congestion-control-in-the-leo-satellite-internet/
  - LEO reordering, arXiv 2405.07627 [V]
- **QUIC vs TCP receive-side bottlenecks.** "QUIC is not Quick Enough over Fast Internet", WWW 2024: https://arxiv.org/abs/2310.09423 [V]. TCBee's receive-side fields (rcv_space, rcv_rtt) are relevant.
- **Reproducibility.** Weyulu, PhD thesis, Saarland 2025. Pantheon is unmaintained: https://ospo.ucsc.edu/project/osre24/nyu/congestion-control/ [V]. TCBee could be part of an evaluation workflow.
- **eBPF transports.** eTran, NSDI 2025: https://www.usenix.org/system/files/nsdi25-chen-zhongjie.pdf [V]
- **AI cluster traffic.** Mostly RDMA (MLCC, arXiv 2402.09589). This fits TCBee poorly except through devmem TCP.

## 4. Comparable tools: related-work positioning

| Tool | Limitation compared with TCBee | Confidence |
|---|---|---|
| `tcp_probe` module, then the `tcp:tcp_probe` tracepoint | Module removed in 4.16 [M]. The tracepoint fires only in `tcp_rcv_established` with a fixed field set and no in-kernel filtering; people kprobe `tcp_rcv_established` to get more. | [V] https://lkml.iu.edu/hypermail/linux/kernel/2403.0/03699.html |
| M-Lab tcp-info | Polls all sockets via inet_diag and writes JSONL. Misses events between polls; each poll costs O(sockets). The closest at-scale comparator. | [V] https://pkg.go.dev/github.com/m-lab/tcp-info |
| Edgio xtcp | Samples sockets through inet_diag | [V] https://beta.pkg.go.dev/github.com/Edgio/xtcp |
| ePPing (Sundberg et al., PAM 2023) | Passive RTT only, no sender state. Over 1 Mpps per core. | [V] https://research.redhat.com/blog/publication/efficient-continuous-latency-monitoring-with-ebpf |
| Netflix Flow Exporter | eBPF flow logs (who talks to whom), not CC state | [V] https://noise.getoto.net/2021/06/07/how-netflix-uses-ebpf-flow-logs-at-scale-for-network-insight/ |
| bcc / bpftrace (tcplife, tcpretrans, tcpcong) | Ad-hoc, per-event text output, no structured high-rate trace | [M] |
| tcptrace, Wireshark, mptcptrace | Packet-level; must infer cwnd and phase | [M] |

For justifying hook choice and overhead: "Demystifying Performance of eBPF Network Applications", CoNEXT 2025: https://cs.nyu.edu/~apanda/assets/papers/conext25.pdf [V]

**Novelty check result.** The search found no 2024–2026 peer-reviewed paper on eBPF recording of full per-flow `tcp_sock` state at high event rates. Before claiming novelty, check the CoNEXT 2025 and IMC 2025 proceedings.

## 5. Suggested paper framing

1. The first scalable recorder of joint MPTCP connection and subflow kernel state. It can serve as the evaluation harness for upstream BPF schedulers and path managers and for ATSSS. **Needs section 1.**
2. Sender-side ground truth for CCA identification and training data for learned CCAs. **Works today.**
3. Visibility into CA-private state (BBRv3 phases, Prague) that `tcp_info` cannot expose. **Needs the BBR record fix or the generic `icsk_ca_priv` dump.**
4. AccECN and L4S counters on 6.18+ kernels. **Needs the ECN fields.**
5. Motivation: hyperscalers already hook TCP internals with ad-hoc BPF (the Meta case), so a robust generic tool is needed.

## 6. Suggested order of work

1. Low effort, high value:
   - add `srtt`, `delivered`, `ca_state`, `packets_out`, `app_limited` and the chrono stats to `sock_trace_entry`
   - add `mode`, `pacing_gain` and `cwnd_gain` to `bbr_trace_entry`
2. MPTCP grouping (section 1, step 1).
3. Generic `icsk_ca_priv` dump with BTF decoding in `tcbee-process`.
4. MPTCP connection-level record and path-manager events.
5. ECN/AccECN fields, guarded by `bpf_core_field_exists` for kernels before 6.18.

For every record change, update all of these together: `records.h`, `tcbee-common/src/records.rs`, `tcbee-process` decoding, the `ts-storage` schema and README, and the compact `vmlinux` header in `tcbee-record/tcbee/src/bpf/vmlinux` (see `tcbee-record/README.md`: "Update the compact header when the BPF program reads new kernel fields"). The per-event cost of `-k` is measured in `evaluation/`. Re-run it after you widen the records.
