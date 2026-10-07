# tcbee-record performance notes

What was changed for per-event cost, what was only evaluated, and how to measure both.
Nothing here has been measured on a running kernel yet (no root on the dev machine):
kernel-side numbers are static counts from the compiled object, userspace numbers are
micro-benchmarks. The testbed runs from `EVALUATION.md` (E2/E3) are the real check.

## Implemented

| # | Change | Commit |
|---|--------|--------|
| 1 | Socket, CUBIC and BBR fields read with direct BTF loads via `bpf_skc_to_tcp_sock()` instead of one `bpf_probe_read_kernel()` per field | `41a3b26` |
| 2 | Records reserved in the ring buffer and filled in place, no stack copy | `225cb66` |
| 3 | Plain (non-atomic) counter adds where exactly one non-nesting program writes a slot | `fc4d994` |
| 3b | Remaining atomic adds emitted as `lock add` (BPF_XADD), not BPF_FETCH | `7fc78bd` |
| 10 | TC reads headers straight from linear packet data, `bpf_skb_load_bytes()` only as fallback | `949da73` |
| 4 | Writer copies each record as precomputed byte ranges instead of bincode/serde | `5f542be` |
| – | `records_written` kept after a writer error (was reported as 0) | `2ea0f2a` |
| – | BBRv1-only `lt_*` fields read only if they exist (BBRv3 / out-of-tree `struct bbr` load) | `093873b` |
| 9 | One ring buffer per CPU; `hook_seq` in every record restores the order of a flow's events at a hook | branch `per-cpu-ringbuf` |

The on-disk format, the STATS slot layout, map names, program names and CLI are unchanged.

### Kernel side: before / after

Object built with the same flags as `build.rs` (clang 22, `-O2 -g -target bpf`).
`probe_read` = `call 0x71` sites, `insns` = static instruction count. The *hot* columns are
built with the rodata config folded to the headless defaults (no filter, no flow tracking),
i.e. the code the verifier keeps for an evaluation run; they still include error branches
and both arms of load-time CO-RE checks, so they are an upper bound of the executed path.

| program | probe_read | hot probe_read | hot insns | helper calls / event (success path) |
|---|---|---|---|---|
| `sock_sendmsg` / `sock_recvmsg` | 41 → 0 | 31 → 0 | 898 → 228 | 37 → 7 |
| `cwnd_sock_*` | 19 → 0 | 9 → 0 | 338 → 155 | 14 → 6 |
| `cubic_*` | 32 → 0 | 22 → 0 | 607 → 135 | 27 → 6 |
| `bbr_*` | 30 → 0 | 20 → 0 | 609 → 159 | 25 → 6 |
| `tc_*_packet_tracer` | 0 | 0 | 429 → 255 | 8 → 5 (3 `skb_load_bytes` gone when headers are linear) |
| `tcp_probe` | 2 → 2 | 2 → 2 | 466 → 148 | unchanged |
| `tcp_retransmit_synack` | 4 → 4 | 4 → 4 | 264 → 160 | unchanged |
| `tcp_bad_csum` | 2 → 2 | 2 → 2 | 138 → 91 | unchanged |

Helper calls per event count the STATS lookups (attempt, handled, bytes for `sock_*`),
`ktime`, `ringbuf_reserve/submit`, `skc_to_tcp_sock` and the probe reads. Newer kernels
inline the PERCPU_ARRAY lookups, so the real call count is lower on both sides.

Most of the instruction drop is item 2: the old `submit()` did
`__builtin_memcpy(slot, rec, size)` through `void *`, which clang lowers to one byte
store (plus shifts) per record byte: 176 byte stores for `sock_trace_entry`, 120 for
`tcp_probe_entry`, 88 for the TC records. Records are now zeroed and written with 8-byte
stores through the typed pointer.

Reproduce (from `tcbee/src/bpf`):

```sh
clang -Wall -fms-extensions -Wno-microsoft-anon-tag -Ivmlinux/x86_64 -g -O2 -target bpf \
      -D__TARGET_ARCH_x86 -c tcbee.bpf.c -o t.o
llvm-objdump -d t.o | awk '/>:$/{n=$2} /call 0x71$/{c[n]++} END{for(k in c) print k, c[k]}'
# hot variant: same after sed -i 's/const volatile/static const/; s/FLOW_TRACKING = 1/FLOW_TRACKING = 0/' config.h
bpftool -d gen min_core_btf /sys/kernel/btf/vmlinux out.btf t.o   # all non-BBR relocations resolve
```

BBR relocates against `tcp_bbr` module BTF, which `min_core_btf` cannot take. Checked by
hand against `tcp_bbr.ko` of 7.2: every field read is a plain `u32`/`u64`, none is a
bitfield, `cycle_mstamp` is 8-byte aligned inside `icsk_ca_priv`.

### Item 1: direct loads (design decision)

The fentry argument `sk` is a BTF pointer to `struct sock`; the verifier allows direct loads
only within that type, so `sk->__sk_common.*`, `sk->sk_pacing_rate` and `skb->len` are
loaded directly. `tcp_sock` fields lie beyond `struct sock` and need a pointer of that type:

- `bpf_skc_to_tcp_sock()` (helper, kernel 5.9, allowed in tracing programs): one cheap call
  (`sk_fullsock` + protocol check), returns NULL for non-full / non-TCP sockets. **Chosen.**
- `bpf_core_cast()` / `bpf_rdonly_cast` kfunc: no helper, but kernel 6.2. Rejected because
  of the minimum kernel; the saving over one cheap helper call is small.

The CUBIC/BBR state is read through `tp->inet_conn.icsk_ca_priv` cast to the flavored local
struct. libbpf still relocates the field offsets against the module's `struct bbr` /
`struct bictcp`; the verifier only checks the loads against the `u64` array
`icsk_ca_priv` in vmlinux's `tcp_sock`, so module BTF is not needed for verification.

Semantics: a direct load that faults yields 0 (exception table) instead of failing like
a probe read. Previously any failed read counted the event as `error`; now only a NULL
`tcp_sock` does. With the socket pointer from these hooks no load faults in practice.
Ports can no longer fail to read, so `sock_ports_filter()`'s error path is gone.
`skc_v6_*` are read behind `bpf_core_field_exists()` (kernels without `CONFIG_IPV6`).

Tracepoints keep `bpf_probe_read_kernel()` for the address arrays: copying them directly
compiles to `ctx + CO-RE offset` and loads through that, and the verifier rejects loads
through a modified ctx pointer. Single scalar fields (`ctx->sport`) were already direct.

### Item 3: plain counter adds (design decision)

Plain `*counter += v` for the slots of `RB_SOCK_*`, `RB_CWND_*` and the byte counters
(each written by one fentry program), and of the three tracepoint ring buffers:

- fentry: the trampoline skips a program already active on the CPU (`bpf_prog->active`,
  kernel 5.12), which also covers preemption. A CO-RE `bpf_core_field_exists(struct
  bpf_prog, active)` picks the atomic add on older kernels, where a softirq can re-enter.
- tracepoints: preemption disabled and `bpf_prog_active` guard, on all kernels.

TC (egress can be entered from TC ingress processing; kept conservative) and CUBIC/BBR (two
programs share one ring buffer, one can interrupt the other) keep atomic adds. Recent clang
defaults to `-mcpu=v3`, which made `__sync_fetch_and_add()` a BPF_FETCH atomic
(`lock xadd`, and a hidden kernel 5.12 requirement); `__atomic_fetch_add(..., RELAXED)`
with the result unused is a plain `lock add` on every kernel.

### Item 10: TC direct packet access

`skb_header()` works like the kernel's `skb_header_pointer()`: pointer into
`skb->data` if `off + len <= data_end`, else `bpf_skb_load_bytes()` into a stack buffer.
Same bytes either way, so behavior is identical for paged headers. Header structs are
read unaligned (IP at offset 14), which the verifier allows on architectures with
efficient unaligned access (x86-64, arm64). The variable TCP offset is bounded to
[34, 74] before the range check, as the verifier needs.

### Item 4: writer encoding

bincode 1 writes `[u8; N]` arrays element by element through `Write for &mut [u8]`, one
variable-length copy per byte. `PackedLayout::of::<T>()` serializes a value whose byte *i*
is *i* once per type: each output byte then names its source offset; a second pattern
verifies the output is a pure byte copy (else the writer falls back to bincode). Adjacent
offsets merge into (offset, len) runs (1 to 7 per record type). The unit test
`packed_layout_matches_bincode` compares against bincode for every record type with
random bytes, including padding.

Micro-benchmark (release, one core, 20 M records, this laptop):

| record | runs | bincode ns | packed ns |
|---|---|---|---|
| tcp4_packet_trace | 1 | 78 | 10 |
| tcp6_packet_trace | 1 | 287 | 5 |
| sock_trace_entry | 7 | 354 | 30 |
| cwnd_trace_entry | 2 | 208 | 9 |
| cubic_trace_entry | 2 | 278 | 8 |
| bbr_trace_entry | 3 | 268 | 12 |
| tcp_probe_entry | 4 | 395 | 20 |

This was the largest userspace per-record cost; at several Mev/s per ring buffer, bincode
alone would have used most of a writer core.

### Item 9: per-CPU ring buffers

With one ring buffer per probe output, every CPU took the same spinlock in
`__bpf_ringbuf_reserve`. On the 400G testbed (KVM guests, 24 vCPUs, `-h`, offloads off,
8 sending cores) that lock took 23% of the sender CPU (`__pv_queued_spin_lock_slowpath`,
paravirt spinlocks make it worse in a guest), `tc_egress_packet_tracer` cost 1.9 µs per
run against 0.45 µs on a single sending core, and the event rate stopped at 1.6 M/s no
matter how many cores sent. Each ring buffer map is now an `ARRAY_OF_MAPS` with one ring
buffer per CPU; userspace creates the rings after load (online CPUs only) and one writer
thread per output file consumes all of them. Measured with the same traffic:
`tc_egress_packet_tracer` 1989 → 507 ns per run, the lock is gone from the profile,
+41% events in a 15 s run with 8 flows, no drops.

A flow's egress hook runs on several CPUs (sending task, ACK processing in softirq, TSQ
and pacing timers), so the file order of its records is no longer its hook order, and the
timestamps cannot restore it (`bpf_ktime_get_ns()` is not monotonic across CPUs; the guest
even runs on kvm-clock with unsynchronized TSCs). The runs never overlap, though: the socket
lock (TC egress, socket hooks) and the NAPI ownership of the RX queue (TC ingress) serialize
them. Every record therefore carries `hook_seq`, taken with an atomic fetch-add on a counter
per flow direction and hook (`HOOK_SEQ` hash map) inside that critical section, right after
the filter. Sorting by `hook_seq` restores the hook order exactly; drops leave gaps, and the
final counters in `metrics.json` (`hook_seq_issued`) also cover drops at the end of a flow.
Validated with traces: with shared ring buffers file order equals `hook_seq` order; with
per-CPU ring buffers file order breaks TCP invariants (sequence and ACK numbers going back
to values never sent) in up to 4186 places per run, `hook_seq` order in none, for 1 to 64
flows, moving RX IRQs and forced drops (missing numbers = dropped events exactly). Cost:
one hash lookup and one fetch-add per event.

### Item 6: other per-record writer work (checked, nothing left to do)

`serialized_size` is computed once per type (now at registration), `bytes_written` is
updated once per consume batch, the `RefCell` borrow is a flag check. The remaining
per-record work is the libbpf callback trampoline and the mmap bounds check.

## Minimum kernel

| Feature | Before | After |
|---|---|---|
| `-h` (TC) | 5.8 (ringbuf) | unchanged |
| `-t` tracepoints | 5.8 | unchanged |
| `-k`, `-w`, `-a` | 5.8 (+5.5 fentry) | **5.9** (`bpf_skc_to_tcp_sock`) |
| BBR (module BTF CO-RE) | 5.11 | unchanged |
| `hook_seq` (BPF_FETCH atomic) | – | **5.12** for all probes |

Since `hook_seq`, every probe needs 5.12; the LTS releases 5.15 and newer qualify.

## Evaluated, not implemented

**5. Prefaulting the mmap'd trace file** (`MADV_POPULATE_WRITE`, 5.14, 256 KiB ahead of
the write position, disabled on error). Prototyped and measured (3 M × 180-byte
records, median of 9 runs): tmpfs 228 → 208 ns/record (−9%), ext4 on kernel 7.2
69 → 76 ns/record (+11%). With large folios ext4 maps many pages per fault (4.5 k faults
for 131 k pages), while populate works page by page. Not a safe win, dropped. Revisit
only if the testbed's output file system maps page by page (no large folios: ext4 got
them only recently, around 6.16; xfs since 5.18; check the fault count); measure with the writer thread's `minflt` and CPU per record.

**7. One consumer thread for several output files.** Busy mode spins one thread per output
file (13 with `-htkwa`), each reading the ring buffers of all CPUs. A single libbpf `RingBuffer` with all maps (one callback per
map, epoll in wait mode) would free cores but caps total consume throughput at one core
and changes the `--writer-cpus` semantics. Proposed: an option `--writers N` that shards
ring buffers over N threads, default unchanged. Gain: T-core CPU, not event rate. Risk:
behavior change, head-of-line blocking between busy and quiet rings. Measure: E3
zero-drop rate and T-core usage with N = 1, 2, 13.

**8. Wakeup batching in wait mode.** `flags = 0` wakes the consumer when it has caught up,
i.e. at most once per drained batch, so wakeups are already adaptive. Further batching:
`BPF_RB_NO_WAKEUP` unless `bpf_ringbuf_query(rb, BPF_RB_AVAIL_DATA)` exceeds a threshold,
then `BPF_RB_FORCE_WAKEUP`; the 100 ms poll timeout bounds latency. Costs one helper call
per event and changes latency semantics (records can sit for up to the timeout). Measure:
irq_work / context switch counts and T-core CPU in `--poll wait`, E3 rate.

**9b. NUMA placement of the per-CPU ring buffers.** Each CPU's ring buffer could be created
with `numa_node` of that CPU so the producer writes local memory. The testbed VMs have one
node, so this was not measured.

**11. Flow tracking (TUI only).** Off in headless runs (rodata), so it does not affect the
evaluation, which does not read `FLOWS` either. With the TUI, every event does a 38-byte
hash lookup, and once 100 flows are tracked every event of an untracked flow does a failed
`update` that takes the bucket lock (`FLOWS` entries are never deleted). Options:
`LRU_PERCPU_HASH` (evicts, so the TUI list rotates; map type change), or a per-CPU
"last flow" cache in front of the lookup. Gain only for interactive use.

**12. Duplicate tuple build.** With an IP filter and the TUI on, the tuple is built for the
filter and again for flow tracking. After item 1 that is ~20 direct loads; not worth the
extra plumbing. The extra probe read for `skb->len` is gone (item 1).

**13. Recursion misses.** Nested fentry invocations on the same CPU are skipped by the
trampoline and only counted in the kernel's `recursion_misses`; `metrics.json` reports it
per program (read before detach). Not a cost issue; item 3 relies on the same guard.

**Tracepoints via `tp_btf`.** The two to four probe reads per tracepoint event could go
with BTF tracepoints (`tp_btf/tcp_probe` gets `sk`, `skb`), but the fields are then computed
by us instead of the tracepoint (e.g. `srtt`), changing program type and semantics.

## How to measure on the testbed

1. **Verifier first** (not done yet): `veristat tcbee.bpf.o` or a normal start with each
   probe group; checks that the direct loads, packet pointers and CO-RE guards are accepted
   and reports verified instructions per program. Do it on the oldest target kernel too.
2. **Per-event kernel cost:** dedicated run with `sysctl kernel.bpf_stats_enabled=1`,
   `bpftool prog show` → `run_time_ns / run_cnt` per program, old vs new binary, same traffic
   (`EVALUATION.md` E2 "per-event in-kernel ns"). Expect the largest drop for `sock_*`,
   `cubic_*`, `bbr_*`.
3. **Event rate:** E3 zero-drop rate per probe set, old vs new binary.
4. **Writer:** T-core utime+stime per written record (E2 metrics); the packed encoding
   should show up most for `-k` and `-t`.
5. **Correctness:** record files of old and new binary for the same traffic must parse
   identically with `tcbee-process` (ENTRY_SIZEs unchanged); counter identity
   `attempted = handled + dropped + error` per ring buffer in `metrics.json`.
