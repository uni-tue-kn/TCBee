# Test fixtures

`tcbee_small/` (1.6 MB) mixes real and generated data.

- **Real**, not regenerable: the first 2000 records (`head -c $((2000 * ENTRY_SIZE))`) of `cubic`,
  `tcp_probe`, `send_sock`, `recv_sock`, `tcp4_send` and `tcp4_receive` from the trace
  `tcbee_2026-10-05T18-16-22` (IPv4, port 8080, many flows, `max_pacing_rate = u64::MAX` records).
  The source trace was in tmpfs; a copy is kept at `~/tcbee-traces` outside the repo. It predates
  `hook_seq`, which was inserted afterwards as the record index + 1 (recorded with shared ring
  buffers, so file order was hook order). The sock records also got `conn_id` = 0 (no MPTCP).
  They are in the old sock layout without `ca_state`, the delivery and the chrono fields, which
  tcbee-process detects and decodes through `Sock172Entry` (172 B, `src/bindings/legacy.rs`).
  The tcp4 records are in the layout before the ECN codepoint and the departure time
  (`Tcp4Packet43Entry`, 43 B). The other older layouts (sock 168, 201 and 202 B, cwnd 70 B)
  are tested with records written by the tests themselves. `cubic` and the generated `bbr` are
  in the layouts before the hook tag (`Cubic122Entry`, `Bbr118Entry`); the current ones are
  tested with records written by the tests.
- **Generated** by `src/fixtures.rs`: `bbr`, `mptcp_pm`, `send_cwnd`, `send_cwnd_oc`, `send_sock_oc` (a
  copy of real records), `tcp6_*` (in the old layout like the tcp4 files, `Tcp6Packet67Entry`),
  the empty files and `tcbee_truncated`. Deterministic values, real bincode records, correct divider, `hook_seq` counting
  each flow from 1. Regenerate with
  `cargo test --features fixture-gen -- --ignored regenerate_fixtures`.

Generated layout: timestamp `1_000_000_000_000 ns + (index / 2) * 1 ms`; two flows alternating by
index (even `10.0.0.1:40000 -> 10.0.0.2:5201`, odd source port 40001; tcp6 uses
`2001:db8::1 -> 2001:db8::2`; receive files are reversed). Every 50th pair repeats the previous
timestamp (duplicates within a flow). `bbr.cycle_mstamp` is near `u64::MAX`.

## `tcbee_small/`

| File | Binding | Record size (bytes) | Records | Origin |
| --- | --- | --- | --- | --- |
| `bbr.tcp` | `Bbr118Entry` | 118 | 500 | generated |
| `mptcp_pm.tcp` | `mptcp_pm_entry` | 123 | 12 | generated |
| `cubic.tcp` | `Cubic122Entry` | 122 | 2000 | real |
| `tcp_probe.tcp` | `tcp_probe_entry` | 124 | 2000 | real |
| `tcp_retransmit_synack.tcp` | none | | 0 | generated |
| `tcp_bad_csum.tcp` | none | | 0 | generated |
| `tcp_events.tcp` | none | | 0 | generated |
| `timer_sock.tcp` | `sock_trace_entry` (source `sock_timer`) | 262 | 0 | generated |
| `ingress_sock.tcp` | `sock_trace_entry` (source `sock_ingress`) | 262 | 0 | generated |
| `event_sock.tcp` | `sock_trace_entry` (source `sock_event`) | 262 | 0 | generated |
| `reno.tcp` | `reno_trace_entry` | 96 | 0 | generated |
| `tcp4_driver_receive.tcp` | `tcp4_packet_trace` (source `tcp4_driver`) | 52 | 0 | generated |
| `tcp6_driver_receive.tcp` | `tcp6_packet_trace` (source `tcp6_driver`) | 76 | 0 | generated |
| `send_sock.tcp` | `Sock172Entry` | 172 | 2000 | real |
| `recv_sock.tcp` | `Sock172Entry` | 172 | 2000 | real |
| `send_cwnd.tcp` | `cwnd_trace_entry` | 74 | 1000 | generated |
| `recv_cwnd.tcp` | `cwnd_trace_entry` | 74 | 0 | generated |
| `tcp4_receive.tcp` | `Tcp4Packet43Entry` | 43 | 2000 | real |
| `tcp4_send.tcp` | `Tcp4Packet43Entry` | 43 | 2000 | real |
| `tcp6_receive.tcp` | `Tcp6Packet67Entry` | 67 | 500 | generated |
| `tcp6_send.tcp` | `Tcp6Packet67Entry` | 67 | 500 | generated |
| `send_sock_oc.tcp` | `Sock172Entry` (source `sock_oc`) | 172 | 200 | real (first 200 of `send_sock.tcp`) |
| `recv_sock_oc.tcp` | `sock_trace_entry` (source `sock_oc`) | 262 | 0 | generated |
| `send_cwnd_oc.tcp` | `cwnd_trace_entry` (source `cwnd_oc`) | 74 | 200 | generated |
| `recv_cwnd_oc.tcp` | `cwnd_trace_entry` (source `cwnd_oc`) | 74 | 0 | generated |

## `tcbee_truncated/`

`send_sock.tcp` only: 10 sock records in the old layout (1720 bytes) followed by the first 17 bytes of an
eleventh record (1737 bytes in total).
