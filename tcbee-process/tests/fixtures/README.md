# Test fixtures

`tcbee_small/` (1.4 MB) mixes real and generated data.

- **Real**, not regenerable: the first 2000 records (`head -c $((2000 * ENTRY_SIZE))`) of `cubic`,
  `tcp_probe`, `send_sock`, `recv_sock`, `tcp4_send` and `tcp4_receive` from the trace
  `tcbee_2026-10-05T18-16-22` (IPv4, port 8080, many flows, `max_pacing_rate = u64::MAX` records).
  The source trace was in tmpfs; a copy is kept at `~/tcbee-traces` outside the repo. It predates
  `hook_seq`, which was inserted afterwards as the record index + 1 (recorded with shared ring
  buffers, so file order was hook order).
- **Generated** by `src/fixtures.rs`: `bbr`, `send_cwnd`, `tcp6_*`, the empty files and
  `tcbee_truncated`. Deterministic values, real bincode records, correct divider, `hook_seq` counting
  each flow from 1. Regenerate with
  `cargo test --features fixture-gen -- --ignored regenerate_fixtures`.

Generated layout: timestamp `1_000_000_000_000 ns + (index / 2) * 1 ms`; two flows alternating by
index (even `10.0.0.1:40000 -> 10.0.0.2:5201`, odd source port 40001; tcp6 uses
`2001:db8::1 -> 2001:db8::2`; receive files are reversed). Every 50th pair repeats the previous
timestamp (duplicates within a flow). `bbr.cycle_mstamp` is near `u64::MAX`.

## `tcbee_small/`

| File | Binding | Record size (bytes) | Records | Origin |
| --- | --- | --- | --- | --- |
| `bbr.tcp` | `BbrEvent` | 118 | 500 | generated |
| `cubic.tcp` | `CubicEvent` | 122 | 2000 | real |
| `tcp_probe.tcp` | `TcpProbe` | 124 | 2000 | real |
| `tcp_retransmit_synack.tcp` | none | | 0 | generated |
| `tcp_bad_csum.tcp` | none | | 0 | generated |
| `send_sock.tcp` | `sock_trace_entry` | 168 | 2000 | real |
| `recv_sock.tcp` | `sock_trace_entry` | 168 | 2000 | real |
| `send_cwnd.tcp` | `cwnd_trace_entry` | 70 | 1000 | generated |
| `recv_cwnd.tcp` | `cwnd_trace_entry` | 70 | 0 | generated |
| `tcp4_receive.tcp` | `Tcp4Packet` | 43 | 2000 | real |
| `tcp4_send.tcp` | `Tcp4Packet` | 43 | 2000 | real |
| `tcp6_receive.tcp` | `Tcp6Packet` | 67 | 500 | generated |
| `tcp6_send.tcp` | `Tcp6Packet` | 67 | 500 | generated |

## `tcbee_truncated/`

`send_sock.tcp` only: 10 sock records (1680 bytes) followed by the first 17 bytes of an
eleventh record (1697 bytes in total).
