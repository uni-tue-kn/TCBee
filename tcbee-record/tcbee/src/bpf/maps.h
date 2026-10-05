/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * All maps. The names are part of the interface: userspace and the evaluation scripts
 * look them up by name (the kernel truncates them to 15 characters).
 */
#ifndef __TCBEE_MAPS_H
#define __TCBEE_MAPS_H

#include "records.h"

/* Mirrors tcbee_common::stats::STATS_LEN, see counters.h */
#define TCBEE_STATS_LEN 54
#define TCBEE_MAX_FLOWS 100
#define TCBEE_FILTER_MAX_ENTRIES 1024

/*
 * Default ring buffer sizes in bytes, as many records as before. libbpf rounds them up to
 * a power-of-two multiple of the page size. --ringbuf-size overrides them before load.
 */
#define RINGBUF(name, record, count)                                                       \
	struct {                                                                           \
		__uint(type, BPF_MAP_TYPE_RINGBUF);                                        \
		__uint(max_entries, sizeof(struct record) * (count));                      \
	} name SEC(".maps")

RINGBUF(TCP4_PACKETS_EGRESS, tcp4_packet_trace, 10000);
RINGBUF(TCP4_PACKETS_INGRESS, tcp4_packet_trace, 10000);
RINGBUF(TCP6_PACKETS_EGRESS, tcp6_packet_trace, 10000);
RINGBUF(TCP6_PACKETS_INGRESS, tcp6_packet_trace, 10000);
RINGBUF(TCP_SEND_SOCK_EVENTS, sock_trace_entry, 100000);
RINGBUF(TCP_RECV_SOCK_EVENTS, sock_trace_entry, 100000);
RINGBUF(TCP_SEND_CWND_EVENTS, cwnd_trace_entry, 100000);
RINGBUF(TCP_RECEIVE_CWND_EVENTS, cwnd_trace_entry, 100000);
RINGBUF(TCP_PROBE_QUEUE, tcp_probe_entry, 10000);
RINGBUF(TCP_RETRANSMIT_SYNACK_QUEUE, tcp_retransmit_synack_entry, 10000);
RINGBUF(TCP_BAD_CSUM_QUEUE, tcp_bad_csum_entry, 10000);
RINGBUF(CUBIC_EVENTS, cubic_trace_entry, 100000);
RINGBUF(BBR_EVENTS, bbr_trace_entry, 100000);

/* Per ring buffer [attempted, handled, dropped, error] counters plus byte counters */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, TCBEE_STATS_LEN);
	__type(key, __u32);
	__type(value, __u64);
} STATS SEC(".maps");

/* Flows seen by any probe, key and value are the canonical tuple */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, TCBEE_MAX_FLOWS);
	__type(key, struct ip_tuple);
	__type(value, struct ip_tuple);
} FLOWS SEC(".maps");

#define FILTER_PORT_MAP(name)                                                              \
	struct {                                                                           \
		__uint(type, BPF_MAP_TYPE_HASH);                                           \
		__uint(max_entries, TCBEE_FILTER_MAX_ENTRIES);                             \
		__type(key, __u16);                                                        \
		__type(value, __u8);                                                       \
	} name SEC(".maps")

#define FILTER_IP_MAP(name)                                                                \
	struct {                                                                           \
		__uint(type, BPF_MAP_TYPE_HASH);                                           \
		__uint(max_entries, TCBEE_FILTER_MAX_ENTRIES);                             \
		__type(key, struct filter_ip);                                             \
		__type(value, __u8);                                                       \
	} name SEC(".maps")

FILTER_PORT_MAP(FILTER_ANY_PORTS);
FILTER_PORT_MAP(FILTER_SRC_PORTS);
FILTER_PORT_MAP(FILTER_DST_PORTS);
FILTER_IP_MAP(FILTER_ANY_IPS);
FILTER_IP_MAP(FILTER_SRC_IPS);
FILTER_IP_MAP(FILTER_DST_IPS);

#endif /* __TCBEE_MAPS_H */
