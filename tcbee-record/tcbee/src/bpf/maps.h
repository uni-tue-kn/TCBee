/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * All maps. The names are part of the interface: userspace and the evaluation scripts
 * look them up by name (the kernel truncates them to 15 characters).
 */
#ifndef __TCBEE_MAPS_H
#define __TCBEE_MAPS_H

#include "records.h"

/* Mirrors tcbee_common::stats::STATS_LEN, see counters.h */
#define TCBEE_STATS_LEN 39
#define TCBEE_MAX_FLOWS 100
#define TCBEE_FILTER_MAX_ENTRIES 1024

/*
 * Default ring buffer sizes in bytes. The kernel allocates the pages when the map is
 * created, so these are real memory. They have to absorb writer stalls (file growth,
 * writeback). --ringbuf-size overrides them before load.
 */
#define RINGBUF(name, bytes)                                                               \
	struct {                                                                           \
		__uint(type, BPF_MAP_TYPE_RINGBUF);                                        \
		__uint(max_entries, bytes);                                                \
	} name SEC(".maps")

#define RB_SMALL (4 << 20)
#define RB_PACKETS (32 << 20)
#define RB_SOCK (64 << 20)

RINGBUF(TCP4_PACKETS_EGRESS, RB_PACKETS);
RINGBUF(TCP4_PACKETS_INGRESS, RB_PACKETS);
RINGBUF(TCP6_PACKETS_EGRESS, RB_PACKETS);
RINGBUF(TCP6_PACKETS_INGRESS, RB_PACKETS);
RINGBUF(TCP_SEND_SOCK_EVENTS, RB_SOCK);
RINGBUF(TCP_RECV_SOCK_EVENTS, RB_SOCK);
RINGBUF(TCP_SEND_CWND_EVENTS, RB_SOCK);
RINGBUF(TCP_RECEIVE_CWND_EVENTS, RB_SOCK);
RINGBUF(TCP_PROBE_QUEUE, RB_SMALL);
RINGBUF(TCP_RETRANSMIT_SYNACK_QUEUE, RB_SMALL);
RINGBUF(TCP_BAD_CSUM_QUEUE, RB_SMALL);
RINGBUF(CUBIC_EVENTS, RB_SOCK);
RINGBUF(BBR_EVENTS, RB_SOCK);

/* Per ring buffer [handled, dropped, error] counters */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, TCBEE_STATS_LEN);
	__type(key, __u32);
	__type(value, __u64);
} STATS SEC(".maps");

/*
 * hook_seq counters, see hook_seq.h. Shared by all CPUs: the counter of a flow direction at a
 * hook has to be one. Entries are only ever inserted with BPF_NOEXIST and never updated or
 * deleted while programs run, an update would replace the element under a concurrent
 * fetch-add. Userspace can raise max_entries before load.
 */
#define TCBEE_SEQ_ENTRIES 262144

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TCBEE_SEQ_ENTRIES);
	__type(key, struct seq_key);
	__type(value, __u64);
} SEQ SEC(".maps");

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
