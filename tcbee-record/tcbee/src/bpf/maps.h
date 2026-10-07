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
 * Ring buffers, one per CPU: a probe reserves its record in the ring buffer of the CPU it
 * runs on, so producers on different CPUs never wait for each other on a ring buffer's
 * lock. Each map below is an array indexed by CPU id. Userspace sets the number of slots
 * to the number of possible CPUs before load and creates the rings with their real size
 * after load (tcbee_common::stats::RINGBUF_SIZES); the inner definition is only the
 * template, its size is not part of the type check.
 */
struct tcbee_ringbuf {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
};

#define RINGBUFS_PER_CPU(name)                                                             \
	struct {                                                                           \
		__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);                                  \
		__uint(max_entries, 1);                                                    \
		__type(key, __u32);                                                        \
		__array(values, struct tcbee_ringbuf);                                     \
	} name SEC(".maps")

RINGBUFS_PER_CPU(TCP4_PACKETS_EGRESS);
RINGBUFS_PER_CPU(TCP4_PACKETS_INGRESS);
RINGBUFS_PER_CPU(TCP6_PACKETS_EGRESS);
RINGBUFS_PER_CPU(TCP6_PACKETS_INGRESS);
RINGBUFS_PER_CPU(TCP_SEND_SOCK_EVENTS);
RINGBUFS_PER_CPU(TCP_RECV_SOCK_EVENTS);
RINGBUFS_PER_CPU(TCP_SEND_CWND_EVENTS);
RINGBUFS_PER_CPU(TCP_RECEIVE_CWND_EVENTS);
RINGBUFS_PER_CPU(TCP_PROBE_QUEUE);
RINGBUFS_PER_CPU(TCP_RETRANSMIT_SYNACK_QUEUE);
RINGBUFS_PER_CPU(TCP_BAD_CSUM_QUEUE);
RINGBUFS_PER_CPU(CUBIC_EVENTS);
RINGBUFS_PER_CPU(BBR_EVENTS);

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
