/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/* Socket helpers: ports, address tuple, flow tracking and the shared record header */
#ifndef __TCBEE_FLOW_H
#define __TCBEE_FLOW_H

#include "config.h"
#include "filter.h"
#include "maps.h"

/* Common prefix of the socket based records, see TCBEE_SOCK_HEADER in records.h */
struct tcbee_sock_header {
	TCBEE_SOCK_HEADER
};

#define ASSERT_SOCK_HEADER(record)                                                         \
	_Static_assert(__builtin_offsetof(struct record, family) ==                        \
			       __builtin_offsetof(struct tcbee_sock_header, family),       \
		       #record " header")
ASSERT_SOCK_HEADER(sock_trace_entry);
ASSERT_SOCK_HEADER(cwnd_trace_entry);
ASSERT_SOCK_HEADER(cubic_trace_entry);
ASSERT_SOCK_HEADER(bbr_trace_entry);

/*
 * Socket fields are read with direct loads from the BTF typed fentry arguments, still
 * CO-RE relocated. The JIT turns them into plain loads with an exception table entry,
 * no helper call. A load that faults yields 0 instead of an error, so a record of a
 * broken socket carries zeros and is still counted as handled; with a valid socket
 * pointer from the hook this does not happen.
 */

/* Local port (skc_num) and remote port, both in host byte order */
static __always_inline void sk_ports(struct sock *sk, __u16 *sport, __u16 *dport)
{
	*sport = sk->__sk_common.skc_num;
	*dport = bpf_ntohs(sk->__sk_common.skc_dport);
}

/* The IPv6 socket addresses only exist with CONFIG_IPV6 */
static __always_inline bool sk_has_v6(void)
{
	return bpf_core_field_exists(struct sock_common, skc_v6_daddr);
}

/*
 * Address tuple of a socket. IPv4 addresses go into the first 4 bytes in network byte
 * order. The whole key is zeroed first so the trailing padding byte is deterministic.
 */
static __always_inline void tuple_from_sk(struct ip_tuple *t, struct sock *sk, __u16 sport,
					  __u16 dport)
{
	__builtin_memset(t, 0, sizeof(*t));
	if (sk->__sk_common.skc_family == AF_INET6) {
		if (sk_has_v6()) {
			__builtin_memcpy(t->src_ip, &sk->__sk_common.skc_v6_rcv_saddr, 16);
			__builtin_memcpy(t->dst_ip, &sk->__sk_common.skc_v6_daddr, 16);
		}
	} else {
		__be32 saddr = sk->__sk_common.skc_rcv_saddr;
		__be32 daddr = sk->__sk_common.skc_daddr;

		__builtin_memcpy(t->src_ip, &saddr, sizeof(saddr));
		__builtin_memcpy(t->dst_ip, &daddr, sizeof(daddr));
	}
	t->sport = sport;
	t->dport = dport;
	t->protocol = IPPROTO_TCP;
}

/* Apply the port and IP filter to a socket. Returns false if the event is filtered out. */
static __always_inline bool filter_sock(struct sock *sk, __u16 sport, __u16 dport)
{
	struct ip_tuple t;

	if (!filter_ports_match(sport, dport))
		return false;
	if (filter_needs_tuple()) {
		tuple_from_sk(&t, sk, sport, dport);
		if (!filter_tuple_match(&t))
			return false;
	}
	return true;
}

/* Lexicographic byte comparison, like Rust's Ord on [u8; 16] */
static __always_inline int cmp_addr(const __u8 *a, const __u8 *b)
{
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (a[i] != b[i])
			return a[i] < b[i] ? -1 : 1;
	}
	return 0;
}

/*
 * Put the lexicographically smaller (ip, port) pair first, so both directions of a
 * connection map to the same key.
 */
static __always_inline void canonical(struct ip_tuple *t)
{
	int c = cmp_addr(t->src_ip, t->dst_ip);
	__u8 tmp[16];
	__u16 port;

	if (c < 0 || (c == 0 && t->sport <= t->dport))
		return;
	__builtin_memcpy(tmp, t->src_ip, sizeof(tmp));
	__builtin_memcpy(t->src_ip, t->dst_ip, sizeof(tmp));
	__builtin_memcpy(t->dst_ip, tmp, sizeof(tmp));
	port = t->sport;
	t->sport = t->dport;
	t->dport = port;
}

/* Remember the flow for the TUI flow list. Takes a tuple built with a zeroed key. */
static __always_inline void flow_track(struct ip_tuple *t)
{
	if (!FLOW_TRACKING)
		return;
	canonical(t);
	/*
	 * The lookup is lockless, an update takes the bucket lock even if the flow already
	 * exists, so only insert flows that are not tracked yet.
	 */
	if (!bpf_map_lookup_elem(&FLOWS, t))
		bpf_map_update_elem(&FLOWS, t, t, BPF_NOEXIST);
}

static __always_inline void flow_track_sk(struct sock *sk, __u16 sport, __u16 dport)
{
	struct ip_tuple t;

	if (!FLOW_TRACKING)
		return;
	tuple_from_sk(&t, sk, sport, dport);
	flow_track(&t);
}

/*
 * Fill the shared header of a socket based record: addr_v4 is the raw skc_addrpair,
 * sport is skc_num and dport is skc_dport in host byte order, from sk_ports().
 */
static __always_inline void fill_header(void *rec, struct sock *sk, __u16 sport, __u16 dport)
{
	struct tcbee_sock_header *h = rec;

	h->time = bpf_ktime_get_ns();
	h->addr_v4 = sk->__sk_common.skc_addrpair;
	/* The record is zeroed, IPv4 flows keep zero v6 addresses */
	if (sk->__sk_common.skc_family == AF_INET6 && sk_has_v6()) {
		__builtin_memcpy(h->src_v6, &sk->__sk_common.skc_v6_rcv_saddr, 16);
		__builtin_memcpy(h->dst_v6, &sk->__sk_common.skc_v6_daddr, 16);
	}
	h->sport = sport;
	h->dport = dport;
	h->family = sk->__sk_common.skc_family;
}

#endif /* __TCBEE_FLOW_H */
