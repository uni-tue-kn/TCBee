// SPDX-License-Identifier: (MIT OR GPL-2.0)
// The tcbee-live probes: cwnd samples of the selected flows, built with libbpf CO-RE.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "live.h"

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Every flow seen, polled by userspace for the flow list. LRU, so old flows
 * make room for new ones. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow_key);
	__type(value, __u8);
} KNOWN_FLOWS SEC(".maps");

/* Flows selected in the GUI: only these produce events */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct flow_key);
	__type(value, __u8);
} FLOW_FILTER SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 << 20);
} EVENTS SEC(".maps");

static __always_inline void ipv4_mapped(__u8 *dst, __be32 addr)
{
	__builtin_memset(dst, 0, 10);
	dst[10] = 0xff;
	dst[11] = 0xff;
	__builtin_memcpy(dst + 12, &addr, 4);
}

static __always_inline int make_flow_key(struct sock *sk, struct flow_key *key)
{
	struct sock_common *skc = &sk->__sk_common;

	key->family = skc->skc_family;
	key->src_port = skc->skc_num;
	key->dst_port = bpf_ntohs(skc->skc_dport);

	if (key->family == AF_INET) {
		ipv4_mapped(key->src_v6, skc->skc_rcv_saddr);
		ipv4_mapped(key->dst_v6, skc->skc_daddr);
		return 0;
	}
	/* The IPv6 fields only exist with CONFIG_IPV6 */
	if (key->family == AF_INET6 && bpf_core_field_exists(skc->skc_v6_daddr)) {
		BPF_CORE_READ_INTO(&key->src_v6, skc, skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&key->dst_v6, skc, skc_v6_daddr.in6_u.u6_addr8);
		return 0;
	}
	return -1;
}

static __always_inline int handle(struct sock *sk)
{
	struct flow_key key;
	struct cwnd_event *event;
	__u8 one = 1;

	__builtin_memset(&key, 0, sizeof(key));
	if (make_flow_key(sk, &key))
		return 0;

	/* Look up first: an update of an existing key still pops a free LRU node */
	if (!bpf_map_lookup_elem(&KNOWN_FLOWS, &key))
		bpf_map_update_elem(&KNOWN_FLOWS, &key, &one, BPF_NOEXIST);

	if (!bpf_map_lookup_elem(&FLOW_FILTER, &key))
		return 0;

	event = bpf_ringbuf_reserve(&EVENTS, sizeof(*event), 0);
	if (!event)
		return 0;
	event->time = bpf_ktime_get_ns();
	event->key = key;
	event->snd_cwnd = BPF_CORE_READ((struct tcp_sock *)sk, snd_cwnd);
	event->_pad = 0;
	/* Userspace consumes on a timer, no wakeup per segment */
	bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
	return 0;
}

SEC("fentry/__tcp_transmit_skb")
int BPF_PROG(cwnd_transmit_skb, struct sock *sk)
{
	return handle(sk);
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(cwnd_rcv_established, struct sock *sk)
{
	return handle(sk);
}
