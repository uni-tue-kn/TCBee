/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * hook_seq: the position of an event among the events of its flow direction at its hook.
 *
 * Each CPU writes into its own ring buffer, so the file order of a flow's records follows
 * the CPUs, not the hook. The hook of one flow does run on several CPUs (TC egress from the
 * sending task, from ACK processing in softirq and from the TSQ and pacing timers), but the
 * runs never overlap: TCP transmits and the socket hooks hold the socket lock, TC ingress
 * and XDP run under the NAPI ownership of the RX queue. The atomic fetch-add on the flow's counter
 * happens inside that critical section, so the numbers follow the order in which the hook
 * ran. Timestamps cannot do that: bpf_ktime_get_ns() is not guaranteed to be monotonic
 * across CPUs and can repeat.
 *
 * Where nothing serializes a flow's hook runs (control socket RSTs, SYN-ACKs, packets sent
 * from the neighbour queue, an RX queue change), the fetch-add still orders the overlapping
 * runs, which is the only order they have.
 *
 * The number is taken right after the filter and before the record is reserved, so a
 * dropped event and an error after the filter leave a gap: issued = handled + dropped +
 * errors after the filter. An event that cannot get a counter (map full) counts as error
 * and writes no record, so every record has hook_seq >= 1.
 *
 * The on-change programs (--on-change) decide first and take a number only for the runs
 * they write: suppressed runs and a missing tcp_sock take none, so there issued = handled +
 * dropped + the errors after hook_seq, and gaps are still exactly the drops. Their ingress
 * and timer programs write one ring and share its numbers, so hook_seq numbers the records
 * of a ring (output file) rather than of one hook.
 */
#ifndef __TCBEE_HOOK_SEQ_H
#define __TCBEE_HOOK_SEQ_H

#include "counters.h"
#include "flow.h"
#include "maps.h"

/* key must be fully initialized, the padding byte of the tuple included */
static __always_inline bool next_hook_seq(struct hook_seq_key *key, __u64 *hook_seq)
{
	__u64 zero = 0, *counter;

	counter = bpf_map_lookup_elem(&HOOK_SEQ, key);
	if (!counter) {
		/* Two CPUs may insert at once, the loser gets -EEXIST and finds the winner's */
		bpf_map_update_elem(&HOOK_SEQ, key, &zero, BPF_NOEXIST);
		counter = bpf_map_lookup_elem(&HOOK_SEQ, key);
		if (!counter)
			return false;
	}
	*hook_seq = __sync_fetch_and_add(counter, 1) + 1;
	return true;
}

/* hook_seq of a tuple based event, counts an error for rb if there is none */
static __always_inline bool hook_seq_tuple(const struct ip_tuple *t, __u8 family, __u8 rb,
					   __u64 *hook_seq)
{
	struct hook_seq_key key;

	__builtin_memset(&key, 0, sizeof(key));
	key.tuple = *t;
	key.rb = rb;
	key.family = family;
	if (next_hook_seq(&key, hook_seq))
		return true;
	count_error(rb);
	return false;
}

/*
 * hook_seq of a tuple based event of a flow that already has a counter at rb. Events from
 * packets without a socket (drops, RSTs of the stack) use it, so that traffic to no socket,
 * a port scan for instance, takes no map entries. Without a counter the event is skipped
 * like a filtered one.
 */
static __always_inline bool hook_seq_known_tuple(const struct ip_tuple *t, __u8 family, __u8 rb,
						 __u64 *hook_seq)
{
	struct hook_seq_key key;
	__u64 *counter;

	__builtin_memset(&key, 0, sizeof(key));
	key.tuple = *t;
	key.rb = rb;
	key.family = family;
	counter = bpf_map_lookup_elem(&HOOK_SEQ, &key);
	if (!counter && family == AF_INET) {
		/*
		 * An IPv4 flow of a dual-stack socket (AF_INET6, v4-mapped addresses) has its
		 * counter under the mapped addresses, as tuple_from_sk() takes them
		 */
		__u8 src[4], dst[4];

		__builtin_memcpy(src, t->src_ip, 4);
		__builtin_memcpy(dst, t->dst_ip, 4);
		__builtin_memset(key.tuple.src_ip, 0, 16);
		__builtin_memset(key.tuple.dst_ip, 0, 16);
		key.tuple.src_ip[10] = key.tuple.src_ip[11] = 0xff;
		key.tuple.dst_ip[10] = key.tuple.dst_ip[11] = 0xff;
		__builtin_memcpy(&key.tuple.src_ip[12], src, 4);
		__builtin_memcpy(&key.tuple.dst_ip[12], dst, 4);
		key.family = AF_INET6;
		counter = bpf_map_lookup_elem(&HOOK_SEQ, &key);
	}
	if (!counter)
		return false;
	*hook_seq = __sync_fetch_and_add(counter, 1) + 1;
	return true;
}

/*
 * The on-change twin of hook_seq_sk(), with hook_seq_tuple() inlined: an error counts with
 * the atomic add (count_shared()). hook_seq_sk() stays as it is so that the default programs
 * compile unchanged (testing/bpf_identity.sh).
 */
static __always_inline bool hook_seq_sk_shared(struct sock *sk, __u16 sport, __u16 dport, __u8 rb,
					       __u64 *hook_seq)
{
	struct hook_seq_key key;

	__builtin_memset(&key, 0, sizeof(key));
	tuple_from_sk(&key.tuple, sk, sport, dport);
	key.rb = rb;
	key.family = sk->__sk_common.skc_family;
	if (next_hook_seq(&key, hook_seq))
		return true;
	count_error_shared(rb);
	return false;
}

/* hook_seq of a socket based event, the tuple is local -> remote */
static __always_inline bool hook_seq_sk(struct sock *sk, __u16 sport, __u16 dport, __u8 rb,
					__u64 *hook_seq)
{
	struct ip_tuple t;

	tuple_from_sk(&t, sk, sport, dport);
	return hook_seq_tuple(&t, sk->__sk_common.skc_family, rb, hook_seq);
}

#endif /* __TCBEE_HOOK_SEQ_H */
