/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * hook_seq: the position of an event among the events of its flow direction at its hook.
 *
 * Each CPU writes into its own ring buffer, so the file order of a flow's records follows
 * the CPUs, not the hook. The hook of one flow does run on several CPUs (TC egress from the
 * sending task, from ACK processing in softirq and from the TSQ and pacing timers), but the
 * runs never overlap: TCP transmits and the socket hooks hold the socket lock, TC ingress
 * runs under the NAPI ownership of the RX queue. The atomic fetch-add on the flow's counter
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

/* hook_seq of a socket based event, the tuple is local -> remote */
static __always_inline bool hook_seq_sk(struct sock *sk, __u16 sport, __u16 dport, __u8 rb,
					__u64 *hook_seq)
{
	struct ip_tuple t;

	tuple_from_sk(&t, sk, sport, dport);
	return hook_seq_tuple(&t, sk->__sk_common.skc_family, rb, hook_seq);
}

#endif /* __TCBEE_HOOK_SEQ_H */
