/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * STATS counters, same slot layout as tcbee-common/src/stats.rs.
 *
 * A probe invocation that passes the filter calls count_attempt() once and then exactly
 * one of submit() (handled or dropped) or count_error(), so
 * attempted == handled + dropped + error holds per ring buffer. Filtered out events
 * touch no counter.
 */
#ifndef __TCBEE_COUNTERS_H
#define __TCBEE_COUNTERS_H

#include "config.h"
#include "maps.h"

/* Ring buffer ids, tcbee_common::stats::RB_* */
#define RB_TCP4_EGRESS 0
#define RB_TCP4_INGRESS 1
#define RB_TCP6_EGRESS 2
#define RB_TCP6_INGRESS 3
#define RB_SOCK_SEND 4
#define RB_SOCK_RECV 5
#define RB_CWND_SEND 6
#define RB_CWND_RECV 7
#define RB_TCP_PROBE 8
#define RB_RETRANSMIT_SYNACK 9
#define RB_BAD_CSUM 10
#define RB_CUBIC 11
#define RB_BBR 12
#define RB_COUNT 13

#define STAT_ATTEMPTED 0
#define STAT_HANDLED 1
#define STAT_DROPPED 2
#define STAT_ERROR 3
#define STATS_PER_RB 4

#define SLOT_TCP_BYTES_SENT (RB_COUNT * STATS_PER_RB)
#define SLOT_TCP_BYTES_RECEIVED (SLOT_TCP_BYTES_SENT + 1)

_Static_assert(SLOT_TCP_BYTES_RECEIVED + 1 == TCBEE_STATS_LEN, "STATS length");

/*
 * fentry and tracepoint programs only run with migration disabled, so a softirq can
 * interrupt an update on the same CPU. The atomic add keeps per-CPU increments exact.
 */
static __always_inline void add_stat(__u32 slot, __u64 value)
{
	__u64 *counter = bpf_map_lookup_elem(&STATS, &slot);

	if (counter)
		__sync_fetch_and_add(counter, value);
}

static __always_inline void count_attempt(__u32 rb)
{
	add_stat(rb * STATS_PER_RB + STAT_ATTEMPTED, 1);
}

static __always_inline void count_error(__u32 rb)
{
	add_stat(rb * STATS_PER_RB + STAT_ERROR, 1);
}

/* Copy a record into the ring buffer and count it as handled, or as dropped if full */
static __always_inline void submit_record(void *ringbuf, __u32 rb, const void *rec, __u64 size)
{
	void *slot = bpf_ringbuf_reserve(ringbuf, size, 0);

	if (!slot) {
		add_stat(rb * STATS_PER_RB + STAT_DROPPED, 1);
		return;
	}
	__builtin_memcpy(slot, rec, size);
	bpf_ringbuf_submit(slot, RB_SUBMIT_FLAGS);
	add_stat(rb * STATS_PER_RB + STAT_HANDLED, 1);
}

#define submit(ringbuf, rb, rec) submit_record(ringbuf, rb, rec, sizeof(*(rec)))

#endif /* __TCBEE_COUNTERS_H */
