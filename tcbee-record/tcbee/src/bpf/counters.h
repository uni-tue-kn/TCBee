/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * STATS counters, same slot layout as tcbee-common/src/stats.rs.
 *
 * A probe invocation that passes the filter calls count_attempt() once and then exactly
 * one of reserve() failing (dropped), commit() (handled) or count_error(), so
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

static __always_inline void count(__u32 rb, __u32 stat)
{
	add_stat(rb * STATS_PER_RB + stat, 1);
}

static __always_inline void count_attempt(__u32 rb)
{
	count(rb, STAT_ATTEMPTED);
}

static __always_inline void count_error(__u32 rb)
{
	count(rb, STAT_ERROR);
}

/*
 * Records are written in place: reserve a slot, fill it, commit it. A full ring buffer
 * counts the event as dropped. The slot is zeroed first, so padding bytes and fields a
 * probe does not set are deterministic. Nothing between reserve and commit can fail, so
 * a reserved record is never discarded.
 */
static __always_inline void *reserve_record(void *ringbuf, __u32 rb, __u64 size)
{
	void *rec = bpf_ringbuf_reserve(ringbuf, size, 0);

	if (!rec)
		count(rb, STAT_DROPPED);
	return rec;
}

/* Hand a reserved record to userspace and count it as handled */
static __always_inline void commit(void *rec, __u32 rb)
{
	bpf_ringbuf_submit(rec, RB_SUBMIT_FLAGS);
	count(rb, STAT_HANDLED);
}

/*
 * rec = reserve(ringbuf, rb, rec): reserves and zeroes sizeof(*rec) bytes, NULL if the
 * ring buffer is full. Zeroing through the typed pointer lets clang use 8 byte stores
 * (every record starts with a u64), a void pointer would make it store byte by byte.
 */
#define reserve(ringbuf, rb, rec)                                                          \
	({                                                                                 \
		typeof(rec) __rec = reserve_record(ringbuf, rb, sizeof(*(rec)));           \
		if (__rec)                                                                 \
			__builtin_memset(__rec, 0, sizeof(*__rec));                        \
		__rec;                                                                     \
	})

#endif /* __TCBEE_COUNTERS_H */
