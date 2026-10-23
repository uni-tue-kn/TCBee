/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * STATS counters, same slot layout as tcbee-common/src/stats.rs.
 *
 * A probe invocation that passes the filter counts exactly one of reserve() failing
 * (dropped), commit() (handled), count_error() or, in on-change mode, count_suppressed(), so
 * the invocations of a ring buffer are handled + dropped + error + suppressed. Filtered out
 * events touch no counter.
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
#define RB_MPTCP_PM 13
#define RB_TCP_EVENTS 14
#define RB_SOCK_TIMER 15
#define RB_SOCK_INGRESS 16
#define RB_SOCK_EVENT 17
#define RB_RENO 18
#define RB_TCP4_DRIVER_INGRESS 19
#define RB_TCP6_DRIVER_INGRESS 20
#define RB_TCP4_DRIVER_EGRESS 21
#define RB_TCP6_DRIVER_EGRESS 22
#define RB_COUNT 23

#define STAT_HANDLED 0
#define STAT_DROPPED 1
#define STAT_ERROR 2
#define STATS_PER_RB 3

/*
 * Appended after the per-ring slots: the runs an on-change probe suppressed, one slot per
 * ring, then the runs that found no socket storage and wrote a full record. Both stay 0 in
 * the default mode.
 */
#define STATS_SUPPRESSED_BASE (RB_COUNT * STATS_PER_RB)
#define STATS_STATE_ERR (STATS_SUPPRESSED_BASE + RB_COUNT)

_Static_assert(STATS_STATE_ERR + 1 == TCBEE_STATS_LEN, "STATS length");

/*
 * fentry and tracepoint programs only run with migration disabled, so a softirq can
 * interrupt an update on the same CPU. The atomic add keeps per-CPU increments exact.
 * A relaxed add whose result is unused compiles to BPF_XADD (lock add), cheaper than the
 * BPF_FETCH atomic of __sync_fetch_and_add().
 */
static __always_inline void add_stat(__u32 slot, __u64 value)
{
	__u64 *counter = bpf_map_lookup_elem(&STATS, &slot);

	if (counter)
		__atomic_fetch_add(counter, value, __ATOMIC_RELAXED);
}

/*
 * Plain read-modify-write for slots that exactly one program writes, cheaper than the
 * locked add. Such a program cannot nest on itself on one CPU, so no update is lost:
 *  - tracepoint programs run with preemption disabled and are skipped while
 *    bpf_prog_active is held on the CPU;
 *  - fentry programs are skipped while the same program is active on the CPU, which also
 *    covers preemption (bpf_prog->active).
 * TC and XDP programs and the CUBIC/BBR hooks, which share a ring buffer between two
 * programs, always use the atomic add.
 */
static __always_inline void add_stat_owned(__u32 slot, __u64 value)
{
	__u64 *counter = bpf_map_lookup_elem(&STATS, &slot);

	if (counter)
		*counter += value;
}

/*
 * Ring buffers whose counters exactly one program updates, see add_stat_owned(). In on-change
 * mode the sock and cwnd rings have several programs (ingress, timer); the on-change programs
 * count through the _shared helpers below, which always take the atomic add.
 */
static __always_inline bool rb_owned(__u32 rb)
{
	return rb == RB_SOCK_SEND || rb == RB_SOCK_RECV || rb == RB_CWND_SEND ||
	       rb == RB_CWND_RECV || rb == RB_TCP_PROBE || rb == RB_RETRANSMIT_SYNACK ||
	       rb == RB_BAD_CSUM;
}

/* rb is a constant in every caller, so this folds to one of the two adds */
static __always_inline void count(__u32 rb, __u32 stat)
{
	__u32 slot = rb * STATS_PER_RB + stat;

	if (rb_owned(rb))
		add_stat_owned(slot, 1);
	else
		add_stat(slot, 1);
}

static __always_inline void count_error(__u32 rb)
{
	count(rb, STAT_ERROR);
}

/*
 * count() of an on-change program. The on-change receive ring has two programs, the ingress
 * and the write timer hook, which can nest on one CPU (backlog processing with BH enabled,
 * interrupted by a timer softirq), so the on-change programs always count with the atomic add.
 * The default helpers stay as they are, so that the default programs compile unchanged
 * (testing/bpf_identity.sh).
 */
static __always_inline void count_shared(__u32 rb, __u32 stat)
{
	add_stat(rb * STATS_PER_RB + stat, 1);
}

static __always_inline void count_error_shared(__u32 rb)
{
	count_shared(rb, STAT_ERROR);
}

/*
 * An on-change run whose watched fields did not change: no hook_seq, no record. Only the
 * on-change programs count it, so it always takes the atomic add like count_shared().
 */
static __always_inline void count_suppressed(__u32 rb)
{
	add_stat(STATS_SUPPRESSED_BASE + rb, 1);
}

/* Several programs share this slot, so it always takes the atomic add */
static __always_inline void count_state_err(void)
{
	add_stat(STATS_STATE_ERR, 1);
}

/*
 * Records are written in place: reserve a slot in this CPU's ring buffer (see maps.h),
 * fill it, commit it. A full ring buffer counts the event as dropped, a missing one (never
 * the case once userspace created them) as error. The slot is zeroed first, so padding
 * bytes and fields a probe does not set are deterministic. Nothing between reserve and
 * commit can fail, so a reserved record is never discarded.
 */
static __always_inline void *reserve_record(void *ringbufs, __u32 rb, __u64 size)
{
	__u32 cpu = bpf_get_smp_processor_id();
	void *ringbuf, *rec;

	ringbuf = bpf_map_lookup_elem(ringbufs, &cpu);
	if (!ringbuf) {
		count_error(rb);
		return NULL;
	}
	rec = bpf_ringbuf_reserve(ringbuf, size, 0);
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
 * rec = reserve(ringbufs, rb, rec): reserves and zeroes sizeof(*rec) bytes in this CPU's
 * ring buffer of ringbufs, NULL if it is full. Zeroing through the typed pointer lets
 * clang use 8 byte stores (every record starts with a u64), a void pointer would make it
 * store byte by byte.
 */
#define reserve(ringbufs, rb, rec)                                                         \
	({                                                                                 \
		typeof(rec) __rec = reserve_record(ringbufs, rb, sizeof(*(rec)));          \
		if (__rec)                                                                 \
			__builtin_memset(__rec, 0, sizeof(*__rec));                        \
		__rec;                                                                     \
	})

/* reserve_record() of an on-change program, see count_shared() */
static __always_inline void *reserve_record_shared(void *ringbufs, __u32 rb, __u64 size)
{
	__u32 cpu = bpf_get_smp_processor_id();
	void *ringbuf, *rec;

	ringbuf = bpf_map_lookup_elem(ringbufs, &cpu);
	if (!ringbuf) {
		count_shared(rb, STAT_ERROR);
		return NULL;
	}
	rec = bpf_ringbuf_reserve(ringbuf, size, 0);
	if (!rec)
		count_shared(rb, STAT_DROPPED);
	return rec;
}

/* commit() of an on-change program, see count_shared() */
static __always_inline void commit_shared(void *rec, __u32 rb)
{
	bpf_ringbuf_submit(rec, RB_SUBMIT_FLAGS);
	count_shared(rb, STAT_HANDLED);
}

/* reserve() of an on-change program, see count_shared() */
#define reserve_shared(ringbufs, rb, rec)                                                  \
	({                                                                                 \
		typeof(rec) __rec = reserve_record_shared(ringbufs, rb, sizeof(*(rec)));   \
		if (__rec)                                                                 \
			__builtin_memset(__rec, 0, sizeof(*__rec));                        \
		__rec;                                                                     \
	})

#endif /* __TCBEE_COUNTERS_H */
