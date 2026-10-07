/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * STATS counters, same slot layout as tcbee-common/src/stats.rs.
 *
 * A probe invocation that passes the filter counts exactly one of reserve() failing
 * (dropped), commit() (handled) or count_error(), so the invocations of a ring buffer are
 * handled + dropped + error. Filtered out events touch no counter.
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

#define STAT_HANDLED 0
#define STAT_DROPPED 1
#define STAT_ERROR 2
#define STATS_PER_RB 3

_Static_assert(RB_COUNT * STATS_PER_RB == TCBEE_STATS_LEN, "STATS length");

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
 *    bpf_prog_active is held on the CPU (all kernels);
 *  - fentry programs are skipped while the same program is active on the CPU, which also
 *    covers preemption (bpf_prog->active, kernel 5.12). Older kernels lack that guard and
 *    a softirq can run the program again on top of itself, so they keep the atomic add.
 *    The check is a CO-RE relocation, resolved when the object is loaded.
 * TC programs and the CUBIC/BBR hooks, which share a ring buffer between two programs,
 * always use the atomic add.
 */
static __always_inline void add_stat_owned(__u32 slot, __u64 value, bool fentry)
{
	__u64 *counter;

	if (fentry && !bpf_core_field_exists(struct bpf_prog, active)) {
		add_stat(slot, value);
		return;
	}
	counter = bpf_map_lookup_elem(&STATS, &slot);
	if (counter)
		*counter += value;
}

/* Ring buffers whose counters exactly one program updates, see add_stat_owned() */
static __always_inline bool rb_owned(__u32 rb)
{
	return rb == RB_SOCK_SEND || rb == RB_SOCK_RECV || rb == RB_CWND_SEND ||
	       rb == RB_CWND_RECV || rb == RB_TCP_PROBE || rb == RB_RETRANSMIT_SYNACK ||
	       rb == RB_BAD_CSUM;
}

static __always_inline bool rb_tracepoint(__u32 rb)
{
	return rb == RB_TCP_PROBE || rb == RB_RETRANSMIT_SYNACK || rb == RB_BAD_CSUM;
}

/* rb is a constant in every caller, so this folds to one of the two adds */
static __always_inline void count(__u32 rb, __u32 stat)
{
	__u32 slot = rb * STATS_PER_RB + stat;

	if (rb_owned(rb))
		add_stat_owned(slot, 1, !rb_tracepoint(rb));
	else
		add_stat(slot, 1);
}

static __always_inline void count_error(__u32 rb)
{
	count(rb, STAT_ERROR);
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

#endif /* __TCBEE_COUNTERS_H */
