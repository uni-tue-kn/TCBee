/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * Field-selected sock records (--sock-fields): the core and the field groups that a
 * record holds instead of the full sock_trace_entry. tcbee-trace/src/sockfields.rs has the
 * same groups with the same fields in the same order and computes the offsets below. Not in
 * records.h on purpose: the Rust bindings are generated from it, and their hash identifies the
 * default record layouts in raw traces.
 *
 * Each group's fields are sorted by size, so a group has no padding between its fields, and
 * every struct is a multiple of 4 bytes. The groups with 8 byte fields come first in a record
 * (Group::PLACEMENT), so each group starts aligned right after the one before it.
 */
#ifndef __TCBEE_SOCKFIELDS_H
#define __TCBEE_SOCKFIELDS_H

#include "records.h"

/* Header, hook tag and MPTCP connection: always recorded */
struct sock_sel_core {
	TCBEE_SOCK_HEADER
	uint32_t ato;
	uint32_t conn_id;
};

struct sock_sel_pacing {
	uint64_t pacing_rate;
	uint64_t max_pacing_rate;
	uint64_t wstamp_ns;
};

struct sock_sel_icsk {
	uint32_t rto;
	uint16_t rcv_mss;
	uint8_t backoff;
};

struct sock_sel_cwnd {
	uint32_t snd_cwnd;
};

struct sock_sel_cc {
	uint64_t bytes_acked;
	uint32_t snd_ssthresh;
	uint32_t total_retrans;
	uint32_t lost;
	uint32_t sacked_out;
	uint32_t retrans;
	uint32_t reordering;
	uint32_t segs_out;
	uint8_t probes;
};

struct sock_sel_rcv {
	uint64_t bytes_received;
	uint32_t rcv_ssthresh;
	uint32_t rcv_rtt;
	uint32_t rcv_space;
	uint32_t segs_in;
	uint16_t advmss;
};

struct sock_sel_rtt {
	uint32_t srtt;
	uint32_t mdev;
	uint32_t min_rtt;
	uint32_t rttvar;
};

struct sock_sel_delivery {
	uint32_t packets_out;
	uint32_t delivered;
	uint32_t delivered_ce;
	uint32_t app_limited;
	uint32_t rate_delivered;
	uint32_t rate_interval_us;
	uint32_t lost_out;
	uint8_t ca_state;
};

struct sock_sel_chrono {
	uint32_t chrono_busy;
	uint32_t chrono_rwnd_limited;
	uint32_t chrono_sndbuf_limited;
	uint8_t chrono_type;
};

struct sock_sel_seq {
	uint32_t snd_una;
	uint32_t snd_nxt;
	uint32_t reord_seen;
	uint32_t dsack_dups;
};

struct sock_sel_sndbuf {
	uint32_t wmem_queued;
	uint32_t sndbuf;
	uint32_t notsent;
};

/* The sizes that tcbee-trace's group table computes (Group::ring_bytes) */
_Static_assert(sizeof(struct sock_sel_core) == 72, "sock_sel_core size");
_Static_assert(sizeof(struct sock_sel_pacing) == 24, "sock_sel_pacing size");
_Static_assert(sizeof(struct sock_sel_icsk) == 8, "sock_sel_icsk size");
_Static_assert(sizeof(struct sock_sel_cwnd) == 4, "sock_sel_cwnd size");
_Static_assert(sizeof(struct sock_sel_cc) == 40, "sock_sel_cc size");
_Static_assert(sizeof(struct sock_sel_rcv) == 32, "sock_sel_rcv size");
_Static_assert(sizeof(struct sock_sel_rtt) == 16, "sock_sel_rtt size");
_Static_assert(sizeof(struct sock_sel_delivery) == 32, "sock_sel_delivery size");
_Static_assert(sizeof(struct sock_sel_chrono) == 16, "sock_sel_chrono size");
_Static_assert(sizeof(struct sock_sel_seq) == 16, "sock_sel_seq size");
_Static_assert(sizeof(struct sock_sel_sndbuf) == 12, "sock_sel_sndbuf size");

/* Index of a group in SOCK_SEL_OFF, the order of Group::ALL (not the order in a record) */
enum sock_sel_group {
	SG_pacing,
	SG_icsk,
	SG_cwnd,
	SG_cc,
	SG_rcv,
	SG_rtt,
	SG_delivery,
	SG_chrono,
	SG_seq,
	SG_sndbuf,
	SG_COUNT,
};

/* Offset of a group a record does not hold */
#define SOCK_SEL_ABSENT 0xffff

/*
 * Set by userspace before the object is loaded (SockShape in tcbee-trace): the offset of
 * each group in a record, the record length (a multiple of 8, the ring buffer's stride) and
 * the offset of the 4 bytes after the last group that round the record up to it. The core,
 * the groups and the tail cover the whole record, so no byte of an earlier record in the
 * ring stays in it. As frozen rodata they are constants to the verifier, which drops the
 * stores of absent groups.
 */
const volatile __u16 SOCK_SEL_OFF[SG_COUNT] = {
	SOCK_SEL_ABSENT, SOCK_SEL_ABSENT, SOCK_SEL_ABSENT, SOCK_SEL_ABSENT, SOCK_SEL_ABSENT,
	SOCK_SEL_ABSENT, SOCK_SEL_ABSENT, SOCK_SEL_ABSENT, SOCK_SEL_ABSENT, SOCK_SEL_ABSENT,
};
const volatile __u32 SOCK_SEL_LEN = sizeof(struct sock_sel_core);
const volatile __u16 SOCK_SEL_TAIL = SOCK_SEL_ABSENT;

#endif /* __TCBEE_SOCKFIELDS_H */
