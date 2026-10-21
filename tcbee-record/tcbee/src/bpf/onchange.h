/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * Fields of sock_trace_entry an on-change probe can watch (--on-change).
 *
 * X(name, bit): name as in sock_trace_entry, bit in the watch mask (SOCK_WATCH_MASK). The
 * order and bits are mirrored by tcbee_trace::onchange::SockField, checked against the enum
 * below in tcbee-common. ato, snd_wscale and rcv_wscale are always 0 and cannot be watched.
 */
#ifndef __TCBEE_ONCHANGE_H
#define __TCBEE_ONCHANGE_H

#define SOCK_FIELDS(X)                                                                     \
	X(pacing_rate, 0)                                                                  \
	X(max_pacing_rate, 1)                                                              \
	X(backoff, 2)                                                                      \
	X(rto, 3)                                                                          \
	X(rcv_mss, 4)                                                                      \
	X(snd_cwnd, 5)                                                                     \
	X(bytes_acked, 6)                                                                  \
	X(snd_ssthresh, 7)                                                                 \
	X(total_retrans, 8)                                                                \
	X(probes, 9)                                                                       \
	X(lost, 10)                                                                        \
	X(sacked_out, 11)                                                                  \
	X(retrans, 12)                                                                     \
	X(rcv_ssthresh, 13)                                                                \
	X(rttvar, 14)                                                                      \
	X(advmss, 15)                                                                      \
	X(reordering, 16)                                                                  \
	X(rcv_rtt, 17)                                                                     \
	X(rcv_space, 18)                                                                   \
	X(bytes_received, 19)                                                              \
	X(segs_out, 20)                                                                    \
	X(segs_in, 21)

#define SOCK_FIELD_ENUM(name, bit) SF_##name = bit,

enum tcbee_sock_field {
	SOCK_FIELDS(SOCK_FIELD_ENUM)
	SF_COUNT
};

#undef SOCK_FIELD_ENUM

/*
 * Shadow mode (ONCHG_SHADOW, --on-change-shadow): every run of the on-change sock probes is
 * written, with the decision in the ato field of the record.
 */
enum tcbee_onchg_reason {
	ONCHG_REASON_SUPPRESS = 1, /* nothing watched changed: no record in on-change mode */
	ONCHG_REASON_CHANGED = 2, /* a watched field changed */
	ONCHG_REASON_FIRST = 3, /* first run of the flow at the hook, or after a drop/error */
	ONCHG_REASON_STATE = 4, /* the socket state changed */
	ONCHG_REASON_NO_STORAGE = 5, /* no socket storage (state_err), always written */
};

#endif /* __TCBEE_ONCHANGE_H */
