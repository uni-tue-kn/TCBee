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
 * written, with the decision in bits 0-7 of the ato field of the record.
 */
enum tcbee_onchg_reason {
	ONCHG_REASON_SUPPRESS = 1, /* nothing watched changed: no record in on-change mode */
	ONCHG_REASON_CHANGED = 2, /* a watched field changed */
	ONCHG_REASON_FIRST = 3, /* first run of the flow at the hook, or after a drop/error */
	ONCHG_REASON_STATE = 4, /* the socket state changed */
	ONCHG_REASON_NO_STORAGE = 5, /* no socket storage (state_err), always written */
};

/*
 * The hook of a sock record, in bits 8-15 of its ato field (bits 0-7 hold the shadow reason
 * of on-change records). 0 in the egress and ingress-entry records without on-change.
 * Mirrored by tcbee_trace::onchange::Hook::tag.
 */
enum tcbee_onchg_hook {
	ONCHG_HOOK_INGRESS = 1, /* fexit/tcp_rcv_established, fexit/tcp_rcv_state_process */
	ONCHG_HOOK_TIMER = 2, /* fexit/tcp_write_timer_handler */
	ONCHG_HOOK_EGRESS = 3, /* fentry/__tcp_transmit_skb */
	/* The socket event hooks of -k (event_sock.tcp) */
	ONCHG_HOOK_STATE = 4, /* tp_btf/inet_sock_set_state, the new state in bits 16-23 */
	ONCHG_HOOK_CA_STATE = 5, /* tp_btf/tcp_cong_state_set, the new ca_state in bits 16-23 */
	ONCHG_HOOK_RETRANSMIT = 6, /* tp_btf/tcp_retransmit_skb */
	ONCHG_HOOK_RESTART = 7, /* fexit/tcp_cwnd_restart */
	ONCHG_HOOK_RCVBUF = 8, /* tp_btf/tcp_rcvbuf_grow */
};

#define ONCHG_HOOK_SHIFT 8
/* The new state of a STATE or CA_STATE record, in ato */
#define SOCK_EVENT_STATE_SHIFT 16

#endif /* __TCBEE_ONCHANGE_H */
