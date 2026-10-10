/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * Records written to the ring buffers and the flow/filter map keys.
 *
 * Single source of truth for the kernel/user layout: tcbee-common runs bindgen on this
 * file. The trace files are written with bincode field by field, so the field order and
 * types below define the on-disk format read by tcbee-process. Do not reorder.
 *
 * Every record starts with time and hook_seq. hook_seq numbers the events of one flow
 * direction at one hook (output file) from 1, see hook_seq.h. A file's records come from the ring
 * buffers of several CPUs, so their order in the file is not their order at the hook;
 * sorting one flow's records of one file by hook_seq restores it exactly.
 */
#ifndef __TCBEE_RECORDS_H
#define __TCBEE_RECORDS_H

#ifndef __VMLINUX_H__
/* bindgen and other host builds; the eBPF build gets these from vmlinux.h */
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __INT64_TYPE__ int64_t;
#endif

/* TC, ring buffers TCP4_PACKETS_{EGRESS,INGRESS}. Addresses in host byte order. */
struct tcp4_packet_trace {
	uint64_t time;
	uint64_t hook_seq;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack;
	uint16_t window;
	uint8_t flags;
};

/* TC, ring buffers TCP6_PACKETS_{EGRESS,INGRESS} */
struct tcp6_packet_trace {
	uint64_t time;
	uint64_t hook_seq;
	uint8_t saddr_v6[16];
	uint8_t daddr_v6[16];
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack;
	uint16_t window;
	uint8_t flags;
};

/*
 * The socket based records start with the same header, filled by fill_header():
 * addr_v4 is the raw skc_addrpair, sport is skc_num (host order), dport is skc_dport
 * converted to host order.
 */
#define TCBEE_SOCK_HEADER                                                                  \
	uint64_t time;                                                                     \
	uint64_t hook_seq;                                                                 \
	uint64_t addr_v4;                                                                  \
	uint8_t src_v6[16];                                                                \
	uint8_t dst_v6[16];                                                                \
	uint16_t sport;                                                                    \
	uint16_t dport;                                                                    \
	uint16_t family;

/* fentry __tcp_transmit_skb / tcp_rcv_established, TCP_{SEND,RECV}_SOCK_EVENTS */
struct sock_trace_entry {
	TCBEE_SOCK_HEADER
	/* struct sock */
	uint64_t pacing_rate;
	uint64_t max_pacing_rate;
	/* struct inet_connection_sock */
	uint8_t backoff;
	uint32_t rto;
	uint32_t ato;
	uint16_t rcv_mss;
	/* struct tcp_sock */
	uint32_t snd_cwnd;
	uint64_t bytes_acked;
	uint32_t snd_ssthresh;
	uint32_t total_retrans;
	uint8_t probes;
	uint32_t lost;
	uint32_t sacked_out;
	uint32_t retrans;
	uint32_t rcv_ssthresh;
	uint32_t rttvar;
	uint16_t advmss;
	uint32_t reordering;
	uint32_t rcv_rtt;
	uint32_t rcv_space;
	uint64_t bytes_received;
	uint32_t segs_out;
	uint32_t segs_in;
	/* struct tcp_options_received */
	uint16_t snd_wscale;
	uint16_t rcv_wscale;
	/* Token of the MPTCP connection of a subflow (-M tag), 0 otherwise. In the padding. */
	uint32_t conn_id;
};

/* Same hooks as sock_trace_entry, TCP_SEND_CWND_EVENTS / TCP_RECEIVE_CWND_EVENTS */
struct cwnd_trace_entry {
	TCBEE_SOCK_HEADER
	uint32_t snd_cwnd;
	/* As in sock_trace_entry */
	uint32_t conn_id;
};

/* fentry cubictcp_cong_avoid / cubictcp_cwnd_event, CUBIC_EVENTS */
struct cubic_trace_entry {
	TCBEE_SOCK_HEADER
	uint32_t cnt;
	uint32_t last_max_cwnd;
	uint32_t last_cwnd;
	uint32_t last_time;
	uint32_t bic_origin_point;
	uint32_t bic_K;
	uint32_t delay_min;
	uint32_t epoch_start;
	uint32_t ack_cnt;
	uint32_t tcp_cwnd;
	uint32_t round_start;
	uint32_t end_seq;
	uint32_t last_ack;
	uint32_t curr_rtt;
};

/* fentry bbr_main / bbr_cwnd_event, BBR_EVENTS */
struct bbr_trace_entry {
	TCBEE_SOCK_HEADER
	uint32_t min_rtt_us;
	uint32_t min_rtt_stamp;
	uint32_t probe_rtt_done_stamp;
	uint32_t rtt_cnt;
	uint32_t next_rtt_delivered;
	uint64_t cycle_mstamp;
	uint32_t lt_bw;
	uint32_t lt_last_delivered;
	uint32_t lt_last_stamp;
	uint32_t lt_last_lost;
	uint32_t prior_cwnd;
	uint32_t full_bw;
};

/* tracepoint tcp/tcp_probe, TCP_PROBE_QUEUE. saddr/daddr hold a sockaddr_in(6). */
struct tcp_probe_entry {
	uint64_t time;
	uint64_t hook_seq;
	uint8_t saddr[28];
	uint8_t daddr[28];
	uint16_t sport;
	uint16_t dport;
	uint16_t family;
	uint32_t mark;
	uint16_t data_len;
	uint32_t snd_nxt;
	uint32_t snd_una;
	uint32_t snd_cwnd;
	uint32_t ssthresh;
	uint32_t snd_wnd;
	uint32_t srtt;
	uint32_t rcv_wnd;
	uint64_t sock_cookie;
};

/* tracepoint tcp/tcp_retransmit_synack, TCP_RETRANSMIT_SYNACK_QUEUE */
struct tcp_retransmit_synack_entry {
	uint64_t time;
	uint64_t hook_seq;
	uint16_t sport;
	uint16_t dport;
	uint16_t family;
	uint8_t saddr[4];
	uint8_t daddr[4];
	uint8_t saddr_v6[16];
	uint8_t daddr_v6[16];
};

/*
 * Event of an mptcp_pm_entry. 1 to 16 are the kernel's enum mptcp_event_type (uapi
 * linux/mptcp.h), the netlink path manager events, from 100 on events of TCBee's own hooks.
 */
enum tcbee_mptcp_event {
	TCBEE_MPTCP_CREATED = 1,
	TCBEE_MPTCP_ESTABLISHED = 2,
	TCBEE_MPTCP_CLOSED = 3,
	TCBEE_MPTCP_ANNOUNCED = 6,
	TCBEE_MPTCP_REMOVED = 7,
	TCBEE_MPTCP_SUB_ESTABLISHED = 10,
	TCBEE_MPTCP_SUB_CLOSED = 11,
	TCBEE_MPTCP_SUB_PRIORITY = 13,
	/* Not recorded, mptcp_event_pm_listener() is not hooked */
	TCBEE_MPTCP_LISTENER_CREATED = 15,
	TCBEE_MPTCP_LISTENER_CLOSED = 16,
	/* The token is freed, the kernel may hand it to a new connection from now on */
	TCBEE_MPTCP_TOKEN_DESTROYED = 100,
	/* The path manager tried to open a subflow, error holds the result */
	TCBEE_MPTCP_SUBFLOW_CONNECT = 101,
	/* The peer sent MP_FAIL on a subflow, data_seq holds the sequence it reported */
	TCBEE_MPTCP_MP_FAIL = 102,
	/*
	 * The path manager marked a subflow stale: it made no progress over several
	 * retransmission timeouts while another subflow could take its data. Its time is the end
	 * of the check, which already requeued the subflow's pending data (PENDING_REQUEUED).
	 */
	TCBEE_MPTCP_SUBFLOW_STALE = 103,
	/*
	 * This host sent MP_PRIO for the subflows on a local address (addr): backup holds the new
	 * flag, error 0 or the negative error (no subflow uses the address)
	 */
	TCBEE_MPTCP_MP_PRIO_SENT = 104,
	/*
	 * The connection retransmitted data at the data level (MPTCP) after its retransmission
	 * timeout, on a subflow the scheduler chose, possibly another than the one that lost it
	 */
	TCBEE_MPTCP_REINJECTED = 105,
	/* Data that waited on a subflow (stale or closing) is queued again for the other subflows */
	TCBEE_MPTCP_PENDING_REQUEUED = 106,
	/*
	 * The connection fell back to plain TCP in the handshake: this host requested MPTCP and
	 * the peer's SYN-ACK did not carry MP_CAPABLE. Client side only: the server side's plain
	 * TCP socket shows as a flow without a token.
	 */
	TCBEE_MPTCP_FALLBACK = 107,
};

/*
 * MPTCP path manager and connection lifecycle (-M pm), MPTCP_PM_EVENTS. The header holds the
 * tuple of the subflow, or for connection events the tuple of the connection, which is the one
 * of its first subflow. Fields that do not apply to an event are 0.
 */
struct mptcp_pm_entry {
	TCBEE_SOCK_HEADER
	/* Local token of the connection, the conn_id of its subflows */
	uint32_t token;
	/* Token of the peer, known on the subflows that the client joined (MP_JOIN) */
	uint32_t remote_token;
	/* Subflow number within the connection, kernel 6.5 and newer */
	uint32_t subflow_id;
	/* SUBFLOW_CONNECT, MP_PRIO_SENT: 0 or the negative error */
	int64_t error;
	/* enum tcbee_mptcp_event */
	uint8_t event;
	/*
	 * Address ids of the subflow's two ends (255: not set yet), and its backup flag;
	 * MP_PRIO_SENT has no subflow, backup is the new flag of addr
	 */
	uint8_t local_id;
	uint8_t remote_id;
	uint8_t backup;
	/*
	 * ANNOUNCED, REMOVED, SUBFLOW_CONNECT, MP_PRIO_SENT: the address (id, AF_INET(6), port in
	 * host order).
	 * addr_0 to addr_3 hold its bytes in network order, 4 each, an IPv4 address only addr_0;
	 * words and not bytes, so that every part is a database column.
	 */
	uint8_t addr_id;
	uint16_t addr_family;
	uint16_t addr_port;
	uint32_t addr_0;
	uint32_t addr_1;
	uint32_t addr_2;
	uint32_t addr_3;
	/*
	 * A data-level (MPTCP) sequence number: MP_FAIL the sequence the peer reported,
	 * REINJECTED and PENDING_REQUEUED the connection's oldest unacknowledged byte when the
	 * kernel function started (ACKs may move it on before the first byte is resent)
	 */
	uint64_t data_seq;
	/* REINJECTED: the bytes that the connection retransmitted at the data level */
	uint32_t data_len;
};

/* tracepoint tcp/tcp_bad_csum, TCP_BAD_CSUM_QUEUE. IPv4 addresses only. */
struct tcp_bad_csum_entry {
	uint64_t time;
	uint64_t hook_seq;
	uint8_t saddr[4];
	uint8_t daddr[4];
};

/*
 * Key and value of the FLOWS map. IPv4 addresses use the first 4 bytes. The padding
 * byte at the end is zeroed by the eBPF side so equal flows hash equally.
 */
struct ip_tuple {
	uint8_t src_ip[16];
	uint8_t dst_ip[16];
	uint16_t sport;
	uint16_t dport;
	uint8_t protocol;
};

/*
 * Key of the HOOK_SEQ map: one counter per flow direction (the tuple as the hook sees it,
 * not canonical) and ring buffer id. family keeps an IPv4 tuple apart from the IPv6 address with
 * the same leading bytes on the socket ring buffers, which carry both. 40 bytes without
 * padding; the padding byte inside ip_tuple is zeroed like for FLOWS.
 */
struct hook_seq_key {
	struct ip_tuple tuple;
	uint8_t rb;
	uint8_t family;
};

/* Key of the FILTER_*_IPS maps, same address encoding as ip_tuple */
struct filter_ip {
	uint8_t addr[16];
};

/* Sizes are mirrored by const asserts in tcbee-common */
_Static_assert(sizeof(struct tcp4_packet_trace) == 40, "tcp4_packet_trace size");
_Static_assert(sizeof(struct tcp6_packet_trace) == 64, "tcp6_packet_trace size");
_Static_assert(sizeof(struct sock_trace_entry) == 184, "sock_trace_entry size");
_Static_assert(sizeof(struct cwnd_trace_entry) == 72, "cwnd_trace_entry size");
_Static_assert(sizeof(struct cubic_trace_entry) == 120, "cubic_trace_entry size");
_Static_assert(sizeof(struct bbr_trace_entry) == 120, "bbr_trace_entry size");
_Static_assert(sizeof(struct tcp_probe_entry) == 128, "tcp_probe_entry size");
_Static_assert(sizeof(struct tcp_retransmit_synack_entry) == 64,
	       "tcp_retransmit_synack_entry size");
_Static_assert(sizeof(struct tcp_bad_csum_entry) == 24, "tcp_bad_csum_entry size");
_Static_assert(sizeof(struct mptcp_pm_entry) == 136, "mptcp_pm_entry size");
/* The address is read into addr_0 to addr_3 at once */
_Static_assert(__builtin_offsetof(struct mptcp_pm_entry, addr_3) ==
		       __builtin_offsetof(struct mptcp_pm_entry, addr_0) + 12,
	       "mptcp_pm_entry address words adjacent");
_Static_assert(sizeof(struct ip_tuple) == 38, "ip_tuple size");
_Static_assert(sizeof(struct hook_seq_key) == 40, "hook_seq_key size");
_Static_assert(sizeof(struct filter_ip) == 16, "filter_ip size");

#endif /* __TCBEE_RECORDS_H */
