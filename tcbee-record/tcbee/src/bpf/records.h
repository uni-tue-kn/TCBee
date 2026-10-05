/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * Records written to the ring buffers and the flow/filter map keys.
 *
 * Single source of truth for the kernel/user layout: tcbee-common runs bindgen on this
 * file. The trace files are written with bincode field by field, so the field order and
 * types below define the on-disk format read by tcbee-process. Do not reorder.
 */
#ifndef __TCBEE_RECORDS_H
#define __TCBEE_RECORDS_H

#ifndef __VMLINUX_H__
/* bindgen and other host builds; the eBPF build gets these from vmlinux.h */
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
#endif

/* TC, ring buffers TCP4_PACKETS_{EGRESS,INGRESS}. Addresses in host byte order. */
struct tcp4_packet_trace {
	uint64_t time;
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
};

/* Same hooks as sock_trace_entry, TCP_SEND_CWND_EVENTS / TCP_RECEIVE_CWND_EVENTS */
struct cwnd_trace_entry {
	TCBEE_SOCK_HEADER
	uint32_t snd_cwnd;
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
	uint16_t sport;
	uint16_t dport;
	uint16_t family;
	uint8_t saddr[4];
	uint8_t daddr[4];
	uint8_t saddr_v6[16];
	uint8_t daddr_v6[16];
};

/* tracepoint tcp/tcp_bad_csum, TCP_BAD_CSUM_QUEUE. IPv4 addresses only. */
struct tcp_bad_csum_entry {
	uint64_t time;
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

/* Key of the FILTER_*_IPS maps, same address encoding as ip_tuple */
struct filter_ip {
	uint8_t addr[16];
};

/* Sizes are mirrored by const asserts in tcbee-common */
_Static_assert(sizeof(struct tcp4_packet_trace) == 32, "tcp4_packet_trace size");
_Static_assert(sizeof(struct tcp6_packet_trace) == 56, "tcp6_packet_trace size");
_Static_assert(sizeof(struct sock_trace_entry) == 176, "sock_trace_entry size");
_Static_assert(sizeof(struct cwnd_trace_entry) == 64, "cwnd_trace_entry size");
_Static_assert(sizeof(struct cubic_trace_entry) == 112, "cubic_trace_entry size");
_Static_assert(sizeof(struct bbr_trace_entry) == 112, "bbr_trace_entry size");
_Static_assert(sizeof(struct tcp_probe_entry) == 120, "tcp_probe_entry size");
_Static_assert(sizeof(struct tcp_retransmit_synack_entry) == 56,
	       "tcp_retransmit_synack_entry size");
_Static_assert(sizeof(struct tcp_bad_csum_entry) == 16, "tcp_bad_csum_entry size");
_Static_assert(sizeof(struct ip_tuple) == 38, "ip_tuple size");
_Static_assert(sizeof(struct filter_ip) == 16, "filter_ip size");

#endif /* __TCBEE_RECORDS_H */
