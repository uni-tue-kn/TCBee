// SPDX-License-Identifier: (MIT OR GPL-2.0)
// All tcbee-record eBPF programs, built into a single object with libbpf CO-RE.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "config.h"
#include "records.h"
#include "maps.h"
#include "counters.h"
#include "filter.h"
#include "flow.h"
#include "cc_structs.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* ---- Tracepoints (-t) ------------------------------------------------------------ */

/* IPv4 address in an ip_tuple, network byte order in the first 4 bytes */
static __always_inline void tuple_set_v4(__u8 *dst, const __u8 *src)
{
	__builtin_memcpy(dst, src, 4);
}

SEC("tracepoint/tcp/tcp_probe")
int tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	struct tcp_probe_entry rec = {};
	struct ip_tuple t;

	/* saddr and daddr hold a sockaddr_in or sockaddr_in6 */
	if (BPF_CORE_READ_INTO(&rec.saddr, ctx, saddr) ||
	    BPF_CORE_READ_INTO(&rec.daddr, ctx, daddr)) {
		/* The filter cannot be evaluated without the event, count it as an error */
		count_attempt(RB_TCP_PROBE);
		count_error(RB_TCP_PROBE);
		return 0;
	}
	rec.sport = ctx->sport;
	rec.dport = ctx->dport;
	rec.family = ctx->family;

	if (!filter_ports_match(rec.sport, rec.dport))
		return 0;

	__builtin_memset(&t, 0, sizeof(t));
	if (rec.family == AF_INET6) {
		/* sin6_addr is at offset 8 */
		__builtin_memcpy(t.src_ip, &rec.saddr[8], 16);
		__builtin_memcpy(t.dst_ip, &rec.daddr[8], 16);
	} else {
		/* sin_addr is at offset 4 */
		tuple_set_v4(t.src_ip, &rec.saddr[4]);
		tuple_set_v4(t.dst_ip, &rec.daddr[4]);
	}
	t.sport = rec.sport;
	t.dport = rec.dport;
	t.protocol = IPPROTO_TCP;
	if (filter_needs_tuple() && !filter_tuple_match(&t))
		return 0;

	count_attempt(RB_TCP_PROBE);
	rec.time = bpf_ktime_get_ns();
	rec.mark = ctx->mark;
	rec.data_len = ctx->data_len;
	rec.snd_nxt = ctx->snd_nxt;
	rec.snd_una = ctx->snd_una;
	rec.snd_cwnd = ctx->snd_cwnd;
	rec.ssthresh = ctx->ssthresh;
	rec.snd_wnd = ctx->snd_wnd;
	rec.srtt = ctx->srtt;
	rec.rcv_wnd = ctx->rcv_wnd;
	rec.sock_cookie = ctx->sock_cookie;
	submit(&TCP_PROBE_QUEUE, RB_TCP_PROBE, &rec);

	flow_track(&t);
	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_synack")
int tcp_retransmit_synack(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
	struct tcp_retransmit_synack_entry rec = {};
	struct ip_tuple t;

	if (BPF_CORE_READ_INTO(&rec.saddr, ctx, saddr) ||
	    BPF_CORE_READ_INTO(&rec.daddr, ctx, daddr) ||
	    BPF_CORE_READ_INTO(&rec.saddr_v6, ctx, saddr_v6) ||
	    BPF_CORE_READ_INTO(&rec.daddr_v6, ctx, daddr_v6)) {
		/* The filter cannot be evaluated without the event, count it as an error */
		count_attempt(RB_RETRANSMIT_SYNACK);
		count_error(RB_RETRANSMIT_SYNACK);
		return 0;
	}
	rec.sport = ctx->sport;
	rec.dport = ctx->dport;
	rec.family = ctx->family;

	if (!filter_ports_match(rec.sport, rec.dport))
		return 0;

	__builtin_memset(&t, 0, sizeof(t));
	if (rec.family == AF_INET6) {
		__builtin_memcpy(t.src_ip, rec.saddr_v6, 16);
		__builtin_memcpy(t.dst_ip, rec.daddr_v6, 16);
	} else {
		tuple_set_v4(t.src_ip, rec.saddr);
		tuple_set_v4(t.dst_ip, rec.daddr);
	}
	t.sport = rec.sport;
	t.dport = rec.dport;
	t.protocol = IPPROTO_TCP;
	if (filter_needs_tuple() && !filter_tuple_match(&t))
		return 0;

	count_attempt(RB_RETRANSMIT_SYNACK);
	rec.time = bpf_ktime_get_ns();
	submit(&TCP_RETRANSMIT_SYNACK_QUEUE, RB_RETRANSMIT_SYNACK, &rec);

	flow_track(&t);
	return 0;
}

/* Event class tcp_event_skb. saddr and daddr hold a sockaddr_in or sockaddr_in6. */
SEC("tracepoint/tcp/tcp_bad_csum")
int tcp_bad_csum(struct trace_event_raw_tcp_event_skb *ctx)
{
	struct tcp_bad_csum_entry rec = {};
	__u8 saddr[28], daddr[28];
	__u16 sport, dport, family;
	struct ip_tuple t;
	bool is_ipv4;

	if (BPF_CORE_READ_INTO(&saddr, ctx, saddr) || BPF_CORE_READ_INTO(&daddr, ctx, daddr)) {
		/* The filter cannot be evaluated without the event, count it as an error */
		count_attempt(RB_BAD_CSUM);
		count_error(RB_BAD_CSUM);
		return 0;
	}

	/* sin_port and sin6_port are at offset 2 in network byte order */
	sport = ((__u16)saddr[2] << 8) | saddr[3];
	dport = ((__u16)daddr[2] << 8) | daddr[3];
	if (!filter_ports_match(sport, dport))
		return 0;

	/* sa_family in host byte order at offset 0, sin_addr at 4, sin6_addr at 8 */
	__builtin_memcpy(&family, saddr, sizeof(family));
	is_ipv4 = family == AF_INET;
	if (filter_needs_tuple()) {
		__builtin_memset(&t, 0, sizeof(t));
		if (is_ipv4) {
			tuple_set_v4(t.src_ip, &saddr[4]);
			tuple_set_v4(t.dst_ip, &daddr[4]);
		} else {
			__builtin_memcpy(t.src_ip, &saddr[8], 16);
			__builtin_memcpy(t.dst_ip, &daddr[8], 16);
		}
		t.sport = sport;
		t.dport = dport;
		t.protocol = IPPROTO_TCP;
		if (!filter_tuple_match(&t))
			return 0;
	}

	/* The record only holds IPv4 addresses, leave them zero for IPv6 */
	if (is_ipv4) {
		__builtin_memcpy(rec.saddr, &saddr[4], 4);
		__builtin_memcpy(rec.daddr, &daddr[4], 4);
	}

	count_attempt(RB_BAD_CSUM);
	rec.time = bpf_ktime_get_ns();
	submit(&TCP_BAD_CSUM_QUEUE, RB_BAD_CSUM, &rec);
	return 0;
}

/* ---- TC packet tracer (-h) ------------------------------------------------------- */

/*
 * Plain wire formats. The vmlinux.h variants carry preserve_access_index, which would
 * add pointless CO-RE relocations for fixed uapi layouts.
 */
struct tc_ipv4_hdr {
	__u8 version_ihl;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct tc_ipv6_hdr {
	__be32 version_tc_flow;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct tc_tcp_hdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff_res;
	__u8 flags; /* CWR ECE URG ACK PSH RST SYN FIN */
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

#define TC_ETH_HLEN 14
#define TC_ETH_PROTO_OFF 12
_Static_assert(sizeof(struct tc_ipv4_hdr) == 20, "ipv4 header");
_Static_assert(sizeof(struct tc_ipv6_hdr) == 40, "ipv6 header");
_Static_assert(sizeof(struct tc_tcp_hdr) == 20, "tcp header");

/*
 * Every early return happens before the filter, so a packet that passes the filter is
 * always counted as attempted and then as handled or dropped. IPv6 extension headers
 * are not parsed, nexthdr must be TCP directly.
 */
static __always_inline int trace_packet(struct __sk_buff *skb, void *rb4, __u32 rb4_id, void *rb6,
					__u32 rb6_id)
{
	struct tc_tcp_hdr tcp;
	struct ip_tuple t;
	__be16 proto;

	if (bpf_skb_load_bytes(skb, TC_ETH_PROTO_OFF, &proto, sizeof(proto)))
		return TC_ACT_UNSPEC;

	__builtin_memset(&t, 0, sizeof(t));
	t.protocol = IPPROTO_TCP;

	if (proto == bpf_htons(ETH_P_IP)) {
		struct tcp4_packet_trace rec = {};
		struct tc_ipv4_hdr ip;
		__u32 ip_hlen;

		if (bpf_skb_load_bytes(skb, TC_ETH_HLEN, &ip, sizeof(ip)))
			return TC_ACT_UNSPEC;
		/* Non-first fragments carry no TCP header */
		if (ip.protocol != IPPROTO_TCP || (bpf_ntohs(ip.frag_off) & IP_OFFSET))
			return TC_ACT_UNSPEC;
		ip_hlen = (ip.version_ihl & 0x0F) << 2;
		if (ip_hlen < sizeof(ip))
			ip_hlen = sizeof(ip);
		if (bpf_skb_load_bytes(skb, TC_ETH_HLEN + ip_hlen, &tcp, sizeof(tcp)))
			return TC_ACT_UNSPEC;

		rec.saddr = bpf_ntohl(ip.saddr);
		rec.daddr = bpf_ntohl(ip.daddr);
		rec.sport = bpf_ntohs(tcp.source);
		rec.dport = bpf_ntohs(tcp.dest);
		__builtin_memcpy(t.src_ip, &ip.saddr, 4);
		__builtin_memcpy(t.dst_ip, &ip.daddr, 4);
		t.sport = rec.sport;
		t.dport = rec.dport;
		if (!filter_ports_match(rec.sport, rec.dport) ||
		    (filter_needs_tuple() && !filter_tuple_match(&t)))
			return TC_ACT_UNSPEC;

		count_attempt(rb4_id);
		rec.time = bpf_ktime_get_ns();
		rec.seq = bpf_ntohl(tcp.seq);
		rec.ack = bpf_ntohl(tcp.ack_seq);
		rec.window = bpf_ntohs(tcp.window);
		rec.flags = tcp.flags;
		submit(rb4, rb4_id, &rec);

		flow_track(&t);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct tcp6_packet_trace rec = {};
		struct tc_ipv6_hdr ip6;

		if (bpf_skb_load_bytes(skb, TC_ETH_HLEN, &ip6, sizeof(ip6)))
			return TC_ACT_UNSPEC;
		if (ip6.nexthdr != IPPROTO_TCP)
			return TC_ACT_UNSPEC;
		if (bpf_skb_load_bytes(skb, TC_ETH_HLEN + sizeof(ip6), &tcp, sizeof(tcp)))
			return TC_ACT_UNSPEC;

		rec.sport = bpf_ntohs(tcp.source);
		rec.dport = bpf_ntohs(tcp.dest);
		__builtin_memcpy(t.src_ip, ip6.saddr, 16);
		__builtin_memcpy(t.dst_ip, ip6.daddr, 16);
		t.sport = rec.sport;
		t.dport = rec.dport;
		if (!filter_ports_match(rec.sport, rec.dport) ||
		    (filter_needs_tuple() && !filter_tuple_match(&t)))
			return TC_ACT_UNSPEC;

		count_attempt(rb6_id);
		rec.time = bpf_ktime_get_ns();
		__builtin_memcpy(rec.saddr_v6, ip6.saddr, 16);
		__builtin_memcpy(rec.daddr_v6, ip6.daddr, 16);
		rec.seq = bpf_ntohl(tcp.seq);
		rec.ack = bpf_ntohl(tcp.ack_seq);
		rec.window = bpf_ntohs(tcp.window);
		rec.flags = tcp.flags;
		submit(rb6, rb6_id, &rec);

		flow_track(&t);
	}

	/*
	 * TC_ACT_UNSPEC hands the packet to the next program unchanged. TC_ACT_OK would end
	 * the chain on tcx and skip programs attached after this one.
	 */
	return TC_ACT_UNSPEC;
}

SEC("tc")
int tc_ingress_packet_tracer(struct __sk_buff *skb)
{
	return trace_packet(skb, &TCP4_PACKETS_INGRESS, RB_TCP4_INGRESS, &TCP6_PACKETS_INGRESS,
			    RB_TCP6_INGRESS);
}

SEC("tc")
int tc_egress_packet_tracer(struct __sk_buff *skb)
{
	return trace_packet(skb, &TCP4_PACKETS_EGRESS, RB_TCP4_EGRESS, &TCP6_PACKETS_EGRESS,
			    RB_TCP6_EGRESS);
}

/* ---- Socket state (-k) and cwnd only (-w) ---------------------------------------- */

/*
 * Ports of a socket for the filter. If they cannot be read the filter cannot be
 * evaluated, which is counted as an error. Returns false if the event is done.
 */
static __always_inline bool sock_ports_filter(struct sock *sk, __u32 rb, __u16 *sport,
					      __u16 *dport)
{
	if (sk_ports(sk, sport, dport)) {
		count_attempt(rb);
		count_error(rb);
		return false;
	}
	return filter_sock(sk, *sport, *dport);
}

static __always_inline int trace_cwnd(struct sock *sk, void *ringbuf, __u32 rb)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct cwnd_trace_entry rec = {};
	__u16 sport, dport;

	if (!sock_ports_filter(sk, rb, &sport, &dport))
		return 0;
	count_attempt(rb);

	if (fill_header(&rec, sk)) {
		count_error(rb);
	} else {
		rec.snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
		submit(ringbuf, rb, &rec);
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

static __always_inline int trace_sock(struct sock *sk, struct sk_buff *skb, void *ringbuf,
				      __u32 rb, __u32 bytes_slot)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct sock_trace_entry rec = {};
	__u16 sport, dport;

	if (!sock_ports_filter(sk, rb, &sport, &dport))
		return 0;
	count_attempt(rb);

	add_stat(bytes_slot, BPF_CORE_READ(skb, len));

	if (fill_header(&rec, sk)) {
		count_error(rb);
	} else {
		/* struct sock */
		rec.pacing_rate = BPF_CORE_READ(sk, sk_pacing_rate);
		rec.max_pacing_rate = BPF_CORE_READ(sk, sk_max_pacing_rate);
		/* struct inet_connection_sock */
		rec.backoff = BPF_CORE_READ(tp, inet_conn.icsk_backoff);
		rec.rto = BPF_CORE_READ(tp, inet_conn.icsk_rto);
		rec.ato = 0;
		rec.rcv_mss = BPF_CORE_READ(tp, inet_conn.icsk_ack.rcv_mss);
		/* struct tcp_sock */
		rec.snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
		rec.bytes_acked = BPF_CORE_READ(tp, bytes_acked);
		rec.snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
		rec.total_retrans = BPF_CORE_READ(tp, total_retrans);
		rec.probes = BPF_CORE_READ(tp, keepalive_probes);
		rec.lost = BPF_CORE_READ(tp, lost);
		rec.sacked_out = BPF_CORE_READ(tp, sacked_out);
		rec.retrans = BPF_CORE_READ(tp, retrans_out);
		rec.rcv_ssthresh = BPF_CORE_READ(tp, rcv_ssthresh);
		rec.rttvar = BPF_CORE_READ(tp, rttvar_us);
		rec.advmss = BPF_CORE_READ(tp, advmss);
		rec.reordering = BPF_CORE_READ(tp, reordering);
		rec.rcv_rtt = BPF_CORE_READ(tp, rcv_rtt_est.rtt_us);
		rec.rcv_space = BPF_CORE_READ(tp, rcvq_space.space);
		rec.bytes_received = BPF_CORE_READ(tp, bytes_received);
		rec.segs_out = BPF_CORE_READ(tp, segs_out);
		rec.segs_in = BPF_CORE_READ(tp, segs_in);
		/* struct tcp_options_received, not read yet */
		rec.snd_wscale = 0;
		rec.rcv_wscale = 0;
		submit(ringbuf, rb, &rec);
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

SEC("fentry/__tcp_transmit_skb")
int BPF_PROG(sock_sendmsg, struct sock *sk, struct sk_buff *skb)
{
	return trace_sock(sk, skb, &TCP_SEND_SOCK_EVENTS, RB_SOCK_SEND, SLOT_TCP_BYTES_SENT);
}

/* Only triggers in established state */
SEC("fentry/tcp_rcv_established")
int BPF_PROG(sock_recvmsg, struct sock *sk, struct sk_buff *skb)
{
	return trace_sock(sk, skb, &TCP_RECV_SOCK_EVENTS, RB_SOCK_RECV, SLOT_TCP_BYTES_RECEIVED);
}

/* Lighter variants of the above that only record the cwnd */
SEC("fentry/__tcp_transmit_skb")
int BPF_PROG(cwnd_sock_sendmsg, struct sock *sk)
{
	return trace_cwnd(sk, &TCP_SEND_CWND_EVENTS, RB_CWND_SEND);
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(cwnd_sock_recvmsg, struct sock *sk)
{
	return trace_cwnd(sk, &TCP_RECEIVE_CWND_EVENTS, RB_CWND_RECV);
}

/* ---- CUBIC (-a) -------------------------------------------------------------------- */

static __always_inline int trace_cubic(struct sock *sk)
{
	struct bictcp___tcbee *ca = inet_csk_ca(sk);
	struct cubic_trace_entry rec = {};
	__u16 sport, dport;

	if (!sock_ports_filter(sk, RB_CUBIC, &sport, &dport))
		return 0;
	count_attempt(RB_CUBIC);

	if (fill_header(&rec, sk)) {
		count_error(RB_CUBIC);
	} else {
		rec.cnt = BPF_CORE_READ(ca, cnt);
		rec.last_max_cwnd = BPF_CORE_READ(ca, last_max_cwnd);
		rec.last_cwnd = BPF_CORE_READ(ca, last_cwnd);
		rec.last_time = BPF_CORE_READ(ca, last_time);
		rec.bic_origin_point = BPF_CORE_READ(ca, bic_origin_point);
		rec.bic_K = BPF_CORE_READ(ca, bic_K);
		rec.delay_min = BPF_CORE_READ(ca, delay_min);
		rec.epoch_start = BPF_CORE_READ(ca, epoch_start);
		rec.ack_cnt = BPF_CORE_READ(ca, ack_cnt);
		rec.tcp_cwnd = BPF_CORE_READ(ca, tcp_cwnd);
		rec.round_start = BPF_CORE_READ(ca, round_start);
		rec.end_seq = BPF_CORE_READ(ca, end_seq);
		rec.last_ack = BPF_CORE_READ(ca, last_ack);
		rec.curr_rtt = BPF_CORE_READ(ca, curr_rtt);
		submit(&CUBIC_EVENTS, RB_CUBIC, &rec);
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

/* Called on every ACK in congestion avoidance */
SEC("fentry/cubictcp_cong_avoid")
int BPF_PROG(cubic_cong_control, struct sock *sk)
{
	return trace_cubic(sk);
}

/* Called on congestion events. TODO: probably the wrong hook */
SEC("fentry/cubictcp_cwnd_event")
int BPF_PROG(cubic_cwnd_event, struct sock *sk)
{
	return trace_cubic(sk);
}
