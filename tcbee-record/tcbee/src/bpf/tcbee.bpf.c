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
#include "hook_seq.h"
#include "cc_structs.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* ---- Tracepoints (-t) ------------------------------------------------------------ */

/*
 * The address arrays are copied with bpf_probe_read_kernel(). A direct copy would load
 * through ctx + CO-RE offset, and the verifier rejects loads through a modified ctx
 * pointer; only single fields like ctx->sport fold the offset into the load.
 */

/* IPv4 address in an ip_tuple, network byte order in the first 4 bytes */
static __always_inline void tuple_set_v4(__u8 *dst, const __u8 *src)
{
	__builtin_memcpy(dst, src, 4);
}

SEC("tracepoint/tcp/tcp_probe")
int tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	/* sockaddr_in or sockaddr_in6 */
	__u8 saddr[28] __attribute__((aligned(8))), daddr[28] __attribute__((aligned(8)));
	struct tcp_probe_entry *rec;
	__u16 sport, dport, family;
	struct ip_tuple t;
	__u64 seq;

	sport = ctx->sport;
	dport = ctx->dport;
	if (!filter_ports_match(sport, dport))
		return 0;

	if (BPF_CORE_READ_INTO(&saddr, ctx, saddr) || BPF_CORE_READ_INTO(&daddr, ctx, daddr)) {
		/* Cannot fill the record without the addresses */
		count_error(RB_TCP_PROBE);
		return 0;
	}
	family = ctx->family;

	__builtin_memset(&t, 0, sizeof(t));
	if (family == AF_INET6) {
		/* sin6_addr is at offset 8 */
		__builtin_memcpy(t.src_ip, &saddr[8], 16);
		__builtin_memcpy(t.dst_ip, &daddr[8], 16);
	} else {
		/* sin_addr is at offset 4 */
		tuple_set_v4(t.src_ip, &saddr[4]);
		tuple_set_v4(t.dst_ip, &daddr[4]);
	}
	t.sport = sport;
	t.dport = dport;
	t.protocol = IPPROTO_TCP;
	if (filter_needs_tuple() && !filter_tuple_match(&t))
		return 0;

	if (!hook_seq_tuple(&t, family, RB_TCP_PROBE, &seq))
		return 0;
	rec = reserve(&TCP_PROBE_QUEUE, RB_TCP_PROBE, rec);
	if (rec) {
		rec->time = bpf_ktime_get_ns();
		rec->hook_seq = seq;
		__builtin_memcpy(rec->saddr, saddr, sizeof(saddr));
		__builtin_memcpy(rec->daddr, daddr, sizeof(daddr));
		rec->sport = sport;
		rec->dport = dport;
		rec->family = family;
		rec->mark = ctx->mark;
		rec->data_len = ctx->data_len;
		rec->snd_nxt = ctx->snd_nxt;
		rec->snd_una = ctx->snd_una;
		rec->snd_cwnd = ctx->snd_cwnd;
		rec->ssthresh = ctx->ssthresh;
		rec->snd_wnd = ctx->snd_wnd;
		rec->srtt = ctx->srtt;
		rec->rcv_wnd = ctx->rcv_wnd;
		rec->sock_cookie = ctx->sock_cookie;
		commit(rec, RB_TCP_PROBE);
	}

	if (FLOW_TRACKING)
		flow_track(&t);
	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_synack")
int tcp_retransmit_synack(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
	__u8 saddr[4] __attribute__((aligned(4))), daddr[4] __attribute__((aligned(4)));
	__u8 saddr_v6[16] __attribute__((aligned(8))), daddr_v6[16] __attribute__((aligned(8)));
	struct tcp_retransmit_synack_entry *rec;
	__u16 sport, dport, family;
	struct ip_tuple t;
	__u64 seq;

	sport = ctx->sport;
	dport = ctx->dport;
	if (!filter_ports_match(sport, dport))
		return 0;

	if (BPF_CORE_READ_INTO(&saddr, ctx, saddr) || BPF_CORE_READ_INTO(&daddr, ctx, daddr) ||
	    BPF_CORE_READ_INTO(&saddr_v6, ctx, saddr_v6) ||
	    BPF_CORE_READ_INTO(&daddr_v6, ctx, daddr_v6)) {
		/* Cannot fill the record without the addresses */
		count_error(RB_RETRANSMIT_SYNACK);
		return 0;
	}
	family = ctx->family;

	__builtin_memset(&t, 0, sizeof(t));
	if (family == AF_INET6) {
		__builtin_memcpy(t.src_ip, saddr_v6, 16);
		__builtin_memcpy(t.dst_ip, daddr_v6, 16);
	} else {
		tuple_set_v4(t.src_ip, saddr);
		tuple_set_v4(t.dst_ip, daddr);
	}
	t.sport = sport;
	t.dport = dport;
	t.protocol = IPPROTO_TCP;
	if (filter_needs_tuple() && !filter_tuple_match(&t))
		return 0;

	if (!hook_seq_tuple(&t, family, RB_RETRANSMIT_SYNACK, &seq))
		return 0;
	rec = reserve(&TCP_RETRANSMIT_SYNACK_QUEUE, RB_RETRANSMIT_SYNACK, rec);
	if (rec) {
		rec->time = bpf_ktime_get_ns();
		rec->hook_seq = seq;
		rec->sport = sport;
		rec->dport = dport;
		rec->family = family;
		__builtin_memcpy(rec->saddr, saddr, sizeof(saddr));
		__builtin_memcpy(rec->daddr, daddr, sizeof(daddr));
		__builtin_memcpy(rec->saddr_v6, saddr_v6, sizeof(saddr_v6));
		__builtin_memcpy(rec->daddr_v6, daddr_v6, sizeof(daddr_v6));
		commit(rec, RB_RETRANSMIT_SYNACK);
	}

	if (FLOW_TRACKING)
		flow_track(&t);
	return 0;
}

/* Event class tcp_event_skb. saddr and daddr hold a sockaddr_in or sockaddr_in6. */
SEC("tracepoint/tcp/tcp_bad_csum")
int tcp_bad_csum(struct trace_event_raw_tcp_event_skb *ctx)
{
	__u8 saddr[28] __attribute__((aligned(8))), daddr[28] __attribute__((aligned(8)));
	struct tcp_bad_csum_entry *rec;
	__u16 sport, dport, family;
	struct ip_tuple t;
	bool is_ipv4;
	__u64 seq;

	if (BPF_CORE_READ_INTO(&saddr, ctx, saddr) || BPF_CORE_READ_INTO(&daddr, ctx, daddr)) {
		/* The filter cannot be evaluated without the event, count it as an error */
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
	if (filter_needs_tuple() && !filter_tuple_match(&t))
		return 0;

	if (!hook_seq_tuple(&t, family, RB_BAD_CSUM, &seq))
		return 0;
	rec = reserve(&TCP_BAD_CSUM_QUEUE, RB_BAD_CSUM, rec);
	if (rec) {
		rec->time = bpf_ktime_get_ns();
		rec->hook_seq = seq;
		/* The record only holds IPv4 addresses, leave them zero for IPv6 */
		if (is_ipv4) {
			__builtin_memcpy(rec->saddr, &saddr[4], 4);
			__builtin_memcpy(rec->daddr, &daddr[4], 4);
		}
		commit(rec, RB_BAD_CSUM);
	}
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
 * Pointer to len bytes at offset off of the packet, like the kernel's
 * skb_header_pointer(): straight into the linear data if the bytes are there (no helper
 * call), otherwise copied into buf with bpf_skb_load_bytes(), which also reads paged
 * data. NULL if the packet is shorter. Both paths yield the same bytes.
 *
 * The header structs are 4 byte aligned while the IP header starts at offset 14, so
 * direct loads can be unaligned. The verifier allows that on architectures with
 * efficient unaligned access (x86, arm64, ...), which is where this tool runs.
 */
static __always_inline void *skb_header(struct __sk_buff *skb, __u32 off, void *buf, __u32 len)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	void *ptr = data + off;

	if (ptr + len <= data_end)
		return ptr;
	if (bpf_skb_load_bytes(skb, off, buf, len))
		return NULL;
	return buf;
}

/*
 * Every early return happens before the filter, so a packet that passes the filter is
 * always counted as handled or dropped. IPv6 extension headers
 * are not parsed, nexthdr must be TCP directly.
 */
static __always_inline int trace_packet(struct __sk_buff *skb, void *rb4, __u32 rb4_id, void *rb6,
					__u32 rb6_id)
{
	struct tc_tcp_hdr tcp_buf, *tcp;
	__be16 proto_buf, *proto;
	__u16 sport, dport;
	struct ip_tuple t;
	__u64 seq;

	proto = skb_header(skb, TC_ETH_PROTO_OFF, &proto_buf, sizeof(proto_buf));
	if (!proto)
		return TC_ACT_UNSPEC;

	__builtin_memset(&t, 0, sizeof(t));
	t.protocol = IPPROTO_TCP;

	if (*proto == bpf_htons(ETH_P_IP)) {
		struct tc_ipv4_hdr ip_buf, *ip;
		struct tcp4_packet_trace *rec;
		__u32 ip_hlen;

		ip = skb_header(skb, TC_ETH_HLEN, &ip_buf, sizeof(ip_buf));
		if (!ip)
			return TC_ACT_UNSPEC;
		/* Non-first fragments carry no TCP header */
		if (ip->protocol != IPPROTO_TCP || (bpf_ntohs(ip->frag_off) & IP_OFFSET))
			return TC_ACT_UNSPEC;
		ip_hlen = (ip->version_ihl & 0x0F) << 2;
		if (ip_hlen < sizeof(*ip))
			ip_hlen = sizeof(*ip);
		tcp = skb_header(skb, TC_ETH_HLEN + ip_hlen, &tcp_buf, sizeof(tcp_buf));
		if (!tcp)
			return TC_ACT_UNSPEC;

		sport = bpf_ntohs(tcp->source);
		dport = bpf_ntohs(tcp->dest);
		__builtin_memcpy(t.src_ip, &ip->saddr, 4);
		__builtin_memcpy(t.dst_ip, &ip->daddr, 4);
		t.sport = sport;
		t.dport = dport;
		if (!filter_ports_match(sport, dport) ||
		    (filter_needs_tuple() && !filter_tuple_match(&t)))
			return TC_ACT_UNSPEC;

		if (!hook_seq_tuple(&t, AF_INET, rb4_id, &seq))
			return TC_ACT_UNSPEC;
		rec = reserve(rb4, rb4_id, rec);
		if (rec) {
			rec->time = bpf_ktime_get_ns();
			rec->hook_seq = seq;
			rec->saddr = bpf_ntohl(ip->saddr);
			rec->daddr = bpf_ntohl(ip->daddr);
			rec->sport = sport;
			rec->dport = dport;
			rec->seq = bpf_ntohl(tcp->seq);
			rec->ack = bpf_ntohl(tcp->ack_seq);
			rec->window = bpf_ntohs(tcp->window);
			rec->flags = tcp->flags;
			commit(rec, rb4_id);
		}

		flow_track(&t);
	} else if (*proto == bpf_htons(ETH_P_IPV6)) {
		struct tc_ipv6_hdr ip6_buf, *ip6;
		struct tcp6_packet_trace *rec;

		ip6 = skb_header(skb, TC_ETH_HLEN, &ip6_buf, sizeof(ip6_buf));
		if (!ip6)
			return TC_ACT_UNSPEC;
		if (ip6->nexthdr != IPPROTO_TCP)
			return TC_ACT_UNSPEC;
		tcp = skb_header(skb, TC_ETH_HLEN + sizeof(*ip6), &tcp_buf, sizeof(tcp_buf));
		if (!tcp)
			return TC_ACT_UNSPEC;

		sport = bpf_ntohs(tcp->source);
		dport = bpf_ntohs(tcp->dest);
		__builtin_memcpy(t.src_ip, ip6->saddr, 16);
		__builtin_memcpy(t.dst_ip, ip6->daddr, 16);
		t.sport = sport;
		t.dport = dport;
		if (!filter_ports_match(sport, dport) ||
		    (filter_needs_tuple() && !filter_tuple_match(&t)))
			return TC_ACT_UNSPEC;

		if (!hook_seq_tuple(&t, AF_INET6, rb6_id, &seq))
			return TC_ACT_UNSPEC;
		rec = reserve(rb6, rb6_id, rec);
		if (rec) {
			rec->time = bpf_ktime_get_ns();
			rec->hook_seq = seq;
			__builtin_memcpy(rec->saddr_v6, ip6->saddr, 16);
			__builtin_memcpy(rec->daddr_v6, ip6->daddr, 16);
			rec->sport = sport;
			rec->dport = dport;
			rec->seq = bpf_ntohl(tcp->seq);
			rec->ack = bpf_ntohl(tcp->ack_seq);
			rec->window = bpf_ntohs(tcp->window);
			rec->flags = tcp->flags;
			commit(rec, rb6_id);
		}

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
 * The hooks pass a struct sock. The verifier only allows direct loads within the BTF type
 * of a pointer, so the tcp_sock (and the congestion control state in it) is reached
 * through bpf_skc_to_tcp_sock() (kernel 5.9), one cheap helper call instead of one
 * bpf_probe_read_kernel() per field. It returns NULL for sockets that are not full TCP
 * sockets, which these hooks do not see; that is counted as an error.
 */

static __always_inline int trace_cwnd(struct sock *sk, void *ringbuf, __u32 rb)
{
	struct cwnd_trace_entry *rec;
	struct tcp_sock *tp;
	__u16 sport, dport;
	__u64 seq;

	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, rb, &seq))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error(rb);
	} else if ((rec = reserve(ringbuf, rb, rec))) {
		fill_header(rec, sk, sport, dport, seq);
		rec->snd_cwnd = tp->snd_cwnd;
		commit(rec, rb);
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

static __always_inline int trace_sock(struct sock *sk, struct sk_buff *skb, void *ringbuf,
				      __u32 rb)
{
	struct sock_trace_entry *rec;
	struct tcp_sock *tp;
	__u16 sport, dport;
	__u64 seq;

	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, rb, &seq))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error(rb);
	} else if ((rec = reserve(ringbuf, rb, rec))) {
		fill_header(rec, sk, sport, dport, seq);
		/* struct sock */
		rec->pacing_rate = sk->sk_pacing_rate;
		rec->max_pacing_rate = sk->sk_max_pacing_rate;
		/* struct inet_connection_sock */
		rec->backoff = tp->inet_conn.icsk_backoff;
		rec->rto = tp->inet_conn.icsk_rto;
		rec->ato = 0;
		rec->rcv_mss = tp->inet_conn.icsk_ack.rcv_mss;
		/* struct tcp_sock */
		rec->snd_cwnd = tp->snd_cwnd;
		rec->bytes_acked = tp->bytes_acked;
		rec->snd_ssthresh = tp->snd_ssthresh;
		rec->total_retrans = tp->total_retrans;
		rec->probes = tp->keepalive_probes;
		rec->lost = tp->lost;
		rec->sacked_out = tp->sacked_out;
		rec->retrans = tp->retrans_out;
		rec->rcv_ssthresh = tp->rcv_ssthresh;
		rec->rttvar = tp->rttvar_us;
		rec->advmss = tp->advmss;
		rec->reordering = tp->reordering;
		rec->rcv_rtt = tp->rcv_rtt_est.rtt_us;
		rec->rcv_space = tp->rcvq_space.space;
		rec->bytes_received = tp->bytes_received;
		rec->segs_out = tp->segs_out;
		rec->segs_in = tp->segs_in;
		/* struct tcp_options_received, not read yet */
		rec->snd_wscale = 0;
		rec->rcv_wscale = 0;
		commit(rec, rb);
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

SEC("fentry/__tcp_transmit_skb")
int BPF_PROG(sock_sendmsg, struct sock *sk, struct sk_buff *skb)
{
	return trace_sock(sk, skb, &TCP_SEND_SOCK_EVENTS, RB_SOCK_SEND);
}

/* Only triggers in established state */
SEC("fentry/tcp_rcv_established")
int BPF_PROG(sock_recvmsg, struct sock *sk, struct sk_buff *skb)
{
	return trace_sock(sk, skb, &TCP_RECV_SOCK_EVENTS, RB_SOCK_RECV);
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
	struct cubic_trace_entry *rec;
	struct bictcp___tcbee *ca;
	struct tcp_sock *tp;
	__u16 sport, dport;
	__u64 seq;

	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, RB_CUBIC, &seq))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error(RB_CUBIC);
	} else if ((rec = reserve(&CUBIC_EVENTS, RB_CUBIC, rec))) {
		ca = tcp_ca(tp);
		fill_header(rec, sk, sport, dport, seq);
		rec->cnt = ca->cnt;
		rec->last_max_cwnd = ca->last_max_cwnd;
		rec->last_cwnd = ca->last_cwnd;
		rec->last_time = ca->last_time;
		rec->bic_origin_point = ca->bic_origin_point;
		rec->bic_K = ca->bic_K;
		rec->delay_min = ca->delay_min;
		rec->epoch_start = ca->epoch_start;
		rec->ack_cnt = ca->ack_cnt;
		rec->tcp_cwnd = ca->tcp_cwnd;
		rec->round_start = ca->round_start;
		rec->end_seq = ca->end_seq;
		rec->last_ack = ca->last_ack;
		rec->curr_rtt = ca->curr_rtt;
		commit(rec, RB_CUBIC);
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

/* ---- BBR (-a) ---------------------------------------------------------------------- */

/*
 * tcp_bbr is usually a module, fentry needs it loaded when the object is loaded. The
 * struct bbr offsets are relocated against the module's BTF; the verifier only checks
 * the loads against icsk_ca_priv in the vmlinux tcp_sock.
 */
static __always_inline int trace_bbr(struct sock *sk)
{
	struct bbr_trace_entry *rec;
	struct bbr___tcbee *bbr;
	struct tcp_sock *tp;
	__u16 sport, dport;
	__u64 seq;

	if (!sk) {
		/* The filter cannot be evaluated without the socket, count it as an error */
		count_error(RB_BBR);
		return 0;
	}
	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, RB_BBR, &seq))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error(RB_BBR);
	} else if ((rec = reserve(&BBR_EVENTS, RB_BBR, rec))) {
		bbr = tcp_ca(tp);
		fill_header(rec, sk, sport, dport, seq);
		rec->min_rtt_us = bbr->min_rtt_us;
		rec->min_rtt_stamp = bbr->min_rtt_stamp;
		rec->probe_rtt_done_stamp = bbr->probe_rtt_done_stamp;
		rec->rtt_cnt = bbr->rtt_cnt;
		rec->next_rtt_delivered = bbr->next_rtt_delivered;
		rec->cycle_mstamp = bbr->cycle_mstamp;
		/* Long-term bandwidth sampling only exists in BBRv1, 0 for BBRv3 and others */
		if (bpf_core_field_exists(bbr->lt_bw))
			rec->lt_bw = bbr->lt_bw;
		if (bpf_core_field_exists(bbr->lt_last_delivered))
			rec->lt_last_delivered = bbr->lt_last_delivered;
		if (bpf_core_field_exists(bbr->lt_last_stamp))
			rec->lt_last_stamp = bbr->lt_last_stamp;
		if (bpf_core_field_exists(bbr->lt_last_lost))
			rec->lt_last_lost = bbr->lt_last_lost;
		rec->prior_cwnd = bbr->prior_cwnd;
		rec->full_bw = bbr->full_bw;
		commit(rec, RB_BBR);
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

/* Called on every ACK */
SEC("fentry/bbr_main")
int BPF_PROG(bbr_cong_control, struct sock *sk)
{
	return trace_bbr(sk);
}

/* Called on congestion events */
SEC("fentry/bbr_cwnd_event")
int BPF_PROG(bbr_cwnd_event, struct sock *sk)
{
	return trace_bbr(sk);
}
