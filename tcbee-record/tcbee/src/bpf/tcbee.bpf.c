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
#include "mptcp.h"
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
	__u64 hook_seq;

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

	if (!hook_seq_tuple(&t, family, RB_TCP_PROBE, &hook_seq))
		return 0;
	rec = reserve(&TCP_PROBE_QUEUE, RB_TCP_PROBE, rec);
	if (rec) {
		rec->time = bpf_ktime_get_ns();
		rec->hook_seq = hook_seq;
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
	__u64 hook_seq;

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

	if (!hook_seq_tuple(&t, family, RB_RETRANSMIT_SYNACK, &hook_seq))
		return 0;
	rec = reserve(&TCP_RETRANSMIT_SYNACK_QUEUE, RB_RETRANSMIT_SYNACK, rec);
	if (rec) {
		rec->time = bpf_ktime_get_ns();
		rec->hook_seq = hook_seq;
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
	__u64 hook_seq;

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

	if (!hook_seq_tuple(&t, family, RB_BAD_CSUM, &hook_seq))
		return 0;
	rec = reserve(&TCP_BAD_CSUM_QUEUE, RB_BAD_CSUM, rec);
	if (rec) {
		rec->time = bpf_ktime_get_ns();
		rec->hook_seq = hook_seq;
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
	__u64 hook_seq;

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

		if (!hook_seq_tuple(&t, AF_INET, rb4_id, &hook_seq))
			return TC_ACT_UNSPEC;
		rec = reserve(rb4, rb4_id, rec);
		if (rec) {
			rec->time = bpf_ktime_get_ns();
			rec->hook_seq = hook_seq;
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

		if (!hook_seq_tuple(&t, AF_INET6, rb6_id, &hook_seq))
			return TC_ACT_UNSPEC;
		rec = reserve(rb6, rb6_id, rec);
		if (rec) {
			rec->time = bpf_ktime_get_ns();
			rec->hook_seq = hook_seq;
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

static __always_inline int trace_cwnd(struct sock *sk, void *ringbufs, __u32 rb)
{
	struct cwnd_trace_entry *rec;
	struct tcp_sock *tp;
	__u16 sport, dport;
	__u64 hook_seq;

	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, rb, &hook_seq))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error(rb);
	} else if ((rec = reserve(ringbufs, rb, rec))) {
		fill_header(rec, sk, sport, dport, hook_seq);
		rec->snd_cwnd = tp->snd_cwnd;
		rec->conn_id = mptcp_conn_id(tp);
		commit(rec, rb);
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

/*
 * The value of a watchable socket field (bpf/onchange.h). field is a constant at every
 * call, so this folds to the one load.
 */
static __always_inline __u64 sock_field(struct sock *sk, struct tcp_sock *tp,
					enum tcbee_sock_field field)
{
	switch (field) {
	/* struct sock */
	case SF_pacing_rate:
		return sk->sk_pacing_rate;
	case SF_max_pacing_rate:
		return sk->sk_max_pacing_rate;
	/* struct inet_connection_sock */
	case SF_backoff:
		return tp->inet_conn.icsk_backoff;
	case SF_rto:
		return tp->inet_conn.icsk_rto;
	case SF_rcv_mss:
		return tp->inet_conn.icsk_ack.rcv_mss;
	/* struct tcp_sock */
	case SF_snd_cwnd:
		return tp->snd_cwnd;
	case SF_bytes_acked:
		return tp->bytes_acked;
	case SF_snd_ssthresh:
		return tp->snd_ssthresh;
	case SF_total_retrans:
		return tp->total_retrans;
	case SF_probes:
		return tp->keepalive_probes;
	case SF_lost:
		return tp->lost;
	case SF_sacked_out:
		return tp->sacked_out;
	case SF_retrans:
		return tp->retrans_out;
	case SF_rcv_ssthresh:
		return tp->rcv_ssthresh;
	case SF_rttvar:
		return tp->rttvar_us;
	case SF_advmss:
		return tp->advmss;
	case SF_reordering:
		return tp->reordering;
	case SF_rcv_rtt:
		return tp->rcv_rtt_est.rtt_us;
	case SF_rcv_space:
		return tp->rcvq_space.space;
	case SF_bytes_received:
		return tp->bytes_received;
	case SF_segs_out:
		return tp->segs_out;
	case SF_segs_in:
		return tp->segs_in;
	default:
		return 0;
	}
}

/*
 * The fields of a sock record after rcv_wscale, which on-change mode does not watch: the
 * congestion state, the delivery rate sample, the time spent limited, the rest of TCP_INFO
 * and the MPTCP connection (mptcp.h). Stored in record order after the ones above.
 */
static __always_inline void fill_sock_extra(struct sock_trace_entry *rec, struct tcp_sock *tp)
{
	rec->ca_state = BPF_CORE_READ_BITFIELD_PROBED(&tp->inet_conn, icsk_ca_state);
	rec->packets_out = tp->packets_out;
	rec->delivered = tp->delivered;
	rec->delivered_ce = tp->delivered_ce;
	rec->app_limited = tp->app_limited;
	rec->chrono_type = BPF_CORE_READ_BITFIELD_PROBED(tp, chrono_type);
	rec->chrono_busy = tp->chrono_stat[0];
	rec->chrono_rwnd_limited = tp->chrono_stat[1];
	rec->chrono_sndbuf_limited = tp->chrono_stat[2];
	rec->srtt = tp->srtt_us >> 3;
	rec->mdev = tp->mdev_us >> 2;
	rec->min_rtt = tp->rtt_min.s[0].v;
	rec->snd_una = tp->snd_una;
	rec->snd_nxt = tp->snd_nxt;
	rec->lost_out = tp->lost_out;
	rec->conn_id = mptcp_conn_id(tp);
}

/*
 * Every field of a sock record after the header, read from the socket. Written out field
 * by field in record order, not with SOCK_FIELDS(): that would move the ato store and
 * change the default programs' code (testing/bpf_identity.sh).
 */
static __always_inline void fill_sock_fields(struct sock_trace_entry *rec, struct sock *sk,
					     struct tcp_sock *tp)
{
	rec->pacing_rate = sock_field(sk, tp, SF_pacing_rate);
	rec->max_pacing_rate = sock_field(sk, tp, SF_max_pacing_rate);
	rec->backoff = sock_field(sk, tp, SF_backoff);
	rec->rto = sock_field(sk, tp, SF_rto);
	rec->ato = 0;
	rec->rcv_mss = sock_field(sk, tp, SF_rcv_mss);
	rec->snd_cwnd = sock_field(sk, tp, SF_snd_cwnd);
	rec->bytes_acked = sock_field(sk, tp, SF_bytes_acked);
	rec->snd_ssthresh = sock_field(sk, tp, SF_snd_ssthresh);
	rec->total_retrans = sock_field(sk, tp, SF_total_retrans);
	rec->probes = sock_field(sk, tp, SF_probes);
	rec->lost = sock_field(sk, tp, SF_lost);
	rec->sacked_out = sock_field(sk, tp, SF_sacked_out);
	rec->retrans = sock_field(sk, tp, SF_retrans);
	rec->rcv_ssthresh = sock_field(sk, tp, SF_rcv_ssthresh);
	rec->rttvar = sock_field(sk, tp, SF_rttvar);
	rec->advmss = sock_field(sk, tp, SF_advmss);
	rec->reordering = sock_field(sk, tp, SF_reordering);
	rec->rcv_rtt = sock_field(sk, tp, SF_rcv_rtt);
	rec->rcv_space = sock_field(sk, tp, SF_rcv_space);
	rec->bytes_received = sock_field(sk, tp, SF_bytes_received);
	rec->segs_out = sock_field(sk, tp, SF_segs_out);
	rec->segs_in = sock_field(sk, tp, SF_segs_in);
	/* struct tcp_options_received, not read yet */
	rec->snd_wscale = 0;
	rec->rcv_wscale = 0;
	fill_sock_extra(rec, tp);
}

/* hook_tag goes into ato; 0 in the default programs, so their code does not change */
static __always_inline int trace_sock(struct sock *sk, struct sk_buff *skb, void *ringbufs,
				      __u32 rb, __u32 hook_tag)
{
	struct sock_trace_entry *rec;
	struct tcp_sock *tp;
	__u16 sport, dport;
	__u64 hook_seq;

	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, rb, &hook_seq))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error(rb);
	} else if ((rec = reserve(ringbufs, rb, rec))) {
		fill_header(rec, sk, sport, dport, hook_seq);
		fill_sock_fields(rec, sk, tp);
		if (hook_tag)
			rec->ato = hook_tag;
		commit(rec, rb);
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

SEC("fentry/__tcp_transmit_skb")
int BPF_PROG(sock_sendmsg, struct sock *sk, struct sk_buff *skb)
{
	return trace_sock(sk, skb, &TCP_SEND_SOCK_EVENTS, RB_SOCK_SEND, 0);
}

/* Only triggers in established state */
SEC("fentry/tcp_rcv_established")
int BPF_PROG(sock_recvmsg, struct sock *sk, struct sk_buff *skb)
{
	return trace_sock(sk, skb, &TCP_RECV_SOCK_EVENTS, RB_SOCK_RECV, 0);
}

/*
 * The socket after every run of the write timer handler: RTO, loss probe, zero window
 * probe, and runs that find no timer due. Optional (soft fail) and own ring, so its
 * hook_seq series and counters stay apart from the ingress ones. The hook tag in ato is the
 * one on-change records carry for the timer.
 */
SEC("?fexit/tcp_write_timer_handler")
int BPF_PROG(sock_timer, struct sock *sk)
{
	return trace_sock(sk, NULL, &TCP_TIMER_SOCK_EVENTS, RB_SOCK_TIMER,
			  ONCHG_HOOK_TIMER << ONCHG_HOOK_SHIFT);
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

/*
 * ---- On-change mode (--on-change) ---------------------------------------------------
 *
 * Separate programs that write a record only when a watched field or the socket state
 * changed since the last record of the connection (at any hook, see struct onchg_state),
 * after a drop or error, and on the first run. They are the only users of ONCHG and declared
 * with "?" (not loaded unless userspace enables them), so the default programs above are
 * unchanged.
 *
 * The decision comes before hook_seq is taken and before the ring buffer is touched: a
 * suppressed run counts as suppressed and takes no number, so hook_seq gaps still are
 * exactly the drops. A tcp_sock error also comes before hook_seq here and leaves no gap.
 *
 * Hooks (--on-change-hooks): ingress and timer write the receive ring, egress the send
 * ring. Ingress is fexit/tcp_rcv_established, which only sees ESTABLISHED sockets, and
 * fexit/tcp_rcv_state_process for the segments of the other states (handshake, FIN_WAIT,
 * CLOSE_WAIT, LAST_ACK; rare, so cheap). Listeners and closed sockets are skipped. Timer is
 * fexit/tcp_write_timer_handler, egress fentry/__tcp_transmit_skb. Ingress and timer records
 * carry the state after the segment or the timer was processed; the timer hook sees what an
 * RTO, loss probe or zero window probe changed while no ACK arrives. It runs from the
 * timer softirq, or from tcp_release_cb when the socket was owned by the user. Egress
 * records carry the state before the transmit.
 * Every hook runs under the socket lock, so the runs of one socket never overlap. Runs for
 * different sockets can nest on one CPU (the timer softirq interrupting backlog
 * processing), so these programs count with the atomic add.
 */

/*
 * Sockets the on-change programs skip like filtered events (no counter): listeners, which
 * tcp_rcv_state_process sees for every SYN, and closed sockets. tcp_done unhashes a socket
 * and clears its local port, so a record of the close would carry another tuple. This also
 * skips the egress run of an RST that tcp_close or tcp_disconnect sends after the close.
 */
static __always_inline bool onchg_skip(struct sock *sk)
{
	__u8 state = sk->__sk_common.skc_state;

	return state == TCP_LISTEN || state == TCP_CLOSE;
}

/* The state of this socket, created on first use; counts state_err if there is none */
static __always_inline struct onchg_state *onchg_state_of(struct sock *sk)
{
	struct onchg_state *st;

	st = bpf_sk_storage_get(&ONCHG, sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);
	if (!st)
		count_state_err();
	return st;
}

static __always_inline int trace_cwnd_oc(struct sock *sk, void *ringbufs, __u32 rb)
{
	struct cwnd_trace_entry *rec;
	struct onchg_state *st;
	struct tcp_sock *tp;
	__u16 sport, dport;
	__u64 hook_seq;
	__u32 cwnd;
	__u8 state;

	if (onchg_skip(sk))
		return 0;
	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error_shared(rb);
		return 0;
	}
	cwnd = tp->snd_cwnd;
	state = sk->__sk_common.skc_state;

	st = onchg_state_of(sk);
	if (st && st->valid[ONCHG_CWND] && st->cwnd_last == cwnd &&
	    st->state_last[ONCHG_CWND] == state) {
		count_suppressed(rb);
		return 0;
	}

	if (!hook_seq_sk_shared(sk, sport, dport, rb, &hook_seq) ||
	    !(rec = reserve_shared(ringbufs, rb, rec))) {
		if (st)
			st->valid[ONCHG_CWND] = 0;
		return 0;
	}
	fill_header(rec, sk, sport, dport, hook_seq);
	rec->snd_cwnd = cwnd;
	rec->conn_id = mptcp_conn_id(tp);
	commit_shared(rec, rb);
	if (st) {
		st->cwnd_last = cwnd;
		st->state_last[ONCHG_CWND] = state;
		st->valid[ONCHG_CWND] = 1;
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

SEC("?fentry/__tcp_transmit_skb")
int BPF_PROG(cwnd_oc_sendmsg, struct sock *sk)
{
	return trace_cwnd_oc(sk, &TCP_SEND_CWND_EVENTS, RB_CWND_SEND);
}

SEC("?fexit/tcp_rcv_established")
int BPF_PROG(cwnd_oc_recvmsg, struct sock *sk)
{
	return trace_cwnd_oc(sk, &TCP_RECEIVE_CWND_EVENTS, RB_CWND_RECV);
}

/* Segments outside ESTABLISHED (handshake, FIN_WAIT, CLOSE_WAIT, LAST_ACK), see above */
SEC("?fexit/tcp_rcv_state_process")
int BPF_PROG(cwnd_oc_rcv_state, struct sock *sk)
{
	return trace_cwnd_oc(sk, &TCP_RECEIVE_CWND_EVENTS, RB_CWND_RECV);
}

SEC("?fexit/tcp_write_timer_handler")
int BPF_PROG(cwnd_oc_timer, struct sock *sk)
{
	return trace_cwnd_oc(sk, &TCP_RECEIVE_CWND_EVENTS, RB_CWND_RECV);
}

/* Every field of a sock record, the watched ones from the snapshot the decision used */
static __always_inline void fill_sock_fields_watched(struct sock_trace_entry *rec,
						     struct sock *sk, struct tcp_sock *tp,
						     const __u64 *snap)
{
#define FILL(name, bit)                                                                    \
	rec->name = (SOCK_WATCH_MASK & (1u << SF_##name)) ? snap[SF_##name] :            \
							      sock_field(sk, tp, SF_##name);
	SOCK_FIELDS(FILL)
#undef FILL
	rec->ato = 0;
	rec->snd_wscale = 0;
	rec->rcv_wscale = 0;
	fill_sock_extra(rec, tp);
}

static __always_inline int trace_sock_oc(struct sock *sk, void *ringbufs, __u32 rb,
					 enum tcbee_onchg_hook hook)
{
	struct sock_trace_entry *rec;
	struct onchg_state *st;
	struct tcp_sock *tp;
	__u64 snap[SF_COUNT] = {};
	__u16 sport, dport;
	__u64 hook_seq;
	bool changed = false;
	__u8 state, reason;

	if (onchg_skip(sk))
		return 0;
	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error_shared(rb);
		return 0;
	}
	state = sk->__sk_common.skc_state;
	/* SOCK_WATCH_MASK is frozen rodata: the verifier drops the unwatched fields */
#define SNAP(name, bit)                                                                    \
	if (SOCK_WATCH_MASK & (1u << SF_##name))                                           \
		snap[SF_##name] = sock_field(sk, tp, SF_##name);
	SOCK_FIELDS(SNAP)
#undef SNAP

	st = onchg_state_of(sk);
	if (!st) {
		reason = ONCHG_REASON_NO_STORAGE;
	} else if (!st->valid[ONCHG_SOCK]) {
		reason = ONCHG_REASON_FIRST;
	} else if (st->state_last[ONCHG_SOCK] != state) {
		reason = ONCHG_REASON_STATE;
	} else {
#define CMP(name, bit)                                                                     \
	if ((SOCK_WATCH_MASK & (1u << SF_##name)) &&                                       \
	    snap[SF_##name] != st->sock_last[SF_##name])                                   \
		changed = true;
		SOCK_FIELDS(CMP)
#undef CMP
		reason = changed ? ONCHG_REASON_CHANGED : ONCHG_REASON_SUPPRESS;
	}
	if (reason == ONCHG_REASON_SUPPRESS && !ONCHG_SHADOW) {
		count_suppressed(rb);
		return 0;
	}

	if (!hook_seq_sk_shared(sk, sport, dport, rb, &hook_seq) ||
	    !(rec = reserve_shared(ringbufs, rb, rec))) {
		if (st)
			st->valid[ONCHG_SOCK] = 0;
		return 0;
	}
	fill_header(rec, sk, sport, dport, hook_seq);
	fill_sock_fields_watched(rec, sk, tp, snap);
	rec->ato = hook << ONCHG_HOOK_SHIFT;
	if (ONCHG_SHADOW)
		rec->ato |= reason;
	commit_shared(rec, rb);
	if (st) {
#define STORE(name, bit)                                                                   \
	if (SOCK_WATCH_MASK & (1u << SF_##name))                                           \
		st->sock_last[SF_##name] = snap[SF_##name];
		SOCK_FIELDS(STORE)
#undef STORE
		st->state_last[ONCHG_SOCK] = state;
		st->valid[ONCHG_SOCK] = 1;
	}

	flow_track_sk(sk, sport, dport);
	return 0;
}

SEC("?fentry/__tcp_transmit_skb")
int BPF_PROG(sock_oc_sendmsg, struct sock *sk, struct sk_buff *skb)
{
	return trace_sock_oc(sk, &TCP_SEND_SOCK_EVENTS, RB_SOCK_SEND, ONCHG_HOOK_EGRESS);
}

SEC("?fexit/tcp_rcv_established")
int BPF_PROG(sock_oc_recvmsg, struct sock *sk, struct sk_buff *skb)
{
	return trace_sock_oc(sk, &TCP_RECV_SOCK_EVENTS, RB_SOCK_RECV, ONCHG_HOOK_INGRESS);
}

SEC("?fexit/tcp_rcv_state_process")
int BPF_PROG(sock_oc_rcv_state, struct sock *sk)
{
	return trace_sock_oc(sk, &TCP_RECV_SOCK_EVENTS, RB_SOCK_RECV, ONCHG_HOOK_INGRESS);
}

/* The write timer writes the receive file, see the section comment */
SEC("?fexit/tcp_write_timer_handler")
int BPF_PROG(sock_oc_timer, struct sock *sk)
{
	return trace_sock_oc(sk, &TCP_RECV_SOCK_EVENTS, RB_SOCK_RECV, ONCHG_HOOK_TIMER);
}

/* ---- CUBIC (-a) -------------------------------------------------------------------- */

static __always_inline int trace_cubic(struct sock *sk)
{
	struct cubic_trace_entry *rec;
	struct bictcp___tcbee *ca;
	struct tcp_sock *tp;
	__u16 sport, dport;
	__u64 hook_seq;

	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, RB_CUBIC, &hook_seq))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error(RB_CUBIC);
	} else if ((rec = reserve(&CUBIC_EVENTS, RB_CUBIC, rec))) {
		ca = tcp_ca(tp);
		fill_header(rec, sk, sport, dport, hook_seq);
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
	__u64 hook_seq;

	if (!sk) {
		/* The filter cannot be evaluated without the socket, count it as an error */
		count_error(RB_BBR);
		return 0;
	}
	sk_ports(sk, &sport, &dport);
	if (!filter_sock(sk, sport, dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, RB_BBR, &hook_seq))
		return 0;

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		count_error(RB_BBR);
	} else if ((rec = reserve(&BBR_EVENTS, RB_BBR, rec))) {
		bbr = tcp_ca(tp);
		fill_header(rec, sk, sport, dport, hook_seq);
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

/* ---- TCP events (-e) --------------------------------------------------------------- */

/*
 * One record per discrete event of a flow, all into TCP_EVENTS. The programs of a flow share
 * its hook_seq counter at RB_TCP_EVENTS, so the numbers order all its events. The socket
 * hooks run under the socket lock. Each program is optional on its own: a missing hook or
 * one the kernel rejects only loses its kind of event.
 */

/* Socket fields of the event, from a full TCP socket; a BTF pointer from the hook's arguments */
static __always_inline void tcp_event_sock_fields(struct tcp_event_entry *rec, struct sock *sk)
{
	struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);

	if (!tp)
		return;
	rec->ca_state = BPF_CORE_READ_BITFIELD_PROBED(&tp->inet_conn, icsk_ca_state);
	rec->backoff = tp->inet_conn.icsk_backoff;
	rec->snd_una = tp->snd_una;
	rec->snd_cwnd = tp->snd_cwnd;
	rec->packets_out = tp->packets_out;
	rec->total_retrans = tp->total_retrans;
}

/*
 * Reserves the event of kind on socket sk with ports sport and dport (sk_ports()) and its
 * header: NULL if the filter rejects it or it is counted as dropped or error. The caller
 * fills the rest and commits.
 */
static __always_inline struct tcp_event_entry *tcp_event_reserve_ports(struct sock *sk,
									__u16 sport, __u16 dport,
									__u8 kind)
{
	struct tcp_event_entry *rec;
	__u64 hook_seq;

	if (!filter_sock(sk, sport, dport))
		return NULL;
	if (!hook_seq_sk(sk, sport, dport, RB_TCP_EVENTS, &hook_seq))
		return NULL;
	rec = reserve(&TCP_EVENTS, RB_TCP_EVENTS, rec);
	if (!rec)
		return NULL;
	fill_header(rec, sk, sport, dport, hook_seq);
	rec->kind = kind;
	return rec;
}

static __always_inline struct tcp_event_entry *tcp_event_reserve_sk(struct sock *sk, __u8 kind)
{
	__u16 sport, dport;

	sk_ports(sk, &sport, &dport);
	return tcp_event_reserve_ports(sk, sport, dport, kind);
}

/* An event on socket sk that carries nothing but the socket fields */
static __always_inline int trace_tcp_event_sk(struct sock *sk, __u8 kind)
{
	struct tcp_event_entry *rec = tcp_event_reserve_sk(sk, kind);

	if (!rec)
		return 0;
	tcp_event_sock_fields(rec, sk);
	commit(rec, RB_TCP_EVENTS);
	return 0;
}

/*
 * Tuple source -> destination and sequence number of the TCP packet in skb, from its
 * headers. False if skb holds no TCP packet with readable headers.
 */
static __always_inline bool tuple_from_skb(const struct sk_buff *skb, struct ip_tuple *t,
					   __u16 *family, __u32 *seq)
{
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 network = BPF_CORE_READ(skb, network_header);
	__u16 transport = BPF_CORE_READ(skb, transport_header);
	__be16 proto = BPF_CORE_READ(skb, protocol);
	struct tc_tcp_hdr tcp;

	__builtin_memset(t, 0, sizeof(*t));
	t->protocol = IPPROTO_TCP;
	if (proto == bpf_htons(ETH_P_IP)) {
		struct tc_ipv4_hdr ip;

		if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network) ||
		    (ip.version_ihl >> 4) != 4 || ip.protocol != IPPROTO_TCP)
			return false;
		__builtin_memcpy(t->src_ip, &ip.saddr, 4);
		__builtin_memcpy(t->dst_ip, &ip.daddr, 4);
		*family = AF_INET;
		/* Not set yet (0xffff) on some paths: the TCP header follows the IP header */
		if (transport == (__u16)~0U || transport <= network)
			transport = network + ((ip.version_ihl & 0x0F) << 2);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct tc_ipv6_hdr ip6;

		if (bpf_probe_read_kernel(&ip6, sizeof(ip6), head + network) ||
		    (bpf_ntohl(ip6.version_tc_flow) >> 28) != 6 || ip6.nexthdr != IPPROTO_TCP)
			return false;
		__builtin_memcpy(t->src_ip, ip6.saddr, 16);
		__builtin_memcpy(t->dst_ip, ip6.daddr, 16);
		*family = AF_INET6;
		if (transport == (__u16)~0U || transport <= network)
			transport = network + sizeof(ip6);
	} else {
		return false;
	}
	if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport))
		return false;
	t->sport = bpf_ntohs(tcp.source);
	t->dport = bpf_ntohs(tcp.dest);
	*seq = bpf_ntohl(tcp.seq);
	return true;
}

static __always_inline void tuple_swap(struct ip_tuple *t)
{
	__u8 addr[16];
	__u16 port;

	__builtin_memcpy(addr, t->src_ip, sizeof(addr));
	__builtin_memcpy(t->src_ip, t->dst_ip, sizeof(addr));
	__builtin_memcpy(t->dst_ip, addr, sizeof(addr));
	port = t->sport;
	t->sport = t->dport;
	t->dport = port;
}

/*
 * An event of the packet in skb, for a flow without a full socket at the hook. The tuple is
 * turned local -> remote: the addresses and ports of a received packet are swapped. Only flows
 * that already have a counter are recorded, see hook_seq_known_tuple().
 */
static __always_inline int trace_tcp_event_skb(const struct sk_buff *skb, bool received,
					       __u8 kind, __u32 reason)
{
	struct tcp_event_entry *rec;
	struct ip_tuple t;
	__u16 family;
	__u64 hook_seq;
	__u32 seq;

	if (!tuple_from_skb(skb, &t, &family, &seq))
		return 0;
	if (received)
		tuple_swap(&t);
	if (!filter_ports_match(t.sport, t.dport))
		return 0;
	if (filter_needs_tuple() && !filter_tuple_match(&t))
		return 0;
	if (!hook_seq_known_tuple(&t, family, RB_TCP_EVENTS, &hook_seq))
		return 0;
	rec = reserve(&TCP_EVENTS, RB_TCP_EVENTS, rec);
	if (!rec)
		return 0;
	fill_header_tuple(rec, &t, family, hook_seq);
	rec->kind = kind;
	rec->reason = reason;
	rec->seq = seq;
	rec->len = BPF_CORE_READ(skb, len);
	commit(rec, RB_TCP_EVENTS);
	return 0;
}

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(tcp_event_retransmit, const struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_event_entry *rec;

	if (!sk)
		return 0;
	rec = tcp_event_reserve_sk((struct sock *)sk, TCBEE_TCP_RETRANSMIT);
	if (!rec)
		return 0;
	tcp_event_sock_fields(rec, (struct sock *)sk);
	if (skb) {
		/* TCP_SKB_CB(skb)->seq, the first field of struct tcp_skb_cb in skb->cb */
		bpf_core_read(&rec->seq, sizeof(rec->seq), &skb->cb);
		rec->len = skb->len;
	}
	commit(rec, RB_TCP_EVENTS);
	return 0;
}

/*
 * sk may be NULL or no full socket (a RST from the control socket, for a request or
 * TIME_WAIT socket); then the tuple comes from skb, the packet the RST answers. From 6.12 on
 * skb is NULL for an active reset, which always has a full socket.
 */
SEC("tp_btf/tcp_send_reset")
int BPF_PROG(tcp_event_rst_sent, const struct sock *sk, const struct sk_buff *skb)
{
	if (sk && bpf_skc_to_tcp_sock((struct sock *)sk))
		return trace_tcp_event_sk((struct sock *)sk, TCBEE_TCP_RST_SENT);
	/* skb is the packet the RST answers, which this host received */
	if (skb)
		return trace_tcp_event_skb(skb, true, TCBEE_TCP_RST_SENT, 0);
	return 0;
}

SEC("tp_btf/tcp_receive_reset")
int BPF_PROG(tcp_event_rst_received, struct sock *sk)
{
	if (!sk)
		return 0;
	return trace_tcp_event_sk(sk, TCBEE_TCP_RST_RECEIVED);
}

/*
 * Listening sockets have no flow and are left out, as are sockets without both ports: an
 * active open enters SYN_SENT before it has its local port. A change to CLOSE comes after
 * the socket released its port (skc_num is 0 then); inet_sport still holds it.
 */
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(tcp_event_state, const struct sock *sk, int oldstate, int newstate)
{
	struct sock *s = (struct sock *)sk;
	struct tcp_event_entry *rec;
	__u16 sport, dport;

	if (!s || s->sk_protocol != IPPROTO_TCP)
		return 0;
	if (oldstate == TCP_LISTEN || newstate == TCP_LISTEN)
		return 0;
	sk_ports(s, &sport, &dport);
	if (!sport && newstate == TCP_CLOSE)
		sport = bpf_ntohs(BPF_CORE_READ((struct inet_sock *)s, inet_sport));
	if (!sport || !dport)
		return 0;
	rec = tcp_event_reserve_ports(s, sport, dport, TCBEE_TCP_STATE);
	if (!rec)
		return 0;
	tcp_event_sock_fields(rec, s);
	rec->old_state = oldstate;
	rec->new_state = newstate;
	commit(rec, RB_TCP_EVENTS);
	return 0;
}

/* Kernel 5.19 and newer. Runs before the state is changed, so the socket still has the old one. */
SEC("tp_btf/tcp_cong_state_set")
int BPF_PROG(tcp_event_ca_state, struct sock *sk, const __u8 ca_state)
{
	struct tcp_event_entry *rec;
	struct tcp_sock *tp;
	__u8 old;

	if (!sk)
		return 0;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return 0;
	old = BPF_CORE_READ_BITFIELD_PROBED(&tp->inet_conn, icsk_ca_state);
	if (old == ca_state)
		return 0;
	rec = tcp_event_reserve_sk(sk, TCBEE_TCP_CA_STATE);
	if (!rec)
		return 0;
	tcp_event_sock_fields(rec, sk);
	rec->old_state = old;
	rec->new_state = ca_state;
	commit(rec, RB_TCP_EVENTS);
	return 0;
}

/* Only the retransmission timer calls tcp_enter_loss */
SEC("fentry/tcp_enter_loss")
int BPF_PROG(tcp_event_rto, struct sock *sk)
{
	return trace_tcp_event_sk(sk, TCBEE_TCP_RTO);
}

/*
 * Before 5.19, without tcp_cong_state_set. The call for ECN marks comes from a static function
 * of the same file and may be inlined into it, so this may only see local congestion.
 */
SEC("fentry/tcp_enter_cwr")
int BPF_PROG(tcp_event_cwr, struct sock *sk)
{
	return trace_tcp_event_sk(sk, TCBEE_TCP_CWR);
}

/* ---- TCP drops (--drops) ------------------------------------------------------------ */

/*
 * kfree_skb runs for every packet the kernel drops, on every path and without the socket
 * lock, so the program leaves early for anything but IP. A packet of a socket that is not a
 * full TCP socket (listener, request or TIME_WAIT socket) is keyed by its headers like one
 * without a socket. The drop reason is an argument from 5.17 on; enum skb_drop_reason came
 * with it, so its existence tells whether ctx[2] may be read.
 */
SEC("tp_btf/kfree_skb")
int BPF_PROG(tcp_event_drop, struct sk_buff *skb, void *location)
{
	struct tcp_event_entry *rec;
	__u16 sport, dport;
	__u32 reason = 0;
	struct sock *sk;
	__be16 proto;
	__u8 state;

	if (!skb)
		return 0;
	proto = skb->protocol;
	if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6))
		return 0;
	if (bpf_core_type_exists(enum skb_drop_reason))
		reason = (__u32)((volatile __u64 *)ctx)[2];

	sk = skb->sk;
	if (sk && sk->sk_protocol == IPPROTO_TCP) {
		state = sk->__sk_common.skc_state;
		sk_ports(sk, &sport, &dport);
		/* The control socket that sends RSTs and TIME_WAIT ACKs has no remote port */
		if (state != TCP_LISTEN && state != TCP_TIME_WAIT && state != TCP_NEW_SYN_RECV &&
		    sport && dport) {
			/* sk is a pointer read from skb, not one the verifier trusts for helpers */
			rec = tcp_event_reserve_ports(sk, sport, dport, TCBEE_TCP_DROP);
			if (!rec)
				return 0;
			rec->reason = reason;
			rec->len = skb->len;
			commit(rec, RB_TCP_EVENTS);
			return 0;
		}
	}
	/* skb_iif is the interface a packet came in on, 0 for packets this host generated */
	return trace_tcp_event_skb(skb, BPF_CORE_READ(skb, skb_iif) != 0, TCBEE_TCP_DROP, reason);
}

/* ---- MPTCP path manager (-m pm) ---------------------------------------------------- */

/*
 * One record per path manager or lifecycle event of an MPTCP connection. These hooks run a
 * few times per connection, so the MPTCP structs are read with BPF_CORE_READ throughout. A
 * connection (struct mptcp_sock) starts with its struct sock, which holds the tuple of the
 * first subflow.
 */

/* Subflow context of an MPTCP subflow, in the ULP data of its socket; NULL for other sockets */
static __always_inline struct mptcp_subflow_context *mptcp_subflow_of(const struct sock *ssk)
{
	struct tcp_sock *tp = bpf_skc_to_tcp_sock((struct sock *)ssk);

	return tp ? tp->inet_conn.icsk_ulp_data : NULL;
}

/* Subflow fields, from the subflow context in the ULP data of ssk */
static __always_inline void mptcp_pm_subflow(struct mptcp_pm_entry *rec, const struct sock *ssk)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_of(ssk);

	if (!subflow)
		return;
	if (!rec->token) {
		struct mptcp_sock *msk = (struct mptcp_sock *)BPF_CORE_READ(subflow, conn);

		rec->token = BPF_CORE_READ(msk, token);
	}
	rec->remote_token = BPF_CORE_READ(subflow, remote_token);
	if (bpf_core_field_exists(subflow->subflow_id))
		rec->subflow_id = BPF_CORE_READ_BITFIELD_PROBED(subflow, subflow_id);
	/* Their types differ between kernels, the probed bitfield read adapts to the size */
	rec->local_id = BPF_CORE_READ_BITFIELD_PROBED(subflow, local_id);
	rec->remote_id = BPF_CORE_READ_BITFIELD_PROBED(subflow, remote_id);
	rec->backup = BPF_CORE_READ_BITFIELD_PROBED(subflow, backup);
}

static __always_inline void mptcp_pm_addr(struct mptcp_pm_entry *rec,
					  const struct mptcp_addr_info *addr)
{
	rec->addr_id = BPF_CORE_READ(addr, id);
	rec->addr_family = BPF_CORE_READ(addr, family);
	rec->addr_port = bpf_ntohs(BPF_CORE_READ(addr, port));
	/* addr_0 to addr_3 are adjacent, they take the address bytes as they are */
	if (rec->addr_family == AF_INET)
		bpf_core_read(&rec->addr_0, 4, &addr->addr);
	/* addr6 only exists with CONFIG_MPTCP_IPV6 */
	else if (bpf_core_field_exists(addr->addr6))
		bpf_core_read(&rec->addr_0, 16, &addr->addr6);
}

/* Fields of a path manager record that only some events have, 0 where not given */
struct mptcp_pm_extra {
	/* SUBFLOW_CONNECT, MP_PRIO_SENT: 0 or the negative error */
	__s64 error;
	__u64 data_seq;
	__u32 data_len;
	/* The address id of events that have an id but no address */
	__u8 addr_id;
	/* A priority change sets the backup flag, else it is the one of ssk */
	bool set_backup;
	__u8 backup;
};

/*
 * The ports of sk, and whether its path manager events are recorded: not for a socket without
 * ports (a connect that fails right away destroys the token before the connection got its
 * addresses; such a connection never had a subflow worth a record), else as the filter says
 */
static __always_inline bool mptcp_pm_wanted(const struct sock *sk, __u16 *sport, __u16 *dport)
{
	/* Not sk_ports(): sk may be a struct mptcp_sock, which allows no direct socket loads */
	*sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	*dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (!*sport && !*dport)
		return false;
	return filter_sock((struct sock *)sk, *sport, *dport);
}

/*
 * The record's tuple is the one of ssk if given, else the one of the connection. addr is the
 * address of the event if there is one, extra the fields that only some events have (or NULL).
 */
static __always_inline int trace_mptcp_pm(__u8 event, const struct mptcp_sock *msk,
					  const struct sock *ssk,
					  const struct mptcp_addr_info *addr,
					  const struct mptcp_pm_extra *extra)
{
	struct sock *sk = ssk ? (struct sock *)ssk : (struct sock *)msk;
	struct mptcp_pm_entry *rec;
	__u16 sport, dport;
	__u64 hook_seq;

	if (!sk || !mptcp_pm_wanted(sk, &sport, &dport))
		return 0;
	if (!hook_seq_sk(sk, sport, dport, RB_MPTCP_PM, &hook_seq))
		return 0;
	rec = reserve(&MPTCP_PM_EVENTS, RB_MPTCP_PM, rec);
	if (!rec)
		return 0;

	fill_header(rec, sk, sport, dport, hook_seq);
	rec->event = event;
	if (msk)
		rec->token = BPF_CORE_READ(msk, token);
	if (ssk)
		mptcp_pm_subflow(rec, ssk);
	if (addr)
		mptcp_pm_addr(rec, addr);
	if (extra) {
		rec->error = extra->error;
		rec->data_seq = extra->data_seq;
		rec->data_len = extra->data_len;
		if (!addr)
			rec->addr_id = extra->addr_id;
		if (extra->set_backup)
			rec->backup = extra->backup;
	}
	commit(rec, RB_MPTCP_PM);
	return 0;
}

/* The netlink path manager events, sent whether or not anyone listens */
SEC("fentry/mptcp_event")
int BPF_PROG(mptcp_pm_event, int type, const struct mptcp_sock *msk, const struct sock *ssk)
{
	return trace_mptcp_pm(type, msk, ssk, NULL, NULL);
}

/* The peer announced an address */
SEC("fentry/mptcp_event_addr_announced")
int BPF_PROG(mptcp_pm_announced, const struct sock *ssk, const struct mptcp_addr_info *info)
{
	return trace_mptcp_pm(TCBEE_MPTCP_ANNOUNCED, NULL, ssk, info, NULL);
}

/* The peer removed the address with this id */
SEC("fentry/mptcp_event_addr_removed")
int BPF_PROG(mptcp_pm_removed, const struct mptcp_sock *msk, __u8 id)
{
	return trace_mptcp_pm(TCBEE_MPTCP_REMOVED, msk, NULL, NULL,
			      &(struct mptcp_pm_extra){ .addr_id = id });
}

/* End of the token's life: a later connection may get the same token */
SEC("fentry/mptcp_token_destroy")
int BPF_PROG(mptcp_pm_token_destroy, struct mptcp_sock *msk)
{
	if (!BPF_CORE_READ(msk, token))
		return 0;
	return trace_mptcp_pm(TCBEE_MPTCP_TOKEN_DESTROYED, msk, NULL, NULL, NULL);
}

/* A subflow the path manager tried to open to the address remote */
SEC("fexit/__mptcp_subflow_connect")
int BPF_PROG(mptcp_pm_subflow_connect, struct sock *sk, const struct mptcp_addr_info *loc,
	     const struct mptcp_addr_info *remote, int ret)
{
	return trace_mptcp_pm(TCBEE_MPTCP_SUBFLOW_CONNECT, (const struct mptcp_sock *)sk, NULL,
			      remote, &(struct mptcp_pm_extra){ .error = ret });
}

/* Stale subflows: remember at the start of the check which subflows were not stale yet */
SEC("fentry/mptcp_pm_nl_subflow_chk_stale")
int BPF_PROG(mptcp_pm_stale_check, const struct mptcp_sock *msk, struct sock *ssk)
{
	struct mptcp_subflow_context *subflow;
	__u64 key = (__u64)ssk;
	__u16 sport, dport;
	__u8 one = 1;

	if (!mptcp_pm_wanted(ssk, &sport, &dport))
		return 0;
	subflow = mptcp_subflow_of(ssk);
	/*
	 * Drop the state of an earlier call whose exit program did not run (recursion guard), so
	 * that this call's exit does not take it for its own
	 */
	if (!subflow || BPF_CORE_READ_BITFIELD_PROBED(subflow, stale)) {
		bpf_map_delete_elem(&MPTCP_STALE_CHECK, &key);
		return 0;
	}
	/* A full map would lose the event: count it as an error of the ring */
	if (bpf_map_update_elem(&MPTCP_STALE_CHECK, &key, &one, BPF_ANY))
		count_error(RB_MPTCP_PM);
	return 0;
}

SEC("fexit/mptcp_pm_nl_subflow_chk_stale")
int BPF_PROG(mptcp_pm_stale, const struct mptcp_sock *msk, struct sock *ssk)
{
	struct mptcp_subflow_context *subflow;
	__u64 key = (__u64)ssk;

	if (!bpf_map_lookup_elem(&MPTCP_STALE_CHECK, &key))
		return 0;
	bpf_map_delete_elem(&MPTCP_STALE_CHECK, &key);
	subflow = mptcp_subflow_of(ssk);
	if (!subflow || !BPF_CORE_READ_BITFIELD_PROBED(subflow, stale))
		return 0;
	return trace_mptcp_pm(TCBEE_MPTCP_SUBFLOW_STALE, msk, ssk, NULL, NULL);
}

/*
 * This host asks the peer to change the priority of the subflows on a local address (MP_PRIO),
 * from ip mptcp endpoint change ... [no]backup or a userspace path manager
 */
SEC("fexit/mptcp_pm_nl_mp_prio_send_ack")
int BPF_PROG(mptcp_pm_prio_sent, struct mptcp_sock *msk, struct mptcp_addr_info *addr,
	     struct mptcp_addr_info *rem, __u8 bkup, int ret)
{
	return trace_mptcp_pm(TCBEE_MPTCP_MP_PRIO_SENT, msk, NULL, addr,
			      &(struct mptcp_pm_extra){
				      .error = ret,
				      .set_backup = true,
				      .backup = bkup,
			      });
}

/*
 * Data-level retransmission after the connection's retransmission timeout. It may find nothing
 * to send, so only a call after which the connection's retransmitted bytes grew is recorded.
 */
SEC("fentry/__mptcp_retrans")
int BPF_PROG(mptcp_pm_retrans_start, struct sock *sk)
{
	const struct mptcp_sock *msk = (const struct mptcp_sock *)sk;
	struct mptcp_retrans_start start = {
		.bytes_retrans = BPF_CORE_READ(msk, bytes_retrans),
		.snd_una = BPF_CORE_READ(msk, snd_una),
	};
	__u64 key = (__u64)sk;
	__u16 sport, dport;

	if (!mptcp_pm_wanted(sk, &sport, &dport))
		return 0;
	if (bpf_map_update_elem(&MPTCP_RETRANS_START, &key, &start, BPF_ANY))
		count_error(RB_MPTCP_PM);
	return 0;
}

SEC("fexit/__mptcp_retrans")
int BPF_PROG(mptcp_pm_retrans, struct sock *sk)
{
	const struct mptcp_sock *msk = (const struct mptcp_sock *)sk;
	struct mptcp_retrans_start *found, start;
	__u64 key = (__u64)sk, bytes;

	found = bpf_map_lookup_elem(&MPTCP_RETRANS_START, &key);
	if (!found)
		return 0;
	start = *found;
	bpf_map_delete_elem(&MPTCP_RETRANS_START, &key);
	bytes = BPF_CORE_READ(msk, bytes_retrans);
	if (bytes <= start.bytes_retrans)
		return 0;
	return trace_mptcp_pm(TCBEE_MPTCP_REINJECTED, msk, NULL, NULL,
			      &(struct mptcp_pm_extra){
				      .data_seq = start.snd_una,
				      .data_len = bytes - start.bytes_retrans,
			      });
}

/* The data waiting on a subflow is queued again for the others (returns whether there was any) */
SEC("fexit/__mptcp_retransmit_pending_data")
int BPF_PROG(mptcp_pm_requeue, struct sock *sk, bool ret)
{
	const struct mptcp_sock *msk = (const struct mptcp_sock *)sk;

	if (!ret)
		return 0;
	return trace_mptcp_pm(TCBEE_MPTCP_PENDING_REQUEUED, msk, NULL, NULL,
			      &(struct mptcp_pm_extra){ .data_seq = BPF_CORE_READ(msk, snd_una) });
}

/* Fallback in the handshake: remember the subflows that requested MPTCP and wait for the SYN-ACK */
SEC("fentry/subflow_finish_connect")
int BPF_PROG(mptcp_pm_connect_check, struct sock *sk, const struct sk_buff *skb)
{
	struct mptcp_subflow_context *subflow;
	__u64 key = (__u64)sk;
	__u16 sport, dport;
	__u8 one = 1;

	if (!mptcp_pm_wanted(sk, &sport, &dport))
		return 0;
	subflow = mptcp_subflow_of(sk);
	/* As for stale subflows: no state of an earlier call survives a call that stores none */
	if (!subflow || !BPF_CORE_READ_BITFIELD_PROBED(subflow, request_mptcp) ||
	    BPF_CORE_READ_BITFIELD_PROBED(subflow, conn_finished)) {
		bpf_map_delete_elem(&MPTCP_CONNECT_CHECK, &key);
		return 0;
	}
	if (bpf_map_update_elem(&MPTCP_CONNECT_CHECK, &key, &one, BPF_ANY))
		count_error(RB_MPTCP_PM);
	return 0;
}

SEC("fexit/subflow_finish_connect")
int BPF_PROG(mptcp_pm_fallback, struct sock *sk, const struct sk_buff *skb)
{
	struct mptcp_subflow_context *subflow;
	__u64 key = (__u64)sk;

	if (!bpf_map_lookup_elem(&MPTCP_CONNECT_CHECK, &key))
		return 0;
	bpf_map_delete_elem(&MPTCP_CONNECT_CHECK, &key);
	subflow = mptcp_subflow_of(sk);
	if (!subflow || BPF_CORE_READ_BITFIELD_PROBED(subflow, mp_capable))
		return 0;
	return trace_mptcp_pm(TCBEE_MPTCP_FALLBACK, NULL, sk, NULL, NULL);
}

SEC("fentry/mptcp_pm_mp_fail_received")
int BPF_PROG(mptcp_pm_mp_fail, struct sock *ssk, __u64 fail_seq)
{
	return trace_mptcp_pm(TCBEE_MPTCP_MP_FAIL, NULL, ssk, NULL,
			      &(struct mptcp_pm_extra){ .data_seq = fail_seq });
}
