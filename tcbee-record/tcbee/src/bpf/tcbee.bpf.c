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
