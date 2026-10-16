/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Minimal x86_64 CO-RE declarations used by tcbee.bpf.c.
 * Derived from the Linux kernel BTF snapshot previously vendored at this path
 * (git history: 62d6a14). Kernel structures are covered by the kernel's
 * licensing terms; this file is not part of the repository's MIT grant.
 *
 * Keep kernel field names and types: libbpf relocates their offsets against
 * the running kernel's BTF. Add a declaration here when a new field is used.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif

typedef _Bool bool;
#define true 1
#define false 0
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u16 __sum16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s64 int64_t;
typedef __u8 u8;
typedef __u16 u16;
typedef __s16 s16;
typedef __u32 u32;
typedef __u64 u64;
typedef __u64 __addrpair;

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_RB_NO_WAKEUP = 1,
	IPPROTO_TCP = 6,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_F_NO_PREALLOC = 1,
	BPF_SK_STORAGE_GET_F_CREATE = 1,
};

/* The TC context is a stable UAPI layout, not a CO-RE kernel struct. */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
};

struct trace_event_raw_tcp_probe {
	__u8 saddr[28];
	__u8 daddr[28];
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u32 mark;
	__u16 data_len;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 snd_cwnd;
	__u32 ssthresh;
	__u32 snd_wnd;
	__u32 srtt;
	__u32 rcv_wnd;
	__u64 sock_cookie;
};

struct trace_event_raw_tcp_retransmit_synack {
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct trace_event_raw_tcp_event_skb {
	__u8 saddr[28];
	__u8 daddr[28];
};

struct in6_addr {
	__u8 bytes[16];
};

struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	volatile unsigned char skc_state;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common __sk_common;
	unsigned long sk_pacing_rate;
	unsigned long sk_max_pacing_rate;
	u16 sk_protocol;
};

struct sk_buff {
	struct sock *sk;
	char cb[48];
	unsigned int len;
	int skb_iif;
	__be16 protocol;
	__u16 transport_header;
	__u16 network_header;
	unsigned char *head;
};

/* Only its existence is checked: 5.17 and newer */
enum skb_drop_reason {
	SKB_DROP_REASON_NOT_SPECIFIED = 2,
};

struct inet_connection_sock {
	__u32 icsk_rto;
	__u8 icsk_ca_state: 5;
	__u8 icsk_backoff;
	struct {
		__u16 rcv_mss;
	} icsk_ack;
	u64 icsk_ca_priv[13];
	void *icsk_ulp_data;
};

struct inet_sock {
	struct sock sk;
	__be16 inet_sport;
};

struct tcp_sock {
	struct inet_connection_sock inet_conn;
	u32 rcv_ssthresh;
	u32 reordering;
	u32 snd_cwnd;
	u32 sacked_out;
	u32 rttvar_us;
	u32 retrans_out;
	u16 advmss;
	u32 lost;
	u32 snd_ssthresh;
	u64 bytes_acked;
	u32 segs_in;
	u32 segs_out;
	u64 bytes_received;
	struct {
		u32 rtt_us;
	} rcv_rtt_est;
	struct {
		int space;
	} rcvq_space;
	u8 keepalive_probes;
	u32 total_retrans;
	bool is_mptcp;
	u32 snd_una;
	u32 snd_nxt;
	u32 srtt_us;
	u32 mdev_us;
	struct {
		struct {
			u32 t;
			u32 v;
		} s[3];
	} rtt_min;
	u32 packets_out;
	u32 lost_out;
	u32 delivered;
	u32 delivered_ce;
	u32 app_limited;
	u8 chrono_type: 2;
	u32 chrono_stat[3];
};

struct in_addr {
	__be32 s_addr;
};

struct mptcp_subflow_context {
	u32 remote_token;
	u32 request_mptcp: 1;
	u32 mp_capable: 1;
	u32 conn_finished: 1;
	u32 backup: 1;
	u32 stale: 1;
	s16 local_id;
	u8 remote_id;
	u8 stale_count;
	u32 subflow_id;
	struct sock *conn;
};

struct mptcp_sock {
	u64 snd_una;
	u64 bytes_retrans;
	u32 token;
};

struct mptcp_addr_info {
	u8 id;
	unsigned short family;
	__be16 port;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
