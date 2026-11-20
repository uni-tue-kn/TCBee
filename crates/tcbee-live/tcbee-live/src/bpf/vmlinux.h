/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The few kernel types tcbee-live reads, written by hand instead of a full
 * `bpftool btf dump file /sys/kernel/btf/vmlinux format c`. The field names and
 * types follow the kernel (include/net/sock.h, include/linux/tcp.h). Offsets do
 * not matter: preserve_access_index makes every access a CO-RE relocation that
 * libbpf resolves against the BTF of the running kernel, by field name.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_NOEXIST = 1,
};

enum {
	BPF_RB_NO_WAKEUP = 1,
};

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct sock_common {
	union {
		__u64 skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		__u32 skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common __sk_common;
};

struct tcp_sock {
	__u32 snd_cwnd;
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
