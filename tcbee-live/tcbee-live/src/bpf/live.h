/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/* Types shared by live.bpf.c and the userspace side (src/bpf.rs) */
#ifndef __LIVE_H__
#define __LIVE_H__

/* A TCP flow from the socket's side: src is local, dst is remote. IPv4
 * addresses are stored IPv4-mapped (::ffff:a.b.c.d). Ports in host order. */
struct flow_key {
	__u8 src_v6[16];
	__u8 dst_v6[16];
	__u16 src_port;
	__u16 dst_port;
	__u16 family;
	__u16 _pad;
};

/* One cwnd sample of a selected flow, sent through the EVENTS ring buffer */
struct cwnd_event {
	__u64 time;
	struct flow_key key;
	__u32 snd_cwnd;
	__u32 _pad;
};

_Static_assert(sizeof(struct flow_key) == 40, "flow_key layout");
_Static_assert(sizeof(struct cwnd_event) == 56, "cwnd_event layout");
_Static_assert(__builtin_offsetof(struct cwnd_event, key) == 8, "cwnd_event layout");
_Static_assert(__builtin_offsetof(struct cwnd_event, snd_cwnd) == 48, "cwnd_event layout");

#endif /* __LIVE_H__ */
