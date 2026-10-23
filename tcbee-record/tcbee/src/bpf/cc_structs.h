/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * Local CO-RE definitions of the congestion control private state in icsk_ca_priv.
 *
 * libbpf drops the ___tcbee flavor suffix and relocates the fields against `struct
 * bictcp` / `struct bbr` in the kernel's BTF, vmlinux or module (tcp_bbr, tcp_cubic)
 * alike. Only the fields we read are listed; their order and the widths of the bitfields here
 * do not matter, BPF_CORE_READ_BITFIELD_PROBED() takes both from the kernel.
 */
#ifndef __TCBEE_CC_STRUCTS_H
#define __TCBEE_CC_STRUCTS_H

/* net/ipv4/tcp_cubic.c */
struct bictcp___tcbee {
	u32 cnt;
	u32 last_max_cwnd;
	u32 last_cwnd;
	u32 last_time;
	u32 bic_origin_point;
	u32 bic_K;
	u32 delay_min;
	u32 epoch_start;
	u32 ack_cnt;
	u32 tcp_cwnd;
	u32 round_start;
	u32 end_seq;
	u32 last_ack;
	u32 curr_rtt;
} __attribute__((preserve_access_index));

/* net/ipv4/tcp_bbr.c */
struct bbr___tcbee {
	u32 min_rtt_us;
	u32 min_rtt_stamp;
	u32 probe_rtt_done_stamp;
	u32 rtt_cnt;
	u32 next_rtt_delivered;
	u64 cycle_mstamp;
	u32 mode : 3, round_start : 1, idle_restart : 1;
	u32 pacing_gain : 10, cwnd_gain : 10, full_bw_reached : 1, full_bw_cnt : 2, cycle_idx : 3;
	/* BBRv1 only, read behind bpf_core_field_exists(); bw is a struct minmax */
	struct {
		struct {
			u32 t;
			u32 v;
		} s[3];
	} bw;
	u32 packet_conservation : 1, lt_use_bw : 1;
	u32 lt_bw;
	u32 lt_last_delivered;
	u32 lt_last_stamp;
	u32 lt_last_lost;
	u32 prior_cwnd;
	u32 full_bw;
} __attribute__((preserve_access_index));

/* include/net/tcp.h, the rate sample that tcp_ack() hands to cong_control (bbr_main) */
struct rate_sample___tcbee {
	__s32 delivered;
	long interval_us;
	long rtt_us;
	int losses;
	bool is_app_limited;
} __attribute__((preserve_access_index));

/* Helpers of the running kernel, see bpf_core_enum_value_exists() */
enum bpf_func_id___tcbee {
	BPF_FUNC_get_func_arg_cnt___tcbee = 185,
};

/*
 * Congestion control private data of a socket, see inet_csk_ca(). The loads through the
 * returned pointer are checked by the verifier against icsk_ca_priv (an array of u64) of
 * the tcp_sock, which is why tp must come from bpf_skc_to_tcp_sock().
 */
static __always_inline void *tcp_ca(struct tcp_sock *tp)
{
	return (void *)tp->inet_conn.icsk_ca_priv;
}

#endif /* __TCBEE_CC_STRUCTS_H */
