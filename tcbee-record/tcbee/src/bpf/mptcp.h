/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/* MPTCP helpers */
#ifndef __TCBEE_MPTCP_H
#define __TCBEE_MPTCP_H

#include <bpf/bpf_core_read.h>

#include "config.h"

/*
 * Token of the MPTCP connection that the subflow tp belongs to, 0 for plain TCP or without
 * MPTCP_TAG. An MPTCP subflow is a plain tcp_sock whose ULP data is its subflow context, which
 * points to the connection (struct mptcp_sock). sk_is_mptcp() and mptcp_subflow_ctx() are
 * inline in the kernel, so the chain is read here.
 *
 * Plain TCP pays one load: icsk_ulp_data is NULL unless a ULP (MPTCP, kTLS) is attached, and
 * it lies next to fields the probes read anyway. is_mptcp and the MPTCP structs are read
 * with BPF_CORE_READ, helper calls that the compiler cannot move above the check that they
 * exist. Without CONFIG_MPTCP their relocations fail, and the verifier only accepts the
 * program because that code is dead.
 */
static __always_inline __u32 mptcp_conn_id(struct tcp_sock *tp)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_sock *msk;

	if (!MPTCP_TAG || !bpf_core_field_exists(tp->is_mptcp))
		return 0;
	subflow = tp->inet_conn.icsk_ulp_data;
	if (!subflow || !BPF_CORE_READ(tp, is_mptcp))
		return 0;
	msk = (struct mptcp_sock *)BPF_CORE_READ(subflow, conn);
	return BPF_CORE_READ(msk, token);
}

#endif /* __TCBEE_MPTCP_H */
