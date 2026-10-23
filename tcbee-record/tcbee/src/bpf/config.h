/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * Configuration set by userspace through the skeleton's rodata before the object is
 * loaded, so the verifier sees constants and drops disabled branches.
 */
#ifndef __TCBEE_CONFIG_H
#define __TCBEE_CONFIG_H

/* Filter settings, see filter.h and tcbee-common/src/filter.rs */
const volatile __u16 FILTER_PORT = 0;
const volatile __u32 FILTER_MODE = 0; /* FILTER_MODE_NONE */
const volatile __u32 FILTER_RULE_FLAGS = 0;

/*
 * Ring buffer submit flags. BPF_RB_NO_WAKEUP while the writers busy-poll, 0 when they
 * block in poll() and need to be woken up.
 */
const volatile __u64 RB_SUBMIT_FLAGS = BPF_RB_NO_WAKEUP;

/* Set to 0 by userspace when the flow list is not displayed */
const volatile __u8 FLOW_TRACKING = 1;

/* Set to 1 by userspace (-m tag) to tag MPTCP subflow records with their connection, mptcp.h */
const volatile __u8 MPTCP_TAG = 0;
/*
 * On-change mode (--on-change, see onchange.h): the socket fields the sock probes compare,
 * one bit per enum tcbee_sock_field. ONCHG_SHADOW writes every run anyway, with the
 * decision as a reason code in the ato field.
 */
const volatile __u32 SOCK_WATCH_MASK = 0;
const volatile __u8 ONCHG_SHADOW = 0;

/* Constants that only exist as macros in the uapi headers, not in BTF */
#define AF_INET 2
#define AF_INET6 10
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IP_OFFSET 0x1FFF
#define IP_ECN_MASK 0x03
#define TC_ACT_UNSPEC (-1)
#define TCP_TIME_WAIT 6
#define TCP_CLOSE 7
#define TCP_LISTEN 10
#define TCP_NEW_SYN_RECV 12

#endif /* __TCBEE_CONFIG_H */
