/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * Port and IP filters, same semantics as tcbee-common/src/filter.rs.
 *
 * Within a stage the rules are ORed, the port and the IP stage are ANDed. A stage
 * without rules matches everything. Probes check the ports first and only build the
 * address tuple when an IP rule is set.
 */
#ifndef __TCBEE_FILTER_H
#define __TCBEE_FILTER_H

#include "config.h"
#include "maps.h"

#define FILTER_MODE_NONE 0
#define FILTER_MODE_SINGLE_PORT 1
#define FILTER_MODE_MAPS 2

#define FILTER_ANY_PORT (1 << 0)
#define FILTER_SRC_PORT (1 << 1)
#define FILTER_DST_PORT (1 << 2)
#define FILTER_ANY_IP (1 << 3)
#define FILTER_SRC_IP (1 << 4)
#define FILTER_DST_IP (1 << 5)

#define FILTER_PORT_BITS (FILTER_ANY_PORT | FILTER_SRC_PORT | FILTER_DST_PORT)
#define FILTER_IP_BITS (FILTER_ANY_IP | FILTER_SRC_IP | FILTER_DST_IP)

static __always_inline bool contains_port(void *map, __u16 port)
{
	return bpf_map_lookup_elem(map, &port) != NULL;
}

static __always_inline bool contains_ip(void *map, const __u8 *addr)
{
	struct filter_ip key;

	__builtin_memcpy(key.addr, addr, sizeof(key.addr));
	return bpf_map_lookup_elem(map, &key) != NULL;
}

/* Whether filter_tuple_match() can reject anything, i.e. the tuple is needed */
static __always_inline bool filter_needs_tuple(void)
{
	return FILTER_MODE == FILTER_MODE_MAPS && (FILTER_RULE_FLAGS & FILTER_IP_BITS);
}

/* Ports in host byte order */
static __always_inline bool filter_ports_match(__u16 sport, __u16 dport)
{
	__u32 flags = FILTER_RULE_FLAGS;

	if (FILTER_MODE == FILTER_MODE_NONE)
		return true;
	if (FILTER_MODE == FILTER_MODE_SINGLE_PORT)
		return sport == FILTER_PORT || dport == FILTER_PORT;

	if (!(flags & FILTER_PORT_BITS))
		return true;
	if ((flags & FILTER_ANY_PORT) &&
	    (contains_port(&FILTER_ANY_PORTS, sport) || contains_port(&FILTER_ANY_PORTS, dport)))
		return true;
	if ((flags & FILTER_SRC_PORT) && contains_port(&FILTER_SRC_PORTS, sport))
		return true;
	if ((flags & FILTER_DST_PORT) && contains_port(&FILTER_DST_PORTS, dport))
		return true;
	return false;
}

static __always_inline bool filter_tuple_match(const struct ip_tuple *t)
{
	__u32 flags = FILTER_RULE_FLAGS;

	if (FILTER_MODE != FILTER_MODE_MAPS)
		return true;
	if (!(flags & FILTER_IP_BITS))
		return true;
	if ((flags & FILTER_ANY_IP) &&
	    (contains_ip(&FILTER_ANY_IPS, t->src_ip) || contains_ip(&FILTER_ANY_IPS, t->dst_ip)))
		return true;
	if ((flags & FILTER_SRC_IP) && contains_ip(&FILTER_SRC_IPS, t->src_ip))
		return true;
	if ((flags & FILTER_DST_IP) && contains_ip(&FILTER_DST_IPS, t->dst_ip))
		return true;
	return false;
}

#endif /* __TCBEE_FILTER_H */
