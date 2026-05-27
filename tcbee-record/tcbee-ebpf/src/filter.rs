use aya_ebpf::{macros::map, maps::HashMap};
use tcbee_common::{bindings::flow::IpTuple, filter::*};

use crate::{FILTER_MODE, FILTER_PORT, FILTER_RULE_FLAGS};

const FILTER_MAX_ENTRIES: u32 = 1024;

#[map(name = "FILTER_ANY_PORTS")]
static FILTER_ANY_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(FILTER_MAX_ENTRIES, 0);
#[map(name = "FILTER_SRC_PORTS")]
static FILTER_SRC_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(FILTER_MAX_ENTRIES, 0);
#[map(name = "FILTER_DST_PORTS")]
static FILTER_DST_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(FILTER_MAX_ENTRIES, 0);

#[map(name = "FILTER_ANY_IPS")]
static FILTER_ANY_IPS: HashMap<FilterIp, u8> = HashMap::with_max_entries(FILTER_MAX_ENTRIES, 0);
#[map(name = "FILTER_SRC_IPS")]
static FILTER_SRC_IPS: HashMap<FilterIp, u8> = HashMap::with_max_entries(FILTER_MAX_ENTRIES, 0);
#[map(name = "FILTER_DST_IPS")]
static FILTER_DST_IPS: HashMap<FilterIp, u8> = HashMap::with_max_entries(FILTER_MAX_ENTRIES, 0);

#[inline(always)]
fn contains_port(map: &HashMap<u16, u8>, port: u16) -> bool {
    unsafe { map.get(&port).is_some() }
}

#[inline(always)]
fn contains_ip(map: &HashMap<FilterIp, u8>, ip: [u8; 16]) -> bool {
    let key = FilterIp { addr: ip };
    unsafe { map.get(&key).is_some() }
}

#[inline(always)]
pub fn filter_needs_tuple() -> bool {
    unsafe { FILTER_MODE == FILTER_MODE_MAPS && (FILTER_RULE_FLAGS & FILTER_IP_BITS) != 0 }
}

#[inline(always)]
pub fn filter_ports_match(sport: u16, dport: u16) -> bool {
    unsafe {
        if FILTER_MODE == FILTER_MODE_NONE {
            return true;
        }

        if FILTER_MODE == FILTER_MODE_SINGLE_PORT {
            return sport == FILTER_PORT || dport == FILTER_PORT;
        }

        let flags = FILTER_RULE_FLAGS;
        if (flags & FILTER_PORT_BITS) == 0 {
            return true;
        }

        if (flags & FILTER_ANY_PORT) != 0
            && (contains_port(&FILTER_ANY_PORTS, sport) || contains_port(&FILTER_ANY_PORTS, dport))
        {
            return true;
        }
        if (flags & FILTER_SRC_PORT) != 0 && contains_port(&FILTER_SRC_PORTS, sport) {
            return true;
        }
        if (flags & FILTER_DST_PORT) != 0 && contains_port(&FILTER_DST_PORTS, dport) {
            return true;
        }

        false
    }
}

#[inline(always)]
pub fn filter_tuple_match(tuple: &IpTuple) -> bool {
    unsafe {
        if FILTER_MODE != FILTER_MODE_MAPS {
            return true;
        }

        let flags = FILTER_RULE_FLAGS;
        if (flags & FILTER_IP_BITS) == 0 {
            return true;
        }

        if (flags & FILTER_ANY_IP) != 0
            && (contains_ip(&FILTER_ANY_IPS, tuple.src_ip)
                || contains_ip(&FILTER_ANY_IPS, tuple.dst_ip))
        {
            return true;
        }
        if (flags & FILTER_SRC_IP) != 0 && contains_ip(&FILTER_SRC_IPS, tuple.src_ip) {
            return true;
        }
        if (flags & FILTER_DST_IP) != 0 && contains_ip(&FILTER_DST_IPS, tuple.dst_ip) {
            return true;
        }

        false
    }
}
