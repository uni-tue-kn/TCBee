use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ts_storage::IpTuple;

/// Address family value of `AF_INET` in the kernel structs.
pub const AF_INET: u16 = 2;

/// The kernel sometimes uses a 28 byte IP address struct:
/// the first 4 bytes are IP version and port, the next 4 bytes the IPv4 address (0 if IPv6),
/// the next 16 bytes the IPv6 address (0 if IPv4).
pub fn shorten_to_ipv6(arg: [u8; 28]) -> [u8; 16] {
    std::array::from_fn(|i| arg[i + 8])
}

pub fn shorten_to_ipv4(arg: [u8; 28]) -> [u8; 4] {
    std::array::from_fn(|i| arg[i + 4])
}

/// Source and destination of the bindings that carry `addr_v4` (both IPv4 addresses packed into
/// one u64, network byte order) next to two IPv6 slots. Which of the two is used is decided by
/// the caller (`use_v4`), and differs between bindings on purpose.
pub fn kernel_addr_pair(
    use_v4: bool,
    addr_v4: u64,
    src_v6: [u8; 16],
    dst_v6: [u8; 16],
) -> (IpAddr, IpAddr) {
    if use_v4 {
        let src = Ipv4Addr::from(u32::from_be((addr_v4 >> 32) as u32));
        let dst = Ipv4Addr::from(u32::from_be(addr_v4 as u32));
        (IpAddr::V4(src), IpAddr::V4(dst))
    } else {
        (ip_addr_from_16_bytes(src_v6), ip_addr_from_16_bytes(dst_v6))
    }
}

/// The flow identity of a TCP packet. Ports are stored as read (not byte swapped).
pub fn flow_tuple(src: IpAddr, dst: IpAddr, sport: u16, dport: u16) -> IpTuple {
    IpTuple {
        src,
        dst,
        sport: i64::from(sport),
        dport: i64::from(dport),
        l4proto: 6,
    }
}

pub fn ip_addr_from_16_bytes(bytes: [u8; 16]) -> IpAddr {
    if is_ipv4_mapped(bytes) {
        IpAddr::V4(Ipv4Addr::from([bytes[12], bytes[13], bytes[14], bytes[15]]))
    } else if is_ipv4_compatible(bytes) {
        IpAddr::V4(Ipv4Addr::from([bytes[0], bytes[1], bytes[2], bytes[3]]))
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    }
}

fn is_ipv4_mapped(bytes: [u8; 16]) -> bool {
    bytes[0..10].iter().all(|&b| b == 0) && bytes[10] == 0xff && bytes[11] == 0xff
}

fn is_ipv4_compatible(bytes: [u8; 16]) -> bool {
    bytes[4..16].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ipv4_mapped_ipv6_to_ipv4() {
        let addr = ip_addr_from_16_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);

        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn converts_kernel_ipv4_compatible_storage_to_ipv4() {
        let addr = ip_addr_from_16_bytes([192, 168, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
    }

    #[test]
    fn leaves_real_ipv6_as_ipv6() {
        let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let addr = ip_addr_from_16_bytes(bytes);

        assert_eq!(addr, IpAddr::V6(Ipv6Addr::from(bytes)));
    }
}
