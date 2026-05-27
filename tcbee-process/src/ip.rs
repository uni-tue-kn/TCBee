use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
