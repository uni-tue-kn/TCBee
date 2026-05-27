use aya_ebpf::helpers::bpf_probe_read_kernel;
use core::ptr::addr_of;
use tcbee_common::bindings::{flow::IpTuple, tcp_sock::sock};

use crate::config::AF_INET6;

// Does not work with all hooks, e.g. for kprobe, use kernel_read_tuple_from_sk
#[inline(always)]
pub unsafe fn tuple_from_sk(sk_ptr: *const sock, sport: u16, dport: u16) -> IpTuple {
    let family = unsafe { (*sk_ptr).__sk_common.skc_family };

    // TODO: Disable with static variable for performance reasons? Not always needed but nice to have
    if family == AF_INET6 {
        unsafe {
            let src_v6 = (*sk_ptr).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8;
            let dst_v6 = (*sk_ptr).__sk_common.skc_v6_daddr.in6_u.u6_addr8;

            IpTuple {
                src_ip: src_v6,
                dst_ip: dst_v6,
                sport,
                dport,
                protocol: 6,
            }
        }
    } else {
        let daddr = unsafe {
            (*sk_ptr)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_daddr
        };
        let saddr = unsafe {
            (*sk_ptr)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_rcv_saddr
        };

        let mut src_ip = [0u8; 16];
        src_ip[..4].copy_from_slice(&saddr.to_le_bytes());
        let mut dst_ip = [0u8; 16];
        dst_ip[..4].copy_from_slice(&daddr.to_le_bytes());

        IpTuple {
            src_ip,
            dst_ip,
            sport,
            dport,
            protocol: 6,
        }
    }
}

#[inline(always)]
pub unsafe fn kernel_read_tuple_from_sk(sk_ptr: *const sock, sport: u16, dport: u16) -> IpTuple {
    let family: u16 =
        bpf_probe_read_kernel(addr_of!((*sk_ptr).__sk_common.skc_family)).unwrap_or(0);

    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];

    if family == AF_INET6 {
        src_ip = bpf_probe_read_kernel(addr_of!(
            (*sk_ptr).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8
        ))
        .unwrap_or([0u8; 16]);
        dst_ip = bpf_probe_read_kernel(addr_of!((*sk_ptr).__sk_common.skc_v6_daddr.in6_u.u6_addr8))
            .unwrap_or([0u8; 16]);
    } else {
        let daddr = bpf_probe_read_kernel(addr_of!(
            (*sk_ptr)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_daddr
        ))
        .unwrap_or(0);
        let saddr = bpf_probe_read_kernel(addr_of!(
            (*sk_ptr)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_rcv_saddr
        ))
        .unwrap_or(0);

        src_ip[..4].copy_from_slice(&saddr.to_le_bytes());
        dst_ip[..4].copy_from_slice(&daddr.to_le_bytes());
    }

    IpTuple {
        src_ip,
        dst_ip,
        sport,
        dport,
        protocol: 6,
    }
}
