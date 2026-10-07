use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, ip_addr_from_16_bytes, shorten_to_ipv4, shorten_to_ipv6, AF_INET},
};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[cfg_attr(feature = "fixture-gen", derive(serde::Serialize))]
pub struct TcpProbe {
    pub time: u64,
    pub hook_seq: u64,
    pub saddr: [u8; 28usize],
    pub daddr: [u8; 28usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub mark: u32,
    pub data_len: u16,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub snd_cwnd: u32,
    pub ssthresh: u32,
    pub snd_wnd: u32,
    pub srtt: u32,
    pub rcv_wnd: u32,
    pub sock_cookie: u64,
    pub div: [u8; 4usize],
}

event_schema! {
    TcpProbe => "tcp_probe", 124 {
        mark => "MARK": U32,
        data_len => "DATA_LEN": U16,
        snd_nxt => "SND_NXT": U32,
        snd_una => "SND_UNA": U32,
        snd_cwnd => "SND_CWND": U32,
        ssthresh => "SSTRESH": U32,
        snd_wnd => "SND_WND": U32,
        srtt => "SRTT": U32,
        rcv_wnd => "RCV_WND": U32,
        sock_cookie => "SOCK_COOKIE": U64,
    }
    {
        fn flow_key(&self) -> IpTuple {
            let (src, dst) = if self.family == AF_INET {
                (
                    IpAddr::V4(Ipv4Addr::from(shorten_to_ipv4(self.saddr))),
                    IpAddr::V4(Ipv4Addr::from(shorten_to_ipv4(self.daddr))),
                )
            } else {
                (
                    ip_addr_from_16_bytes(shorten_to_ipv6(self.saddr)),
                    ip_addr_from_16_bytes(shorten_to_ipv6(self.daddr)),
                )
            };
            flow_tuple(src, dst, self.sport, self.dport)
        }
    }
}
