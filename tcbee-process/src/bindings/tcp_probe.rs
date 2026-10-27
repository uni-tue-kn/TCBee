use std::net::{IpAddr, Ipv4Addr};

use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, ip_addr_from_16_bytes, shorten_to_ipv4, shorten_to_ipv6, AF_INET},
};

use tcbee_common::records::tcp_probe_entry;

event_schema! {
    tcp_probe_entry => "tcp_probe", 124 {
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
        fn socket_level(&self) -> bool {
            true
        }
    }
}
