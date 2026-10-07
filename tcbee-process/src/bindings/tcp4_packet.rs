use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use ts_storage::IpTuple;

use crate::{event::event_schema, ip::flow_tuple};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[cfg_attr(feature = "fixture-gen", derive(serde::Serialize))]
pub struct Tcp4Packet {
    pub time: u64,
    pub hook_seq: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub flags: u8,
    pub div: [u8; 4usize],
}

event_schema! {
    Tcp4Packet => "tcp4", 43 {
        seq => "SEQ_NUM": U32,
        ack => "ACK_NUM": U32,
        window => "WINDOW": U16,
        flags => "FLAGS": U8,
    }
    {
        fn flow_key(&self) -> IpTuple {
            flow_tuple(
                IpAddr::V4(Ipv4Addr::from(self.saddr)),
                IpAddr::V4(Ipv4Addr::from(self.daddr)),
                self.sport,
                self.dport,
            )
        }
    }
}
