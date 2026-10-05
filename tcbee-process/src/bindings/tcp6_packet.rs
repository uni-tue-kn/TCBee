use serde::Deserialize;
use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, ip_addr_from_16_bytes},
};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[cfg_attr(feature = "fixture-gen", derive(serde::Serialize))]
pub struct Tcp6Packet {
    pub time: u64,
    pub saddr: [u8; 16usize],
    pub daddr: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub flags: u8,
    pub div: [u8; 4usize],
}

event_schema! {
    Tcp6Packet => "tcp6", 59 {
        seq => "SEQ_NUM": U32,
        ack => "ACK_NUM": U32,
        window => "WINDOW": U16,
        flags => "FLAGS": U8,
    }
    {
        fn flow_key(&self) -> IpTuple {
            flow_tuple(
                ip_addr_from_16_bytes(self.saddr),
                ip_addr_from_16_bytes(self.daddr),
                self.sport,
                self.dport,
            )
        }
    }
}
