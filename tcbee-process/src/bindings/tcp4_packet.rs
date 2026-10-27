use std::net::{IpAddr, Ipv4Addr};

use ts_storage::IpTuple;

use crate::{event::event_schema, ip::flow_tuple};

use tcbee_common::records::tcp4_packet_trace;

event_schema! {
    tcp4_packet_trace => "tcp4", 52 {
        seq => "SEQ_NUM": U32,
        ack => "ACK_NUM": U32,
        window => "WINDOW": U16,
        flags => "FLAGS": U8,
        ecn => "ECN": U8,
        tstamp => "TSTAMP": U64,
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
