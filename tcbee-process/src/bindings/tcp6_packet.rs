use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, ip_addr_from_16_bytes},
};

use tcbee_common::records::tcp6_packet_trace;

event_schema! {
    tcp6_packet_trace => "tcp6", 67 {
        seq => "SEQ_NUM": U32,
        ack => "ACK_NUM": U32,
        window => "WINDOW": U16,
        flags => "FLAGS": U8,
    }
    {
        fn flow_key(&self) -> IpTuple {
            flow_tuple(
                ip_addr_from_16_bytes(self.saddr_v6),
                ip_addr_from_16_bytes(self.daddr_v6),
                self.sport,
                self.dport,
            )
        }
    }
}
