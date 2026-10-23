use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair, AF_INET},
};

use tcbee_common::records::reno_trace_entry;

event_schema! {
    reno_trace_entry => "reno", 96 {
        hook: U8,
        ca_state: U8,
        snd_cwnd: U32,
        snd_ssthresh: U32,
        snd_cwnd_cnt: U32,
        acked: U32,
        new_ssthresh: U32,
        ca_name: U64,
    }
    {
        fn flow_key(&self) -> IpTuple {
            let (src, dst) = kernel_addr_pair(
                self.family == AF_INET,
                self.addr_v4,
                self.src_v6,
                self.dst_v6,
            );
            flow_tuple(src, dst, self.sport, self.dport)
        }
        fn socket_level(&self) -> bool {
            true
        }
    }
}
