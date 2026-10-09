use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair, AF_INET},
};

use tcbee_common::records::cwnd_trace_entry;

event_schema! {
    cwnd_trace_entry => "cwnd", 74 {
        snd_cwnd => "perf_snd_cwnd": U32,
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
        fn conn_key(&self) -> u32 {
            self.conn_id
        }
    }
}
