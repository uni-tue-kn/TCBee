use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair},
};

use tcbee_common::records::cubic_trace_entry;

event_schema! {
    cubic_trace_entry => "cubic", 123 {
        hook: U8,
        cnt: U32,
        last_max_cwnd: U32,
        last_cwnd: U32,
        last_time: U32,
        bic_origin_point: U32,
        bic_K: U32,
        delay_min: U32,
        epoch_start: U32,
        ack_cnt: U32,
        tcp_cwnd: U32,
        round_start: U32,
        end_seq: U32,
        last_ack: U32,
        curr_rtt: U32,
    }
    {
        fn flow_key(&self) -> IpTuple {
            let (src, dst) = kernel_addr_pair(
                self.addr_v4 != 0,
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
