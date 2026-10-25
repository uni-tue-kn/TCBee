use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair},
};

use tcbee_common::records::bbr_trace_entry;

event_schema! {
    bbr_trace_entry => "bbr", 168 {
        hook: U8,
        min_rtt_us: U32,
        min_rtt_stamp: U32,
        probe_rtt_done_stamp: U32,
        rtt_cnt: U32,
        next_rtt_delivered: U32,
        cycle_mstamp: U64,
        lt_bw: U32,
        lt_last_delivered: U32,
        lt_last_stamp: U32,
        lt_last_lost: U32,
        prior_cwnd: U32,
        full_bw: U32,
        mode: U8,
        cycle_idx: U8,
        pacing_gain: U16,
        cwnd_gain: U16,
        full_bw_reached: U8,
        full_bw_cnt: U8,
        round_start: U8,
        packet_conservation: U8,
        idle_restart: U8,
        lt_use_bw: U8,
        max_bw: U32,
        rs_delivered: I64,
        rs_interval_us: I64,
        rs_rtt_us: I64,
        rs_losses: I64,
        rs_is_app_limited: U8,
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
