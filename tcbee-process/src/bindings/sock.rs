use tcbee_common::records::sock_trace_entry;
use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair, AF_INET},
};

event_schema! {
    sock_trace_entry => "sock", 226 {
        pacing_rate: U64,
        max_pacing_rate: U64,
        backoff: U8,
        rto: U32,
        ato: U32,
        rcv_mss: U16,
        snd_cwnd: U32,
        bytes_acked: U64,
        snd_ssthresh: U32,
        total_retrans: U32,
        probes: U8,
        lost: U32,
        sacked_out: U32,
        retrans: U32,
        rcv_ssthresh: U32,
        rttvar: U32,
        advmss: U16,
        reordering: U32,
        rcv_rtt: U32,
        rcv_space: U32,
        bytes_received: U64,
        segs_out: U32,
        segs_in: U32,
        snd_wscale: U16,
        rcv_wscale: U16,
        ca_state: U8,
        packets_out: U32,
        delivered: U32,
        delivered_ce: U32,
        app_limited: U32,
        chrono_type: U8,
        chrono_busy: U32,
        chrono_rwnd_limited: U32,
        chrono_sndbuf_limited: U32,
        srtt: U32,
        mdev: U32,
        min_rtt: U32,
        snd_una: U32,
        snd_nxt: U32,
        lost_out: U32,
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
        fn connection_key(&self) -> u32 {
            self.conn_id
        }
        fn socket_level(&self) -> bool {
            true
        }
    }
}
