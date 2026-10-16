use serde::{Deserialize, Serialize};
use tcbee_common::records::sock_trace_entry;
use ts_storage::{EventBatch, EventTable, IpTuple};

use crate::{
    event::{decode_record, event_schema, DecodeError, Event},
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

/// Columns of the sock record that recordings in the old layout (`OldSockEntry`, and the 168 B
/// layout) do not have: the run-metadata fields and the rest of TCP_INFO
pub const ADDED_COLUMNS: &[&str] = &[
    "ca_state",
    "packets_out",
    "delivered",
    "delivered_ce",
    "app_limited",
    "chrono_type",
    "chrono_busy",
    "chrono_rwnd_limited",
    "chrono_sndbuf_limited",
    "srtt",
    "mdev",
    "min_rtt",
    "snd_una",
    "snd_nxt",
    "lost_out",
];

/// The sock record of dev with MPTCP (172 B), before `ADDED_COLUMNS` were recorded, so that
/// older recordings still decode (one of the `legacy` layouts). Its rows go into the same table with 0 in the added columns; the pipeline leaves
/// the series of those columns out.
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OldSockEntry {
    pub time: u64,
    pub hook_seq: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16],
    pub dst_v6: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    pub backoff: u8,
    pub rto: u32,
    pub ato: u32,
    pub rcv_mss: u16,
    pub snd_cwnd: u32,
    pub bytes_acked: u64,
    pub snd_ssthresh: u32,
    pub total_retrans: u32,
    pub probes: u8,
    pub lost: u32,
    pub sacked_out: u32,
    pub retrans: u32,
    pub rcv_ssthresh: u32,
    pub rttvar: u32,
    pub advmss: u16,
    pub reordering: u32,
    pub rcv_rtt: u32,
    pub rcv_space: u32,
    pub bytes_received: u64,
    pub segs_out: u32,
    pub segs_in: u32,
    pub snd_wscale: u16,
    pub rcv_wscale: u16,
    pub conn_id: u32,
}

impl OldSockEntry {
    fn current(&self) -> sock_trace_entry {
        sock_trace_entry {
            time: self.time,
            hook_seq: self.hook_seq,
            addr_v4: self.addr_v4,
            src_v6: self.src_v6,
            dst_v6: self.dst_v6,
            sport: self.sport,
            dport: self.dport,
            family: self.family,
            pacing_rate: self.pacing_rate,
            max_pacing_rate: self.max_pacing_rate,
            backoff: self.backoff,
            rto: self.rto,
            ato: self.ato,
            rcv_mss: self.rcv_mss,
            snd_cwnd: self.snd_cwnd,
            bytes_acked: self.bytes_acked,
            snd_ssthresh: self.snd_ssthresh,
            total_retrans: self.total_retrans,
            probes: self.probes,
            lost: self.lost,
            sacked_out: self.sacked_out,
            retrans: self.retrans,
            rcv_ssthresh: self.rcv_ssthresh,
            rttvar: self.rttvar,
            advmss: self.advmss,
            reordering: self.reordering,
            rcv_rtt: self.rcv_rtt,
            rcv_space: self.rcv_space,
            bytes_received: self.bytes_received,
            segs_out: self.segs_out,
            segs_in: self.segs_in,
            snd_wscale: self.snd_wscale,
            rcv_wscale: self.rcv_wscale,
            conn_id: self.conn_id,
            ..Default::default()
        }
    }
}

impl Event for OldSockEntry {
    const TABLE: &'static EventTable = sock_trace_entry::TABLE;
    const ENTRY_SIZE: usize = 172;

    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        decode_record(buf, Self::ENTRY_SIZE)
    }
    fn flow_key(&self) -> IpTuple {
        Event::flow_key(&self.current())
    }
    fn ts_ns(&self) -> i64 {
        self.time as i64
    }
    fn connection_key(&self) -> u32 {
        self.conn_id
    }
    fn socket_level(&self) -> bool {
        true
    }
    fn hook_seq(&self) -> i64 {
        self.hook_seq as i64
    }
    fn push_row(&self, batch: &mut EventBatch) {
        Event::push_row(&self.current(), batch)
    }
}
