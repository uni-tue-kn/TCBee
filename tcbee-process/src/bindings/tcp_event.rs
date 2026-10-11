//! Discrete TCP events (`tcbee-record -e`). Besides the fields, every row gets a text label
//! in the `event` column, which the visualizer draws as a marker.

use tcbee_common::records::{
    tcp_event_entry, TCBEE_TCP_CA_STATE, TCBEE_TCP_CWR, TCBEE_TCP_DROP, TCBEE_TCP_RETRANSMIT,
    TCBEE_TCP_RST_RECEIVED, TCBEE_TCP_RST_SENT, TCBEE_TCP_RTO, TCBEE_TCP_STATE,
};
use ts_storage::{ColType, Column, EventBatch, EventTable, IpTuple};

use crate::{
    event::{decode_record, push_col, DecodeError, Event},
    ip::{flow_tuple, kernel_addr_pair, AF_INET},
};

const fn col(name: &'static str, ty: ColType) -> Column {
    Column { name, ty }
}

/// TCP states, include/net/tcp_states.h
const TCP_STATES: [&str; 14] = [
    "0",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
    "NEW_SYN_RECV",
    "BOUND_INACTIVE",
];

/// Congestion states, enum tcp_ca_state
const CA_STATES: [&str; 5] = ["Open", "Disorder", "CWR", "Recovery", "Loss"];

fn name(names: &[&'static str], value: u8) -> String {
    names
        .get(value as usize)
        .map_or_else(|| value.to_string(), |n| n.to_string())
}

/// The marker text of an event
pub fn label(e: &tcp_event_entry) -> String {
    match u32::from(e.kind) {
        TCBEE_TCP_RETRANSMIT => "retransmit".to_string(),
        TCBEE_TCP_RST_SENT => "RST sent".to_string(),
        TCBEE_TCP_RST_RECEIVED => "RST received".to_string(),
        TCBEE_TCP_STATE => format!(
            "{} → {}",
            name(&TCP_STATES, e.old_state),
            name(&TCP_STATES, e.new_state)
        ),
        TCBEE_TCP_CA_STATE => format!(
            "{} → {}",
            name(&CA_STATES, e.old_state),
            name(&CA_STATES, e.new_state)
        ),
        TCBEE_TCP_RTO if e.backoff > 0 => format!("RTO, backoff {}", e.backoff),
        TCBEE_TCP_RTO => "RTO".to_string(),
        TCBEE_TCP_CWR => "CWR".to_string(),
        TCBEE_TCP_DROP => format!("drop, reason {}", e.reason),
        other => format!("event {other}"),
    }
}

static COLUMNS: [Column; 13] = [
    col("event", ColType::Text),
    col("kind", ColType::U8),
    col("old_state", ColType::U8),
    col("new_state", ColType::U8),
    col("ca_state", ColType::U8),
    col("backoff", ColType::U8),
    col("reason", ColType::U32),
    col("tcp_seq", ColType::U32),
    col("len", ColType::U32),
    col("snd_una", ColType::U32),
    col("snd_cwnd", ColType::U32),
    col("packets_out", ColType::U32),
    col("total_retrans", ColType::U32),
];

impl Event for tcp_event_entry {
    const TABLE: &'static EventTable = &EventTable {
        source: "tcp_event",
        columns: &COLUMNS,
    };
    const ENTRY_SIZE: usize = 99;

    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        decode_record(buf, Self::ENTRY_SIZE)
    }
    fn flow_key(&self) -> IpTuple {
        let (src, dst) = kernel_addr_pair(
            self.family == AF_INET,
            self.addr_v4,
            self.src_v6,
            self.dst_v6,
        );
        flow_tuple(src, dst, self.sport, self.dport)
    }
    fn ts_ns(&self) -> i64 {
        self.time as i64
    }
    fn hook_seq(&self) -> i64 {
        self.hook_seq as i64
    }
    fn push_row(&self, b: &mut EventBatch) {
        push_col!(b, 0, Text, label(self));
        push_col!(b, 1, U8, self.kind);
        push_col!(b, 2, U8, self.old_state);
        push_col!(b, 3, U8, self.new_state);
        push_col!(b, 4, U8, self.ca_state);
        push_col!(b, 5, U8, self.backoff);
        push_col!(b, 6, U32, self.reason);
        push_col!(b, 7, U32, self.seq);
        push_col!(b, 8, U32, self.len);
        push_col!(b, 9, U32, self.snd_una);
        push_col!(b, 10, U32, self.snd_cwnd);
        push_col!(b, 11, U32, self.packets_out);
        push_col!(b, 12, U32, self.total_retrans);
    }
}
