use crate::bindings::{tcp_bad_csum::tcp_bad_csum_entry, tcp_probe::tcp_probe_entry, tcp_retransmit_synack::tcp_retransmit_synack_entry};

pub trait TracePointProbe {
    const CATEGORY: &'static str;
    const NAME: &'static str;
    const QUEUE: &'static str;
}

impl TracePointProbe for tcp_probe_entry {
    const CATEGORY: &'static str = "tcp";
    const NAME: &'static str = "tcp_probe";
    const QUEUE: &'static str = "TCP_PROBE_QUEUE";
}

impl TracePointProbe for tcp_retransmit_synack_entry {
    const CATEGORY: &'static str = "tcp";
    const NAME: &'static str = "tcp_retransmit_synack";
    const QUEUE: &'static str = "TCP_RETRANSMIT_SYNACK_QUEUE";
}

impl TracePointProbe for tcp_bad_csum_entry {
    const CATEGORY: &'static str = "tcp";
    const NAME: &'static str = "tcp_bad_csum";
    const QUEUE: &'static str = "TCP_BAD_CSUM_QUEUE";
}