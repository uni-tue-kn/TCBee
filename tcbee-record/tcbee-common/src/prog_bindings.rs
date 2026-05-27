use crate::bindings::{
    bbr::bbr_trace_entry,
    cubic::cubic_trace_entry,
    tcp_bad_csum::tcp_bad_csum_entry,
    tcp_header::{tcp4_packet_trace, tcp6_packet_trace},
    tcp_probe::tcp_probe_entry,
    tcp_retransmit_synack::tcp_retransmit_synack_entry,
    tcp_sock::{cwnd_trace_entry, sock_trace_entry},
};

// FIXME: We currently need to manually copy these bindings to tcbee-process as it cannot import tcbee-common
//   (There is some problem with the repr(C) that causes a segfault on DB start, dont know why ...
pub trait TracePointProbe {
    const CATEGORY: &'static str;
    const NAME: &'static str;
    const QUEUE: &'static str;
    const FILE: &'static str;
}

impl TracePointProbe for tcp_probe_entry {
    const CATEGORY: &'static str = "tcp";
    const NAME: &'static str = "tcp_probe";
    const QUEUE: &'static str = "TCP_PROBE_QUEUE";
    const FILE: &'static str = "tcp_probe.tcp";
}

impl TracePointProbe for tcp_retransmit_synack_entry {
    const CATEGORY: &'static str = "tcp";
    const NAME: &'static str = "tcp_retransmit_synack";
    const QUEUE: &'static str = "TCP_RETRANSMIT_SYNACK_QUEUE";
    const FILE: &'static str = "tcp_retransmit_synack.tcp";
}

impl TracePointProbe for tcp_bad_csum_entry {
    const CATEGORY: &'static str = "tcp";
    const NAME: &'static str = "tcp_bad_csum";
    const QUEUE: &'static str = "TCP_BAD_CSUM_QUEUE";
    const FILE: &'static str = "tcp_bad_csum.tcp";
}

pub trait TraceInoutProbe {
    const IN_QUEUE: &'static str;
    const IN_FILE: &'static str;
    const OUT_QUEUE: &'static str;
    const OUT_FILE: &'static str;
}

impl TraceInoutProbe for sock_trace_entry {
    const IN_FILE: &'static str = "recv_sock.tcp";
    const IN_QUEUE: &'static str = "TCP_RECV_SOCK_EVENTS";
    const OUT_FILE: &'static str = "send_sock.tcp";
    const OUT_QUEUE: &'static str = "TCP_SEND_SOCK_EVENTS";
}

impl TraceInoutProbe for cwnd_trace_entry {
    const IN_FILE: &'static str = "recv_cwnd.tcp";
    const IN_QUEUE: &'static str = "TCP_RECEIVE_CWND_EVENTS";
    const OUT_FILE: &'static str = "send_cwnd.tcp";
    const OUT_QUEUE: &'static str = "TCP_SEND_CWND_EVENTS";
}

impl TraceInoutProbe for tcp4_packet_trace {
    const IN_FILE: &'static str = "tcp4_receive.tcp";
    const IN_QUEUE: &'static str = "TCP4_PACKETS_INGRESS";
    const OUT_FILE: &'static str = "tcp4_send.tcp";
    const OUT_QUEUE: &'static str = "TCP4_PACKETS_EGRESS";
}

impl TraceInoutProbe for tcp6_packet_trace {
    const IN_FILE: &'static str = "tcp6_receive.tcp";
    const IN_QUEUE: &'static str = "TCP6_PACKETS_INGRESS";
    const OUT_FILE: &'static str = "tcp6_send.tcp";
    const OUT_QUEUE: &'static str = "TCP6_PACKETS_EGRESS";
}

pub trait TraceProbe {
    const QUEUE: &'static str;
    const FILE: &'static str;
}

impl TraceProbe for bbr_trace_entry {
    const QUEUE: &'static str = "BBR_EVENTS";
    const FILE: &'static str = "bbr.tcp";
}

impl TraceProbe for cubic_trace_entry {
    const QUEUE: &'static str = "CUBIC_EVENTS";
    const FILE: &'static str = "cubic.tcp";
}
