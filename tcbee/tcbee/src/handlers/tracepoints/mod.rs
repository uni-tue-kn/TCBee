// Available handlers
mod tcp_bad_csum;
mod tcp_retransmit_synack;
mod tcpprobe;

use aya::Pod;
use tcbee_common::bindings::{
    tcp_bad_csum::tcp_bad_csum_entry, tcp_probe::tcp_probe_entry, tcp_retransmit_synack::tcp_retransmit_synack_entry, tcp_sock::sock_trace_entry, EBPFTracePointType
};

// Constraint bounds for handler objects
pub trait HandlerConstraints<T>:
    std::fmt::Debug + Clone + Copy + Pod + std::marker::Send + std::marker::Sync + EBPFTracePointType
{
}
impl HandlerConstraints<tcp_probe_entry> for tcp_probe_entry {}
impl HandlerConstraints<tcp_retransmit_synack_entry> for tcp_retransmit_synack_entry {}
impl HandlerConstraints<tcp_bad_csum_entry> for tcp_bad_csum_entry {}
// TODO: move to another file
impl HandlerConstraints<sock_trace_entry> for sock_trace_entry {}
