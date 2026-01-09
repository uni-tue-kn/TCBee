use std::error::Error;

use anyhow::Context;
use aya::{maps::RingBuf, programs::FEntry, Btf, Ebpf};
use tcbee_common::{bindings::tcp_sock::sock_trace_entry, prog_bindings::TraceInoutProbe};

use crate::{
    eBPF::{ebpf_runner::prepend_string, errors::EBPFRunnerError},
    writer::Writer,
};

pub struct KernelTracer {}

impl KernelTracer {
    pub fn spawn(ebpf: &mut Ebpf, dir: String, writer: &mut Writer) -> Result<(), Box<dyn Error>> {
        let btf = Btf::from_sys_fs().context("BTF from sysfs")?;

        // Outgoing TCP
        let sendmsg: &mut FEntry = ebpf.program_mut("sock_sendmsg").unwrap().try_into()?;
        sendmsg.load("__tcp_transmit_skb", &btf)?;
        sendmsg.attach()?;

        // Incoming TCP
        let recvmsg: &mut FEntry = ebpf.program_mut("sock_recvmsg").unwrap().try_into()?;
        recvmsg.load("tcp_rcv_established", &btf)?;
        recvmsg.attach()?;

        // Start SOCK_SEND handling
        // Get queue from
        let map =
            ebpf.take_map("TCP_SEND_SOCK_EVENTS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP_SEND_SOCK_EVENTS".to_string(),
                    trace: "Socket Tracer tcp_sendmsg".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // Register with writer object
        writer.register::<sock_trace_entry>(
            buff,
            prepend_string(sock_trace_entry::OUT_FILE.to_string(), &dir),
        )?;

        // Start SOCK_RECV handling
        // Get queue from
        let map =
            ebpf.take_map("TCP_RECV_SOCK_EVENTS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP_RECV_SOCK_EVENTS".to_string(),
                    trace: "Socket Tracer tcp_recvmsg".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        writer.register::<sock_trace_entry>(
            buff,
            prepend_string(sock_trace_entry::IN_FILE.to_string(), &dir),
        )?;

        Ok(())
    }
}
