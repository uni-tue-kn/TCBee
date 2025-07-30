use std::{error::Error};

use anyhow::Context;
use aya::{maps::RingBuf, programs::FEntry, Btf, Ebpf};
use tcbee_common::bindings::tcp_sock::cwnd_trace_entry;
use tokio::task::{self, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{eBPF::errors::EBPFRunnerError, handlers::BufferHandler};


pub struct CwndTracer {
}

impl CwndTracer {
    pub fn spawn(
        ebpf: &mut Ebpf,
        token: CancellationToken,
        send_file_path: String,
        recv_file_path: String,
    ) -> Result<Vec<JoinHandle<()>>, Box<dyn Error>> {
        let btf = Btf::from_sys_fs().context("BTF from sysfs")?;

        // Outgoing TCP
        let sendmsg: &mut FEntry = ebpf.program_mut("cwnd_sock_sendmsg").unwrap().try_into()?;
        sendmsg.load("tcp_sendmsg", &btf)?;
        sendmsg.attach()?;

        // Incoming TCP
        let recvmsg: &mut FEntry = ebpf.program_mut("cwnd_sock_recvmsg").unwrap().try_into()?;
        recvmsg.load("tcp_recvmsg", &btf)?;
        recvmsg.attach()?;

        // Start SOCK_SEND handling
        // Get queue from
        let map =
            ebpf.take_map("TCP_SEND_CWND_EVENTS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP_SEND_CWND_EVENTS".to_string(),
                    trace: "CWND Tracer tcp_sendmsg".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // Create handler object
        let mut handler: BufferHandler<cwnd_trace_entry> = BufferHandler::<cwnd_trace_entry>::new(
            "TCP_SEND_CWND_EVENTS",
            token.clone(),
            buff,
            send_file_path
        )
        .unwrap();

        // Start thread and store join handle
        let send_thread: JoinHandle<()> = task::spawn(async move {
            handler.run().await;
        });


        // Start SOCK_RECV handling
        // Get queue from
        let map =
            ebpf.take_map("TCP_RECEIVE_CWND_EVENTS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP_RECEIVE_CWND_EVENTS".to_string(),
                    trace: "CWND Tracer tcp_recvmsg".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // Create handler object
        let mut handler: BufferHandler<cwnd_trace_entry> = BufferHandler::<cwnd_trace_entry>::new(
            "TCP_RECEIVE_CWND_EVENTS",
            token,
            buff,
            recv_file_path,
        )
        .unwrap();

        // Start thread and store join handle
        let recv_thread: JoinHandle<()> = task::spawn(async move {
            handler.run().await;
        });


        Ok(vec![send_thread,recv_thread])
    }
}