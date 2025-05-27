use std::error::Error;

use aya::{maps::RingBuf, programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags}, Ebpf};
use tcbee_common::bindings::tcp_header::tcp_packet_trace;
use tokio::task::{self, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{eBPF::errors::EBPFRunnerError, handlers::BufferHandler};

pub struct TCTracer {
}

impl TCTracer {
    pub fn spawn(
        ebpf: &mut Ebpf,
        interface: String,
        token: CancellationToken,
        file_path: String,
    ) -> Result<JoinHandle<()>, Box<dyn Error>> {
        let name = "tc_packet_tracer";

        // Needs to be called before a TC can be attached to a program!
        // Error supressed because if this fails it may be a false positive "file exists"
        // The next call will fail either way if this fails due to any other reason!
        //
        let _ = tc::qdisc_add_clsact(&interface);

        // Attach eBPF TC to Egress
        let tracer: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or(EBPFRunnerError::InvalidProgramError {
                name: name.to_string(),
            })?
            .try_into()?;

        // Load and attach tracepoint to kernel
        tracer.load()?;
        tracer.attach(&interface, TcAttachType::Egress)?;

        // Start handling function
        // Get queue from
        let map =
            ebpf.take_map("TCP_PACKETS_EGRESS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP_PACKETS_EGRESS".to_string(),
                    trace: "TC Packet Tracer".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // Create handler object
        // TODO: handling of None!
        let mut handler: BufferHandler<tcp_packet_trace> =
            BufferHandler::<tcp_packet_trace>::new(name, token, buff, file_path).unwrap();

        // Start thread and store join handle
        Ok(task::spawn(async move {
            handler.run().await;
        }))

    }
}

pub struct XDPTracer {
}

impl XDPTracer {
    pub fn spawn(
        ebpf: &mut Ebpf,
        interface: String,
        token: CancellationToken,
        file_path: String,
    ) -> Result<JoinHandle<()>, Box<dyn Error>> {
        // Get tracepoint name
        let name = "xdp_packet_tracer";

        // Get XDP object from eBPF library
        let tracer: &mut Xdp = ebpf
            .program_mut(name)
            .ok_or(EBPFRunnerError::InvalidProgramError {
                name: name.to_string(),
            })?
            .try_into()?;

        // Load and attach tracepoint to kernel
        tracer.load()?;
        tracer.attach(&interface, XdpFlags::default())?;

        // Start handling function
        // Get queue from
        let map =
            ebpf.take_map("TCP_PACKETS_INGRESS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP_PACKETS_INGRESS".to_string(),
                    trace: "XDP Packet Tracer".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;

        // Handler takes ownership of all variables, no storage in struct needed
        let mut handler: BufferHandler<tcp_packet_trace> =
            BufferHandler::<tcp_packet_trace>::new(name, token, buff, file_path).unwrap();

        // Start thread and store join handle
        Ok(task::spawn(async move {
            handler.run().await;
        }))
    }
}
