use std::error::Error;

use aya::{
    maps::RingBuf,
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    Ebpf,
};
use tcbee_common::bindings::tcp_header::{tcp4_packet_trace,tcp6_packet_trace};

use crate::{
    eBPF::errors::EBPFRunnerError,
    writer::Writer,
};

pub struct TCTracer {}

impl TCTracer {
    pub fn spawn(
        ebpf: &mut Ebpf,
        interface: String,
        dir: String,
        writer: &mut Writer,
    ) -> Result<(), Box<dyn Error>> {
        let name = "tc_ingress_packet_tracer";

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
        tracer.attach(&interface, TcAttachType::Ingress)?;

        // Start handling function
        // Get queue from
        let map =
            ebpf.take_map("TCP4_PACKETS_INGRESS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP4_PACKETS_INGRESS".to_string(),
                    trace: "TC Packet Tracer".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        writer.register::<tcp4_packet_trace>(buff, "/tmp/tc4_ingress.tcp")?;

        let map =
            ebpf.take_map("TCP6_PACKETS_INGRESS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP6_PACKETS_INGRESS".to_string(),
                    trace: "TC Packet Tracer".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        writer.register::<tcp6_packet_trace>(buff, "/tmp/tc6_ingress.tcp")?;

        let name = "tc_egress_packet_tracer";

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
            ebpf.take_map("TCP4_PACKETS_EGRESS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP4_PACKETS_EGRESS".to_string(),
                    trace: "TC Packet Tracer".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        writer.register::<tcp4_packet_trace>(buff, "/tmp/tc4_egress.tcp")?;

        let map =
            ebpf.take_map("TCP6_PACKETS_EGRESS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP6_PACKETS_EGRESS".to_string(),
                    trace: "TC Packet Tracer".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        writer.register::<tcp6_packet_trace>(buff, "/tmp/tc6_egress.tcp")?;




        Ok(())
    }
}

pub struct XDPTracer {}

impl XDPTracer {
    pub fn spawn(
        ebpf: &mut Ebpf,
        interface: String,
        file_path: String,
        writer: &mut Writer,
    ) -> Result<(), Box<dyn Error>> {
        /* 
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
        writer.register::<tcp_packet_trace>(buff, file_path)?;
        */
        Ok(())
    }
}
