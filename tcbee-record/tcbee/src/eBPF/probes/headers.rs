use std::{error::Error, process::Command};

use log::{info, warn};

use aya::{
    maps::RingBuf,
    programs::{tc, SchedClassifier, TcAttachType},
    util::KernelVersion,
    Ebpf,
};
use tcbee_common::{
    bindings::tcp_header::{tcp4_packet_trace, tcp6_packet_trace},
    prog_bindings::TraceInoutProbe,
};

use tcbee_common::stats::{RB_TCP4_EGRESS, RB_TCP4_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS};

use crate::{
    eBPF::{ebpf_runner::prepend_string, errors::EBPFRunnerError},
    writer::Writer,
};

pub struct TCTracer {}

fn uses_tcx() -> bool {
    KernelVersion::current().is_ok_and(|version| version >= KernelVersion::new(6, 6, 0))
}

/// Removes the clsact qdisc added by `TCTracer::spawn`. A leftover clsact qdisc keeps
/// the TC hooks enabled in the kernel datapath.
pub fn remove_clsact(interface: &str) {
    let result = Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "clsact"])
        .status();
    match result {
        Ok(status) if status.success() => info!("Removed clsact qdisc from {}", interface),
        Ok(status) => warn!(
            "Removing clsact qdisc from {} failed: {}",
            interface, status
        ),
        Err(err) => warn!(
            "Could not run tc to remove clsact qdisc from {}: {}",
            interface, err
        ),
    }
}

impl TCTracer {
    pub fn spawn(
        ebpf: &mut Ebpf,
        interface: String,
        dir: String,
        writer: &mut Writer,
        created_clsact: &mut Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let name = "tc_ingress_packet_tracer";

        // aya attaches with tcx from kernel 6.6 on. Older kernels need the clsact qdisc,
        // adding it fails if it already exists. In that case it is not ours to remove.
        // If adding fails for any other reason, attaching fails below. The interface is
        // stored before attaching so the qdisc is also removed if attaching fails.
        if !uses_tcx() && tc::qdisc_add_clsact(&interface).is_ok() {
            *created_clsact = Some(interface.clone());
        }

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
        writer.register::<tcp4_packet_trace>(
            RB_TCP4_INGRESS,
            buff,
            prepend_string(tcp4_packet_trace::IN_FILE.to_string(), &dir),
        )?;

        let map =
            ebpf.take_map("TCP6_PACKETS_INGRESS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP6_PACKETS_INGRESS".to_string(),
                    trace: "TC Packet Tracer".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        writer.register::<tcp6_packet_trace>(
            RB_TCP6_INGRESS,
            buff,
            prepend_string(tcp6_packet_trace::IN_FILE.to_string(), &dir),
        )?;

        let name = "tc_egress_packet_tracer";

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
        writer.register::<tcp4_packet_trace>(
            RB_TCP4_EGRESS,
            buff,
            prepend_string(tcp4_packet_trace::OUT_FILE.to_string(), &dir),
        )?;

        let map =
            ebpf.take_map("TCP6_PACKETS_EGRESS")
                .ok_or(EBPFRunnerError::QueueNotFoundError {
                    name: "TCP6_PACKETS_EGRESS".to_string(),
                    trace: "TC Packet Tracer".to_string(),
                })?;

        let buff: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        writer.register::<tcp6_packet_trace>(
            RB_TCP6_EGRESS,
            buff,
            prepend_string(tcp6_packet_trace::OUT_FILE.to_string(), &dir),
        )?;

        Ok(())
    }
}
