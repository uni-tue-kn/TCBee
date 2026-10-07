use std::{error::Error, ffi::CString, io, mem::size_of, os::fd::AsFd, ptr::NonNull};

use libbpf_rs::{
    libbpf_sys, AsRawLibbpf, Link, ProgramAttachType, ProgramMut, TcHook, TcHookBuilder, TC_EGRESS,
    TC_INGRESS,
};
use log::{info, warn};
use tcbee_common::{
    prog_bindings::TraceInoutProbe,
    records::{tcp4_packet_trace, tcp6_packet_trace},
};

use tcbee_common::stats::{RB_TCP4_EGRESS, RB_TCP4_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS};

use crate::{
    eBPF::{
        ebpf_runner::prepend_string,
        errors::EBPFRunnerError,
        host::kernel_version,
        probes::handle,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

pub struct TCTracer {}

/// How the TC programs are attached to the interface
pub enum TcAttachment {
    /// tcx links (kernel 6.6 and newer), detached when dropped
    Tcx(Vec<Link>),
    /// Filters in the clsact qdisc of the interface
    Clsact {
        ifindex: i32,
        /// Whether TCBee added the qdisc. Only then it is removed again, which also
        /// removes the filters.
        created: bool,
        filters: Vec<TcHook>,
    },
}

impl TcAttachment {
    /// Detaches the programs. A leftover clsact qdisc keeps the TC hooks enabled in the
    /// kernel datapath, so the qdisc is removed if TCBee added it.
    pub fn detach(self) {
        let (ifindex, created, filters) = match self {
            TcAttachment::Tcx(links) => {
                drop(links);
                return;
            }
            TcAttachment::Clsact {
                ifindex,
                created,
                filters,
            } => (ifindex, created, filters),
        };
        if created {
            match clsact(ifindex, libbpf_sys::bpf_tc_hook_destroy) {
                Ok(()) => {
                    info!("Removed clsact qdisc from interface {}", ifindex);
                    return;
                }
                // At least take our programs out of the datapath
                Err(err) => warn!(
                    "Removing clsact qdisc from interface {} failed, detaching the filters: {}",
                    ifindex, err
                ),
            }
        }
        for mut filter in filters {
            if let Err(err) = filter.detach() {
                warn!(
                    "Detaching TC filter from interface {} failed: {}",
                    ifindex, err
                );
            }
        }
    }
}

/// tcx replaces the clsact qdisc for eBPF programs from kernel 6.6 on
pub fn uses_tcx() -> bool {
    kernel_version().is_some_and(|version| version >= (6, 6))
}

/// Creates or destroys the clsact qdisc of an interface
fn clsact(
    ifindex: i32,
    op: unsafe extern "C" fn(*mut libbpf_sys::bpf_tc_hook) -> i32,
) -> io::Result<()> {
    let mut hook = libbpf_sys::bpf_tc_hook {
        sz: size_of::<libbpf_sys::bpf_tc_hook>() as libbpf_sys::size_t,
        ifindex,
        attach_point: libbpf_sys::BPF_TC_INGRESS | libbpf_sys::BPF_TC_EGRESS,
        ..Default::default()
    };
    match unsafe { op(&mut hook) } {
        0 => Ok(()),
        err => Err(io::Error::from_raw_os_error(-err)),
    }
}

fn if_index(interface: &str) -> Result<i32, EBPFRunnerError> {
    let not_found = || EBPFRunnerError::InterfaceNotFound {
        name: interface.to_string(),
    };
    let name = CString::new(interface).map_err(|_| not_found())?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(not_found()),
        index => Ok(index as i32),
    }
}

fn attach_error(program: &ProgramMut<'_>, err: impl Into<libbpf_rs::Error>) -> EBPFRunnerError {
    EBPFRunnerError::AttachError {
        name: program.name().to_string_lossy().into_owned(),
        source: err.into(),
    }
}

fn attach_tcx(program: &ProgramMut<'_>, ifindex: i32) -> Result<Link, EBPFRunnerError> {
    // libbpf-rs has no tcx support yet
    let opts = libbpf_sys::bpf_tcx_opts {
        sz: size_of::<libbpf_sys::bpf_tcx_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    let link = unsafe {
        libbpf_sys::bpf_program__attach_tcx(program.as_libbpf_object().as_ptr(), ifindex, &opts)
    };
    match NonNull::new(link) {
        // SAFETY: a link that libbpf returned without error
        Some(link) => Ok(unsafe { Link::from_ptr(link) }),
        None => Err(attach_error(program, io::Error::last_os_error())),
    }
}

impl TCTracer {
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool, tcx: bool) {
        progs.tc_ingress_packet_tracer.set_autoload(enabled);
        progs.tc_egress_packet_tracer.set_autoload(enabled);
        // libbpf creates the tcx link with the program's expected attach type, SEC("tc")
        // leaves it unset
        if enabled && tcx {
            progs
                .tc_ingress_packet_tracer
                .set_attach_type(ProgramAttachType::TcxIngress);
            progs
                .tc_egress_packet_tracer
                .set_attach_type(ProgramAttachType::TcxEgress);
        }
    }

    /// Attaches both programs to `interface`. `attachment` is filled while attaching,
    /// so the caller can clean up a partial attachment if this fails.
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        interface: &str,
        dir: &str,
        writer: &mut Writer,
        tcx: bool,
        attachment: &mut Option<TcAttachment>,
    ) -> Result<(), Box<dyn Error>> {
        let ifindex = if_index(interface)?;
        let ingress = &skel.progs.tc_ingress_packet_tracer;
        let egress = &skel.progs.tc_egress_packet_tracer;

        if tcx {
            let links = match attachment.insert(TcAttachment::Tcx(Vec::new())) {
                TcAttachment::Tcx(links) => links,
                TcAttachment::Clsact { .. } => unreachable!(),
            };
            links.push(attach_tcx(ingress, ifindex)?);
            links.push(attach_tcx(egress, ifindex)?);
        } else {
            // Older kernels need the clsact qdisc. If it already exists, it is not ours
            // to remove.
            let created = match clsact(ifindex, libbpf_sys::bpf_tc_hook_create) {
                Ok(()) => true,
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => false,
                Err(err) => return Err(attach_error(ingress, err).into()),
            };
            let filters = match attachment.insert(TcAttachment::Clsact {
                ifindex,
                created,
                filters: Vec::new(),
            }) {
                TcAttachment::Clsact { filters, .. } => filters,
                TcAttachment::Tcx(_) => unreachable!(),
            };
            for (program, point) in [(ingress, TC_INGRESS), (egress, TC_EGRESS)] {
                // Handle and priority 0 let the kernel pick free ones, libbpf stores them
                // in the hook for detaching
                let mut hook = TcHookBuilder::new(program.as_fd())
                    .ifindex(ifindex)
                    .hook(point);
                let hook = hook.attach().map_err(|err| attach_error(program, err))?;
                filters.push(hook);
            }
        }

        writer.register::<tcp4_packet_trace>(
            RB_TCP4_INGRESS,
            vec![handle(&skel.maps.TCP4_PACKETS_INGRESS)?],
            prepend_string(tcp4_packet_trace::IN_FILE.to_string(), dir),
        )?;
        writer.register::<tcp6_packet_trace>(
            RB_TCP6_INGRESS,
            vec![handle(&skel.maps.TCP6_PACKETS_INGRESS)?],
            prepend_string(tcp6_packet_trace::IN_FILE.to_string(), dir),
        )?;
        writer.register::<tcp4_packet_trace>(
            RB_TCP4_EGRESS,
            vec![handle(&skel.maps.TCP4_PACKETS_EGRESS)?],
            prepend_string(tcp4_packet_trace::OUT_FILE.to_string(), dir),
        )?;
        writer.register::<tcp6_packet_trace>(
            RB_TCP6_EGRESS,
            vec![handle(&skel.maps.TCP6_PACKETS_EGRESS)?],
            prepend_string(tcp6_packet_trace::OUT_FILE.to_string(), dir),
        )?;

        Ok(())
    }
}
