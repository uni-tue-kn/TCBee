use std::{
    error::Error,
    ffi::CString,
    io,
    mem::size_of,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    ptr::NonNull,
};

use libbpf_rs::{
    libbpf_sys, AsRawLibbpf, Link, ProgramAttachType, ProgramMut, TcHook, TcHookBuilder, TC_EGRESS,
    TC_INGRESS,
};
use log::{info, warn, Level};
use tcbee_common::records::{tcp4_packet_trace, tcp6_packet_trace};

use tcbee_common::stats::{
    RB_TCP4_DRIVER_INGRESS, RB_TCP4_EGRESS, RB_TCP4_INGRESS, RB_TCP6_DRIVER_INGRESS,
    RB_TCP6_EGRESS, RB_TCP6_INGRESS,
};

use crate::{
    eBPF::{
        ebpf_runner_config::HeadersAt,
        errors::EBPFRunnerError,
        host::kernel_version,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    metadata::Offloads,
    writer::Writer,
};

pub struct TCTracer {}

/// The driver hooks of -h (`--headers-at driver`): native XDP for received packets
pub struct DriverTracer {}

/// The XDP link of the driver hook; closing it detaches the program
pub struct XdpLink(#[allow(dead_code)] OwnedFd);

/// What the offloads of `iface` mean for the header hooks of `at`: messages to log, or an error
/// if the driver hooks would not see the packets one by one. An offload the driver does not
/// report counts as off.
pub fn check_offloads(
    iface: &str,
    at: HeadersAt,
    offloads: &Offloads,
) -> Result<Vec<(Level, String)>, String> {
    let on = |offload: Option<bool>| offload == Some(true);
    let hw_merge = on(offloads.lro) || on(offloads.gro_hw);
    if at.driver && hw_merge {
        return Err(format!(
            "--headers-at driver: {iface} merges received packets in hardware (LRO or rx-gro-hw), \
            so XDP would not see them one by one (and mlx5 refuses XDP then). Switch it off with: \
            ethtool -K {iface} lro off rx-gro-hw off"
        ));
    }
    let mut notes = Vec::new();
    if hw_merge {
        notes.push((
            Level::Warn,
            format!(
                "{iface} merges received packets in hardware (LRO or rx-gro-hw): no hook sees them \
                one by one, a received header record can stand for several segments"
            ),
        ));
    }
    if at.tc {
        if on(offloads.tso) || on(offloads.gso) {
            notes.push((
                Level::Info,
                format!(
                    "TC egress on {iface} sees packets before segmentation (TSO/GSO on): a sent \
                    header record can stand for several segments"
                ),
            ));
        }
        if on(offloads.gro) {
            notes.push((
                Level::Info,
                format!(
                    "TC ingress on {iface} sees packets after GRO: a received header record can \
                    stand for several segments"
                ),
            ));
        }
    }
    if at.driver && on(offloads.tso) {
        notes.push((
            Level::Warn,
            format!(
                "{iface} segments sent packets in hardware (TSO on): net_dev_start_xmit sees them \
                before segmentation, a sent header record can stand for several segments. ethtool \
                -K {iface} tso off gives one record per segment"
            ),
        ));
    }
    Ok(notes)
}

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
            rings::of(&skel.maps.TCP4_PACKETS_INGRESS)?,
            dir,
        )?;
        writer.register::<tcp6_packet_trace>(
            RB_TCP6_INGRESS,
            rings::of(&skel.maps.TCP6_PACKETS_INGRESS)?,
            dir,
        )?;
        writer.register::<tcp4_packet_trace>(
            RB_TCP4_EGRESS,
            rings::of(&skel.maps.TCP4_PACKETS_EGRESS)?,
            dir,
        )?;
        writer.register::<tcp6_packet_trace>(
            RB_TCP6_EGRESS,
            rings::of(&skel.maps.TCP6_PACKETS_EGRESS)?,
            dir,
        )?;

        Ok(())
    }
}

/// Attaches the XDP program in native (driver) mode through a link. The kernel refuses the
/// link if the driver has no native XDP (generic XDP would run after the skb is built and see
/// what TC sees) and if the interface already has an XDP program: a link never replaces one.
fn attach_xdp(
    program: &ProgramMut<'_>,
    ifindex: i32,
    interface: &str,
) -> Result<XdpLink, EBPFRunnerError> {
    let opts = libbpf_sys::bpf_link_create_opts {
        sz: size_of::<libbpf_sys::bpf_link_create_opts>() as libbpf_sys::size_t,
        flags: libbpf_sys::XDP_FLAGS_DRV_MODE,
        ..Default::default()
    };
    let fd = unsafe {
        libbpf_sys::bpf_link_create(
            program.as_fd().as_raw_fd(),
            ifindex,
            libbpf_sys::BPF_XDP,
            &opts,
        )
    };
    if fd >= 0 {
        // SAFETY: a new link fd that nothing else owns
        return Ok(XdpLink(unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    let err = io::Error::from_raw_os_error(-fd);
    let reason = match err.raw_os_error() {
        Some(libc::EOPNOTSUPP) => {
            format!("the driver of {interface} has no native XDP, which --headers-at driver needs")
        }
        Some(libc::EBUSY) | Some(libc::EEXIST) => {
            format!("{interface} already has an XDP program, tcbee-record does not replace it")
        }
        _ => format!("attaching XDP to {interface} failed: {err}"),
    };
    Err(EBPFRunnerError::Unavailable(reason))
}

impl DriverTracer {
    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, enabled: bool) {
        progs.xdp_ingress_packet_tracer.set_autoload(enabled);
    }

    /// Attaches the driver hooks to `interface`. `xdp` holds the XDP link once attached, so
    /// the caller detaches it if a later step fails.
    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        interface: &str,
        dir: &str,
        writer: &mut Writer,
        xdp: &mut Option<XdpLink>,
    ) -> Result<(), Box<dyn Error>> {
        let ifindex = if_index(interface)?;
        info!("Attaching XDP to {interface}, which may reset the rings of its driver");
        *xdp = Some(attach_xdp(
            &skel.progs.xdp_ingress_packet_tracer,
            ifindex,
            interface,
        )?);

        writer.register::<tcp4_packet_trace>(
            RB_TCP4_DRIVER_INGRESS,
            rings::of(&skel.maps.TCP4_DRIVER_INGRESS)?,
            dir,
        )?;
        writer.register::<tcp6_packet_trace>(
            RB_TCP6_DRIVER_INGRESS,
            rings::of(&skel.maps.TCP6_DRIVER_INGRESS)?,
            dir,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TC: HeadersAt = HeadersAt {
        tc: true,
        driver: false,
    };
    const DRIVER: HeadersAt = HeadersAt {
        tc: false,
        driver: true,
    };

    fn levels(notes: &[(Level, String)]) -> Vec<Level> {
        notes.iter().map(|(level, _)| *level).collect()
    }

    #[test]
    fn offloads_against_the_header_hooks() {
        let off = Offloads {
            tso: Some(false),
            gso: Some(false),
            gro: Some(false),
            lro: Some(false),
            gro_hw: Some(false),
        };
        assert!(check_offloads("eth0", TC, &off).unwrap().is_empty());
        assert!(check_offloads("eth0", DRIVER, &off).unwrap().is_empty());
        // unknown counts as off
        assert!(check_offloads("eth0", DRIVER, &Offloads::default())
            .unwrap()
            .is_empty());

        let software = Offloads {
            gso: Some(true),
            gro: Some(true),
            ..off
        };
        assert_eq!(
            levels(&check_offloads("eth0", TC, &software).unwrap()),
            [Level::Info, Level::Info]
        );
        // the driver hooks see the packets after software GSO and before GRO
        assert!(check_offloads("eth0", DRIVER, &software)
            .unwrap()
            .is_empty());

        let tso = Offloads {
            tso: Some(true),
            ..off
        };
        assert_eq!(
            levels(&check_offloads("eth0", DRIVER, &tso).unwrap()),
            [Level::Warn]
        );

        for hw in [
            Offloads {
                lro: Some(true),
                ..off
            },
            Offloads {
                gro_hw: Some(true),
                ..off
            },
        ] {
            let err = check_offloads("eth1", DRIVER, &hw).unwrap_err();
            assert!(
                err.contains("ethtool -K eth1 lro off rx-gro-hw off"),
                "{err}"
            );
            assert_eq!(
                levels(&check_offloads("eth1", TC, &hw).unwrap()),
                [Level::Warn]
            );
        }
    }

    /// Every message reads as one sentence, without the indentation of a broken line
    #[test]
    fn offload_messages_have_no_gaps() {
        let all = Offloads {
            tso: Some(true),
            gso: Some(true),
            gro: Some(true),
            lro: Some(true),
            gro_hw: Some(true),
        };
        let mut messages = vec![check_offloads("eth0", DRIVER, &all).unwrap_err()];
        messages.extend(
            check_offloads("eth0", TC, &all)
                .unwrap()
                .into_iter()
                .map(|n| n.1),
        );
        let tso = Offloads {
            tso: Some(true),
            ..Offloads::default()
        };
        messages.extend(
            check_offloads("eth0", DRIVER, &tso)
                .unwrap()
                .into_iter()
                .map(|n| n.1),
        );
        assert_eq!(messages.len(), 5);
        for message in messages {
            assert!(!message.contains("  "), "{message}");
        }
    }
}
