//! One ring buffer per CPU for every probe output.
//!
//! A probe reserves its record in the ring buffer of the CPU it runs on (see `maps.h`), so
//! producers on different CPUs never wait for each other. With one ring buffer shared by
//! all CPUs, its reservation lock limited `-h` to about 1.6 M events/s on 8 and more
//! sending CPUs. Each ring buffer map of the eBPF object is an array of ring buffers
//! indexed by CPU id: the slots are sized before load, the rings are created after load.
//! The order of a flow's events at a hook is in the records (`hook_seq`), not in the files.

use std::{
    fs, mem,
    os::fd::{AsFd, AsRawFd},
};

use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapMut, MapType, Object, OpenObject};
use log::info;
use tcbee_common::stats::RINGBUFS;

use super::errors::EBPFRunnerError;

/// The CPUs that get ring buffers
pub struct Cpus {
    /// Online CPU ids, each gets a ring buffer per probe output
    pub online: Vec<u32>,
    /// Slots per array: highest possible CPU id + 1, ids need not be contiguous
    pub slots: u32,
}

impl Cpus {
    pub fn get() -> Result<Cpus, EBPFRunnerError> {
        let online = read_cpu_list("online")?;
        let slots = read_cpu_list("possible")?.into_iter().max().unwrap_or(0) + 1;
        Ok(Cpus { online, slots })
    }
}

/// Parses /sys/devices/system/cpu/<name>, a list like "0-3,8-11"
fn read_cpu_list(name: &str) -> Result<Vec<u32>, EBPFRunnerError> {
    let path = format!("/sys/devices/system/cpu/{name}");
    let invalid = || EBPFRunnerError::Unavailable(format!("Cannot read the CPU list {path}"));
    let list = fs::read_to_string(&path).map_err(|_| invalid())?;
    let mut cpus = Vec::new();
    for range in list.trim().split(',') {
        let (first, last) = range.split_once('-').unwrap_or((range, range));
        let (first, last): (u32, u32) = (
            first.parse().map_err(|_| invalid())?,
            last.parse().map_err(|_| invalid())?,
        );
        cpus.extend(first..=last);
    }
    Ok(cpus)
}

/// Gives every ring buffer array one slot per CPU id. Must run before the object is loaded.
pub fn set_slots(object: &mut OpenObject, cpus: &Cpus) -> Result<(), EBPFRunnerError> {
    for mut map in object.maps_mut() {
        if RINGBUFS.iter().any(|ringbuf| map.name() == ringbuf.map) {
            let name = map.name().to_string_lossy().into_owned();
            map.set_max_entries(cpus.slots)
                .map_err(|source| EBPFRunnerError::MapError { name, source })?;
        }
    }
    Ok(())
}

/// Creates the ring buffers `rbs` (indexes into `RINGBUFS`) for every online CPU with
/// `size(rb)` bytes each and puts them into their arrays. The arrays keep them alive.
/// Events on a CPU that comes online later find no ring buffer and count as errors.
pub fn create(
    object: &Object,
    rbs: &[u32],
    size: impl Fn(u32) -> u32,
    cpus: &Cpus,
) -> Result<(), EBPFRunnerError> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    let mut total: u64 = 0;
    for &rb in rbs {
        let name = RINGBUFS[rb as usize].map;
        let bytes = size(rb);
        let error = |source| EBPFRunnerError::MapError {
            name: format!("{name} ({bytes} bytes per CPU)"),
            source,
        };
        let array = object
            .maps()
            .find(|map| map.name() == name)
            .ok_or_else(|| EBPFRunnerError::Unavailable(format!("Map {name} not found")))?;
        for &cpu in &cpus.online {
            let ring = MapHandle::create(
                MapType::RingBuf,
                Some(format!("rb{rb}_cpu{cpu}")),
                0,
                0,
                bytes,
                &opts,
            )
            .map_err(error)?;
            let fd = ring.as_fd().as_raw_fd() as u32;
            array
                .update(&cpu.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
                .map_err(error)?;
            total += u64::from(bytes);
        }
    }
    info!(
        "Created {} ring buffers per CPU on {} CPUs, {} MiB in total",
        rbs.len(),
        cpus.online.len(),
        total >> 20
    );
    Ok(())
}

/// The ring buffers of an array filled by `create`, one per online CPU
pub fn of(array: &MapMut<'_>) -> Result<Vec<MapHandle>, EBPFRunnerError> {
    let error = |source| EBPFRunnerError::MapError {
        name: array.name().to_string_lossy().into_owned(),
        source,
    };
    let mut rings = Vec::new();
    for cpu in 0..array.max_entries() {
        // Userspace lookups in a map of maps return the inner map's id
        if let Some(id) = array
            .lookup(&cpu.to_ne_bytes(), MapFlags::ANY)
            .map_err(error)?
        {
            let id = u32::from_ne_bytes(id[..4].try_into().expect("map id is 4 bytes"));
            rings.push(MapHandle::from_map_id(id).map_err(error)?);
        }
    }
    Ok(rings)
}
