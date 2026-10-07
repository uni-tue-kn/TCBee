//! One ring buffer per CPU for every probe output.
//!
//! A probe reserves its record in the ring buffer of the CPU it runs on (see `maps.h`), so
//! producers on different CPUs never wait for each other. With one ring buffer shared by
//! all CPUs, its reservation lock limited `-h` to about 1.6 M events/s on 8 and more
//! sending CPUs. Each ring buffer map of the eBPF object is an array of ring buffers
//! indexed by CPU id: the slots are sized before load, the rings are created after load.
//! The order of a flow's events at a hook is in the records (`hook_seq`), not in the files.

use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapMut, MapType, Object, OpenObject};
use log::info;
use tcbee_common::stats::RINGBUFS;

use super::errors::EBPFRunnerError;

/// Number of ring buffers per probe output, one per possible CPU id
pub fn cpus() -> Result<u32, EBPFRunnerError> {
    libbpf_rs::num_possible_cpus()
        .map(|n| n as u32)
        .map_err(|err| EBPFRunnerError::Unavailable(format!("Cannot count the CPUs: {err}")))
}

/// Gives every ring buffer array one slot per CPU. Must run before the object is loaded.
pub fn set_slots(object: &mut OpenObject, cpus: u32) -> libbpf_rs::Result<()> {
    for mut map in object.maps_mut() {
        if RINGBUFS.iter().any(|(name, _)| map.name() == *name) {
            map.set_max_entries(cpus)?;
        }
    }
    Ok(())
}

/// Creates the ring buffers `rbs` (indexes into `RINGBUFS`) for every CPU with
/// `size(rb)` bytes each and puts them into their arrays. The arrays keep them alive.
pub fn create(
    object: &Object,
    rbs: &[u32],
    size: impl Fn(u32) -> u32,
    cpus: u32,
) -> Result<(), EBPFRunnerError> {
    let mut total: u64 = 0;
    for &rb in rbs {
        let name = RINGBUFS[rb as usize].0;
        let error = |source| EBPFRunnerError::MapError {
            name: name.to_string(),
            source,
        };
        let array = object
            .maps()
            .find(|map| map.name() == name)
            .ok_or_else(|| EBPFRunnerError::Unavailable(format!("Map {name} not found")))?;
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        for cpu in 0..cpus {
            let ring = MapHandle::create(
                MapType::RingBuf,
                Some(format!("rb{rb}_cpu{cpu}")),
                0,
                0,
                size(rb),
                &opts,
            )
            .map_err(error)?;
            let fd = ring.as_fd().as_raw_fd() as u32;
            array
                .update(&cpu.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
                .map_err(error)?;
            total += u64::from(size(rb));
        }
    }
    info!(
        "Created {} ring buffers per CPU on {} CPUs, {} MiB in total",
        rbs.len(),
        cpus,
        total >> 20
    );
    Ok(())
}

/// The ring buffers of an array created by `create`, one per CPU
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
