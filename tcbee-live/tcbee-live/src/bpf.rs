//! The C eBPF object (`src/bpf/live.bpf.c`) and the types shared with it.

use std::mem::{offset_of, size_of};

mod skel {
    include!(concat!(env!("OUT_DIR"), "/live.skel.rs"));
}

pub use skel::{LiveMaps, LiveSkelBuilder};

use crate::types::CwndEvent;

/// `struct flow_key` of live.h: a TCP flow from the socket's side (src is local,
/// dst is remote). IPv4 addresses are IPv4-mapped, ports in host order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_v6: [u8; 16],
    pub dst_v6: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub family: u16,
    pub _pad: u16,
}

/// `struct cwnd_event` of live.h, as the probes write it into EVENTS. The skeleton
/// does not generate it: only the map key and value types are in the object's BTF.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawCwndEvent {
    time: u64,
    key: FlowKey,
    snd_cwnd: u32,
    _pad: u32,
}

// The sizes and offsets of live.h (_Static_assert there)
const _: () = assert!(size_of::<FlowKey>() == 40);
const _: () = assert!(size_of::<FlowKey>() == size_of::<skel::types::flow_key>());
const _: () = assert!(size_of::<RawCwndEvent>() == 56);
const _: () = assert!(offset_of!(RawCwndEvent, key) == 8);
const _: () = assert!(offset_of!(RawCwndEvent, snd_cwnd) == 48);

impl FlowKey {
    /// The key as the BPF maps store it
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: repr(C) with only integer fields and no padding (size asserted above)
        unsafe { std::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }

    /// Reads a key from the bytes of a BPF map key
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == size_of::<Self>())
            // SAFETY: length checked, every bit pattern is a valid FlowKey
            .then(|| unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }
}

/// Reads a `struct cwnd_event` from the EVENTS ring buffer
pub fn parse_event(bytes: &[u8]) -> Option<CwndEvent> {
    if bytes.len() != size_of::<RawCwndEvent>() {
        return None;
    }
    // SAFETY: length checked, every bit pattern is a valid RawCwndEvent
    let event: RawCwndEvent = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
    Some(CwndEvent {
        key: event.key,
        time_ns: event.time,
        snd_cwnd: event.snd_cwnd,
    })
}
