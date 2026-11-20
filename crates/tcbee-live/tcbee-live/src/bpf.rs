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

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use libbpf_rs::{MapType, skel::SkelBuilder};

    use super::*;

    fn key() -> FlowKey {
        let mut src_v6 = [0; 16];
        src_v6[10..].copy_from_slice(&[0xff, 0xff, 10, 0, 0, 1]);
        FlowKey {
            src_v6,
            dst_v6: [7; 16],
            src_port: 5201,
            dst_port: 40000,
            family: 2,
            _pad: 0,
        }
    }

    #[test]
    fn skeleton_has_the_programs_and_maps() {
        let mut storage = MaybeUninit::uninit();
        let open = LiveSkelBuilder::default().open(&mut storage).unwrap();
        // Compiles only while both programs exist
        let _ = (
            &open.progs.cwnd_transmit_skb,
            &open.progs.cwnd_rcv_established,
        );

        assert_eq!(open.maps.KNOWN_FLOWS.map_type(), MapType::LruHash);
        assert_eq!(open.maps.FLOW_FILTER.map_type(), MapType::Hash);
        // README: at most 256 flows can be selected at a time
        assert_eq!(open.maps.FLOW_FILTER.max_entries(), 256);
        assert_eq!(open.maps.EVENTS.map_type(), MapType::RingBuf);
        assert_eq!(
            open.maps.KNOWN_FLOWS.key_size() as usize,
            size_of::<FlowKey>()
        );
        assert_eq!(
            open.maps.FLOW_FILTER.key_size() as usize,
            size_of::<FlowKey>()
        );

        // The kernel wants a ring buffer size that is a power of two and a page multiple
        let size = open.maps.EVENTS.max_entries();
        assert!(size.is_power_of_two() && size >= 4096, "{size}");
    }

    #[test]
    fn flow_key_bytes_round_trip() {
        let key = key();
        assert_eq!(key.as_bytes().len(), 40);
        assert_eq!(FlowKey::from_bytes(key.as_bytes()), Some(key));
        assert_eq!(FlowKey::from_bytes(&[0; 39]), None);
    }

    #[test]
    fn parse_event_reads_the_c_layout() {
        let mut bytes = Vec::new();
        bytes.extend(123_456_789u64.to_ne_bytes());
        bytes.extend(key().as_bytes());
        bytes.extend(42u32.to_ne_bytes());
        bytes.extend(0u32.to_ne_bytes());

        let event = parse_event(&bytes).unwrap();
        assert_eq!(event.time_ns, 123_456_789);
        assert_eq!(event.key, key());
        assert_eq!(event.snd_cwnd, 42);

        assert!(parse_event(&bytes[..55]).is_none());
    }
}
