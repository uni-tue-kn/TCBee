use egui::Color32;
use tcbee_live_common::tcp_sock::{cwnd_trace_entry, FlowKey};

/// Minimum nanoseconds between stored samples — one point per 50 ms.
pub const SAMPLE_INTERVAL_NS: u64 = 50_000_000;

pub const PALETTE: &[Color32] = &[
    Color32::from_rgb(0x4E, 0x79, 0xA7),
    Color32::from_rgb(0xF2, 0x8E, 0x2B),
    Color32::from_rgb(0xE1, 0x57, 0x59),
    Color32::from_rgb(0x76, 0xB7, 0xB2),
    Color32::from_rgb(0x59, 0xA1, 0x4F),
    Color32::from_rgb(0xED, 0xC9, 0x48),
    Color32::from_rgb(0xB0, 0x7A, 0xA1),
    Color32::from_rgb(0xFF, 0x9D, 0xA7),
];

pub struct CwndEvent {
    pub key: FlowKey,
    pub time_ns: u64,
    pub snd_cwnd: u32,
}

pub enum FilterCmd {
    Add(FlowKey),
    Remove(FlowKey),
}

pub struct FlowData {
    pub label: String,
    pub points: Vec<[f64; 2]>, // [rel_time_secs, snd_cwnd]
    pub last_sample_ns: u64,
    pub selected: bool,
    pub color: Color32,
}

impl FlowData {
    pub fn new(key: &FlowKey, color: Color32) -> Self {
        FlowData {
            label: format_flow(key),
            points: Vec::new(),
            last_sample_ns: 0,
            selected: false,
            color,
        }
    }
}

/// Extract a FlowKey from a ring-buffer event using the same socket-local
/// ordering as the eBPF probe's make_flow_key().
pub fn flow_key_from_entry(entry: &cwnd_trace_entry) -> FlowKey {
    FlowKey {
        src_v6: entry.src_v6,
        dst_v6: entry.dst_v6,
        src_port: entry.sport,
        dst_port: entry.dport,
        family: entry.family,
        _pad: 0,
    }
}

pub fn format_flow(key: &FlowKey) -> String {
    let src = format_addr(&key.src_v6, key.family);
    let dst = format_addr(&key.dst_v6, key.family);
    format!("{}:{} \u{2192} {}:{}", src, key.src_port, dst, key.dst_port)
}

fn format_addr(v6: &[u8; 16], family: u16) -> String {
    const AF_INET: u16 = 2;
    if family == AF_INET {
        format!("{}.{}.{}.{}", v6[12], v6[13], v6[14], v6[15])
    } else {
        std::net::Ipv6Addr::from(*v6).to_string()
    }
}
