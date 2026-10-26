//! Fixtures the TUI tests share: counters, runs, flows, owner records and a rendered screen

use std::{mem, net::IpAddr, time::Duration};

use ratatui::{backend::TestBackend, Terminal};
use tcbee_common::{
    records::flow_owner_entry,
    stats::{
        slot, RB_TCP4_EGRESS, RB_TCP4_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS, STATS_LEN,
        STAT_DROPPED, STAT_HANDLED,
    },
};

use crate::{
    config::{AF_INET, AF_INET6},
    stats::Snapshot,
    viz::{
        context::RunContext,
        flow_owners::Endpoint,
        flow_tracker::{Flow, Flows},
        model::Model,
        view::{render, Areas, UiState},
    },
};

/// The rings of the TC header hooks
pub const TC_RINGS: [u32; 4] = [
    RB_TCP4_EGRESS,
    RB_TCP4_INGRESS,
    RB_TCP6_EGRESS,
    RB_TCP6_INGRESS,
];

/// A snapshot with `values` in the given slots, zero elsewhere
pub fn snapshot(values: &[(u32, u64)]) -> Snapshot {
    let mut all = vec![0; STATS_LEN as usize];
    for (slot, value) in values {
        all[*slot as usize] = *value;
    }
    Snapshot::from_values(all)
}

/// Two ticks one second apart: 1000 records and 10 drops, 600 packets in, 400 out
pub fn busy_model(rings: &[u32]) -> Model {
    let mut model = Model::new(rings);
    model.update(snapshot(&[]), 0, Duration::from_millis(500));
    model.record_history();
    let values = [
        (slot(RB_TCP4_INGRESS, STAT_HANDLED), 600),
        (slot(RB_TCP4_EGRESS, STAT_HANDLED), 390),
        (slot(RB_TCP4_EGRESS, STAT_DROPPED), 10),
    ];
    model.update(snapshot(&values), 2_000_000, Duration::from_millis(1500));
    model.record_history();
    model
}

/// A run with the given rings
pub fn context(rings: &[u32]) -> RunContext {
    RunContext {
        dir: "/data/run1".to_string(),
        iface: Some("eth0".to_string()),
        cpus: 8,
        active_rings: rings.to_vec(),
        skipped: vec!["BBR: tcp_bbr is not loaded".to_string()],
        on_change: false,
        observation_window: None,
        owners: None,
    }
}

/// The screen as lines of text, and where the frame put the clickable parts
pub fn screen(
    width: u16,
    height: u16,
    model: &Model,
    context: &RunContext,
    ui: &UiState,
    flows: &Flows,
) -> (Vec<String>, Areas) {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    let mut areas = Areas::default();
    terminal
        .draw(|frame| areas = render(frame, model, context, ui, flows))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let lines = (0..height)
        .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect())
        .collect();
    (lines, areas)
}

pub fn contains(lines: &[String], text: &str) -> bool {
    lines.iter().any(|line| line.contains(text))
}

/// The words of the first left column line that starts with `name`, inside the borders of
/// its block: the values of a health or group table row, whatever their padding
pub fn row(lines: &[String], name: &str) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            let inside = line
                .split(['\u{2502}', '\u{250c}', '\u{2514}'])
                .find(|part| !part.trim().is_empty());
            inside
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .find(|words| words.first().is_some_and(|word| word == name))
        .unwrap_or_else(|| panic!("no row {name}"))
}

/// The flow 10.0.0.1:5201 - 10.0.0.2:`port`
pub fn flow(port: u16) -> Flow {
    Flow {
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        sport: 5201,
        dport: port,
    }
}

/// `count` flows with ports from 1
pub fn many_flows(count: u16) -> Flows {
    let mut flows = Flows::default();
    for port in 1..=count {
        flows.add(flow(port));
    }
    flows
}

pub fn ep(text: &str) -> Endpoint {
    let addr: std::net::SocketAddr = text.parse().unwrap();
    (addr.ip(), addr.port())
}

/// An owner record of `local` -> `remote`
pub fn record(local: Endpoint, remote: Endpoint, comm: &str, pid: u32, kind: u32) -> Vec<u8> {
    // SAFETY: flow_owner_entry is plain old data, all zeros is a valid value
    let mut rec: flow_owner_entry = unsafe { mem::zeroed() };
    match (local.0, remote.0) {
        (IpAddr::V4(l), IpAddr::V4(r)) => {
            rec.family = AF_INET;
            rec.addr_v4 = ((u32::from_le_bytes(l.octets()) as u64) << 32)
                | u32::from_le_bytes(r.octets()) as u64;
        }
        (l, r) => {
            rec.family = AF_INET6;
            let v6 = |ip: IpAddr| match ip {
                IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                IpAddr::V6(ip) => ip.octets(),
            };
            rec.src_v6 = v6(l);
            rec.dst_v6 = v6(r);
        }
    }
    rec.sport = local.1;
    rec.dport = remote.1;
    rec.kind = kind as u8;
    rec.pid = pid;
    rec.comm[..comm.len()].copy_from_slice(comm.as_bytes());
    // SAFETY: rec is a plain old data struct that lives for the whole borrow
    unsafe {
        std::slice::from_raw_parts(
            &rec as *const flow_owner_entry as *const u8,
            mem::size_of::<flow_owner_entry>(),
        )
    }
    .to_vec()
}
