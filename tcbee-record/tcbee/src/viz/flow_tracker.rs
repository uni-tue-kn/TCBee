use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libbpf_rs::{MapCore, MapFlags, MapHandle};
use log::warn;
use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style, Stylize},
    widgets::{Cell, Row, Table},
};
use tcbee_common::records::IpTuple;

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
}
pub struct FlowTracker {
    map: MapHandle,
    // TODO: other metrics to track in hash map?
    flows: HashMap<Flow, bool>,
}

impl FlowTracker {
    pub fn new(map: MapHandle) -> FlowTracker {
        let flows: HashMap<Flow, bool> = HashMap::new();
        FlowTracker { map, flows }
    }

    fn shorten_to_ipv4(arg: [u8; 16]) -> [u8; 4] {
        std::array::from_fn(|i| arg[i])
    }

    /// The flows seen so far
    pub fn flows(&self) -> Vec<Flow> {
        self.flows.keys().cloned().collect()
    }

    /// Values of one FLOWS entry on all CPUs
    fn lookup(&self, key: &[u8]) -> libbpf_rs::Result<Vec<IpTuple>> {
        let values = self.map.lookup_percpu(key, MapFlags::ANY)?;
        Ok(values
            .unwrap_or_default()
            .iter()
            .filter(|value| value.len() >= std::mem::size_of::<IpTuple>())
            .map(|value| unsafe { std::ptr::read_unaligned(value.as_ptr() as *const IpTuple) })
            .collect())
    }

    pub fn read_flows(&mut self) {
        let keys: Vec<Vec<u8>> = self.map.keys().collect();
        for key in keys {
            let tuples = match self.lookup(&key) {
                Ok(tuples) => tuples,
                Err(err) => {
                    warn!("Could not read flows in eBPF watcher: {}", err);
                    continue;
                }
            };
            // CPUs that never saw the flow hold an all-zero value
            for tuple in tuples.iter().filter(|t| **t != IpTuple::default()) {
                let ipv4_mapped = tuple.src_ip[0..10].iter().all(|&b| b == 0)
                    && tuple.src_ip[10] == 0xFF
                    && tuple.src_ip[11] == 0xFF;
                let ipv4_compat = tuple.src_ip[4..16].iter().all(|&b| b == 0);

                let (src, dst, is_ipv6) = if ipv4_mapped {
                    let src = IpAddr::V4(Ipv4Addr::from([
                        tuple.src_ip[12],
                        tuple.src_ip[13],
                        tuple.src_ip[14],
                        tuple.src_ip[15],
                    ]));
                    let dst = IpAddr::V4(Ipv4Addr::from([
                        tuple.dst_ip[12],
                        tuple.dst_ip[13],
                        tuple.dst_ip[14],
                        tuple.dst_ip[15],
                    ]));
                    (src, dst, false)
                } else if ipv4_compat {
                    let src =
                        IpAddr::V4(Ipv4Addr::from(FlowTracker::shorten_to_ipv4(tuple.src_ip)));
                    let dst =
                        IpAddr::V4(Ipv4Addr::from(FlowTracker::shorten_to_ipv4(tuple.dst_ip)));
                    (src, dst, false)
                } else {
                    let src = IpAddr::V6(Ipv6Addr::from(tuple.src_ip));
                    let dst = IpAddr::V6(Ipv6Addr::from(tuple.dst_ip));
                    (src, dst, true)
                };

                let flow = Flow {
                    src,
                    dst,
                    sport: tuple.sport,
                    dport: tuple.dport,
                };

                self.flows.insert(flow, is_ipv6);
            }
        }
    }
}

/// The table of the flows
pub fn flow_table(flows: &[Flow]) -> Table<'static> {
    let header = [
        "#",
        "Source",
        "Source Port",
        "Destination",
        "Destination Port",
    ]
    .into_iter()
    .map(Cell::from)
    .collect::<Row>()
    .height(1)
    .style(Style::new().fg(Color::Reset).bold());

    let rows = flows.iter().enumerate().map(|(i, flow)| {
        let src = flow.src.to_string();
        let dst = flow.dst.to_string();
        let sport = flow.sport.to_string();
        let dport = flow.dport.to_string();

        let style = if i % 2 == 0 {
            Style::new().fg(Color::Reset)
        } else {
            Style::new().fg(Color::Reset).add_modifier(Modifier::DIM)
        };

        [(i + 1).to_string(), src, sport, dst, dport]
            .into_iter()
            .collect::<Row>()
            .height(1)
            .style(style)
    });

    Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Percentage(32),
            Constraint::Length(13),
            Constraint::Percentage(32),
            Constraint::Length(18),
        ],
    )
    .header(header)
    .column_spacing(1)
    .style(Style::new().fg(Color::Reset))
}
