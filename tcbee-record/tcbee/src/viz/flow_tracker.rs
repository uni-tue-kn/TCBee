use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libbpf_rs::{MapCore, MapFlags, MapHandle};
use log::warn;
use ratatui::{
    layout::Constraint,
    style::{Modifier, Style},
    widgets::{Cell, Row, Table},
};
use tcbee_common::records::IpTuple;

/// A flow as the FLOWS map keys it: the endpoints in canonical order, not by direction
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
}

/// The flows in the order they were first seen. Rows keep their place, so the table does
/// not jump while flows come in.
#[derive(Default)]
pub struct Flows {
    list: Vec<Flow>,
    index: HashMap<Flow, usize>,
    /// The FLOWS map is full, newer flows are missing
    pub full: bool,
}

impl Flows {
    /// Appends `flow` if it is new
    pub fn add(&mut self, flow: Flow) {
        if !self.index.contains_key(&flow) {
            self.index.insert(flow.clone(), self.list.len());
            self.list.push(flow);
        }
    }

    pub fn list(&self) -> &[Flow] {
        &self.list
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }
}

pub struct FlowTracker {
    map: MapHandle,
    pub flows: Flows,
}

fn shorten_to_ipv4(arg: [u8; 16]) -> [u8; 4] {
    std::array::from_fn(|i| arg[i])
}

impl FlowTracker {
    pub fn new(map: MapHandle) -> FlowTracker {
        FlowTracker {
            map,
            flows: Flows::default(),
        }
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
        self.flows.full = keys.len() >= self.map.max_entries() as usize;
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

                let (src, dst) = if ipv4_mapped {
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
                    (src, dst)
                } else if ipv4_compat {
                    let src = IpAddr::V4(Ipv4Addr::from(shorten_to_ipv4(tuple.src_ip)));
                    let dst = IpAddr::V4(Ipv4Addr::from(shorten_to_ipv4(tuple.dst_ip)));
                    (src, dst)
                } else {
                    let src = IpAddr::V6(Ipv6Addr::from(tuple.src_ip));
                    let dst = IpAddr::V6(Ipv6Addr::from(tuple.dst_ip));
                    (src, dst)
                };

                let flow = Flow {
                    src,
                    dst,
                    sport: tuple.sport,
                    dport: tuple.dport,
                };

                self.flows.add(flow);
            }
        }
    }
}

/// Widths of the flow table columns: room for any IPv6 address and port
pub const FLOW_COLUMNS: [Constraint; 4] = [
    Constraint::Length(39),
    Constraint::Length(10),
    Constraint::Length(39),
    Constraint::Length(10),
];

/// The table of the flows, the selected row highlighted
pub fn flow_table(flows: &[Flow]) -> Table<'_> {
    let header = ["Endpoint A", "port", "Endpoint B", "port"]
        .into_iter()
        .map(Cell::from)
        .collect::<Row>()
        .style(Style::new().add_modifier(Modifier::BOLD));
    let rows = flows.iter().map(|flow| {
        Row::new([
            flow.src.to_string(),
            flow.sport.to_string(),
            flow.dst.to_string(),
            flow.dport.to_string(),
        ])
    });
    Table::new(rows, FLOW_COLUMNS)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn flow(port: u16) -> Flow {
        Flow {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            sport: 5201,
            dport: port,
        }
    }

    #[test]
    fn flows_keep_the_order_they_came_in() {
        let mut flows = Flows::default();
        for port in [3, 1, 2, 1, 3, 4] {
            flows.add(flow(port));
        }
        let ports: Vec<u16> = flows.list().iter().map(|f| f.dport).collect();
        assert_eq!(ports, [3, 1, 2, 4]);
    }
}
