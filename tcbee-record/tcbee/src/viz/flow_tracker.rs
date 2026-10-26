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

use crate::viz::flow_owners::{Owner, OwnerTable, SnapshotOwners};

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
    /// The owner of each flow, once known
    owners: Vec<Option<Owner>>,
    /// The FLOWS map is full, newer flows are missing
    pub full: bool,
}

impl Flows {
    /// Appends `flow` if it is new
    pub fn add(&mut self, flow: Flow) {
        if !self.index.contains_key(&flow) {
            self.index.insert(flow.clone(), self.list.len());
            self.list.push(flow);
            self.owners.push(None);
        }
    }

    /// Looks up the owners of the flows that have none yet: in the records, then in the
    /// snapshot
    pub fn find_owners(&mut self, live: &OwnerTable, snapshot: Option<&SnapshotOwners>) {
        for (flow, owner) in self.list.iter().zip(self.owners.iter_mut()) {
            if owner.is_none() {
                let (a, b) = ((flow.src, flow.sport), (flow.dst, flow.dport));
                *owner = live
                    .find(a, b)
                    .or_else(|| snapshot.and_then(|s| s.find(a, b)))
                    .cloned();
            }
        }
    }

    #[cfg(test)]
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

/// Width of the process column
const PROCESS_WIDTH: u16 = 20;
/// Width of the port columns: a port and the service mark
const PORT_WIDTH: u16 = 9;

/// Widths of the flow table columns in `width` cells: the addresses share what the ports and
/// the process leave, up to a full IPv6 address. They depend on the width only, not on the
/// rows, so columns do not move while flows come in.
pub fn flow_columns(width: u16) -> [Constraint; 5] {
    // A narrow table drops the service mark and shortens the process
    let (port, process) = match width < 2 * 15 + 2 * PORT_WIDTH + PROCESS_WIDTH + 4 {
        true => (5, 12),
        false => (PORT_WIDTH, PROCESS_WIDTH),
    };
    let address = (width.saturating_sub(2 * port + process + 4) / 2).clamp(8, 39);
    [
        Constraint::Length(address),
        Constraint::Length(port),
        Constraint::Length(process),
        Constraint::Length(address),
        Constraint::Length(port),
    ]
}

/// The table of the flows in `width` cells, the selected row highlighted. A flow with a known
/// owner shows its local side first and the process; one without keeps the map's order, its
/// sides are just two endpoints.
pub fn flow_table(flows: &Flows, width: u16) -> Table<'_> {
    let header = ["Local", "port", "Process", "Remote", "port"]
        .into_iter()
        .map(Cell::from)
        .collect::<Row>()
        .style(Style::new().add_modifier(Modifier::BOLD));
    let rows = flows
        .list
        .iter()
        .zip(&flows.owners)
        .map(|(flow, owner)| match owner {
            Some(owner) => {
                let mut local_port = owner.local.1.to_string();
                if owner.service {
                    local_port.push_str(" svc");
                }
                Row::new([
                    owner.local.0.to_string(),
                    local_port,
                    owner.process.clone(),
                    owner.remote.0.to_string(),
                    owner.remote.1.to_string(),
                ])
            }
            None => Row::new([
                flow.src.to_string(),
                flow.sport.to_string(),
                "?".to_string(),
                flow.dst.to_string(),
                flow.dport.to_string(),
            ])
            .style(Style::new().add_modifier(Modifier::DIM)),
        });
    Table::new(rows, flow_columns(width))
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::viz::test_support::{ep, flow};

    #[test]
    fn flows_keep_the_order_they_came_in() {
        let mut flows = Flows::default();
        for port in [3, 1, 2, 1, 3, 4] {
            flows.add(flow(port));
        }
        let ports: Vec<u16> = flows.list().iter().map(|f| f.dport).collect();
        assert_eq!(ports, [3, 1, 2, 4]);
    }

    #[test]
    fn flows_take_the_owners_once_known() {
        let mut flows = Flows::default();
        flows.add(flow(40000));
        flows.add(flow(40001));
        let mut table = OwnerTable::default();
        flows.find_owners(&table, None);
        assert!(flows.owners.iter().all(Option::is_none));
        // The map orders 10.0.0.1 first, the owner has it as the remote side
        table.insert(Owner {
            local: ep("10.0.0.2:40001"),
            remote: ep("10.0.0.1:5201"),
            process: "iperf3[812]".to_string(),
            service: false,
        });
        flows.find_owners(&table, None);
        assert!(flows.owners[0].is_none());
        assert_eq!(
            flows.owners[1].as_ref().unwrap().local,
            ep("10.0.0.2:40001")
        );
    }

    #[test]
    fn columns_depend_on_the_width_only() {
        for width in (120..320).step_by(10) {
            assert_eq!(flow_columns(width)[1], Constraint::Length(PORT_WIDTH));
            assert_eq!(flow_columns(width)[2], Constraint::Length(PROCESS_WIDTH));
        }
        assert_eq!(flow_columns(200)[0], Constraint::Length(39));
        assert_eq!(flow_columns(72)[0], Constraint::Length(15));
        assert_eq!(flow_columns(46)[0], Constraint::Length(10));
        assert_eq!(flow_columns(46)[2], Constraint::Length(12));
    }
}
