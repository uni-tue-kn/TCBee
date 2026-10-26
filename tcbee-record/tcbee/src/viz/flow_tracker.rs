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

    /// Looks up the owners of the flows: a record names the owner, and a newer one for the
    /// same tuple (a reused port pair) replaces it; the snapshot names those without a record
    pub fn find_owners(&mut self, live: &OwnerTable, snapshot: Option<&SnapshotOwners>) {
        for (flow, owner) in self.list.iter().zip(self.owners.iter_mut()) {
            let (a, b) = ((flow.src, flow.sport), (flow.dst, flow.dport));
            match live.find(a, b) {
                Some(found) if owner.as_ref() != Some(found) => *owner = Some(found.clone()),
                Some(_) => {}
                None if owner.is_none() => {
                    *owner = snapshot.and_then(|s| s.find(a, b)).cloned();
                }
                None => {}
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
                self.flows.add(flow_of(tuple));
            }
        }
    }
}

/// Headers of the flow table columns
const HEADERS: [&str; 5] = ["Local/A", "port", "Remote/B", "port", "Process"];
/// Widest address column, a full IPv6 address
const MAX_ADDRESS: usize = 39;
/// Narrowest address column the process takes room from
const MIN_ADDRESS: usize = 8;
/// Port columns: a port, and the service mark on the local one
const MIN_PORT: usize = 5;
const MAX_PORT: usize = 9;
/// Narrowest process column the addresses give room to
const MIN_PROCESS: usize = 8;
/// Widest gap after an endpoint, so that a wide table keeps a row readable
const MAX_GAP: usize = 16;

/// The cells of a flow row and whether its owner is known
fn cells(flow: &Flow, owner: Option<&Owner>) -> ([String; 5], bool) {
    match owner {
        Some(owner) => {
            let mut local_port = owner.local.1.to_string();
            if owner.service {
                local_port.push_str(" svc");
            }
            let cells = [
                owner.local.0.to_string(),
                local_port,
                owner.remote.0.to_string(),
                owner.remote.1.to_string(),
                owner.process.clone(),
            ];
            (cells, true)
        }
        None => {
            let cells = [
                flow.src.to_string(),
                flow.sport.to_string(),
                flow.dst.to_string(),
                flow.dport.to_string(),
                "?".to_string(),
            ];
            (cells, false)
        }
    }
}

/// Widths of the flow table columns for `rows` in `width` cells: each as wide as its cells,
/// an address up to a full IPv6 address, a port 5 to 9 cells. The spare room is split evenly
/// into a gap after each endpoint, at most 16 cells, and the process; the process gets the
/// rest. A narrow table shortens the longer address first, down to 8 cells, for a process of 8.
pub fn flow_columns(rows: &[[String; 5]], width: u16) -> [Constraint; 5] {
    let content = |column: usize| {
        rows.iter()
            .map(|cells| cells[column].chars().count())
            .chain([HEADERS[column].len()])
            .max()
            .unwrap_or_default()
    };
    let mut local = content(0).min(MAX_ADDRESS);
    let mut remote = content(2).min(MAX_ADDRESS);
    let local_port = content(1).clamp(MIN_PORT, MAX_PORT);
    let remote_port = content(3).clamp(MIN_PORT, MAX_PORT);
    // Four spaces between the columns
    let room = (width as usize).saturating_sub(local_port + remote_port + 4);
    while local + remote + MIN_PROCESS > room && local.max(remote) > MIN_ADDRESS {
        if local >= remote {
            local -= 1;
        } else {
            remote -= 1;
        }
    }
    // A port column ends in the gap after its endpoint
    let spare = room.saturating_sub(local + remote + content(4).max(MIN_PROCESS));
    let gap = (spare / 3).min(MAX_GAP);
    let process = room.saturating_sub(local + remote + 2 * gap);
    [local, local_port + gap, remote, remote_port + gap, process]
        .map(|width| Constraint::Length(width as u16))
}

/// The table of the flows in `width` cells, the selected row highlighted. A flow with a known
/// owner shows its local side first and the process last. One without is dimmed with "?" as
/// process; its sides are endpoints A and B in the map's address order, so neither is known to
/// be local, which the headers say.
pub fn flow_table(flows: &Flows, width: u16) -> Table<'_> {
    let header = HEADERS
        .into_iter()
        .map(Cell::from)
        .collect::<Row>()
        .style(Style::new().add_modifier(Modifier::BOLD));
    let (cells, known): (Vec<_>, Vec<_>) = flows
        .list
        .iter()
        .zip(&flows.owners)
        .map(|(flow, owner)| cells(flow, owner.as_ref()))
        .unzip();
    let widths = flow_columns(&cells, width);
    let rows = cells.into_iter().zip(known).map(|(cells, known)| {
        let row = Row::new(cells);
        match known {
            true => row,
            false => row.style(Style::new().add_modifier(Modifier::DIM)),
        }
    });
    Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
}

/// The flow of a FLOWS map tuple. The map holds IPv4 addresses in the first 4 bytes and has no
/// address family, so a tuple whose both addresses end in 12 zero bytes is read as IPv4.
fn flow_of(tuple: &IpTuple) -> Flow {
    let ipv4_mapped = tuple.src_ip[0..10].iter().all(|&b| b == 0)
        && tuple.src_ip[10] == 0xFF
        && tuple.src_ip[11] == 0xFF;
    let ipv4_compat = [tuple.src_ip, tuple.dst_ip]
        .iter()
        .all(|ip| ip[4..16].iter().all(|&b| b == 0));

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

    Flow {
        src,
        dst,
        sport: tuple.sport,
        dport: tuple.dport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4, v4-mapped and IPv6 tuples of the FLOWS map; an IPv6 address that ends in zero
    /// bytes next to an IPv4 one stays IPv6
    #[test]
    fn flows_of_map_tuples() {
        let tuple = |src: [u8; 16], dst: [u8; 16]| IpTuple {
            src_ip: src,
            dst_ip: dst,
            sport: 1,
            dport: 2,
            ..Default::default()
        };
        let v4 = |a: [u8; 4]| {
            let mut ip = [0u8; 16];
            ip[..4].copy_from_slice(&a);
            ip
        };
        let mapped = |a: Ipv4Addr| a.to_ipv6_mapped().octets();
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap().octets();
        let addrs = |f: Flow| (f.src.to_string(), f.dst.to_string());

        let f = flow_of(&tuple(v4([10, 0, 0, 1]), v4([10, 0, 0, 2])));
        assert_eq!(addrs(f), ("10.0.0.1".into(), "10.0.0.2".into()));
        let f = flow_of(&tuple(
            mapped(Ipv4Addr::new(10, 0, 0, 1)),
            mapped(Ipv4Addr::new(10, 0, 0, 2)),
        ));
        assert_eq!(addrs(f), ("10.0.0.1".into(), "10.0.0.2".into()));
        let f = flow_of(&tuple(v6("2001:db8::"), v6("2001:db8::7")));
        assert_eq!(addrs(f), ("2001:db8::".into(), "2001:db8::7".into()));
        let f = flow_of(&tuple(v6("fe80::1"), v6("fe80::2")));
        assert_eq!(addrs(f), ("fe80::1".into(), "fe80::2".into()));
    }
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
    fn a_newer_record_replaces_the_owner_of_a_flow() {
        let mut flows = Flows::default();
        flows.add(flow(40000));
        let mut table = OwnerTable::default();
        let owner = |process: &str| Owner {
            local: ep("10.0.0.2:40000"),
            remote: ep("10.0.0.1:5201"),
            process: process.to_string(),
            service: false,
        };
        table.insert(owner("iperf3[812]"));
        flows.find_owners(&table, None);
        // The port pair is reused by another process
        table.insert(owner("curl[900]"));
        flows.find_owners(&table, None);
        assert_eq!(flows.owners[0].as_ref().unwrap().process, "curl[900]");
        // Pushed out of the table, the flow keeps the owner it had
        flows.find_owners(&OwnerTable::default(), None);
        assert_eq!(flows.owners[0].as_ref().unwrap().process, "curl[900]");
    }

    #[test]
    fn columns_fit_the_content_and_share_the_spare_room() {
        let row = |local: &str, port: &str, remote: &str| {
            [local, port, remote, "5201", "iperf3[812]"].map(str::to_string)
        };
        let lengths = |widths: [Constraint; 5]| {
            widths.map(|width| match width {
                Constraint::Length(length) => length,
                _ => panic!("{width:?}"),
            })
        };
        let v4 = [row("10.0.0.2", "40000", "10.0.0.1")];
        assert_eq!(lengths(flow_columns(&v4, 100)), [8, 21, 8, 21, 38]);
        // A third of the spare room after each endpoint, up to 16 cells
        assert_eq!(lengths(flow_columns(&v4, 60)), [8, 11, 8, 11, 18]);
        // The headers are wider than a short address, a service mark widens the port
        let short = [row("::1", "22 svc", "::1")];
        assert_eq!(lengths(flow_columns(&short, 60)), [7, 12, 8, 11, 18]);
        // A full IPv6 address fits, a longer one is cut
        let v6 = "2001:db8:85a3:8d3:1319:8a2e:370:7348";
        let long = [row(v6, "40000", &"f".repeat(50))];
        assert_eq!(lengths(flow_columns(&long, 200)), [36, 21, 39, 21, 79]);
        // A narrow table has no gaps and shortens the longer address first, the process keeps 8
        assert_eq!(lengths(flow_columns(&long, 80)), [29, 5, 29, 5, 8]);
        assert_eq!(lengths(flow_columns(&long, 30)), [8, 5, 8, 5, 0]);
        assert_eq!(lengths(flow_columns(&[], 50)), [7, 9, 8, 9, 13]);
    }
}
