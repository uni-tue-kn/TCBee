use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use aya::maps::PerCpuHashMap;

use log::warn;
use ratatui::{
    layout::Constraint,
    style::{Color, Style, Stylize},
    widgets::{Cell, Row, ScrollbarState, Table},
};
use tcbee_common::bindings::flow::IpTuple;

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Flow {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}
pub struct FlowTracker {
    map: PerCpuHashMap<aya::maps::MapData, IpTuple, IpTuple>,
    // TODO: other metrics to track in hash map?
    flows: HashMap<Flow, bool>,
    pub num_flows: usize,
}

impl FlowTracker {
    pub fn new(map: PerCpuHashMap<aya::maps::MapData, IpTuple, IpTuple>) -> FlowTracker {
        let flows: HashMap<Flow, bool> = HashMap::new();
        let scrollbar_state = ScrollbarState::new(0);
        FlowTracker {
            map,
            flows,
            num_flows: 0,
        }
    }

    fn shorten_to_ipv4(arg: [u8; 16]) -> [u8; 4] {
        std::array::from_fn(|i| arg[i])
    }

    pub fn update_scrollbar_state(&self, state: ScrollbarState) -> ScrollbarState {
        state.content_length(self.num_flows)
    }

    pub fn get_flows(&mut self) -> Table<'_> {
        let header = ["Source", "Source Port", "Destination", "Destination Port"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .height(1)
            .style(Style::new().bold());

        let rows = self.flows.iter().enumerate().map(|(i, (flow, is_ipv6))| {
            let color = match i % 2 {
                0 => Color::Reset,
                _ => Color::DarkGray,
            };

            let src = flow.src.to_string();
            let dst = flow.dst.to_string();
            let sport = flow.sport.to_string();
            let dport = flow.dport.to_string();

            [src, sport, dst, dport]
                .into_iter()
                .collect::<Row>()
                .height(1)
                .style(Style::new().bg(color))
        });

        // Update number of entries that can be scrolled
        self.num_flows = rows.len();

        let tab = Table::new(
            rows,
            [
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(33),
            ],
        )
        .header(header);

        tab
    }

    pub fn read_flows(&mut self) {
        let mut i: u16 = 1;

        for entry in self.map.iter() {
            if let Ok((_t, v)) = entry {
                for tuple in v.iter() {
                    let ipv4_mapped = tuple.src_ip[0..10].iter().all(|&b| b == 0)
                        && tuple.src_ip[10] == 0xFF
                        && tuple.src_ip[11] == 0xFF;
                    let ipv4_compat = tuple.src_ip[4..16].iter().all(|&b| b == 0);

                    let (src, dst, is_ipv6) = if ipv4_mapped {
                        let src = IpAddr::V4(Ipv4Addr::from([
                            tuple.src_ip[12], tuple.src_ip[13],
                            tuple.src_ip[14], tuple.src_ip[15],
                        ]));
                        let dst = IpAddr::V4(Ipv4Addr::from([
                            tuple.dst_ip[12], tuple.dst_ip[13],
                            tuple.dst_ip[14], tuple.dst_ip[15],
                        ]));
                        (src, dst, false)
                    } else if ipv4_compat {
                        let src = IpAddr::V4(Ipv4Addr::from(FlowTracker::shorten_to_ipv4(tuple.src_ip)));
                        let dst = IpAddr::V4(Ipv4Addr::from(FlowTracker::shorten_to_ipv4(tuple.dst_ip)));
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
            } else {
                warn!("Could not read flows for CPU id {} in eBPF watcher!", i);
            }
            i += 1;
        }
    }
}
