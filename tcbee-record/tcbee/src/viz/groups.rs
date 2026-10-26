//! How the watcher groups the ring buffers: one probe group per chart or table row

use ratatui::style::Color;
use tcbee_common::stats::{
    RB_BAD_CSUM, RB_BBR, RB_COUNT, RB_CUBIC, RB_CWND_RECV, RB_CWND_SEND, RB_MPTCP_PM, RB_OWNERS,
    RB_RENO, RB_RETRANSMIT_SYNACK, RB_SOCK_EVENT, RB_SOCK_INGRESS, RB_SOCK_RECV, RB_SOCK_SEND,
    RB_SOCK_TIMER, RB_TCP4_DRIVER_EGRESS, RB_TCP4_DRIVER_INGRESS, RB_TCP4_EGRESS, RB_TCP4_INGRESS,
    RB_TCP6_DRIVER_EGRESS, RB_TCP6_DRIVER_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS, RB_TCP_EVENTS,
    RB_TCP_PROBE,
};

/// A probe group, in the order its chart gets a slot
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// Packet headers at TC or in the driver (-h)
    Headers,
    /// Socket and cwnd hooks (-k, -w)
    Sock,
    /// Congestion control internals: CUBIC, BBR and Reno (-a)
    Cc,
    /// The tracepoints of -t
    Tracepoints,
    /// The TCP event hooks of -t
    TcpEvents,
    /// MPTCP path manager events
    Mptcp,
    /// The processes that own sockets, at connect and accept
    Owners,
}

impl Group {
    /// In the order their charts get a slot
    pub const ALL: [Group; 7] = [
        Group::Headers,
        Group::Sock,
        Group::Cc,
        Group::Tracepoints,
        Group::TcpEvents,
        Group::Mptcp,
        Group::Owners,
    ];

    /// Name in the probe group table
    pub fn name(self) -> &'static str {
        match self {
            Group::Headers => "headers",
            Group::Sock => "sock",
            Group::Cc => "cc",
            Group::Tracepoints => "tracept",
            Group::TcpEvents => "tcp_ev",
            Group::Mptcp => "mptcp",
            Group::Owners => "owners",
        }
    }

    /// Chart title
    pub fn title(self) -> &'static str {
        match self {
            Group::Headers => "Headers",
            Group::Sock => "Socket hooks",
            Group::Cc => "CC internals",
            Group::Tracepoints => "Tracepoints",
            Group::TcpEvents => "TCP events",
            Group::Mptcp => "MPTCP PM",
            Group::Owners => "Flow owners",
        }
    }

    /// Unit of the runs of its hooks
    pub fn unit(self) -> &'static str {
        match self {
            Group::Headers => "pps",
            _ => "runs/s",
        }
    }

    /// Names of the lines of its chart, at most four, indexed by `Ring::series`
    pub fn series_labels(self) -> &'static [&'static str] {
        match self {
            Group::Headers => &["in", "out", "drv in", "drv out"],
            Group::Sock => &["send", "recv", "ingress", "timer+ev"],
            Group::Cc => &["cubic", "bbr", "reno"],
            Group::Tracepoints => &["tcp_probe", "synack", "bad_csum"],
            Group::TcpEvents => &["events"],
            Group::Mptcp => &["pm"],
            Group::Owners => &["owners"],
        }
    }

    /// The lines of its chart: each sums the runs of its rings
    pub fn series(self) -> Vec<Series> {
        self.series_labels()
            .iter()
            .enumerate()
            .map(|(index, label)| Series {
                label,
                rings: RINGS
                    .iter()
                    .filter(|ring| ring.group == self && ring.series == index)
                    .map(|ring| ring.rb)
                    .collect(),
            })
            .collect()
    }

    /// Colours of its series, in order
    pub fn palette(self) -> [Color; 4] {
        match self {
            Group::Headers => [
                Color::Green,
                Color::Cyan,
                Color::LightGreen,
                Color::LightCyan,
            ],
            Group::Sock => [Color::Blue, Color::Magenta, Color::LightBlue, Color::Yellow],
            Group::Cc => [Color::Yellow, Color::Magenta, Color::LightRed, Color::Reset],
            _ => [Color::Reset, Color::Yellow, Color::LightRed, Color::Cyan],
        }
    }
}

/// A line of a group's chart
pub struct Series {
    pub label: &'static str,
    pub rings: Vec<u32>,
}

/// What the TUI shows of a ring buffer
pub struct Ring {
    pub rb: u32,
    pub group: Group,
    /// Short name in the expanded group table
    pub label: &'static str,
    /// Its line in the group's chart, see `Group::series_labels`
    pub series: usize,
}

const fn ring(rb: u32, group: Group, label: &'static str, series: usize) -> Ring {
    Ring {
        rb,
        group,
        label,
        series,
    }
}

/// Every ring buffer, indexed by `RB_*`
pub const RINGS: [Ring; RB_COUNT as usize] = [
    ring(RB_TCP4_EGRESS, Group::Headers, "tc v4 out", 1),
    ring(RB_TCP4_INGRESS, Group::Headers, "tc v4 in", 0),
    ring(RB_TCP6_EGRESS, Group::Headers, "tc v6 out", 1),
    ring(RB_TCP6_INGRESS, Group::Headers, "tc v6 in", 0),
    ring(RB_SOCK_SEND, Group::Sock, "send", 0),
    ring(RB_SOCK_RECV, Group::Sock, "recv", 1),
    ring(RB_CWND_SEND, Group::Sock, "cwnd send", 0),
    ring(RB_CWND_RECV, Group::Sock, "cwnd recv", 1),
    ring(RB_TCP_PROBE, Group::Tracepoints, "tcp_probe", 0),
    ring(RB_RETRANSMIT_SYNACK, Group::Tracepoints, "synack", 1),
    ring(RB_BAD_CSUM, Group::Tracepoints, "bad_csum", 2),
    ring(RB_CUBIC, Group::Cc, "cubic", 0),
    ring(RB_BBR, Group::Cc, "bbr", 1),
    ring(RB_MPTCP_PM, Group::Mptcp, "mptcp_pm", 0),
    ring(RB_TCP_EVENTS, Group::TcpEvents, "tcp_events", 0),
    ring(RB_SOCK_TIMER, Group::Sock, "timer", 3),
    ring(RB_SOCK_INGRESS, Group::Sock, "ingress", 2),
    ring(RB_SOCK_EVENT, Group::Sock, "events", 3),
    ring(RB_RENO, Group::Cc, "reno", 2),
    ring(RB_TCP4_DRIVER_INGRESS, Group::Headers, "drv v4 in", 2),
    ring(RB_TCP6_DRIVER_INGRESS, Group::Headers, "drv v6 in", 2),
    ring(RB_TCP4_DRIVER_EGRESS, Group::Headers, "drv v4 out", 3),
    ring(RB_TCP6_DRIVER_EGRESS, Group::Headers, "drv v6 out", 3),
    ring(RB_OWNERS, Group::Owners, "owners", 0),
];

/// The groups of `active_rings` that get a chart besides the events, by priority
pub fn chart_groups(active_rings: &[u32], slots: usize) -> Vec<Group> {
    Group::ALL
        .into_iter()
        .filter(|group| {
            active_rings
                .iter()
                .any(|rb| display_group(*rb) == Some(*group))
        })
        .take(slots)
        .collect()
}

/// The probe group the watcher shows ring buffer `rb` in, None for an unknown ring
pub fn display_group(rb: u32) -> Option<Group> {
    RINGS.get(rb as usize).map(|ring| ring.group)
}

/// Short name of ring buffer `rb` in the expanded group table
pub fn ring_label(rb: u32) -> &'static str {
    RINGS.get(rb as usize).map_or("?", |ring| ring.label)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn rings_are_listed_by_id_once() {
        for (index, ring) in RINGS.iter().enumerate() {
            assert_eq!(ring.rb as usize, index, "{}", ring.label);
            assert!(
                ring.series < ring.group.series_labels().len(),
                "{}",
                ring.label
            );
        }
        let labels: HashSet<&str> = RINGS.iter().map(|ring| ring.label).collect();
        assert_eq!(labels.len(), RINGS.len(), "two rings share a label");
        assert_eq!(display_group(RB_COUNT), None);
        assert_eq!(ring_label(RB_COUNT), "?");
    }

    #[test]
    fn every_group_charts_all_its_rings_in_at_most_four_lines() {
        for group in Group::ALL {
            let series = group.series();
            assert!(series.len() <= 4);
            // Every line has a ring, every ring of the group a line
            assert!(series.iter().all(|s| !s.rings.is_empty()), "{group:?}");
            let charted: usize = series.iter().map(|s| s.rings.len()).sum();
            let rings = RINGS.iter().filter(|ring| ring.group == group).count();
            assert_eq!(charted, rings, "{group:?}");
        }
    }

    #[test]
    fn charts_go_to_the_first_groups() {
        let all: Vec<u32> = (0..RB_COUNT).collect();
        assert_eq!(
            chart_groups(&all, 3),
            [Group::Headers, Group::Sock, Group::Cc]
        );
        assert_eq!(
            chart_groups(&[RB_TCP_EVENTS, RB_CUBIC], 3),
            [Group::Cc, Group::TcpEvents]
        );
    }
}
