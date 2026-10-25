//! How the watcher groups the ring buffers: one probe group per chart or table row

use ratatui::style::Color;
use tcbee_common::stats::{
    RB_BAD_CSUM, RB_BBR, RB_CUBIC, RB_CWND_RECV, RB_CWND_SEND, RB_MPTCP_PM, RB_RENO,
    RB_RETRANSMIT_SYNACK, RB_SOCK_EVENT, RB_SOCK_INGRESS, RB_SOCK_RECV, RB_SOCK_SEND,
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
}

impl Group {
    /// In the order their charts get a slot
    pub const ALL: [Group; 6] = [
        Group::Headers,
        Group::Sock,
        Group::Cc,
        Group::Tracepoints,
        Group::TcpEvents,
        Group::Mptcp,
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
        }
    }

    /// Unit of the runs of its hooks
    pub fn unit(self) -> &'static str {
        match self {
            Group::Headers => "pps",
            _ => "runs/s",
        }
    }

    /// The series of its chart, at most four. A series sums the runs of its rings.
    pub fn series(self) -> &'static [Series] {
        match self {
            Group::Headers => &[
                Series {
                    label: "in",
                    rings: &[RB_TCP4_INGRESS, RB_TCP6_INGRESS],
                },
                Series {
                    label: "out",
                    rings: &[RB_TCP4_EGRESS, RB_TCP6_EGRESS],
                },
                Series {
                    label: "drv in",
                    rings: &[RB_TCP4_DRIVER_INGRESS, RB_TCP6_DRIVER_INGRESS],
                },
                Series {
                    label: "drv out",
                    rings: &[RB_TCP4_DRIVER_EGRESS, RB_TCP6_DRIVER_EGRESS],
                },
            ],
            Group::Sock => &[
                Series {
                    label: "send",
                    rings: &[RB_SOCK_SEND, RB_CWND_SEND],
                },
                Series {
                    label: "recv",
                    rings: &[RB_SOCK_RECV, RB_CWND_RECV],
                },
                Series {
                    label: "ingress",
                    rings: &[RB_SOCK_INGRESS],
                },
                Series {
                    label: "timer+ev",
                    rings: &[RB_SOCK_TIMER, RB_SOCK_EVENT],
                },
            ],
            Group::Cc => &[
                Series {
                    label: "cubic",
                    rings: &[RB_CUBIC],
                },
                Series {
                    label: "bbr",
                    rings: &[RB_BBR],
                },
                Series {
                    label: "reno",
                    rings: &[RB_RENO],
                },
            ],
            Group::Tracepoints => &[
                Series {
                    label: "tcp_probe",
                    rings: &[RB_TCP_PROBE],
                },
                Series {
                    label: "synack",
                    rings: &[RB_RETRANSMIT_SYNACK],
                },
                Series {
                    label: "bad_csum",
                    rings: &[RB_BAD_CSUM],
                },
            ],
            Group::TcpEvents => &[Series {
                label: "events",
                rings: &[RB_TCP_EVENTS],
            }],
            Group::Mptcp => &[Series {
                label: "pm",
                rings: &[RB_MPTCP_PM],
            }],
        }
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
    pub rings: &'static [u32],
}

/// The groups of `active_rings` that get a chart besides the events, by priority
pub fn chart_groups(active_rings: &[u32], slots: usize) -> Vec<Group> {
    Group::ALL
        .into_iter()
        .filter(|group| active_rings.iter().any(|rb| display_group(*rb) == *group))
        .take(slots)
        .collect()
}

/// The probe group the watcher shows ring buffer `rb` in
pub fn display_group(rb: u32) -> Group {
    match rb {
        RB_TCP4_EGRESS | RB_TCP4_INGRESS | RB_TCP6_EGRESS | RB_TCP6_INGRESS => Group::Headers,
        RB_TCP4_DRIVER_INGRESS
        | RB_TCP6_DRIVER_INGRESS
        | RB_TCP4_DRIVER_EGRESS
        | RB_TCP6_DRIVER_EGRESS => Group::Headers,
        RB_SOCK_SEND | RB_SOCK_RECV | RB_SOCK_TIMER | RB_SOCK_INGRESS | RB_SOCK_EVENT => {
            Group::Sock
        }
        RB_CWND_SEND | RB_CWND_RECV => Group::Sock,
        RB_CUBIC | RB_BBR | RB_RENO => Group::Cc,
        RB_TCP_PROBE | RB_RETRANSMIT_SYNACK | RB_BAD_CSUM => Group::Tracepoints,
        RB_TCP_EVENTS => Group::TcpEvents,
        RB_MPTCP_PM => Group::Mptcp,
        _ => panic!("ring buffer {rb} has no display group"),
    }
}

/// Short name of ring buffer `rb` in the expanded group table
pub fn ring_label(rb: u32) -> &'static str {
    match rb {
        RB_TCP4_INGRESS => "tc v4 in",
        RB_TCP4_EGRESS => "tc v4 out",
        RB_TCP6_INGRESS => "tc v6 in",
        RB_TCP6_EGRESS => "tc v6 out",
        RB_TCP4_DRIVER_INGRESS => "drv v4 in",
        RB_TCP4_DRIVER_EGRESS => "drv v4 out",
        RB_TCP6_DRIVER_INGRESS => "drv v6 in",
        RB_TCP6_DRIVER_EGRESS => "drv v6 out",
        RB_SOCK_SEND => "send",
        RB_SOCK_RECV => "recv",
        RB_SOCK_TIMER => "timer",
        RB_SOCK_INGRESS => "ingress",
        RB_SOCK_EVENT => "events",
        RB_CWND_SEND => "cwnd send",
        RB_CWND_RECV => "cwnd recv",
        RB_CUBIC => "cubic",
        RB_BBR => "bbr",
        RB_RENO => "reno",
        RB_TCP_PROBE => "tcp_probe",
        RB_RETRANSMIT_SYNACK => "synack",
        RB_BAD_CSUM => "bad_csum",
        RB_TCP_EVENTS => "tcp_events",
        RB_MPTCP_PM => "mptcp_pm",
        _ => panic!("ring buffer {rb} has no label"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use tcbee_common::stats::RB_COUNT;

    use super::*;

    #[test]
    fn every_ring_has_a_group_and_a_label() {
        let groups: HashSet<Group> = (0..RB_COUNT).map(display_group).collect();
        // And every group has a ring
        assert_eq!(groups.len(), 6);
        let labels: HashSet<&str> = (0..RB_COUNT).map(ring_label).collect();
        assert_eq!(labels.len(), RB_COUNT as usize, "two rings share a label");
    }

    #[test]
    fn every_ring_is_in_one_series_of_its_group() {
        for rb in 0..RB_COUNT {
            let group = display_group(rb);
            let series = group.series().iter().filter(|s| s.rings.contains(&rb));
            assert_eq!(series.count(), 1, "ring {rb}");
        }
        for group in Group::ALL {
            assert!(group.series().len() <= 4);
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
