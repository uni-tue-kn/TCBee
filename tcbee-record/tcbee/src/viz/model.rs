//! What the watcher shows, computed once per tick from a counter snapshot

use std::time::Duration;

use ratatui::style::Color;
use tcbee_common::stats::{
    invocation_slots, packet_rings, slot, RB_BAD_CSUM, RB_BBR, RB_COUNT, RB_CUBIC, RB_CWND_RECV,
    RB_CWND_SEND, RB_RETRANSMIT_SYNACK, RB_SOCK_INGRESS, RB_SOCK_RECV, RB_SOCK_SEND, RB_SOCK_TIMER,
    RB_TCP4_DRIVER_INGRESS, RB_TCP4_INGRESS, RB_TCP_PROBE, STAT_DROPPED, STAT_HANDLED,
};

use crate::{
    stats::Snapshot,
    viz::{components::graph::Graph, format},
};

/// Graphs in the order of their ids
pub const GRAPH_EVENTS: usize = 0;
pub const GRAPH_PACKETS: usize = 1;
pub const GRAPH_CALLS: usize = 2;
pub const GRAPH_CUBIC: usize = 3;
pub const GRAPH_BBR: usize = 4;
pub const GRAPH_TRACEPOINTS: usize = 5;

/// Counter slots whose sums the watcher shows as rates
struct Slots {
    handled: Vec<u32>,
    dropped: Vec<u32>,
    ingress: Vec<u32>,
    egress: Vec<u32>,
    send: Vec<u32>,
    recv: Vec<u32>,
    cubic: Vec<u32>,
    bbr: Vec<u32>,
    tracepoints: Vec<u32>,
}

impl Slots {
    fn new(active_rings: &[u32]) -> Slots {
        let all = |stat: u32| (0..RB_COUNT).map(|rb| slot(rb, stat)).collect::<Vec<u32>>();
        let attempts = |rbs: &[u32]| {
            rbs.iter()
                .flat_map(|rb| invocation_slots(*rb))
                .collect::<Vec<u32>>()
        };
        // With both header hooks, the TC rates
        let driver_packets = !active_rings.contains(&RB_TCP4_INGRESS)
            && active_rings.contains(&RB_TCP4_DRIVER_INGRESS);
        let (ingress, egress) = packet_rings(driver_packets);
        Slots {
            handled: all(STAT_HANDLED),
            dropped: all(STAT_DROPPED),
            ingress: attempts(&ingress),
            egress: attempts(&egress),
            send: attempts(&[RB_SOCK_SEND, RB_CWND_SEND]),
            // The write timer and ingress runs counted with the receive side
            recv: attempts(&[RB_SOCK_RECV, RB_CWND_RECV, RB_SOCK_TIMER, RB_SOCK_INGRESS]),
            cubic: attempts(&[RB_CUBIC]),
            bbr: attempts(&[RB_BBR]),
            tracepoints: attempts(&[RB_TCP_PROBE, RB_RETRANSMIT_SYNACK, RB_BAD_CSUM]),
        }
    }
}

pub struct Model {
    /// Time since the watcher started, at the current snapshot
    pub elapsed: Duration,
    pub snapshot: Snapshot,
    /// The snapshot before and its time, None until the second tick
    previous: Option<(Snapshot, Duration)>,
    ticks: u64,
    /// Bytes the writers wrote so far
    pub bytes_written: u64,
    previous_bytes: u64,
    slots: Slots,
    /// Graph histories, indexed by `GRAPH_*`
    pub graphs: Vec<Graph>,
}

impl Model {
    pub fn new(active_rings: &[u32], observation_window: Option<f64>) -> Model {
        let window = observation_window;
        let graphs = vec![
            Graph::new(
                "Handled".to_string(),
                "Dropped".to_string(),
                Color::Green,
                Color::Red,
                window,
                "Events".to_string(),
            ),
            Graph::new(
                "Ingress".to_string(),
                "Egress".to_string(),
                Color::Green,
                Color::Cyan,
                window,
                "Packet Rates".to_string(),
            ),
            Graph::new(
                "tcp_recvmsg".to_string(),
                "tcp_sendmsg".to_string(),
                Color::Red,
                Color::Blue,
                window,
                "Function Calls".to_string(),
            ),
            Graph::new_single(
                "Cubic".to_string(),
                Color::Yellow,
                window,
                "Cubic Events".to_string(),
            ),
            Graph::new_single(
                "BBR".to_string(),
                Color::Magenta,
                window,
                "BBR Events".to_string(),
            ),
            Graph::new_single(
                "Tracepoints".to_string(),
                Color::Reset,
                window,
                "Tracepoint Events".to_string(),
            ),
        ];
        Model {
            elapsed: Duration::ZERO,
            snapshot: Snapshot::default(),
            previous: None,
            ticks: 0,
            bytes_written: 0,
            previous_bytes: 0,
            slots: Slots::new(active_rings),
            graphs,
        }
    }

    /// Takes the counters of a tick. Rates compare them with the tick before.
    pub fn update(&mut self, snapshot: Snapshot, bytes_written: u64, elapsed: Duration) {
        let current = std::mem::replace(&mut self.snapshot, snapshot);
        if self.ticks > 0 {
            self.previous = Some((current, self.elapsed));
        }
        self.ticks += 1;
        self.previous_bytes = self.bytes_written;
        self.bytes_written = bytes_written;
        self.elapsed = elapsed;
    }

    /// Seconds between the previous and the current snapshot, None on the first tick
    fn interval(&self) -> Option<f64> {
        let (_, before) = self.previous.as_ref()?;
        let secs = self.elapsed.saturating_sub(*before).as_secs_f64();
        (secs > 0.0).then_some(secs)
    }

    /// Increase of the sum of `slots` per second since the previous tick
    fn rate(&self, slots: &[u32]) -> f64 {
        let (Some(secs), Some((previous, _))) = (self.interval(), self.previous.as_ref()) else {
            return 0.0;
        };
        self.snapshot.sum(slots).wrapping_sub(previous.sum(slots)) as f64 / secs
    }

    pub fn handled_rate(&self) -> f64 {
        self.rate(&self.slots.handled)
    }

    pub fn dropped_rate(&self) -> f64 {
        self.rate(&self.slots.dropped)
    }

    pub fn ingress_rate(&self) -> f64 {
        self.rate(&self.slots.ingress)
    }

    pub fn egress_rate(&self) -> f64 {
        self.rate(&self.slots.egress)
    }

    /// Bytes written per second since the previous tick
    pub fn disk_rate(&self) -> f64 {
        self.interval().map_or(0.0, |secs| {
            self.bytes_written.saturating_sub(self.previous_bytes) as f64 / secs
        })
    }

    /// Adds the current rates to the graphs
    pub fn record_history(&mut self) {
        let x = self.elapsed.as_secs_f64();
        let values = [
            (GRAPH_EVENTS, 0, self.handled_rate()),
            (GRAPH_EVENTS, 1, self.dropped_rate()),
            (GRAPH_PACKETS, 0, self.ingress_rate()),
            (GRAPH_PACKETS, 1, self.egress_rate()),
            (GRAPH_CALLS, 0, self.rate(&self.slots.recv)),
            (GRAPH_CALLS, 1, self.rate(&self.slots.send)),
            (GRAPH_CUBIC, 0, self.rate(&self.slots.cubic)),
            (GRAPH_BBR, 0, self.rate(&self.slots.bbr)),
            (GRAPH_TRACEPOINTS, 0, self.rate(&self.slots.tracepoints)),
        ];
        for (graph, series, y) in values {
            self.graphs[graph].add_val(series, (x, y));
        }
    }

    /// The status line of -q, overwriting the line before
    pub fn quiet_line(&self) -> String {
        let elapsed = self.elapsed;
        format!(
            // \r returns cursor to beginning of line, effectively overwriting the last line
            "\r| {}s {}ms time elapsed | {} handled | {} dropped | {} events/s | {} drops/s | {} ingress packets/s | {} egress packets/s | ",
            elapsed.as_secs(),
            elapsed.subsec_millis(),
            self.snapshot.handled(),
            self.snapshot.dropped(),
            format::quiet_rate(self.handled_rate(), "Events/s"),
            format::quiet_rate(self.dropped_rate(), "Events/s"),
            format::quiet_rate(self.ingress_rate(), "pps"),
            format::quiet_rate(self.egress_rate(), "pps"),
        )
    }
}
