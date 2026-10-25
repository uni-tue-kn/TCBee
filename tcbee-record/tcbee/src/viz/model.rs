//! What the watcher shows, computed once per tick from a counter snapshot

use std::time::Duration;

use ratatui::style::Color;
use tcbee_common::stats::{
    invocation_slots, packet_rings, slot, RB_COUNT, RB_TCP4_DRIVER_INGRESS, RB_TCP4_INGRESS,
    STAT_DROPPED, STAT_HANDLED,
};

use crate::{
    stats::Snapshot,
    viz::{
        format,
        groups::{chart_groups, Group},
        history::{History, HISTORY_POINTS},
    },
};

/// Charts of the grid, the events chart first
pub const CHARTS: usize = 4;

/// Slots of the runs of `rings`: handled, dropped, failed and suppressed
fn run_slots(rings: &[u32]) -> Vec<u32> {
    rings.iter().flat_map(|rb| invocation_slots(*rb)).collect()
}

/// Slots of one stat of every ring
fn all_slots(stat: u32) -> Vec<u32> {
    (0..RB_COUNT).map(|rb| slot(rb, stat)).collect()
}

/// A line of a chart: the rate of a sum of counter slots
pub struct ChartSeries {
    pub label: &'static str,
    pub color: Color,
    slots: Vec<u32>,
    pub history: History,
}

pub struct ChartModel {
    pub title: &'static str,
    pub unit: &'static str,
    pub series: Vec<ChartSeries>,
}

impl ChartModel {
    fn events(window: Option<f64>) -> ChartModel {
        let series = |label, color, stat| ChartSeries {
            label,
            color,
            slots: all_slots(stat),
            history: History::new(HISTORY_POINTS, window),
        };
        ChartModel {
            title: "Events",
            unit: "rec/s",
            series: vec![
                series("rec", Color::Green, STAT_HANDLED),
                series("drop", Color::Red, STAT_DROPPED),
            ],
        }
    }

    /// The chart of a group, with the series that have an active ring
    fn group(group: Group, active_rings: &[u32], window: Option<f64>) -> ChartModel {
        let series = group
            .series()
            .iter()
            .zip(group.palette())
            .filter_map(|(series, color)| {
                let rings: Vec<u32> = series
                    .rings
                    .iter()
                    .copied()
                    .filter(|rb| active_rings.contains(rb))
                    .collect();
                (!rings.is_empty()).then(|| ChartSeries {
                    label: series.label,
                    color,
                    slots: run_slots(&rings),
                    history: History::new(HISTORY_POINTS, window),
                })
            })
            .collect();
        ChartModel {
            title: group.title(),
            unit: group.unit(),
            series,
        }
    }

    /// Largest value in the histories, 0 when empty
    pub fn max(&self) -> f64 {
        self.series
            .iter()
            .map(|series| series.history.max())
            .fold(0.0, f64::max)
    }

    /// Time of the newest point
    pub fn end(&self) -> f64 {
        self.series
            .iter()
            .filter_map(|series| series.history.end())
            .fold(0.0, f64::max)
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
    handled: Vec<u32>,
    dropped: Vec<u32>,
    /// Runs of the header hooks of the -q line
    ingress: Vec<u32>,
    egress: Vec<u32>,
    /// The events chart and those of the first groups
    pub charts: Vec<ChartModel>,
    /// Dropped share of the events per tick, in hundredths of a percent
    pub drop_history: Vec<u64>,
}

impl Model {
    pub fn new(active_rings: &[u32], observation_window: Option<f64>) -> Model {
        let window = observation_window;
        let mut charts = vec![ChartModel::events(window)];
        for group in chart_groups(active_rings, CHARTS - 1) {
            charts.push(ChartModel::group(group, active_rings, window));
        }
        // With both header hooks, the TC rates
        let driver_packets = !active_rings.contains(&RB_TCP4_INGRESS)
            && active_rings.contains(&RB_TCP4_DRIVER_INGRESS);
        let (ingress, egress) = packet_rings(driver_packets);
        Model {
            elapsed: Duration::ZERO,
            snapshot: Snapshot::default(),
            previous: None,
            ticks: 0,
            bytes_written: 0,
            previous_bytes: 0,
            handled: all_slots(STAT_HANDLED),
            dropped: all_slots(STAT_DROPPED),
            ingress: run_slots(&ingress),
            egress: run_slots(&egress),
            charts,
            drop_history: Vec::new(),
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
        self.rate(&self.handled)
    }

    pub fn dropped_rate(&self) -> f64 {
        self.rate(&self.dropped)
    }

    pub fn ingress_rate(&self) -> f64 {
        self.rate(&self.ingress)
    }

    pub fn egress_rate(&self) -> f64 {
        self.rate(&self.egress)
    }

    /// Dropped share of the events since the previous tick in percent
    pub fn drop_percent(&self) -> f64 {
        percent(
            self.dropped_rate(),
            self.handled_rate() + self.dropped_rate(),
        )
    }

    /// Bytes written per second since the previous tick
    pub fn disk_rate(&self) -> f64 {
        self.interval().map_or(0.0, |secs| {
            self.bytes_written.saturating_sub(self.previous_bytes) as f64 / secs
        })
    }

    /// Adds the current rates to the chart histories
    pub fn record_history(&mut self) {
        let x = self.elapsed.as_secs_f64();
        for c in 0..self.charts.len() {
            for s in 0..self.charts[c].series.len() {
                let y = self.rate(&self.charts[c].series[s].slots);
                self.charts[c].series[s].history.push(x, y);
            }
        }
        if self.drop_history.len() == HISTORY_POINTS {
            self.drop_history.remove(0);
        }
        self.drop_history
            .push((self.drop_percent() * 100.0).round() as u64);
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

/// `part` of `whole` in percent, 0 for nothing
pub fn percent(part: f64, whole: f64) -> f64 {
    if whole > 0.0 {
        100.0 * part / whole
    } else {
        0.0
    }
}
