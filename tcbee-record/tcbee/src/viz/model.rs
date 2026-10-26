//! What the watcher shows, computed once per tick from a counter snapshot

use std::{collections::VecDeque, time::Duration};

use ratatui::style::Color;
use tcbee_common::stats::{
    invocation_slots, packet_rings, slot, RB_COUNT, RB_TCP4_DRIVER_INGRESS, RB_TCP4_INGRESS,
    STAT_DROPPED, STAT_HANDLED,
};

use crate::{
    stats::Snapshot,
    viz::{
        format,
        groups::{chart_groups, display_group, Group},
        history::{History, Recent, Span, HISTORY_POINTS},
    },
};

/// Ticks the drop sparkline keeps, more than the widest terminal shows
pub const DROP_TICKS: usize = 512;

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

/// Slots of the runs of every ring
fn all_runs() -> Vec<u32> {
    run_slots(&(0..RB_COUNT).collect::<Vec<_>>())
}

/// Slots of the records of `rings`
fn handled_slots(rings: &[u32]) -> Vec<u32> {
    rings.iter().map(|rb| slot(*rb, STAT_HANDLED)).collect()
}

/// A line of a chart: the rate of a sum of counter slots
pub struct ChartSeries {
    pub label: &'static str,
    pub color: Color,
    slots: Vec<u32>,
    /// The whole run, decimated
    pub whole: History,
    /// The last half hour at full resolution
    pub recent: Recent,
}

impl ChartSeries {
    fn new(label: &'static str, color: Color, slots: Vec<u32>) -> ChartSeries {
        ChartSeries {
            label,
            color,
            slots,
            whole: History::new(HISTORY_POINTS),
            recent: Recent::default(),
        }
    }

    /// The points of `span` up to `end` seconds
    pub fn points(&self, span: Span, end: f64) -> &[(f64, f64)] {
        match span {
            Span::Whole => self.whole.points(),
            Span::Last(window) => self.recent.since(end - window),
        }
    }
}

pub struct ChartModel {
    pub title: &'static str,
    pub unit: &'static str,
    pub series: Vec<ChartSeries>,
}

impl ChartModel {
    fn events() -> ChartModel {
        let series = |label, color, stat| ChartSeries::new(label, color, all_slots(stat));
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
    fn group(group: Group, active_rings: &[u32]) -> ChartModel {
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
                (!rings.is_empty())
                    .then(|| ChartSeries::new(series.label, color, run_slots(&rings)))
            })
            .collect();
        ChartModel {
            title: group.title(),
            unit: group.unit(),
            series,
        }
    }

    /// Time of the newest sample. The last point of the whole-run history is older once it
    /// merges samples: it holds the time of its first.
    pub fn end(&self) -> f64 {
        self.series
            .iter()
            .filter_map(|series| series.recent.end())
            .fold(0.0, f64::max)
    }
}

/// How often the left column takes new counters: its rates are averages over this period
pub const SUMMARY_PERIOD: Duration = Duration::from_secs(1);

/// Seconds a group row keeps for its sparkline, one value per summary
pub const ROW_HISTORY: usize = 30;

/// A row of the probe group table
pub struct GroupRow {
    pub group: Group,
    /// Its rings that record
    pub rings: Vec<u32>,
    /// Index of its chart in `Model::charts`
    pub chart: Option<usize>,
    /// Records per second of the last summaries, the newest last
    pub history: Vec<f64>,
}

/// Counters and rates of some rings
pub struct RingStats {
    /// Probe runs per second
    pub runs: f64,
    /// Records per second
    pub records: f64,
    pub drops: u64,
    /// Share of the runs an on-change probe suppressed, in percent
    pub suppressed: f64,
    /// Share of the runs at packets that stand for several segments, in percent
    pub aggregated: f64,
}

/// The counters taken last and those taken before: the totals and the rates between them
#[derive(Default)]
pub struct Counters {
    /// Time since the watcher started, at `snapshot`
    pub elapsed: Duration,
    pub snapshot: Snapshot,
    /// Bytes the writers wrote so far
    pub bytes_written: u64,
    /// The counters before, their time and the bytes, None until the second take
    previous: Option<(Snapshot, Duration, u64)>,
    /// Whether counters were taken
    taken: bool,
}

impl Counters {
    fn take(&mut self, snapshot: Snapshot, bytes_written: u64, elapsed: Duration) {
        let current = std::mem::replace(&mut self.snapshot, snapshot);
        if self.taken {
            self.previous = Some((current, self.elapsed, self.bytes_written));
        }
        self.taken = true;
        self.bytes_written = bytes_written;
        self.elapsed = elapsed;
    }

    /// Seconds between the previous and the current counters, None after the first take
    fn interval(&self) -> Option<f64> {
        let (_, before, _) = self.previous.as_ref()?;
        let secs = self.elapsed.saturating_sub(*before).as_secs_f64();
        (secs > 0.0).then_some(secs)
    }

    /// Increase of the sum of `slots` per second since the previous counters
    fn rate(&self, slots: &[u32]) -> f64 {
        let (Some(secs), Some((previous, _, _))) = (self.interval(), self.previous.as_ref()) else {
            return 0.0;
        };
        self.snapshot.sum(slots).wrapping_sub(previous.sum(slots)) as f64 / secs
    }

    pub fn handled_rate(&self) -> f64 {
        self.rate(&all_slots(STAT_HANDLED))
    }

    pub fn dropped_rate(&self) -> f64 {
        self.rate(&all_slots(STAT_DROPPED))
    }

    /// Probe runs per second over all rings
    pub fn runs_rate(&self) -> f64 {
        self.rate(&all_runs())
    }

    /// Probe runs since the start over all rings
    pub fn runs_total(&self) -> u64 {
        self.snapshot.sum(&all_runs())
    }

    /// Counters of `rings`: rates since the previous counters, the rest since the start
    pub fn ring_stats(&self, rings: &[u32]) -> RingStats {
        let snap = &self.snapshot;
        let runs: u64 = rings.iter().map(|rb| snap.invocations(*rb)).sum();
        let suppressed: u64 = rings.iter().map(|rb| snap.suppressed(*rb)).sum();
        let aggregated: u64 = rings.iter().map(|rb| snap.aggregated(*rb)).sum();
        RingStats {
            runs: self.rate(&run_slots(rings)),
            records: self.rate(&handled_slots(rings)),
            drops: rings.iter().map(|rb| snap.rb(*rb, STAT_DROPPED)).sum(),
            suppressed: percent(suppressed as f64, runs as f64),
            aggregated: percent(aggregated as f64, runs as f64),
        }
    }

    /// Dropped share of all events since the start in percent
    pub fn drop_percent_total(&self) -> f64 {
        let dropped = self.snapshot.dropped() as f64;
        percent(dropped, self.snapshot.handled() as f64 + dropped)
    }

    /// Dropped share of the events since the previous counters in percent
    pub fn drop_percent(&self) -> f64 {
        percent(
            self.dropped_rate(),
            self.handled_rate() + self.dropped_rate(),
        )
    }

    /// Bytes written per second since the previous counters
    pub fn disk_rate(&self) -> f64 {
        let (Some(secs), Some((_, _, bytes))) = (self.interval(), self.previous.as_ref()) else {
            return 0.0;
        };
        self.bytes_written.saturating_sub(*bytes) as f64 / secs
    }
}

pub struct Model {
    /// The counters of the last tick and the tick before, for the charts and the -q line
    pub tick: Counters,
    /// The counters of the last summary and the one before, at least `SUMMARY_PERIOD` apart,
    /// for the left column: it changes once per period, with the rates averaged over it
    pub second: Counters,
    /// Runs of the header hooks of the -q line
    ingress: Vec<u32>,
    egress: Vec<u32>,
    /// The events chart and those of the first groups
    pub charts: Vec<ChartModel>,
    /// Dropped share of the events of the last `DROP_TICKS` ticks, in hundredths of a percent
    pub drop_history: VecDeque<u64>,
    /// Active groups in chart priority
    pub groups: Vec<GroupRow>,
}

impl Model {
    pub fn new(active_rings: &[u32]) -> Model {
        let mut charts = vec![ChartModel::events()];
        let charted = chart_groups(active_rings, CHARTS - 1);
        for group in &charted {
            charts.push(ChartModel::group(*group, active_rings));
        }
        let groups = Group::ALL
            .into_iter()
            .map(|group| GroupRow {
                group,
                rings: active_rings
                    .iter()
                    .copied()
                    .filter(|rb| display_group(*rb) == Some(group))
                    .collect(),
                // The events chart comes first
                chart: charted.iter().position(|g| *g == group).map(|i| i + 1),
                history: Vec::new(),
            })
            .filter(|row| !row.rings.is_empty())
            .collect();
        // With both header hooks, the TC rates
        let driver_packets = !active_rings.contains(&RB_TCP4_INGRESS)
            && active_rings.contains(&RB_TCP4_DRIVER_INGRESS);
        let (ingress, egress) = packet_rings(driver_packets);
        Model {
            tick: Counters::default(),
            second: Counters::default(),
            ingress: run_slots(&ingress),
            egress: run_slots(&egress),
            charts,
            drop_history: VecDeque::new(),
            groups,
        }
    }

    /// Takes the counters of a tick. Rates compare them with the tick before, those of the
    /// left column with the last summary once it is a period old.
    pub fn update(&mut self, snapshot: Snapshot, bytes_written: u64, elapsed: Duration) {
        let summary =
            !self.second.taken || elapsed.saturating_sub(self.second.elapsed) >= SUMMARY_PERIOD;
        if summary {
            self.second.take(snapshot.clone(), bytes_written, elapsed);
            for row in &mut self.groups {
                if row.history.len() == ROW_HISTORY {
                    row.history.remove(0);
                }
                row.history
                    .push(self.second.rate(&handled_slots(&row.rings)));
            }
        }
        self.tick.take(snapshot, bytes_written, elapsed);
    }

    /// Time since the watcher started, at the last tick
    pub fn elapsed(&self) -> Duration {
        self.tick.elapsed
    }

    pub fn ingress_rate(&self) -> f64 {
        self.tick.rate(&self.ingress)
    }

    pub fn egress_rate(&self) -> f64 {
        self.tick.rate(&self.egress)
    }

    /// Adds the rates of the tick to the chart histories
    pub fn record_history(&mut self) {
        let x = self.tick.elapsed.as_secs_f64();
        for c in 0..self.charts.len() {
            for s in 0..self.charts[c].series.len() {
                let y = self.tick.rate(&self.charts[c].series[s].slots);
                let series = &mut self.charts[c].series[s];
                series.whole.push(x, y);
                series.recent.push(x, y);
            }
        }
        if self.drop_history.len() == DROP_TICKS {
            self.drop_history.pop_front();
        }
        self.drop_history
            .push_back((self.tick.drop_percent() * 100.0).round() as u64);
    }

    /// The status line of -q, overwriting the line before
    pub fn quiet_line(&self) -> String {
        let elapsed = self.tick.elapsed;
        let snap = &self.tick.snapshot;
        format!(
            // \r returns cursor to beginning of line, effectively overwriting the last line
            "\r| {}s {}ms time elapsed | {} handled | {} dropped | {} events/s | {} drops/s | {} ingress packets/s | {} egress packets/s | ",
            elapsed.as_secs(),
            elapsed.subsec_millis(),
            snap.handled(),
            snap.dropped(),
            format::quiet_rate(self.tick.handled_rate(), "Events/s"),
            format::quiet_rate(self.tick.dropped_rate(), "Events/s"),
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

#[cfg(test)]
mod tests {
    use tcbee_common::stats::{
        slot, RB_COUNT, RB_TCP4_DRIVER_INGRESS, RB_TCP4_INGRESS, STAT_HANDLED,
    };

    use std::time::Duration;

    use super::*;
    use crate::viz::test_support::{busy_model, snapshot, TC_RINGS};

    #[test]
    fn charts_end_at_the_newest_sample_after_the_history_merged() {
        let mut model = Model::new(&TC_RINGS);
        // More ticks than the whole-run history keeps
        for t in 0..3000u64 {
            let count = 600 * t + if t == 2990 { 6000 } else { 0 };
            model.update(
                snapshot(&[(slot(RB_TCP4_INGRESS, STAT_HANDLED), count)]),
                0,
                Duration::from_secs(t),
            );
            model.record_history();
        }
        let headers = &model.charts[1];
        let whole_end = headers.series[0].whole.points().last().unwrap().0;
        assert!(whole_end < 2999.0, "{whole_end}");
        assert_eq!(headers.end(), 2999.0);
        // The window ends now and holds the spike of 10 s ago
        let window = headers.series[0].points(Span::Last(60.0), headers.end());
        assert_eq!(window.len(), 61);
        assert_eq!(window.last().unwrap().0, 2999.0);
        assert!(window.iter().any(|(_, y)| *y == 6600.0));
    }

    #[test]
    fn quiet_line_keeps_its_format() {
        assert_eq!(
            busy_model(&TC_RINGS).quiet_line(),
            "\r| 1s 500ms time elapsed | 990 handled | 10 dropped | 990.00 Events/s events/s | \
             10.00 Events/s drops/s | 600.00 pps ingress packets/s | 400.00 pps egress packets/s | "
        );
    }

    #[test]
    fn rates_follow_the_counters() {
        let model = busy_model(&TC_RINGS);
        assert_eq!(model.tick.handled_rate(), 990.0);
        assert_eq!(model.tick.dropped_rate(), 10.0);
        assert_eq!(model.ingress_rate(), 600.0);
        assert_eq!(model.egress_rate(), 400.0);
        assert_eq!(model.tick.disk_rate(), 2_000_000.0);
        // The driver rings saw nothing
        assert_eq!(busy_model(&[RB_TCP4_DRIVER_INGRESS]).ingress_rate(), 0.0);
    }

    #[test]
    fn the_left_column_takes_one_second_averages() {
        let mut model = Model::new(&TC_RINGS);
        // 100 ms ticks, 100 packets in each but the 1000 of the fifth
        let mut count = 0;
        for tick in 0..=10u64 {
            count += if tick == 5 { 1000 } else { 100 };
            let values = [(slot(RB_TCP4_INGRESS, STAT_HANDLED), count)];
            model.update(snapshot(&values), 0, Duration::from_millis(100 * tick));
            if tick < 10 {
                // The counters of the first tick stay
                assert_eq!(model.second.snapshot.handled(), 100, "{tick}");
                assert_eq!(model.second.handled_rate(), 0.0);
            }
        }
        assert_eq!(model.tick.handled_rate(), 1000.0);
        assert_eq!(model.second.handled_rate(), 1900.0);
        assert_eq!(model.second.snapshot.handled(), 2000);
        assert_eq!(model.groups[0].history, [0.0, 1900.0]);
    }

    #[test]
    fn first_tick_has_no_rates() {
        let mut model = Model::new(&TC_RINGS);
        model.update(
            snapshot(&[(slot(RB_TCP4_INGRESS, STAT_HANDLED), 5)]),
            10,
            Duration::from_secs(1),
        );
        assert_eq!(model.ingress_rate(), 0.0);
        assert_eq!(model.tick.disk_rate(), 0.0);
    }

    #[test]
    fn charts_follow_the_active_rings() {
        let all = Model::new(&(0..RB_COUNT).collect::<Vec<_>>());
        let titles: Vec<&str> = all.charts.iter().map(|chart| chart.title).collect();
        assert_eq!(
            titles,
            ["Events", "Headers", "Socket hooks", "CC internals"]
        );
        let labels: Vec<&str> = all.charts[1].series.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["in", "out", "drv in", "drv out"]);
        let tc = Model::new(&TC_RINGS);
        assert_eq!(tc.charts.len(), 2);
        assert_eq!(tc.charts[1].series.len(), 2);
        assert_eq!(Model::new(&[]).charts.len(), 1);
    }

    #[test]
    fn group_charts_show_runs_per_series() {
        let model = busy_model(&TC_RINGS);
        let headers = &model.charts[1];
        let last = |s: usize| *headers.series[s].whole.points().last().unwrap();
        assert_eq!(last(0), (1.5, 600.0));
        assert_eq!(last(1), (1.5, 400.0));
        assert_eq!(model.drop_history, [0, 100]);
        assert_eq!(model.tick.drop_percent(), 1.0);
    }
}
