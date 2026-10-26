//! The values of one chart series in bounded memory: the whole run at falling resolution
//! and the last minutes at full resolution

use std::{borrow::Cow, time::Duration};

/// Points the whole-run history keeps at most: two per Braille dot of a chart 256 cells wide
pub const HISTORY_POINTS: usize = 1024;

/// Seconds the full-resolution history covers, the longest chart window
pub const RECENT_SECONDS: f64 = 1800.0;

/// Points the full-resolution history keeps at most: 30 min at 50 ms ticks. Faster ticks
/// cover less than `RECENT_SECONDS`.
pub const RECENT_POINTS: usize = 36_000;

/// Window lengths in seconds that `+` and `-` step through, up to `RECENT_SECONDS`
pub const WINDOWS: [f64; 7] = [10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0];

/// The window steps the full-resolution history covers at one point per `tick`: all of them
/// down to 50 ms ticks, fewer at faster ones, at least the shortest
pub fn window_steps(tick: Duration) -> usize {
    let covered = RECENT_POINTS as f64 * tick.as_secs_f64();
    WINDOWS
        .iter()
        .filter(|window| **window <= covered)
        .count()
        .max(1)
}

/// The step of the shortest window of at least `seconds`, the longest of `steps` for longer ones
pub fn window_step(seconds: f64, steps: usize) -> usize {
    WINDOWS[..steps]
        .iter()
        .position(|window| *window >= seconds)
        .unwrap_or(steps - 1)
}

/// A window length as people say it: "30 s", "2 min"
pub fn window_name(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{seconds:.0} s")
    } else {
        format!("{:.0} min", seconds / 60.0)
    }
}

/// What a chart shows
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Span {
    /// Everything since the start
    Whole,
    /// The last seconds
    Last(f64),
}

/// Values of a series since the start. When the history is full, neighbouring points merge
/// into their maximum, so a recording of any length fits and a spike survives at half the
/// resolution.
pub struct History {
    /// (seconds, value), the last point may still take samples
    points: Vec<(f64, f64)>,
    capacity: usize,
    /// Samples per point
    stride: usize,
    /// Samples in the last point
    last_samples: usize,
}

impl History {
    pub fn new(capacity: usize) -> History {
        History {
            points: Vec::new(),
            capacity: capacity.max(2),
            stride: 1,
            last_samples: 0,
        }
    }

    pub fn push(&mut self, x: f64, y: f64) {
        match self.points.last_mut() {
            Some(last) if self.last_samples < self.stride => {
                last.1 = last.1.max(y);
                self.last_samples += 1;
            }
            _ => {
                self.points.push((x, y));
                self.last_samples = 1;
            }
        }
        if self.points.len() >= self.capacity {
            self.halve();
        }
    }

    /// Merges pairs of points into their maximum, at the time of the first
    fn halve(&mut self) {
        let open = self.points.len() % 2 == 1;
        self.points = self
            .points
            .chunks(2)
            .map(|pair| {
                (
                    pair[0].0,
                    pair.iter().map(|(_, y)| *y).fold(f64::MIN, f64::max),
                )
            })
            .collect();
        // A last point left alone keeps taking samples up to the new stride
        if !open {
            self.last_samples += self.stride;
        }
        self.stride *= 2;
    }

    pub fn points(&self) -> &[(f64, f64)] {
        &self.points
    }
}

/// Every value of a series in the last `RECENT_SECONDS`
#[derive(Default)]
pub struct Recent {
    points: Vec<(f64, f64)>,
    /// First point still in the span; older ones go in batches
    start: usize,
}

impl Recent {
    pub fn push(&mut self, x: f64, y: f64) {
        self.points.push((x, y));
        let live = &self.points[self.start..];
        let old = live.partition_point(|(px, _)| *px < x - RECENT_SECONDS);
        self.start += old.max(live.len().saturating_sub(RECENT_POINTS));
        // Moving the points left once per half buffer keeps a push O(1) on average
        if self.start > self.points.len() / 2 {
            self.points.drain(..self.start);
            self.start = 0;
        }
    }

    /// Points at `from` seconds and later
    pub fn since(&self, from: f64) -> &[(f64, f64)] {
        let live = &self.points[self.start..];
        &live[live.partition_point(|(x, _)| *x < from)..]
    }

    /// Time of the newest point
    pub fn end(&self) -> Option<f64> {
        self.points[self.start..].last().map(|(x, _)| *x)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.points.len() - self.start
    }
}

/// At most about `max` points of `points`, the maximum of each bucket, so spikes stay
pub fn thin(points: &[(f64, f64)], max: usize) -> Cow<'_, [(f64, f64)]> {
    if points.len() <= max.max(1) {
        return Cow::Borrowed(points);
    }
    let bucket = points.len().div_ceil(max.max(1));
    Cow::Owned(
        points
            .chunks(bucket)
            .map(|chunk| {
                let y = chunk.iter().map(|(_, y)| *y).fold(f64::MIN, f64::max);
                (chunk[0].0, y)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn max(points: &[(f64, f64)]) -> f64 {
        points.iter().map(|(_, y)| *y).fold(0.0, f64::max)
    }

    #[test]
    fn whole_run_stays_bounded_and_keeps_spikes() {
        let mut history = History::new(16);
        for i in 0..1000 {
            let y = if i == 333 { 100.0 } else { 1.0 };
            history.push(i as f64, y);
            assert!(history.points().len() < 16);
        }
        assert_eq!(max(history.points()), 100.0);
        assert_eq!(history.points()[0].0, 0.0);
        // Points stay in time order and evenly spaced
        let points = history.points();
        let step = points[1].0 - points[0].0;
        for pair in points.windows(2).take(points.len() - 2) {
            assert_eq!(pair[1].0 - pair[0].0, step);
        }
    }

    #[test]
    fn recent_keeps_every_point_of_the_last_half_hour() {
        let mut recent = Recent::default();
        // An hour at 100 ms ticks
        for i in 0..36_000 {
            recent.push(i as f64 / 10.0, i as f64);
        }
        assert!((18_000..=18_001).contains(&recent.len()));
        assert!(recent.points.len() <= 2 * 18_001);
        let last_minute = recent.since(3599.9 - 60.0);
        assert!((600..=601).contains(&last_minute.len()));
        assert_eq!(last_minute.last(), Some(&(3599.9, 35_999.0)));
    }

    #[test]
    fn recent_is_bounded_at_fast_ticks() {
        let mut recent = Recent::default();
        for i in 0..100_000 {
            recent.push(i as f64 / 1000.0, 1.0);
        }
        assert_eq!(recent.len(), RECENT_POINTS);
    }

    #[test]
    fn windows_round_up_to_a_step() {
        let all = WINDOWS.len();
        assert_eq!(window_step(0.5, all), 0);
        assert_eq!(window_step(10.0, all), 0);
        assert_eq!(window_step(11.0, all), 1);
        assert_eq!(window_step(90.0, all), 3);
        assert_eq!(window_step(7200.0, all), all - 1);
        assert_eq!(window_step(7200.0, 3), 2);
        assert_eq!(window_name(WINDOWS[1]), "30 s");
        assert_eq!(window_name(WINDOWS[3]), "2 min");
        assert_eq!(*WINDOWS.last().unwrap(), RECENT_SECONDS);
    }

    #[test]
    fn fast_ticks_shorten_the_longest_window() {
        assert_eq!(window_steps(Duration::from_millis(100)), WINDOWS.len());
        assert_eq!(window_steps(Duration::from_millis(50)), WINDOWS.len());
        // 36 000 points of 10 ms are 6 min
        assert_eq!(window_steps(Duration::from_millis(10)), 5);
        assert_eq!(window_steps(Duration::from_micros(1)), 1);
    }

    #[test]
    fn thinning_keeps_spikes() {
        let mut points: Vec<(f64, f64)> = (0..1000).map(|i| (i as f64, 1.0)).collect();
        points[517].1 = 9.0;
        let thinned = thin(&points, 100);
        assert_eq!(thinned.len(), 100);
        assert_eq!(max(&thinned), 9.0);
        assert!(matches!(thin(&points[..50], 100), Cow::Borrowed(_)));
    }
}
