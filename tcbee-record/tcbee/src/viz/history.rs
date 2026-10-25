//! The recent values of one chart series in bounded memory

/// Points a history keeps at most: two per Braille dot of a chart 256 cells wide
pub const HISTORY_POINTS: usize = 1024;

/// Values of a series over time. With a window, points older than the window go. When the
/// history is full, neighbouring points merge into their maximum, so a recording of any
/// length fits and a spike survives at half the resolution.
pub struct History {
    /// (seconds, value), the last point may still take samples
    points: Vec<(f64, f64)>,
    capacity: usize,
    window: Option<f64>,
    /// Samples per point
    stride: usize,
    /// Samples in the last point
    last_samples: usize,
}

impl History {
    pub fn new(capacity: usize, window: Option<f64>) -> History {
        History {
            points: Vec::with_capacity(capacity),
            capacity: capacity.max(2),
            window,
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
        if let Some(window) = self.window {
            let old = self.points.partition_point(|(px, _)| *px < x - window);
            // The last point stays, it may still take samples
            self.points.drain(..old.min(self.points.len() - 1));
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

    /// Largest value, 0 for an empty history
    pub fn max(&self) -> f64 {
        self.points.iter().map(|(_, y)| *y).fold(0.0, f64::max)
    }

    /// Time of the newest point
    pub fn end(&self) -> Option<f64> {
        self.points.last().map(|(x, _)| *x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_run_stays_bounded_and_keeps_spikes() {
        let mut history = History::new(16, None);
        for i in 0..1000 {
            let y = if i == 333 { 100.0 } else { 1.0 };
            history.push(i as f64, y);
            assert!(history.points().len() < 16);
        }
        assert_eq!(history.max(), 100.0);
        assert_eq!(history.points()[0].0, 0.0);
        // Points stay in time order and evenly spaced
        let points = history.points();
        let step = points[1].0 - points[0].0;
        for pair in points.windows(2).take(points.len() - 2) {
            assert_eq!(pair[1].0 - pair[0].0, step);
        }
    }

    #[test]
    fn window_drops_old_points() {
        let mut history = History::new(1024, Some(10.0));
        for i in 0..100 {
            history.push(i as f64, i as f64);
        }
        assert_eq!(history.points()[0].0, 89.0);
        assert_eq!(history.end(), Some(99.0));
        assert_eq!(history.max(), 99.0);
    }

    #[test]
    fn a_spike_survives_the_window_until_it_ages_out() {
        let mut history = History::new(8, Some(100.0));
        history.push(0.0, 50.0);
        for i in 1..200 {
            history.push(i as f64, 1.0);
            if i < 100 {
                assert_eq!(history.max(), 50.0, "at {i}");
            }
        }
        assert_eq!(history.max(), 1.0);
        assert!(history.points().len() < 8);
    }
}
