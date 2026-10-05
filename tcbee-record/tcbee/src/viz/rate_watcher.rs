use std::time::Duration;

use crate::stats::Snapshot;

/// Tracks the rate of a sum of counter slots between snapshots.
pub struct RateWatcher {
    slots: Vec<u32>,
    suffix: String,
    last_val: u64,
    needs_baseline: bool,
}

impl RateWatcher {
    pub fn new(slots: Vec<u32>, suffix: &str) -> RateWatcher {
        RateWatcher {
            slots,
            suffix: suffix.to_string(),
            last_val: 0,
            needs_baseline: true,
        }
    }

    pub fn get_rate_string(&mut self, snapshot: &Snapshot, elapsed: Duration) -> String {
        let rate = self.get_rate(snapshot, elapsed);
        RateWatcher::format_rate(rate, &self.suffix)
    }

    pub fn get_rate(&mut self, snapshot: &Snapshot, elapsed: Duration) -> f64 {
        let sum = self.get_counter_sum(snapshot);

        if self.needs_baseline {
            self.last_val = sum;
            self.needs_baseline = false;
            return 0.0;
        }

        if elapsed.is_zero() {
            return 0.0;
        }

        let rate = sum.wrapping_sub(self.last_val) as f64 / elapsed.as_secs_f64();
        self.last_val = sum;
        rate
    }

    pub fn get_counter_sum(&self, snapshot: &Snapshot) -> u64 {
        snapshot.sum(&self.slots)
    }

    pub fn get_counter_sum_string(&self, snapshot: &Snapshot) -> String {
        RateWatcher::format_sum(self.get_counter_sum(snapshot), "")
    }

    // TODO: prettier?
    pub fn format_rate(val: f64, suffix: &str) -> String {
        if val > 1_000_000_000.0 {
            return format!("{:.2} G{}", val / 1_000_000_000.0, suffix);
        } else if val > 1_000_000.0 {
            return format!("{:.2} M{}", val / 1_000_000.0, suffix);
        } else if val > 1_000.0 {
            return format!("{:.2} K{}", val / 1_000.0, suffix);
        } else {
            return format!("{:.2} {}", val, suffix);
        }
    }
    pub fn format_sum(val: u64, suffix: &str) -> String {
        let val = val as f64;
        if val > 1_000_000_000.0 {
            return format!("{:.2} G{}", val / 1_000_000_000.0, suffix);
        } else if val > 1_000_000.0 {
            return format!("{:.2} M{}", val / 1_000_000.0, suffix);
        } else if val > 1_000.0 {
            return format!("{:.2} K{}", val / 1_000.0, suffix);
        } else {
            return format!("{:.0} {}", val, suffix);
        }
    }
}
