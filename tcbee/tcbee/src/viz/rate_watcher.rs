use std::{ops::{AddAssign, Sub}, time::Duration};

use aya::{maps::PerCpuArray, util::nr_cpus, Pod};
use log::error;


// TODO: make more generic to handle float maps as well?
pub struct RateWatcher<T: Pod + AddAssign + Sub> {
    map: PerCpuArray<aya::maps::MapData, T>,
    suffix: String,
    last_val: T,
    name: String,
}

impl<T: Pod + AddAssign + Default + Sub> RateWatcher<T> {
    pub fn new(
        map: PerCpuArray<aya::maps::MapData, T>,
        suffix: String,
        init_val: T,
        name: String,
    ) -> RateWatcher<T> {
        RateWatcher {
            map: map,
            suffix: suffix,
            last_val: init_val,
            name: name,
        }
    }
    pub fn get_rate_string(&mut self, elapsed: Duration) -> String
    where
        f64: From<<T as Sub>::Output>,
    {
        let rate = self.get_rate(elapsed);
        RateWatcher::<T>::format_rate(rate, &self.suffix)
    }

    pub fn get_rate(&mut self, elapsed: Duration) -> f64
    where
        f64: From<<T as Sub>::Output>,
    {
        let sum = self.get_counter_sum();

        // TODO: better handling?
        let rate = f64::try_from(sum - self.last_val).unwrap_or_else(|_| -1.0)
            * (1.0 / elapsed.as_secs_f64());

        self.last_val = sum;

        rate
    }

    pub fn get_counter_sum(&self) -> T {
        // Counter is per CPU, sum will hold sum across CPUs
        let mut sum: T = T::default();

        // Get counter array
        let values = self.map.get(&0, 0);

        // Check if error erturned
        match values {
            Err(err) => {
                error!("Failed to read event counter {}: {}!", self.name, err);
            }
            Ok(counters) => {
                // Iterate and sum over array
                if let Ok(num_cpus) = nr_cpus() {
                    for i in 0..num_cpus {
                        sum += counters[i];
                    }
                } else {
                    error!("Failed to get number of CPUs for {}", self.name);
                }
            }
        }
        sum
    }

    // TODO: Cache this? Since rate and count is called multiple times in one loop iteration
    pub fn get_counter_sum_string(&self) -> String
    where
        u64: From<T>,
    {
        let Ok(sum) = u64::try_from(self.get_counter_sum());
        RateWatcher::<T>::format_sum(sum, "")
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
            return format!("{:.2} K{}", val / 1_0000.0, suffix);
        } else {
            return format!("{:.0} {}", val, suffix);
        }
    }
}


