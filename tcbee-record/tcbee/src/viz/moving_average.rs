use std::collections::VecDeque;

#[derive(Debug, Clone)]
struct TimedValue {
    value: f64,
    duration: f64,
}

pub struct MovingAverage {
    values: VecDeque<TimedValue>,
    max_values: usize,
}

impl MovingAverage{
    /// Create a new MovingAverage that keeps the last `max_values` entries
    pub fn new(max_values: usize) -> Self {
        Self {
            values: VecDeque::new(),
            max_values,
        }
    }

    /// Add a new value with its duration
    pub fn add_value(&mut self, value: f64, duration: f64) {
        self.values.push_back(TimedValue { value, duration });
        
        // Remove oldest values if we exceed the limit
        while self.values.len() > self.max_values {
            self.values.pop_front();
        }
    }

    /// Calculate the time-weighted moving average
    pub fn get_average(&self) -> Option<f64> {
        if self.values.is_empty() {
            return None;
        }

        let total_weighted_sum: f64 = self.values
            .iter()
            .map(|tv| tv.value * tv.duration)
            .sum();
        
        let total_duration: f64 = self.values
            .iter()
            .map(|tv| tv.duration)
            .sum();

        if total_duration == 0.0 {
            None
        } else {
            Some(total_weighted_sum / total_duration)
        }
    }

    /// Get the number of values currently stored
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if the tracker is empty
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Clear all stored values
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// Get the capacity (max number of values that can be stored)
    pub fn capacity(&self) -> usize {
        self.max_values
    }
}