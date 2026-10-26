use libbpf_rs::{MapCore, MapFlags, MapHandle};
use tcbee_common::stats::{
    aggregated_slot, invocation_slots, slot, suppressed_slot, RB_COUNT, STATS_LEN, STATS_STATE_ERR,
    STAT_DROPPED, STAT_ERROR, STAT_HANDLED,
};

/// Reads the `STATS` per-CPU counter array of the eBPF programs.
pub struct Stats {
    map: MapHandle,
}

impl Stats {
    pub fn new(map: MapHandle) -> Stats {
        Stats { map }
    }

    /// Sums every counter slot over all CPUs.
    ///
    /// Slots are read one by one while the probes keep counting.
    pub fn snapshot(&self) -> libbpf_rs::Result<Snapshot> {
        let mut values = vec![0u64; STATS_LEN as usize];
        for index in 0..STATS_LEN {
            let per_cpu = self
                .map
                .lookup_percpu(&index.to_ne_bytes(), MapFlags::ANY)?
                .unwrap_or_default();
            values[index as usize] = per_cpu
                .iter()
                .filter_map(|value| value.as_slice().try_into().ok())
                .map(u64::from_ne_bytes)
                .fold(0u64, u64::wrapping_add);
        }
        Ok(Snapshot { values })
    }
}

#[derive(Clone, Default)]
pub struct Snapshot {
    values: Vec<u64>,
}

impl Snapshot {
    /// A snapshot with the given slot values, for tests
    #[cfg(test)]
    pub fn from_values(values: Vec<u64>) -> Snapshot {
        Snapshot { values }
    }

    pub fn get(&self, index: u32) -> u64 {
        self.values.get(index as usize).copied().unwrap_or(0)
    }

    pub fn rb(&self, rb: u32, stat: u32) -> u64 {
        self.get(slot(rb, stat))
    }

    pub fn sum(&self, slots: &[u32]) -> u64 {
        slots.iter().map(|s| self.get(*s)).sum()
    }

    /// Sum of one stat over all ring buffers
    pub fn total(&self, stat: u32) -> u64 {
        (0..RB_COUNT).map(|rb| self.rb(rb, stat)).sum()
    }

    pub fn handled(&self) -> u64 {
        self.total(STAT_HANDLED)
    }

    pub fn dropped(&self) -> u64 {
        self.total(STAT_DROPPED)
    }

    pub fn errors(&self) -> u64 {
        self.total(STAT_ERROR)
    }

    /// Runs of one ring buffer that an on-change probe suppressed
    pub fn suppressed(&self, rb: u32) -> u64 {
        suppressed_slot(rb).map_or(0, |slot| self.get(slot))
    }

    pub fn suppressed_total(&self) -> u64 {
        (0..RB_COUNT).map(|rb| self.suppressed(rb)).sum()
    }

    /// On-change runs without socket storage, which wrote a full record
    pub fn state_errors(&self) -> u64 {
        self.get(STATS_STATE_ERR)
    }

    /// Packets of one ring buffer's header hook that stand for several segments
    pub fn aggregated(&self, rb: u32) -> u64 {
        aggregated_slot(rb).map_or(0, |slot| self.get(slot))
    }

    pub fn aggregated_total(&self) -> u64 {
        (0..RB_COUNT).map(|rb| self.aggregated(rb)).sum()
    }

    /// Probe invocations of one ring buffer: handled, dropped, failed and suppressed events
    pub fn invocations(&self, rb: u32) -> u64 {
        self.sum(&invocation_slots(rb))
    }

    pub fn attempted(&self) -> u64 {
        (0..RB_COUNT).map(|rb| self.invocations(rb)).sum()
    }
}
