use anyhow::anyhow;
use aya::{
    maps::{MapData, MapError, PerCpuArray},
    Ebpf,
};
use tcbee_common::stats::{
    slot, RB_COUNT, STATS_LEN, STATS_PER_RB, STAT_ATTEMPTED, STAT_DROPPED, STAT_ERROR, STAT_HANDLED,
};

/// Reads the `STATS` per-CPU counter array of the eBPF programs.
pub struct Stats {
    map: PerCpuArray<MapData, u64>,
}

impl Stats {
    pub fn new(ebpf: &mut Ebpf) -> anyhow::Result<Stats> {
        let map = ebpf
            .take_map("STATS")
            .ok_or_else(|| anyhow!("Could not find STATS map!"))?;
        Ok(Stats {
            map: PerCpuArray::try_from(map)?,
        })
    }

    /// Sums every counter slot over all CPUs.
    ///
    /// Slots are read one by one while the probes keep counting. The attempted counters
    /// are read last, so a live snapshot never shows more outcomes than attempts.
    pub fn snapshot(&self) -> Result<Snapshot, MapError> {
        let mut values = vec![0u64; STATS_LEN as usize];
        let attempted =
            |index: &u32| *index < slot(RB_COUNT, 0) && *index % STATS_PER_RB == STAT_ATTEMPTED;
        let outcomes = (0..STATS_LEN).filter(|i| !attempted(i));
        for index in outcomes.chain((0..STATS_LEN).filter(attempted)) {
            let per_cpu = self.map.get(&index, 0)?;
            values[index as usize] = per_cpu.iter().copied().fold(0u64, u64::wrapping_add);
        }
        Ok(Snapshot { values })
    }
}

#[derive(Clone, Default)]
pub struct Snapshot {
    values: Vec<u64>,
}

impl Snapshot {
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

    pub fn attempted(&self) -> u64 {
        self.total(STAT_ATTEMPTED)
    }
}
