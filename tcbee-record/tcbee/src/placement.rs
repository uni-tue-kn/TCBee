//! Where writer threads and their file helpers run on the `--writer-cpus`.
//!
//! Pinning writers round-robin in spawn order can put the busiest writers on one CPU and
//! leave another idle, and a file helper that runs on its own writer's CPU takes half of it
//! while the writer is busiest. With `Placement::Balanced`, a balancer thread measures each
//! writer's CPU time and moves busy writers apart, and file helpers run on the least loaded
//! writer CPU. A writer moves itself: no other thread acts on a writer's thread id, which is
//! gone once the writer exits.

use std::{
    io, mem,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};

use log::{error, info, warn};

/// How writer threads are spread over the writer CPUs
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Placement {
    /// Start round-robin, then move writers between the CPUs by their CPU time so that busy
    /// writers do not share a CPU, and run file helpers on the least loaded CPU
    #[default]
    Balanced,
    /// Pin writers round-robin in spawn order and leave them there
    RoundRobin,
}

/// How often the balancer looks at the writers' loads
const BALANCE_INTERVAL: Duration = Duration::from_millis(100);
/// A writer moves only if that unloads the busiest CPU by more than this many cores
const BALANCE_MARGIN: f64 = 0.1;
/// How often a writer publishes its CPU time and checks where it should run
pub const FOLLOW_INTERVAL: Duration = Duration::from_millis(10);

/// One writer to move from the most loaded CPU to the least loaded one, as (writer, CPU),
/// if that lowers the most loaded CPU by more than `margin` cores. Writer `i` runs on
/// `placed[i]` with load `loads[i]`, in cores. Of the writers on the most loaded CPU it picks
/// the one that leaves the lowest maximum. One move per call keeps migrations rare; repeated
/// calls converge.
pub fn balance(
    cpus: &[usize],
    placed: &[usize],
    loads: &[f64],
    margin: f64,
) -> Option<(usize, usize)> {
    let totals = totals(cpus, placed, loads);
    let busiest = argmax(&totals)?;
    let idlest = argmin(&totals)?;
    if busiest == idlest {
        return None;
    }
    let before = totals[busiest];
    let mut best: Option<(usize, f64)> = None;
    for (i, &cpu) in placed.iter().enumerate() {
        if cpu != cpus[busiest] {
            continue;
        }
        let mut after = totals.clone();
        after[busiest] -= loads[i];
        after[idlest] += loads[i];
        let max = after.iter().copied().fold(0.0, f64::max);
        if best.is_none_or(|(_, m)| max < m) {
            best = Some((i, max));
        }
    }
    let (writer, after) = best?;
    (after < before - margin).then_some((writer, cpus[idlest]))
}

/// The CPUs for a file helper of the writer on `own` with load `own_load`: the pool CPUs
/// without a writer if there are any, else the least loaded CPU, where the writer's own CPU
/// counts its load twice: the writer waits for the helper, so sharing hurts it twice.
pub fn helper_cpus(
    cpus: &[usize],
    placed: &[usize],
    loads: &[f64],
    own: usize,
    own_load: f64,
) -> Vec<usize> {
    let free: Vec<usize> = cpus
        .iter()
        .copied()
        .filter(|c| !placed.contains(c))
        .collect();
    if !free.is_empty() {
        return free;
    }
    let mut totals = totals(cpus, placed, loads);
    if let Some(k) = cpus.iter().position(|&c| c == own) {
        totals[k] += own_load;
    }
    argmin(&totals).map_or_else(|| cpus.to_vec(), |k| vec![cpus[k]])
}

/// Load per CPU of `cpus`
fn totals(cpus: &[usize], placed: &[usize], loads: &[f64]) -> Vec<f64> {
    cpus.iter()
        .map(|&cpu| {
            placed
                .iter()
                .zip(loads)
                .filter(|(&c, _)| c == cpu)
                .map(|(_, load)| load)
                .sum()
        })
        .collect()
}

/// Index of the largest value, the first one on a tie
fn argmax(values: &[f64]) -> Option<usize> {
    (0..values.len()).reduce(|best, k| if values[k] > values[best] { k } else { best })
}

/// Index of the smallest value, the first one on a tie
fn argmin(values: &[f64]) -> Option<usize> {
    (0..values.len()).reduce(|best, k| if values[k] < values[best] { k } else { best })
}

/// The writer CPUs and the writers pinned to them
#[derive(Default)]
pub struct WriterCpus {
    /// The writer CPU pool, empty if writers are not pinned
    pub pool: Vec<usize>,
    placement: Placement,
    writers: Mutex<Vec<Arc<WriterSlot>>>,
    /// Writer moves so far
    pub moves: AtomicU64,
    /// The warning that helpers share the writers' CPUs was logged
    warned: AtomicBool,
}

/// A pinned writer thread, shared by the writer and the balancer
pub struct WriterSlot {
    /// The CPU the writer runs on, or is to move to
    pub cpu: AtomicUsize,
    /// The writer's CPU time in ns and when it read it, published by the writer
    published: Mutex<Option<(u64, Instant)>>,
    /// The balancer's view of the writer
    sample: Mutex<LoadSample>,
    /// A CPU the writer could not move to, usize::MAX if none
    refused: AtomicUsize,
    /// For the log
    name: String,
}

#[derive(Default)]
struct LoadSample {
    /// The last publication the balancer used
    last: Option<(u64, Instant)>,
    /// Smoothed load in cores, None before the first measurement
    load: Option<f64>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl WriterSlot {
    fn load(&self) -> f64 {
        lock(&self.sample).load.unwrap_or(0.0)
    }

    fn publish(&self, cpu_ns: u64, at: Instant) {
        *lock(&self.published) = Some((cpu_ns, at));
    }
}

impl WriterCpus {
    pub fn new(pool: Vec<usize>, placement: Placement) -> Self {
        WriterCpus {
            pool,
            placement,
            ..Default::default()
        }
    }

    pub fn balanced(&self) -> bool {
        self.placement == Placement::Balanced
    }

    pub fn add_writer(&self, cpu: usize, name: &str) -> Arc<WriterSlot> {
        let slot = Arc::new(WriterSlot {
            cpu: AtomicUsize::new(cpu),
            published: Mutex::new(None),
            sample: Mutex::new(LoadSample::default()),
            refused: AtomicUsize::new(usize::MAX),
            name: name.to_string(),
        });
        lock(&self.writers).push(slot.clone());
        slot
    }

    /// Forgets a writer that did not start or has stopped
    pub fn remove_writer(&self, slot: &Arc<WriterSlot>) {
        lock(&self.writers).retain(|w| !Arc::ptr_eq(w, slot));
    }

    /// The writers' CPUs and loads
    fn snapshot(&self) -> (Vec<usize>, Vec<f64>) {
        lock(&self.writers)
            .iter()
            .map(|w| (w.cpu.load(Ordering::Relaxed), w.load()))
            .unzip()
    }

    /// The pool CPUs without a writer, or the whole pool if every one has a writer. None if
    /// writers are not pinned: helpers then run wherever their writer may.
    pub fn round_robin_helper_set(&self) -> Option<libc::cpu_set_t> {
        if self.pool.is_empty() {
            return None;
        }
        let (placed, _) = self.snapshot();
        let mut free: Vec<usize> = self
            .pool
            .iter()
            .copied()
            .filter(|c| !placed.contains(c))
            .collect();
        if free.is_empty() {
            if !self.warned.swap(true, Ordering::Relaxed) {
                warn!("Every writer CPU has a writer, file growth shares their CPUs");
            }
            free = self.pool.clone();
        }
        Some(cpu_set(&free))
    }

    /// The CPU for a helper of `writer`, see `helper_cpus`
    fn balanced_helper_set(&self, writer: &WriterSlot) -> libc::cpu_set_t {
        let (placed, loads) = self.snapshot();
        cpu_set(&helper_cpus(
            &self.pool,
            &placed,
            &loads,
            writer.cpu.load(Ordering::Relaxed),
            writer.load(),
        ))
    }

    /// Updates the loads from what the writers published and moves at most one writer.
    /// A load is the CPU time between two publications over the time between them, both
    /// taken by the writer, so a late publication does not distort it.
    pub fn rebalance(&self) -> Option<(usize, usize)> {
        let writers = lock(&self.writers);
        let mut placed = Vec::with_capacity(writers.len());
        let mut loads = Vec::with_capacity(writers.len());
        for writer in writers.iter() {
            let published = *lock(&writer.published);
            let mut sample = lock(&writer.sample);
            if let (Some((ns, at)), Some((last_ns, last_at))) = (published, sample.last) {
                let elapsed = at.saturating_duration_since(last_at).as_secs_f64();
                if elapsed > 0.0 {
                    let load = ns.saturating_sub(last_ns) as f64 / 1e9 / elapsed;
                    sample.load = Some(sample.load.map_or(load, |old| (old + load) / 2.0));
                }
            }
            if published.is_some() {
                sample.last = published;
            }
            placed.push(writer.cpu.load(Ordering::Relaxed));
            loads.push(sample.load.unwrap_or(0.0));
        }

        let (writer, cpu) = balance(&self.pool, &placed, &loads, BALANCE_MARGIN)?;
        if writers[writer].refused.load(Ordering::Relaxed) == cpu {
            return None;
        }
        info!(
            "Moving the writer of {} ({:.2} cores) from CPU {} to CPU {}",
            writers[writer].name, loads[writer], placed[writer], cpu
        );
        writers[writer].cpu.store(cpu, Ordering::Relaxed);
        self.moves.fetch_add(1, Ordering::Relaxed);
        Some((writer, cpu))
    }
}

/// Moves writers between the writer CPUs until `stop` is set
pub fn balance_loop(cpus: &WriterCpus, stop: &AtomicBool) {
    crate::avoid_cpus(&cpus.pool);
    let mut last = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        thread::park_timeout(BALANCE_INTERVAL);
        if last.elapsed() < BALANCE_INTERVAL {
            continue;
        }
        last = Instant::now();
        cpus.rebalance();
    }
}

/// Where a file's growth and unmap helpers run
#[derive(Clone)]
pub struct HelperPlacement {
    pub cpus: Arc<WriterCpus>,
    /// The file's writer, None if writers are not pinned
    pub writer: Option<Arc<WriterSlot>>,
}

impl HelperPlacement {
    /// The CPUs for a helper started now, None to inherit the writer's
    pub fn cpu_set(&self) -> Option<libc::cpu_set_t> {
        match &self.writer {
            Some(writer) if self.cpus.balanced() => Some(self.cpus.balanced_helper_set(writer)),
            _ => self.cpus.round_robin_helper_set(),
        }
    }
}

/// A balanced writer's side of its slot: publishes its CPU time and moves to the CPU the
/// balancer chose. Dropping it takes the writer out of the balancing.
pub struct Follower {
    cpus: Arc<WriterCpus>,
    slot: Arc<WriterSlot>,
    pinned: usize,
    last: Instant,
}

impl Follower {
    pub fn new(cpus: Arc<WriterCpus>, slot: Arc<WriterSlot>) -> Self {
        let mut follower = Follower {
            pinned: slot.cpu.load(Ordering::Relaxed),
            cpus,
            slot,
            last: Instant::now(),
        };
        follower.publish();
        follower
    }

    fn publish(&mut self) {
        self.last = Instant::now();
        if let Some(ns) = thread_cpu_ns() {
            self.slot.publish(ns, self.last);
        }
    }

    pub fn tick(&mut self) {
        if self.last.elapsed() < FOLLOW_INTERVAL {
            return;
        }
        self.publish();
        let cpu = self.slot.cpu.load(Ordering::Relaxed);
        if cpu == self.pinned {
            return;
        }
        if pin_to_cpu(cpu) {
            self.pinned = cpu;
        } else {
            // Stay where the writer is, so that the balancer sees where it runs, unless the
            // balancer chose yet another CPU meanwhile; and never try that CPU again
            self.slot.refused.store(cpu, Ordering::Relaxed);
            let _ = self.slot.cpu.compare_exchange(
                cpu,
                self.pinned,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }
}

impl Drop for Follower {
    fn drop(&mut self) {
        self.cpus.remove_writer(&self.slot);
    }
}

/// Pins the calling thread to `cpu_id`, false if that failed
pub fn pin_to_cpu(cpu_id: usize) -> bool {
    let set = cpu_set(&[cpu_id]);
    let ret = unsafe { libc::sched_setaffinity(0, mem::size_of_val(&set), &set) };
    if ret != 0 {
        error!(
            "Failed to pin writer thread to CPU {}: errno {}",
            cpu_id,
            io::Error::last_os_error()
        );
        return false;
    }
    info!("Writer thread pinned to CPU {}", cpu_id);
    true
}

pub fn cpu_set(cpus: &[usize]) -> libc::cpu_set_t {
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for &cpu in cpus {
            libc::CPU_SET(cpu, &mut set);
        }
        set
    }
}

/// CPU time of the calling thread, ns
fn thread_cpu_ns() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    (ret == 0).then(|| ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const MARGIN: f64 = 0.05;

    /// The CPUs the calling thread may run on
    pub fn allowed_cpus() -> Vec<usize> {
        let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
        if unsafe { libc::sched_getaffinity(0, mem::size_of_val(&set), &mut set) } != 0 {
            return Vec::new();
        }
        in_set(&set)
    }

    pub fn in_set(set: &libc::cpu_set_t) -> Vec<usize> {
        (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| unsafe { libc::CPU_ISSET(c, set) })
            .collect()
    }

    /// Moves until nothing is left to move
    fn settle(cpus: &[usize], placed: &mut [usize], loads: &[f64]) -> usize {
        let mut moves = 0;
        while let Some((writer, cpu)) = balance(cpus, placed, loads, MARGIN) {
            placed[writer] = cpu;
            moves += 1;
            assert!(moves <= placed.len() * cpus.len(), "no convergence");
        }
        moves
    }

    /// E5a hk at 16 flows: both busy writers on 26, the second CPU almost idle
    #[test]
    fn busy_writers_are_spread() {
        let cpus = [26, 27];
        let mut placed = [26, 27, 26, 27, 26, 27];
        let loads = [0.05, 0.03, 0.6, 0.03, 0.2, 0.01];
        assert_eq!(balance(&cpus, &placed, &loads, MARGIN), Some((4, 27)));
        settle(&cpus, &mut placed, &loads);
        assert_ne!(placed[2], placed[4]);
        assert!(totals(&cpus, &placed, &loads).iter().all(|&t| t < 0.7));
    }

    /// The busiest writer gets a CPU of its own, in one move
    #[test]
    fn the_busiest_writer_gets_its_own_cpu() {
        let cpus = [0, 1];
        let mut placed = [0, 0, 0];
        assert_eq!(settle(&cpus, &mut placed, &[0.7, 0.1, 0.1]), 1);
        assert_ne!(placed[0], placed[1]);
        assert_eq!(placed[1], placed[2]);
    }

    /// Two writers that share a CPU measure at most one core together
    #[test]
    fn writers_sharing_a_full_cpu_split() {
        let mut placed = [0, 0];
        assert_eq!(settle(&[0, 1], &mut placed, &[0.5, 0.5]), 1);
        assert_ne!(placed[0], placed[1]);
    }

    #[test]
    fn small_gains_move_nothing() {
        // Moving the 0.03 writer would lower the maximum by only 0.03 core
        assert_eq!(
            balance(&[0, 1], &[0, 0, 1], &[0.5, 0.03, 0.47], MARGIN),
            None
        );
    }

    #[test]
    fn balanced_writers_stay() {
        assert_eq!(
            balance(&[0, 1], &[0, 1, 0, 1], &[0.4, 0.4, 0.1, 0.1], MARGIN),
            None
        );
        // Idle writers right after the start
        assert_eq!(balance(&[0, 1], &[0, 1, 0], &[0.0; 3], MARGIN), None);
        // One writer more than a CPU can hold has nowhere better to go
        assert_eq!(balance(&[0, 1], &[0, 1], &[1.0, 0.1], MARGIN), None);
    }

    #[test]
    fn one_cpu_or_no_writer_has_nothing_to_balance() {
        assert_eq!(balance(&[3], &[3, 3], &[0.9, 0.9], MARGIN), None);
        assert_eq!(balance(&[0, 1], &[], &[], MARGIN), None);
    }

    #[test]
    fn three_cpus_converge() {
        let cpus = [0, 1, 2];
        let loads = [0.9, 0.8, 0.7, 0.2, 0.1, 0.1];
        let mut placed = [0; 6];
        settle(&cpus, &mut placed, &loads);
        let totals = totals(&cpus, &placed, &loads);
        assert!(totals.iter().all(|&t| t <= 1.0 + 1e-9), "{totals:?}");
    }

    #[test]
    fn helpers_prefer_cpus_without_a_writer() {
        assert_eq!(
            helper_cpus(&[0, 1, 2], &[0, 0], &[0.5, 0.1], 0, 0.5),
            [1, 2]
        );
    }

    /// E5a k at 16 flows: the send writer's helper ran on its CPU, 26
    #[test]
    fn helpers_avoid_a_busy_writer() {
        let cpus = [26, 27];
        let placed = [26, 27, 27];
        let loads = [0.7, 0.1, 0.02];
        assert_eq!(helper_cpus(&cpus, &placed, &loads, 26, 0.7), [27]);
        // The light writers' helpers stay away from the send writer too
        assert_eq!(helper_cpus(&cpus, &placed, &loads, 27, 0.1), [27]);
        // Two busy CPUs: the other one
        let loads = [0.7, 0.8, 0.0];
        assert_eq!(helper_cpus(&cpus, &placed, &loads, 26, 0.7), [27]);
    }

    #[test]
    fn a_single_cpu_is_shared() {
        assert_eq!(helper_cpus(&[5], &[5, 5], &[0.9, 0.1], 5, 0.9), [5]);
    }

    /// Writers on `cpus`, each with a first publication at `start`
    fn writers(
        pool: &[usize],
        cpus: &[usize],
        start: Instant,
    ) -> (WriterCpus, Vec<Arc<WriterSlot>>) {
        let writer_cpus = WriterCpus::new(pool.to_vec(), Placement::Balanced);
        let slots = cpus
            .iter()
            .map(|&cpu| {
                let slot = writer_cpus.add_writer(cpu, "w");
                slot.publish(1, start);
                slot
            })
            .collect();
        (writer_cpus, slots)
    }

    /// Publishes CPU times as if each writer used `loads` cores until `at`
    fn publish_cpu_time(slots: &[Arc<WriterSlot>], loads: &[f64], since: Instant, at: Instant) {
        for (slot, load) in slots.iter().zip(loads) {
            let (ns, _) = lock(&slot.published).unwrap();
            let used = (load * (at - since).as_secs_f64() * 1e9) as u64;
            slot.publish(ns + used, at);
        }
    }

    /// E5a hk at 16 flows: the two busy writers started on one CPU
    #[test]
    fn rebalance_moves_a_busy_writer_once() {
        let t0 = Instant::now();
        let (t1, t2) = (t0 + BALANCE_INTERVAL, t0 + 2 * BALANCE_INTERVAL);
        let (cpus, slots) = writers(&[26, 27], &[26, 27, 26], t0);
        // The first round only takes the CPU times
        assert_eq!(cpus.rebalance(), None);
        publish_cpu_time(&slots, &[0.6, 0.02, 0.4], t0, t1);
        let (writer, cpu) = cpus.rebalance().unwrap();
        assert_eq!(cpu, 27);
        assert_eq!(slots[writer].cpu.load(Ordering::Relaxed), 27);
        assert_ne!(
            slots[0].cpu.load(Ordering::Relaxed),
            slots[2].cpu.load(Ordering::Relaxed)
        );
        // Spread now, nothing more to move
        publish_cpu_time(&slots, &[0.6, 0.02, 0.4], t1, t2);
        assert_eq!(cpus.rebalance(), None);
        assert_eq!(cpus.moves.load(Ordering::Relaxed), 1);
    }

    /// The load is the writer's CPU time over the writer's own time between publications,
    /// also when the balancer runs late or a writer has not published again
    #[test]
    fn loads_use_the_writers_timestamps() {
        let t0 = Instant::now();
        let (cpus, slots) = writers(&[0, 1], &[0, 0], t0);
        cpus.rebalance();
        // Published 30 ms later at 0.8 cores; the second writer did not publish again
        let t1 = t0 + Duration::from_millis(30);
        publish_cpu_time(&slots[..1], &[0.8], t0, t1);
        cpus.rebalance();
        assert!((slots[0].load() - 0.8).abs() < 1e-6);
        assert_eq!(slots[1].load(), 0.0);
        // A writer that never published counts as idle
        let silent = cpus.add_writer(1, "silent");
        cpus.rebalance();
        assert_eq!(silent.load(), 0.0);
    }

    /// E5a k at 16 flows: the send writer's helpers ran on its CPU
    #[test]
    fn balanced_helpers_avoid_their_busy_writer() {
        let t0 = Instant::now();
        let (cpus, slots) = writers(&[26, 27], &[26, 27, 26], t0);
        cpus.rebalance();
        publish_cpu_time(&slots, &[0.7, 0.1, 0.02], t0, t0 + BALANCE_INTERVAL);
        cpus.rebalance();
        let helpers = HelperPlacement {
            cpus: Arc::new(cpus),
            writer: Some(slots[0].clone()),
        };
        assert_eq!(in_set(&helpers.cpu_set().unwrap()), [27]);
        // Round-robin keeps the old rule: every CPU has a writer, so the whole pool
        let round_robin = WriterCpus::new(vec![26, 27], Placement::RoundRobin);
        let writer = round_robin.add_writer(26, "w");
        round_robin.add_writer(27, "w");
        let helpers = HelperPlacement {
            cpus: Arc::new(round_robin),
            writer: Some(writer),
        };
        assert_eq!(in_set(&helpers.cpu_set().unwrap()), [26, 27]);
        assert!(WriterCpus::default().round_robin_helper_set().is_none());
    }

    /// A writer moves itself to the CPU in its slot, publishes its CPU time, and leaves the
    /// balancing when it stops
    #[test]
    fn follower_moves_to_its_slot_cpu() {
        let online = allowed_cpus();
        if online.len() < 2 {
            return;
        }
        let (first, second) = (online[0], online[1]);
        let cpus = Arc::new(WriterCpus::new(vec![first, second], Placement::Balanced));
        let writer_slot = cpus.add_writer(first, "w");
        let (theirs, their_cpus) = (writer_slot.clone(), cpus.clone());
        let allowed = thread::spawn(move || {
            pin_to_cpu(first);
            let mut follower = Follower::new(their_cpus, theirs.clone());
            assert!(lock(&theirs.published).is_some());
            theirs.cpu.store(second, Ordering::Relaxed);
            thread::sleep(FOLLOW_INTERVAL * 2);
            follower.tick();
            allowed_cpus()
        })
        .join()
        .unwrap();
        assert_eq!(allowed, [second]);
        assert!(lock(&cpus.writers).is_empty());
    }

    /// A move the writer cannot make is taken back, so the balancer sees where it runs
    #[test]
    fn a_failed_move_is_taken_back() {
        let online = allowed_cpus();
        let first = online[0];
        let cpus = Arc::new(WriterCpus::new(vec![first], Placement::Balanced));
        let slot = cpus.add_writer(first, "w");
        let theirs = slot.clone();
        thread::spawn(move || {
            pin_to_cpu(first);
            let mut follower = Follower::new(cpus, theirs.clone());
            // An offline CPU on any host with fewer than CPU_SETSIZE CPUs: the pin fails
            theirs
                .cpu
                .store(libc::CPU_SETSIZE as usize - 1, Ordering::Relaxed);
            thread::sleep(FOLLOW_INTERVAL * 2);
            follower.tick();
        })
        .join()
        .unwrap();
        assert_eq!(slot.cpu.load(Ordering::Relaxed), first);
        assert_eq!(
            slot.refused.load(Ordering::Relaxed),
            libc::CPU_SETSIZE as usize - 1
        );
    }

    /// The balancer does not send a writer to a CPU it could not move to
    #[test]
    fn a_refused_cpu_is_not_proposed_again() {
        let t0 = Instant::now();
        let (cpus, slots) = writers(&[0, 1], &[0, 0], t0);
        cpus.rebalance();
        publish_cpu_time(&slots, &[0.6, 0.5], t0, t0 + BALANCE_INTERVAL);
        let (writer, cpu) = cpus.rebalance().unwrap();
        slots[writer].refused.store(cpu, Ordering::Relaxed);
        slots[writer].cpu.store(0, Ordering::Relaxed);
        publish_cpu_time(
            &slots,
            &[0.6, 0.5],
            t0 + BALANCE_INTERVAL,
            t0 + 2 * BALANCE_INTERVAL,
        );
        assert_eq!(cpus.rebalance(), None);
    }

    /// A load that drops is smoothed over two rounds and moves nothing back
    #[test]
    fn a_falling_load_is_smoothed() {
        let t0 = Instant::now();
        let (t1, t2) = (t0 + BALANCE_INTERVAL, t0 + 2 * BALANCE_INTERVAL);
        let (cpus, slots) = writers(&[0, 1], &[0, 1], t0);
        cpus.rebalance();
        publish_cpu_time(&slots, &[0.6, 0.3], t0, t1);
        assert_eq!(cpus.rebalance(), None);
        publish_cpu_time(&slots, &[0.2, 0.3], t1, t2);
        assert_eq!(cpus.rebalance(), None);
        assert!((slots[0].load() - 0.4).abs() < 1e-6);
    }

    /// A stopped writer's CPU is free for helpers again
    #[test]
    fn a_stopped_writer_frees_its_cpu() {
        let cpus = Arc::new(WriterCpus::new(vec![0, 1], Placement::Balanced));
        let busy = cpus.add_writer(0, "busy");
        let stopped = cpus.add_writer(1, "stopped");
        cpus.remove_writer(&stopped);
        let helpers = HelperPlacement {
            cpus,
            writer: Some(busy),
        };
        assert_eq!(in_set(&helpers.cpu_set().unwrap()), [1]);
    }
}
