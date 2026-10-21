//! Throughput benchmark of the writer's storage path, without eBPF: writer threads feed
//! synthetic records through `MapWriterJob::write` (what the ring buffer callback calls) as
//! fast as they can, or at a fixed rate, into files in a target directory. It reports the
//! throughput, the CPU it costs and how busy the disk was, so that a run on tmpfs (no disk)
//! and one on a disk tell whether the CPU or the disk limits recording. The cost of reading
//! the ring buffers is not included.
//!
//! ```text
//! TCBEE_BENCH_DIR=/dev/shm cargo test --release --bin tcbee-record writer::bench -- --ignored --nocapture
//! ```
//!
//! Environment: `TCBEE_BENCH_DIR` (required), `TCBEE_BENCH_SECS` (default 20),
//! `TCBEE_BENCH_FILES` (writer threads, one file each, default 1), `TCBEE_BENCH_RECORD`
//! (sock, tcp4 or cwnd, default sock), `TCBEE_BENCH_RATE` (records/s per file, 0 = as fast
//! as possible), `TCBEE_BENCH_CPUS` (cores to pin the writers to, round robin),
//! `TCBEE_BENCH_IDLE_SECS` (host CPU measured before the run as a baseline, default 2),
//! `TCBEE_BENCH_OUT` (append the JSON result to this file), `TCBEE_BENCH_MAX_GB` (stop when
//! the files hold this much; by default 40 % of what the directory can hold after the writer's
//! preallocation, which keeps about twice the data plus up to 1 GiB per file allocated). A run
//! that hits the cap before `TCBEE_BENCH_SECS` says so (`size_capped`). On a tmpfs that is small
//! against the write rate the runs end within seconds: they give the CPU cost per MB without a
//! disk (`writer_ns_per_mb`), not a sustained rate. The files are removed
//! after the end of the measurement, also when a writer fails.
//!
//! Reading the numbers: the cost per MB `c` for "lossless rate = min(B, 1 core / c)" comes from
//! the disk run (writer or host ns per MB; tmpfs has no page faults on file pages, dirty
//! throttling or writeback), `B` from the disk's own steady MB/s (`disk_mbps_steady`), not from
//! the writer's. A disk util near 1 only says that I/O was in flight all the time; whether the
//! device was saturated needs its queue (`avg_queue`) and a comparison with its sequential write
//! bandwidth (e.g. fio, see `testing/writer_bench.sh`). The record pool is small and stays in
//! the cache, so real ring buffer reads cost more than this.

use std::{
    collections::BTreeMap, env, io::Write as _, os::unix::fs::MetadataExt, sync::Mutex,
    time::Instant,
};

use serde_json::{json, Value};
use tcbee_common::records::*;

use super::*;

/// Distinct records each thread cycles through (random contents)
const POOL: usize = 4096;
/// Records between two looks at the clock
const BATCH: u64 = 1024;

struct Config {
    dir: PathBuf,
    secs: f64,
    files: usize,
    record: String,
    rate: f64,
    cpus: Vec<usize>,
    idle_secs: f64,
    out: Option<PathBuf>,
    max_bytes: u64,
}

impl Config {
    fn from_env() -> Self {
        let var = |k: &str| env::var(k).ok().filter(|v| !v.is_empty());
        let num = |k: &str, d: f64| var(k).map(|v| v.parse().expect(k)).unwrap_or(d);
        Config {
            dir: var("TCBEE_BENCH_DIR").expect("set TCBEE_BENCH_DIR").into(),
            secs: num("TCBEE_BENCH_SECS", 20.0),
            files: num("TCBEE_BENCH_FILES", 1.0) as usize,
            record: var("TCBEE_BENCH_RECORD").unwrap_or_else(|| "sock".into()),
            rate: num("TCBEE_BENCH_RATE", 0.0),
            cpus: var("TCBEE_BENCH_CPUS")
                .map(|v| {
                    v.split(',')
                        .map(|c| c.trim().parse().expect("TCBEE_BENCH_CPUS"))
                        .collect()
                })
                .unwrap_or_default(),
            idle_secs: num("TCBEE_BENCH_IDLE_SECS", 2.0),
            out: var("TCBEE_BENCH_OUT").map(PathBuf::from),
            max_bytes: (num("TCBEE_BENCH_MAX_GB", 0.0) * 1e9) as u64,
        }
    }
}

/// Free bytes of the file system a directory is on
fn free_bytes(dir: &Path) -> u64 {
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
    let mut st: libc::statvfs = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::statvfs(c.as_ptr(), &mut st) },
        0,
        "statvfs {}",
        dir.display()
    );
    st.f_bavail as u64 * st.f_frsize as u64
}

/// Removes a file when dropped, also when the thread panics
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Sets a flag when dropped, also when the thread panics
struct SetOnDrop<'a>(&'a AtomicBool);

impl Drop for SetOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Pins the calling thread to one core; fails the benchmark if that is not possible
fn pin(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        let ret = libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &set);
        assert_eq!(ret, 0, "pin to CPU {cpu}: {}", io::Error::last_os_error());
    }
}

/// True if the directory is on tmpfs
fn on_tmpfs(dir: &Path) -> bool {
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
    let mut st: libc::statfs = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::statfs(c.as_ptr(), &mut st) },
        0,
        "statfs {}",
        dir.display()
    );
    st.f_type == libc::TMPFS_MAGIC
}

/// CPU time (user + system) in ns of the calling thread or of the whole process, which
/// includes threads that have exited, like the growth helpers
fn cpu_ns(who: libc::c_int) -> u64 {
    let mut ru: libc::rusage = unsafe { mem::zeroed() };
    unsafe { libc::getrusage(who, &mut ru) };
    let ns = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1000;
    ns(ru.ru_utime) + ns(ru.ru_stime)
}

/// Per-core jiffies from /proc/stat: user nice system idle iowait irq softirq steal
fn proc_stat() -> BTreeMap<String, Vec<u64>> {
    fs::read_to_string("/proc/stat")
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("cpu"))
        .map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next().unwrap().to_string();
            (name, it.take(8).map(|x| x.parse().unwrap()).collect())
        })
        .collect()
}

/// The block devices a directory is stored on: its own device (partition or dm/LVM volume)
/// and every device below it, down to the whole disks. Empty for tmpfs.
fn devices(dir: &Path) -> Vec<String> {
    let mut dev = fs::metadata(dir).unwrap().dev();
    if libc::major(dev) == 0 {
        // btrfs, ZFS and overlay give an anonymous device: take the mount's source device
        let src = std::process::Command::new("findmnt")
            .args(["-no", "SOURCE", "-T"])
            .arg(dir)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        // btrfs shows subvolumes as /dev/x[/subvol]
        let src = src.split('[').next().unwrap_or("");
        if let Ok(m) = fs::metadata(src) {
            dev = m.rdev();
        }
    }
    let (major, minor) = (libc::major(dev), libc::minor(dev));
    let Ok(sys) = fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut todo = vec![sys];
    while let Some(d) = todo.pop() {
        let name = d.file_name().unwrap().to_string_lossy().to_string();
        if out.contains(&name) {
            continue;
        }
        out.push(name);
        if d.join("partition").exists() {
            todo.push(d.parent().unwrap().to_path_buf());
        }
        if let Ok(slaves) = fs::read_dir(d.join("slaves")) {
            todo.extend(
                slaves
                    .flatten()
                    .filter_map(|s| fs::canonicalize(s.path()).ok()),
            );
        }
    }
    out
}

/// /proc/diskstats fields after the name, for the given devices
fn diskstats(devs: &[String]) -> BTreeMap<String, Vec<u64>> {
    fs::read_to_string("/proc/diskstats")
        .unwrap()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            devs.iter().any(|d| d == f[2]).then(|| {
                (
                    f[2].to_string(),
                    f[3..].iter().map(|x| x.parse().unwrap()).collect(),
                )
            })
        })
        .collect()
}

fn meminfo_kb(key: &str) -> u64 {
    fs::read_to_string("/proc/meminfo")
        .unwrap()
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn busy(a: &[u64], b: &[u64]) -> (u64, u64, u64) {
    let d: Vec<u64> = a.iter().zip(b).map(|(x, y)| y - x).collect();
    let total: u64 = d.iter().sum();
    // busy = everything but idle, iowait and steal (time a hypervisor gave to others)
    (total - d[3] - d[4] - d[7], d[4], total)
}

struct ThreadResult {
    records: u64,
    /// stopped by the size limit before TCBEE_BENCH_SECS
    size_capped: bool,
    write_secs: f64,
    finish_secs: f64,
    /// CPU of the write phase and of the final flush (msync, truncate, fsync)
    cpu_ns: u64,
    finish_cpu_ns: u64,
    /// removes the file when dropped, after the run's end snapshots
    file: Option<RemoveOnDrop>,
}

fn writer_thread<T>(cfg: &Config, idx: usize, count: &AtomicU64) -> ThreadResult
where
    T: Serialize + Copy + Send + 'static,
{
    if !cfg.cpus.is_empty() {
        pin(cfg.cpus[idx % cfg.cpus.len()]);
    }
    let path = cfg
        .dir
        .join(format!("tcbee-bench-{}-{idx}.tcp", std::process::id()));
    let file = RemoveOnDrop(path.clone());
    let mut job = MapWriterJob::<T>::new(path.clone(), Arc::new(AtomicU64::new(0))).unwrap();
    let size = mem::size_of::<T>();
    let limit =
        cfg.max_bytes / cfg.files as u64 / (job.record_size + RECORD_DELIMITER.len()) as u64;
    let mut rng = tests::Rng(0x2545_F491 ^ idx as u64);
    let pool = rng.bytes(size * POOL);

    let cpu0 = cpu_ns(libc::RUSAGE_THREAD);
    let start = Instant::now();
    let mut n: u64 = 0;
    let mut size_capped = false;
    loop {
        for _ in 0..BATCH {
            let i = (n as usize) % POOL;
            assert_eq!(
                job.write(&pool[i * size..(i + 1) * size]),
                0,
                "write failed: {:?}",
                job.error
            );
            n += 1;
        }
        count.store(n, Ordering::Relaxed);
        let t = start.elapsed().as_secs_f64();
        if t >= cfg.secs {
            break;
        }
        if n >= limit {
            size_capped = true;
            break;
        }
        if cfg.rate > 0.0 {
            let ahead = n as f64 / cfg.rate - t;
            if ahead > 0.0 {
                thread::sleep(Duration::from_secs_f64(ahead));
            }
        }
    }
    let write_secs = start.elapsed().as_secs_f64();
    let cpu1 = cpu_ns(libc::RUSAGE_THREAD);
    job.flush().unwrap();
    let finish_secs = start.elapsed().as_secs_f64() - write_secs;
    ThreadResult {
        records: n,
        size_capped,
        write_secs,
        finish_secs,
        cpu_ns: cpu1 - cpu0,
        finish_cpu_ns: cpu_ns(libc::RUSAGE_THREAD) - cpu1,
        file: Some(file),
    }
}

fn run<T>(cfg: &Config) -> Value
where
    T: Serialize + Copy + Send + 'static,
{
    let record_bytes = bincode::serialized_size(&unsafe { mem::zeroed::<T>() }).unwrap() as usize
        + RECORD_DELIMITER.len();
    let devs = devices(&cfg.dir);
    let vm_num = |k: &str| -> u64 {
        fs::read_to_string(format!("/proc/sys/vm/{k}"))
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    };
    let avail_kb = meminfo_kb("MemAvailable:");
    let limit = |bytes: &str, ratio: &str| match vm_num(bytes) {
        0 => vm_num(ratio) * avail_kb / 100,
        b => b / 1024,
    };
    let dirty_limit_kb = limit("dirty_bytes", "dirty_ratio");
    // balance_dirty_pages throttles writers around the midpoint of the background threshold and
    // the limit, so Dirty settles there, not at the limit
    let dirty_setpoint_kb =
        (dirty_limit_kb + limit("dirty_background_bytes", "dirty_background_ratio")) / 2;

    // host CPU while idle, so the cost of the run can be told from background load
    let idle0 = proc_stat();
    thread::sleep(Duration::from_secs_f64(cfg.idle_secs));
    let idle1 = proc_stat();
    let (ib, _, it) = busy(&idle0["cpu"], &idle1["cpu"]);
    let ncpu = idle1.len() - 1;
    let idle_busy_cores = ib as f64 / it as f64 * ncpu as f64;

    let counts: Vec<AtomicU64> = (0..cfg.files).map(|_| AtomicU64::new(0)).collect();
    let done = AtomicBool::new(false);
    // (t, records, Dirty kB, Writeback kB, sectors written to the target's device)
    let series: Mutex<Vec<(f64, u64, u64, u64, u64)>> = Mutex::new(Vec::new());
    let target = devs.first().cloned();
    let sectors = || {
        target
            .as_ref()
            .and_then(|d| diskstats(std::slice::from_ref(d)).remove(d))
            .map_or(0, |f| f[6])
    };
    let (stat0, disk0, proc0) = (proc_stat(), diskstats(&devs), cpu_ns(libc::RUSAGE_SELF));
    let start = Instant::now();
    let results: Vec<ThreadResult> = thread::scope(|s| {
        // the monitor must end even if a writer panics, or the scope never returns
        let _stop = SetOnDrop(&done);
        // records written, Dirty and Writeback every 100 ms
        s.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                let n = counts.iter().map(|c| c.load(Ordering::Relaxed)).sum();
                series.lock().unwrap().push((
                    start.elapsed().as_secs_f64(),
                    n,
                    meminfo_kb("Dirty:"),
                    meminfo_kb("Writeback:"),
                    sectors(),
                ));
                thread::sleep(Duration::from_millis(100));
            }
        });
        let handles: Vec<_> = (0..cfg.files)
            .map(|i| {
                let c = &counts[i];
                s.spawn(move || writer_thread::<T>(cfg, i, c))
            })
            .collect();
        let r = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // the end snapshots are taken before the files are removed: unlinking GBs takes time
        done.store(true, Ordering::Relaxed);
        r
    });
    let total_secs = start.elapsed().as_secs_f64();
    let (stat1, disk1, proc1) = (proc_stat(), diskstats(&devs), cpu_ns(libc::RUSAGE_SELF));
    let mut results = results;
    for r in &mut results {
        r.file.take();
    }

    let records: u64 = results.iter().map(|r| r.records).sum();
    let mb = (records * record_bytes as u64) as f64 / 1e6;
    let write_secs = results.iter().map(|r| r.write_secs).fold(0.0, f64::max);
    let writer_cpu_ns: u64 = results.iter().map(|r| r.cpu_ns).sum();
    let finish_cpu_ns: u64 = results.iter().map(|r| r.finish_cpu_ns).sum();
    let proc_cpu_ns = proc1 - proc0;

    // Per second of the write phase (the final flush is not part of it): the writer's MB/s
    // and the MB/s that reached the target's device. Steady state: the second half of the write
    // phase, and for a disk only after Dirty reached 90 % of its maximum (the page cache filled
    // up to the dirty limit); before that the writer runs at memory speed.
    let series = series.into_inner().unwrap();
    let in_write: Vec<_> = series.iter().filter(|s| s.0 <= write_secs).collect();
    let mut per_sec = Vec::new();
    let mut disk_per_sec = Vec::new();
    let mut last = (0.0, 0u64, in_write.first().map_or(0, |s| s.4));
    for &&(t, n, _, _, sec) in &in_write {
        if t - last.0 >= 1.0 {
            let dt = t - last.0;
            per_sec.push((t, (n - last.1) as f64 * record_bytes as f64 / 1e6 / dt));
            disk_per_sec.push((t, (sec - last.2) as f64 * 512.0 / 1e6 / dt));
            last = (t, n, sec);
        }
    }
    // The steady state of a disk run starts once Dirty is near the kernel's throttling setpoint
    // (from vm.dirty_bytes/dirty_ratio and the background ones, ratios of the memory available at
    // the start, which is close to the kernel's dirtyable memory). A run that never gets there
    // wrote into memory only: no steady MB/s then.
    let dirty_max = in_write.iter().map(|s| s.2).max().unwrap_or(0);
    let limit_reached = |t: &&&(f64, u64, u64, u64, u64)| t.2 * 10 >= dirty_setpoint_kb * 9;
    let plateau = in_write.iter().find(limit_reached).map(|s| s.0);
    let disk_run = !devs.is_empty();
    let plateau_t = if disk_run {
        plateau.unwrap_or(write_secs)
    } else {
        0.0
    };
    let from = plateau_t.max(write_secs / 2.0);
    let median = |v: &[(f64, f64)]| {
        let mut x: Vec<f64> = v
            .iter()
            .filter(|(t, _)| *t > from)
            .map(|(_, r)| *r)
            .collect();
        x.sort_by(|a, b| a.partial_cmp(b).unwrap());
        x.get(x.len() / 2).copied()
    };
    let (steady_mbps, disk_steady_mbps) = match (disk_run, plateau) {
        (false, _) => (median(&per_sec), None),
        (true, Some(_)) => (median(&per_sec), median(&disk_per_sec)),
        (true, None) => (None, None),
    };
    // in the steady state the writer can only go as fast as the disk takes the data
    let steady_consistent = match (steady_mbps, disk_steady_mbps) {
        (Some(w), Some(d)) if d > 0.0 => Some((w / d - 1.0).abs() <= 0.15),
        _ => None,
    };

    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let mut cores = BTreeMap::new();
    for (name, a) in &stat0 {
        let (b, w, t) = busy(a, &stat1[name]);
        cores.insert(
            name.clone(),
            json!({"busy": b as f64 / t as f64, "iowait": w as f64 / t as f64}),
        );
    }
    let (hb, hw, _) = busy(&stat0["cpu"], &stat1["cpu"]);
    let host_busy_cores = hb as f64 / tck / total_secs;
    let mut disks = BTreeMap::new();
    for (d, a) in &disk0 {
        let b = &disk1[d];
        let dd: Vec<u64> = a.iter().zip(b).map(|(x, y)| y - x).collect();
        disks.insert(
            d.clone(),
            json!({
                "mb_written": dd[6] as f64 * 512.0 / 1e6,
                "writes": dd[4],
                "util": dd[9] as f64 / (total_secs * 1000.0),
                "avg_queue": dd[10] as f64 / (total_secs * 1000.0),
            }),
        );
    }
    let vm = |k: &str| {
        fs::read_to_string(format!("/proc/sys/vm/{k}"))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let ns_per_mb = |ns: f64| if mb > 0.0 { ns / mb } else { 0.0 };

    // in parts: one json! of all keys exceeds the macro recursion limit
    let mut out = json!({
        "record": cfg.record, "record_bytes": record_bytes, "files": cfg.files, "dir": cfg.dir,
        "devices": devs, "tmpfs": on_tmpfs(&cfg.dir), "rate_per_file": cfg.rate, "cpus": cfg.cpus, "secs": cfg.secs,
        "max_bytes": cfg.max_bytes, "size_capped": results.iter().any(|r| r.size_capped),
    });
    let throughput = json!({
        "records": records, "mb": mb,
        "write_secs": write_secs, "total_secs": total_secs,
        "finish_secs_max": results.iter().map(|r| r.finish_secs).fold(0.0, f64::max),
        "records_per_s": records as f64 / write_secs,
        "mbps_write": mb / write_secs,
        "mbps_durable": mb / total_secs,
        "mbps_steady": steady_mbps,
        "mbps_per_sec": per_sec.iter().map(|x| x.1).collect::<Vec<_>>(),
        "disk_mbps_steady": disk_steady_mbps,
        "disk_mbps_per_sec": disk_per_sec.iter().map(|x| x.1).collect::<Vec<_>>(),
        "dirty_plateau_secs": plateau_t, "steady_from_secs": from,
        "dirty_limit_kb": dirty_limit_kb, "dirty_setpoint_kb": dirty_setpoint_kb,
        "dirty_limit_reached": plateau.is_some(),
        "steady_consistent": steady_consistent,
    });
    out.as_object_mut()
        .unwrap()
        .extend(throughput.as_object().unwrap().clone());
    let cpu = json!({
        "writer_cores": writer_cpu_ns as f64 / 1e9 / write_secs,
        "writer_cores_per_thread": results.iter().map(|r| r.cpu_ns as f64 / 1e9 / r.write_secs).collect::<Vec<_>>(),
        // writer_cores is the write phase; the flush CPU is separate; process and host cores are
        // over the whole run including the final flush
        "writer_finish_cpu_secs": finish_cpu_ns as f64 / 1e9,
        "process_cores": proc_cpu_ns as f64 / 1e9 / total_secs,
        "host_busy_cores": host_busy_cores,
        "host_iowait_cores": hw as f64 / tck / total_secs,
        "host_idle_busy_cores": idle_busy_cores,
        "writer_ns_per_mb": ns_per_mb(writer_cpu_ns as f64),
        "process_ns_per_mb": ns_per_mb(proc_cpu_ns as f64),
        "host_ns_per_mb": ns_per_mb((host_busy_cores - idle_busy_cores).max(0.0) * total_secs * 1e9),
    });
    out.as_object_mut()
        .unwrap()
        .extend(cpu.as_object().unwrap().clone());
    let host = json!({
        "cores": cores,
        "disks": disks,
        "dirty_kb_max": dirty_max,
        "writeback_kb_max": series.iter().map(|s| s.3).max(),
        "vm": {"dirty_ratio": vm("dirty_ratio"), "dirty_background_ratio": vm("dirty_background_ratio"),
               "dirty_bytes": vm("dirty_bytes"), "dirty_expire_centisecs": vm("dirty_expire_centisecs")},
        "mem_total_kb": meminfo_kb("MemTotal:"),
    });
    out.as_object_mut()
        .unwrap()
        .extend(host.as_object().unwrap().clone());
    out
}

#[test]
#[ignore = "benchmark, needs TCBEE_BENCH_DIR"]
fn bench_writer_throughput() {
    let mut cfg = Config::from_env();
    if cfg.max_bytes == 0 {
        // the files grow in preallocated steps of up to MAX_MMAP_GROWTH ahead of the data
        // a file keeps about twice its data plus up to MAX_MMAP_GROWTH allocated (it grows when
        // half full, by its size, at most MAX_MMAP_GROWTH); 40 % of that bound leaves a margin
        let reserve = cfg.files as u64 * MAX_MMAP_GROWTH as u64;
        cfg.max_bytes = free_bytes(&cfg.dir).saturating_sub(reserve) / 2 * 2 / 5;
    }
    if !on_tmpfs(&cfg.dir) && devices(&cfg.dir).is_empty() {
        eprintln!(
            "warning: no block device found for {}: no disk statistics",
            cfg.dir.display()
        );
    }
    let res = match cfg.record.as_str() {
        "sock" => run::<sock_trace_entry>(&cfg),
        "tcp4" => run::<tcp4_packet_trace>(&cfg),
        "cwnd" => run::<cwnd_trace_entry>(&cfg),
        other => panic!("TCBEE_BENCH_RECORD {other}: sock, tcp4 or cwnd"),
    };
    let f = |k: &str| res[k].as_f64().unwrap_or(f64::NAN);
    println!(
        "{} x{} on {}: {:.0} MB/s write, {:.0} MB/s steady (disk {:.0}), {:.0} MB/s durable; \
         writer {:.2} cores, process {:.2}, host {:.2} (idle {:.2}); {:.0} ns/MB writer, {:.0} ns/MB host{}",
        cfg.record, cfg.files, cfg.dir.display(), f("mbps_write"), f("mbps_steady"),
        f("disk_mbps_steady"), f("mbps_durable"), f("writer_cores"), f("process_cores"),
        f("host_busy_cores"), f("host_idle_busy_cores"), f("writer_ns_per_mb"), f("host_ns_per_mb"),
        if res["size_capped"].as_bool().unwrap() {
            format!(" [size-capped after {:.1} s]", f("write_secs"))
        } else {
            String::new()
        }
    );
    for (d, v) in res["disks"].as_object().unwrap() {
        println!(
            "  {d}: util {:.2}, avg queue {:.1}, {:.0} MB written",
            v["util"].as_f64().unwrap(),
            v["avg_queue"].as_f64().unwrap(),
            v["mb_written"].as_f64().unwrap()
        );
    }
    let line = res.to_string();
    println!("{line}");
    if let Some(out) = &cfg.out {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }
}
