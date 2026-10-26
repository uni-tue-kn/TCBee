//! `flow_owners.json`: what the recorder learned about the processes of the connections apart
//! from the owner records (`flow_owners.tcp`). The connections that already existed when the
//! recording started, with the processes that held them, as netstat or `ss -p` find them; and
//! the command lines of the processes, which the records do not carry.

use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::SocketAddr,
    path::Path,
};

use serde::{Deserialize, Serialize};

pub const FLOW_OWNERS_FILE: &str = "flow_owners.json";
pub const FLOW_OWNERS_FORMAT: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FlowOwners {
    pub format: u32,
    /// When the snapshot of the existing connections started and ended, ns of CLOCK_MONOTONIC
    /// (the clock of the records). The owner programs ran already, so a connection opened
    /// meanwhile can be in both.
    pub snapshot_ns: u64,
    #[serde(default)]
    pub snapshot_end_ns: u64,
    /// Clock ticks per second, the unit of `ProcessInfo::start_ticks`
    pub clock_ticks: u64,
    /// The TCP connections that existed at the start, listeners left out
    pub connections: Vec<SnapshotConnection>,
    /// The processes of the snapshot and of the owner records, each once per pid and start
    pub processes: Vec<ProcessInfo>,
}

/// A connection of the snapshot, from `/proc/<pid>/net/tcp{,6}` of its network namespace
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotConnection {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Inode number of the network namespace, as in the owner records
    pub netns: u32,
    /// TCP state, e.g. `ESTABLISHED`
    pub state: String,
    /// The uid that owns the socket
    pub uid: u32,
    /// Inode of the socket
    pub inode: u64,
    /// The processes holding the socket open (an fd of theirs refers to it); empty if none
    /// does (a kernel socket), or the process exited before it was looked at
    pub holders: Vec<Holder>,
}

/// A process that holds a socket, named by pid and start as in `ProcessInfo`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Holder {
    pub pid: u32,
    pub start_ticks: u64,
}

/// A process, from `/proc/<pid>`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    /// When the process started, in clock ticks since boot (`/proc/<pid>/stat`). With the pid
    /// it names the process: pids are reused.
    pub start_ticks: u64,
    pub comm: String,
    /// Empty for a kernel thread, or if it could not be read
    pub cmdline: Vec<String>,
    pub uid: Option<u32>,
    /// cgroup v2 path
    pub cgroup: Option<String>,
}

impl FlowOwners {
    pub fn new(snapshot_ns: u64, clock_ticks: u64) -> FlowOwners {
        FlowOwners {
            format: FLOW_OWNERS_FORMAT,
            snapshot_ns,
            clock_ticks,
            ..FlowOwners::default()
        }
    }

    pub fn write(&self, dir: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(dir.join(FLOW_OWNERS_FILE), json)
    }

    /// None if the recording has none (recorded with `--no-owners` or before owners existed)
    pub fn read(dir: &Path) -> io::Result<Option<FlowOwners>> {
        match fs::read_to_string(dir.join(FLOW_OWNERS_FILE)) {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Adds the processes that are not listed yet (by pid and start)
    pub fn add_processes(&mut self, processes: impl IntoIterator<Item = ProcessInfo>) {
        let mut listed: HashSet<(u32, u64)> = self
            .processes
            .iter()
            .map(|p| (p.pid, p.start_ticks))
            .collect();
        for process in processes {
            if listed.insert((process.pid, process.start_ticks)) {
                self.processes.push(process);
            }
        }
    }

    /// The processes by pid and start in clock ticks
    pub fn process_index(&self) -> HashMap<(u32, u64), &ProcessInfo> {
        self.processes
            .iter()
            .map(|p| ((p.pid, p.start_ticks), p))
            .collect()
    }

    /// A start in clock ticks in ns since boot, the unit of the owner records; rounded down to
    /// a tick by the kernel. None without a tick length.
    pub fn start_ns(&self, start_ticks: u64) -> Option<u64> {
        tick_ns(self.clock_ticks).map(|tick| start_ticks * tick)
    }

    /// A start in ns since boot, as in the owner records, in clock ticks
    pub fn start_ticks(&self, start_ns: u64) -> Option<u64> {
        tick_ns(self.clock_ticks).map(|tick| start_ns / tick)
    }
}

/// The length of a clock tick in ns, None for no ticks per second
fn tick_ns(clock_ticks: u64) -> Option<u64> {
    1_000_000_000u64
        .checked_div(clock_ticks)
        .filter(|tick| *tick > 0)
}

/// Whether a start time in ns since boot and one in clock ticks are the same: the kernel shows
/// the ns divided by the length of a tick, rounded down
pub fn same_start(start_ns: u64, start_ticks: u64, clock_ticks: u64) -> bool {
    tick_ns(clock_ticks).is_some_and(|tick| start_ns / tick == start_ticks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_times_compare_at_tick_resolution() {
        assert!(same_start(1_234_567_890, 123, 100));
        assert!(same_start(1_239_999_999, 123, 100));
        assert!(!same_start(1_240_000_000, 123, 100));
        assert!(!same_start(1_234_567_890, 123, 0));
    }

    #[test]
    fn round_trip() {
        let dir = std::env::temp_dir().join(format!("tcbee-owners-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(FlowOwners::read(&dir).unwrap(), None);
        let mut owners = FlowOwners::new(5, 100);
        owners.connections.push(SnapshotConnection {
            local: "[::ffff:10.0.0.1]:40000".parse().unwrap(),
            remote: "10.0.0.2:5201".parse().unwrap(),
            netns: 4026531840,
            state: "ESTABLISHED".into(),
            uid: 1000,
            inode: 77,
            holders: vec![Holder {
                pid: 42,
                start_ticks: 123,
            }],
        });
        owners.processes.push(ProcessInfo {
            pid: 42,
            start_ticks: 123,
            comm: "iperf3".into(),
            cmdline: vec!["iperf3".into(), "-c".into(), "10.0.0.2".into()],
            uid: Some(1000),
            cgroup: Some("/user.slice".into()),
        });
        owners.write(&dir).unwrap();
        let read = FlowOwners::read(&dir).unwrap().unwrap();
        assert_eq!(read, owners);
        let index = read.process_index();
        let ticks = read.start_ticks(1_239_999_999).unwrap();
        assert_eq!(index[&(42, ticks)].comm, "iperf3");
        assert!(!index.contains_key(&(42, read.start_ticks(1_240_000_000).unwrap())));
        assert_eq!(read.start_ns(123), Some(1_230_000_000));
        assert_eq!(FlowOwners::new(0, 0).start_ns(1), None);
        let mut more = read.clone();
        let later = ProcessInfo {
            start_ticks: 200,
            ..read.processes[0].clone()
        };
        more.add_processes([read.processes[0].clone(), later]);
        assert_eq!(more.processes.len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }
}
