//! `flow_owners.json`: what the recorder learned about the processes of the connections apart
//! from the owner records (`flow_owners.tcp`). The connections that already existed when the
//! recording started, with the processes that held them, as netstat or `ss -p` find them; and
//! the command lines of the processes, which the records do not carry.

use std::{fs, io, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};

pub const FLOW_OWNERS_FILE: &str = "flow_owners.json";
pub const FLOW_OWNERS_FORMAT: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FlowOwners {
    pub format: u32,
    /// When the snapshot of the existing connections started, ns of CLOCK_MONOTONIC (the clock
    /// of the records). The owner programs ran already, so a connection opened meanwhile can
    /// be in both.
    pub snapshot_ns: u64,
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
    pub pids: Vec<u32>,
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
        for process in processes {
            let listed = self
                .processes
                .iter()
                .any(|p| p.pid == process.pid && p.start_ticks == process.start_ticks);
            if !listed {
                self.processes.push(process);
            }
        }
    }

    /// The process `pid` that started at `start_ns` (ns since boot, as in the owner records)
    pub fn process(&self, pid: u32, start_ns: u64) -> Option<&ProcessInfo> {
        self.processes
            .iter()
            .find(|p| p.pid == pid && same_start(start_ns, p.start_ticks, self.clock_ticks))
    }
}

/// Whether a start time in ns since boot and one in clock ticks are the same: the kernel shows
/// the ns divided by the length of a tick, rounded down
pub fn same_start(start_ns: u64, start_ticks: u64, clock_ticks: u64) -> bool {
    match 1_000_000_000u64.checked_div(clock_ticks) {
        Some(tick_ns) if tick_ns > 0 => start_ns / tick_ns == start_ticks,
        _ => false,
    }
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
            pids: vec![42],
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
        assert_eq!(read.process(42, 1_230_000_000).unwrap().comm, "iperf3");
        assert!(read.process(42, 1_240_000_000).is_none());
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
