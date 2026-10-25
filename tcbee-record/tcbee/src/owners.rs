//! The processes of the connections that exist when the recording starts, found the way
//! netstat and `ss -p` find them: the TCP sockets of each network namespace from
//! `/proc/<pid>/net/tcp{,6}` of one process in it, and the processes holding each socket from
//! the socket inodes of `/proc/<pid>/fd`. The owner programs cover the connections opened from
//! then on. The pids are the ones of the procfs read, so tcbee-record has to run in the pid
//! namespace of the host for them to match the owner records.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use log::warn;
use procfs::{
    net::TcpState,
    process::{all_processes_with_root, FDTarget, Process},
};
use tcbee_trace::owners::{FlowOwners, ProcessInfo, SnapshotConnection};

use crate::metadata::clock_ns;

/// Clock ticks per second, the unit of the start times in `/proc/<pid>/stat`
pub fn clock_ticks() -> u64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks).unwrap_or(0)
}

/// The kernel's name of a TCP state, as `ss` shows it
fn state_name(state: TcpState) -> &'static str {
    match state {
        TcpState::Established => "ESTABLISHED",
        TcpState::SynSent => "SYN_SENT",
        TcpState::SynRecv => "SYN_RECV",
        TcpState::FinWait1 => "FIN_WAIT1",
        TcpState::FinWait2 => "FIN_WAIT2",
        TcpState::TimeWait => "TIME_WAIT",
        TcpState::Close => "CLOSE",
        TcpState::CloseWait => "CLOSE_WAIT",
        TcpState::LastAck => "LAST_ACK",
        TcpState::Listen => "LISTEN",
        TcpState::Closing => "CLOSING",
        TcpState::NewSynRecv => "NEW_SYN_RECV",
    }
}

/// Inode number of the network namespace of a process, from its `ns/net` link
/// (`net:[4026531840]`)
fn netns(proc_root: &Path, pid: i32) -> Option<u32> {
    let link = fs::read_link(proc_root.join(pid.to_string()).join("ns/net")).ok()?;
    link.to_str()?
        .strip_prefix("net:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The cgroup v2 path of a process
fn cgroup(proc_root: &Path, pid: u32) -> Option<String> {
    let text = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_string)
}

/// The process `pid` below `proc_root`, None if it exited
pub fn process_info(proc_root: &Path, pid: u32) -> Option<ProcessInfo> {
    let process = Process::new_with_root(proc_root.join(pid.to_string())).ok()?;
    let stat = process.stat().ok()?;
    Some(ProcessInfo {
        pid,
        start_ticks: stat.starttime,
        comm: stat.comm,
        cmdline: process.cmdline().unwrap_or_default(),
        uid: process.uid().ok(),
        cgroup: cgroup(proc_root, pid),
    })
}

/// The TCP connections below `proc_root` (`/proc`) and the processes that hold them. Listeners
/// and sockets without an inode (TIME_WAIT, a connection still in an accept queue, which the
/// accept program sees) are left out. Processes that exit or deny access while it runs are
/// skipped; the result is as complete as procfs allows.
pub fn snapshot(proc_root: &Path) -> FlowOwners {
    let mut owners = FlowOwners::new(clock_ns(libc::CLOCK_MONOTONIC) as u64, clock_ticks());
    let all = match all_processes_with_root(proc_root) {
        Ok(all) => all,
        Err(err) => {
            warn!(
                "Cannot list the processes in {}: {}",
                proc_root.display(),
                err
            );
            return owners;
        }
    };
    // A process per network namespace, and the processes holding each socket inode
    let mut namespaces: BTreeMap<u32, i32> = BTreeMap::new();
    let mut holders: BTreeMap<u64, BTreeSet<u32>> = BTreeMap::new();
    for process in all.flatten() {
        let pid = process.pid();
        let Ok(fds) = process.fd() else {
            continue;
        };
        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                holders.entry(inode).or_default().insert(pid as u32);
            }
        }
        if let Some(ns) = netns(proc_root, pid) {
            namespaces.entry(ns).or_insert(pid);
        }
    }

    for (ns, pid) in namespaces {
        let Ok(process) = Process::new_with_root(proc_root.join(pid.to_string())) else {
            continue;
        };
        // tcp6 is missing without IPv6
        let entries = [process.tcp(), process.tcp6()]
            .into_iter()
            .flatten()
            .flatten();
        for entry in entries {
            if entry.inode == 0 || entry.state == TcpState::Listen {
                continue;
            }
            owners.connections.push(SnapshotConnection {
                local: entry.local_address,
                remote: entry.remote_address,
                netns: ns,
                state: state_name(entry.state).to_string(),
                uid: entry.uid,
                inode: entry.inode,
                pids: holders
                    .get(&entry.inode)
                    .map(|pids| pids.iter().copied().collect())
                    .unwrap_or_default(),
            });
        }
    }

    let pids: BTreeSet<u32> = owners
        .connections
        .iter()
        .flat_map(|c| c.pids.iter().copied())
        .collect();
    owners.processes = pids
        .into_iter()
        .filter_map(|pid| process_info(proc_root, pid))
        .collect();
    owners
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{env, os::unix::fs::symlink, path::PathBuf};

    use super::*;

    /// A procfs with the files the snapshot reads, below a temporary directory
    pub(crate) struct FakeProc {
        pub root: PathBuf,
    }

    impl FakeProc {
        pub fn new(name: &str) -> FakeProc {
            let root =
                env::temp_dir().join(format!("tcbee-fake-proc-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            FakeProc { root }
        }

        /// A process with its comm, command line, start time, the socket inodes of its fds and
        /// its network namespace
        pub fn process(
            &self,
            pid: u32,
            comm: &str,
            cmdline: &[&str],
            start: u64,
            sockets: &[u64],
            ns: u32,
        ) {
            let dir = self.root.join(pid.to_string());
            fs::create_dir_all(dir.join("fd")).unwrap();
            fs::create_dir_all(dir.join("ns")).unwrap();
            fs::create_dir_all(dir.join("net")).unwrap();
            let stat = format!(
                "{pid} ({comm}) S 1 {pid} {pid} 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 {start} \
                 1000000 100 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 \
                 0 0 0 0\n"
            );
            fs::write(dir.join("stat"), stat).unwrap();
            let mut args = cmdline.join("\0");
            args.push('\0');
            fs::write(dir.join("cmdline"), args).unwrap();
            fs::write(dir.join("cgroup"), "0::/user.slice/test.scope\n").unwrap();
            for (fd, inode) in sockets.iter().enumerate() {
                symlink(
                    format!("socket:[{inode}]"),
                    dir.join("fd").join((fd + 3).to_string()),
                )
                .unwrap();
            }
            symlink("pipe:[9]", dir.join("fd/0")).unwrap();
            symlink(format!("net:[{ns}]"), dir.join("ns/net")).unwrap();
        }

        /// The tcp and tcp6 tables of the namespace of `pid`, lines without the header
        pub fn tables(&self, pid: u32, tcp: &[&str], tcp6: &[&str]) {
            let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
            for (name, lines) in [("tcp", tcp), ("tcp6", tcp6)] {
                let text = header.to_string() + &lines.join("\n") + "\n";
                fs::write(self.root.join(pid.to_string()).join("net").join(name), text).unwrap();
            }
        }
    }

    impl Drop for FakeProc {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// 10.0.0.1:40000 -> 10.0.0.2:5201, ESTABLISHED, uid 1000, inode 1001
    const V4: &str = "   0: 0100000A:9C40 0200000A:1451 01 00000000:00000000 00:00000000 00000000  1000        0 1001 1 0000000000000000 20 4 30 10 -1";
    /// A listener on port 5201
    const LISTEN: &str = "   1: 00000000:1451 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 100 0 0 10 0";
    /// TIME_WAIT, no inode
    const TIME_WAIT: &str = "   2: 0100000A:9C41 0200000A:1451 06 00000000:00000000 03:00000F9F 00000000     0        0 0 3 0000000000000000";
    /// [::ffff:10.0.0.1]:40002 -> [::ffff:10.0.0.3]:443, ESTABLISHED, inode 1003
    const MAPPED: &str = "   0: 0000000000000000FFFF00000100000A:9C42 0000000000000000FFFF00000300000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1003 1 0000000000000000 20 4 30 10 -1";

    #[test]
    fn snapshot_finds_connections_and_their_processes() {
        let proc = FakeProc::new("snapshot");
        proc.process(
            100,
            "iperf3",
            &["iperf3", "-c", "10.0.0.2"],
            4242,
            &[1001, 1002],
            7,
        );
        proc.process(101, "curl", &["curl", "https://10.0.0.3"], 4343, &[1003], 7);
        // Shares the socket of 100 after a fork
        proc.process(102, "iperf3", &["iperf3"], 4444, &[1001], 7);
        proc.tables(100, &[V4, LISTEN, TIME_WAIT], &[MAPPED]);
        proc.tables(101, &[V4, LISTEN, TIME_WAIT], &[MAPPED]);
        proc.tables(102, &[V4, LISTEN, TIME_WAIT], &[MAPPED]);

        let owners = snapshot(&proc.root);
        let connections: Vec<_> = owners
            .connections
            .iter()
            .map(|c| {
                (
                    c.local.to_string(),
                    c.remote.to_string(),
                    c.netns,
                    c.state.as_str(),
                    c.pids.clone(),
                )
            })
            .collect();
        assert_eq!(
            connections,
            [
                (
                    "10.0.0.1:40000".to_string(),
                    "10.0.0.2:5201".to_string(),
                    7,
                    "ESTABLISHED",
                    vec![100, 102]
                ),
                (
                    "[::ffff:10.0.0.1]:40002".to_string(),
                    "[::ffff:10.0.0.3]:443".to_string(),
                    7,
                    "ESTABLISHED",
                    vec![101]
                ),
            ]
        );
        let processes: Vec<_> = owners
            .processes
            .iter()
            .map(|p| (p.pid, p.comm.as_str(), p.start_ticks))
            .collect();
        assert_eq!(
            processes,
            [
                (100, "iperf3", 4242),
                (101, "curl", 4343),
                (102, "iperf3", 4444)
            ]
        );
        assert_eq!(owners.processes[1].cmdline, ["curl", "https://10.0.0.3"]);
        assert_eq!(
            owners.processes[0].cgroup.as_deref(),
            Some("/user.slice/test.scope")
        );
        assert_eq!(owners.clock_ticks, clock_ticks());
    }

    #[test]
    fn each_namespace_is_read_once() {
        let proc = FakeProc::new("netns");
        proc.process(200, "a", &["a"], 1, &[1001], 7);
        proc.process(201, "b", &["b"], 1, &[1003], 8);
        proc.tables(200, &[V4], &[]);
        proc.tables(201, &[], &[MAPPED]);
        let owners = snapshot(&proc.root);
        let found: Vec<_> = owners
            .connections
            .iter()
            .map(|c| (c.netns, c.inode, c.pids.clone()))
            .collect();
        assert_eq!(found, [(7, 1001, vec![200]), (8, 1003, vec![201])]);
    }

    /// Whatever this host runs: every process of a connection is listed, at most once
    #[test]
    fn snapshot_of_this_host() {
        let owners = snapshot(Path::new("/proc"));
        let listed: BTreeSet<u32> = owners.processes.iter().map(|p| p.pid).collect();
        assert_eq!(listed.len(), owners.processes.len());
        for c in &owners.connections {
            assert!(c.inode != 0 && c.state != "LISTEN");
        }
        assert!(owners.clock_ticks > 0);
    }

    #[test]
    fn missing_proc_gives_an_empty_snapshot() {
        let owners = snapshot(Path::new("/nonexistent/proc"));
        assert!(owners.connections.is_empty() && owners.processes.is_empty());
        assert!(process_info(Path::new("/nonexistent/proc"), 1).is_none());
    }
}
