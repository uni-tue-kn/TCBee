//! What `flow_owners.json` holds about the processes of the connections. The connections that
//! exist when the recording starts, found the way netstat and `ss -p` find them: the TCP
//! sockets of each network namespace from `/proc/<pid>/net/tcp{,6}` of one process in it, and
//! the processes holding each socket from the socket inodes of `/proc/<pid>/fd`. The owner
//! programs cover the connections opened from then on, and `Resolver` looks up their
//! processes' command lines. The pids are the ones of the procfs read, so tcbee-record has to
//! run in the pid namespace of the host for them to match the owner records.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    mem,
    net::SocketAddr,
    path::{Path, PathBuf},
    ptr,
    sync::mpsc,
    thread,
};

use log::{debug, warn};
use procfs::{
    net::TcpState,
    process::{all_processes_with_root, FDTarget, Process},
};
use tcbee_common::records::{flow_owner_entry, TCBEE_OWNER_KTHREAD};
use tcbee_trace::owners::{same_start, FlowOwners, Holder, ProcessInfo, SnapshotConnection};

use crate::{metadata::clock_ns, writer::Observer};

/// Clock ticks per second, the unit of the start times in `/proc/<pid>/stat`
pub fn clock_ticks() -> u64 {
    // SAFETY: sysconf only reads a configuration value, it has no memory arguments
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks).unwrap_or(0)
}

/// Inode number of the initial pid namespace, PROC_PID_INIT_INO in include/linux/proc_ns.h. It
/// is fixed, so it tells the host's pid namespace apart from that of a container, also where the
/// container mounted a procfs of its own (whose NSpid lines then show a single level).
const PROC_PID_INIT_INO: u64 = 0xEFFF_FFFC;

/// Whether the process of `proc_root/self` runs in the initial pid namespace, where the owner
/// records take their pids from; None if procfs does not tell
pub fn in_initial_pid_namespace(proc_root: &Path) -> Option<bool> {
    let process = Process::new_with_root(proc_root.join("self")).ok()?;
    let namespaces = process.namespaces().ok()?;
    let pid = namespaces.0.get(std::ffi::OsStr::new("pid"))?;
    Some(pid.identifier == PROC_PID_INIT_INO)
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

/// Inode number of the network namespace of a process
fn netns(process: &Process) -> Option<u32> {
    let namespaces = process.namespaces().ok()?;
    let net = namespaces.0.get(std::ffi::OsStr::new("net"))?;
    u32::try_from(net.identifier).ok()
}

/// The cgroup v2 path of a process
fn cgroup(process: &Process) -> Option<String> {
    let cgroups = process.cgroups().ok()?;
    cgroups
        .0
        .into_iter()
        .find(|c| c.hierarchy == 0)
        .map(|c| c.pathname)
}

/// The process `pid` below `proc_root`, None if it exited. Its uid is the real one, as in the
/// owner records.
pub fn process_info(proc_root: &Path, pid: u32) -> Option<ProcessInfo> {
    let process = Process::new_with_root(proc_root.join(pid.to_string())).ok()?;
    let stat = process.stat().ok()?;
    Some(ProcessInfo {
        pid,
        start_ticks: stat.starttime,
        comm: stat.comm,
        cmdline: process.cmdline().unwrap_or_default(),
        uid: process.status().ok().map(|status| status.ruid),
        cgroup: cgroup(&process),
    })
}

/// The TCP connections below `proc_root` (`/proc`) that `keep` (local, remote) takes, the flow
/// filter, and the processes that hold them. Listeners and sockets without an inode (TIME_WAIT,
/// a connection still in an accept queue, which the accept program sees) are left out.
/// Processes that exit or deny access while it runs are skipped; the result is as complete as
/// procfs allows.
pub fn snapshot(proc_root: &Path, keep: &dyn Fn(SocketAddr, SocketAddr) -> bool) -> FlowOwners {
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
    let mut holders: BTreeMap<u64, BTreeSet<Holder>> = BTreeMap::new();
    for process in all.flatten() {
        let pid = process.pid();
        let Ok(fds) = process.fd() else {
            continue;
        };
        let sockets: Vec<u64> = fds
            .flatten()
            .filter_map(|fd| match fd.target {
                FDTarget::Socket(inode) => Some(inode),
                _ => None,
            })
            .collect();
        // The start names the process, its pid may belong to another one by the time the
        // process list is read
        if let (false, Ok(stat)) = (sockets.is_empty(), process.stat()) {
            let holder = Holder {
                pid: pid as u32,
                start_ticks: stat.starttime,
            };
            for inode in sockets {
                holders.entry(inode).or_default().insert(holder);
            }
        }
        if let Some(ns) = netns(&process) {
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
            if entry.inode == 0
                || entry.state == TcpState::Listen
                || !keep(entry.local_address, entry.remote_address)
            {
                continue;
            }
            owners.connections.push(SnapshotConnection {
                local: entry.local_address,
                remote: entry.remote_address,
                netns: ns,
                state: state_name(entry.state).to_string(),
                uid: entry.uid,
                inode: entry.inode,
                holders: holders
                    .get(&entry.inode)
                    .map(|holders| holders.iter().copied().collect())
                    .unwrap_or_default(),
            });
        }
    }

    let holders: BTreeSet<Holder> = owners
        .connections
        .iter()
        .flat_map(|c| c.holders.iter().copied())
        .collect();
    owners.processes = holders
        .into_iter()
        .filter_map(|h| process_info(proc_root, h.pid).filter(|p| p.start_ticks == h.start_ticks))
        .collect();
    owners.snapshot_end_ns = clock_ns(libc::CLOCK_MONOTONIC) as u64;
    owners
}

/// Looks up the processes of the owner records while the recording runs, on a thread of its
/// own: a short-lived process is gone by its end. Each process, pid and start time, is looked
/// up once, and kept only if procfs still shows the same process, as pids are reused. Best
/// effort: a process that exits first, or execs another program, is missed or shows that one.
pub struct Resolver {
    processes: mpsc::Sender<(u32, u64)>,
    thread: thread::JoinHandle<Vec<ProcessInfo>>,
}

impl Resolver {
    pub fn start(proc_root: PathBuf) -> Resolver {
        let (processes, received) = mpsc::channel();
        let thread = thread::spawn(move || resolve(&proc_root, received));
        Resolver { processes, thread }
    }

    /// The observer of the owner ring's writer: hands the process of each record over. Kernel
    /// threads have no command line.
    pub fn observer(&self) -> Observer {
        let processes = self.processes.clone();
        Box::new(move |entry: &[u8]| {
            if entry.len() < mem::size_of::<flow_owner_entry>() {
                return;
            }
            // SAFETY: entry holds at least one flow_owner_entry (checked above), a plain old
            // data struct valid for any bytes; read_unaligned does not need its alignment
            let rec = unsafe { ptr::read_unaligned(entry.as_ptr() as *const flow_owner_entry) };
            if u32::from(rec.flags) & TCBEE_OWNER_KTHREAD == 0 {
                let _ = processes.send((rec.pid, rec.start_time));
            }
        })
    }

    /// The processes found. Waits for the lookups of every record handed over, so the
    /// observers must be gone (the writer shut down).
    pub fn finish(self) -> Vec<ProcessInfo> {
        drop(self.processes);
        self.thread.join().unwrap_or_default()
    }
}

/// Looks up each process (pid, start time in ns since boot) that arrives, once
fn resolve(proc_root: &Path, processes: mpsc::Receiver<(u32, u64)>) -> Vec<ProcessInfo> {
    let clock_ticks = clock_ticks();
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    for (pid, start_ns) in processes {
        if !seen.insert((pid, start_ns)) {
            continue;
        }
        match process_info(proc_root, pid) {
            Some(info) if same_start(start_ns, info.start_ticks, clock_ticks) => found.push(info),
            Some(_) => debug!("Process {pid} is another process by now, no command line"),
            None => debug!("Process {pid} exited before its command line was read"),
        }
    }
    found
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        env, fs,
        os::unix::fs::{symlink, MetadataExt},
        path::PathBuf,
    };

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
            // The status of this test process, with the pid and the real uid 1000 of the
            // process (effective uid 0, which the owner of /proc/<pid> would show)
            let status: String = fs::read_to_string("/proc/self/status")
                .unwrap()
                .lines()
                .map(|line| match line.split(':').next() {
                    Some("Pid" | "Tgid") => {
                        format!("{}:\t{pid}\n", &line[..line.find(':').unwrap()])
                    }
                    Some("Uid") => "Uid:\t1000\t0\t0\t0\n".to_string(),
                    _ => format!("{line}\n"),
                })
                .collect();
            fs::write(dir.join("status"), status).unwrap();
            for (fd, inode) in sockets.iter().enumerate() {
                symlink(
                    format!("socket:[{inode}]"),
                    dir.join("fd").join((fd + 3).to_string()),
                )
                .unwrap();
            }
            symlink("pipe:[9]", dir.join("fd/0")).unwrap();
            // ns/net names its namespace by the inode it leads to, a file per namespace here
            let ns_file = self.root.join(format!("netns-{ns}"));
            if !ns_file.exists() {
                fs::write(&ns_file, "").unwrap();
            }
            symlink(&ns_file, dir.join("ns/net")).unwrap();
            // A pid namespace of its own, never the initial one
            let pid_ns = self.root.join("pidns");
            if !pid_ns.exists() {
                fs::write(&pid_ns, "").unwrap();
            }
            symlink(&pid_ns, dir.join("ns/pid")).unwrap();
        }

        /// `self` names process `pid`
        pub fn myself(&self, pid: u32) {
            symlink(pid.to_string(), self.root.join("self")).unwrap();
        }

        /// The inode number that stands for namespace `ns` of `process`
        pub fn netns(&self, ns: u32) -> u32 {
            let ino = fs::metadata(self.root.join(format!("netns-{ns}")))
                .unwrap()
                .ino();
            ino as u32
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

        let owners = snapshot(&proc.root, &|_, _| true);
        let ns = proc.netns(7);
        let connections: Vec<_> = owners
            .connections
            .iter()
            .map(|c| {
                (
                    c.local.to_string(),
                    c.remote.to_string(),
                    c.netns,
                    c.state.as_str(),
                    c.holders.iter().map(|h| h.pid).collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            connections,
            [
                (
                    "10.0.0.1:40000".to_string(),
                    "10.0.0.2:5201".to_string(),
                    ns,
                    "ESTABLISHED",
                    vec![100, 102]
                ),
                (
                    "[::ffff:10.0.0.1]:40002".to_string(),
                    "[::ffff:10.0.0.3]:443".to_string(),
                    ns,
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
        // The real uid, not the effective one or the owner of /proc/<pid>
        assert_eq!(owners.processes[0].uid, Some(1000));
    }

    /// Only the connections the filter takes, and only their processes
    #[test]
    fn snapshot_keeps_the_filtered_connections() {
        let proc = FakeProc::new("filter");
        proc.process(100, "iperf3", &["iperf3"], 1, &[1001], 7);
        proc.process(101, "curl", &["curl"], 1, &[1003], 7);
        proc.tables(100, &[V4], &[MAPPED]);
        proc.tables(101, &[V4], &[MAPPED]);
        let https = |_local: SocketAddr, remote: SocketAddr| remote.port() == 443;
        let owners = snapshot(&proc.root, &https);
        let inodes: Vec<u64> = owners.connections.iter().map(|c| c.inode).collect();
        assert_eq!(inodes, [1003]);
        let pids: Vec<u32> = owners.processes.iter().map(|p| p.pid).collect();
        assert_eq!(pids, [101]);
    }

    #[test]
    fn each_namespace_is_read_once() {
        let proc = FakeProc::new("netns");
        proc.process(200, "a", &["a"], 1, &[1001], 7);
        proc.process(201, "b", &["b"], 1, &[1003], 8);
        proc.tables(200, &[V4], &[]);
        proc.tables(201, &[], &[MAPPED]);
        let owners = snapshot(&proc.root, &|_, _| true);
        let found: Vec<_> = owners
            .connections
            .iter()
            .map(|c| {
                (
                    c.netns,
                    c.inode,
                    c.holders.iter().map(|h| h.pid).collect::<Vec<_>>(),
                )
            })
            .collect();
        let mut want = [
            (proc.netns(7), 1001, vec![200]),
            (proc.netns(8), 1003, vec![201]),
        ];
        want.sort();
        assert_eq!(found, want);
    }

    /// Whatever this host runs: every process of a connection is listed, at most once
    #[test]
    fn snapshot_of_this_host() {
        let owners = snapshot(Path::new("/proc"), &|_, _| true);
        let listed: BTreeSet<u32> = owners.processes.iter().map(|p| p.pid).collect();
        assert_eq!(listed.len(), owners.processes.len());
        for c in &owners.connections {
            assert!(c.inode != 0 && c.state != "LISTEN");
        }
        assert!(owners.snapshot_end_ns >= owners.snapshot_ns);
        assert!(owners.clock_ticks > 0);
    }

    fn owner_record(pid: u32, start_time: u64, flags: u8) -> Vec<u8> {
        let rec = flow_owner_entry {
            pid,
            start_time,
            flags,
            ..Default::default()
        };
        // SAFETY: rec is a plain old data struct that lives for the whole borrow
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &rec as *const flow_owner_entry as *const u8,
                mem::size_of::<flow_owner_entry>(),
            )
        };
        bytes.to_vec()
    }

    #[test]
    fn resolver_keeps_the_processes_that_are_still_the_same() {
        let proc = FakeProc::new("resolver");
        proc.process(300, "curl", &["curl", "-O", "x"], 500, &[], 7);
        proc.process(301, "sshd", &["sshd: alice"], 600, &[], 7);
        let resolver = Resolver::start(proc.root.clone());
        let mut observe = resolver.observer();
        let tick_ns = 1_000_000_000 / clock_ticks();
        observe(&owner_record(300, 500 * tick_ns + 1, 0));
        observe(&owner_record(300, 500 * tick_ns + 1, 0));
        // pid 301 now belongs to a process that started later
        observe(&owner_record(301, 10 * tick_ns, 0));
        // exited
        observe(&owner_record(302, 10 * tick_ns, 0));
        observe(&owner_record(300, 500 * tick_ns, TCBEE_OWNER_KTHREAD as u8));
        observe(&[0; 3]);
        drop(observe);
        let found = resolver.finish();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pid, 300);
        assert_eq!(found[0].cmdline, ["curl", "-O", "x"]);
    }

    #[test]
    fn a_pid_namespace_of_its_own_is_not_the_hosts() {
        let proc = FakeProc::new("pidns");
        assert_eq!(in_initial_pid_namespace(&proc.root), None);
        proc.process(100, "tcbee-record", &["tcbee-record"], 1, &[], 7);
        proc.myself(100);
        assert_eq!(in_initial_pid_namespace(&proc.root), Some(false));
        // This host's procfs tells, whichever namespace the test runs in
        assert!(in_initial_pid_namespace(Path::new("/proc")).is_some());
    }

    #[test]
    fn missing_proc_gives_an_empty_snapshot() {
        let owners = snapshot(Path::new("/nonexistent/proc"), &|_, _| true);
        assert!(owners.connections.is_empty() && owners.processes.is_empty());
        assert!(process_info(Path::new("/nonexistent/proc"), 1).is_none());
    }
}
