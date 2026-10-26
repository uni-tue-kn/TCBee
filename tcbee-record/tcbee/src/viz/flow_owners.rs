//! The processes that own the flows, for the TUI flow table: the owner records as the owner
//! ring's writer sees them, and the connections of the startup snapshot. Only with the TUI.

use std::{
    collections::{HashMap, VecDeque},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
    sync::{Arc, Mutex, OnceLock},
};

use tcbee_common::records::{flow_owner_entry, TCBEE_OWNER_ACCEPT, TCBEE_OWNER_KTHREAD};
use tcbee_trace::owners::FlowOwners;

use crate::{config::AF_INET, writer::Observer};

/// Connections whose owner the table keeps, the oldest go first. The FLOWS map lists 100.
pub const OWNERS_KEPT: usize = 4096;

/// An address and port
pub type Endpoint = (IpAddr, u16);

/// The process that opened a connection
#[derive(Clone, Debug, PartialEq)]
pub struct Owner {
    pub local: Endpoint,
    pub remote: Endpoint,
    /// "comm[pid]", or "[kernel]" for a kernel thread
    pub process: String,
    /// The process accepted the connection: the local side is a service
    pub service: bool,
}

/// A connection: its local and remote side
type Connection = (Endpoint, Endpoint);

/// The latest owner of each connection, at most `OWNERS_KEPT`
#[derive(Default)]
pub struct OwnerTable {
    owners: HashMap<Connection, Owner>,
    /// Connections in the order they came in
    order: VecDeque<Connection>,
}

impl OwnerTable {
    /// Adds `owner`, a newer record of a connection replaces the older one
    pub fn insert(&mut self, owner: Owner) {
        let key = (owner.local, owner.remote);
        if self.owners.insert(key, owner).is_none() {
            self.order.push_back(key);
            if self.order.len() > OWNERS_KEPT {
                if let Some(oldest) = self.order.pop_front() {
                    self.owners.remove(&oldest);
                }
            }
        }
    }

    /// The owner of the connection between `a` and `b`, either of them local
    pub fn find(&self, a: Endpoint, b: Endpoint) -> Option<&Owner> {
        find(&self.owners, a, b)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.owners.len()
    }
}

/// The owners of the connections that existed at the start, from the snapshot
pub struct SnapshotOwners {
    owners: HashMap<Connection, Owner>,
}

impl SnapshotOwners {
    pub fn find(&self, a: Endpoint, b: Endpoint) -> Option<&Owner> {
        find(&self.owners, a, b)
    }
}

fn find(owners: &HashMap<Connection, Owner>, a: Endpoint, b: Endpoint) -> Option<&Owner> {
    let (a, b) = (canonical(a), canonical(b));
    owners.get(&(a, b)).or_else(|| owners.get(&(b, a)))
}

/// What the TUI knows about the owners: the records the owner ring's writer saw, filled by
/// its thread, and the snapshot, set once by the snapshot thread. They stay apart, so the
/// snapshot neither waits for the lock nor pushes records out of the bounded table.
#[derive(Default)]
pub struct Owners {
    pub live: Mutex<OwnerTable>,
    pub snapshot: OnceLock<SnapshotOwners>,
}

pub type SharedOwners = Arc<Owners>;

/// IPv4 addresses as IPv4, also when an IPv6 socket holds them
fn canonical((ip, port): Endpoint) -> Endpoint {
    (ip.to_canonical(), port)
}

/// The owner an owner record names
pub fn decode(rec: &flow_owner_entry) -> Owner {
    let (local, remote) = if rec.family == AF_INET {
        // The raw skc_addrpair: the local address in the high half, both in network order
        let local = Ipv4Addr::from(((rec.addr_v4 >> 32) as u32).to_le_bytes());
        let remote = Ipv4Addr::from((rec.addr_v4 as u32).to_le_bytes());
        (IpAddr::V4(local), IpAddr::V4(remote))
    } else {
        (
            IpAddr::V6(Ipv6Addr::from(rec.src_v6)),
            IpAddr::V6(Ipv6Addr::from(rec.dst_v6)),
        )
    };
    let process = if u32::from(rec.flags) & TCBEE_OWNER_KTHREAD != 0 {
        "[kernel]".to_string()
    } else {
        let len = rec
            .comm
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(rec.comm.len());
        format!("{}[{}]", String::from_utf8_lossy(&rec.comm[..len]), rec.pid)
    };
    Owner {
        local: canonical((local, rec.sport)),
        remote: canonical((remote, rec.dport)),
        process,
        service: u32::from(rec.kind) == TCBEE_OWNER_ACCEPT,
    }
}

/// The observer of the owner ring's writer that fills `owners`
pub fn observer(owners: SharedOwners) -> Observer {
    Box::new(move |entry: &[u8]| {
        if entry.len() < mem::size_of::<flow_owner_entry>() {
            return;
        }
        // SAFETY: entry holds at least one flow_owner_entry (checked above), a plain old data
        // struct valid for any bytes; read_unaligned does not need its alignment
        let rec = unsafe { ptr::read_unaligned(entry.as_ptr() as *const flow_owner_entry) };
        if let Ok(mut live) = owners.live.lock() {
            live.insert(decode(&rec));
        }
    })
}

/// Sets the connections that existed at the start, with the first process holding each
/// socket. Built before it is shared, it takes no lock. The snapshot leaves listeners out, so
/// it cannot tell which side accepted: its owners are never marked as a service.
pub fn add_snapshot(owners: &Owners, snapshot: &FlowOwners) {
    let processes = snapshot.process_index();
    let mut found = HashMap::new();
    for connection in &snapshot.connections {
        let Some(holder) = connection.holders.first() else {
            continue;
        };
        let local = canonical((connection.local.ip(), connection.local.port()));
        let remote = canonical((connection.remote.ip(), connection.remote.port()));
        let comm = processes
            .get(&(holder.pid, holder.start_ticks))
            .map_or("?", |process| process.comm.as_str());
        let owner = Owner {
            local,
            remote,
            process: format!("{comm}[{}]", holder.pid),
            service: false,
        };
        found.insert((local, remote), owner);
    }
    let _ = owners.snapshot.set(SnapshotOwners { owners: found });
}

#[cfg(test)]
mod tests {
    use tcbee_trace::owners::{Holder, ProcessInfo, SnapshotConnection};

    use super::*;
    use crate::{
        viz::test_support::{ep, record},
        writer::observe_all,
    };

    #[test]
    fn records_name_the_local_side_and_the_process() {
        let owners = SharedOwners::default();
        let mut observe = observer(owners.clone());
        observe(&record(
            ep("10.0.0.1:40000"),
            ep("10.0.0.2:5201"),
            "iperf3",
            812,
            1,
        ));
        // An IPv6 socket of an IPv4 connection, accepted
        observe(&record(
            ep("[::ffff:10.0.0.1]:22"),
            ep("[::ffff:10.0.0.9]:51000"),
            "sshd",
            90,
            TCBEE_OWNER_ACCEPT,
        ));
        observe(&[0; 8]);
        let owners = owners.live.lock().unwrap();
        assert_eq!(owners.len(), 2);
        // Found from either side
        let iperf = owners
            .find(ep("10.0.0.2:5201"), ep("10.0.0.1:40000"))
            .unwrap();
        assert_eq!(iperf.local, ep("10.0.0.1:40000"));
        assert_eq!(iperf.process, "iperf3[812]");
        assert!(!iperf.service);
        let sshd = owners
            .find(ep("10.0.0.1:22"), ep("10.0.0.9:51000"))
            .unwrap();
        assert_eq!(sshd.local, ep("10.0.0.1:22"));
        assert!(sshd.service);
    }

    #[test]
    fn kernel_threads_have_no_process_name() {
        let bytes = record(ep("10.0.0.1:2049"), ep("10.0.0.2:700"), "kworker", 5, 1);
        // SAFETY: bytes holds one flow_owner_entry
        let mut rec: flow_owner_entry =
            unsafe { ptr::read_unaligned(bytes.as_ptr() as *const flow_owner_entry) };
        rec.flags = TCBEE_OWNER_KTHREAD as u8;
        assert_eq!(decode(&rec).process, "[kernel]");
    }

    #[test]
    fn table_keeps_the_latest_owners() {
        let mut owners = OwnerTable::default();
        for port in 0..OWNERS_KEPT as u16 + 10 {
            owners.insert(Owner {
                local: ep("10.0.0.1:1"),
                remote: (ep("10.0.0.2:0").0, port),
                process: "a[1]".to_string(),
                service: false,
            });
        }
        assert_eq!(owners.len(), OWNERS_KEPT);
        assert!(owners.find(ep("10.0.0.1:1"), ep("10.0.0.2:5")).is_none());
        assert!(owners.find(ep("10.0.0.1:1"), ep("10.0.0.2:4000")).is_some());
    }

    #[test]
    fn both_observers_see_every_record() {
        let (first, second) = (SharedOwners::default(), SharedOwners::default());
        let mut observe =
            observe_all(vec![observer(first.clone()), observer(second.clone())]).unwrap();
        observe(&record(ep("10.0.0.1:1"), ep("10.0.0.2:2"), "a", 1, 1));
        assert_eq!(first.live.lock().unwrap().len(), 1);
        assert_eq!(second.live.lock().unwrap().len(), 1);
        assert!(observe_all(Vec::new()).is_none());
    }

    #[test]
    fn snapshot_stays_apart_from_the_records() {
        let owners = SharedOwners::default();
        observer(owners.clone())(&record(
            ep("10.0.0.1:22"),
            ep("10.0.0.9:51000"),
            "sshd",
            90,
            TCBEE_OWNER_ACCEPT,
        ));
        let mut snapshot = FlowOwners::new(0, 100);
        let connection = |local: String, remote: &str, pid| SnapshotConnection {
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
            netns: 1,
            state: "ESTABLISHED".to_string(),
            uid: 0,
            inode: 1,
            holders: vec![Holder {
                pid,
                start_ticks: 7,
            }],
        };
        // More connections than the record table keeps
        snapshot.connections = (0..OWNERS_KEPT as u16 + 100)
            .map(|port| connection(format!("10.0.0.1:{}", 1000 + port), "10.0.0.3:443", 300))
            .collect();
        snapshot
            .connections
            .push(connection("10.0.0.1:22".to_string(), "10.0.0.9:51000", 1));
        snapshot.processes = vec![ProcessInfo {
            pid: 300,
            start_ticks: 7,
            comm: "curl".to_string(),
            cmdline: Vec::new(),
            uid: None,
            cgroup: None,
        }];
        add_snapshot(&owners, &snapshot);
        // The record stays, and wins over the snapshot
        let live = owners.live.lock().unwrap();
        assert_eq!(live.len(), 1);
        let sshd = live.find(ep("10.0.0.1:22"), ep("10.0.0.9:51000")).unwrap();
        assert_eq!(sshd.process, "sshd[90]");
        let snapshot = owners.snapshot.get().unwrap();
        let curl = snapshot
            .find(ep("10.0.0.3:443"), ep("10.0.0.1:1000"))
            .unwrap();
        assert_eq!(curl.process, "curl[300]");
        assert_eq!(curl.local, ep("10.0.0.1:1000"));
        assert!(!curl.service);
        // A holder without process information keeps its pid
        let unknown = snapshot
            .find(ep("10.0.0.1:22"), ep("10.0.0.9:51000"))
            .unwrap();
        assert_eq!(unknown.process, "?[1]");
    }
}
