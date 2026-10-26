//! The processes that own the flows, for the TUI flow table: the owner records as the owner
//! ring's writer sees them, and the connections of the startup snapshot. Only with the TUI.

use std::{
    collections::{HashMap, VecDeque},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
    sync::{Arc, Mutex},
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

/// The latest owner of each connection, at most `OWNERS_KEPT`
#[derive(Default)]
pub struct OwnerTable {
    owners: HashMap<(Endpoint, Endpoint), Owner>,
    /// Connections in the order they came in
    order: VecDeque<(Endpoint, Endpoint)>,
}

pub type SharedOwners = Arc<Mutex<OwnerTable>>;

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
        let (a, b) = (canonical(a), canonical(b));
        self.owners
            .get(&(a, b))
            .or_else(|| self.owners.get(&(b, a)))
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.owners.len()
    }
}

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
        if let Ok(mut owners) = owners.lock() {
            owners.insert(decode(&rec));
        }
    })
}

/// Adds the connections that existed at the start, unless an owner record named them since.
/// A connection takes the first process holding its socket.
pub fn add_snapshot(owners: &SharedOwners, snapshot: &FlowOwners) {
    let processes = snapshot.process_index();
    let Ok(mut owners) = owners.lock() else {
        return;
    };
    for connection in &snapshot.connections {
        let Some(holder) = connection.holders.first() else {
            continue;
        };
        let local = canonical((connection.local.ip(), connection.local.port()));
        let remote = canonical((connection.remote.ip(), connection.remote.port()));
        if owners.find(local, remote).is_some() {
            continue;
        }
        let comm = processes
            .get(&(holder.pid, holder.start_ticks))
            .map_or("?", |process| process.comm.as_str());
        owners.insert(Owner {
            local,
            remote,
            process: format!("{comm}[{}]", holder.pid),
            service: false,
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use tcbee_trace::owners::{Holder, ProcessInfo, SnapshotConnection};

    use super::*;
    use crate::config::AF_INET6;

    /// An owner record of `local` -> `remote`
    pub fn record(local: Endpoint, remote: Endpoint, comm: &str, pid: u32, kind: u32) -> Vec<u8> {
        let mut rec: flow_owner_entry = unsafe { mem::zeroed() };
        match (local.0, remote.0) {
            (IpAddr::V4(l), IpAddr::V4(r)) => {
                rec.family = AF_INET;
                rec.addr_v4 = ((u32::from_le_bytes(l.octets()) as u64) << 32)
                    | u32::from_le_bytes(r.octets()) as u64;
            }
            (l, r) => {
                rec.family = AF_INET6;
                let v6 = |ip: IpAddr| match ip {
                    IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                    IpAddr::V6(ip) => ip.octets(),
                };
                rec.src_v6 = v6(l);
                rec.dst_v6 = v6(r);
            }
        }
        rec.sport = local.1;
        rec.dport = remote.1;
        rec.kind = kind as u8;
        rec.pid = pid;
        rec.comm[..comm.len()].copy_from_slice(comm.as_bytes());
        // SAFETY: rec is a plain old data struct that lives for the whole borrow
        unsafe {
            std::slice::from_raw_parts(
                &rec as *const flow_owner_entry as *const u8,
                mem::size_of::<flow_owner_entry>(),
            )
        }
        .to_vec()
    }

    pub fn ep(text: &str) -> Endpoint {
        let addr: std::net::SocketAddr = text.parse().unwrap();
        (addr.ip(), addr.port())
    }

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
        let owners = owners.lock().unwrap();
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
    fn snapshot_fills_in_what_the_records_did_not_name() {
        let owners = SharedOwners::default();
        observer(owners.clone())(&record(
            ep("10.0.0.1:22"),
            ep("10.0.0.9:51000"),
            "sshd",
            90,
            TCBEE_OWNER_ACCEPT,
        ));
        let mut snapshot = FlowOwners::new(0, 100);
        let connection = |local: &str, remote: &str, pid| SnapshotConnection {
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
        snapshot.connections = vec![
            connection("10.0.0.1:22", "10.0.0.9:51000", 1),
            connection("10.0.0.1:443", "10.0.0.3:60000", 300),
        ];
        snapshot.processes = vec![ProcessInfo {
            pid: 300,
            start_ticks: 7,
            comm: "nginx".to_string(),
            cmdline: Vec::new(),
            uid: None,
            cgroup: None,
        }];
        add_snapshot(&owners, &snapshot);
        let owners = owners.lock().unwrap();
        assert_eq!(
            owners
                .find(ep("10.0.0.1:22"), ep("10.0.0.9:51000"))
                .unwrap()
                .process,
            "sshd[90]"
        );
        assert_eq!(
            owners
                .find(ep("10.0.0.1:443"), ep("10.0.0.3:60000"))
                .unwrap()
                .process,
            "nginx[300]"
        );
    }
}
