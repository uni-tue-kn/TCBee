//! The processes that own the flows, table `flow_owners`: the owner records of tcbee-record
//! (`flow_owners.tcp`, one per connect and accept) and the connections that existed when the
//! recording started (`flow_owners.json`), joined to the flows of the event tables.
//!
//! An owner names its connection local -> remote. The records of received packets, and those of
//! the peer if both ends were recorded, name it the other way round, so an owner is joined to the
//! flow of its tuple and to the flow of the reversed tuple, as far as they exist. Owners never
//! create flows: the owner of a connection without any other record is counted as unmatched.
//! Dual-stack sockets name IPv4 peers with v4-mapped addresses, which become the IPv4 addresses
//! the event tables use. A tuple that is reused gets one owner per connection, told apart by
//! time. The subflows that the MPTCP path manager adds have no owner of their own, they take the
//! owner of their connection.

use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::{IpAddr, SocketAddr},
    path::Path,
};

use tcbee_common::records::{
    flow_owner_entry, TCBEE_OWNER_ACCEPT, TCBEE_OWNER_CONNECT, TCBEE_OWNER_KTHREAD,
};
use tcbee_trace::owners::{FlowOwners, ProcessInfo};
use ts_storage::{Catalog, ConnectionFlow, ConnectionInfo, Flow, FlowOwner, IpTuple};

use crate::{
    event::{decode_record, DecodeError},
    ip::{flow_tuple, ip_addr_from_16_bytes, kernel_addr_pair, AF_INET},
};

/// Size of one owner record in the trace file: the bincode encoding and the divider
pub const ENTRY_SIZE: usize = 112;

/// An owner and the tuple (local -> remote) of its connection, before the join
#[derive(Debug, Clone, PartialEq)]
pub struct Owned {
    pub tuple: IpTuple,
    /// `flow_id` is set by the join
    pub owner: FlowOwner,
    /// A snapshot owner: when the snapshot ended. An owner record of the same flow and process
    /// from before then is the same connection, opened while the snapshot ran.
    pub seen_until: Option<i64>,
}

/// The owners of a recording, from both files; a part that cannot be read is a warning
#[derive(Debug, Default)]
pub struct Owners {
    pub owned: Vec<Owned>,
    pub warnings: Vec<String>,
}

/// Owners whose connection has no flow
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Unmatched {
    /// Owner records: connections without any other record
    pub records: usize,
    /// Holders of the snapshot: mostly connections that sent nothing while recording
    pub snapshot: usize,
}

/// The tuple of an owner record, as the event tables write it
fn record_tuple(r: &flow_owner_entry) -> IpTuple {
    let (src, dst) = kernel_addr_pair(r.family == AF_INET, r.addr_v4, r.src_v6, r.dst_v6);
    flow_tuple(src, dst, r.sport, r.dport)
}

/// The text before the first NUL of a C string
fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn cmdline(process: &ProcessInfo) -> Option<String> {
    (!process.cmdline.is_empty()).then(|| process.cmdline.join(" "))
}

/// The processes of `flow_owners.json`, by pid and start
struct Processes<'a> {
    json: &'a FlowOwners,
    index: HashMap<(u32, u64), &'a ProcessInfo>,
}

impl<'a> Processes<'a> {
    fn new(json: &'a FlowOwners) -> Self {
        Processes {
            json,
            index: json.process_index(),
        }
    }

    /// The process `pid` that started at `start_ns`, ns since boot as in the owner records
    fn started_at(&self, pid: u32, start_ns: u64) -> Option<&'a ProcessInfo> {
        let ticks = self.json.start_ticks(start_ns)?;
        self.index.get(&(pid, ticks)).copied()
    }
}

/// The owner of one record. The command line and cgroup path come from `flow_owners.json`, if
/// the recorder found the process there.
fn record_owner(r: &flow_owner_entry, processes: Option<&Processes>) -> Owned {
    let source = match u32::from(r.kind) {
        TCBEE_OWNER_CONNECT => FlowOwner::SOURCE_CONNECT.to_string(),
        TCBEE_OWNER_ACCEPT => FlowOwner::SOURCE_ACCEPT.to_string(),
        other => format!("kind {other}"),
    };
    let process = processes.and_then(|p| p.started_at(r.pid, r.start_time));
    Owned {
        tuple: record_tuple(r),
        owner: FlowOwner {
            flow_id: 0,
            ts: r.time as i64,
            source,
            pid: i64::from(r.pid),
            uid: Some(i64::from(r.uid)),
            comm: c_string(&r.comm),
            cmdline: process.and_then(cmdline),
            start_time: Some(r.start_time as i64),
            cgroup_id: Some(r.cgroup_id as i64),
            cgroup: process.and_then(|p| p.cgroup.clone()),
            netns: Some(i64::from(r.netns)),
            kthread: u32::from(r.flags) & TCBEE_OWNER_KTHREAD != 0,
        },
        seen_until: None,
    }
}

/// Decodes the owner records of `bytes`; a truncated last record is left out with a warning
pub fn decode_records(
    bytes: &[u8],
    json: Option<&FlowOwners>,
    warnings: &mut Vec<String>,
) -> Result<Vec<Owned>, DecodeError> {
    let (records, tail) = bytes.as_chunks::<ENTRY_SIZE>();
    if !tail.is_empty() {
        warnings.push(format!(
            "flow_owners.tcp: {} trailing bytes do not form a whole record ({ENTRY_SIZE} \
             bytes) and are ignored (recording stopped mid-write?)",
            tail.len()
        ));
    }
    let processes = json.map(Processes::new);
    records
        .iter()
        .map(|record| {
            decode_record::<flow_owner_entry>(record, ENTRY_SIZE)
                .map(|r| record_owner(&r, processes.as_ref()))
        })
        .collect()
}

/// An address of the snapshot, as the event tables write it
fn snapshot_addr(addr: SocketAddr) -> (IpAddr, u16) {
    let ip = match addr.ip() {
        IpAddr::V6(v6) => ip_addr_from_16_bytes(v6.octets()),
        v4 => v4,
    };
    (ip, addr.port())
}

/// The owners of the connections that existed at the start: every process that held the
/// socket. Their start is the one /proc shows, rounded down to a clock tick.
pub fn snapshot_owners(json: &FlowOwners) -> Vec<Owned> {
    let processes = Processes::new(json);
    let seen_until = json.snapshot_end_ns.max(json.snapshot_ns) as i64;
    let mut owned = Vec::new();
    for c in &json.connections {
        let (src, sport) = snapshot_addr(c.local);
        let (dst, dport) = snapshot_addr(c.remote);
        let tuple = flow_tuple(src, dst, sport, dport);
        for holder in &c.holders {
            let process = processes
                .index
                .get(&(holder.pid, holder.start_ticks))
                .copied();
            owned.push(Owned {
                tuple: tuple.clone(),
                owner: FlowOwner {
                    flow_id: 0,
                    ts: json.snapshot_ns as i64,
                    source: FlowOwner::SOURCE_SNAPSHOT.to_string(),
                    pid: i64::from(holder.pid),
                    uid: Some(i64::from(process.and_then(|p| p.uid).unwrap_or(c.uid))),
                    comm: process.map(|p| p.comm.clone()).unwrap_or_default(),
                    cmdline: process.and_then(cmdline),
                    start_time: json.start_ns(holder.start_ticks).map(|ns| ns as i64),
                    cgroup_id: None,
                    cgroup: process.and_then(|p| p.cgroup.clone()),
                    netns: Some(i64::from(c.netns)),
                    kthread: false,
                },
                seen_until: Some(seen_until),
            });
        }
    }
    owned
}

/// Reads `flow_owners.tcp` and `flow_owners.json` of `trace_dir`; either may be missing
pub fn read(trace_dir: &Path) -> Owners {
    let mut owners = Owners::default();
    let json = match FlowOwners::read(trace_dir) {
        Ok(json) => json,
        Err(e) => {
            owners
                .warnings
                .push(format!("cannot read flow_owners.json: {e}"));
            None
        }
    };
    let path = trace_dir.join(tcbee_trace::TraceFile::FlowOwners.filename());
    match fs::read(&path) {
        Ok(bytes) => match decode_records(&bytes, json.as_ref(), &mut owners.warnings) {
            Ok(owned) => owners.owned = owned,
            Err(e) => owners
                .warnings
                .push(format!("{}: {e}, owners left out", path.display())),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => owners
            .warnings
            .push(format!("cannot read {}: {e}", path.display())),
    }
    if let Some(json) = &json {
        owners.owned.extend(snapshot_owners(json));
    }
    owners
}

fn reversed(t: &IpTuple) -> IpTuple {
    IpTuple {
        src: t.dst,
        dst: t.src,
        sport: t.dport,
        dport: t.sport,
        l4proto: t.l4proto,
    }
}

/// Keeps one row per key of the table (flow, time, process), sorted by it
fn by_key(rows: &mut Vec<FlowOwner>) {
    let mut seen = HashSet::new();
    rows.retain(|r| seen.insert((r.flow_id, r.ts, r.pid)));
    rows.sort_by_key(|r| (r.flow_id, r.ts, r.pid));
}

/// The owner rows of `flows`, and the owners whose connection has no flow. A snapshot owner
/// that an owner record of the same flow and process names from before the snapshot ended is
/// left out: the connection was opened while the snapshot ran.
pub fn join(owned: &[Owned], flows: &[Flow]) -> (Vec<FlowOwner>, Unmatched) {
    let ids: HashMap<&IpTuple, i64> = flows.iter().map(|f| (&f.tuple, f.id)).collect();
    let mut rows: Vec<(FlowOwner, Option<i64>)> = Vec::new();
    let mut unmatched = Unmatched::default();
    for o in owned {
        let back = reversed(&o.tuple);
        let mut matched: Vec<i64> = [&o.tuple, &back]
            .into_iter()
            .filter_map(|t| ids.get(t).copied())
            .collect();
        matched.dedup();
        if matched.is_empty() {
            match o.seen_until {
                Some(_) => unmatched.snapshot += 1,
                None => unmatched.records += 1,
            }
        }
        rows.extend(matched.into_iter().map(|flow_id| {
            let owner = FlowOwner {
                flow_id,
                ..o.owner.clone()
            };
            (owner, o.seen_until)
        }));
    }
    // The first owner record of each flow and process
    let mut recorded: HashMap<(i64, i64), i64> = HashMap::new();
    for (r, _) in rows.iter().filter(|(_, seen_until)| seen_until.is_none()) {
        let first = recorded.entry((r.flow_id, r.pid)).or_insert(r.ts);
        *first = (*first).min(r.ts);
    }
    let mut rows: Vec<FlowOwner> = rows
        .into_iter()
        .filter(|(r, seen_until)| match seen_until {
            Some(until) => recorded
                .get(&(r.flow_id, r.pid))
                .is_none_or(|first| first > until),
            None => true,
        })
        .map(|(r, _)| r)
        .collect();
    by_key(&mut rows);
    (rows, unmatched)
}

/// Gives the flows of each connection that have no owner of their own the owner of the
/// connection, from their first record on. The recorder writes no owner record for an MPTCP
/// subflow the path manager added: its process is the one that opened the connection's first
/// subflow. The connection's owner is the one that opened a member flow last before the
/// connection ended; a flow has an owner of its own if one opened it since.
pub fn inherit(
    rows: &mut Vec<FlowOwner>,
    connections: &[ConnectionInfo],
    members: &[ConnectionFlow],
) {
    let mut by_flow: HashMap<i64, Vec<usize>> = HashMap::new();
    for (i, r) in rows.iter().enumerate() {
        by_flow.entry(r.flow_id).or_default().push(i);
    }
    let mut by_connection: HashMap<i64, Vec<&ConnectionFlow>> = HashMap::new();
    for m in members {
        by_connection.entry(m.connection_id).or_default().push(m);
    }
    let mut inherited = Vec::new();
    for c in connections {
        let Some(flows) = by_connection.get(&c.id) else {
            continue;
        };
        let candidates: Vec<&FlowOwner> = flows
            .iter()
            .filter_map(|m| by_flow.get(&m.flow_id))
            .flatten()
            .map(|&i| &rows[i])
            .filter(|r| r.ts <= c.end_ts)
            .collect();
        let Some(opened) = candidates.iter().map(|r| r.ts).max() else {
            continue;
        };
        for m in flows {
            let own = candidates
                .iter()
                .any(|r| r.flow_id == m.flow_id && r.ts >= opened && r.ts <= m.last_ts);
            if own {
                continue;
            }
            inherited.extend(
                candidates
                    .iter()
                    .filter(|r| r.ts == opened)
                    .map(|r| FlowOwner {
                        flow_id: m.flow_id,
                        ts: m.first_ts,
                        source: FlowOwner::SOURCE_CONNECTION.to_string(),
                        ..(*r).clone()
                    }),
            );
        }
    }
    rows.extend(inherited);
    by_key(rows);
}

/// Fills the owners of `catalog`, whose flows and connections are in place, and returns the
/// owners whose connection has no flow
pub fn add_to(catalog: &mut Catalog, owned: &[Owned]) -> Unmatched {
    let (mut rows, unmatched) = join(owned, &catalog.flows);
    inherit(&mut rows, &catalog.connections, &catalog.connection_flows);
    catalog.owners = rows;
    unmatched
}

#[cfg(test)]
mod tests {
    use tcbee_trace::owners::{Holder, SnapshotConnection};

    use super::*;

    const AF_INET6: u16 = 10;

    /// addr_v4 as the recorder stores it: local address in the high half
    fn addr_v4(local: [u8; 4], remote: [u8; 4]) -> u64 {
        ((u32::from_le_bytes(local) as u64) << 32) | u32::from_le_bytes(remote) as u64
    }

    fn comm(name: &str) -> [u8; 16] {
        let mut c = [0u8; 16];
        c[..name.len()].copy_from_slice(name.as_bytes());
        c
    }

    fn record(time: u64, pid: u32, kind: u32, sport: u16, dport: u16) -> flow_owner_entry {
        flow_owner_entry {
            time,
            hook_seq: 1,
            addr_v4: addr_v4([10, 0, 0, 1], [10, 0, 0, 2]),
            sport,
            dport,
            family: AF_INET,
            kind: kind as u8,
            pid,
            uid: 1000,
            netns: 7,
            cgroup_id: 99,
            start_time: 1_230_000_000,
            comm: comm("iperf3"),
            ..Default::default()
        }
    }

    fn encode(recs: &[flow_owner_entry]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for r in recs {
            bytes.extend_from_slice(&bincode::serialize(r).unwrap());
            bytes.extend_from_slice(&tcbee_common::records::RECORD_DELIMITER);
        }
        bytes
    }

    fn tuple(src: &str, dst: &str, sport: u16, dport: u16) -> IpTuple {
        flow_tuple(src.parse().unwrap(), dst.parse().unwrap(), sport, dport)
    }

    fn flows(tuples: &[IpTuple]) -> Vec<Flow> {
        (1..)
            .zip(tuples)
            .map(|(id, t)| Flow::new(id, t.clone()))
            .collect()
    }

    #[test]
    fn records_decode_with_their_command_lines() {
        let bytes = encode(&[record(5, 42, TCBEE_OWNER_CONNECT, 40000, 5201)]);
        assert_eq!(bytes.len(), ENTRY_SIZE);
        let mut json = FlowOwners::new(1, 100);
        json.processes.push(ProcessInfo {
            pid: 42,
            start_ticks: 123,
            comm: "iperf3".into(),
            cmdline: vec!["iperf3".into(), "-c".into(), "10.0.0.2".into()],
            ..ProcessInfo::default()
        });
        let mut warnings = Vec::new();
        let mut truncated = bytes.clone();
        truncated.extend_from_slice(&[0; 7]);
        let owned = decode_records(&truncated, Some(&json), &mut warnings).unwrap();
        assert_eq!(warnings.len(), 1);
        let o = &owned[0];
        assert_eq!(o.tuple, tuple("10.0.0.1", "10.0.0.2", 40000, 5201));
        assert_eq!(o.owner.source, "connect");
        assert_eq!(o.owner.comm, "iperf3");
        assert_eq!(o.owner.cmdline.as_deref(), Some("iperf3 -c 10.0.0.2"));
        assert_eq!((o.owner.uid, o.owner.netns), (Some(1000), Some(7)));
        assert!(!o.owner.kthread);
        let without = decode_records(&bytes, None, &mut warnings).unwrap();
        assert_eq!(without[0].owner.cmdline, None);
    }

    #[test]
    fn v4_mapped_addresses_become_ipv4() {
        let mut r = record(5, 42, TCBEE_OWNER_ACCEPT, 5201, 40000);
        r.family = AF_INET6;
        r.src_v6[10..12].copy_from_slice(&[0xff, 0xff]);
        r.src_v6[12..].copy_from_slice(&[10, 0, 0, 2]);
        r.dst_v6[10..12].copy_from_slice(&[0xff, 0xff]);
        r.dst_v6[12..].copy_from_slice(&[10, 0, 0, 1]);
        let owned = decode_records(&encode(&[r]), None, &mut Vec::new()).unwrap();
        assert_eq!(owned[0].tuple, tuple("10.0.0.2", "10.0.0.1", 5201, 40000));
        assert_eq!(owned[0].owner.source, "accept");

        let mut json = FlowOwners::new(9, 100);
        json.connections.push(SnapshotConnection {
            local: "[::ffff:10.0.0.1]:40000".parse().unwrap(),
            remote: "[::ffff:10.0.0.2]:5201".parse().unwrap(),
            netns: 7,
            state: "ESTABLISHED".into(),
            uid: 1000,
            inode: 5,
            holders: vec![Holder {
                pid: 42,
                start_ticks: 1,
            }],
        });
        let snap = snapshot_owners(&json);
        assert_eq!(snap[0].tuple, tuple("10.0.0.1", "10.0.0.2", 40000, 5201));
    }

    /// The flow of the tuple and the reversed one both get the owner
    #[test]
    fn owners_join_both_directions() {
        let out = tuple("10.0.0.1", "10.0.0.2", 40000, 5201);
        let back = reversed(&out);
        let other = tuple("10.0.0.1", "10.0.0.3", 40001, 443);
        let owned = decode_records(
            &encode(&[
                record(5, 42, TCBEE_OWNER_CONNECT, 40000, 5201),
                record(6, 43, TCBEE_OWNER_CONNECT, 40002, 22),
            ]),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        let (rows, unmatched) = join(&owned, &flows(&[out, other, back]));
        let got: Vec<(i64, i64)> = rows.iter().map(|r| (r.flow_id, r.pid)).collect();
        assert_eq!(got, [(1, 42), (3, 42)]);
        assert_eq!(
            unmatched,
            Unmatched {
                records: 1,
                snapshot: 0
            }
        );
    }

    /// A reused tuple has an owner per connection, by time
    #[test]
    fn reused_tuple_keeps_both_owners() {
        let owned = decode_records(
            &encode(&[
                record(5, 42, TCBEE_OWNER_CONNECT, 40000, 5201),
                record(900, 77, TCBEE_OWNER_CONNECT, 40000, 5201),
            ]),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        let (rows, _) = join(
            &owned,
            &flows(&[tuple("10.0.0.1", "10.0.0.2", 40000, 5201)]),
        );
        let got: Vec<(i64, i64)> = rows.iter().map(|r| (r.ts, r.pid)).collect();
        assert_eq!(got, [(5, 42), (900, 77)]);
    }

    #[test]
    fn snapshot_lists_every_holder_unless_a_record_was_first() {
        let mut json = FlowOwners::new(50, 100);
        json.connections.push(SnapshotConnection {
            local: "10.0.0.1:40000".parse().unwrap(),
            remote: "10.0.0.2:5201".parse().unwrap(),
            netns: 7,
            state: "ESTABLISHED".into(),
            uid: 1000,
            inode: 5,
            holders: vec![
                Holder {
                    pid: 42,
                    start_ticks: 1,
                },
                Holder {
                    pid: 43,
                    start_ticks: 2,
                },
            ],
        });
        json.processes.push(ProcessInfo {
            pid: 43,
            start_ticks: 2,
            comm: "worker".into(),
            cmdline: vec!["worker".into()],
            cgroup: Some("/a".into()),
            uid: Some(0),
        });
        // A later process with pid 42, whose command line the resolver found: not the holder
        json.processes.push(ProcessInfo {
            pid: 42,
            start_ticks: 99,
            comm: "later".into(),
            ..ProcessInfo::default()
        });
        let flow = flows(&[tuple("10.0.0.1", "10.0.0.2", 40000, 5201)]);
        let snap = snapshot_owners(&json);
        let (rows, unmatched) = join(&snap, &flow);
        assert_eq!(unmatched, Unmatched::default());
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r.pid, r.comm.as_str(), r.uid, r.start_time))
            .collect();
        assert_eq!(
            got,
            [
                (42, "", Some(1000), Some(10_000_000)),
                (43, "worker", Some(0), Some(20_000_000))
            ]
        );
        assert_eq!(rows[1].cmdline.as_deref(), Some("worker"));

        // pid 42 connected just before the snapshot: its record stays, the snapshot row goes
        let mut owned = decode_records(
            &encode(&[record(40, 42, TCBEE_OWNER_CONNECT, 40000, 5201)]),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        owned.extend(snap);
        let (rows, _) = join(&owned, &flow);
        let got: Vec<_> = rows.iter().map(|r| (r.pid, r.source.as_str())).collect();
        assert_eq!(got, [(42, "connect"), (43, "snapshot")]);
    }

    /// A record of the same process from while the snapshot ran is the same connection
    #[test]
    fn records_from_during_the_snapshot_replace_it() {
        let mut json = FlowOwners::new(50, 100);
        json.snapshot_end_ns = 70;
        let holder = |pid| Holder {
            pid,
            start_ticks: 1,
        };
        json.connections.push(SnapshotConnection {
            local: "10.0.0.1:40000".parse().unwrap(),
            remote: "10.0.0.2:5201".parse().unwrap(),
            netns: 7,
            state: "ESTABLISHED".into(),
            uid: 1000,
            inode: 5,
            holders: vec![holder(42), holder(43)],
        });
        // Not a flow: counted apart from the records
        json.connections.push(SnapshotConnection {
            local: "10.0.0.1:40009".parse().unwrap(),
            remote: "10.0.0.2:22".parse().unwrap(),
            netns: 7,
            state: "ESTABLISHED".into(),
            uid: 1000,
            inode: 6,
            holders: vec![holder(44)],
        });
        let mut owned = decode_records(
            &encode(&[
                record(60, 42, TCBEE_OWNER_CONNECT, 40000, 5201),
                record(80, 43, TCBEE_OWNER_CONNECT, 40000, 5201),
            ]),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        owned.extend(snapshot_owners(&json));
        let flow = flows(&[tuple("10.0.0.1", "10.0.0.2", 40000, 5201)]);
        let (rows, unmatched) = join(&owned, &flow);
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r.ts, r.pid, r.source.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (50, 43, "snapshot"),
                (60, 42, "connect"),
                (80, 43, "connect")
            ]
        );
        assert_eq!(
            unmatched,
            Unmatched {
                records: 0,
                snapshot: 1
            }
        );
    }

    /// The first subflow has the owner record, a joined subflow takes it from the connection
    #[test]
    fn joined_subflows_take_the_owner_of_their_connection() {
        let first = tuple("10.0.0.1", "10.0.0.2", 40000, 5201);
        let joined = tuple("10.0.1.1", "10.0.0.2", 40100, 5201);
        let unrelated = tuple("10.0.0.1", "10.0.0.3", 40200, 22);
        let all = flows(&[first, joined, unrelated]);
        let owned = decode_records(
            &encode(&[record(5, 42, TCBEE_OWNER_CONNECT, 40000, 5201)]),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        let (mut rows, _) = join(&owned, &all);
        let connection = ConnectionInfo {
            id: 1,
            kind: ConnectionInfo::KIND_MPTCP.into(),
            key: 7,
            flow_id: None,
            start_ts: 10,
            end_ts: 500,
        };
        let member = |flow_id, first_ts, last_ts| ConnectionFlow {
            connection_id: 1,
            flow_id,
            subflow_id: None,
            first_ts,
            last_ts,
        };
        inherit(
            &mut rows,
            &[connection],
            &[member(1, 10, 500), member(2, 100, 400)],
        );
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r.flow_id, r.ts, r.pid, r.source.as_str()))
            .collect();
        assert_eq!(got, [(1, 5, 42, "connect"), (2, 100, 42, "connection")]);
    }

    /// The first subflow's tuple is reused by a later connection of another process: each
    /// connection's joined subflow takes the owner of its own connection
    #[test]
    fn reused_first_subflow_tuple_gives_each_connection_its_owner() {
        let first = tuple("10.0.0.1", "10.0.0.2", 40000, 5201);
        let joined_a = tuple("10.0.1.1", "10.0.0.2", 40100, 5201);
        let joined_b = tuple("10.0.1.1", "10.0.0.2", 40101, 5201);
        let all = flows(&[first, joined_a, joined_b]);
        let owned = decode_records(
            &encode(&[
                record(5, 42, TCBEE_OWNER_CONNECT, 40000, 5201),
                record(1000, 77, TCBEE_OWNER_CONNECT, 40000, 5201),
            ]),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        let (mut rows, _) = join(&owned, &all);
        let connection = |id, start_ts, end_ts| ConnectionInfo {
            id,
            kind: ConnectionInfo::KIND_MPTCP.into(),
            key: 7,
            flow_id: None,
            start_ts,
            end_ts,
        };
        let member = |connection_id, flow_id, first_ts, last_ts| ConnectionFlow {
            connection_id,
            flow_id,
            subflow_id: None,
            first_ts,
            last_ts,
        };
        inherit(
            &mut rows,
            &[connection(1, 10, 500), connection(2, 1010, 1500)],
            &[
                member(1, 1, 10, 500),
                member(1, 2, 100, 400),
                member(2, 1, 1010, 1500),
                member(2, 3, 1100, 1400),
            ],
        );
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r.flow_id, r.ts, r.pid, r.source.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (1, 5, 42, "connect"),
                (1, 1000, 77, "connect"),
                (2, 100, 42, "connection"),
                (3, 1100, 77, "connection")
            ]
        );
    }

    /// Both ends of a connection on one host, over loopback: the client's connect and the
    /// server's accept name the two directions, and each flow gets both processes
    #[test]
    fn loopback_flows_name_client_and_server() {
        let loopback = |time, pid, kind, local: u16, remote: u16| flow_owner_entry {
            addr_v4: addr_v4([127, 0, 0, 1], [127, 0, 0, 1]),
            ..record(time, pid, kind, local, remote)
        };
        let owned = decode_records(
            &encode(&[
                loopback(5, 42, TCBEE_OWNER_CONNECT, 40000, 5201),
                loopback(6, 77, TCBEE_OWNER_ACCEPT, 5201, 40000),
            ]),
            None,
            &mut Vec::new(),
        )
        .unwrap();
        let out = tuple("127.0.0.1", "127.0.0.1", 40000, 5201);
        let back = reversed(&out);
        let (rows, _) = join(&owned, &flows(&[out, back]));
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r.flow_id, r.pid, r.source.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (1, 42, "connect"),
                (1, 77, "accept"),
                (2, 42, "connect"),
                (2, 77, "accept")
            ]
        );
    }

    #[test]
    fn a_trace_without_owners_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let owners = read(dir.path());
        assert!(owners.owned.is_empty() && owners.warnings.is_empty());
    }
}
