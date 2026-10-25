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
//! time.

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
use ts_storage::{Flow, FlowOwner, IpTuple};

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
}

/// The owners of a recording, from both files; a part that cannot be read is a warning
#[derive(Debug, Default)]
pub struct Owners {
    pub owned: Vec<Owned>,
    pub warnings: Vec<String>,
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

/// The owner of one record. The command line and cgroup path come from `flow_owners.json`, if
/// the recorder found the process there.
fn record_owner(r: &flow_owner_entry, json: Option<&FlowOwners>) -> Owned {
    let source = match u32::from(r.kind) {
        TCBEE_OWNER_CONNECT => FlowOwner::SOURCE_CONNECT.to_string(),
        TCBEE_OWNER_ACCEPT => FlowOwner::SOURCE_ACCEPT.to_string(),
        other => format!("kind {other}"),
    };
    let process = json.and_then(|j| j.process(r.pid, r.start_time));
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
    }
}

/// Decodes the owner records of `bytes`; a truncated last record is left out with a warning
pub fn decode_records(
    bytes: &[u8],
    json: Option<&FlowOwners>,
    warnings: &mut Vec<String>,
) -> Result<Vec<Owned>, DecodeError> {
    let tail = bytes.len() % ENTRY_SIZE;
    if tail != 0 {
        warnings.push(format!(
            "flow_owners.tcp: {tail} trailing bytes do not form a whole record ({ENTRY_SIZE} \
             bytes) and are ignored (recording stopped mid-write?)"
        ));
    }
    bytes
        .chunks_exact(ENTRY_SIZE)
        .map(|chunk| {
            decode_record::<flow_owner_entry>(chunk, ENTRY_SIZE).map(|r| record_owner(&r, json))
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

/// The owners of the connections that existed at the start: every process that held the socket
pub fn snapshot_owners(json: &FlowOwners) -> Vec<Owned> {
    let tick_ns = 1_000_000_000u64.checked_div(json.clock_ticks).unwrap_or(0);
    let mut owned = Vec::new();
    for c in &json.connections {
        let (src, sport) = snapshot_addr(c.local);
        let (dst, dport) = snapshot_addr(c.remote);
        let tuple = flow_tuple(src, dst, sport, dport);
        for &pid in &c.pids {
            // The snapshot's processes come first, before those of the owner records
            let process = json.processes.iter().find(|p| p.pid == pid);
            owned.push(Owned {
                tuple: tuple.clone(),
                owner: FlowOwner {
                    flow_id: 0,
                    ts: json.snapshot_ns as i64,
                    source: FlowOwner::SOURCE_SNAPSHOT.to_string(),
                    pid: i64::from(pid),
                    uid: Some(i64::from(process.and_then(|p| p.uid).unwrap_or(c.uid))),
                    comm: process.map(|p| p.comm.clone()).unwrap_or_default(),
                    cmdline: process.and_then(cmdline),
                    start_time: process.map(|p| (p.start_ticks * tick_ns) as i64),
                    cgroup_id: None,
                    cgroup: process.and_then(|p| p.cgroup.clone()),
                    netns: Some(i64::from(c.netns)),
                    kthread: false,
                },
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

/// The owner rows of `flows`, and the number of owners whose connection has no flow. A snapshot
/// owner that an owner record of the same process already names, from before the snapshot, is
/// left out: the connection was opened while the snapshot started.
pub fn join(owned: &[Owned], flows: &[Flow]) -> (Vec<FlowOwner>, usize) {
    let ids: HashMap<&IpTuple, i64> = flows.iter().map(|f| (&f.tuple, f.id)).collect();
    let mut rows: Vec<FlowOwner> = Vec::new();
    let mut unmatched = 0;
    for o in owned {
        let back = reversed(&o.tuple);
        let mut matched: Vec<i64> = [&o.tuple, &back]
            .into_iter()
            .filter_map(|t| ids.get(t).copied())
            .collect();
        matched.dedup();
        if matched.is_empty() {
            unmatched += 1;
        }
        rows.extend(matched.into_iter().map(|flow_id| FlowOwner {
            flow_id,
            ..o.owner.clone()
        }));
    }
    // The first owner record of each flow and process
    let mut recorded: HashMap<(i64, i64), i64> = HashMap::new();
    for r in rows
        .iter()
        .filter(|r| r.source != FlowOwner::SOURCE_SNAPSHOT)
    {
        let first = recorded.entry((r.flow_id, r.pid)).or_insert(r.ts);
        *first = (*first).min(r.ts);
    }
    rows.retain(|r| {
        r.source != FlowOwner::SOURCE_SNAPSHOT
            || recorded
                .get(&(r.flow_id, r.pid))
                .is_none_or(|&first| first > r.ts)
    });
    // One row per flow, time and process, the key of the table
    let mut seen = HashSet::new();
    rows.retain(|r| seen.insert((r.flow_id, r.ts, r.pid)));
    rows.sort_by_key(|r| (r.flow_id, r.ts, r.pid));
    (rows, unmatched)
}

#[cfg(test)]
mod tests {
    use tcbee_trace::owners::SnapshotConnection;

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
            pids: vec![42],
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
        assert_eq!(unmatched, 1);
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
            pids: vec![42, 43],
        });
        json.processes.push(ProcessInfo {
            pid: 43,
            start_ticks: 2,
            comm: "worker".into(),
            cmdline: vec!["worker".into()],
            cgroup: Some("/a".into()),
            uid: Some(0),
        });
        let flow = flows(&[tuple("10.0.0.1", "10.0.0.2", 40000, 5201)]);
        let snap = snapshot_owners(&json);
        let (rows, unmatched) = join(&snap, &flow);
        assert_eq!(unmatched, 0);
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r.pid, r.comm.as_str(), r.uid, r.start_time))
            .collect();
        assert_eq!(
            got,
            [
                (42, "", Some(1000), None),
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

    #[test]
    fn a_trace_without_owners_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let owners = read(dir.path());
        assert!(owners.owned.is_empty() && owners.warnings.is_empty());
    }
}
