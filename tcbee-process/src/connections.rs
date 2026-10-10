//! Groups flows into connections. MPTCP is the only kind so far.
//!
//! The recorder tags the sock and cwnd records of a subflow with the local token of its
//! connection (`conn_id`) and writes the path manager events of the connection with the same
//! token. The workers collect the tagged flows from `Event::connection_key` of every record,
//! path manager events included; the events themselves are read once more afterwards.
//!
//! A token is only unique while its connection lives: the kernel may hand it to a new
//! connection once it is destroyed (TOKEN_DESTROYED). So the events of a token are cut into
//! lifetimes at each TOKEN_DESTROYED, and every lifetime is one connection. A subflow belongs to
//! the lifetime of its token that has not ended before the subflow's first record. Without path
//! manager events (`-M tag` alone), a token is one connection.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::fs::File;
use std::ops::Range;
use std::path::Path;

use anyhow::{anyhow, Result};
use tcbee_common::records::{
    mptcp_pm_entry, TCBEE_MPTCP_CREATED, TCBEE_MPTCP_SUB_ESTABLISHED, TCBEE_MPTCP_TOKEN_DESTROYED,
};
use tcbee_trace::TraceFile;
use ts_storage::{ConnectionFlow, ConnectionInfo, Flow, IpTuple};

use crate::decode::decode_range;
use crate::event::Event;

/// The trace file whose events cut tokens into connections
pub const EVENT_FILE: TraceFile = TraceFile::MptcpPm;

/// First and last timestamp of the tagged records of each (flow, token), collected by the
/// workers.
#[derive(Default, Debug)]
pub struct TaggedFlows {
    spans: HashMap<(i64, u32), (i64, i64)>,
    /// Flows with socket records (sock, cwnd) without a token: plain TCP sockets
    untagged_sockets: HashSet<i64>,
}

impl TaggedFlows {
    pub fn observe(&mut self, flow_id: i64, token: u32, ts: i64) {
        let span = self.spans.entry((flow_id, token)).or_insert((ts, ts));
        span.0 = span.0.min(ts);
        span.1 = span.1.max(ts);
    }

    pub fn untagged_socket(&mut self, flow_id: i64) {
        self.untagged_sockets.insert(flow_id);
    }

    pub fn merge(&mut self, other: TaggedFlows) {
        for ((flow_id, token), (first, last)) in other.spans {
            self.observe(flow_id, token, first);
            self.observe(flow_id, token, last);
        }
        self.untagged_sockets.extend(other.untagged_sockets);
    }
}

/// The fields of a path manager record that the grouping needs.
#[derive(Clone, Debug)]
pub struct PmEvent {
    pub ts: i64,
    pub event: u32,
    pub token: u32,
    pub subflow_id: u32,
    pub flow: IpTuple,
}

/// Reads the records `records` of an `mptcp_pm.tcp` file.
pub fn read_pm_events(path: &Path, records: Range<u64>) -> Result<Vec<PmEvent>> {
    let file = File::open(path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
    let mut events = Vec::new();
    decode_range::<mptcp_pm_entry, Infallible>(&file, records, |_, r| {
        events.push(PmEvent {
            ts: r.ts_ns(),
            event: r.event.into(),
            token: r.token,
            subflow_id: r.subflow_id,
            flow: r.flow_key(),
        });
        Ok(())
    })
    .map_err(|e| anyhow!("{}: {e}", path.display()))?;
    Ok(events)
}

/// One lifetime of a token
#[derive(Debug)]
struct Lifetime {
    /// First path manager event, none if there are only tagged records
    start: Option<i64>,
    /// TOKEN_DESTROYED, if recorded
    end: Option<i64>,
}

/// Cuts the events of each token into lifetimes, in time order per token.
fn lifetimes(events: &[PmEvent]) -> BTreeMap<u32, Vec<Lifetime>> {
    let mut sorted: Vec<&PmEvent> = events.iter().filter(|e| e.token != 0).collect();
    sorted.sort_by_key(|e| e.ts);
    let mut by_token: BTreeMap<u32, Vec<Lifetime>> = BTreeMap::new();
    for e in sorted {
        let lives = by_token.entry(e.token).or_default();
        if lives.last().is_none_or(|l| l.end.is_some()) {
            lives.push(Lifetime {
                start: Some(e.ts),
                end: None,
            });
        }
        if e.event == TCBEE_MPTCP_TOKEN_DESTROYED {
            lives.last_mut().unwrap().end = Some(e.ts);
        }
    }
    by_token
}

/// The lifetime a flow whose records start at `first` belongs to: the first that has not ended
/// before, else the last one
fn lifetime_of(lives: &[Lifetime], first: i64) -> usize {
    lives
        .iter()
        .position(|l| l.end.is_none_or(|end| end >= first))
        .unwrap_or(lives.len() - 1)
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

/// A flow of a connection: its first and last tagged record
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Member {
    flow_id: i64,
    first_ts: i64,
    last_ts: i64,
}

/// Subflow ids from the events that name one, per (flow, token)
fn subflow_ids(events: &[PmEvent], flow_ids: &HashMap<&IpTuple, i64>) -> HashMap<(i64, u32), i64> {
    let mut ids = HashMap::new();
    for e in events {
        let names_subflow =
            e.event == TCBEE_MPTCP_CREATED || e.event == TCBEE_MPTCP_SUB_ESTABLISHED;
        if !names_subflow || e.token == 0 || e.subflow_id == 0 {
            continue;
        }
        if let Some(&flow_id) = flow_ids.get(&e.flow) {
            ids.entry((flow_id, e.token)).or_insert(e.subflow_id.into());
        }
    }
    ids
}

/// The members of each lifetime, keyed by (token, index into the token's lifetimes)
fn members_per_lifetime(
    tagged: TaggedFlows,
    lifetimes: &BTreeMap<u32, Vec<Lifetime>>,
) -> BTreeMap<(u32, usize), Vec<Member>> {
    let mut members: BTreeMap<(u32, usize), Vec<Member>> = BTreeMap::new();
    for ((flow_id, token), (first_ts, last_ts)) in tagged.spans {
        let life = lifetime_of(&lifetimes[&token], first_ts);
        members.entry((token, life)).or_default().push(Member {
            flow_id,
            first_ts,
            last_ts,
        });
    }
    for list in members.values_mut() {
        list.sort();
    }
    members
}

/// One connection per lifetime, ordered by start, with ids from 1
fn connection_rows(
    lifetimes: BTreeMap<u32, Vec<Lifetime>>,
    mut members: BTreeMap<(u32, usize), Vec<Member>>,
) -> Vec<(ConnectionInfo, Vec<Member>)> {
    let mut connections = Vec::new();
    for (token, lives) in lifetimes {
        for (index, life) in lives.into_iter().enumerate() {
            let flows = members.remove(&(token, index)).unwrap_or_default();
            let first = flows.iter().map(|m| m.first_ts).min();
            let last = flows.iter().map(|m| m.last_ts).max();
            let Some(start) = [life.start, first].into_iter().flatten().min() else {
                continue;
            };
            let end = [life.end, last]
                .into_iter()
                .flatten()
                .max()
                .unwrap_or(start);
            let info = ConnectionInfo {
                id: 0,
                kind: ConnectionInfo::KIND_MPTCP.to_string(),
                key: token.into(),
                flow_id: None,
                start_ts: start,
                end_ts: end,
            };
            connections.push((info, flows));
        }
    }
    connections.sort_by_key(|(c, _)| (c.start_ts, c.key));
    for (index, (info, _)) in connections.iter_mut().enumerate() {
        info.id = index as i64 + 1;
    }
    connections
}

/// The connections and their flows. A flow without a token of its own whose reversed tuple is a
/// member (the receive side of packet header records) belongs to the same connection. Flows
/// with a token keep their own: both ends of a connection may be recorded on one host. So does
/// a flow whose socket records carry no token: the plain TCP end of a connection that fell
/// back on one side only.
pub fn assemble(
    tagged: TaggedFlows,
    events: &[PmEvent],
    flows: &[Flow],
) -> (Vec<ConnectionInfo>, Vec<ConnectionFlow>) {
    let flow_ids: HashMap<&IpTuple, i64> = flows.iter().map(|f| (&f.tuple, f.id)).collect();
    let tuples: HashMap<i64, &IpTuple> = flows.iter().map(|f| (f.id, &f.tuple)).collect();
    let subflow_ids = subflow_ids(events, &flow_ids);
    let mut has_connection: HashSet<i64> = tagged.spans.keys().map(|(flow, _)| *flow).collect();
    has_connection.extend(tagged.untagged_sockets.iter().copied());

    let mut lifetimes = lifetimes(events);
    for &(_, token) in tagged.spans.keys() {
        // A token with tagged records but no events is one connection over all of them
        lifetimes.entry(token).or_insert_with(|| {
            vec![Lifetime {
                start: None,
                end: None,
            }]
        });
    }
    let members = members_per_lifetime(tagged, &lifetimes);

    let mut infos = Vec::new();
    let mut connection_flows = Vec::new();
    for (info, members) in connection_rows(lifetimes, members) {
        let token = info.key as u32;
        for m in members {
            let row = |flow_id| ConnectionFlow {
                connection_id: info.id,
                flow_id,
                subflow_id: subflow_ids.get(&(m.flow_id, token)).copied(),
                first_ts: m.first_ts,
                last_ts: m.last_ts,
            };
            connection_flows.push(row(m.flow_id));
            let reverse = tuples
                .get(&m.flow_id)
                .and_then(|t| flow_ids.get(&reversed(t)));
            if let Some(&reverse) = reverse {
                if has_connection.insert(reverse) {
                    connection_flows.push(row(reverse));
                }
            }
        }
        infos.push(info);
    }
    (infos, connection_flows)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tcbee_common::records::{TCBEE_MPTCP_CLOSED, TCBEE_MPTCP_ESTABLISHED};

    use super::*;

    fn tuple(sport: i64, dport: i64) -> IpTuple {
        IpTuple {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            sport,
            dport,
            l4proto: 6,
        }
    }

    fn flows(tuples: &[IpTuple]) -> Vec<Flow> {
        tuples
            .iter()
            .enumerate()
            .map(|(i, t)| Flow::new(i as i64 + 1, t.clone()))
            .collect()
    }

    fn event(ts: i64, event: u32, token: u32, subflow_id: u32, flow: &IpTuple) -> PmEvent {
        PmEvent {
            ts,
            event,
            token,
            subflow_id,
            flow: flow.clone(),
        }
    }

    fn members(cf: &[ConnectionFlow], connection_id: i64) -> Vec<(i64, Option<i64>)> {
        cf.iter()
            .filter(|c| c.connection_id == connection_id)
            .map(|c| (c.flow_id, c.subflow_id))
            .collect()
    }

    #[test]
    fn subflows_of_one_connection() {
        let (a, b) = (tuple(40000, 5201), tuple(40001, 5201));
        let fl = flows(&[a.clone(), b.clone()]);
        let mut tagged = TaggedFlows::default();
        // The first record of a subflow can precede CREATED
        tagged.observe(1, 7, 5);
        tagged.observe(1, 7, 90);
        tagged.observe(2, 7, 30);
        let events = [
            event(10, TCBEE_MPTCP_CREATED, 7, 1, &a),
            event(20, TCBEE_MPTCP_ESTABLISHED, 7, 1, &a),
            event(25, TCBEE_MPTCP_SUB_ESTABLISHED, 7, 2, &b),
            event(80, TCBEE_MPTCP_CLOSED, 7, 0, &a),
            event(85, TCBEE_MPTCP_TOKEN_DESTROYED, 7, 0, &a),
        ];
        let (conns, cf) = assemble(tagged, &events, &fl);
        assert_eq!(conns.len(), 1);
        assert_eq!(
            (conns[0].key, conns[0].start_ts, conns[0].end_ts),
            (7, 5, 90)
        );
        assert_eq!(conns[0].kind, "mptcp");
        assert_eq!(members(&cf, 1), vec![(1, Some(1)), (2, Some(2))]);
    }

    #[test]
    fn reused_token_is_a_new_connection() {
        let (a, b) = (tuple(40000, 5201), tuple(40002, 5201));
        let fl = flows(&[a.clone(), b.clone()]);
        let mut tagged = TaggedFlows::default();
        tagged.observe(1, 7, 10);
        tagged.observe(2, 7, 210);
        let events = [
            event(10, TCBEE_MPTCP_CREATED, 7, 1, &a),
            event(100, TCBEE_MPTCP_TOKEN_DESTROYED, 7, 0, &a),
            event(200, TCBEE_MPTCP_CREATED, 7, 1, &b),
        ];
        let (conns, cf) = assemble(tagged, &events, &fl);
        assert_eq!(conns.len(), 2);
        assert_eq!((conns[0].start_ts, conns[0].end_ts), (10, 100));
        assert_eq!((conns[1].start_ts, conns[1].end_ts), (200, 210));
        assert_eq!(members(&cf, 1), vec![(1, Some(1))]);
        assert_eq!(members(&cf, 2), vec![(2, Some(1))]);
    }

    #[test]
    fn records_after_the_last_lifetime_belong_to_it() {
        let a = tuple(40000, 5201);
        let fl = flows(&[a.clone()]);
        let mut tagged = TaggedFlows::default();
        // Data still leaving after the token was destroyed
        tagged.observe(1, 7, 150);
        let events = [
            event(10, TCBEE_MPTCP_CREATED, 7, 1, &a),
            event(100, TCBEE_MPTCP_TOKEN_DESTROYED, 7, 0, &a),
        ];
        let (conns, cf) = assemble(tagged, &events, &fl);
        assert_eq!(conns.len(), 1);
        assert_eq!((conns[0].start_ts, conns[0].end_ts), (10, 150));
        assert_eq!(members(&cf, 1), vec![(1, Some(1))]);
    }

    #[test]
    fn tags_without_path_manager_events() {
        let (a, b) = (tuple(40000, 5201), tuple(40001, 5201));
        let fl = flows(&[a, b]);
        let mut tagged = TaggedFlows::default();
        tagged.observe(1, 7, 10);
        tagged.observe(2, 7, 20);
        tagged.observe(2, 9, 50);
        let (conns, cf) = assemble(tagged, &[], &fl);
        assert_eq!(conns.len(), 2);
        assert_eq!(
            (conns[0].key, conns[0].start_ts, conns[0].end_ts),
            (7, 10, 20)
        );
        assert_eq!(conns[1].key, 9);
        assert_eq!(members(&cf, 1), vec![(1, None), (2, None)]);
        assert_eq!(members(&cf, 2), vec![(2, None)]);
    }

    #[test]
    fn both_ends_on_one_host_keep_their_tokens() {
        let a = tuple(40000, 5201);
        let fl = flows(&[a.clone(), reversed(&a)]);
        let mut tagged = TaggedFlows::default();
        tagged.observe(1, 7, 10);
        tagged.observe(2, 9, 10);
        let (_, cf) = assemble(tagged, &[], &fl);
        assert_eq!(members(&cf, 1), vec![(1, None)]);
        assert_eq!(members(&cf, 2), vec![(2, None)]);
    }

    #[test]
    fn plain_tcp_socket_keeps_out_of_the_reversed_connection() {
        let a = tuple(40000, 5201);
        let fl = flows(&[a.clone(), reversed(&a)]);
        let mut tagged = TaggedFlows::default();
        tagged.observe(1, 7, 10);
        tagged.untagged_socket(2);
        let (_, cf) = assemble(tagged, &[], &fl);
        assert_eq!(members(&cf, 1), vec![(1, None)]);
    }

    #[test]
    fn reversed_flow_joins_its_connection() {
        let a = tuple(40000, 5201);
        let fl = flows(&[a.clone(), reversed(&a), tuple(1, 2)]);
        let mut tagged = TaggedFlows::default();
        tagged.observe(1, 7, 10);
        let (_, cf) = assemble(tagged, &[], &fl);
        assert_eq!(members(&cf, 1), vec![(1, None), (2, None)]);
    }
}
