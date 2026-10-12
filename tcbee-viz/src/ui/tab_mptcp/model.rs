//! The parts of the MPTCP tab that do not draw: which end of a connection a recording shows,
//! the sidebar rows and their filter, the order of the subflows, the line segments of a series,
//! the path manager event types (names, lane rows, backup flag) and the subflows' byte shares.

use tcbee_common::records::{
    TCBEE_MPTCP_ANNOUNCED, TCBEE_MPTCP_CLOSED, TCBEE_MPTCP_CREATED, TCBEE_MPTCP_ESTABLISHED,
    TCBEE_MPTCP_FALLBACK, TCBEE_MPTCP_LISTENER_CLOSED, TCBEE_MPTCP_LISTENER_CREATED,
    TCBEE_MPTCP_MP_FAIL, TCBEE_MPTCP_MP_PRIO_SENT, TCBEE_MPTCP_PENDING_REQUEUED,
    TCBEE_MPTCP_REINJECTED, TCBEE_MPTCP_REMOVED, TCBEE_MPTCP_SUBFLOW_CONNECT,
    TCBEE_MPTCP_SUBFLOW_STALE, TCBEE_MPTCP_SUB_CLOSED, TCBEE_MPTCP_SUB_ESTABLISHED,
    TCBEE_MPTCP_SUB_PRIORITY, TCBEE_MPTCP_TOKEN_DESTROYED,
};
use ts_storage::ConnectionFlow;

/// A path manager event of the selected connection
#[derive(Clone, Debug, PartialEq)]
pub struct PmEvent {
    pub t: f64,
    /// `enum tcbee_mptcp_event` in records.h
    pub code: i64,
    /// Lane row: 0 for the connection, 1 + the index of the subflow otherwise
    pub row: usize,
    pub label: String,
    /// The subflow's backup flag, where the event carries it (see `carries_backup`)
    pub backup: bool,
}

/// Name of an event of the path manager records (`enum tcbee_mptcp_event` in records.h)
pub fn pm_event_name(event: i64) -> &'static str {
    match u32::try_from(event).unwrap_or(0) {
        TCBEE_MPTCP_CREATED => "created",
        TCBEE_MPTCP_ESTABLISHED => "established",
        TCBEE_MPTCP_CLOSED => "closed",
        TCBEE_MPTCP_ANNOUNCED => "address announced",
        TCBEE_MPTCP_REMOVED => "address removed",
        TCBEE_MPTCP_SUB_ESTABLISHED => "subflow established",
        TCBEE_MPTCP_SUB_CLOSED => "subflow closed",
        TCBEE_MPTCP_SUB_PRIORITY => "subflow priority",
        TCBEE_MPTCP_LISTENER_CREATED => "listener created",
        TCBEE_MPTCP_LISTENER_CLOSED => "listener closed",
        TCBEE_MPTCP_TOKEN_DESTROYED => "token destroyed",
        TCBEE_MPTCP_SUBFLOW_CONNECT => "subflow connect",
        TCBEE_MPTCP_MP_FAIL => "MP_FAIL",
        TCBEE_MPTCP_SUBFLOW_STALE => "subflow stale",
        TCBEE_MPTCP_MP_PRIO_SENT => "MP_PRIO sent",
        TCBEE_MPTCP_REINJECTED => "reinjected",
        TCBEE_MPTCP_PENDING_REQUEUED => "pending data requeued",
        TCBEE_MPTCP_FALLBACK => "fallback to TCP",
        _ => "event",
    }
}

/// Whether an event's record holds the subflow's backup flag
pub fn carries_backup(code: i64) -> bool {
    [
        TCBEE_MPTCP_SUB_ESTABLISHED,
        TCBEE_MPTCP_SUB_PRIORITY,
        TCBEE_MPTCP_MP_PRIO_SENT,
    ]
    .iter()
    .any(|c| *c as i64 == code)
}

/// Events about the whole connection go to its own lane row, the others to their subflow's.
/// Joins, sent MP_PRIOs, reinjections and requeued data are recorded on the connection's
/// socket, which carries the first subflow's tuple, so their record does not tell the subflow.
pub fn is_connection_event(code: i64) -> bool {
    [
        TCBEE_MPTCP_CREATED,
        TCBEE_MPTCP_ESTABLISHED,
        TCBEE_MPTCP_CLOSED,
        TCBEE_MPTCP_ANNOUNCED,
        TCBEE_MPTCP_REMOVED,
        TCBEE_MPTCP_LISTENER_CREATED,
        TCBEE_MPTCP_LISTENER_CLOSED,
        TCBEE_MPTCP_TOKEN_DESTROYED,
        TCBEE_MPTCP_FALLBACK,
        TCBEE_MPTCP_SUBFLOW_CONNECT,
        TCBEE_MPTCP_MP_PRIO_SENT,
        TCBEE_MPTCP_REINJECTED,
        TCBEE_MPTCP_PENDING_REQUEUED,
    ]
    .iter()
    .any(|c| *c as i64 == code)
}

/// Whether the event changes the connection's paths, as opposed to moving data, which can
/// happen thousands of times. Only these are marked in the metric plots.
pub fn is_structural(code: i64) -> bool {
    code != TCBEE_MPTCP_REINJECTED as i64 && code != TCBEE_MPTCP_PENDING_REQUEUED as i64
}

/// Plot height of a lane row; row 0 is at the top
pub fn lane_y(row: usize, rows: usize) -> f64 {
    rows.saturating_sub(1 + row) as f64
}

/// Name of a row of the event lane at plot height `y`: the connection on top, then the
/// subflows in the order they started
pub fn lane_row_name(y: f64, rows: usize) -> String {
    let row = rows as f64 - 1.0 - y;
    if row.fract() != 0.0 || row < 0.0 || row >= rows as f64 {
        return String::new();
    }
    match row as usize {
        0 => "conn".to_string(),
        k => format!("#{k}"),
    }
}

/// The event that the pointer at (`x`, `y`) of the lane is on: of type `name`, in the row at
/// `y`, closest in time. `name` is empty when the pointer is on no event.
pub fn nearest_event<'a>(
    events: &'a [PmEvent],
    name: &str,
    x: f64,
    y: f64,
    rows: usize,
) -> Option<&'a PmEvent> {
    if name.is_empty() {
        return None;
    }
    events
        .iter()
        .filter(|e| pm_event_name(e.code) == name && (lane_y(e.row, rows) - y).abs() < 0.5)
        .min_by(|a, b| (a.t - x).abs().total_cmp(&(b.t - x).abs()))
}

/// Puts the subflows of a connection in the order they started. The server does not number
/// its joins (no subflow id), so the id only breaks ties.
pub fn sort_subflows<M: std::borrow::Borrow<ConnectionFlow>>(members: &mut [M]) {
    members.sort_by_key(|m| (m.borrow().first_ts, m.borrow().subflow_id));
}

/// Which end of an MPTCP connection the recording shows
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
    /// Guessed from the lower port being the server's
    LikelyClient,
    LikelyServer,
}

impl Side {
    pub fn label(self) -> &'static str {
        match self {
            Side::Client => "client",
            Side::Server => "server",
            Side::LikelyClient => "client?",
            Side::LikelyServer => "server?",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Side::Client | Side::Server => {
                "From the token of the other end that the client's joins carry"
            }
            Side::LikelyClient | Side::LikelyServer => {
                "Guessed: the side of the port that every subflow shares, or else the lower port"
            }
        }
    }
}

/// What `infer_sides` needs of one connection
#[derive(Clone, Debug, Default)]
pub struct SideInput {
    /// The local token
    pub key: i64,
    /// Tokens of the other end that its subflows' path manager records carry (0 = none)
    pub remote_tokens: Vec<i64>,
    /// (local port, remote port) of each subflow
    pub ports: Vec<(i64, i64)>,
}

/// The side of each connection and the index of its other end, if both ends were recorded.
///
/// The joins of a client carry the server's token, which settles both ends. Otherwise the
/// server's port is the one that all subflows share (the listening port), and if that does
/// not decide, the lower port.
pub fn infer_sides(connections: &[SideInput]) -> Vec<(Option<Side>, Option<usize>)> {
    let mut out: Vec<(Option<Side>, Option<usize>)> = vec![(None, None); connections.len()];
    for (client, c) in connections.iter().enumerate() {
        let peer = c.remote_tokens.iter().filter(|t| **t != 0).find_map(|t| {
            connections
                .iter()
                .position(|other| other.key == *t)
                .filter(|server| *server != client)
        });
        if let Some(server) = peer {
            out[client] = (Some(Side::Client), Some(server));
            out[server] = (Some(Side::Server), Some(client));
        }
    }
    for (i, c) in connections.iter().enumerate() {
        if out[i].0.is_none() {
            out[i].0 = side_from_ports(&c.ports);
        }
    }
    out
}

fn side_from_ports(ports: &[(i64, i64)]) -> Option<Side> {
    let &(local, remote) = ports.first()?;
    let local_shared = ports.iter().all(|p| p.0 == local);
    let remote_shared = ports.iter().all(|p| p.1 == remote);
    Some(match (local_shared, remote_shared) {
        (true, false) => Side::LikelyServer,
        (false, true) => Side::LikelyClient,
        _ if local < remote => Side::LikelyServer,
        _ => Side::LikelyClient,
    })
}

/// One MPTCP connection in the sidebar table
#[derive(Clone, Debug)]
pub struct ConnectionSummary {
    pub id: i64,
    pub token: i64,
    /// local -> remote of the first subflow
    pub first_subflow: String,
    pub side: Option<Side>,
    /// Connection id of the other end, if recorded too
    pub peer: Option<i64>,
    pub subflows: usize,
    /// Path manager records on the subflows' tuples
    pub events: i64,
    pub start_s: f64,
    pub duration_s: f64,
}

impl ConnectionSummary {
    pub fn token_text(&self) -> String {
        format!("{:#010x}", self.token)
    }

    /// Whether the row matches every whitespace-separated term of a lowercase filter
    pub fn matches(&self, filter: &str) -> bool {
        let text = format!(
            "#{} {} {} {} {}",
            self.id,
            self.token_text(),
            self.token,
            self.first_subflow,
            self.side.map_or("", Side::label)
        )
        .to_lowercase();
        filter.split_whitespace().all(|term| text.contains(term))
    }
}

/// A pause between two loaded points this many times longer than usual breaks the line
const GAP_FACTOR: f64 = 20.0;

/// The pause between two loaded points from which on they are not joined: `GAP_FACTOR` times
/// the sampling interval or the median distance of the points, whichever is larger. The median
/// covers points that are thinned out by count instead of by time.
pub fn gap_threshold(points: &[(f64, f64)], sample_interval: f64) -> f64 {
    let mut distances: Vec<f64> = points.windows(2).map(|w| w[1].0 - w[0].0).collect();
    let median = if distances.is_empty() {
        0.0
    } else {
        let mid = distances.len() / 2;
        *distances
            .select_nth_unstable_by(mid, |a, b| a.total_cmp(b))
            .1
    };
    GAP_FACTOR * sample_interval.max(median)
}

/// Splits a series where two points are more than `gap` apart. With `step`, each value holds
/// until the next point, as for counters and states, instead of a straight line between them.
pub fn segments(points: &[(f64, f64)], gap: f64, step: bool) -> Vec<Vec<[f64; 2]>> {
    let mut out: Vec<Vec<[f64; 2]>> = Vec::new();
    let mut previous: Option<(f64, f64)> = None;
    for &(t, v) in points {
        match previous {
            Some((pt, pv)) if t - pt <= gap => {
                let segment = out.last_mut().expect("a segment is open");
                if step && v != pv {
                    segment.push([t, pv]);
                }
                segment.push([t, v]);
            }
            _ => out.push(vec![[t, v]]),
        }
        previous = Some((t, v));
    }
    out
}

/// Bytes in binary units, e.g. "2.42 GiB"
pub fn format_bytes(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value.abs() >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

/// Each subflow's share of the connection's bytes: of the acknowledged bytes on a sender, of
/// the received bytes on a receiver. Each side counts a byte or so of the other direction
/// (the SYN), so the larger total tells the direction.
pub fn byte_shares(acked: &[Option<f64>], received: &[Option<f64>]) -> Vec<Option<f64>> {
    let total = |values: &[Option<f64>]| values.iter().flatten().sum::<f64>();
    let values = if total(acked) >= total(received) {
        acked
    } else {
        received
    };
    let sum = total(values);
    values
        .iter()
        .map(|v| v.filter(|_| sum > 0.0).map(|v| v / sum))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(key: i64, remote_tokens: &[i64], ports: &[(i64, i64)]) -> SideInput {
        SideInput {
            key,
            remote_tokens: remote_tokens.to_vec(),
            ports: ports.to_vec(),
        }
    }

    #[test]
    fn remote_token_settles_both_ends() {
        // e6: the client's join carries the server's token; ports alone would also work
        let sides = infer_sides(&[
            input(0x3fa1, &[0, 0x5a4b], &[(55872, 5501), (58139, 5501)]),
            input(0x5a4b, &[0], &[(5501, 55872), (5501, 58139)]),
        ]);
        assert_eq!(sides[0], (Some(Side::Client), Some(1)));
        assert_eq!(sides[1], (Some(Side::Server), Some(0)));
    }

    #[test]
    fn remote_token_beats_ports() {
        // Joins to a signal endpoint on another port: neither end shares a port
        let sides = infer_sides(&[
            input(7, &[9], &[(40000, 5501), (40001, 6000)]),
            input(9, &[], &[(5501, 40000), (6000, 40001)]),
        ]);
        assert_eq!(sides[0].0, Some(Side::Client));
        assert_eq!(sides[1].0, Some(Side::Server));
    }

    #[test]
    fn shared_port_without_token() {
        let sides = infer_sides(&[
            input(1, &[], &[(5501, 40000), (5501, 40001)]),
            input(2, &[], &[(40000, 5501), (40001, 5501)]),
        ]);
        assert_eq!(sides[0], (Some(Side::LikelyServer), None));
        assert_eq!(sides[1], (Some(Side::LikelyClient), None));
    }

    #[test]
    fn single_subflow_falls_back_to_the_lower_port() {
        // A fallback to TCP has one subflow and no joins
        let sides = infer_sides(&[
            input(1, &[], &[(43959, 5501)]),
            input(2, &[], &[(80, 51000)]),
        ]);
        assert_eq!(sides[0].0, Some(Side::LikelyClient));
        assert_eq!(sides[1].0, Some(Side::LikelyServer));
    }

    #[test]
    fn unknown_or_own_token_is_ignored() {
        let sides = infer_sides(&[input(5, &[5, 77], &[]), input(6, &[], &[])]);
        assert_eq!(sides, vec![(None, None), (None, None)]);
    }

    fn event(t: f64, code: u32, row: usize) -> PmEvent {
        PmEvent {
            t,
            code: code as i64,
            row,
            label: format!("{code} at {t}"),
            backup: false,
        }
    }

    #[test]
    fn event_names_cover_the_recorded_events() {
        assert_eq!(pm_event_name(1), "created");
        assert_eq!(pm_event_name(10), "subflow established");
        assert_eq!(pm_event_name(100), "token destroyed");
        assert_eq!(pm_event_name(105), "reinjected");
        assert_eq!(pm_event_name(107), "fallback to TCP");
        assert_eq!(pm_event_name(-1), "event");
    }

    #[test]
    fn lane_rows_are_named_from_the_top() {
        assert_eq!(lane_row_name(2.0, 3), "conn");
        assert_eq!(lane_row_name(1.0, 3), "#1");
        assert_eq!(lane_row_name(0.0, 3), "#2");
        assert_eq!(lane_row_name(0.5, 3), "");
        assert_eq!(lane_row_name(3.0, 3), "");
    }

    #[test]
    fn lane_rows_from_the_top() {
        assert_eq!(lane_y(0, 4), 3.0);
        assert_eq!(lane_y(3, 4), 0.0);
        assert!(is_connection_event(TCBEE_MPTCP_TOKEN_DESTROYED as i64));
        // Recorded on the connection's socket, not on a subflow
        for code in [
            TCBEE_MPTCP_SUBFLOW_CONNECT,
            TCBEE_MPTCP_MP_PRIO_SENT,
            TCBEE_MPTCP_REINJECTED,
            TCBEE_MPTCP_PENDING_REQUEUED,
        ] {
            assert!(is_connection_event(code as i64));
        }
        assert!(!is_connection_event(TCBEE_MPTCP_SUBFLOW_STALE as i64));
        assert!(!is_structural(TCBEE_MPTCP_REINJECTED as i64));
        assert!(is_structural(TCBEE_MPTCP_CLOSED as i64));
    }

    #[test]
    fn nearest_event_in_the_hovered_row() {
        let events = [
            event(1.0, TCBEE_MPTCP_CREATED, 0),
            event(5.0, TCBEE_MPTCP_CREATED, 0),
            event(4.0, TCBEE_MPTCP_REINJECTED, 1),
        ];
        // Row 0 of two is at y = 1
        let hit = nearest_event(&events, "created", 3.5, 1.1, 2);
        assert_eq!(hit, Some(&events[1]));
        let hit = nearest_event(&events, "reinjected", 3.5, 0.0, 2);
        assert_eq!(hit, Some(&events[2]));
        // In the other row, or on no item at all
        assert_eq!(nearest_event(&events, "created", 3.5, 0.0, 2), None);
        assert_eq!(nearest_event(&events, "", 1.0, 1.0, 2), None);
    }

    #[test]
    fn bytes_in_binary_units() {
        assert_eq!(format_bytes(0.0), "0 B");
        assert_eq!(format_bytes(1023.0), "1023 B");
        assert_eq!(format_bytes(1536.0), "1.50 KiB");
        assert_eq!(format_bytes(2_596_458_090.0), "2.42 GiB");
    }

    #[test]
    fn shares_of_acked_or_received_bytes() {
        // Sender: acknowledged bytes
        let shares = byte_shares(&[Some(3.0), Some(1.0), None], &[Some(0.0), Some(1.0), None]);
        assert_eq!(shares, vec![Some(0.75), Some(0.25), None]);
        // Receiver: nothing acknowledged, so the received bytes count
        let shares = byte_shares(&[Some(0.0), Some(0.0)], &[Some(1.0), Some(3.0)]);
        assert_eq!(shares, vec![Some(0.25), Some(0.75)]);
        // Receiving client: each subflow acknowledged the server's SYN
        let gib = 1024.0 * 1024.0 * 1024.0;
        let shares = byte_shares(&[Some(1.0); 3], &[Some(2.0 * gib), Some(gib), Some(gib)]);
        assert_eq!(shares, vec![Some(0.5), Some(0.25), Some(0.25)]);
        // No bytes at all
        assert_eq!(byte_shares(&[Some(0.0)], &[None]), vec![None]);
    }

    #[test]
    fn segments_break_at_gaps() {
        let points = [
            (0.0, 1.0),
            (1.0, 2.0),
            (2.0, 2.0),
            (10.0, 5.0),
            (11.0, 3.0),
            (30.0, 4.0),
        ];
        let lines = segments(&points, 2.0, false);
        assert_eq!(
            lines,
            vec![
                vec![[0.0, 1.0], [1.0, 2.0], [2.0, 2.0]],
                vec![[10.0, 5.0], [11.0, 3.0]],
                vec![[30.0, 4.0]],
            ]
        );
        assert!(segments(&[], 2.0, true).is_empty());
    }

    #[test]
    fn steps_hold_the_value_until_the_next_point() {
        let lines = segments(&[(0.0, 1.0), (1.0, 3.0), (2.0, 3.0), (3.0, 2.0)], 5.0, true);
        assert_eq!(
            lines,
            vec![vec![
                [0.0, 1.0],
                [1.0, 1.0],
                [1.0, 3.0],
                [2.0, 3.0],
                [3.0, 3.0],
                [3.0, 2.0]
            ]]
        );
    }

    #[test]
    fn gap_follows_sampling_or_point_distance() {
        let points: Vec<(f64, f64)> = (0..10).map(|i| (i as f64 * 2.0, 0.0)).collect();
        // Thinned by count: the median distance counts
        assert_eq!(gap_threshold(&points, 0.0), 40.0);
        // Sampled by time with a larger interval
        assert_eq!(gap_threshold(&points, 5.0), 100.0);
        assert_eq!(gap_threshold(&[(1.0, 1.0)], 0.0), 0.0);
    }

    #[test]
    fn subflows_start_in_time_order() {
        let member = |flow_id, subflow_id, first_ts| ConnectionFlow {
            connection_id: 2,
            flow_id,
            subflow_id,
            first_ts,
            last_ts: first_ts + 10,
        };
        // e6, server side: only the initial subflow has an id
        let mut members = vec![
            member(4, None, 200),
            member(6, None, 900),
            member(2, Some(1), 50),
        ];
        sort_subflows(&mut members);
        let order: Vec<i64> = members.iter().map(|m| m.flow_id).collect();
        assert_eq!(order, vec![2, 4, 6]);
    }

    #[test]
    fn filter_matches_all_terms() {
        let row = ConnectionSummary {
            id: 2,
            token: 0x5a4bd6e2,
            first_subflow: "10.31.1.2:5501 -> 10.31.1.1:55872".into(),
            side: Some(Side::Server),
            peer: Some(1),
            subflows: 3,
            events: 12,
            start_s: 0.05,
            duration_s: 22.4,
        };
        assert!(row.matches(""));
        assert!(row.matches("0x5a4b server"));
        assert!(row.matches("10.31.1.1 #2"));
        assert!(row.matches(&0x5a4bd6e2_i64.to_string()));
        assert!(!row.matches("client"));
        assert!(!row.matches("5501 10.99"));
    }
}
