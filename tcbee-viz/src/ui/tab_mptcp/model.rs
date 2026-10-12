//! The parts of the MPTCP tab that do not draw: which end of a connection a recording shows,
//! the sidebar rows and their filter, the order of the subflows, the line segments of a series,
//! the path manager event types (names, lane rows, backup flag) and the subflows' byte shares.

use egui_plot::MarkerShape;
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
    /// The event reports an error (a failed join or MP_PRIO)
    pub failed: bool,
}

/// What an event means for the connection, which sets its colour
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventKind {
    /// Moves data: reinjected, requeued. Can be many.
    Data,
    /// The connection or a listener starts or ends
    Lifecycle,
    /// Addresses and priorities
    Info,
    /// A subflow comes up
    Up,
    /// A subflow or address goes away as intended
    End,
    /// Something failed: a failed event, MP_FAIL, a stale subflow, a fallback to TCP
    Trouble,
}

/// Lane row of an event type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventRow {
    /// The connection's own row
    Connection,
    /// The row of the subflow it was recorded on
    Subflow,
}

/// A type of path manager event (`enum tcbee_mptcp_event` in records.h)
#[derive(Debug, PartialEq)]
pub struct EventType {
    pub code: u32,
    pub name: &'static str,
    /// Label next to a marker
    pub short: &'static str,
    pub kind: EventKind,
    /// Marker; unique with the kind, also for the failed variant (kind `Trouble`)
    pub shape: MarkerShape,
    /// Joins, sent MP_PRIOs, reinjections and requeued data are recorded on the
    /// connection's socket, which carries the first subflow's tuple, so their record does
    /// not tell the subflow: they go to the connection row
    pub row: EventRow,
    /// Whether its record holds the subflow's backup flag
    pub carries_backup: bool,
}

const fn event_type_row(
    code: u32,
    name: &'static str,
    short: &'static str,
    kind: EventKind,
    shape: MarkerShape,
    row: EventRow,
    carries_backup: bool,
) -> EventType {
    EventType {
        code,
        name,
        short,
        kind,
        shape,
        row,
        carries_backup,
    }
}

/// Every recorded event type
#[rustfmt::skip]
pub const EVENT_TYPES: [EventType; 18] = {
    use EventKind as K;
    use EventRow::{Connection as Conn, Subflow as Sub};
    use MarkerShape as M;
    [
        event_type_row(TCBEE_MPTCP_CREATED,          "created",               "created",    K::Lifecycle, M::Circle,   Conn, false),
        event_type_row(TCBEE_MPTCP_ESTABLISHED,      "established",           "est.",       K::Lifecycle, M::Square,   Conn, false),
        event_type_row(TCBEE_MPTCP_CLOSED,           "closed",                "closed",     K::Lifecycle, M::Cross,    Conn, false),
        event_type_row(TCBEE_MPTCP_TOKEN_DESTROYED,  "token destroyed",       "token gone", K::Lifecycle, M::Plus,     Conn, false),
        event_type_row(TCBEE_MPTCP_LISTENER_CREATED, "listener created",      "listen",     K::Lifecycle, M::Up,       Conn, false),
        event_type_row(TCBEE_MPTCP_LISTENER_CLOSED,  "listener closed",       "unlisten",   K::Lifecycle, M::Down,     Conn, false),
        event_type_row(TCBEE_MPTCP_ANNOUNCED,        "address announced",     "add addr",   K::Info,      M::Up,       Conn, false),
        event_type_row(TCBEE_MPTCP_SUB_PRIORITY,     "subflow priority",      "prio",       K::Info,      M::Diamond,  Sub,  true),
        event_type_row(TCBEE_MPTCP_MP_PRIO_SENT,     "MP_PRIO sent",          "MP_PRIO",    K::Info,      M::Plus,     Conn, true),
        event_type_row(TCBEE_MPTCP_SUB_ESTABLISHED,  "subflow established",   "up",         K::Up,        M::Up,       Sub,  true),
        event_type_row(TCBEE_MPTCP_SUBFLOW_CONNECT,  "subflow connect",       "join",       K::Up,        M::Right,    Conn, false),
        event_type_row(TCBEE_MPTCP_SUB_CLOSED,       "subflow closed",        "down",       K::End,       M::Down,     Sub,  false),
        event_type_row(TCBEE_MPTCP_REMOVED,          "address removed",       "rm addr",    K::End,       M::Left,     Conn, false),
        event_type_row(TCBEE_MPTCP_MP_FAIL,          "MP_FAIL",               "MP_FAIL",    K::Trouble,   M::Asterisk, Sub,  false),
        event_type_row(TCBEE_MPTCP_SUBFLOW_STALE,    "subflow stale",         "stale",      K::Trouble,   M::Square,   Sub,  false),
        event_type_row(TCBEE_MPTCP_FALLBACK,         "fallback to TCP",       "fallback",   K::Trouble,   M::Cross,    Conn, false),
        event_type_row(TCBEE_MPTCP_REINJECTED,       "reinjected",            "reinj.",     K::Data,      M::Circle,   Conn, false),
        event_type_row(TCBEE_MPTCP_PENDING_REQUEUED, "pending data requeued", "requeue",    K::Data,      M::Left,     Conn, false),
    ]
};

/// For a code the recorder does not know (a newer recorder)
const UNKNOWN_EVENT: EventType = event_type_row(
    0,
    "event",
    "event",
    EventKind::Lifecycle,
    MarkerShape::Asterisk,
    EventRow::Connection,
    false,
);

pub fn event_type(code: i64) -> &'static EventType {
    EVENT_TYPES
        .iter()
        .find(|t| t.code as i64 == code)
        .unwrap_or(&UNKNOWN_EVENT)
}

/// The kind of an event: a failed event counts as trouble whatever its type
pub fn event_kind(code: i64, failed: bool) -> EventKind {
    if failed {
        EventKind::Trouble
    } else {
        event_type(code).kind
    }
}

impl PmEvent {
    pub fn kind(&self) -> EventKind {
        event_kind(self.code, self.failed)
    }
}

/// Name of an event type, which tells failed events apart
pub fn event_type_name(code: i64, failed: bool) -> String {
    let name = event_type(code).name;
    if failed {
        format!("{name} failed")
    } else {
        name.to_string()
    }
}

/// Whether an event's record holds the subflow's backup flag
pub fn carries_backup(code: i64) -> bool {
    event_type(code).carries_backup
}

/// Events about the whole connection go to its own lane row, the others to their subflow's
pub fn is_connection_event(code: i64) -> bool {
    event_type(code).row == EventRow::Connection
}

/// Whether the event changes the connection's paths, as opposed to moving data, which can
/// happen thousands of times. Only these are marked in the metric plots.
pub fn is_structural(code: i64) -> bool {
    event_type(code).kind != EventKind::Data
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
    row_name(row as usize)
}

/// Events of one lane row that are too close to tell apart on screen, shown as one marker
#[derive(Debug, PartialEq)]
pub struct EventGroup {
    pub row: usize,
    /// Indices into the events, in time order
    pub members: Vec<usize>,
    /// The member shown: the most severe one
    pub representative: usize,
}

impl EventGroup {
    /// Label next to the marker: the short name of the representative and how many more
    /// there are. Data moves count only for a data marker, as they get no line in the plots.
    pub fn label(&self, events: &[PmEvent]) -> String {
        let shown = &events[self.representative];
        let short = event_type(shown.code).short;
        let failed = if shown.failed { " failed" } else { "" };
        let is_data = |e: &PmEvent| e.kind() == EventKind::Data;
        let more = self
            .members
            .iter()
            .filter(|&&i| i != self.representative && is_data(&events[i]) == is_data(shown))
            .count();
        match more {
            0 => format!("{short}{failed}"),
            n => format!("{short}{failed} +{n}"),
        }
    }
}

/// Groups the events of each row in which one follows the previous within `tol` (ns, the
/// time a few pixels take on screen). `events` is in time order.
pub fn group_events(events: &[PmEvent], tol: f64) -> Vec<EventGroup> {
    let mut groups: Vec<EventGroup> = Vec::new();
    // The open group of each row
    let mut open: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (i, e) in events.iter().enumerate() {
        let joined = open.get(&e.row).copied().filter(|&g| {
            let last = *groups[g].members.last().expect("a group has members");
            e.t - events[last].t <= tol
        });
        match joined {
            Some(g) => {
                let group = &mut groups[g];
                group.members.push(i);
                // Ties keep the earlier event
                if e.kind() > events[group.representative].kind() {
                    group.representative = i;
                }
            }
            None => {
                open.insert(e.row, groups.len());
                groups.push(EventGroup {
                    row: e.row,
                    members: vec![i],
                    representative: i,
                });
            }
        }
    }
    groups
}

/// The group under the pointer at time `x` in lane row `row`: the one whose time span,
/// widened by `tol`, holds `x`
pub fn group_at(
    groups: &[EventGroup],
    events: &[PmEvent],
    row: usize,
    x: f64,
    tol: f64,
) -> Option<usize> {
    groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g.row == row)
        .filter(|(_, g)| {
            let first = events[g.members[0]].t;
            let last = events[*g.members.last().expect("a group has members")].t;
            first - tol <= x && x <= last + tol
        })
        .min_by(|(_, a), (_, b)| {
            let distance = |g: &EventGroup| (events[g.representative].t - x).abs();
            distance(a).total_cmp(&distance(b))
        })
        .map(|(i, _)| i)
}

/// Which labels to draw: greedily from the left, each label that keeps `gap` to the last one
/// drawn and ends `gap` before its limit (e.g. the next marker). `spans` are the labels'
/// (left, right, limit) on screen, sorted by left.
pub fn place_labels(spans: &[(f32, f32, f32)], gap: f32) -> Vec<bool> {
    let mut right_end = f32::NEG_INFINITY;
    spans
        .iter()
        .map(|&(left, right, limit)| {
            let free = left >= right_end + gap && right + gap <= limit;
            if free {
                right_end = right;
            }
            free
        })
        .collect()
}

/// Name of a lane row in tables: "conn" for the connection, "#k" for subflow k
pub fn row_name(row: usize) -> String {
    match row {
        0 => "conn".to_string(),
        k => format!("#{k}"),
    }
}

/// Whether an event matches every whitespace-separated term of a lowercase filter. A row
/// term ("conn", "#2") must name the event's row, so "#1" does not match "#12"; other terms
/// are looked up in its type name and label.
pub fn event_matches(event: &PmEvent, filter: &str) -> bool {
    let row = row_name(event.row);
    let text = format!(
        "{} {}",
        event_type_name(event.code, event.failed),
        event.label
    )
    .to_lowercase();
    filter.split_whitespace().all(|term| {
        let is_row_term = term == "conn"
            || term
                .strip_prefix('#')
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if is_row_term {
            term == row
        } else {
            text.contains(term)
        }
    })
}

/// The time range that shows `t` in the middle at the width of `lo..hi`, kept within
/// `min..max`
pub fn centered_x(lo: f64, hi: f64, t: f64, min: f64, max: f64) -> (f64, f64) {
    let width = hi - lo;
    if width >= max - min {
        return (min, max);
    }
    let start = (t - width / 2.0).clamp(min, max - width);
    (start, start + width)
}

/// The lane row at plot height `y`, if `y` is within a row
pub fn lane_row_at(y: f64, rows: usize) -> Option<usize> {
    let row = (rows as f64 - 1.0 - y).round();
    (row >= 0.0 && row < rows as f64).then_some(row as usize)
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

/// A part of a plotted series
#[derive(Debug, PartialEq)]
pub struct Segment {
    pub points: Vec<[f64; 2]>,
    /// A value held over a pause without records, drawn faint
    pub held: bool,
}

/// Splits a series where two points are more than `gap` apart. With `step`, each value holds
/// until the next point, as for counters and states, instead of a straight line between them,
/// and a pause does not break the line: the value is held across it in a segment of its own.
pub fn segments(points: &[(f64, f64)], gap: f64, step: bool) -> Vec<Segment> {
    let open = |points| Segment {
        points,
        held: false,
    };
    let mut out: Vec<Segment> = Vec::new();
    let mut previous: Option<(f64, f64)> = None;
    for &(t, v) in points {
        match previous {
            Some((pt, pv)) if t - pt <= gap => {
                let segment = out.last_mut().expect("a segment is open");
                if step && v != pv {
                    segment.points.push([t, pv]);
                }
                segment.points.push([t, v]);
            }
            Some((pt, pv)) if step => {
                out.push(Segment {
                    points: vec![[pt, pv], [t, pv]],
                    held: true,
                });
                out.push(open(if v != pv {
                    vec![[t, pv], [t, v]]
                } else {
                    vec![[t, v]]
                }));
            }
            _ => out.push(open(vec![[t, v]])),
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
            failed: false,
        }
    }

    #[test]
    fn event_names_cover_the_recorded_events() {
        assert_eq!(event_type(1).name, "created");
        assert_eq!(event_type(10).name, "subflow established");
        assert_eq!(event_type(100).name, "token destroyed");
        assert_eq!(event_type(105).name, "reinjected");
        assert_eq!(event_type(107).name, "fallback to TCP");
        assert_eq!(event_type(-1).name, "event");
        assert_eq!(event_type_name(101, true), "subflow connect failed");
    }

    #[test]
    fn event_types_are_told_apart_by_kind_and_shape() {
        let codes: Vec<u32> = EVENT_TYPES.iter().map(|t| t.code).collect();
        for (i, a) in EVENT_TYPES.iter().enumerate() {
            assert!(!codes[..i].contains(&a.code), "{} twice", a.name);
            assert!(!a.short.is_empty());
            // Failed variants (only joins and MP_PRIOs report errors) are trouble
            let mut looks = vec![(a.kind, a.shape)];
            if matches!(
                a.code,
                TCBEE_MPTCP_SUBFLOW_CONNECT | TCBEE_MPTCP_MP_PRIO_SENT
            ) {
                looks.push((EventKind::Trouble, a.shape));
            }
            for b in &EVENT_TYPES[..i] {
                assert!(
                    !looks.contains(&(b.kind, b.shape)),
                    "{} looks like {}",
                    a.name,
                    b.name
                );
            }
        }
        let failed_join = PmEvent {
            failed: true,
            ..event(1.0, TCBEE_MPTCP_SUBFLOW_CONNECT, 0)
        };
        assert_eq!(failed_join.kind(), EventKind::Trouble);
        assert_eq!(event(1.0, TCBEE_MPTCP_SUB_CLOSED, 1).kind(), EventKind::End);
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
    fn close_events_of_a_row_form_one_group() {
        let events = [
            event(0.0, TCBEE_MPTCP_CREATED, 0),
            event(1.0, TCBEE_MPTCP_ESTABLISHED, 0),
            event(1.5, TCBEE_MPTCP_SUB_ESTABLISHED, 1),
            event(2.5, TCBEE_MPTCP_SUBFLOW_STALE, 0),
            event(9.0, TCBEE_MPTCP_CLOSED, 0),
        ];
        let groups = group_events(&events, 1.0);
        let members: Vec<Vec<usize>> = groups.iter().map(|g| g.members.clone()).collect();
        // Row 1 does not split row 0's chain 0, 1, 2.5
        assert_eq!(members, vec![vec![0, 1], vec![2], vec![3], vec![4]]);
        let groups = group_events(&events, 1.5);
        assert_eq!(groups[0].members, vec![0, 1, 3]);
        // The stale subflow is the trouble shown
        assert_eq!(groups[0].representative, 3);
        assert_eq!(groups[0].label(&events), "stale +2");
        assert_eq!(groups[1].label(&events), "up");
        // Reinjections next to an event are not counted with it
        let events = [
            event(0.0, TCBEE_MPTCP_ESTABLISHED, 0),
            event(0.1, TCBEE_MPTCP_REINJECTED, 0),
            event(0.2, TCBEE_MPTCP_REINJECTED, 0),
        ];
        let groups = group_events(&events, 1.0);
        assert_eq!(groups[0].label(&events), "est.");
    }

    #[test]
    fn group_under_the_pointer() {
        let events = [
            event(0.0, TCBEE_MPTCP_CREATED, 0),
            event(0.5, TCBEE_MPTCP_ESTABLISHED, 0),
            event(5.0, TCBEE_MPTCP_SUB_ESTABLISHED, 1),
        ];
        let groups = group_events(&events, 1.0);
        assert_eq!(group_at(&groups, &events, 0, 0.8, 0.5), Some(0));
        assert_eq!(group_at(&groups, &events, 1, 5.2, 0.5), Some(1));
        assert_eq!(group_at(&groups, &events, 1, 0.2, 0.5), None);
        assert_eq!(group_at(&groups, &events, 0, 3.0, 0.5), None);
        assert_eq!(lane_row_at(1.2, 2), Some(0));
        assert_eq!(lane_row_at(-0.3, 2), Some(1));
        assert_eq!(lane_row_at(-0.7, 2), None);
    }

    #[test]
    fn events_filter_by_row_type_and_label() {
        let stale = PmEvent {
            label: "subflow stale (subflow 2)".into(),
            ..event(1.0, TCBEE_MPTCP_SUBFLOW_STALE, 2)
        };
        assert!(event_matches(&stale, ""));
        assert!(event_matches(&stale, "#2 stale"));
        assert!(!event_matches(&stale, "conn"));
        let failed = PmEvent {
            failed: true,
            ..event(1.0, TCBEE_MPTCP_SUBFLOW_CONNECT, 0)
        };
        assert!(event_matches(&failed, "conn failed"));
        let on_twelve = event(1.0, TCBEE_MPTCP_SUB_CLOSED, 12);
        assert!(event_matches(&on_twelve, "#12"));
        assert!(!event_matches(&on_twelve, "#1"));
        // "conn" names the row, not "subflow connect"
        let join_on_one = event(1.0, TCBEE_MPTCP_SUBFLOW_CONNECT, 1);
        assert!(!event_matches(&join_on_one, "conn"));
        assert!(event_matches(&join_on_one, "connect"));
    }

    #[test]
    fn view_centres_on_an_event_within_the_connection() {
        assert_eq!(centered_x(0.0, 4.0, 10.0, 0.0, 20.0), (8.0, 12.0));
        // Near either end it stops at the connection
        assert_eq!(centered_x(0.0, 4.0, 1.0, 0.0, 20.0), (0.0, 4.0));
        assert_eq!(centered_x(10.0, 14.0, 19.5, 0.0, 20.0), (16.0, 20.0));
        // A view wider than the connection shows all of it
        assert_eq!(centered_x(-5.0, 30.0, 3.0, 0.0, 20.0), (0.0, 20.0));
    }

    #[test]
    fn labels_skip_what_would_overlap() {
        let none = f32::INFINITY;
        let shown = place_labels(
            &[
                (0.0, 30.0, none),
                (20.0, 40.0, none),
                (34.0, 50.0, none),
                (60.0, 70.0, none),
            ],
            4.0,
        );
        assert_eq!(shown, vec![true, false, true, true]);
        // A label running into the next marker is left out
        assert_eq!(place_labels(&[(0.0, 30.0, 32.0)], 4.0), vec![false]);
        assert_eq!(place_labels(&[(0.0, 30.0, 34.0)], 4.0), vec![true]);
        assert!(place_labels(&[], 4.0).is_empty());
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
        let lines: Vec<Vec<[f64; 2]>> = segments(&points, 2.0, false)
            .into_iter()
            .map(|s| s.points)
            .collect();
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
    fn steps_hold_their_value_across_a_pause() {
        // cwnd recorded only when it changes: flat from 2 to 10, then down to 5
        let lines = segments(
            &[(0.0, 1.0), (2.0, 4.0), (10.0, 5.0), (30.0, 5.0)],
            3.0,
            true,
        );
        let plain = |points: Vec<[f64; 2]>| Segment {
            points,
            held: false,
        };
        let held = |points: Vec<[f64; 2]>| Segment { points, held: true };
        assert_eq!(
            lines,
            vec![
                plain(vec![[0.0, 1.0], [2.0, 1.0], [2.0, 4.0]]),
                held(vec![[2.0, 4.0], [10.0, 4.0]]),
                plain(vec![[10.0, 4.0], [10.0, 5.0]]),
                held(vec![[10.0, 5.0], [30.0, 5.0]]),
                plain(vec![[30.0, 5.0]]),
            ]
        );
    }

    #[test]
    fn steps_hold_the_value_until_the_next_point() {
        let lines = segments(&[(0.0, 1.0), (1.0, 3.0), (2.0, 3.0), (3.0, 2.0)], 5.0, true);
        assert_eq!(
            lines.into_iter().map(|s| s.points).collect::<Vec<_>>(),
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
