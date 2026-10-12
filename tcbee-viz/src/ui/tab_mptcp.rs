//! MPTCP connections: one connection at a time, its path manager events in a lane, a plot per
//! chosen metric with all subflows, and a table of the subflows with their share of the
//! acknowledged bytes.

mod model;

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use egui::{RichText, ScrollArea, Vec2};
use egui_plot::{GridMark, Line, MarkerShape, Plot, PlotBounds, PlotPoints, Points, VLine};
use tcbee_common::records::{
    TCBEE_MPTCP_ANNOUNCED, TCBEE_MPTCP_CLOSED, TCBEE_MPTCP_CREATED, TCBEE_MPTCP_ESTABLISHED,
    TCBEE_MPTCP_FALLBACK, TCBEE_MPTCP_LISTENER_CLOSED, TCBEE_MPTCP_LISTENER_CREATED,
    TCBEE_MPTCP_MP_FAIL, TCBEE_MPTCP_MP_PRIO_SENT, TCBEE_MPTCP_PENDING_REQUEUED,
    TCBEE_MPTCP_REINJECTED, TCBEE_MPTCP_REMOVED, TCBEE_MPTCP_SUBFLOW_CONNECT,
    TCBEE_MPTCP_SUBFLOW_STALE, TCBEE_MPTCP_SUB_CLOSED, TCBEE_MPTCP_SUB_ESTABLISHED,
    TCBEE_MPTCP_SUB_PRIORITY, TCBEE_MPTCP_TOKEN_DESTROYED,
};
use ts_storage::{
    ColType, ConnectionFlow, ConnectionInfo, DataValue, Dir, SeriesInfo, SeriesKind, ValueKind,
};

use model::{
    byte_shares, format_bytes, gap_threshold, infer_sides, is_connection_event, is_structural,
    lane_y, nearest_event, segments, sort_subflows, ConnectionSummary, PmEvent, SideInput,
};

use crate::{
    backend::db::{flow_x_bounds, format_flow, DbBackend},
    data::{
        plot_state::{fetch_range, load_series_window},
        preprocessing::generate_colors,
        series_data::SeriesData,
    },
    settings::AppSettings,
    ui::{
        tab_single_flow::{
            seconds_grid_spacer, seconds_label_formatter, seconds_since_formatter, section_heading,
            split_plot_height_with_footer, time_or_compact_formatter,
        },
        table::{self, data_cell, header_cell, number_cell, ROW_HEIGHT},
        theme,
    },
};

/// Shown when the database has no MPTCP connection
pub const NO_MPTCP_HINT: &str =
    "No MPTCP was recorded in this database. Record with tcbee-record -M to see MPTCP connections.";
/// Plotted first if the subflows have it
const DEFAULT_METRIC: (&str, Dir, &str) = ("sock", Dir::Send, "snd_cwnd");

/// Smallest height of a metric plot; more plots scroll
const MIN_PLOT_HEIGHT: f32 = 120.0;
/// Width of the value axis of every metric plot
const Y_AXIS_WIDTH: f32 = 56.0;
/// Height of a row of the event lane
const LANE_ROW_HEIGHT: f32 = 18.0;
const MIN_LANE_HEIGHT: f32 = 60.0;

/// Columns of the subflow table: header, width, hover text. "Local -> remote" takes the rest
/// of the width and comes after the third.
const SUBFLOW_COLUMNS: [(&str, f32, &str); 12] = [
    (
        "",
        24.0,
        "Colour in the plots; click a row to hide or show the subflow",
    ),
    ("#", 28.0, "Position in the event lane"),
    (
        "Id",
        30.0,
        "Subflow id of the kernel; the server does not number its joins",
    ),
    ("Start", 62.0, "Seconds since the connection started"),
    ("End", 62.0, ""),
    ("Acked", 80.0, "Bytes acknowledged by the peer"),
    ("Received", 80.0, "Bytes received"),
    (
        "Share",
        110.0,
        "Share of the bytes sent, or on a receiver of the bytes received",
    ),
    ("Retrans", 56.0, "Retransmitted segments"),
    (
        "Backoff",
        60.0,
        "Highest RTO backoff: retransmission timeouts in a row",
    ),
    (
        "Backup",
        54.0,
        "Backup flag of the last path manager event that carries it",
    ),
    ("Events", 52.0, "Path manager events of the subflow"),
];

// Columns of the connection table; the first subflow takes the rest of the width
const COL_TOKEN: f32 = 86.0;
const COL_SIDE: f32 = 56.0;
const COL_SUBFLOWS: f32 = 30.0;
const COL_EVENTS: f32 = 50.0;
const COL_DURATION: f32 = 62.0;

/// Whether the database has MPTCP connections, which enables the tab
pub fn has_mptcp(db: &DbBackend) -> bool {
    db.list_connections()
        .iter()
        .any(|c| c.kind == ConnectionInfo::KIND_MPTCP)
}

/// A series that every subflow may have: (source, dir, name)
type MetricKey = (String, Dir, String);

fn metric_key(s: &SeriesInfo) -> MetricKey {
    (s.source.clone(), s.dir, s.name.clone())
}

fn metric_label((source, dir, name): &MetricKey) -> String {
    match dir {
        Dir::None => format!("{name} · {source}"),
        _ => format!("{name} · {source} · {dir:?}").to_lowercase(),
    }
}

/// The metrics whose label contains every term of `filter`, grouped by source
fn group_metrics<'a>(metrics: &'a [MetricKey], filter: &str) -> Vec<(&'a str, Vec<&'a MetricKey>)> {
    let filter = filter.to_lowercase();
    let mut groups: Vec<(&str, Vec<&MetricKey>)> = Vec::new();
    for m in metrics {
        let label = metric_label(m).to_lowercase();
        if !filter.split_whitespace().all(|term| label.contains(term)) {
            continue;
        }
        match groups.iter_mut().find(|(source, _)| *source == m.0) {
            Some((_, group)) => group.push(m),
            None => groups.push((&m.0, vec![m])),
        }
    }
    groups
}

/// Name of an event of the path manager records (`enum tcbee_mptcp_event` in records.h)
fn pm_event_name(event: i64) -> &'static str {
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

/// The value of a catalog series of a flow: the largest value of `name` over both directions
fn catalog_max(series: &[SeriesInfo], source: &str, name: &str) -> Option<f64> {
    series
        .iter()
        .filter(|s| s.source == source && s.name == name)
        .filter_map(|s| s.v_max)
        .reduce(f64::max)
}

/// The MPTCP connections of the database as sidebar rows, oldest first. `catalogs` caches the
/// series catalog of each flow.
fn connection_summaries(
    db: &DbBackend,
    catalogs: &mut HashMap<i64, Vec<SeriesInfo>>,
) -> Vec<ConnectionSummary> {
    let mut mptcp: Vec<&ConnectionInfo> = db
        .list_connections()
        .iter()
        .filter(|c| c.kind == ConnectionInfo::KIND_MPTCP)
        .collect();
    mptcp.sort_by_key(|c| (c.start_ts, c.id));
    let origin = mptcp.first().map_or(0, |c| c.start_ts);

    let mut inputs = Vec::with_capacity(mptcp.len());
    let mut rows = Vec::with_capacity(mptcp.len());
    for c in &mptcp {
        let mut members: Vec<&ConnectionFlow> = db
            .list_connection_flows()
            .iter()
            .filter(|m| m.connection_id == c.id)
            .collect();
        sort_subflows(&mut members);
        let mut input = SideInput {
            key: c.key,
            ..SideInput::default()
        };
        let mut events = 0;
        for m in &members {
            let series = catalogs
                .entry(m.flow_id)
                .or_insert_with(|| db.list_series_for_flow(m.flow_id));
            if let Some(token) = catalog_max(series, "mptcp_pm", "remote_token") {
                input.remote_tokens.push(token as i64);
            }
            events += series
                .iter()
                .find(|s| s.source == "mptcp_pm" && s.name == "event")
                .map_or(0, |s| s.n);
            if let Some(flow) = db.get_flow_by_id(m.flow_id) {
                input.ports.push((flow.tuple.sport, flow.tuple.dport));
            }
        }
        // connections.flow_id stays empty, so the first subflow is the earliest member
        let first_subflow = members
            .first()
            .and_then(|m| db.get_flow_by_id(m.flow_id))
            .map_or_else(String::new, |f| {
                format!(
                    "{}:{} -> {}:{}",
                    f.tuple.src, f.tuple.sport, f.tuple.dst, f.tuple.dport
                )
            });
        inputs.push(input);
        rows.push(ConnectionSummary {
            id: c.id,
            token: c.key,
            first_subflow,
            side: None,
            peer: None,
            subflows: members.len(),
            events,
            start_s: (c.start_ts - origin) as f64 / 1e9,
            duration_s: (c.end_ts - c.start_ts) as f64 / 1e9,
        });
    }
    for (row, (side, peer)) in rows.iter_mut().zip(infer_sides(&inputs)) {
        row.side = side;
        row.peer = peer.map(|i| mptcp[i].id);
    }
    rows
}

fn connection_tooltip(row: &ConnectionSummary) -> String {
    let mut text = format!(
        "Connection #{}, token {} ({})\nFirst subflow {}\nStarts at {:.3} s, lasts {:.3} s",
        row.id,
        row.token_text(),
        row.token,
        row.first_subflow,
        row.start_s,
        row.duration_s
    );
    if let Some(side) = row.side {
        text.push_str(&format!(
            "\nSide: {} ({})",
            side.label(),
            side.description()
        ));
    }
    if let Some(peer) = row.peer {
        text.push_str(&format!("\nThe other end is connection #{peer}"));
    }
    text
}

/// The path manager events of one subflow that belong to `connection` (a flow tuple may be
/// reused by another connection): (time, event code, label, backup flag)
fn subflow_events(
    db: &DbBackend,
    sub: &Subflow,
    connection: &ConnectionInfo,
) -> Vec<(f64, i64, String, bool)> {
    let column = |name: &str| -> Vec<(f64, DataValue)> {
        sub.series
            .iter()
            .find(|s| s.source == "mptcp_pm" && s.name == name)
            .and_then(|s| db.load_all(s).ok())
            .unwrap_or_default()
    };
    let events = column("event");
    let others = [
        "token",
        "error",
        "addr_id",
        "addr_family",
        "addr_port",
        "backup",
        "data_len",
    ]
    .map(|n| column(n));
    let words = ["addr_0", "addr_1", "addr_2", "addr_3"].map(|n| column(n));
    // Columns of one table, read in the same (ts, seq) order: rows line up unless the reads
    // disagree, then only the event names are shown
    let aligned = others
        .iter()
        .chain(&words)
        .all(|c| c.len() == events.len() && c.iter().zip(&events).all(|(a, b)| a.0 == b.0));
    let [token, error, addr_id, family, port, backup, data_len] = others;
    let span = connection.start_ts as f64..=connection.end_ts as f64;
    let subflow = sub.member.subflow_id.map(|id| format!(" (subflow {id})"));
    let mut out = Vec::new();
    for (row, (t, event)) in events.iter().enumerate() {
        let DataValue::Int(event) = *event else {
            continue;
        };
        let int = |values: &[(f64, DataValue)]| match values.get(row) {
            Some((_, DataValue::Int(v))) if aligned => *v,
            _ => 0,
        };
        if aligned && int(&token) != connection.key || !span.contains(t) {
            continue;
        }
        let mut label = pm_event_name(event).to_string();
        match event_address(int(&family), int(&port), words.each_ref().map(|w| int(w))) {
            Some(address) => label.push_str(&format!(" {address}")),
            None if int(&addr_id) != 0 => label.push_str(&format!(" id {}", int(&addr_id))),
            None => {}
        }
        if int(&error) != 0 {
            label.push_str(&format!(" failed ({})", int(&error)));
        }
        if event == TCBEE_MPTCP_MP_PRIO_SENT as i64 {
            label.push_str(if int(&backup) != 0 {
                " backup"
            } else {
                " not backup"
            });
        }
        if event == TCBEE_MPTCP_REINJECTED as i64 {
            label.push_str(&format!(" {} B", int(&data_len)));
        }
        label.push_str(subflow.as_deref().unwrap_or(""));
        out.push((*t, event, label, int(&backup) != 0));
    }
    out
}

/// The address of a path manager event, from its family, port and the four words that hold
/// its bytes in network order (see `mptcp_pm_entry` in records.h)
fn event_address(family: i64, port: i64, words: [i64; 4]) -> Option<String> {
    let mut bytes = [0u8; 16];
    for (chunk, word) in bytes.chunks_mut(4).zip(words) {
        chunk.copy_from_slice(&(word as u32).to_le_bytes());
    }
    let ip = match family {
        2 => IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]),
        10 => IpAddr::from(bytes),
        _ => return None,
    };
    Some(match (ip, port) {
        (ip, 0) => ip.to_string(),
        (IpAddr::V6(ip), port) => format!("[{ip}]:{port}"),
        (ip, port) => format!("{ip}:{port}"),
    })
}

/// Title above a plot, like the section headings of the sidebar
fn plot_heading(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .strong()
            .size(12.5)
            .color(theme::muted_text(ui.visuals().dark_mode)),
    );
}

/// Name of a row of the event lane at plot height `y`: the connection on top, then the
/// subflows in the order they started
fn lane_row_name(y: f64, rows: usize) -> String {
    let row = rows as f64 - 1.0 - y;
    if row.fract() != 0.0 || row < 0.0 || row >= rows as f64 {
        return String::new();
    }
    match row as usize {
        0 => "conn".to_string(),
        k => format!("#{k}"),
    }
}

/// Marker of an event type. Types share a shape only between the connection row and the
/// subflow rows, where the row tells them apart.
fn event_shape(code: i64) -> MarkerShape {
    match u32::try_from(code).unwrap_or(0) {
        TCBEE_MPTCP_CREATED | TCBEE_MPTCP_REINJECTED => MarkerShape::Circle,
        TCBEE_MPTCP_ESTABLISHED | TCBEE_MPTCP_SUBFLOW_STALE => MarkerShape::Square,
        TCBEE_MPTCP_CLOSED | TCBEE_MPTCP_LISTENER_CLOSED => MarkerShape::Cross,
        TCBEE_MPTCP_ANNOUNCED | TCBEE_MPTCP_SUB_ESTABLISHED => MarkerShape::Up,
        TCBEE_MPTCP_REMOVED | TCBEE_MPTCP_SUB_CLOSED => MarkerShape::Down,
        TCBEE_MPTCP_TOKEN_DESTROYED | TCBEE_MPTCP_MP_PRIO_SENT => MarkerShape::Plus,
        TCBEE_MPTCP_FALLBACK | TCBEE_MPTCP_MP_FAIL => MarkerShape::Asterisk,
        TCBEE_MPTCP_LISTENER_CREATED | TCBEE_MPTCP_SUB_PRIORITY => MarkerShape::Diamond,
        TCBEE_MPTCP_SUBFLOW_CONNECT => MarkerShape::Right,
        TCBEE_MPTCP_PENDING_REQUEUED => MarkerShape::Left,
        _ => MarkerShape::Circle,
    }
}

/// Events in the text colour, data movements muted, so that subflow colours stay for the
/// subflows
fn event_color(code: i64, dark_mode: bool) -> egui::Color32 {
    if is_structural(code) {
        theme::text(dark_mode)
    } else {
        theme::muted_text(dark_mode)
    }
}

/// Paints an egui_plot marker shape for the legend
fn paint_marker(
    painter: &egui::Painter,
    c: egui::Pos2,
    shape: MarkerShape,
    color: egui::Color32,
    r: f32,
) {
    use egui::{pos2, Shape, Stroke};
    let stroke = Stroke::new(1.5, color);
    let triangle =
        |points: [egui::Pos2; 3]| Shape::convex_polygon(points.to_vec(), color, Stroke::NONE);
    let shape = match shape {
        MarkerShape::Circle => Shape::circle_filled(c, r, color),
        MarkerShape::Square => Shape::rect_filled(
            egui::Rect::from_center_size(c, Vec2::splat(2.0 * r)),
            0.0,
            color,
        ),
        MarkerShape::Diamond => Shape::convex_polygon(
            vec![
                pos2(c.x, c.y - r),
                pos2(c.x + r, c.y),
                pos2(c.x, c.y + r),
                pos2(c.x - r, c.y),
            ],
            color,
            Stroke::NONE,
        ),
        MarkerShape::Up => triangle([
            pos2(c.x, c.y - r),
            pos2(c.x + r, c.y + r),
            pos2(c.x - r, c.y + r),
        ]),
        MarkerShape::Down => triangle([
            pos2(c.x - r, c.y - r),
            pos2(c.x + r, c.y - r),
            pos2(c.x, c.y + r),
        ]),
        MarkerShape::Left => triangle([
            pos2(c.x - r, c.y),
            pos2(c.x + r, c.y - r),
            pos2(c.x + r, c.y + r),
        ]),
        MarkerShape::Right => triangle([
            pos2(c.x - r, c.y - r),
            pos2(c.x + r, c.y),
            pos2(c.x - r, c.y + r),
        ]),
        MarkerShape::Plus => Shape::Vec(vec![
            Shape::line_segment([pos2(c.x - r, c.y), pos2(c.x + r, c.y)], stroke),
            Shape::line_segment([pos2(c.x, c.y - r), pos2(c.x, c.y + r)], stroke),
        ]),
        MarkerShape::Cross => Shape::Vec(vec![
            Shape::line_segment([pos2(c.x - r, c.y - r), pos2(c.x + r, c.y + r)], stroke),
            Shape::line_segment([pos2(c.x - r, c.y + r), pos2(c.x + r, c.y - r)], stroke),
        ]),
        MarkerShape::Asterisk => Shape::Vec(vec![
            Shape::line_segment([pos2(c.x - r, c.y), pos2(c.x + r, c.y)], stroke),
            Shape::line_segment([pos2(c.x - r, c.y - r), pos2(c.x + r, c.y + r)], stroke),
            Shape::line_segment([pos2(c.x - r, c.y + r), pos2(c.x + r, c.y - r)], stroke),
        ]),
    };
    painter.add(shape);
}

/// One subflow of the selected connection with its catalog
struct Subflow {
    member: ConnectionFlow,
    /// Legend name
    label: String,
    /// Same in every plot and table
    color: egui::Color32,
    /// Its flow, for the table
    flow: String,
    series: Vec<SeriesInfo>,
    /// Backup flag of its last path manager event that carries one
    backup: Option<bool>,
    /// Its path manager events
    events: usize,
    /// Left out of the plots
    hidden: bool,
}

impl Subflow {
    fn find(&self, (source, dir, name): &MetricKey) -> Option<&SeriesInfo> {
        self.series
            .iter()
            .find(|s| &s.source == source && s.dir == *dir && &s.name == name)
    }

    /// The last value of a socket counter: its catalog maximum
    fn counter(&self, name: &str) -> Option<f64> {
        catalog_max(&self.series, "sock", name)
    }
}

/// What the event lane reports to the plots below it
#[derive(Default)]
struct LaneResponse {
    /// Height it took, with its title and legend
    height: f32,
    /// Right-clicked to reset the view
    reset: bool,
}

/// One plotted metric: a series per subflow that has it, with the subflow's index
struct MetricPlot {
    series: Vec<(usize, SeriesData)>,
}

/// The tab is reset whenever another tab is shown, and the database only changes on the Home
/// tab, so its state always belongs to the open database.
#[derive(Default)]
pub struct TabMptcp {
    /// The MPTCP connections of the database, read when the tab is first shown
    connections: Vec<ConnectionSummary>,
    connections_read: bool,
    connection_filter: String,
    /// Series catalog of each subflow, read once
    catalogs: HashMap<i64, Vec<SeriesInfo>>,
    connection: Option<ConnectionInfo>,
    subflows: Vec<Subflow>,
    /// The metrics that at least one subflow has
    metrics: Vec<MetricKey>,
    metric_filter: String,
    /// Plotted metrics, top to bottom
    selected: Vec<MetricKey>,
    /// The loaded plots, in the order of `selected`; the last ones may still be missing
    plots: Vec<MetricPlot>,
    /// Path manager events, in time order
    events: Vec<PmEvent>,
    needs_fit: bool,
}

impl TabMptcp {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn show(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if !self.connections_read {
            self.connections = connection_summaries(db, &mut self.catalogs);
            self.connections_read = true;
            if let Some(first) = self.connections.first().map(|c| c.id) {
                self.select_connection(db, first);
            }
        }
        if self.connections.is_empty() {
            // The tab is disabled then, this only shows if that changes
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new(NO_MPTCP_HINT).color(theme::muted_text(settings.dark_mode)));
            });
            return;
        }

        egui::SidePanel::left("mptcp_sidebar")
            .resizable(true)
            .min_width(280.0)
            .max_width(720.0)
            .default_width(460.0)
            .frame(theme::sidebar_frame(settings.dark_mode))
            .show_inside(ui, |ui| {
                ScrollArea::vertical()
                    .id_salt("mptcp_sidebar_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin::symmetric(16, 8))
                            .show(ui, |ui| self.show_sidebar(ui, db));
                    });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::panel_bg(settings.dark_mode)))
            .show_inside(ui, |ui| {
                ui.add_space(4.0);
                self.show_connection(ui, db, settings);
            });
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui, db: &DbBackend) {
        section_heading(ui, "Connections");
        if let Some(id) = self.show_connection_table(ui) {
            self.select_connection(db, id);
        }

        if self.connection.is_none() {
            return;
        }
        ui.add_space(12.0);
        section_heading(ui, "Metrics of every subflow");
        ui.add(
            egui::TextEdit::singleline(&mut self.metric_filter)
                .hint_text("Filter metrics")
                .desired_width(ui.available_width()),
        );
        let mut toggled = None;
        for (source, metrics) in group_metrics(&self.metrics, &self.metric_filter) {
            let selected = metrics.iter().filter(|m| self.selected.contains(m)).count();
            let title = if selected > 0 {
                format!("{source} ({selected})")
            } else {
                source.to_string()
            };
            egui::CollapsingHeader::new(title)
                .id_salt(("mptcp_metric_group", source))
                .default_open(source == DEFAULT_METRIC.0)
                .show(ui, |ui| {
                    for m in metrics {
                        let mut on = self.selected.contains(m);
                        if ui.checkbox(&mut on, metric_label(m)).changed() {
                            toggled = Some(m.clone());
                        }
                    }
                });
        }
        if let Some(m) = toggled {
            match self.selected.iter().position(|s| *s == m) {
                Some(i) => {
                    self.selected.remove(i);
                    if i < self.plots.len() {
                        self.plots.remove(i);
                    }
                }
                // Loaded by show_connection, at the width of the plots. It takes the time range
                // of the others and fits its values itself; only the first one fits the view.
                None => {
                    self.needs_fit |= self.selected.is_empty();
                    self.selected.push(m);
                }
            }
        }
    }

    /// The filterable connection table. Returns the id of a newly clicked connection.
    fn show_connection_table(&mut self, ui: &mut egui::Ui) -> Option<i64> {
        let dark_mode = ui.visuals().dark_mode;
        let selected_id = self.connection.as_ref().map(|c| c.id);
        let mut clicked = None;
        table::frame(dark_mode).show(ui, |ui| {
            let content_w = ui.available_width().max(1.0);
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.add(
                egui::TextEdit::singleline(&mut self.connection_filter)
                    .hint_text("Filter, e.g. 0x3fa1 10.31.1.1 server")
                    .desired_width(content_w),
            );
            let filter = self.connection_filter.to_lowercase();
            let visible: Vec<&ConnectionSummary> = self
                .connections
                .iter()
                .filter(|c| c.matches(&filter))
                .collect();
            let fixed = COL_TOKEN + COL_SIDE + COL_SUBFLOWS + COL_EVENTS + COL_DURATION;
            let col_flow = (content_w - fixed).max(80.0);

            let header_rect = egui::Rect::from_min_size(
                ui.available_rect_before_wrap().min,
                Vec2::new(content_w, ROW_HEIGHT),
            );
            ui.painter()
                .rect_filled(header_rect, 0.0, theme::table_header_bg(dark_mode));
            ui.horizontal(|ui| {
                ui.set_height(ROW_HEIGHT);
                header_cell(ui, "Token", COL_TOKEN);
                header_cell(ui, "First subflow", col_flow);
                header_cell(ui, "Side", COL_SIDE);
                header_cell(ui, "Sf", COL_SUBFLOWS).on_hover_text("Subflows");
                header_cell(ui, "Events", COL_EVENTS)
                    .on_hover_text("Path manager records on the subflows' tuples");
                header_cell(ui, "Length", COL_DURATION);
            });
            if visible.is_empty() {
                ui.label(
                    RichText::new("No connections match the filter.")
                        .color(theme::muted_text(dark_mode))
                        .italics(),
                );
                return;
            }
            // At most 8 rows, the metrics follow below
            ScrollArea::vertical()
                .id_salt("mptcp_connection_rows")
                .max_height(8.0 * ROW_HEIGHT)
                .auto_shrink([false, true])
                .show_rows(ui, ROW_HEIGHT, visible.len(), |ui, range| {
                    ui.set_width(content_w);
                    for i in range {
                        let row = visible[i];
                        let selected = selected_id == Some(row.id);
                        let response = ui.horizontal(|ui| {
                            ui.set_width(content_w);
                            ui.set_height(ROW_HEIGHT);
                            let rect = ui.max_rect();
                            let hovered = ui.rect_contains_pointer(rect);
                            ui.painter().rect_filled(
                                rect,
                                0.0,
                                table::row_fill(dark_mode, i, selected, hovered),
                            );
                            data_cell(ui, &row.token_text(), COL_TOKEN, selected);
                            data_cell(ui, &row.first_subflow, col_flow, selected);
                            data_cell(ui, row.side.map_or("–", |s| s.label()), COL_SIDE, selected);
                            data_cell(ui, &row.subflows.to_string(), COL_SUBFLOWS, selected);
                            data_cell(ui, &row.events.to_string(), COL_EVENTS, selected);
                            data_cell(
                                ui,
                                &format!("{:.2} s", row.duration_s),
                                COL_DURATION,
                                selected,
                            );
                        });
                        let rect = response.response.rect;
                        let click = ui
                            .interact(
                                rect,
                                ui.id().with(("mptcp_connection", row.id)),
                                egui::Sense::click(),
                            )
                            .on_hover_text(connection_tooltip(row));
                        if click.clicked() && !selected {
                            clicked = Some(row.id);
                        }
                        table::row_divider(ui, rect);
                    }
                });
        });
        clicked
    }

    /// Reads the subflows of a connection and their catalogs, the metrics they share and the
    /// path manager events.
    fn select_connection(&mut self, db: &DbBackend, connection_id: i64) {
        let Some(connection) = db
            .list_connections()
            .iter()
            .find(|c| c.id == connection_id)
            .cloned()
        else {
            return;
        };
        self.subflows.clear();
        self.events.clear();
        let mut members: Vec<&ConnectionFlow> = db
            .list_connection_flows()
            .iter()
            .filter(|m| m.connection_id == connection_id)
            .collect();
        sort_subflows(&mut members);
        let colors = generate_colors(members.len());
        for (m, color) in members.into_iter().zip(colors) {
            let Some(flow) = db.get_flow_by_id(m.flow_id) else {
                continue;
            };
            let label = match m.subflow_id {
                Some(id) => format!("subflow {id}"),
                None => format!("flow {}", m.flow_id),
            };
            self.subflows.push(Subflow {
                member: m.clone(),
                label: format!("{label} ({}:{})", flow.tuple.src, flow.tuple.sport),
                color,
                flow: format_flow(flow),
                series: self
                    .catalogs
                    .entry(m.flow_id)
                    .or_insert_with(|| db.list_series_for_flow(m.flow_id))
                    .clone(),
                backup: None,
                events: 0,
                hidden: false,
            });
        }

        let metrics: BTreeSet<MetricKey> = self
            .subflows
            .iter()
            .flat_map(|s| s.series.iter())
            .filter(|s| s.kind == SeriesKind::Raw && s.value_type != ColType::Text && s.n > 0)
            .filter(|s| s.source != "mptcp_pm")
            .map(metric_key)
            .collect();
        self.metrics = metrics.into_iter().collect();
        let default = (
            DEFAULT_METRIC.0.to_string(),
            DEFAULT_METRIC.1,
            DEFAULT_METRIC.2.to_string(),
        );
        // Keep the plotted metrics when switching connections, as far as the new one has them
        self.selected.retain(|m| self.metrics.contains(m));
        if self.selected.is_empty() {
            self.selected = if self.metrics.contains(&default) {
                vec![default]
            } else {
                self.metrics.first().cloned().into_iter().collect()
            };
        }
        self.plots.clear();
        self.needs_fit = true;

        for (index, sub) in self.subflows.iter_mut().enumerate() {
            let events = subflow_events(db, sub, &connection);
            sub.events = events.len();
            sub.backup = events
                .iter()
                .rev()
                .find(|e| carries_backup(e.1))
                .map(|e| e.3);
            for (t, code, label, _) in events {
                let row = if is_connection_event(code) {
                    0
                } else {
                    index + 1
                };
                self.events.push(PmEvent {
                    t,
                    code,
                    row,
                    label,
                });
            }
        }
        self.events.sort_by(|a, b| a.t.total_cmp(&b.t));
        self.connection = Some(connection);
    }

    /// Loads `metric` of every subflow over the whole connection.
    fn load_metric(
        &self,
        db: &DbBackend,
        settings: &AppSettings,
        metric: &MetricKey,
        width: f32,
    ) -> MetricPlot {
        let mut plot = MetricPlot { series: Vec::new() };
        let infos: Vec<(usize, &Subflow, &SeriesInfo)> = self
            .subflows
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.find(metric).map(|info| (i, s, info)))
            .collect();
        let Some(connection) = &self.connection else {
            return plot;
        };
        // A flow tuple may also belong to other connections: only this one's time span
        let Some((t_min, t_max)) = flow_x_bounds(infos.iter().map(|(_, _, info)| *info))
            .map(|(lo, hi)| {
                (
                    lo.max(connection.start_ts as f64),
                    hi.min(connection.end_ts as f64),
                )
            })
            .filter(|(lo, hi)| lo <= hi)
        else {
            return plot;
        };
        for (index, sub, info) in infos {
            let mut sd = SeriesData::from_info(info, t_min, t_max, sub.color);
            sd.name = sub.label.clone();
            fetch_range(db, &mut sd, t_min, t_max, settings, Some(width));
            plot.series.push((index, sd));
        }
        plot
    }

    fn show_connection(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if self.connection.is_none() {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Select an MPTCP connection from the sidebar.")
                        .color(theme::muted_text(settings.dark_mode)),
                );
            });
            return;
        }
        while self.plots.len() < self.selected.len() {
            let metric = &self.selected[self.plots.len()];
            let plot = self.load_metric(db, settings, metric, ui.available_width());
            self.plots.push(plot);
        }
        // The panel takes its space first, the plots get the rest
        let rows = self.subflows.len() as f32 + 1.0;
        egui::TopBottomPanel::bottom("mptcp_subflow_panel")
            .resizable(true)
            .default_height((rows * ROW_HEIGHT + 24.0).clamp(80.0, 260.0))
            .height_range(60.0..=600.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::panel_bg(settings.dark_mode))
                    .inner_margin(egui::Margin::symmetric(0, 8)),
            )
            .show_inside(ui, |ui| {
                if let Some(index) = self.show_subflow_table(ui) {
                    let sub = &mut self.subflows[index];
                    sub.hidden = !sub.hidden;
                }
            });
        self.show_plots(ui, db, settings, ui.available_height());
    }

    /// One plot per selected metric, stacked, with a shared time axis
    fn show_plots(
        &mut self,
        ui: &mut egui::Ui,
        db: &DbBackend,
        settings: &AppSettings,
        height: f32,
    ) {
        let Some(connection) = &self.connection else {
            return;
        };
        // Time 0 is the start of the connection
        let origin = connection.start_ts as f64;
        let (fit_x_min, fit_x_max) = (connection.start_ts as f64, connection.end_ts as f64);
        let fit = std::mem::take(&mut self.needs_fit);
        let width = ui.available_width().max(1.0);

        let lane = self.show_event_lane(ui, settings, fit, origin);
        let mut reset = lane.reset;
        let height = height - lane.height;
        if self.selected.is_empty() {
            ui.allocate_ui(Vec2::new(ui.available_width(), height), |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new("Select metrics in the sidebar.")
                            .color(theme::muted_text(settings.dark_mode)),
                    );
                });
            });
            self.needs_fit |= reset;
            return;
        }
        // Room for the metric name above each plot
        let plot_height = (split_plot_height_with_footer(height, self.selected.len()) - 22.0)
            .max(MIN_PLOT_HEIGHT);
        let marker_color = theme::muted_text(settings.dark_mode);

        let mut visible = None;
        ScrollArea::vertical()
            .id_salt("mptcp_plots_scroll")
            .max_height(height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (metric, plot) in self.selected.iter().zip(&self.plots) {
                    plot_heading(ui, &metric_label(metric));
                    let response = Plot::new(("mptcp_metric", metric_label(metric)))
                        .allow_boxed_zoom(true)
                        .allow_drag(true)
                        // The wheel scrolls the stack, not the values
                        .allow_scroll([true, false])
                        // Its auto bounds would spread to the linked plots and unlink their
                        // time; a double-click resets the whole view instead, see below
                        .allow_double_click_reset(false)
                        .link_axis("mptcp_time", [true, false])
                        .link_cursor("mptcp_time", [true, false])
                        .x_grid_spacer(seconds_grid_spacer(origin))
                        .x_axis_formatter(seconds_since_formatter(origin))
                        .y_axis_formatter(time_or_compact_formatter(origin))
                        // Same width in every plot, so the time axes line up
                        .y_axis_min_width(Y_AXIS_WIDTH)
                        .label_formatter(seconds_label_formatter(origin))
                        .height(plot_height)
                        .show(ui, |plot_ui| {
                            if fit {
                                let (y_min, y_max) = plot
                                    .series
                                    .iter()
                                    .filter(|(i, _)| !self.subflows[*i].hidden)
                                    .fold((0.0_f64, 1.0_f64), |(lo, hi), (_, s)| {
                                        (lo.min(s.global_y_min), hi.max(s.global_y_max))
                                    });
                                plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                                    [fit_x_min, y_min * 1.05],
                                    [fit_x_max, y_max * 1.05],
                                ));
                            } else if visible.is_none() {
                                let bounds = plot_ui.plot_bounds();
                                visible = Some((bounds.min()[0], bounds.max()[0]));
                            }
                            for (_, s) in plot
                                .series
                                .iter()
                                .filter(|(i, _)| !self.subflows[*i].hidden)
                            {
                                // Counters and states hold their value until the next record.
                                // Not booleans: only their true records are loaded.
                                let step = s.val_type == ValueKind::Int;
                                let gap = gap_threshold(&s.points, s.loaded_sample_interval);
                                for segment in segments(&s.points, gap, step) {
                                    if segment.len() == 1 {
                                        plot_ui.points(
                                            Points::new(PlotPoints::from(segment))
                                                .color(s.color)
                                                .radius(2.0)
                                                .name(&s.name),
                                        );
                                    } else {
                                        plot_ui.line(
                                            Line::new(PlotPoints::from(segment))
                                                .color(s.color)
                                                .name(&s.name),
                                        );
                                    }
                                }
                            }
                            // Details are in the event lane
                            for e in self.events.iter().filter(|e| is_structural(e.code)) {
                                plot_ui
                                    .vline(VLine::new(e.t).color(marker_color.gamma_multiply(0.5)));
                            }
                        });
                    reset |=
                        response.response.secondary_clicked() || response.response.double_clicked();
                    ui.add_space(4.0);
                }
            });
        if reset {
            self.needs_fit = true;
        }

        // Panned or zoomed in: load the visible part of the data in more detail. The plots
        // share the time axis, so one of them gives the visible range of all.
        if let Some((x_min, x_max)) = visible {
            for (_, sd) in self.plots.iter_mut().flat_map(|p| p.series.iter_mut()) {
                let lo = x_min.max(sd.global_t_min);
                let hi = x_max.min(sd.global_t_max);
                if lo >= hi {
                    continue;
                }
                let stale = sd.loaded_range.is_none_or(|(loaded_lo, loaded_hi)| {
                    lo < loaded_lo || hi > loaded_hi || (hi - lo) * 4.0 < loaded_hi - loaded_lo
                });
                if stale {
                    load_series_window(db, sd, x_min, x_max, settings, Some(width));
                }
            }
        }
    }

    /// The path manager events above the metric plots: a row for the connection and one per
    /// subflow, a marker per event, the full text on hover.
    fn show_event_lane(
        &self,
        ui: &mut egui::Ui,
        settings: &AppSettings,
        fit: bool,
        origin: f64,
    ) -> LaneResponse {
        let Some(connection) = &self.connection else {
            return LaneResponse::default();
        };
        let top = ui.cursor().top();
        let rows = self.subflows.len() + 1;
        let lane_height = ((rows + 1) as f32 * LANE_ROW_HEIGHT).max(MIN_LANE_HEIGHT);
        let dark_mode = settings.dark_mode;
        plot_heading(ui, "Path manager events");
        let events = self.events.clone();
        let response = Plot::new("mptcp_event_lane")
            // Only time moves; the rows stay in view
            .allow_drag([true, false])
            .allow_zoom([true, false])
            .allow_scroll([true, false])
            .allow_boxed_zoom(false)
            .allow_double_click_reset(false)
            .link_axis("mptcp_time", [true, false])
            .link_cursor("mptcp_time", [true, false])
            // Hover needs one of the two; the label shows the event, not the coordinates
            .show_x(true)
            .show_y(false)
            .x_grid_spacer(seconds_grid_spacer(origin))
            .x_axis_formatter(|_, _| String::new())
            .y_grid_spacer(move |_| {
                (0..rows)
                    .map(|i| GridMark {
                        value: i as f64,
                        step_size: 1.0,
                    })
                    .collect()
            })
            .y_axis_formatter(move |mark, _| lane_row_name(mark.value, rows))
            .y_axis_min_width(Y_AXIS_WIDTH)
            .label_formatter(move |name, point| {
                let time = format!("{:.3} s", (point.x - origin) / 1e9);
                match nearest_event(&events, pm_event_name, name, point.x, point.y, rows) {
                    Some(e) => format!("{}\n{:.3} s", e.label, (e.t - origin) / 1e9),
                    None => time,
                }
            })
            .height(lane_height)
            .show(ui, |plot_ui| {
                if fit {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [connection.start_ts as f64, -0.6],
                        [connection.end_ts as f64, rows as f64 - 0.4],
                    ));
                }
                let mut codes: Vec<i64> = self.events.iter().map(|e| e.code).collect();
                codes.sort_unstable();
                codes.dedup();
                for code in codes {
                    let points: Vec<[f64; 2]> = self
                        .events
                        .iter()
                        .filter(|e| e.code == code)
                        .map(|e| [e.t, lane_y(e.row, rows)])
                        .collect();
                    plot_ui.points(
                        Points::new(PlotPoints::from(points))
                            .shape(event_shape(code))
                            .color(event_color(code, dark_mode))
                            .filled(true)
                            .radius(4.0)
                            .name(pm_event_name(code)),
                    );
                }
            });
        self.show_event_legend(ui, dark_mode);
        ui.add_space(4.0);
        LaneResponse {
            height: ui.cursor().top() - top,
            reset: response.response.secondary_clicked(),
        }
    }

    /// Marker and name of each event type of the connection
    fn show_event_legend(&self, ui: &mut egui::Ui, dark_mode: bool) {
        let mut codes: Vec<i64> = self.events.iter().map(|e| e.code).collect();
        codes.sort_unstable();
        codes.dedup();
        ui.horizontal_wrapped(|ui| {
            for code in codes {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), egui::Sense::hover());
                paint_marker(
                    ui.painter(),
                    rect.center(),
                    event_shape(code),
                    event_color(code, dark_mode),
                    4.0,
                );
                ui.label(
                    RichText::new(pm_event_name(code))
                        .size(11.5)
                        .color(theme::muted_text(dark_mode)),
                );
                ui.add_space(8.0);
            }
        });
    }

    /// The subflows with their bytes and counters. Returns the index of a clicked row, which
    /// shows or hides the subflow in the plots.
    fn show_subflow_table(&self, ui: &mut egui::Ui) -> Option<usize> {
        let dark_mode = ui.visuals().dark_mode;
        let origin = self.connection.as_ref().map_or(0, |c| c.start_ts);
        let acked: Vec<Option<f64>> = self
            .subflows
            .iter()
            .map(|s| s.counter("bytes_acked"))
            .collect();
        let received: Vec<Option<f64>> = self
            .subflows
            .iter()
            .map(|s| s.counter("bytes_received"))
            .collect();
        let shares = byte_shares(&acked, &received);
        let mut clicked = None;
        table::frame(dark_mode).show(ui, |ui| {
            let content_w = ui.available_width().max(1.0);
            ui.spacing_mut().item_spacing.x = 0.0;
            let fixed = SUBFLOW_COLUMNS.iter().map(|c| c.1).sum::<f32>();
            let col_flow = (content_w - fixed).max(120.0);
            let header_rect = egui::Rect::from_min_size(
                ui.available_rect_before_wrap().min,
                Vec2::new(content_w, ROW_HEIGHT),
            );
            ui.painter()
                .rect_filled(header_rect, 0.0, theme::table_header_bg(dark_mode));
            ui.horizontal(|ui| {
                ui.set_height(ROW_HEIGHT);
                for (i, (header, width, hint)) in SUBFLOW_COLUMNS.iter().enumerate() {
                    if i == 3 {
                        header_cell(ui, "Local -> remote", col_flow);
                    }
                    let response = header_cell(ui, header, *width);
                    if !hint.is_empty() {
                        response.on_hover_text(*hint);
                    }
                }
            });
            ScrollArea::vertical()
                .id_salt("mptcp_subflow_rows")
                .auto_shrink([false, false])
                .show_rows(ui, ROW_HEIGHT, self.subflows.len(), |ui, range| {
                    ui.set_width(content_w);
                    for i in range {
                        let sub = &self.subflows[i];
                        let m = &sub.member;
                        let response = ui.horizontal(|ui| {
                            ui.set_width(content_w);
                            ui.set_height(ROW_HEIGHT);
                            let rect = ui.max_rect();
                            let hovered = ui.rect_contains_pointer(rect);
                            ui.painter().rect_filled(
                                rect,
                                0.0,
                                table::row_fill(dark_mode, i, false, hovered),
                            );
                            let (swatch, _) = ui.allocate_exact_size(
                                Vec2::new(SUBFLOW_COLUMNS[0].1, ROW_HEIGHT),
                                egui::Sense::hover(),
                            );
                            let dot =
                                egui::Rect::from_center_size(swatch.center(), Vec2::splat(10.0));
                            if sub.hidden {
                                ui.painter().rect_stroke(
                                    dot,
                                    2.0,
                                    egui::Stroke::new(1.5, sub.color),
                                    egui::StrokeKind::Inside,
                                );
                            } else {
                                ui.painter().rect_filled(dot, 2.0, sub.color);
                            }
                            let opt =
                                |v: Option<f64>, f: fn(f64) -> String| v.map_or("–".to_string(), f);
                            number_cell(ui, &format!("{}", i + 1), SUBFLOW_COLUMNS[1].1, false);
                            number_cell(
                                ui,
                                &m.subflow_id.map_or("–".to_string(), |id| id.to_string()),
                                SUBFLOW_COLUMNS[2].1,
                                false,
                            );
                            data_cell(ui, &sub.flow, col_flow, false).on_hover_text(&sub.flow);
                            let seconds = |ts: i64| format!("{:.3}", (ts - origin) as f64 / 1e9);
                            number_cell(ui, &seconds(m.first_ts), SUBFLOW_COLUMNS[3].1, false);
                            number_cell(ui, &seconds(m.last_ts), SUBFLOW_COLUMNS[4].1, false);
                            number_cell(
                                ui,
                                &opt(acked[i], format_bytes),
                                SUBFLOW_COLUMNS[5].1,
                                false,
                            );
                            number_cell(
                                ui,
                                &opt(received[i], format_bytes),
                                SUBFLOW_COLUMNS[6].1,
                                false,
                            );
                            share_cell(ui, shares[i], sub.color, SUBFLOW_COLUMNS[7].1);
                            let count = |v: f64| format!("{v:.0}");
                            number_cell(
                                ui,
                                &opt(sub.counter("total_retrans"), count),
                                SUBFLOW_COLUMNS[8].1,
                                false,
                            );
                            number_cell(
                                ui,
                                &opt(sub.counter("backoff"), count),
                                SUBFLOW_COLUMNS[9].1,
                                false,
                            );
                            data_cell(
                                ui,
                                sub.backup.map_or("–", |b| if b { "yes" } else { "no" }),
                                SUBFLOW_COLUMNS[10].1,
                                false,
                            );
                            number_cell(ui, &sub.events.to_string(), SUBFLOW_COLUMNS[11].1, false);
                        });
                        let rect = response.response.rect;
                        let hint = if sub.hidden {
                            "Show in the plots"
                        } else {
                            "Hide in the plots"
                        };
                        let click = ui
                            .interact(
                                rect,
                                ui.id().with(("mptcp_subflow", i)),
                                egui::Sense::click(),
                            )
                            .on_hover_text(hint);
                        if click.clicked() {
                            clicked = Some(i);
                        }
                        table::row_divider(ui, rect);
                    }
                });
        });
        clicked
    }
}

/// A share as a bar in the subflow's colour with the percentage on it
fn share_cell(ui: &mut egui::Ui, share: Option<f64>, color: egui::Color32, width: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, ROW_HEIGHT), egui::Sense::hover());
    let Some(share) = share else {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "–",
            egui::FontId::proportional(12.0),
            theme::text(ui.visuals().dark_mode),
        );
        return;
    };
    let bar = rect.shrink2(Vec2::new(6.0, 5.0));
    ui.painter()
        .rect_filled(bar, 2.0, theme::border(ui.visuals().dark_mode));
    let filled =
        egui::Rect::from_min_size(bar.min, Vec2::new(bar.width() * share as f32, bar.height()));
    ui.painter()
        .rect_filled(filled, 2.0, color.gamma_multiply(0.6));
    ui.painter().text(
        bar.center(),
        egui::Align2::CENTER_CENTER,
        format!("{:.1} %", 100.0 * share),
        egui::FontId::proportional(11.5),
        theme::text(ui.visuals().dark_mode),
    );
}

/// Whether an event's record holds the subflow's backup flag
fn carries_backup(code: i64) -> bool {
    [
        TCBEE_MPTCP_SUB_ESTABLISHED,
        TCBEE_MPTCP_SUB_PRIORITY,
        TCBEE_MPTCP_MP_PRIO_SENT,
    ]
    .iter()
    .any(|c| *c as i64 == code)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn event_addresses() {
        let v4 = u32::from_le_bytes([10, 31, 1, 2]) as i64;
        assert_eq!(
            event_address(2, 5501, [v4, 0, 0, 0]).unwrap(),
            "10.31.1.2:5501"
        );
        assert_eq!(event_address(2, 0, [v4, 0, 0, 0]).unwrap(), "10.31.1.2");
        let one = u32::from_le_bytes([0, 0, 0, 1]) as i64;
        let db8 = u32::from_le_bytes([0x20, 0x01, 0x0d, 0xb8]) as i64;
        assert_eq!(
            event_address(10, 80, [db8, 0, 0, one]).unwrap(),
            "[2001:db8::1]:80"
        );
        assert_eq!(event_address(0, 0, [0; 4]), None);
    }

    #[test]
    fn metrics_group_by_source_and_filter() {
        let key = |source: &str, dir, name: &str| (source.to_string(), dir, name.to_string());
        let metrics = vec![
            key("cwnd", Dir::None, "snd_cwnd"),
            key("sock", Dir::Send, "backoff"),
            key("sock", Dir::Send, "snd_cwnd"),
            key("sock", Dir::Recv, "snd_cwnd"),
        ];
        let groups = group_metrics(&metrics, "");
        let sizes: Vec<(&str, usize)> = groups.iter().map(|(s, g)| (*s, g.len())).collect();
        assert_eq!(sizes, vec![("cwnd", 1), ("sock", 3)]);
        let groups = group_metrics(&metrics, "CWND send");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].1, vec![&metrics[2]]);
        assert!(group_metrics(&metrics, "rtt").is_empty());
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
    fn metric_labels() {
        let key = ("sock".to_string(), Dir::Send, "snd_cwnd".to_string());
        assert_eq!(metric_label(&key), "snd_cwnd · sock · send");
        let key = ("tcp_probe".to_string(), Dir::None, "SRTT".to_string());
        assert_eq!(metric_label(&key), "SRTT · tcp_probe");
    }
}
