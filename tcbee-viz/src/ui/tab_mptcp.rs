//! MPTCP connections: one connection at a time, its path manager events in a lane, a plot per
//! chosen metric with all subflows, and a table of the subflows with their bytes and their
//! share of the connection's bytes.

mod lane;
mod model;

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use egui::{RichText, ScrollArea, Vec2};
use egui_plot::{Line, LineStyle, Plot, PlotBounds, PlotPoints, Points, VLine};
use tcbee_common::records::{TCBEE_MPTCP_MP_PRIO_SENT, TCBEE_MPTCP_REINJECTED};
use ts_storage::{
    ColType, ConnectionFlow, ConnectionInfo, DataValue, Dir, SeriesInfo, SeriesKind, ValueKind,
};

use model::{
    byte_shares, carries_backup, event_type, format_bytes, gap_threshold, infer_sides,
    is_connection_event, is_structural, segments, sort_subflows, ConnectionSummary, PmEvent,
    SideInput,
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
        table::{
            self, data_cell, header_cell, number_cell, number_header_cell, text_cell,
            text_header_cell, ROW_HEIGHT,
        },
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
/// Width of the value axis of every metric plot and the lane
const Y_AXIS_WIDTH: f32 = 56.0;
/// Columns of the subflow table, left to right
#[derive(Clone, Copy, PartialEq)]
enum SubflowColumn {
    Swatch,
    Position,
    Id,
    Flow,
    Start,
    End,
    Acked,
    Received,
    Share,
    Retrans,
    Backoff,
    Backup,
    Events,
}

impl SubflowColumn {
    const ALL: [SubflowColumn; 13] = [
        Self::Swatch,
        Self::Position,
        Self::Id,
        Self::Flow,
        Self::Start,
        Self::End,
        Self::Acked,
        Self::Received,
        Self::Share,
        Self::Retrans,
        Self::Backoff,
        Self::Backup,
        Self::Events,
    ];
    /// Narrowest width of the flow column, which takes the rest
    const MIN_FLOW_WIDTH: f32 = 120.0;

    /// Header, width (none for the flow) and hover text
    fn spec(self) -> (&'static str, Option<f32>, &'static str) {
        match self {
            Self::Swatch => (
                "",
                Some(24.0),
                "Colour in the plots; click a row to hide or show the subflow",
            ),
            Self::Position => ("#", Some(28.0), "Row in the event lane"),
            Self::Id => (
                "Id",
                Some(30.0),
                "Subflow id of the kernel; the server does not number its joins",
            ),
            Self::Flow => ("Local -> remote", None, ""),
            Self::Start => ("Start", Some(62.0), "Seconds since the connection started"),
            Self::End => ("End", Some(62.0), ""),
            Self::Acked => ("Acked", Some(80.0), "Bytes acknowledged by the peer"),
            Self::Received => ("Received", Some(80.0), "Bytes received"),
            Self::Share => (
                "Share",
                Some(110.0),
                "Share of the bytes sent, or on a receiver of the bytes received",
            ),
            Self::Retrans => ("Retrans", Some(56.0), "Retransmitted segments"),
            Self::Backoff => (
                "Backoff",
                Some(60.0),
                "Highest RTO backoff: retransmission timeouts in a row",
            ),
            Self::Backup => (
                "Backup",
                Some(54.0),
                "Backup flag of the last path manager event that carries it",
            ),
            Self::Events => (
                "Events",
                Some(52.0),
                "Path manager events in the subflow's row of the lane",
            ),
        }
    }

    /// Whether the column holds numbers, set at the right edge
    fn is_number(self) -> bool {
        !matches!(self, Self::Swatch | Self::Flow | Self::Share | Self::Backup)
    }

    /// Width of all columns but the flow
    fn fixed_width() -> f32 {
        Self::ALL.iter().filter_map(|c| c.spec().1).sum()
    }
}

/// Rows the subflow panel makes room for at first
const PANEL_MIN_ROWS: usize = 5;
const PANEL_MAX_ROWS: usize = 10;
/// Space above and below the table in the subflow panel
const PANEL_MARGIN: f32 = 8.0;

/// Space between the filter box, its icon and buttons
const FILTER_GAP: f32 = 4.0;
const CONNECTION_FILTER_HELP: &str = "Plain text searches the token (hex or decimal), the \
first subflow and the side.\nCombine terms with spaces, e.g. 10.31.1.1 client";

/// Horizontal margin of the sidebar's content
const SIDEBAR_MARGIN: i8 = 16;
/// The connection table with its first subflow column at its narrowest
const CONNECTION_TABLE_MIN_WIDTH: f32 =
    COL_TOKEN + COL_FIRST_SUBFLOW_MIN + COL_SIDE + COL_SUBFLOWS + COL_EVENTS + COL_DURATION;
const COL_FIRST_SUBFLOW_MIN: f32 = 80.0;

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
        _ => format!("{name} · {source} · {}", format!("{dir:?}").to_lowercase()),
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
/// reused by another connection), in the lane row of subflow `index`
fn subflow_events(
    db: &DbBackend,
    sub: &Subflow,
    index: usize,
    connection: &ConnectionInfo,
) -> Vec<PmEvent> {
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
        let mut label = event_type(event).name.to_string();
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
        if !is_connection_event(event) {
            label.push_str(subflow.as_deref().unwrap_or(""));
        }
        out.push(PmEvent {
            t: *t,
            code: event,
            row: if is_connection_event(event) {
                0
            } else {
                index + 1
            },
            label,
            backup: int(&backup) != 0,
            failed: int(&error) != 0,
        });
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
    /// Bytes acknowledged by the peer and received, and the share of the connection's bytes
    acked: Option<f64>,
    received: Option<f64>,
    share: Option<f64>,
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

/// One plotted metric: a series per subflow that has it, with the subflow's index
struct MetricPlot {
    series: Vec<(usize, SeriesData)>,
    /// Not shown yet: its values are fitted once, the time range comes from the other plots
    new: bool,
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
    /// Path manager events, in time order; shared with the lane's hover label
    events: Arc<[PmEvent]>,
    /// The event types among them: code and whether failed
    event_keys: Vec<(i64, bool)>,
    /// Time per screen pixel of the lane in the last frame, for grouping close events
    lane_ns_per_px: std::cell::Cell<f64>,
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
            .min_width(CONNECTION_TABLE_MIN_WIDTH + 2.0 * SIDEBAR_MARGIN as f32)
            .max_width(720.0)
            .default_width(460.0)
            .frame(theme::sidebar_frame(settings.dark_mode))
            .show_inside(ui, |ui| {
                ScrollArea::vertical()
                    .id_salt("mptcp_sidebar_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin::symmetric(SIDEBAR_MARGIN, 8))
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
        let width = ui.available_width();
        table::filter_bar(
            ui,
            &mut self.metric_filter,
            "Filter, e.g. cwnd send",
            None,
            width,
            FILTER_GAP,
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
            table::filter_bar(
                ui,
                &mut self.connection_filter,
                "Filter, e.g. 0x3fa1 server",
                Some(CONNECTION_FILTER_HELP),
                content_w,
                FILTER_GAP,
            );
            let filter = self.connection_filter.to_lowercase();
            let visible: Vec<&ConnectionSummary> = self
                .connections
                .iter()
                .filter(|c| c.matches(&filter))
                .collect();
            let fixed = COL_TOKEN + COL_SIDE + COL_SUBFLOWS + COL_EVENTS + COL_DURATION;
            let col_flow = (content_w - fixed).max(COL_FIRST_SUBFLOW_MIN);

            table::header_row(ui, content_w, |ui| {
                header_cell(ui, "Token", COL_TOKEN);
                header_cell(ui, "First subflow", col_flow);
                header_cell(ui, "Side", COL_SIDE);
                number_header_cell(ui, "Sf", COL_SUBFLOWS).on_hover_text("Subflows");
                number_header_cell(ui, "Events", COL_EVENTS)
                    .on_hover_text("Path manager records on the subflows' tuples");
                number_header_cell(ui, "Length", COL_DURATION);
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
                            number_cell(ui, &row.subflows.to_string(), COL_SUBFLOWS, selected);
                            number_cell(ui, &row.events.to_string(), COL_EVENTS, selected);
                            number_cell(
                                ui,
                                &format!("{:.2} s", row.duration_s),
                                COL_DURATION,
                                selected,
                            );
                        });
                        let rect = response.response.rect;
                        let click =
                            table::row_click(ui, rect, ui.id().with(("mptcp_connection", row.id)))
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
        self.events = Arc::default();
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
                acked: None,
                received: None,
                share: None,
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

        for sub in &mut self.subflows {
            sub.acked = sub.counter("bytes_acked");
            sub.received = sub.counter("bytes_received");
        }
        let acked: Vec<Option<f64>> = self.subflows.iter().map(|s| s.acked).collect();
        let received: Vec<Option<f64>> = self.subflows.iter().map(|s| s.received).collect();
        for (sub, share) in self.subflows.iter_mut().zip(byte_shares(&acked, &received)) {
            sub.share = share;
        }

        let mut events = Vec::new();
        for (index, sub) in self.subflows.iter_mut().enumerate() {
            let own = subflow_events(db, sub, index, &connection);
            // Only the events in the subflow's own row are about it
            let mine = || own.iter().filter(|e| e.row != 0);
            sub.events = mine().count();
            sub.backup = mine()
                .rev()
                .find(|e| carries_backup(e.code))
                .map(|e| e.backup);
            events.extend(own);
        }
        events.sort_by(|a, b| a.t.total_cmp(&b.t));
        self.event_keys = events.iter().map(|e| (e.code, e.failed)).collect();
        self.event_keys.sort_unstable();
        self.event_keys.dedup();
        self.events = events.into();
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
        let mut plot = MetricPlot {
            series: Vec::new(),
            new: true,
        };
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
        // The panel takes its space first, the plots get the rest. Its height is chosen once;
        // after that it keeps what the user resized it to.
        let rows = self.subflows.len().clamp(PANEL_MIN_ROWS, PANEL_MAX_ROWS);
        egui::TopBottomPanel::bottom("mptcp_subflow_panel")
            .resizable(true)
            .default_height(table::table_height(rows) + 2.0 * PANEL_MARGIN)
            .height_range(60.0..=600.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::panel_bg(settings.dark_mode))
                    .inner_margin(egui::Margin::symmetric(0, PANEL_MARGIN as i8)),
            )
            .show_inside(ui, |ui| {
                if let Some(index) = self.show_subflow_table(ui) {
                    let sub = &mut self.subflows[index];
                    sub.hidden = !sub.hidden;
                }
            });
        self.show_plots(ui, db, settings, ui.available_height());
    }

    /// The value range a plot is fitted to: its visible subflows' values and 0, with some room
    fn value_range(&self, plot: &MetricPlot) -> (f64, f64) {
        let (lo, hi) = plot
            .series
            .iter()
            .filter(|(i, _)| !self.subflows[*i].hidden)
            .fold((0.0_f64, 1.0_f64), |(lo, hi), (_, s)| {
                (lo.min(s.global_y_min), hi.max(s.global_y_max))
            });
        (lo * 1.05, hi * 1.05)
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
                    let (y_min, y_max) = self.value_range(plot);
                    section_heading(ui, &metric_label(metric));
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
                                plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                                    [fit_x_min, y_min],
                                    [fit_x_max, y_max],
                                ));
                            } else if plot.new {
                                // Otherwise its values stay on auto bounds and rescale with
                                // every detail load while panning
                                let (x_min, x_max) = lane.time_range;
                                plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                                    [x_min, y_min],
                                    [x_max, y_max],
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
                                    if segment.held {
                                        // No records over the pause, the value only held
                                        plot_ui.line(
                                            Line::new(PlotPoints::from(segment.points))
                                                .color(s.color.gamma_multiply(0.4))
                                                .style(LineStyle::dashed_dense())
                                                .name(&s.name),
                                        );
                                    } else if segment.points.len() == 1 {
                                        plot_ui.points(
                                            Points::new(PlotPoints::from(segment.points))
                                                .color(s.color)
                                                .radius(2.0)
                                                .name(&s.name),
                                        );
                                    } else {
                                        plot_ui.line(
                                            Line::new(PlotPoints::from(segment.points))
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
        for plot in &mut self.plots {
            plot.new = false;
        }
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

    /// The subflows with their bytes and counters. Returns the index of a clicked row, which
    /// shows or hides the subflow in the plots.
    fn show_subflow_table(&self, ui: &mut egui::Ui) -> Option<usize> {
        let dark_mode = ui.visuals().dark_mode;
        let min_width = SubflowColumn::fixed_width() + SubflowColumn::MIN_FLOW_WIDTH + 2.0;
        let mut clicked = None;
        // Scrolls sideways in a narrow window instead of cutting off the last columns
        ScrollArea::horizontal()
            .id_salt("mptcp_subflow_table")
            .show(ui, |ui| {
                ui.set_min_width(min_width);
                table::frame(dark_mode).show(ui, |ui| {
                    let content_w = ui.available_width().max(1.0);
                    // Packed rows, so that table_height holds
                    ui.spacing_mut().item_spacing = Vec2::ZERO;
                    let flow_w = (content_w - SubflowColumn::fixed_width())
                        .max(SubflowColumn::MIN_FLOW_WIDTH);
                    let width = |c: SubflowColumn| c.spec().1.unwrap_or(flow_w);
                    table::header_row(ui, content_w, |ui| {
                        for column in SubflowColumn::ALL {
                            let (header, _, hint) = column.spec();
                            let response = if column.is_number() {
                                number_header_cell(ui, header, width(column))
                            } else if column == SubflowColumn::Flow {
                                text_header_cell(ui, header, width(column))
                            } else {
                                header_cell(ui, header, width(column))
                            };
                            if !hint.is_empty() {
                                response.on_hover_text(hint);
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
                                    for column in SubflowColumn::ALL {
                                        self.subflow_cell(ui, column, i, width(column));
                                    }
                                });
                                let rect = response.response.rect;
                                let hint = if sub.hidden {
                                    "Show in the plots"
                                } else {
                                    "Hide in the plots"
                                };
                                let click =
                                    table::row_click(ui, rect, ui.id().with(("mptcp_subflow", i)))
                                        .on_hover_text(hint);
                                if click.clicked() {
                                    clicked = Some(i);
                                }
                                table::row_divider(ui, rect);
                            }
                        });
                });
            });
        clicked
    }

    /// One cell of the subflow table: `column` of subflow `index`
    fn subflow_cell(&self, ui: &mut egui::Ui, column: SubflowColumn, index: usize, width: f32) {
        let sub = &self.subflows[index];
        let m = &sub.member;
        let origin = self.connection.as_ref().map_or(0, |c| c.start_ts);
        let or_dash = |v: Option<String>| v.unwrap_or_else(|| "–".to_string());
        let count = |v: Option<f64>| or_dash(v.map(|v| format!("{v:.0}")));
        let seconds = |ts: i64| format!("{:.3}", (ts - origin) as f64 / 1e9);
        let text = match column {
            SubflowColumn::Swatch => {
                swatch_cell(ui, sub.color, sub.hidden, width);
                return;
            }
            SubflowColumn::Share => {
                share_cell(ui, sub.share, sub.color, width);
                return;
            }
            SubflowColumn::Flow => {
                text_cell(ui, &sub.flow, width, false).on_hover_text(&sub.flow);
                return;
            }
            SubflowColumn::Position => (index + 1).to_string(),
            SubflowColumn::Id => or_dash(m.subflow_id.map(|id| id.to_string())),
            SubflowColumn::Start => seconds(m.first_ts),
            SubflowColumn::End => seconds(m.last_ts),
            SubflowColumn::Acked => or_dash(sub.acked.map(format_bytes)),
            SubflowColumn::Received => or_dash(sub.received.map(format_bytes)),
            SubflowColumn::Retrans => count(sub.counter("total_retrans")),
            SubflowColumn::Backoff => count(sub.counter("backoff")),
            SubflowColumn::Backup => {
                or_dash(sub.backup.map(|b| if b { "yes" } else { "no" }.to_string()))
            }
            SubflowColumn::Events => sub.events.to_string(),
        };
        if column.is_number() {
            number_cell(ui, &text, width, false);
        } else {
            data_cell(ui, &text, width, false);
        }
    }
}

/// The subflow's colour, hollow if it is hidden in the plots
fn swatch_cell(ui: &mut egui::Ui, color: egui::Color32, hidden: bool, width: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, ROW_HEIGHT), egui::Sense::hover());
    let dot = egui::Rect::from_center_size(rect.center(), Vec2::splat(10.0));
    if hidden {
        ui.painter().rect_stroke(
            dot,
            2.0,
            egui::Stroke::new(1.5, color),
            egui::StrokeKind::Inside,
        );
    } else {
        ui.painter().rect_filled(dot, 2.0, color);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn metric_labels() {
        let key = ("sock".to_string(), Dir::Send, "snd_cwnd".to_string());
        assert_eq!(metric_label(&key), "snd_cwnd · sock · send");
        let key = ("tcp_probe".to_string(), Dir::None, "SRTT".to_string());
        assert_eq!(metric_label(&key), "SRTT · tcp_probe");
        let key = ("tcp4".to_string(), Dir::Recv, "ACK_NUM".to_string());
        assert_eq!(metric_label(&key), "ACK_NUM · tcp4 · recv");
    }
}
