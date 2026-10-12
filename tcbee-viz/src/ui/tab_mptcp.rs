//! MPTCP connections: one connection at a time, one metric of all its subflows in one plot,
//! the path manager events as markers, and a table of the subflows with their share of the
//! acknowledged bytes.

mod model;

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use egui::{RichText, ScrollArea, Vec2};
use egui_plot::{Line, Plot, PlotBounds, PlotPoint, PlotPoints, Text, VLine};
use tcbee_common::records::{
    TCBEE_MPTCP_ANNOUNCED, TCBEE_MPTCP_CLOSED, TCBEE_MPTCP_CREATED, TCBEE_MPTCP_ESTABLISHED,
    TCBEE_MPTCP_FALLBACK, TCBEE_MPTCP_LISTENER_CLOSED, TCBEE_MPTCP_LISTENER_CREATED,
    TCBEE_MPTCP_MP_FAIL, TCBEE_MPTCP_MP_PRIO_SENT, TCBEE_MPTCP_PENDING_REQUEUED,
    TCBEE_MPTCP_REINJECTED, TCBEE_MPTCP_REMOVED, TCBEE_MPTCP_SUBFLOW_CONNECT,
    TCBEE_MPTCP_SUBFLOW_STALE, TCBEE_MPTCP_SUB_CLOSED, TCBEE_MPTCP_SUB_ESTABLISHED,
    TCBEE_MPTCP_SUB_PRIORITY, TCBEE_MPTCP_TOKEN_DESTROYED,
};
use ts_storage::{ColType, ConnectionFlow, ConnectionInfo, DataValue, Dir, SeriesInfo, SeriesKind};

use model::{infer_sides, sort_subflows, ConnectionSummary, SideInput};

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
            split_plot_height_with_footer, time_or_compact_formatter, vertical_marker_label,
        },
        table::{self, data_cell, header_cell, ROW_HEIGHT},
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
/// reused by another connection): (time, marker label)
fn subflow_events(
    db: &DbBackend,
    sub: &Subflow,
    connection: &ConnectionInfo,
) -> Vec<(f64, String)> {
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
        out.push((*t, label));
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
}

impl Subflow {
    fn find(&self, (source, dir, name): &MetricKey) -> Option<&SeriesInfo> {
        self.series
            .iter()
            .find(|s| &s.source == source && s.dir == *dir && &s.name == name)
    }

    /// Bytes acknowledged by the peer: the last value of the counter, its catalog maximum
    fn bytes_acked(&self) -> Option<f64> {
        let key = ("sock".to_string(), Dir::Send, "bytes_acked".to_string());
        self.find(&key).and_then(|s| s.v_max)
    }
}

/// One plotted metric: a series per subflow that has it
struct MetricPlot {
    series: Vec<SeriesData>,
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
    /// Path manager events: (time, label)
    events: Vec<(f64, String)>,
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
                ui.label(RichText::new(NO_MPTCP_HINT).color(egui::Color32::GRAY));
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
                // Loaded by show_connection, at the width of the plots
                None => self.selected.push(m),
            }
            self.needs_fit = true;
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

        for sub in &self.subflows {
            self.events.extend(subflow_events(db, sub, &connection));
        }
        self.events.sort_by(|a, b| a.0.total_cmp(&b.0));
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
        let infos: Vec<(&Subflow, &SeriesInfo)> = self
            .subflows
            .iter()
            .filter_map(|s| s.find(metric).map(|info| (s, info)))
            .collect();
        let Some(connection) = &self.connection else {
            return plot;
        };
        // A flow tuple may also belong to other connections: only this one's time span
        let Some((t_min, t_max)) = flow_x_bounds(infos.iter().map(|(_, info)| *info))
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
        for (sub, info) in infos {
            let mut sd = SeriesData::from_info(info, t_min, t_max, sub.color);
            sd.name = sub.label.clone();
            fetch_range(db, &mut sd, t_min, t_max, settings, Some(width));
            plot.series.push(sd);
        }
        plot
    }

    fn show_connection(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if self.connection.is_none() {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Select an MPTCP connection from the sidebar.")
                        .color(egui::Color32::GRAY),
                );
            });
            return;
        }
        while self.plots.len() < self.selected.len() {
            let metric = &self.selected[self.plots.len()];
            let plot = self.load_metric(db, settings, metric, ui.available_width());
            self.plots.push(plot);
        }
        let table_height = ((self.subflows.len() as f32 + 2.0) * 22.0 + 16.0).min(200.0);
        self.show_plots(ui, db, settings, ui.available_height() - table_height);
        ui.separator();
        ScrollArea::vertical()
            .id_salt("mptcp_subflow_table_scroll")
            .max_height(table_height)
            .show(ui, |ui| self.show_subflow_table(ui));
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
        if self.selected.is_empty() {
            ui.allocate_ui(Vec2::new(ui.available_width(), height), |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new("Select metrics in the sidebar.")
                            .color(theme::muted_text(settings.dark_mode)),
                    );
                });
            });
            return;
        }
        // Time 0 is the start of the connection
        let origin = connection.start_ts as f64;
        let (fit_x_min, fit_x_max) = (connection.start_ts as f64, connection.end_ts as f64);
        let fit = std::mem::take(&mut self.needs_fit);
        let width = ui.available_width().max(1.0);
        // Room for the metric name above each plot
        let plot_height = (split_plot_height_with_footer(height, self.selected.len()) - 22.0)
            .max(MIN_PLOT_HEIGHT);
        let marker_color = theme::muted_text(settings.dark_mode);

        let mut visible = None;
        let mut reset = false;
        ScrollArea::vertical()
            .id_salt("mptcp_plots_scroll")
            .max_height(height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (metric, plot) in self.selected.iter().zip(&self.plots) {
                    ui.label(
                        RichText::new(metric_label(metric))
                            .strong()
                            .color(theme::muted_text(settings.dark_mode)),
                    );
                    let response = Plot::new(("mptcp_metric", metric_label(metric)))
                        .allow_boxed_zoom(true)
                        .allow_drag(true)
                        // The wheel scrolls the stack, not the values
                        .allow_scroll([true, false])
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
                                let (y_min, y_max) =
                                    plot.series.iter().fold((0.0_f64, 1.0_f64), |(lo, hi), s| {
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
                            for s in &plot.series {
                                let points: Vec<[f64; 2]> =
                                    s.points.iter().map(|(t, v)| [*t, *v]).collect();
                                plot_ui.line(
                                    Line::new(PlotPoints::from(points))
                                        .color(s.color)
                                        .name(&s.name),
                                );
                            }
                            let bounds = plot_ui.plot_bounds();
                            let marker_y = (bounds.min()[1] + bounds.max()[1]) * 0.5;
                            for (t, label) in &self.events {
                                plot_ui.vline(VLine::new(*t).color(marker_color));
                                plot_ui.text(
                                    Text::new(
                                        PlotPoint::new(*t, marker_y),
                                        vertical_marker_label(label),
                                    )
                                    .anchor(egui::Align2::LEFT_CENTER)
                                    .color(marker_color),
                                );
                            }
                        });
                    reset |= response.response.secondary_clicked();
                    ui.add_space(4.0);
                }
            });
        if reset {
            self.needs_fit = true;
        }

        // Panned or zoomed in: load the visible part of the data in more detail. The plots
        // share the time axis, so one of them gives the visible range of all.
        if let Some((x_min, x_max)) = visible {
            for sd in self.plots.iter_mut().flat_map(|p| p.series.iter_mut()) {
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

    fn show_subflow_table(&self, ui: &mut egui::Ui) {
        let total: f64 = self.subflows.iter().filter_map(Subflow::bytes_acked).sum();
        let origin = self
            .subflows
            .iter()
            .map(|s| s.member.first_ts)
            .min()
            .unwrap_or(0);
        egui::Grid::new("mptcp_subflow_table")
            .striped(true)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                for header in ["Subflow", "Flow", "Seen (s)", "Acked bytes", "Share"] {
                    ui.label(RichText::new(header).strong());
                }
                ui.end_row();
                for sub in &self.subflows {
                    let m = &sub.member;
                    ui.label(m.subflow_id.map_or("-".to_string(), |id| id.to_string()));
                    ui.label(&sub.flow);
                    ui.label(format!(
                        "{:.3} – {:.3}",
                        (m.first_ts - origin) as f64 / 1e9,
                        (m.last_ts - origin) as f64 / 1e9
                    ));
                    match sub.bytes_acked() {
                        Some(bytes) => {
                            ui.label(format!("{bytes:.0}"));
                            if total > 0.0 {
                                ui.label(format!("{:.1} %", 100.0 * bytes / total));
                            } else {
                                ui.label("-");
                            }
                        }
                        None => {
                            ui.label("-");
                            ui.label("-");
                        }
                    }
                    ui.end_row();
                }
            });
    }
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
    fn metric_labels() {
        let key = ("sock".to_string(), Dir::Send, "snd_cwnd".to_string());
        assert_eq!(metric_label(&key), "snd_cwnd · sock · send");
        let key = ("tcp_probe".to_string(), Dir::None, "SRTT".to_string());
        assert_eq!(metric_label(&key), "SRTT · tcp_probe");
    }
}
