//! MPTCP connections: one connection at a time, its path manager events in a lane, the plot
//! groups of the chosen metrics with a line per subflow and lines at the events, and below
//! them a table of the subflows with their bytes and share, and a list of the events.

mod event_list;
mod lane;
mod markers;
mod model;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use egui::{RichText, ScrollArea, Vec2};
use egui_plot::{LineStyle, PlotTransform, PlotUi, VLine};
use tcbee_common::records::{TCBEE_MPTCP_MP_PRIO_SENT, TCBEE_MPTCP_REINJECTED};
use ts_storage::{ColType, ConnectionFlow, ConnectionInfo, DataValue, Dir, SeriesInfo, SeriesKind};

use markers::kind_color;
use model::{
    byte_shares, carries_backup, event_type, format_bytes, infer_sides, is_connection_event,
    sort_subflows, ConnectionSummary, PmEvent, SideInput,
};

use crate::{
    backend::db::{format_flow, DbBackend},
    data::{
        plot_groups::{FlowSlot, PlotGroups, Preset, SeriesKey},
        plot_state::PlotState,
        preprocessing::generate_colors,
        series_styles::SeriesStyles,
    },
    settings::AppSettings,
    ui::{
        flow_table::flow_matches,
        group_editor::{self, SidebarTab},
        grouped_plots,
        series_table::{SeriesAction, SeriesTable},
        sidebar,
        tab_single_flow::{seconds_label_formatter, section_heading},
        table::{
            self, data_cell, header_cell, number_cell, number_header_cell, text_cell,
            text_header_cell, ROW_HEIGHT,
        },
        theme,
    },
};

/// Shown when the database has no MPTCP connection
pub const NO_MPTCP_HINT: &str =
    "No MPTCP was recorded in this database. Record with tcbee-record -m to see MPTCP connections.";
/// Plotted first if the subflows have it
const DEFAULT_METRIC: (&str, Dir, &str) = ("sock", Dir::Send, "snd_cwnd");
/// Salt of the plot ids, see [`grouped_plots::Settings::id`]
const PLOTS_ID: &str = "mptcp";
const MPTCP_PRESETS: &[Preset] = &[Preset::AllTogether, Preset::PerMetric];
// The lines at path manager events in the plots, and at the one picked in the event list.
// Dotted, so that they look like neither grid lines nor the steps of a series.
const EVENT_LINE_WIDTH: f32 = 1.5;
const EVENT_LINE_STYLE: LineStyle = LineStyle::Dotted { spacing: 5.0 };
const SELECTED_EVENT_WIDTH: f32 = 2.5;
const SELECTED_EVENT_STYLE: LineStyle = LineStyle::Dashed { length: 5.0 };
/// Share of the sidebar's height the metric table may take
const METRIC_TABLE_SHARE: f32 = 0.6;
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
                "Backup flag of the subflow's last own event that carries it (established, \
                 priority). An MP_PRIO this host sends is on the connection row; see the event list.",
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

const CONNECTION_EVENTS_HELP: &str = "All path manager records on the subflows' tuples, \
also those of another connection that used a tuple before or after. The event list shows \
this connection's own events.";

/// Rows the subflow panel makes room for at first
const PANEL_MIN_ROWS: usize = 5;
const PANEL_MAX_ROWS: usize = 10;
/// Space above and below the table in the subflow panel
const PANEL_MARGIN: f32 = 8.0;
/// The tabs above the table, with their spacing
const TAB_BAR_HEIGHT: f32 = 28.0;

/// Space between the filter box, its icon and buttons
const FILTER_GAP: f32 = 4.0;
const CONNECTION_FILTER_HELP: &str = "Filter syntax:\n\
Plain text searches the token (hex or decimal), the first subflow, the side and the columns \
and processes of every subflow.\n\
Use column:value to limit a term:\n\
  token:0x3fa1\n\
  side:client\n\
  conn:3\n\
and the flow table's columns, which match if any subflow does:\n\
  src:, dst:, sport:, dport:, port:, id:, proc:, pid:, uid:, cmd:\n\
Combine terms with spaces, e.g. side:server dport:5201";

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

/// The metrics of the subflows for the metric table: one catalog row per metric that a
/// subflow has records of, the first subflow's that has it, in the order they come
fn metric_catalog<'a>(catalogs: impl IntoIterator<Item = &'a [SeriesInfo]>) -> Vec<SeriesInfo> {
    let mut metrics: Vec<SeriesInfo> = Vec::new();
    for info in catalogs.into_iter().flatten() {
        let plotted =
            info.kind == SeriesKind::Raw && info.value_type != ColType::Text && info.n > 0;
        if plotted && info.source != "mptcp_pm" && !metrics.iter().any(|m| same_metric(m, info)) {
            metrics.push(info.clone());
        }
    }
    metrics
}

fn same_metric(a: &SeriesInfo, b: &SeriesInfo) -> bool {
    a.source == b.source && a.dir == b.dir && a.name == b.name
}

/// The key of a metric of every subflow, see [`grouped_plots::Flow`]
fn metric_key(info: &SeriesInfo) -> SeriesKey {
    SeriesKey::from_info(FlowSlot::Single, info)
}

/// The rows of `metrics` whose metric is loaded in one of the subflows of `loaded`
fn selected_metric_ids(metrics: &[SeriesInfo], loaded: &[SeriesKey]) -> Vec<i64> {
    metrics
        .iter()
        .filter(|m| loaded.contains(&metric_key(m)))
        .map(|m| m.id)
        .collect()
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
            subflow_ids: members.iter().map(|m| m.flow_id).collect(),
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
    /// Same in every plot and table
    color: egui::Color32,
    /// Its flow, for the table
    flow: String,
    series: Vec<SeriesInfo>,
    /// Its loaded metrics, limited to the connection's time
    state: PlotState,
    /// Before its series names in the legends
    prefix: String,
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
    /// Its catalog row of `key`
    fn find(&self, key: &SeriesKey) -> Option<&SeriesInfo> {
        self.series.iter().find(|s| metric_key(s) == *key)
    }

    /// The keys of its loaded metrics
    fn loaded(&self) -> impl Iterator<Item = SeriesKey> + '_ {
        self.state
            .series
            .iter()
            .map(|s| SeriesKey::of(FlowSlot::Single, s))
    }

    /// The last value of a socket counter: its catalog maximum
    fn counter(&self, name: &str) -> Option<f64> {
        catalog_max(&self.series, "sock", name)
    }
}

/// The tables below the plots
#[derive(Clone, Copy, Default, PartialEq)]
enum BottomTab {
    #[default]
    Subflows,
    Events,
}

/// The tab is reset whenever another tab is shown, and the database only changes on the Home
/// tab, so its state always belongs to the open database.
pub struct TabMptcp {
    /// The MPTCP connections of the database, read when the tab is first shown
    connections: Vec<ConnectionSummary>,
    connections_read: bool,
    connection_filter: String,
    /// The connection table is shown below the picked connection
    choosing_connection: bool,
    /// Series catalog of each subflow, read once
    catalogs: HashMap<i64, Vec<SeriesInfo>>,
    connection: Option<ConnectionInfo>,
    subflows: Vec<Subflow>,
    /// The metrics that at least one subflow has, see [`metric_catalog`]
    metrics: Vec<SeriesInfo>,
    series_table: SeriesTable,
    /// Which metrics share a plot
    groups: PlotGroups,
    /// Line widths picked in the View tab; the colours are the subflows'
    styles: SeriesStyles,
    sidebar_tab: SidebarTab,
    /// Grid lines in the plots, set in the View tab
    show_grid: bool,
    /// The time range the plots showed in the last frame
    shown_x: Option<(f64, f64)>,
    /// Path manager events, in time order; shared with the lane's hover label
    events: Arc<[PmEvent]>,
    /// The event types among them: code and whether failed
    event_keys: Vec<(i64, bool)>,
    /// Time per screen pixel of the lane in the last frame, for grouping close events
    lane_ns_per_px: f64,
    /// What the panel below the plots shows
    bottom_tab: BottomTab,
    event_filter: String,
    /// Index into `events` of the event picked in the event list
    selected_event: Option<usize>,
    /// Time to move the view to, once
    focus: Option<f64>,
    needs_fit: bool,
}

impl Default for TabMptcp {
    fn default() -> Self {
        let mut groups = PlotGroups::default();
        // One plot per metric, the subflows together
        groups.apply_preset(Preset::PerMetric, &[]);
        Self {
            connections: Vec::new(),
            connections_read: false,
            connection_filter: String::new(),
            choosing_connection: false,
            catalogs: HashMap::new(),
            connection: None,
            subflows: Vec::new(),
            metrics: Vec::new(),
            series_table: SeriesTable::default(),
            groups,
            styles: SeriesStyles::default(),
            sidebar_tab: SidebarTab::default(),
            show_grid: true,
            shown_x: None,
            events: Arc::default(),
            event_keys: Vec::new(),
            lane_ns_per_px: 0.0,
            bottom_tab: BottomTab::default(),
            event_filter: String::new(),
            selected_event: None,
            focus: None,
            needs_fit: false,
        }
    }
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
                self.select_connection(db, settings, first);
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
                let sidebar_height = ui.available_height();
                ScrollArea::vertical()
                    .id_salt("mptcp_sidebar_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin::symmetric(SIDEBAR_MARGIN, 8))
                            .show(ui, |ui| self.show_sidebar(ui, db, settings, sidebar_height));
                    });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::panel_bg(settings.dark_mode)))
            .show_inside(ui, |ui| {
                ui.add_space(4.0);
                self.show_connection(ui, db, settings);
            });
    }

    fn show_sidebar(
        &mut self,
        ui: &mut egui::Ui,
        db: &DbBackend,
        settings: &AppSettings,
        sidebar_height: f32,
    ) {
        group_editor::tab_strip(ui, &mut self.sidebar_tab);
        if self.sidebar_tab == SidebarTab::View {
            let selected = self.selected_colors();
            if group_editor::show(
                ui,
                "mptcp_groups",
                (&mut self.groups, &mut self.styles),
                &mut self.show_grid,
                grouped_plots::plot_stack_id(PLOTS_ID),
                &selected,
                MPTCP_PRESETS,
                // A line's colour is its subflow's
                false,
            ) {
                self.needs_fit = true;
            }
            return;
        }

        section_heading(ui, "Connection");
        if let Some(row) = self
            .connection
            .as_ref()
            .and_then(|c| self.connections.iter().find(|r| r.id == c.id))
        {
            let side = row
                .side
                .map_or(String::new(), |s| format!(" · {}", s.label()));
            let title = format!("{}{side}", row.token_text());
            let detail = format!("{} · {} subflows", row.first_subflow, row.subflows);
            if sidebar::picker_card(ui, &title, &detail, self.choosing_connection) {
                self.choosing_connection = !self.choosing_connection;
            }
            ui.add_space(4.0);
        }
        if self.connection.is_none() || self.choosing_connection {
            if let Some(id) = self.show_connection_table(ui, db) {
                self.choosing_connection = false;
                self.select_connection(db, settings, id);
            }
        }

        if self.connection.is_none() {
            return;
        }
        ui.add_space(12.0);
        section_heading(ui, "Metrics of every subflow");
        let loaded = self.loaded_keys();
        let selected_ids = selected_metric_ids(&self.metrics, &loaded);
        // A metric has a line per subflow: no single colour to show
        let muted = theme::muted_text(settings.dark_mode);
        let colors: Vec<(i64, egui::Color32)> =
            selected_ids.iter().map(|&id| (id, muted)).collect();
        let mut action = None;
        egui::Frame::NONE.show(ui, |ui| {
            ui.set_max_height((sidebar_height * METRIC_TABLE_SHARE).max(160.0));
            action = self.series_table.show_with_id_salt(
                ui,
                &self.metrics,
                &selected_ids,
                &colors,
                "mptcp_series_table",
            );
        });
        if let Some(action) = action {
            self.apply_metric_action(db, settings, action);
        }
    }

    /// The metrics loaded in any subflow, each once
    fn loaded_keys(&self) -> Vec<SeriesKey> {
        self.selected_colors().into_iter().map(|(k, _)| k).collect()
    }

    /// The loaded metrics with a colour for the View tab: the first subflow's that has it
    fn selected_colors(&self) -> Vec<(SeriesKey, egui::Color32)> {
        let mut selected: Vec<(SeriesKey, egui::Color32)> = Vec::new();
        for sub in &self.subflows {
            for key in sub.loaded() {
                if !selected.iter().any(|(k, _)| *k == key) {
                    selected.push((key, sub.color));
                }
            }
        }
        selected
    }

    /// Selects or deselects the metrics of the rows of `action` in every subflow that has
    /// them. A row toggles on if no subflow has its metric loaded.
    fn apply_metric_action(
        &mut self,
        db: &DbBackend,
        settings: &AppSettings,
        action: SeriesAction,
    ) {
        let keys_of = |ids: &[i64]| -> Vec<SeriesKey> {
            self.metrics
                .iter()
                .filter(|m| ids.contains(&m.id))
                .map(metric_key)
                .collect()
        };
        let (keys, on) = match action {
            SeriesAction::Toggle(id) => {
                let keys = keys_of(&[id]);
                let on = !keys.iter().any(|k| self.loaded_keys().contains(k));
                (keys, on)
            }
            SeriesAction::Select(ids) => (keys_of(&ids), true),
            SeriesAction::Deselect(ids) => (keys_of(&ids), false),
        };
        self.set_metrics(db, settings, &keys, on);
        self.needs_fit = true;
    }

    /// Loads or drops `keys` in every subflow that has them
    fn set_metrics(
        &mut self,
        db: &DbBackend,
        settings: &AppSettings,
        keys: &[SeriesKey],
        on: bool,
    ) {
        for sub in &mut self.subflows {
            let ids: Vec<i64> = keys
                .iter()
                .filter_map(|k| sub.find(k))
                .map(|info| info.id)
                .collect();
            if on {
                sub.state.select_series(db, &ids, settings);
            } else {
                sub.state.deselect_series(&ids);
            }
        }
    }

    /// The filterable connection table. Returns the id of a newly clicked connection.
    fn show_connection_table(&mut self, ui: &mut egui::Ui, db: &DbBackend) -> Option<i64> {
        let dark_mode = ui.visuals().dark_mode;
        let selected_id = self.connection.as_ref().map(|c| c.id);
        let mut clicked = None;
        table::frame(dark_mode).show(ui, |ui| {
            let content_w = ui.available_width().max(1.0);
            ui.spacing_mut().item_spacing.x = 0.0;
            table::filter_bar(
                ui,
                &mut self.connection_filter,
                "Filter, e.g. side:server dport:5201",
                Some(CONNECTION_FILTER_HELP),
                content_w,
                FILTER_GAP,
            );
            let filter = self.connection_filter.to_lowercase();
            let visible: Vec<&ConnectionSummary> = self
                .connections
                .iter()
                .filter(|c| {
                    c.matches(&filter, |term| {
                        c.subflow_ids
                            .iter()
                            .filter_map(|&id| db.get_flow_by_id(id))
                            .any(|f| {
                                flow_matches(
                                    f,
                                    db.connection_label(f.id),
                                    db.flow_owners(f.id),
                                    term,
                                )
                            })
                    })
                })
                .collect();
            let fixed = COL_TOKEN + COL_SIDE + COL_SUBFLOWS + COL_EVENTS + COL_DURATION;
            let col_flow = (content_w - fixed).max(COL_FIRST_SUBFLOW_MIN);

            table::header_row(ui, content_w, |ui| {
                header_cell(ui, "Token", COL_TOKEN);
                header_cell(ui, "First subflow", col_flow);
                header_cell(ui, "Side", COL_SIDE);
                number_header_cell(ui, "Sf", COL_SUBFLOWS).on_hover_text("Subflows");
                number_header_cell(ui, "Events", COL_EVENTS).on_hover_text(CONNECTION_EVENTS_HELP);
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
                        // Clicking the picked one again only hides the table
                        if click.clicked() {
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
    fn select_connection(&mut self, db: &DbBackend, settings: &AppSettings, connection_id: i64) {
        if self
            .connection
            .as_ref()
            .is_some_and(|c| c.id == connection_id)
        {
            return;
        }
        let Some(connection) = db
            .list_connections()
            .iter()
            .find(|c| c.id == connection_id)
            .cloned()
        else {
            return;
        };
        // Keep the plotted metrics when switching connections, as far as the new one has them
        let mut keep = self.loaded_keys();
        self.subflows.clear();
        self.events = Arc::default();
        // The picked event belonged to the old connection
        self.selected_event = None;
        self.focus = None;
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
            let label = format!("{label} ({}:{})", flow.tuple.src, flow.tuple.sport);
            let mut state = PlotState::default();
            state.select_flow(db, m.flow_id);
            // A flow tuple may also belong to other connections: only this one's time span
            state.data_x_min = state.data_x_min.max(connection.start_ts as f64);
            state.data_x_max = state.data_x_max.min(connection.end_ts as f64);
            if state.data_x_min > state.data_x_max {
                (state.data_x_min, state.data_x_max) =
                    (connection.start_ts as f64, connection.end_ts as f64);
            }
            (state.x_min, state.x_max) = (state.data_x_min, state.data_x_max);
            self.subflows.push(Subflow {
                member: m.clone(),
                prefix: format!("{label}: "),
                color,
                flow: format_flow(flow),
                series: self
                    .catalogs
                    .entry(m.flow_id)
                    .or_insert_with(|| db.list_series_for_flow(m.flow_id))
                    .clone(),
                state,
                acked: None,
                received: None,
                share: None,
                backup: None,
                events: 0,
                hidden: false,
            });
        }

        self.metrics = metric_catalog(self.subflows.iter().map(|s| s.series.as_slice()));
        let has = |k: &SeriesKey| self.metrics.iter().any(|m| metric_key(m) == *k);
        keep.retain(|k| has(k));
        if keep.is_empty() {
            let (source, dir, name) = DEFAULT_METRIC;
            keep = self
                .metrics
                .iter()
                .find(|m| m.source == source && m.dir == dir && m.name == name)
                .or(self.metrics.first())
                .map(metric_key)
                .into_iter()
                .collect();
        }
        self.set_metrics(db, settings, &keep, true);
        self.shown_x = None;
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
        // The panel takes its space first, the plots get the rest. Its height is chosen once;
        // after that it keeps what the user resized it to.
        let rows = self.subflows.len().clamp(PANEL_MIN_ROWS, PANEL_MAX_ROWS);
        egui::TopBottomPanel::bottom("mptcp_subflow_panel")
            .resizable(true)
            .default_height(table::table_height(rows) + 2.0 * PANEL_MARGIN + TAB_BAR_HEIGHT)
            .height_range(60.0..=600.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::panel_bg(settings.dark_mode))
                    .inner_margin(egui::Margin::symmetric(0, PANEL_MARGIN as i8)),
            )
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    let subflows = format!("Subflows ({})", self.subflows.len());
                    let events = format!("Events ({})", self.events.len());
                    ui.selectable_value(&mut self.bottom_tab, BottomTab::Subflows, subflows);
                    ui.selectable_value(&mut self.bottom_tab, BottomTab::Events, events);
                });
                ui.add_space(4.0);
                match self.bottom_tab {
                    BottomTab::Subflows => {
                        if let Some(index) = self.show_subflow_table(ui) {
                            self.toggle_hidden(db, settings, index);
                        }
                    }
                    BottomTab::Events => self.show_event_table(ui),
                }
            });
        self.show_plots(ui, db, settings);
    }

    /// Shows or hides a subflow in the plots. A hidden one is not reloaded while the view
    /// moves, so it catches up when shown again.
    fn toggle_hidden(&mut self, db: &DbBackend, settings: &AppSettings, index: usize) {
        let shown_x = self.shown_x;
        let sub = &mut self.subflows[index];
        sub.hidden = !sub.hidden;
        if let (false, Some((x_min, x_max))) = (sub.hidden, shown_x) {
            (sub.state.x_min, sub.state.x_max) = (x_min, x_max);
            sub.state.reload_visible_data(db, settings, None);
        }
    }

    /// Hover text of a metric plot: the value under the pointer, and the events of `marked`
    /// (time, text) whose lines are within `tol` of it
    fn plot_label_formatter(
        origin: f64,
        tol: f64,
        marked: Arc<[(f64, String)]>,
    ) -> impl Fn(&str, &egui_plot::PlotPoint) -> String + 'static {
        let value = seconds_label_formatter(origin);
        move |name, point| {
            let mut text = value(name, point);
            for (_, label) in marked.iter().filter(|(t, _)| (t - point.x).abs() <= tol) {
                text.push_str(&format!("\n{label}"));
            }
            text
        }
    }

    /// Whether an event gets a line in the metric plots: not data moves, which can be many,
    /// and not events of hidden subflows
    fn marks_plots(&self, e: &PmEvent) -> bool {
        !e.moves_data() && !self.is_hidden_row(e.row)
    }

    /// Whether a lane row belongs to a subflow hidden in the plots
    fn is_hidden_row(&self, row: usize) -> bool {
        row > 0 && self.subflows.get(row - 1).is_some_and(|s| s.hidden)
    }

    /// The plot groups of the selected metrics, a line per visible subflow, below the event
    /// lane and with lines at its events
    fn show_plots(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let Some(connection) = &self.connection else {
            return;
        };
        // Time 0 is the start of the connection
        let origin = connection.start_ts as f64;
        let data_x = (connection.start_ts as f64, connection.end_ts as f64);
        let fit = std::mem::take(&mut self.needs_fit);
        let width = ui.available_width().max(1.0);
        for sub in &mut self.subflows {
            sub.state.reload_if_sampling_changed(db, settings, width);
            // Line widths from the View tab; a line's colour stays its subflow's, as in the
            // tables and the lane
            self.styles.apply(FlowSlot::Single, &mut sub.state.series);
            for sd in &mut sub.state.series {
                sd.color = sub.color;
            }
        }
        let selected: Vec<SeriesKey> = self.loaded_keys();
        self.groups.sync(&selected);
        let groups = self.groups.resolve(&selected);

        let lane = self.show_event_lane(ui, settings, fit, origin);
        if selected.is_empty() || groups.is_empty() {
            if selected.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new("Select metrics in the sidebar.")
                            .color(theme::muted_text(settings.dark_mode)),
                    );
                });
            } else {
                grouped_plots::all_hidden(ui);
            }
            self.needs_fit |= lane.reset;
            return;
        }

        let dark_mode = settings.dark_mode;
        let marking: Vec<&PmEvent> = self.events.iter().filter(|e| self.marks_plots(e)).collect();
        let event_lines: Vec<(f64, egui::Color32)> = marking
            .iter()
            .map(|e| (e.t, kind_color(e.kind(), dark_mode)))
            .collect();
        let selected_time = self
            .selected_event
            .and_then(|i| self.events.get(i))
            .filter(|e| !self.is_hidden_row(e.row))
            .map(|e| e.t);
        // The events with a line, for the hover text of every plot
        let marked: Arc<[(f64, String)]> = marking.iter().map(|e| (e.t, e.label.clone())).collect();
        let draw_events = |plot_ui: &mut PlotUi, _: usize| {
            if let Some(t) = selected_time {
                plot_ui.vline(
                    VLine::new(t)
                        .color(theme::text(dark_mode))
                        .width(SELECTED_EVENT_WIDTH)
                        .style(SELECTED_EVENT_STYLE),
                );
            }
            for &(t, color) in &event_lines {
                plot_ui.vline(
                    VLine::new(t)
                        .color(color)
                        .width(EVENT_LINE_WIDTH)
                        .style(EVENT_LINE_STYLE),
                );
            }
        };
        // The top plot names the lines
        let paint_labels = |ui: &egui::Ui, transform: &PlotTransform, index: usize| {
            if index == 0 {
                self.paint_plot_labels(ui, transform, &lane.groups, dark_mode);
            }
        };
        let hover = Self::plot_label_formatter(origin, lane.tol, marked);

        // Hidden subflows are left out; `shown[i]` is the subflow of flow i
        let shown: Vec<usize> = (0..self.subflows.len())
            .filter(|&i| !self.subflows[i].hidden)
            .collect();
        let flows: Vec<grouped_plots::Flow> = shown
            .iter()
            .map(|&i| grouped_plots::Flow {
                slot: FlowSlot::Single,
                state: &self.subflows[i].state,
                prefix: &self.subflows[i].prefix,
            })
            .collect();
        let plot_settings = grouped_plots::Settings {
            id: PLOTS_ID,
            x_origin: origin,
            data_x,
            fit,
            set_x: None,
            remove_outliers: false,
            show_gaps: false,
            show_grid: self.show_grid,
            hooks: grouped_plots::Hooks {
                draw: Some(&draw_events),
                paint: Some(&paint_labels),
                label: Some(&hover),
                link_cursor: true,
                // The wheel scrolls the stack, not the values
                scroll_y: false,
                double_click_reset: false,
                split_at_gaps: true,
            },
        };
        let outcome = grouped_plots::show(ui, &groups, &flows, &plot_settings);
        drop(flows);

        if outcome.right_clicked || lane.reset {
            self.needs_fit = true;
        }
        self.shown_x = outcome.x().or(self.shown_x);
        // Panned or zoomed in: load the visible part in more detail
        for (&index, reload) in shown.iter().zip(&outcome.reload) {
            if let Some((x_min, x_max)) = *reload {
                let state = &mut self.subflows[index].state;
                (state.x_min, state.x_max) = (x_min, x_max);
                state.reload_visible_data(db, settings, Some(width));
            }
        }
    }

    /// The subflows with their bytes and counters. Returns the index of a clicked row, which
    /// shows or hides the subflow in the plots.
    fn show_subflow_table(&self, ui: &mut egui::Ui) -> Option<usize> {
        let dark_mode = ui.visuals().dark_mode;
        let min_width =
            SubflowColumn::fixed_width() + SubflowColumn::MIN_FLOW_WIDTH + table::FRAME_BORDER;
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

    fn info(id: i64, source: &str, dir: Dir, name: &str, n: i64) -> SeriesInfo {
        SeriesInfo {
            id,
            flow_id: id / 10,
            kind: SeriesKind::Raw,
            source: source.into(),
            dir,
            name: name.into(),
            value_type: ColType::I64,
            tbl: None,
            col: None,
            n,
            t_min: Some(0),
            t_max: Some(1),
            v_min: Some(0.0),
            v_max: Some(1.0),
        }
    }

    #[test]
    fn metrics_of_all_subflows_once() {
        // Subflow 1 lacks srtt and has no cwnd records; subflow 2 has both
        let first = [
            info(10, "sock", Dir::Send, "snd_cwnd", 0),
            info(11, "mptcp_pm", Dir::None, "event", 4),
        ];
        let mut text = info(22, "sock", Dir::None, "state", 3);
        text.value_type = ColType::Text;
        let second = [
            info(20, "sock", Dir::Send, "snd_cwnd", 5),
            info(21, "sock", Dir::Send, "srtt", 5),
            text,
        ];
        let third = [info(30, "sock", Dir::Send, "srtt", 5)];
        let metrics = metric_catalog([&first[..], &second[..], &third[..]]);
        let ids: Vec<i64> = metrics.iter().map(|m| m.id).collect();
        assert_eq!(ids, [20, 21]);

        // A metric counts as selected while any subflow has it loaded
        let loaded = [metric_key(&third[0])];
        assert_eq!(selected_metric_ids(&metrics, &loaded), [21]);
        assert!(selected_metric_ids(&metrics, &[]).is_empty());
    }
}
