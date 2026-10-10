//! MPTCP connections: one connection at a time, one metric of all its subflows in one plot,
//! the path manager events as markers, and a table of the subflows with their share of the
//! acknowledged bytes.

use std::collections::BTreeSet;
use std::net::IpAddr;

use egui::{RichText, ScrollArea};
use egui_plot::{Corner, Legend, Line, Plot, PlotBounds, PlotPoint, PlotPoints, Text, VLine};
use tcbee_common::records::{
    TCBEE_MPTCP_ANNOUNCED, TCBEE_MPTCP_CLOSED, TCBEE_MPTCP_CREATED, TCBEE_MPTCP_ESTABLISHED,
    TCBEE_MPTCP_FALLBACK, TCBEE_MPTCP_LISTENER_CLOSED, TCBEE_MPTCP_LISTENER_CREATED,
    TCBEE_MPTCP_MP_FAIL, TCBEE_MPTCP_MP_PRIO_SENT, TCBEE_MPTCP_PENDING_REQUEUED,
    TCBEE_MPTCP_REINJECTED, TCBEE_MPTCP_REMOVED, TCBEE_MPTCP_SUBFLOW_CONNECT,
    TCBEE_MPTCP_SUBFLOW_STALE, TCBEE_MPTCP_SUB_CLOSED, TCBEE_MPTCP_SUB_ESTABLISHED,
    TCBEE_MPTCP_SUB_PRIORITY, TCBEE_MPTCP_TOKEN_DESTROYED,
};
use ts_storage::{ColType, ConnectionFlow, ConnectionInfo, DataValue, Dir, SeriesInfo, SeriesKind};

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
            plot_height_with_footer, seconds_grid_spacer, seconds_since_formatter,
            time_or_compact_coordinates_formatter, time_or_compact_formatter,
            vertical_marker_label,
        },
        theme,
    },
};

/// Shown when the database has no MPTCP connection
pub const NO_MPTCP_HINT: &str =
    "No MPTCP was recorded in this database. Record with tcbee-record -M to see MPTCP connections.";
/// Plotted first if the subflows have it
const DEFAULT_METRIC: (&str, Dir, &str) = ("sock", Dir::Send, "snd_cwnd");

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

/// The MPTCP connections of the database with their sidebar text
fn connection_rows(db: &DbBackend) -> Vec<ConnectionRow> {
    let mptcp: Vec<&ConnectionInfo> = db
        .list_connections()
        .iter()
        .filter(|c| c.kind == ConnectionInfo::KIND_MPTCP)
        .collect();
    let origin = mptcp.iter().map(|c| c.start_ts).min().unwrap_or(0);
    mptcp
        .into_iter()
        .map(|c| {
            let flows = db
                .list_connection_flows()
                .iter()
                .filter(|m| m.connection_id == c.id)
                .count();
            ConnectionRow {
                info: c.clone(),
                text: format!(
                    "#{}  token {:#010x}  {} flows  {:.2} s, at {:.3} s",
                    c.id,
                    c.key,
                    flows,
                    (c.end_ts - c.start_ts) as f64 / 1e9,
                    (c.start_ts - origin) as f64 / 1e9
                ),
            }
        })
        .collect()
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

/// A connection in the sidebar
struct ConnectionRow {
    info: ConnectionInfo,
    text: String,
}

/// The tab is reset whenever another tab is shown, and the database only changes on the Home
/// tab, so its state always belongs to the open database.
#[derive(Default)]
pub struct TabMptcp {
    /// The MPTCP connections of the database, read when the tab is first shown
    connections: Vec<ConnectionRow>,
    connection: Option<ConnectionInfo>,
    subflows: Vec<Subflow>,
    metrics: Vec<MetricKey>,
    metric: Option<MetricKey>,
    /// One series per subflow that has the metric
    series: Vec<SeriesData>,
    /// Path manager events: (time, label)
    events: Vec<(f64, String)>,
    needs_fit: bool,
}

impl TabMptcp {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn show(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if self.connections.is_empty() {
            self.connections = connection_rows(db);
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
            .min_width(240.0)
            .max_width(500.0)
            .default_width(360.0)
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
        ui.label(RichText::new("MPTCP connections").strong());
        ui.add_space(4.0);
        let mut clicked = None;
        for row in &self.connections {
            let selected = self.connection.as_ref().map(|c| c.id) == Some(row.info.id);
            if ui.selectable_label(selected, &row.text).clicked() {
                clicked = Some(row.info.clone());
            }
        }
        if let Some(connection) = clicked {
            self.select_connection(db, connection);
        }

        if self.connection.is_none() {
            return;
        }
        ui.add_space(12.0);
        ui.label(RichText::new("Metric of every subflow").strong());
        let current = self
            .metric
            .as_ref()
            .map_or_else(|| "none".to_string(), metric_label);
        let mut chosen = None;
        egui::ComboBox::from_id_salt("mptcp_metric")
            .selected_text(current)
            .width(ui.available_width())
            .show_ui(ui, |ui| {
                for m in &self.metrics {
                    if ui
                        .selectable_label(self.metric.as_ref() == Some(m), metric_label(m))
                        .clicked()
                    {
                        chosen = Some(m.clone());
                    }
                }
            });
        if let Some(m) = chosen {
            // Loaded by show_connection, at the width of the plot
            self.metric = Some(m);
            self.series.clear();
            self.needs_fit = true;
        }
    }

    /// Reads the subflows of a connection and their catalogs, the metrics they share and the
    /// path manager events.
    fn select_connection(&mut self, db: &DbBackend, connection: ConnectionInfo) {
        let connection_id = connection.id;
        self.subflows.clear();
        self.events.clear();
        for m in db
            .list_connection_flows()
            .iter()
            .filter(|m| m.connection_id == connection_id)
        {
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
                flow: format_flow(flow),
                series: db.list_series_for_flow(m.flow_id),
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
        self.metric = if self.metrics.contains(&default) {
            Some(default)
        } else {
            self.metrics.first().cloned()
        };
        self.series.clear();
        self.needs_fit = true;

        for sub in &self.subflows {
            self.events.extend(subflow_events(db, sub, &connection));
        }
        self.events.sort_by(|a, b| a.0.total_cmp(&b.0));
        self.connection = Some(connection);
    }

    /// Loads the selected metric of every subflow over the whole connection.
    fn load_metric(&mut self, db: &DbBackend, settings: &AppSettings, width: f32) {
        self.series.clear();
        self.needs_fit = true;
        let Some(metric) = &self.metric else { return };
        let infos: Vec<(&Subflow, &SeriesInfo)> = self
            .subflows
            .iter()
            .filter_map(|s| s.find(metric).map(|info| (s, info)))
            .collect();
        let Some(connection) = &self.connection else {
            return;
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
            return;
        };
        let colors = generate_colors(infos.len());
        for ((sub, info), color) in infos.into_iter().zip(colors) {
            let mut sd = SeriesData::from_info(info, t_min, t_max, color);
            sd.name = sub.label.clone();
            fetch_range(db, &mut sd, t_min, t_max, settings, Some(width));
            self.series.push(sd);
        }
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
        if self.series.is_empty() && self.metric.is_some() && self.needs_fit {
            self.load_metric(db, settings, ui.available_width());
        }
        let table_height = ((self.subflows.len() as f32 + 2.0) * 22.0 + 16.0).min(200.0);
        let plot_height = plot_height_with_footer(ui.available_height() - table_height);
        self.show_plot(ui, db, settings, plot_height);
        ui.separator();
        ScrollArea::vertical()
            .id_salt("mptcp_subflow_table_scroll")
            .max_height(table_height)
            .show(ui, |ui| self.show_subflow_table(ui));
    }

    fn show_plot(
        &mut self,
        ui: &mut egui::Ui,
        db: &DbBackend,
        settings: &AppSettings,
        height: f32,
    ) {
        let origin = self
            .series
            .iter()
            .map(|s| s.global_t_min)
            .fold(f64::INFINITY, f64::min);
        let origin = if origin.is_finite() {
            origin
        } else {
            self.events.first().map_or(0.0, |e| e.0)
        };
        let fit = std::mem::take(&mut self.needs_fit);
        let width = ui.available_width().max(1.0);

        let plot = Plot::new("mptcp_subflows")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .x_grid_spacer(seconds_grid_spacer(origin))
            .x_axis_formatter(seconds_since_formatter(origin))
            .y_axis_formatter(time_or_compact_formatter(origin))
            .coordinates_formatter(
                Corner::LeftBottom,
                time_or_compact_coordinates_formatter(origin),
            )
            .legend(Legend::default())
            .height(height);

        let mut visible = None;
        plot.show(ui, |plot_ui| {
            if fit {
                let (mut x_min, mut x_max) = (f64::MAX, f64::MIN);
                let (mut y_min, mut y_max) = (0.0_f64, 1.0_f64);
                for s in &self.series {
                    x_min = x_min.min(s.global_t_min);
                    x_max = x_max.max(s.global_t_max);
                    y_min = y_min.min(s.global_y_min);
                    y_max = y_max.max(s.global_y_max);
                }
                for (t, _) in &self.events {
                    x_min = x_min.min(*t);
                    x_max = x_max.max(*t);
                }
                if x_min < x_max {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [x_min, y_min * 1.05],
                        [x_max, y_max * 1.05],
                    ));
                }
            } else {
                let bounds = plot_ui.plot_bounds();
                visible = Some((bounds.min()[0], bounds.max()[0]));
            }
            for s in &self.series {
                let points: Vec<[f64; 2]> = s.points.iter().map(|(t, v)| [*t, *v]).collect();
                plot_ui.line(
                    Line::new(PlotPoints::from(points))
                        .color(s.color)
                        .name(&s.name),
                );
            }
            let bounds = plot_ui.plot_bounds();
            let marker_y = (bounds.min()[1] + bounds.max()[1]) * 0.5;
            let color = theme::muted_text(settings.dark_mode);
            for (t, label) in &self.events {
                plot_ui.vline(VLine::new(*t).color(color).name("path manager"));
                plot_ui.text(
                    Text::new(PlotPoint::new(*t, marker_y), vertical_marker_label(label))
                        .anchor(egui::Align2::LEFT_CENTER)
                        .color(color),
                );
            }
        });

        // Panned or zoomed in: load the visible part of the data in more detail
        if let Some((x_min, x_max)) = visible {
            for sd in &mut self.series {
                // The plot may show more than there is data, as the markers widen the fit
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
    fn metric_labels() {
        let key = ("sock".to_string(), Dir::Send, "snd_cwnd".to_string());
        assert_eq!(metric_label(&key), "snd_cwnd · sock · send");
        let key = ("tcp_probe".to_string(), Dir::None, "SRTT".to_string());
        assert_eq!(metric_label(&key), "SRTT · tcp_probe");
    }
}
