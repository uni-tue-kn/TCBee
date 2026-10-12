use std::collections::HashMap;

use egui::{RichText, Ui};
use ts_storage::Flow;

use crate::{
    backend::db::DbBackend,
    ui::{
        table::{self, data_cell, header_cell, ROW_HEIGHT},
        theme,
    },
};

const COL_ID: f32 = 36.0;
const COL_PORT: f32 = 54.0;
const COL_SERIES: f32 = 54.0;
const COL_POINTS: f32 = 72.0;
const COL_CONN: f32 = 54.0;
const FILTER_GAP: f32 = 20.0;
const FILTER_HELP: &str = "Filter syntax:\n\
Plain text searches all flow columns.\n\
Use column:value to limit a term:\n\
  id:52\n\
  src:10.0.0.1\n\
  dst:192.168\n\
  sport:443\n\
  dport:5201\n\
  port:443\n\
  conn:3 (flows of MPTCP connection 3)\n\
Combine terms with spaces, e.g. src:10.0.0.1 dport:443";

/// A filterable table widget for selecting a TCP flow.
#[derive(Default)]
pub struct FlowTable {
    pub filter: String,
    pub selected_id: Option<i64>,
    stats_cache: HashMap<i64, FlowStats>,
}

#[derive(Clone, Copy, Debug, Default)]
struct FlowStats {
    series_count: usize,
    point_count: i64,
}

impl FlowTable {
    pub fn reset(&mut self) {
        self.filter.clear();
        self.selected_id = None;
        self.stats_cache.clear();
    }

    pub fn clear_stats_cache(&mut self) {
        self.stats_cache.clear();
    }

    /// Render the table. Returns `Some(flow_id)` when a new row is clicked.
    pub fn show(&mut self, ui: &mut Ui, db: &DbBackend, flows: &[Flow]) -> Option<i64> {
        self.show_with_id_salt(ui, db, flows, "flow_table")
    }

    /// Render the table with a caller-provided ID salt for repeated table instances.
    pub fn show_with_id_salt(
        &mut self,
        ui: &mut Ui,
        db: &DbBackend,
        flows: &[Flow],
        id_salt: &'static str,
    ) -> Option<i64> {
        let mut new_selection: Option<i64> = None;
        let dark_mode = ui.visuals().dark_mode;

        table::frame(dark_mode).show(ui, |ui| {
            // All width measurements are taken inside the frame so the
            // 1 px stroke on each side is already excluded.
            let content_w = ui.available_width().max(1.0);
            ui.spacing_mut().item_spacing.x = 0.0;

            // ── Filter bar ──────────────────────────────────────────────────
            table::filter_bar(
                ui,
                &mut self.filter,
                "Filter, e.g. id:52 src:10.0.0.1",
                Some(FILTER_HELP),
                content_w * 0.9,
                FILTER_GAP,
            );

            let filter_lower = self.filter.to_lowercase();
            // The connection column only appears for recordings with connections
            let show_conn = !db.list_connections().is_empty();
            let visible: Vec<(&Flow, &str)> = flows
                .iter()
                .map(|f| (f, db.connection_label(f.id)))
                .filter(|(f, conn)| flow_matches(f, conn, &filter_lower))
                .collect();

            ui.separator();

            if visible.is_empty() {
                ui.add_space(4.0);
                ui.label(
                    RichText::new("No flows match the filter.")
                        .color(theme::muted_text(dark_mode))
                        .italics(),
                );
                ui.add_space(4.0);
                return;
            }

            // ── Header ────────────────────────────────────────────────────────
            let conn_w = if show_conn { COL_CONN } else { 0.0 };
            let fixed_w = COL_ID + COL_PORT + COL_PORT + COL_SERIES + COL_POINTS + conn_w;
            let col_ip = ((content_w - fixed_w) / 2.0).max(40.0);

            table::header_row(ui, content_w, |ui| {
                header_cell(ui, "ID", COL_ID);
                header_cell(ui, "Src IP", col_ip);
                header_cell(ui, "Sport", COL_PORT);
                header_cell(ui, "Dst IP", col_ip);
                header_cell(ui, "Dport", COL_PORT);
                if show_conn {
                    header_cell(ui, "Conn", COL_CONN).on_hover_text("MPTCP connection/subflow");
                }
                header_cell(ui, "Series", COL_SERIES);
                header_cell(ui, "Points", COL_POINTS);
            });

            ui.separator();

            // ── Rows ──────────────────────────────────────────────────────────
            let row_count = visible.len();
            egui::ScrollArea::vertical()
                .id_salt((id_salt, "scroll"))
                .auto_shrink([false, false])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                .show_rows(ui, ROW_HEIGHT, row_count, |ui, range| {
                    ui.set_width(content_w);
                    for i in range {
                        let (flow, conn) = &visible[i];
                        let fid = flow.id;
                        let is_selected = self.selected_id == Some(fid);
                        let stats = *self
                            .stats_cache
                            .entry(fid)
                            .or_insert_with(|| flow_stats(db, flow));

                        let row_response = ui.horizontal(|ui| {
                            ui.set_width(content_w);
                            ui.set_height(ROW_HEIGHT);

                            let rect = ui.max_rect();
                            let hovered = ui.rect_contains_pointer(rect);
                            let bg = table::row_fill(dark_mode, i, is_selected, hovered);
                            ui.painter().rect_filled(rect, 0.0, bg);

                            data_cell(ui, &fid.to_string(), COL_ID, is_selected);
                            data_cell(ui, &flow.tuple.src.to_string(), col_ip, is_selected);
                            data_cell(ui, &flow.tuple.sport.to_string(), COL_PORT, is_selected);
                            data_cell(ui, &flow.tuple.dst.to_string(), col_ip, is_selected);
                            data_cell(ui, &flow.tuple.dport.to_string(), COL_PORT, is_selected);
                            if show_conn {
                                data_cell(ui, conn, COL_CONN, is_selected);
                            }
                            data_cell(ui, &stats.series_count.to_string(), COL_SERIES, is_selected);
                            data_cell(
                                ui,
                                &format_count(stats.point_count),
                                COL_POINTS,
                                is_selected,
                            );
                        });

                        // Make the whole row clickable
                        let row_rect = row_response.response.rect;
                        let row_click =
                            table::row_click(ui, row_rect, ui.id().with((id_salt, "row", fid)));
                        if row_click.clicked() && !is_selected {
                            self.selected_id = Some(fid);
                            new_selection = Some(fid);
                        }

                        table::row_divider(ui, row_response.response.rect);
                    }
                });
        });

        new_selection
    }
}

fn flow_stats(db: &DbBackend, flow: &Flow) -> FlowStats {
    // Catalog rows carry the point counts.
    let series = db.list_series_for_flow(flow.id);
    let point_count = series.iter().map(|series| series.n).sum();
    FlowStats {
        series_count: series.len(),
        point_count,
    }
}

/// `conn` is the flow's connection label, see `DbBackend::connection_label`
fn flow_matches(flow: &Flow, conn: &str, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }

    if filter.split_whitespace().count() > 1 {
        return filter
            .split_whitespace()
            .all(|term| flow_matches(flow, conn, term));
    }

    if let Some((column, value)) = filter.split_once(':') {
        if column == "conn" {
            return value.is_empty()
                || conn.split(", ").any(|c| c.split('/').next() == Some(value));
        }
        return flow_column_matches(flow, column, value);
    }

    let src = flow.tuple.src.to_string().to_lowercase();
    let dst = flow.tuple.dst.to_string().to_lowercase();
    let sport = flow.tuple.sport.to_string();
    let dport = flow.tuple.dport.to_string();
    let id = flow.id.to_string();
    src.contains(filter)
        || dst.contains(filter)
        || sport.contains(filter)
        || dport.contains(filter)
        || id.contains(filter)
}

fn flow_column_matches(flow: &Flow, column: &str, value: &str) -> bool {
    if value.is_empty() {
        return true;
    }

    match column {
        "id" => flow.id.to_string().contains(value),
        "src" | "srcip" | "source" => flow.tuple.src.to_string().to_lowercase().contains(value),
        "dst" | "dstip" | "dest" | "destination" => {
            flow.tuple.dst.to_string().to_lowercase().contains(value)
        }
        "sport" | "srcport" => flow.tuple.sport.to_string().contains(value),
        "dport" | "dstport" => flow.tuple.dport.to_string().contains(value),
        "port" => {
            flow.tuple.sport.to_string().contains(value)
                || flow.tuple.dport.to_string().contains(value)
        }
        _ => false,
    }
}

fn format_count(count: i64) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}k", count as f64 / 1_000.0)
    } else {
        count.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ts_storage::IpTuple;

    use super::*;

    fn flow() -> Flow {
        let ip = |last| IpAddr::V4(Ipv4Addr::new(10, 0, 0, last));
        Flow::new(
            12,
            IpTuple {
                src: ip(1),
                dst: ip(2),
                sport: 40000,
                dport: 5201,
                l4proto: 6,
            },
        )
    }

    #[test]
    fn conn_filter_matches_the_connection_id() {
        let f = flow();
        assert!(flow_matches(&f, "3/2", "conn:3"));
        assert!(flow_matches(&f, "1, 3", "conn:3"));
        assert!(!flow_matches(&f, "13/1", "conn:3"));
        assert!(!flow_matches(&f, "", "conn:3"));
        assert!(flow_matches(&f, "3/2", "conn:3 dport:5201"));
        assert!(flow_matches(&f, "", "dport:5201"));
    }
}
