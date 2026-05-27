use std::collections::HashMap;

use egui::{Color32, RichText, Stroke, Ui, Vec2};
use ts_storage::Flow;

use crate::{backend::db::DbBackend, ui::theme};

const COL_ID: f32 = 36.0;
const COL_PORT: f32 = 54.0;
const COL_SERIES: f32 = 54.0;
const COL_POINTS: f32 = 72.0;
const ROW_HEIGHT: f32 = 22.0;
const SEARCH_ICON_W: f32 = 18.0;
const CLEAR_BUTTON_W: f32 = 22.0;
const HELP_BUTTON_W: f32 = 20.0;
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
Combine terms with spaces, e.g. src:10.0.0.1 dport:443";

/// A filterable table widget for selecting a TCP flow.
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

impl Default for FlowTable {
    fn default() -> Self {
        Self {
            filter: String::new(),
            selected_id: None,
            stats_cache: HashMap::new(),
        }
    }
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

        egui::Frame::new()
            .fill(theme::panel_bg(dark_mode))
            .stroke(Stroke::new(1.0, theme::border(dark_mode)))
            .corner_radius(6.0)
            .inner_margin(egui::Margin::ZERO)
            .show(ui, |ui| {
                // All width measurements are taken inside the frame so the
                // 1 px stroke on each side is already excluded.
                let content_w = ui.available_width().max(1.0);
                ui.spacing_mut().item_spacing.x = 0.0;

                // ── Filter bar ──────────────────────────────────────────────────
                // Use content_w - 2 so the framed clear button's 1px stroke never
                // overflows the table frame boundary.
                let filter_w = content_w * 0.9;
                ui.allocate_ui_with_layout(
                    Vec2::new(filter_w, ROW_HEIGHT),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.spacing_mut().item_spacing.x = FILTER_GAP;
                        ui.add_sized([SEARCH_ICON_W, ROW_HEIGHT], egui::Label::new("🔍"));
                        let text_w = (filter_w
                            - SEARCH_ICON_W
                            - HELP_BUTTON_W
                            - CLEAR_BUTTON_W
                            - 3.0 * FILTER_GAP)
                            .max(40.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.filter)
                                .hint_text("Filter, e.g. id:52 src:10.0.0.1")
                                .desired_width(text_w)
                                .min_size(Vec2::new(text_w, ROW_HEIGHT)),
                        );
                        ui.add_sized(
                            [HELP_BUTTON_W, ROW_HEIGHT],
                            egui::Label::new(RichText::new("?").strong())
                                .sense(egui::Sense::hover()),
                        )
                        .on_hover_text(FILTER_HELP);
                        let clear = ui.add_sized(
                            [CLEAR_BUTTON_W, ROW_HEIGHT],
                            egui::Button::new("x").frame(!self.filter.is_empty()),
                        );
                        if !self.filter.is_empty() && clear.clicked() {
                            self.filter.clear();
                        }
                    },
                );

                let filter_lower = self.filter.to_lowercase();
                let visible: Vec<&Flow> = flows
                    .iter()
                    .filter(|f| flow_matches(f, &filter_lower))
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
                let fixed_w = COL_ID + COL_PORT + COL_PORT + COL_SERIES + COL_POINTS;
                let col_ip = ((content_w - fixed_w) / 2.0).max(40.0);

                let header_rect = egui::Rect::from_min_size(
                    ui.available_rect_before_wrap().min,
                    Vec2::new(content_w, ROW_HEIGHT),
                );
                ui.painter()
                    .rect_filled(header_rect, 0.0, theme::table_header_bg(dark_mode));

                ui.horizontal(|ui| {
                    ui.set_height(ROW_HEIGHT);
                    header_cell(ui, "ID", COL_ID);
                    header_cell(ui, "Src IP", col_ip);
                    header_cell(ui, "Sport", COL_PORT);
                    header_cell(ui, "Dst IP", col_ip);
                    header_cell(ui, "Dport", COL_PORT);
                    header_cell(ui, "Series", COL_SERIES);
                    header_cell(ui, "Points", COL_POINTS);
                });

                ui.separator();

                // ── Rows ──────────────────────────────────────────────────────────
                let row_count = visible.len();
                egui::ScrollArea::vertical()
                    .id_salt((id_salt, "scroll"))
                    .auto_shrink([false, false])
                    .scroll_bar_visibility(
                        egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded,
                    )
                    .show_rows(ui, ROW_HEIGHT, row_count, |ui, range| {
                        ui.set_width(content_w);
                        for i in range {
                            let flow = visible[i];
                            let fid = flow.id;
                            let is_selected = self.selected_id == Some(fid);
                            let stats = *self
                                .stats_cache
                                .entry(fid)
                                .or_insert_with(|| flow_stats(db, flow));

                            let base_color = if is_selected {
                                theme::table_row_selected(dark_mode)
                            } else if i % 2 == 0 {
                                theme::table_row_even(dark_mode)
                            } else {
                                theme::table_row_odd(dark_mode)
                            };

                            let row_response = ui.horizontal(|ui| {
                                ui.set_width(content_w);
                                ui.set_height(ROW_HEIGHT);

                                let rect = ui.max_rect();
                                let hovered = ui.rect_contains_pointer(rect);
                                let bg = if is_selected {
                                    if hovered {
                                        theme::table_row_selected_hover(dark_mode)
                                    } else {
                                        theme::table_row_selected(dark_mode)
                                    }
                                } else if hovered {
                                    theme::table_row_hover(dark_mode)
                                } else {
                                    base_color
                                };
                                ui.painter().rect_filled(rect, 0.0, bg);

                                data_cell(ui, &fid.to_string(), COL_ID, is_selected);
                                data_cell(ui, &flow.tuple.src.to_string(), col_ip, is_selected);
                                data_cell(ui, &flow.tuple.sport.to_string(), COL_PORT, is_selected);
                                data_cell(ui, &flow.tuple.dst.to_string(), col_ip, is_selected);
                                data_cell(ui, &flow.tuple.dport.to_string(), COL_PORT, is_selected);
                                data_cell(
                                    ui,
                                    &stats.series_count.to_string(),
                                    COL_SERIES,
                                    is_selected,
                                );
                                data_cell(
                                    ui,
                                    &format_count(stats.point_count),
                                    COL_POINTS,
                                    is_selected,
                                );
                            });

                            // Make the whole row clickable
                            let row_rect = row_response.response.rect;
                            let row_click = ui.interact(
                                row_rect,
                                ui.id().with((id_salt, "row", fid)),
                                egui::Sense::click(),
                            );
                            if row_click.hovered() {
                                ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::PointingHand);
                            }
                            if row_click.clicked() && !is_selected {
                                self.selected_id = Some(fid);
                                new_selection = Some(fid);
                            }

                            // Row divider
                            let rect = row_response.response.rect;
                            ui.painter().hline(
                                rect.x_range(),
                                rect.bottom(),
                                Stroke::new(0.5, theme::border(dark_mode)),
                            );
                        }
                    });
            });

        new_selection
    }
}

fn flow_stats(db: &DbBackend, flow: &Flow) -> FlowStats {
    let series = db.list_series_for_flow(flow);
    let point_count = series
        .iter()
        .map(|series| db.get_point_count(series.id))
        .sum();
    FlowStats {
        series_count: series.len(),
        point_count,
    }
}

fn flow_matches(flow: &Flow, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }

    if filter.split_whitespace().count() > 1 {
        return filter
            .split_whitespace()
            .all(|term| flow_matches(flow, term));
    }

    if let Some((column, value)) = filter.split_once(':') {
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

fn header_cell(ui: &mut Ui, label: &str, width: f32) {
    let dark_mode = ui.visuals().dark_mode;
    ui.add_sized(
        [width, ROW_HEIGHT],
        egui::Label::new(
            RichText::new(label)
                .color(theme::table_header_text(dark_mode))
                .strong()
                .size(12.0),
        ),
    );
}

fn data_cell(ui: &mut Ui, text: &str, width: f32, selected: bool) {
    let dark_mode = ui.visuals().dark_mode;
    let color = if selected {
        if dark_mode {
            Color32::from_rgb(226, 232, 240)
        } else {
            Color32::from_rgb(20, 40, 80)
        }
    } else {
        theme::text(dark_mode)
    };
    ui.add_sized(
        [width, ROW_HEIGHT],
        egui::Label::new(RichText::new(text).color(color).size(12.0)).truncate(),
    );
}
