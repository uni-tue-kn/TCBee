use egui::{Color32, RichText, Stroke, Ui, Vec2};
use ts_storage::{DataValue, TimeSeries};

use crate::ui::theme;

const COL_CHECK: f32 = 28.0;
const COL_TYPE: f32 = 44.0;
const COL_COUNT: f32 = 64.0;
const ROW_HEIGHT: f32 = 22.0;
const SEARCH_ICON_W: f32 = 18.0;
const CLEAR_BUTTON_W: f32 = 22.0;
const FILTER_GAP: f32 = 4.0;

/// A searchable, checkable table for selecting time series metrics.
#[derive(Default)]
pub struct SeriesTable {
    pub filter: String,
}

impl SeriesTable {
    pub fn reset(&mut self) {
        self.filter.clear();
    }

    /// Render the table.
    ///
    /// `entries` — `(TimeSeries, point_count)` for the current flow.
    /// `selected_ids` — currently checked series IDs.
    /// `colors` — `(series_id, Color32)` for series that are already selected (used for the dot).
    ///
    /// Returns `Some(series_id)` when a row checkbox is toggled.
    pub fn show(
        &mut self,
        ui: &mut Ui,
        entries: &[(TimeSeries, i64)],
        selected_ids: &[i64],
        colors: &[(i64, Color32)],
    ) -> Option<i64> {
        self.show_with_id_salt(ui, entries, selected_ids, colors, "series_table")
    }

    /// Render the table with a caller-provided ID salt for repeated table instances.
    pub fn show_with_id_salt(
        &mut self,
        ui: &mut Ui,
        entries: &[(TimeSeries, i64)],
        selected_ids: &[i64],
        colors: &[(i64, Color32)],
        id_salt: &'static str,
    ) -> Option<i64> {
        let mut toggled: Option<i64> = None;
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

                // ── Filter bar ───────────────────────────────────────────────────
                let filter_w = content_w * 0.9;
                ui.allocate_ui_with_layout(
                    Vec2::new(filter_w, ROW_HEIGHT),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.spacing_mut().item_spacing.x = FILTER_GAP;
                        ui.add_sized([SEARCH_ICON_W, ROW_HEIGHT], egui::Label::new("🔍"));
                        let text_w = (filter_w - SEARCH_ICON_W - CLEAR_BUTTON_W - 2.0 * FILTER_GAP)
                            .max(40.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.filter)
                                .hint_text("Search metrics…")
                                .desired_width(text_w)
                                .min_size(Vec2::new(text_w, ROW_HEIGHT)),
                        );
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
                let visible: Vec<&(TimeSeries, i64)> = entries
                    .iter()
                    .filter(|(ts, _)| ts.name.to_lowercase().contains(&filter_lower))
                    .collect();

                ui.separator();

                if visible.is_empty() {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("No metrics match the filter.")
                            .color(theme::muted_text(dark_mode))
                            .italics(),
                    );
                    ui.add_space(4.0);
                    return;
                }

                // ── Header ────────────────────────────────────────────────────────
                let fixed_w = COL_CHECK + COL_TYPE + COL_COUNT;
                let col_name = (content_w - fixed_w).max(40.0);

                let header_rect = egui::Rect::from_min_size(
                    ui.available_rect_before_wrap().min,
                    Vec2::new(content_w, ROW_HEIGHT),
                );
                ui.painter()
                    .rect_filled(header_rect, 0.0, theme::table_header_bg(dark_mode));

                ui.horizontal(|ui| {
                    ui.set_height(ROW_HEIGHT);
                    header_cell(ui, "", COL_CHECK);
                    header_cell(ui, "Name", col_name);
                    header_cell(ui, "Type", COL_TYPE);
                    header_cell(ui, "Points", COL_COUNT);
                });

                ui.separator();

                // ── Rows ──────────────────────────────────────────────────────────
                egui::ScrollArea::vertical()
                    .id_salt((id_salt, "scroll"))
                    .auto_shrink([false, false])
                    .show_rows(ui, ROW_HEIGHT, visible.len(), |ui, range| {
                        ui.set_width(content_w);
                        for i in range {
                            let (ts, count) = visible[i];
                            let sid = ts.id;
                            let is_selected = selected_ids.contains(&sid);
                            let dot_color =
                                colors.iter().find(|&&(id, _)| id == sid).map(|&(_, c)| c);

                            let base = if is_selected {
                                theme::table_row_selected(dark_mode)
                            } else if i % 2 == 0 {
                                theme::table_row_even(dark_mode)
                            } else {
                                theme::table_row_odd(dark_mode)
                            };

                            let row_resp = ui.horizontal(|ui| {
                                ui.set_width(content_w);
                                ui.set_height(ROW_HEIGHT);
                                let rect = ui.max_rect();
                                let hovered = ui.rect_contains_pointer(rect);
                                let bg = if hovered && !is_selected {
                                    theme::table_row_hover(dark_mode)
                                } else if hovered {
                                    theme::table_row_selected_hover(dark_mode)
                                } else {
                                    base
                                };
                                ui.painter().rect_filled(rect, 0.0, bg);

                                // Checkbox / color dot cell
                                ui.allocate_ui_with_layout(
                                    Vec2::new(COL_CHECK, ROW_HEIGHT),
                                    egui::Layout::centered_and_justified(egui::Direction::TopDown),
                                    |ui| {
                                        if let Some(color) = dot_color {
                                            let (r, _) = ui.allocate_exact_size(
                                                Vec2::new(12.0, 12.0),
                                                egui::Sense::hover(),
                                            );
                                            ui.painter().circle_filled(r.center(), 5.0, color);
                                            ui.painter().circle_stroke(
                                                r.center(),
                                                5.0,
                                                Stroke::new(1.0, color.linear_multiply(0.6)),
                                            );
                                        } else {
                                            let (r, _) = ui.allocate_exact_size(
                                                Vec2::new(12.0, 12.0),
                                                egui::Sense::hover(),
                                            );
                                            ui.painter().rect_stroke(
                                                r,
                                                2.0,
                                                Stroke::new(1.5, Color32::from_gray(160)),
                                                egui::StrokeKind::Middle,
                                            );
                                        }
                                    },
                                );

                                data_cell(ui, &ts.name, col_name, is_selected);
                                type_cell(ui, &ts.ts_type, COL_TYPE, is_selected);
                                count_cell(ui, *count, COL_COUNT, is_selected);
                            });

                            // Clicking anywhere in the row toggles the series
                            let row_rect = row_resp.response.rect;
                            let row_click = ui.interact(
                                row_rect,
                                ui.id().with((id_salt, "srow", sid)),
                                egui::Sense::click(),
                            );
                            if row_click.hovered() {
                                ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::PointingHand);
                            }
                            if row_click.clicked() {
                                toggled = Some(sid);
                            }

                            // Row divider
                            ui.painter().hline(
                                row_resp.response.rect.x_range(),
                                row_resp.response.rect.bottom(),
                                Stroke::new(0.5, theme::border(dark_mode)),
                            );
                        }
                    });
            });

        toggled
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

fn type_cell(ui: &mut Ui, val_type: &DataValue, width: f32, selected: bool) {
    let (label, color) = type_display(val_type, selected);
    ui.add_sized(
        [width, ROW_HEIGHT],
        egui::Label::new(RichText::new(label).color(color).size(11.5).monospace()),
    );
}

fn count_cell(ui: &mut Ui, count: i64, width: f32, selected: bool) {
    let color = if selected {
        Color32::from_rgb(40, 60, 120)
    } else {
        Color32::from_gray(90)
    };
    let text = if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}k", count as f64 / 1_000.0)
    } else {
        count.to_string()
    };
    ui.add_sized(
        [width, ROW_HEIGHT],
        egui::Label::new(RichText::new(text).color(color).size(11.5)),
    );
}

fn type_display(val_type: &DataValue, selected: bool) -> (&'static str, Color32) {
    let base = if selected { 220u8 } else { 255u8 };
    match val_type {
        DataValue::Float(_) => ("f64", Color32::from_rgb(60, 140, base)),
        DataValue::Int(_) => ("i64", Color32::from_rgb(180, 100, 20)),
        DataValue::Boolean(_) => ("bool", Color32::from_rgb(140, 60, 160)),
        DataValue::String(_) => ("str", Color32::from_rgb(60, 120, 60)),
    }
}
