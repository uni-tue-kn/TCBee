use egui::{Color32, RichText, Stroke, Ui, Vec2};
use ts_storage::Flow;

const COL_ID: f32 = 36.0;
const COL_IP: f32 = 120.0;
const COL_PORT: f32 = 54.0;
const ROW_HEIGHT: f32 = 22.0;
const HEADER_BG: Color32 = Color32::from_rgb(45, 55, 72);
const HEADER_FG: Color32 = Color32::from_rgb(226, 232, 240);
const ROW_ODD: Color32 = Color32::from_rgb(247, 248, 250);
const ROW_EVEN: Color32 = Color32::from_rgb(255, 255, 255);
const ROW_SELECTED: Color32 = Color32::from_rgb(190, 219, 255);
const ROW_SELECTED_HOVER: Color32 = Color32::from_rgb(167, 207, 255);
const ROW_HOVER: Color32 = Color32::from_rgb(235, 240, 248);
const BORDER: Color32 = Color32::from_rgb(200, 210, 220);

/// A filterable table widget for selecting a TCP flow.
pub struct FlowTable {
    pub filter: String,
    pub selected_id: Option<i64>,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self { filter: String::new(), selected_id: None }
    }
}

impl FlowTable {
    pub fn reset(&mut self) {
        self.filter.clear();
        self.selected_id = None;
    }

    /// Render the table. Returns `Some(flow_id)` when a new row is clicked.
    pub fn show(&mut self, ui: &mut Ui, flows: &[Flow]) -> Option<i64> {
        let mut new_selection: Option<i64> = None;

        // ── Filter bar ──────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label(RichText::new("🔍").size(14.0));
            // Reserve space for the clear button before sizing the text edit,
            // so the button never overflows the panel and inflates available_width.
            let clear_w = if self.filter.is_empty() { 0.0 } else { 22.0 };
            let text_w = (ui.available_width() - clear_w).max(0.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter by IP or port…")
                    .desired_width(text_w),
            );
            if !self.filter.is_empty() && ui.small_button("✕").clicked() {
                self.filter.clear();
            }
        });
        ui.add_space(4.0);

        let filter_lower = self.filter.to_lowercase();
        let visible: Vec<&Flow> = flows
            .iter()
            .filter(|f| flow_matches(f, &filter_lower))
            .collect();

        if visible.is_empty() {
            ui.label(RichText::new("No flows match the filter.").color(Color32::GRAY).italics());
            return None;
        }

        // ── Table ────────────────────────────────────────────────────────
        egui::Frame::new()
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(6.0)
            .show(ui, |ui| {
                // Measure inside the frame so border/padding is already subtracted.
                let available_w = ui.available_width();
                // Fixed columns: ID + Sport + Dport + 5 gaps of 8px each
                let fixed_w = COL_ID + COL_PORT + COL_PORT + 5.0 * 8.0;
                let col_ip = ((available_w - fixed_w) / 2.0).max(40.0);

                // Header
                let header_rect = egui::Rect::from_min_size(
                    ui.available_rect_before_wrap().min,
                    Vec2::new(available_w, ROW_HEIGHT),
                );
                ui.painter().rect_filled(header_rect, 0.0, HEADER_BG);

                ui.horizontal(|ui| {
                    ui.set_height(ROW_HEIGHT);
                    header_cell(ui, "ID", COL_ID);
                    header_cell(ui, "Src IP", col_ip);
                    header_cell(ui, "Sport", COL_PORT);
                    header_cell(ui, "Dst IP", col_ip);
                    header_cell(ui, "Dport", COL_PORT);
                });

                ui.separator();

                // Rows
                let row_count = visible.len();
                egui::ScrollArea::vertical()
                    .id_salt("flow_table_scroll")
                    .auto_shrink([false, false])
                    .show_rows(ui, ROW_HEIGHT, row_count, |ui, range| {
                        for i in range {
                            let flow = visible[i];
                            let fid = flow.id;
                            let is_selected = self.selected_id == Some(fid);

                            let base_color =
                                if is_selected { ROW_SELECTED } else if i % 2 == 0 { ROW_EVEN } else { ROW_ODD };

                            let row_response = ui.horizontal(|ui| {
                                ui.set_height(ROW_HEIGHT);

                                let rect = ui.max_rect();
                                let hovered = ui.rect_contains_pointer(rect);
                                let bg = if is_selected {
                                    if hovered { ROW_SELECTED_HOVER } else { ROW_SELECTED }
                                } else if hovered {
                                    ROW_HOVER
                                } else {
                                    base_color
                                };
                                ui.painter().rect_filled(rect, 0.0, bg);

                                data_cell(ui, &fid.to_string(), COL_ID, is_selected);
                                data_cell(ui, &flow.tuple.src.to_string(), col_ip, is_selected);
                                data_cell(ui, &flow.tuple.sport.to_string(), COL_PORT, is_selected);
                                data_cell(ui, &flow.tuple.dst.to_string(), col_ip, is_selected);
                                data_cell(ui, &flow.tuple.dport.to_string(), COL_PORT, is_selected);
                            });

                            // Make the whole row clickable
                            let row_rect = row_response.response.rect;
                            if ui.interact(row_rect, ui.id().with(("row", fid)), egui::Sense::click()).clicked() {
                                if !is_selected {
                                    self.selected_id = Some(fid);
                                    new_selection = Some(fid);
                                }
                            }

                            // Row divider
                            let rect = row_response.response.rect;
                            ui.painter().hline(
                                rect.x_range(),
                                rect.bottom(),
                                Stroke::new(0.5, BORDER),
                            );
                        }
                    });
            });

        new_selection
    }
}

fn flow_matches(flow: &Flow, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
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

fn header_cell(ui: &mut Ui, label: &str, width: f32) {
    ui.add_sized(
        [width, ROW_HEIGHT],
        egui::Label::new(RichText::new(label).color(HEADER_FG).strong().size(12.0)),
    );
}

fn data_cell(ui: &mut Ui, text: &str, width: f32, selected: bool) {
    let color = if selected { Color32::from_rgb(20, 40, 80) } else { Color32::from_rgb(30, 30, 40) };
    ui.add_sized(
        [width, ROW_HEIGHT],
        egui::Label::new(RichText::new(text).color(color).size(12.0)).truncate(),
    );
}
