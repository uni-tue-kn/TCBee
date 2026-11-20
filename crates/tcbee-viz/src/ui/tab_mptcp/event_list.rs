//! The list of path manager events below the plots: time, row, type and details of each
//! event. A click moves the view to the event and marks it in the lane and the plots.

use egui::{ScrollArea, Vec2};

use super::markers::{kind_color, paint_marker, SMALL_MARKER_RADIUS};
use super::model::{event_matches, event_type, event_type_name, row_name};
use super::{TabMptcp, FILTER_GAP};
use crate::ui::{
    table::{self, header_cell, number_cell, number_header_cell, text_cell, text_header_cell},
    theme,
};

// Columns; the details take the rest of the width
const COL_TIME: f32 = 72.0;
const COL_ROW: f32 = 64.0;
const COL_EVENT: f32 = 200.0;
const MIN_DETAILS_WIDTH: f32 = 160.0;
/// The marker before the event name
const COL_MARKER: f32 = 22.0;
/// Space before the subflow's colour in the row column, and the colour's size
const ROW_PADDING: f32 = 8.0;
const ROW_DOT: f32 = 10.0;

impl TabMptcp {
    /// The filterable event list; a click selects an event and moves the view to it
    pub(super) fn show_event_table(&mut self, ui: &mut egui::Ui) {
        let dark_mode = ui.visuals().dark_mode;
        let origin = self.connection.as_ref().map_or(0, |c| c.start_ts) as f64;
        let mut clicked = None;
        let min_width = COL_TIME + COL_ROW + COL_EVENT + MIN_DETAILS_WIDTH + table::FRAME_BORDER;
        ScrollArea::horizontal()
            .id_salt("mptcp_event_table")
            .show(ui, |ui| {
                ui.set_min_width(min_width);
                table::frame(dark_mode).show(ui, |ui| {
                    let content_w = ui.available_width().max(1.0);
                    ui.spacing_mut().item_spacing = Vec2::ZERO;
                    table::filter_bar(
                        ui,
                        &mut self.event_filter,
                        "Filter, e.g. #2 stale",
                        None,
                        content_w * 0.5,
                        FILTER_GAP,
                    );
                    let filter = self.event_filter.to_lowercase();
                    let visible: Vec<usize> = (0..self.events.len())
                        .filter(|&i| event_matches(&self.events[i], &filter))
                        .collect();
                    let details_w =
                        (content_w - COL_TIME - COL_ROW - COL_EVENT).max(MIN_DETAILS_WIDTH);
                    table::header_row(ui, content_w, |ui| {
                        number_header_cell(ui, "Time (s)", COL_TIME);
                        header_cell(ui, "Row", COL_ROW);
                        text_header_cell(ui, "Event", COL_EVENT);
                        text_header_cell(ui, "Details", details_w);
                    });
                    ScrollArea::vertical()
                        .id_salt("mptcp_event_rows")
                        .auto_shrink([false, false])
                        .show_rows(ui, table::ROW_HEIGHT, visible.len(), |ui, range| {
                            ui.set_width(content_w);
                            for i in range {
                                let index = visible[i];
                                let e = &self.events[index];
                                let selected = self.selected_event == Some(index);
                                let response = ui.horizontal(|ui| {
                                    ui.set_width(content_w);
                                    ui.set_height(table::ROW_HEIGHT);
                                    let rect = ui.max_rect();
                                    let hovered = ui.rect_contains_pointer(rect);
                                    ui.painter().rect_filled(
                                        rect,
                                        0.0,
                                        table::row_fill(dark_mode, i, selected, hovered),
                                    );
                                    let time = format!("{:.3}", (e.t - origin) / 1e9);
                                    number_cell(ui, &time, COL_TIME, selected);
                                    self.row_cell(ui, e.row, selected);
                                    let (marker, _) = ui.allocate_exact_size(
                                        Vec2::new(COL_MARKER, table::ROW_HEIGHT),
                                        egui::Sense::hover(),
                                    );
                                    paint_marker(
                                        ui.painter(),
                                        marker.center(),
                                        event_type(e.code).shape,
                                        kind_color(e.kind(), dark_mode),
                                        SMALL_MARKER_RADIUS,
                                    );
                                    let name = event_type_name(e.code, e.failed);
                                    text_cell(ui, &name, COL_EVENT - COL_MARKER, selected);
                                    text_cell(ui, &e.label, details_w, selected)
                                        .on_hover_text(&e.label);
                                });
                                let rect = response.response.rect;
                                let click = table::row_click(
                                    ui,
                                    rect,
                                    ui.id().with(("mptcp_event", index)),
                                )
                                .on_hover_text("Show in the plots; click again to let go");
                                if click.clicked() {
                                    clicked = Some(index);
                                }
                                table::row_divider(ui, rect);
                            }
                        });
                    if visible.is_empty() {
                        ui.label(
                            egui::RichText::new("No events match the filter.")
                                .color(theme::muted_text(dark_mode))
                                .italics(),
                        );
                    }
                });
            });
        // A second click on the picked event lets it go
        if let Some(index) = clicked {
            if self.selected_event == Some(index) {
                self.selected_event = None;
            } else {
                self.selected_event = Some(index);
                self.focus = Some(self.events[index].t);
            }
        }
    }

    /// The row of an event: the subflow's colour and number, or the connection
    fn row_cell(&self, ui: &mut egui::Ui, row: usize, selected: bool) {
        let color = row
            .checked_sub(1)
            .and_then(|i| self.subflows.get(i))
            .map(|s| s.color);
        ui.allocate_ui_with_layout(
            Vec2::new(COL_ROW, table::ROW_HEIGHT),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_min_size(Vec2::new(COL_ROW, table::ROW_HEIGHT));
                ui.add_space(ROW_PADDING);
                let (dot, _) = ui.allocate_exact_size(Vec2::splat(ROW_DOT), egui::Sense::hover());
                if let Some(color) = color {
                    ui.painter().rect_filled(dot, 2.0, color);
                }
                text_cell(
                    ui,
                    &row_name(row),
                    COL_ROW - ROW_PADDING - ROW_DOT,
                    selected,
                );
            },
        );
    }
}
