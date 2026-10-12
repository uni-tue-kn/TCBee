//! Cells, rows and frame shared by the hand-painted tables (flows, series, MPTCP).

use egui::{Color32, RichText, Stroke, Ui};

use crate::ui::theme;

pub const ROW_HEIGHT: f32 = 22.0;

/// Rounded, bordered frame around a table
pub fn frame(dark_mode: bool) -> egui::Frame {
    egui::Frame::new()
        .fill(theme::panel_bg(dark_mode))
        .stroke(Stroke::new(1.0, theme::border(dark_mode)))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::ZERO)
}

pub fn header_cell(ui: &mut Ui, label: &str, width: f32) -> egui::Response {
    let dark_mode = ui.visuals().dark_mode;
    ui.add_sized(
        [width, ROW_HEIGHT],
        egui::Label::new(
            RichText::new(label)
                .color(theme::table_header_text(dark_mode))
                .strong()
                .size(12.0),
        ),
    )
}

pub fn data_cell(ui: &mut Ui, text: &str, width: f32, selected: bool) -> egui::Response {
    ui.add_sized(
        [width, ROW_HEIGHT],
        egui::Label::new(
            RichText::new(text)
                .color(cell_text(ui, selected))
                .size(12.0),
        )
        .truncate(),
    )
}

/// Text colour of a data cell
fn cell_text(ui: &Ui, selected: bool) -> Color32 {
    let dark_mode = ui.visuals().dark_mode;
    match (selected, dark_mode) {
        (true, true) => Color32::from_rgb(226, 232, 240),
        (true, false) => Color32::from_rgb(20, 40, 80),
        (false, _) => theme::text(dark_mode),
    }
}

/// Background of row `index`: striped, selected and hovered
pub fn row_fill(dark_mode: bool, index: usize, selected: bool, hovered: bool) -> Color32 {
    match (selected, hovered) {
        (true, true) => theme::table_row_selected_hover(dark_mode),
        (true, false) => theme::table_row_selected(dark_mode),
        (false, true) => theme::table_row_hover(dark_mode),
        (false, false) if index.is_multiple_of(2) => theme::table_row_even(dark_mode),
        (false, false) => theme::table_row_odd(dark_mode),
    }
}

/// Thin line under a row
pub fn row_divider(ui: &Ui, rect: egui::Rect) {
    ui.painter().hline(
        rect.x_range(),
        rect.bottom(),
        Stroke::new(0.5, theme::border(ui.visuals().dark_mode)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_fill_stripes_unless_selected_or_hovered() {
        for dark in [false, true] {
            assert_eq!(row_fill(dark, 0, false, false), theme::table_row_even(dark));
            assert_eq!(row_fill(dark, 1, false, false), theme::table_row_odd(dark));
            assert_eq!(row_fill(dark, 1, false, true), theme::table_row_hover(dark));
            assert_eq!(
                row_fill(dark, 0, true, false),
                theme::table_row_selected(dark)
            );
            assert_eq!(
                row_fill(dark, 1, true, true),
                theme::table_row_selected_hover(dark)
            );
        }
    }
}
