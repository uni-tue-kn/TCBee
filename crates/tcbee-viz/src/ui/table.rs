//! Cells, rows and frame shared by the hand-painted tables (flows, series, MPTCP).

use egui::{Color32, RichText, Stroke, Ui, Vec2};

use crate::ui::theme;

pub const ROW_HEIGHT: f32 = 22.0;
/// Space between a right-aligned number and the next column
const NUMBER_PADDING: f32 = 8.0;
/// Space between the previous column and left-aligned text
const TEXT_PADDING: f32 = 6.0;
/// The table frame's border on both sides together
pub const FRAME_BORDER: f32 = 2.0;
/// Room for a horizontal scroll bar below the rows
const SCROLL_BAR_ROOM: f32 = 8.0;

const SEARCH_ICON_W: f32 = 18.0;
const CLEAR_BUTTON_W: f32 = 22.0;
const HELP_BUTTON_W: f32 = 20.0;
/// Inner margin that egui gives a text box on each side
const TEXT_EDIT_MARGIN: f32 = 4.0;

/// Filter box `width` wide with a search icon, a "?" with `help` if given and a clear button,
/// `gap` apart
pub fn filter_bar(
    ui: &mut Ui,
    filter: &mut String,
    hint: &str,
    help: Option<&str>,
    width: f32,
    gap: f32,
) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, ROW_HEIGHT),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = gap;
            ui.add_sized([SEARCH_ICON_W, ROW_HEIGHT], egui::Label::new("🔍"));
            let text_w = filter_text_width(width, gap, help.is_some(), TEXT_EDIT_MARGIN);
            ui.add(
                egui::TextEdit::singleline(filter)
                    .hint_text(hint)
                    .desired_width(text_w)
                    .min_size(Vec2::new(text_w, ROW_HEIGHT)),
            );
            if let Some(help) = help {
                ui.add_sized(
                    [HELP_BUTTON_W, ROW_HEIGHT],
                    egui::Label::new(RichText::new("?").strong()).sense(egui::Sense::hover()),
                )
                .on_hover_text(help);
            }
            let clear = ui.add_sized(
                [CLEAR_BUTTON_W, ROW_HEIGHT],
                egui::Button::new("x").frame(!filter.is_empty()),
            );
            if !filter.is_empty() && clear.clicked() {
                filter.clear();
            }
        },
    );
}

/// Width to ask of the filter's text box so that the bar fills `width`: the rest after the
/// icon, the buttons and the gaps, less the box's own margin on both sides, which egui adds
fn filter_text_width(width: f32, gap: f32, help: bool, margin: f32) -> f32 {
    let help_w = if help { HELP_BUTTON_W + gap } else { 0.0 };
    (width - SEARCH_ICON_W - help_w - CLEAR_BUTTON_W - 2.0 * gap - 2.0 * margin).max(40.0)
}

/// The header of a table `width` wide: its background, then the cells that `add_cells` adds
pub fn header_row(ui: &mut Ui, width: f32, add_cells: impl FnOnce(&mut Ui)) {
    let rect = egui::Rect::from_min_size(
        ui.available_rect_before_wrap().min,
        Vec2::new(width, ROW_HEIGHT),
    );
    ui.painter()
        .rect_filled(rect, 0.0, theme::table_header_bg(ui.visuals().dark_mode));
    ui.horizontal(|ui| {
        ui.set_height(ROW_HEIGHT);
        add_cells(ui);
    });
}

/// Makes a whole row clickable, with a pointing hand on hover
pub fn row_click(ui: &Ui, rect: egui::Rect, id: egui::Id) -> egui::Response {
    let response = ui.interact(rect, id, egui::Sense::click());
    if response.hovered() {
        ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::PointingHand);
    }
    response
}

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

/// A data cell with its text at the left edge, for addresses and descriptions
pub fn text_cell(ui: &mut Ui, text: &str, width: f32, selected: bool) -> egui::Response {
    let color = cell_text(ui, selected);
    ui.allocate_ui_with_layout(
        Vec2::new(width, ROW_HEIGHT),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            // A left-to-right child only takes the width of its content
            ui.set_min_size(Vec2::new(width, ROW_HEIGHT));
            ui.add_space(TEXT_PADDING);
            ui.add(egui::Label::new(RichText::new(text).color(color).size(12.0)).truncate())
        },
    )
    .inner
}

/// A header cell with its text at the left edge, over a column of `text_cell`s
pub fn text_header_cell(ui: &mut Ui, label: &str, width: f32) -> egui::Response {
    let color = theme::table_header_text(ui.visuals().dark_mode);
    ui.allocate_ui_with_layout(
        Vec2::new(width, ROW_HEIGHT),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            // A left-to-right child only takes the width of its content
            ui.set_min_size(Vec2::new(width, ROW_HEIGHT));
            ui.add_space(TEXT_PADDING);
            ui.add(egui::Label::new(
                RichText::new(label).color(color).strong().size(12.0),
            ))
        },
    )
    .inner
}

/// Height of a table frame with a header and `rows` rows, when the rows are packed without
/// spacing (`item_spacing.y` 0): the rows, the header, the frame's border and room for a
/// horizontal scroll bar
pub fn table_height(rows: usize) -> f32 {
    (rows + 1) as f32 * ROW_HEIGHT + FRAME_BORDER + SCROLL_BAR_ROOM
}

/// A header cell with its text at the right edge, over a column of numbers
pub fn number_header_cell(ui: &mut Ui, label: &str, width: f32) -> egui::Response {
    let color = theme::table_header_text(ui.visuals().dark_mode);
    ui.allocate_ui_with_layout(
        Vec2::new(width, ROW_HEIGHT),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            ui.add_space(NUMBER_PADDING);
            ui.add(egui::Label::new(
                RichText::new(label).color(color).strong().size(12.0),
            ))
        },
    )
    .inner
}

/// A data cell with its text at the right edge, for numbers
pub fn number_cell(ui: &mut Ui, text: &str, width: f32, selected: bool) -> egui::Response {
    let color = cell_text(ui, selected);
    ui.allocate_ui_with_layout(
        Vec2::new(width, ROW_HEIGHT),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            ui.add_space(NUMBER_PADDING);
            ui.add(egui::Label::new(RichText::new(text).color(color).size(12.0)).truncate())
        },
    )
    .inner
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
    fn filter_text_box_leaves_room_for_icon_buttons_and_margin() {
        // 18 icon + 22 clear + 2 gaps of 4 + 2 margins of 4
        assert_eq!(filter_text_width(200.0, 4.0, false, 4.0), 144.0);
        // The help adds its width and a gap
        assert_eq!(filter_text_width(200.0, 20.0, true, 4.0), 72.0);
        assert_eq!(filter_text_width(50.0, 4.0, true, 4.0), 40.0);
    }

    /// How far `add_cell` moves the cursor of a row
    fn cell_advance(add_cell: impl Fn(&mut Ui)) -> f32 {
        let ctx = egui::Context::default();
        let mut advance = 0.0;
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing = Vec2::ZERO;
                    let start = ui.cursor().left();
                    add_cell(ui);
                    advance = ui.cursor().left() - start;
                });
            });
        });
        advance
    }

    #[test]
    fn cells_take_their_column_width() {
        for text in ["x", "10.31.1.1:55872 -> 10.31.1.2:5501"] {
            assert_eq!(
                cell_advance(|ui| drop(text_cell(ui, text, 200.0, false))),
                200.0
            );
            assert_eq!(
                cell_advance(|ui| drop(text_header_cell(ui, text, 200.0))),
                200.0
            );
            assert_eq!(
                cell_advance(|ui| drop(number_cell(ui, text, 200.0, false))),
                200.0
            );
            assert_eq!(
                cell_advance(|ui| drop(number_header_cell(ui, text, 200.0))),
                200.0
            );
            assert_eq!(
                cell_advance(|ui| drop(data_cell(ui, text, 200.0, false))),
                200.0
            );
        }
    }

    #[test]
    fn table_height_counts_header_border_and_scroll_bar() {
        assert_eq!(table_height(0), 22.0 + 2.0 + 8.0);
        assert_eq!(table_height(3), 4.0 * 22.0 + 2.0 + 8.0);
    }

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
