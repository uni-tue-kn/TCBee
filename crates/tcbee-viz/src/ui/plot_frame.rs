//! Layout shared by the stacked plots of all tabs.

/// Minimum width of the y axis of stacked plots (px). The same in every plot of a stack,
/// so their time axes line up.
pub const Y_AXIS_WIDTH: f32 = 56.0;

/// Space between the left border and the title of a plot (px).
pub const TITLE_INSET: f32 = 8.0;
/// Space above the title of a plot (px).
const TITLE_SPACE_ABOVE: f32 = 6.0;
/// Space between the title and its plot (px).
const TITLE_SPACE_BELOW: f32 = 2.0;
/// Height a plot title takes, without its text (px).
pub const TITLE_SPACING: f32 = TITLE_SPACE_ABOVE + TITLE_SPACE_BELOW;

/// The title above a plot, inset from the left border.
pub fn plot_title(ui: &mut egui::Ui, title: egui::RichText) {
    ui.add_space(TITLE_SPACE_ABOVE);
    ui.horizontal(|ui| {
        ui.add_space(TITLE_INSET);
        ui.label(title);
    });
    ui.add_space(TITLE_SPACE_BELOW);
}
