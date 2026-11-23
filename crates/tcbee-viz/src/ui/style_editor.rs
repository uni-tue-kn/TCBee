//! Editor of the figure export style, used in the settings and the export preview.

use crate::plot_style::{self, LegendPosition, PlotStyle, SIZE_PRESETS};

/// A colour field edited as `#rrggbb`; returns whether it changed.
fn color_edit(ui: &mut egui::Ui, hex: &mut String) -> bool {
    let mut color = plot_style::parse_hex(hex).unwrap_or(egui::Color32::BLACK);
    if ui.color_edit_button_srgba(&mut color).changed() {
        *hex = plot_style::to_hex(color);
        return true;
    }
    false
}

/// Widgets for the figure style; returns whether anything changed.
pub fn show(ui: &mut egui::Ui, style: &mut PlotStyle) -> bool {
    let mut changed = false;
    egui::Grid::new("plot_style_grid")
        .num_columns(2)
        .spacing([40.0, 8.0])
        .show(ui, |ui| {
            ui.label("Size:");
            ui.horizontal(|ui| {
                for preset in &SIZE_PRESETS {
                    if ui
                        .button(preset.label)
                        .on_hover_text("Sets size, font size and line width")
                        .clicked()
                    {
                        preset.apply(style);
                        changed = true;
                    }
                }
            });
            ui.end_row();

            ui.label("Width × height:");
            ui.horizontal(|ui| {
                changed |= ui
                    .add(
                        egui::DragValue::new(&mut style.width_in)
                            .range(1.0..=20.0)
                            .speed(0.05)
                            .suffix(" in"),
                    )
                    .changed();
                changed |= ui
                    .add(
                        egui::DragValue::new(&mut style.height_in)
                            .range(1.0..=20.0)
                            .speed(0.05)
                            .suffix(" in"),
                    )
                    .on_hover_text("Height of each plot; a figure of several plots stacks them")
                    .changed();
            });
            ui.end_row();

            ui.label("Font family:");
            changed |= ui.text_edit_singleline(&mut style.font_family).lost_focus();
            ui.end_row();

            ui.label("Font size:");
            changed |= ui
                .add(egui::Slider::new(&mut style.font_size_pt, 5.0..=24.0).suffix(" pt"))
                .changed();
            ui.end_row();

            ui.label("Line width:");
            changed |= ui
                .add(egui::Slider::new(&mut style.line_width_pt, 0.25..=4.0).suffix(" pt"))
                .changed();
            ui.end_row();

            ui.label("Grid:");
            changed |= ui.checkbox(&mut style.grid, "").changed();
            ui.end_row();

            ui.label("Legend:");
            egui::ComboBox::from_id_salt("plot_style_legend")
                .selected_text(style.legend.label())
                .show_ui(ui, |ui| {
                    for pos in LegendPosition::ALL {
                        changed |= ui
                            .selectable_value(&mut style.legend, pos, pos.label())
                            .changed();
                    }
                });
            ui.end_row();

            ui.label("Line colours:");
            ui.horizontal(|ui| {
                changed |= ui
                    .checkbox(&mut style.use_palette, "palette instead of the viewer's")
                    .changed();
                for hex in &mut style.palette {
                    changed |= color_edit(ui, hex);
                }
            });
            ui.end_row();

            ui.label("Gaps (hook_seq) in figures:");
            ui.horizontal(|ui| {
                changed |= ui.checkbox(&mut style.show_gaps, "show").changed();
                changed |= ui
                    .checkbox(&mut style.gaps_in_series_color, "in series colour")
                    .changed();
                if !style.gaps_in_series_color {
                    changed |= color_edit(ui, &mut style.gap_color);
                }
                changed |= ui
                    .add(egui::Slider::new(&mut style.gap_opacity, 0.05..=1.0).text("opacity"))
                    .changed();
            });
            ui.end_row();

            ui.label("PNG resolution:");
            changed |= ui
                .add(egui::Slider::new(&mut style.png_dpi, 72..=1200).suffix(" dpi"))
                .changed();
            ui.end_row();
        });
    if ui.button("Reset to defaults").clicked() {
        *style = PlotStyle::default();
        changed = true;
    }
    changed
}
