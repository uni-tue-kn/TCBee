use crate::{
    plot_style::{self, LegendPosition, PlotStyle, SIZE_PRESETS},
    settings::AppSettings,
    ui::theme,
};

#[derive(Default)]
pub struct TabSettings {
    /// Result of the last save of the plot style
    style_status: Option<Result<String, String>>,
    /// The plot style changed and is not saved yet
    style_dirty: bool,
}

impl TabSettings {
    pub fn show(&mut self, ui: &mut egui::Ui, settings: &mut AppSettings) {
        egui::Frame::NONE
            .inner_margin(egui::Margin::symmetric(22, 18))
            .show(ui, |ui| {
                let dark_mode = ui.visuals().dark_mode;
                ui.heading(egui::RichText::new("Settings").color(theme::text(dark_mode)));
                ui.separator();

                egui::Grid::new("settings_grid")
                    .num_columns(2)
                    .spacing([40.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("UI text size:");
                        ui.add(
                            egui::Slider::new(&mut settings.text_size, 10.0..=24.0).suffix("pt"),
                        );
                        ui.end_row();

                        ui.label("Skip every Nth point:");
                        ui.add(
                            egui::Slider::new(&mut settings.skip_every_nth, 1..=100)
                                .text("(1 = draw all)"),
                        );
                        ui.end_row();

                        ui.label("Time granularity:");
                        ui.add(
                            egui::Slider::new(&mut settings.time_granularity_ms, 0.0..=1000.0)
                                .suffix(" ms")
                                .text("(0 = automatic only)"),
                        );
                        ui.end_row();

                        ui.label("Adaptive downsample:");
                        ui.checkbox(&mut settings.adaptive_downsample, "");
                        ui.end_row();

                        ui.label("Min pixels per point:");
                        ui.add(
                            egui::Slider::new(&mut settings.pointseries_threshold, 0.5..=20.0)
                                .text("px/point"),
                        );
                        ui.end_row();

                        ui.label("Dark mode:");
                        ui.checkbox(&mut settings.dark_mode, "");
                        ui.end_row();
                    });

                ui.add_space(12.0);
                ui.separator();
                ui.heading(egui::RichText::new("Figure export").color(theme::text(dark_mode)));
                self.style_dirty |= style_editor(ui, &mut settings.plot_style);
                // Save once a drag or edit has ended, not on every frame of it
                if self.style_dirty && !ui.input(|i| i.pointer.any_down()) {
                    self.style_dirty = false;
                    self.style_status = Some(save_style(&settings.plot_style));
                }
                match &self.style_status {
                    Some(Ok(path)) => {
                        ui.label(
                            egui::RichText::new(format!("Saved to {path}"))
                                .color(theme::muted_text(dark_mode)),
                        );
                    }
                    Some(Err(e)) => {
                        ui.colored_label(egui::Color32::RED, format!("Saving failed: {e}"));
                    }
                    None => {}
                }

                ui.add_space(12.0);
                ui.separator();
                ui.label(
                    egui::RichText::new("Tip: changes take effect immediately.")
                        .italics()
                        .color(theme::muted_text(dark_mode)),
                );
            });
    }
}

fn save_style(style: &PlotStyle) -> Result<String, String> {
    let path = plot_style::config_path().ok_or("no home directory")?;
    style.save_to(&path)?;
    Ok(path.display().to_string())
}

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
fn style_editor(ui: &mut egui::Ui, style: &mut PlotStyle) -> bool {
    let mut changed = false;
    egui::Grid::new("plot_style_grid")
        .num_columns(2)
        .spacing([40.0, 8.0])
        .show(ui, |ui| {
            ui.label("Size:");
            ui.horizontal(|ui| {
                for (label, w, h) in SIZE_PRESETS {
                    if ui.button(label).clicked() {
                        (style.width_in, style.height_in) = (w, h);
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
                    .changed();
            });
            ui.end_row();

            ui.label("Font family:");
            changed |= ui.text_edit_singleline(&mut style.font_family).lost_focus();
            ui.end_row();

            ui.label("Font size:");
            changed |= ui
                .add(egui::Slider::new(&mut style.font_size_pt, 5.0..=16.0).suffix(" pt"))
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
                for hex in &mut style.palette {
                    changed |= color_edit(ui, hex);
                }
            });
            ui.end_row();

            ui.label("Gaps (hook_seq) in figures:");
            ui.horizontal(|ui| {
                changed |= ui.checkbox(&mut style.show_gaps, "show").changed();
                changed |= color_edit(ui, &mut style.gap_color);
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
