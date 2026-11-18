use crate::{
    plot_style::{self, PlotStyle},
    settings::AppSettings,
    ui::{style_editor, theme},
};

#[derive(Default)]
pub struct TabSettings {
    /// Result of the last save of the plot style
    style_status: Option<Result<String, String>>,
    /// The plot style changed and is not saved yet
    style_dirty: bool,
    style_preview: crate::export::preview::StylePreview,
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
                ui.horizontal_top(|ui| {
                    ui.vertical(|ui| {
                        self.style_dirty |= style_editor::show(ui, &mut settings.plot_style);
                    });
                    ui.separator();
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("The figure last opened for export, or a sample")
                                .small()
                                .color(theme::muted_text(dark_mode)),
                        );
                        self.style_preview.show(ui, &settings.plot_style);
                    });
                });
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
