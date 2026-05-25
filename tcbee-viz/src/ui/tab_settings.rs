use crate::settings::AppSettings;

#[derive(Default)]
pub struct TabSettings;

impl TabSettings {
    pub fn show(&mut self, ui: &mut egui::Ui, settings: &mut AppSettings) {
        ui.heading("Settings");
        ui.separator();

        egui::Grid::new("settings_grid")
            .num_columns(2)
            .spacing([40.0, 8.0])
            .show(ui, |ui| {
                ui.label("UI text size:");
                ui.add(egui::Slider::new(&mut settings.text_size, 10.0..=24.0).suffix("pt"));
                ui.end_row();

                ui.label("Skip every Nth point:");
                ui.add(
                    egui::Slider::new(&mut settings.skip_every_nth, 1..=100)
                        .text("(1 = draw all)"),
                );
                ui.end_row();

                ui.label("Reduce density on zoom:");
                ui.checkbox(&mut settings.reduce_density_on_zoom, "");
                ui.end_row();

                if settings.reduce_density_on_zoom {
                    ui.label("Zoom skip amount:");
                    ui.add(egui::Slider::new(&mut settings.zoom_skip_amount, 1..=50));
                    ui.end_row();
                }

                ui.label("Point series threshold:");
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
        ui.label(egui::RichText::new("Tip: changes take effect immediately.").italics());
    }
}
