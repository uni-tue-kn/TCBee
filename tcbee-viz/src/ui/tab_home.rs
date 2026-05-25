use egui::RichText;
use rfd::FileDialog;

use crate::{backend::db::DbBackend, settings::AppSettings};

#[derive(Default)]
pub struct TabHome {
    status: String,
}

impl TabHome {
    pub fn show(&mut self, ui: &mut egui::Ui, db: &mut DbBackend, _settings: &mut AppSettings) {
        ui.heading(RichText::new("TCBee — TCP Flow Visualizer").size(28.0));
        ui.separator();

        ui.horizontal(|ui| {
            // Left column: database selection
            ui.vertical(|ui| {
                ui.set_min_width(300.0);
                ui.heading("Select Database");
                ui.separator();

                if ui.button("Open database file…").clicked() {
                    if let Some(path) = FileDialog::new()
                        .add_filter("Database files", &["sqlite", "duck"])
                        .set_directory("~/")
                        .pick_file()
                    {
                        match DbBackend::open(path.clone()) {
                            Ok(new_db) => {
                                *db = new_db;
                                self.status =
                                    format!("Connected: {}", path.to_string_lossy());
                            }
                            Err(e) => {
                                self.status = format!("Error: {}", e);
                            }
                        }
                    }
                }

                ui.add_space(8.0);
                if db.is_connected() {
                    ui.label(
                        RichText::new(&self.status).color(egui::Color32::from_rgb(50, 180, 50)),
                    );
                    if let Some(src) = db.source {
                        ui.label(format!("Backend: {}", src));
                    }
                } else {
                    ui.label(
                        RichText::new("No database loaded.").color(egui::Color32::GRAY),
                    );
                }
            });

            ui.separator();

            // Right column: usage guide
            ui.vertical(|ui| {
                ui.heading("Usage Guide");
                ui.separator();
                egui::ScrollArea::vertical().id_salt("home_scroll").show(ui, |ui| {
                    section(ui, "Home", "The starting screen where you select the database file (.sqlite or .duck) containing recorded TCP flow data.");
                    section(ui, "Single Flow", "Visualise metrics for one TCP flow over time. Select a flow, choose time series to display, and use the plot tools to zoom and pan. Supports combined or split-chart view.");
                    section(ui, "Multi Flow", "Compare metrics from two TCP flows side-by-side. Useful for analysing bandwidth sharing or congestion window interactions.");
                    section(ui, "Process", "Apply plugins to compute derived metrics (e.g. upper TCP window = SND_UNA + SND_WND). Results can be previewed and saved to the database.");
                    section(ui, "Settings", "Configure display options such as point density reduction and skip factor.");
                });
            });
        });
    }
}

fn section(ui: &mut egui::Ui, title: &str, body: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(title).strong().size(15.0));
    ui.label(body);
    ui.add_space(4.0);
}
