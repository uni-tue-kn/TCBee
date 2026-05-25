use egui::RichText;
use rfd::FileDialog;

use crate::{backend::db::DbBackend, settings::AppSettings};

#[derive(Default)]
pub struct TabHome {
    status: String,
}

impl TabHome {
    pub fn set_status(&mut self, status: String) {
        self.status = status;
    }

    pub fn show(&mut self, ui: &mut egui::Ui, db: &mut DbBackend, _settings: &mut AppSettings) {
        ui.heading(RichText::new("TCBee — TCP Flow Visualizer").size(28.0));
        ui.separator();

        ui.columns(2, |columns| {
            // Left column: database selection
            columns[0].vertical(|ui| {
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
                } else if !self.status.is_empty() {
                    ui.label(RichText::new(&self.status).color(egui::Color32::RED));
                } else {
                    ui.label(
                        RichText::new("No database loaded.").color(egui::Color32::GRAY),
                    );
                }

                ui.separator();
                ui.label(RichText::new("About").strong().size(15.0));
                paragraph(
                    ui,
                    "This program visualizes recorded TCP flow metrics for exploratory analysis.",
                );
                paragraph(
                    ui,
                    "It can show single flows or compare multiple flows with their corresponding time series data.",
                );
                paragraph(
                    ui,
                    "Database modification and derived metrics are handled through an extensible plugin system.",
                );
            });

            // Right column: usage guide
            columns[1].vertical(|ui| {
                ui.heading("Usage Guide");
                ui.separator();
                egui::ScrollArea::vertical().id_salt("home_scroll").show(ui, |ui| {
                    section(ui, "Home", "The starting screen where you select the database file (.sqlite or .duck) containing recorded TCP flow data. If the button to open a file is not visible, increase the window size.");
                    section(ui, "Single Flow", "Visualize metrics for one TCP flow over time. Flows are identified by their IP 5-tuple and sorted by start time. Multiple metrics can be plotted together in one graph or split into separate graphs. The plot tools support zooming, panning, fitting, and manual x-range selection.");
                    section(ui, "Multi Flow", "Compare metrics from two TCP flows side by side. This is useful for analyzing interactions between concurrent flows, such as bandwidth sharing, pacing, or congestion window changes. The interface is similar to Single Flow, but supports selecting two flows and comparing their metrics.");
                    section(ui, "Process", "Calculate derived TCP metrics that are not directly recorded. This is done through plugins, for example modules that compute window-related series. Calculated results can be previewed and stored in the loaded database for later analysis.");
                    section(ui, "Settings", "Configure application options such as point density reduction and plot sampling. Some settings are mainly useful for large recordings or performance tuning.");
                });
            });
        });
    }
}

fn section(ui: &mut egui::Ui, title: &str, body: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(title).strong().size(15.0));
    paragraph(ui, body);
    ui.add_space(4.0);
}

fn paragraph(ui: &mut egui::Ui, body: &str) {
    ui.add(egui::Label::new(body).wrap());
}
