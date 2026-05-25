use egui::RichText;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use crate::ui::{flow_table::FlowTable, tab_single_flow::to_plot_points};

use crate::{
    backend::{
        db::DbBackend,
        plugin::PluginKind,
    },
    data::{preprocessing::generate_colors, series_data::SeriesData},
    settings::AppSettings,
};

pub struct TabProcess {
    flow_table: FlowTable,
    selected_plugin: Option<PluginKind>,
    /// Input series loaded from the database (raw_data populated).
    input_series: Vec<SeriesData>,
    /// Output series produced by the plugin.
    preview_series: Vec<SeriesData>,
    status: String,
    save_status: String,
}

impl Default for TabProcess {
    fn default() -> Self {
        Self {
            flow_table: FlowTable::default(),
            selected_plugin: None,
            input_series: Vec::new(),
            preview_series: Vec::new(),
            status: String::new(),
            save_status: String::new(),
        }
    }
}

impl TabProcess {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn show(&mut self, ui: &mut egui::Ui, db: &DbBackend, _settings: &AppSettings) {
        if !db.is_connected() {
            ui.centered_and_justified(|ui| {
                ui.label("No database loaded. Go to Home and select a database file.");
            });
            return;
        }

        egui::SidePanel::left("process_left_panel")
            .resizable(true)
            .min_width(180.0)
            .max_width(300.0)
            .show_inside(ui, |ui| {
                self.show_flow_panel(ui, db);
            });

        egui::SidePanel::right("process_right_panel")
            .resizable(true)
            .min_width(180.0)
            .max_width(300.0)
            .show_inside(ui, |ui| {
                self.show_plugin_panel(ui, db);
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            self.show_preview_plot(ui);
        });
    }

    fn show_flow_panel(&mut self, ui: &mut egui::Ui, db: &DbBackend) {
        ui.label(RichText::new("Flow").strong().size(13.0));
        ui.add_space(2.0);

        let flows = db.list_flows();
        if flows.is_empty() {
            ui.label(RichText::new("No flows found.").color(egui::Color32::GRAY));
            return;
        }

        if self.flow_table.show(ui, &flows).is_some() {
            self.input_series.clear();
            self.preview_series.clear();
            self.status.clear();
            self.save_status.clear();
        }
    }

    fn show_plugin_panel(&mut self, ui: &mut egui::Ui, db: &DbBackend) {
        ui.heading("Plugin");
        ui.separator();

        for kind in PluginKind::ALL {
            let selected = self.selected_plugin == Some(*kind);
            if ui.selectable_label(selected, kind.label()).clicked() {
                self.selected_plugin = Some(*kind);
                self.preview_series.clear();
                self.status.clear();
            }
        }

        if let Some(kind) = self.selected_plugin {
            let plugin = kind.create();
            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new(plugin.name()).strong());
            ui.label(plugin.description());
            ui.add_space(4.0);
            ui.label("Required series:");
            for name in plugin.required_series() {
                ui.label(format!("  • {}", name));
            }
        }

        ui.add_space(12.0);
        ui.separator();

        let can_preview = self.flow_table.selected_id.is_some() && self.selected_plugin.is_some();
        if ui.add_enabled(can_preview, egui::Button::new("Load & Preview")).clicked() {
            self.run_preview(db);
        }

        if !self.status.is_empty() {
            ui.add_space(4.0);
            let color = if self.status.starts_with("Error") {
                egui::Color32::RED
            } else {
                egui::Color32::from_rgb(50, 180, 50)
            };
            ui.label(RichText::new(&self.status).color(color));
        }

        if !self.preview_series.is_empty() {
            ui.add_space(8.0);
            let can_save = self.flow_table.selected_id.is_some();
            if ui.add_enabled(can_save, egui::Button::new("Save to database")).clicked() {
                self.save_results(db);
            }
            if !self.save_status.is_empty() {
                ui.label(&self.save_status);
            }
        }
    }

    fn show_preview_plot(&self, ui: &mut egui::Ui) {
        if self.input_series.is_empty() && self.preview_series.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label("Select a flow and plugin, then click \"Load & Preview\".");
            });
            return;
        }

        Plot::new("process_preview")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .legend(Legend::default())
            .height(ui.available_height())
            .show(ui, |plot_ui| {
                for s in &self.input_series {
                    let pts = PlotPoints::from(to_plot_points(&s.points));
                    plot_ui.line(Line::new(pts).color(s.color).name(&s.name));
                }
                for s in &self.preview_series {
                    let pts = PlotPoints::from(to_plot_points(&s.points));
                    plot_ui.line(
                        Line::new(pts)
                            .color(s.color)
                            .name(format!("[new] {}", s.name))
                            .style(egui_plot::LineStyle::dashed_dense()),
                    );
                }
            });
    }

    fn run_preview(&mut self, db: &DbBackend) {
        let (Some(flow_id), Some(plugin_kind)) = (self.flow_table.selected_id, self.selected_plugin)
        else {
            return;
        };

        let plugin = plugin_kind.create();
        let required = plugin.required_series();

        let Some(flow) = db.get_flow_by_id(flow_id) else {
            self.status = "Error: flow not found".to_string();
            return;
        };

        let series_ids = match db.find_series_ids_by_name(&flow, &required) {
            Ok(ids) => ids,
            Err(e) => {
                self.status = format!("Error: {}", e);
                return;
            }
        };

        let colors = generate_colors(series_ids.len());
        let (x_min, x_max) = db.get_flow_x_bounds(flow_id).unwrap_or((0.0, 1.0));

        self.input_series.clear();
        for (i, &sid) in series_ids.iter().enumerate() {
            let Some(ts) = db.get_series_by_id(sid) else { continue };
            let (y_min, y_max) = db.get_series_y_bounds(&[sid]).unwrap_or((0.0, 1.0));
            let color = colors.get(i).copied().unwrap_or(egui::Color32::WHITE);
            let mut sd = SeriesData::new(
                ts.name.clone(),
                sid,
                ts.ts_type.clone(),
                x_min,
                x_max,
                y_min,
                y_max,
                color,
            );
            // Load raw data for plugin computation
            sd.raw_data = db.load_all(sid);
            // Also load points for visualisation
            sd.points = sd.raw_data.iter()
                .filter_map(|(t, v)| crate::backend::db::datavalue_as_f64(v).map(|f| (*t, f)))
                .collect();
            sd.loaded_range = Some((x_min, x_max));
            self.input_series.push(sd);
        }

        match plugin.compute(&self.input_series) {
            Ok(results) => {
                self.preview_series = results;
                self.status = format!(
                    "OK — {} new series computed.",
                    self.preview_series.len()
                );
            }
            Err(e) => {
                self.status = format!("Error: {}", e);
            }
        }
    }

    fn save_results(&mut self, db: &DbBackend) {
        let Some(flow_id) = self.flow_table.selected_id else { return };
        let Some(flow) = db.get_flow_by_id(flow_id) else {
            self.save_status = "Error: flow not found".to_string();
            return;
        };

        let mut saved = 0;
        let mut errors = Vec::new();
        for series in &self.preview_series {
            match db.create_series_for_flow(&flow, series) {
                Ok(()) => saved += 1,
                Err(e) => errors.push(e),
            }
        }

        self.save_status = if errors.is_empty() {
            format!("Saved {} series to database.", saved)
        } else {
            format!("Saved {}, errors: {}", saved, errors.join("; "))
        };
    }
}
