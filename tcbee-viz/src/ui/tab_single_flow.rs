use egui::{RichText, ScrollArea};
use egui_plot::{Legend, Line, Plot, PlotBounds, PlotPoint, PlotPoints, Text};

use crate::{
    backend::db::DbBackend,
    data::plot_state::PlotState,
    settings::AppSettings,
    ui::{flow_table::FlowTable, series_table::SeriesTable},
};

pub struct TabSingleFlow {
    state: PlotState,
    flow_table: FlowTable,
    series_table: SeriesTable,
    manual_x_min: f64,
    manual_x_max: f64,
    apply_manual_x: bool,
    needs_fit: bool,
}

impl Default for TabSingleFlow {
    fn default() -> Self {
        Self {
            state: PlotState::default(),
            flow_table: FlowTable::default(),
            series_table: SeriesTable::default(),
            manual_x_min: 0.0,
            manual_x_max: 1.0,
            apply_manual_x: false,
            needs_fit: false,
        }
    }
}

impl TabSingleFlow {
    pub fn reset(&mut self) {
        self.state.reset();
        self.flow_table.reset();
        self.series_table.reset();
        self.manual_x_min = 0.0;
        self.manual_x_max = 1.0;
        self.apply_manual_x = false;
        self.needs_fit = false;
    }

    pub fn show(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if !db.is_connected() {
            ui.centered_and_justified(|ui| {
                ui.label("No database loaded. Go to Home and select a database file.");
            });
            return;
        }

        egui::SidePanel::left("single_flow_sidebar")
            .resizable(true)
            .min_width(240.0)
            .max_width(500.0)
            .show_inside(ui, |ui| {
                self.show_sidebar(ui, db, settings);
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            self.show_plot_area(ui, db, settings);
        });
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        // ── Flow table ──────────────────────────────────────────────────
        ui.add_space(4.0);
        section_heading(ui, "Flow Selection");

        let flows = db.list_flows();
        if flows.is_empty() {
            ui.label(RichText::new("No flows found in database.").color(egui::Color32::GRAY));
        } else {
            // Reserve space for flow table — takes up top half of sidebar
            let table_height = (ui.available_height() * 0.45).max(120.0);
            egui::Frame::none().show(ui, |ui| {
                ui.set_max_height(table_height);
                if let Some(new_id) = self.flow_table.show(ui, &flows) {
                    self.state.select_flow(db, new_id);
                    self.manual_x_min = self.state.data_x_min;
                    self.manual_x_max = self.state.data_x_max;
                    self.needs_fit = true;
                }
            });
        }

        if self.state.flow_id.is_none() {
            ui.add_space(8.0);
            ui.label(RichText::new("← Select a flow above.").color(egui::Color32::GRAY).italics());
            return;
        }

        ui.add_space(10.0);
        ui.separator();

        // ── Metrics ─────────────────────────────────────────────────────
        section_heading(ui, "Metrics");

        let available = self.state.available_series.clone();
        if available.is_empty() {
            ui.label(RichText::new("No time series in this flow.").color(egui::Color32::GRAY));
        } else {
            let selected_ids = self.state.selected_series_ids.clone();
            let colors: Vec<(i64, egui::Color32)> =
                self.state.series.iter().map(|s| (s.series_id, s.color)).collect();

            let metrics_height = (ui.available_height() - 120.0).max(80.0);
            egui::Frame::none().show(ui, |ui| {
                ui.set_max_height(metrics_height);
                if let Some(toggled_id) =
                    self.series_table.show(ui, &available, &selected_ids, &colors)
                {
                    self.state.toggle_series(db, toggled_id, settings);
                    self.needs_fit = true;
                }
            });
        }

        ui.add_space(10.0);
        ui.separator();

        // ── View options ─────────────────────────────────────────────────
        section_heading(ui, "View");

        if ui.checkbox(&mut self.state.split_view, "Split into separate plots").changed() {
            self.needs_fit = true;
        }

        ui.add_space(8.0);
        ui.label(RichText::new("X range").strong().size(12.0));

        egui::Grid::new("x_range_grid").num_columns(2).spacing([6.0, 4.0]).show(ui, |ui| {
            ui.label("Min:");
            ui.add(egui::DragValue::new(&mut self.manual_x_min).speed(0.1));
            ui.end_row();
            ui.label("Max:");
            ui.add(egui::DragValue::new(&mut self.manual_x_max).speed(0.1));
            ui.end_row();
        });

        ui.horizontal(|ui| {
            if ui.button("Apply").clicked() {
                self.apply_manual_x = true;
            }
            if ui.button("Reset zoom").clicked() {
                self.manual_x_min = self.state.data_x_min;
                self.manual_x_max = self.state.data_x_max;
                self.apply_manual_x = true;
            }
        });
    }

    fn show_plot_area(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if self.state.series.is_empty() {
            ui.centered_and_justified(|ui| {
                if self.state.flow_id.is_none() {
                    ui.label(RichText::new("Select a flow from the sidebar.").color(egui::Color32::GRAY));
                } else {
                    ui.label(RichText::new("Select metrics to display.").color(egui::Color32::GRAY));
                }
            });
            return;
        }

        let has_string = self.state.series.iter().any(|s| s.is_string_type());
        let split_view = self.state.split_view;

        if split_view {
            self.show_split_plots(ui, db, settings);
        } else {
            self.show_combined_plot(ui, db, settings);
        }

        if has_string {
            let string_data: Vec<(String, egui::Color32, Vec<(f64, String)>)> = self
                .state
                .series
                .iter()
                .filter(|s| s.is_string_type())
                .map(|s| (s.name.clone(), s.color, s.string_points.clone()))
                .collect();

            ui.separator();
            ui.label(RichText::new("String series (events):").strong());
            ScrollArea::vertical().id_salt("string_series_scroll").max_height(120.0).show(
                ui,
                |ui| {
                    for (name, color, points) in &string_data {
                        ui.label(RichText::new(name).color(*color).strong());
                        for (t, val) in points {
                            ui.label(format!("  t={:.4}  {}", t, val));
                        }
                    }
                },
            );
        }
    }

    fn show_combined_plot(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let apply_x = self.apply_manual_x;
        let x_min = self.manual_x_min;
        let x_max = self.manual_x_max;
        self.apply_manual_x = false;

        let fit = std::mem::take(&mut self.needs_fit);
        let fit_x_min = self.state.data_x_min;
        let fit_x_max = self.state.data_x_max;
        let (fit_y_min, fit_y_max) = self.state.y_bounds();

        let display: Vec<(Vec<[f64; 2]>, egui::Color32, String)> = self
            .state
            .series
            .iter()
            .filter(|s| !s.is_string_type())
            .map(|s| (to_plot_points(&s.points), s.color, s.name.clone()))
            .collect();

        let plot = Plot::new("single_combined")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .legend(Legend::default())
            .height(ui.available_height());

        let mut new_x_min = self.state.x_min;
        let mut new_x_max = self.state.x_max;
        let mut needs_reload = false;

        let plot_response = plot.show(ui, |plot_ui| {
            if fit {
                plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                    [fit_x_min, fit_y_min],
                    [fit_x_max, fit_y_max],
                ));
                // Skip needs_reload: toggle_series already loaded data for the full
                // range and set_plot_bounds hasn't propagated to plot_bounds() yet.
            } else {
                if apply_x {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [x_min, f64::NEG_INFINITY],
                        [x_max, f64::INFINITY],
                    ));
                }
                let bounds = plot_ui.plot_bounds();
                let vx_min = bounds.min()[0];
                let vx_max = bounds.max()[0];
                if self.state.needs_reload(vx_min, vx_max) {
                    new_x_min = vx_min;
                    new_x_max = vx_max;
                    needs_reload = true;
                }
            }

            for (pts, color, name) in &display {
                plot_ui.line(
                    Line::new(PlotPoints::from(pts.clone())).color(*color).name(name),
                );
            }
        });

        if plot_response.response.secondary_clicked() {
            self.needs_fit = true;
        }

        if needs_reload {
            self.state.x_min = new_x_min;
            self.state.x_max = new_x_max;
            self.state.reload_visible_data(db, settings);
        }
    }

    fn show_split_plots(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let apply_x = self.apply_manual_x;
        let x_min = self.manual_x_min;
        let x_max = self.manual_x_max;
        self.apply_manual_x = false;

        let fit = std::mem::take(&mut self.needs_fit);
        let fit_x_min = self.state.data_x_min;
        let fit_x_max = self.state.data_x_max;

        // Include global y bounds per series for explicit fit.
        let display: Vec<(i64, Vec<[f64; 2]>, egui::Color32, String, f64, f64)> = self
            .state
            .series
            .iter()
            .filter(|s| !s.is_string_type())
            .map(|s| {
                (s.series_id, to_plot_points(&s.points), s.color, s.name.clone(),
                 s.global_y_min, s.global_y_max)
            })
            .collect();

        let plot_height = (ui.available_height() / display.len().max(1) as f32).max(80.0);

        let mut needs_reload = false;
        let mut new_x_min = self.state.x_min;
        let mut new_x_max = self.state.x_max;
        let mut right_clicked = false;

        ScrollArea::vertical().id_salt("split_scroll").show(ui, |ui| {
            for (sid, pts, color, name, y_min, y_max) in &display {
                ui.label(RichText::new(name).color(*color).strong());

                let plot = Plot::new(format!("split_{}", sid))
                    .allow_boxed_zoom(true)
                    .allow_drag(true)
                    .allow_scroll(true)
                    .link_axis("single_x_axis", [true, false])
                    .height(plot_height);

                let pr = plot.show(ui, |plot_ui| {
                    if fit {
                        // Fit both axes; skip needs_reload for same reason as combined view.
                        let pad = (y_max - y_min).abs() * 0.05;
                        plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                            [fit_x_min, y_min - pad],
                            [fit_x_max, y_max + pad],
                        ));
                    } else {
                        if apply_x {
                            let cur = plot_ui.plot_bounds();
                            plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                                [x_min, cur.min()[1]],
                                [x_max, cur.max()[1]],
                            ));
                        }
                        let bounds = plot_ui.plot_bounds();
                        let vx_min = bounds.min()[0];
                        let vx_max = bounds.max()[0];
                        if self.state.needs_reload(vx_min, vx_max) {
                            new_x_min = vx_min;
                            new_x_max = vx_max;
                            needs_reload = true;
                        }
                    }

                    plot_ui.line(
                        Line::new(PlotPoints::from(pts.clone())).color(*color).name(name),
                    );

                    // Show DB y bounds in the lower-right corner for debugging.
                    let vb = plot_ui.plot_bounds();
                    plot_ui.text(
                        Text::new(
                            PlotPoint::new(vb.max()[0], vb.min()[1]),
                            format!("DB y: [{:.4}, {:.4}]", y_min, y_max),
                        )
                        .anchor(egui::Align2::RIGHT_BOTTOM)
                        .color(egui::Color32::from_gray(150)),
                    );
                });

                if pr.response.secondary_clicked() {
                    right_clicked = true;
                }

                ui.add_space(4.0);
            }
        });

        if right_clicked {
            self.needs_fit = true;
        }

        if needs_reload {
            self.state.x_min = new_x_min;
            self.state.x_max = new_x_max;
            self.state.reload_visible_data(db, settings);
        }
    }
}

/// Convert (f64, f64) pairs to egui_plot's expected [f64; 2] arrays.
pub fn to_plot_points(pts: &[(f64, f64)]) -> Vec<[f64; 2]> {
    pts.iter().map(|&(x, y)| [x, y]).collect()
}

fn section_heading(ui: &mut egui::Ui, label: &str) {
    ui.label(RichText::new(label).strong().size(13.0));
    ui.add_space(2.0);
}
