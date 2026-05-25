use egui::RichText;
use egui_plot::{Legend, Line, Plot, PlotBounds, PlotPoints};
use ts_storage::Flow;

use crate::{
    backend::db::DbBackend,
    data::plot_state::PlotState,
    settings::AppSettings,
    ui::{flow_table::FlowTable, series_table::SeriesTable, tab_single_flow::to_plot_points},
};

pub struct TabMultiFlow {
    state_a: PlotState,
    state_b: PlotState,
    table_a: FlowTable,
    table_b: FlowTable,
    series_table_a: SeriesTable,
    series_table_b: SeriesTable,
    merged_view: bool,
    manual_x_min: f64,
    manual_x_max: f64,
    apply_manual_x: bool,
}

impl Default for TabMultiFlow {
    fn default() -> Self {
        Self {
            state_a: PlotState::default(),
            state_b: PlotState::default(),
            table_a: FlowTable::default(),
            table_b: FlowTable::default(),
            series_table_a: SeriesTable::default(),
            series_table_b: SeriesTable::default(),
            merged_view: true,
            manual_x_min: 0.0,
            manual_x_max: 1.0,
            apply_manual_x: false,
        }
    }
}

impl TabMultiFlow {
    pub fn reset(&mut self) {
        self.state_a.reset();
        self.state_b.reset();
        self.table_a.reset();
        self.table_b.reset();
        self.series_table_a.reset();
        self.series_table_b.reset();
        self.merged_view = true;
        self.manual_x_min = 0.0;
        self.manual_x_max = 1.0;
        self.apply_manual_x = false;
    }

    pub fn show(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if !db.is_connected() {
            ui.centered_and_justified(|ui| {
                ui.label("No database loaded. Go to Home and select a database file.");
            });
            return;
        }

        egui::SidePanel::left("multi_flow_sidebar")
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
        let flows = db.list_flows();
        let half_h = ((ui.available_height() - 120.0) / 2.0).max(80.0);

        // ── Flow A ───────────────────────────────────────────────────────
        flow_section(
            ui,
            "Flow A",
            egui::Color32::from_rgb(70, 130, 200),
            &mut self.table_a,
            &mut self.series_table_a,
            &mut self.state_a,
            &flows,
            db,
            settings,
            half_h,
        );

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);

        // ── Flow B ───────────────────────────────────────────────────────
        flow_section(
            ui,
            "Flow B",
            egui::Color32::from_rgb(200, 100, 60),
            &mut self.table_b,
            &mut self.series_table_b,
            &mut self.state_b,
            &flows,
            db,
            settings,
            half_h,
        );

        ui.add_space(8.0);
        ui.separator();

        // ── View ─────────────────────────────────────────────────────────
        ui.label(RichText::new("View").strong().size(13.0));
        ui.add_space(2.0);
        ui.checkbox(&mut self.merged_view, "Merge into one plot");

        ui.add_space(6.0);
        ui.label(RichText::new("X range").strong().size(12.0));
        egui::Grid::new("multi_x_range").num_columns(2).spacing([6.0, 4.0]).show(ui, |ui| {
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
                let x_min = self.state_a.data_x_min.min(self.state_b.data_x_min);
                let x_max = self.state_a.data_x_max.max(self.state_b.data_x_max);
                self.manual_x_min = x_min;
                self.manual_x_max = x_max;
                self.apply_manual_x = true;
            }
        });
    }

    fn show_plot_area(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let has_data = !self.state_a.series.is_empty() || !self.state_b.series.is_empty();
        if !has_data {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Select flows and metrics from the sidebar.").color(egui::Color32::GRAY));
            });
            return;
        }

        if self.merged_view {
            self.show_merged_plot(ui, db, settings);
        } else {
            self.show_split_plots(ui, db, settings);
        }
    }

    fn show_merged_plot(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let apply_x = self.apply_manual_x;
        let x_min = self.manual_x_min;
        let x_max = self.manual_x_max;
        self.apply_manual_x = false;

        let display_a = series_display(&self.state_a.series, "A:");
        let display_b = series_display(&self.state_b.series, "B:");

        let mut reload_a = false;
        let mut reload_b = false;
        let mut new_x_min = self.state_a.x_min;
        let mut new_x_max = self.state_a.x_max;

        Plot::new("multi_merged")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .legend(Legend::default())
            .height(ui.available_height())
            .show(ui, |plot_ui| {
                if apply_x {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [x_min, f64::NEG_INFINITY],
                        [x_max, f64::INFINITY],
                    ));
                }
                let bounds = plot_ui.plot_bounds();
                let vx_min = bounds.min()[0];
                let vx_max = bounds.max()[0];

                if self.state_a.needs_reload(vx_min, vx_max) {
                    reload_a = true;
                    new_x_min = vx_min;
                    new_x_max = vx_max;
                }
                if self.state_b.needs_reload(vx_min, vx_max) {
                    reload_b = true;
                    new_x_min = vx_min;
                    new_x_max = vx_max;
                }

                for (pts, color, name) in &display_a {
                    plot_ui.line(Line::new(PlotPoints::from(pts.clone())).color(*color).name(name));
                }
                for (pts, color, name) in &display_b {
                    plot_ui.line(Line::new(PlotPoints::from(pts.clone())).color(*color).name(name));
                }
            });

        if reload_a {
            self.state_a.x_min = new_x_min;
            self.state_a.x_max = new_x_max;
            self.state_a.reload_visible_data(db, settings);
        }
        if reload_b {
            self.state_b.x_min = new_x_min;
            self.state_b.x_max = new_x_max;
            self.state_b.reload_visible_data(db, settings);
        }
    }

    fn show_split_plots(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let apply_x = self.apply_manual_x;
        let x_min = self.manual_x_min;
        let x_max = self.manual_x_max;
        self.apply_manual_x = false;

        let half_height = (ui.available_height() / 2.0).max(80.0);
        let display_a = series_display(&self.state_a.series, "");
        let display_b = series_display(&self.state_b.series, "");
        let label_a = self.state_a.flow_label.clone();
        let label_b = self.state_b.flow_label.clone();

        let mut reload_a = false;
        let mut reload_b = false;
        let mut new_x_a = (self.state_a.x_min, self.state_a.x_max);
        let mut new_x_b = (self.state_b.x_min, self.state_b.x_max);

        ui.label(RichText::new(format!("Flow A: {}", label_a)).strong());
        Plot::new("multi_split_a")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .link_axis("multi_x_axis", [true, false])
            .legend(Legend::default())
            .height(half_height)
            .show(ui, |plot_ui| {
                if apply_x {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [x_min, f64::NEG_INFINITY],
                        [x_max, f64::INFINITY],
                    ));
                }
                let bounds = plot_ui.plot_bounds();
                let (vx_min, vx_max) = (bounds.min()[0], bounds.max()[0]);
                if self.state_a.needs_reload(vx_min, vx_max) {
                    reload_a = true;
                    new_x_a = (vx_min, vx_max);
                }
                for (pts, color, name) in &display_a {
                    plot_ui.line(Line::new(PlotPoints::from(pts.clone())).color(*color).name(name));
                }
            });

        ui.add_space(4.0);

        ui.label(RichText::new(format!("Flow B: {}", label_b)).strong());
        Plot::new("multi_split_b")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .link_axis("multi_x_axis", [true, false])
            .legend(Legend::default())
            .height(half_height)
            .show(ui, |plot_ui| {
                if apply_x {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [x_min, f64::NEG_INFINITY],
                        [x_max, f64::INFINITY],
                    ));
                }
                let bounds = plot_ui.plot_bounds();
                let (vx_min, vx_max) = (bounds.min()[0], bounds.max()[0]);
                if self.state_b.needs_reload(vx_min, vx_max) {
                    reload_b = true;
                    new_x_b = (vx_min, vx_max);
                }
                for (pts, color, name) in &display_b {
                    plot_ui.line(Line::new(PlotPoints::from(pts.clone())).color(*color).name(name));
                }
            });

        if reload_a {
            (self.state_a.x_min, self.state_a.x_max) = new_x_a;
            self.state_a.reload_visible_data(db, settings);
        }
        if reload_b {
            (self.state_b.x_min, self.state_b.x_max) = new_x_b;
            self.state_b.reload_visible_data(db, settings);
        }
    }
}

fn series_display(
    series: &[crate::data::series_data::SeriesData],
    prefix: &str,
) -> Vec<(Vec<[f64; 2]>, egui::Color32, String)> {
    series
        .iter()
        .filter(|s| !s.is_string_type())
        .map(|s| {
            let pts = to_plot_points(&s.points);
            let name = format!("{}{}", prefix, s.name);
            (pts, s.color, name)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn flow_section(
    ui: &mut egui::Ui,
    title: &str,
    accent: egui::Color32,
    flow_table: &mut FlowTable,
    series_table: &mut SeriesTable,
    state: &mut PlotState,
    flows: &[Flow],
    db: &DbBackend,
    settings: &AppSettings,
    table_height: f32,
) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 16.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 2.0, accent);
        ui.add_space(4.0);
        ui.label(RichText::new(title).strong().size(13.0).color(accent));
    });
    ui.add_space(2.0);

    if flows.is_empty() {
        ui.label(RichText::new("No flows found.").color(egui::Color32::GRAY));
        return;
    }

    egui::Frame::none().show(ui, |ui| {
        ui.set_max_height(table_height * 0.45);
        if let Some(new_id) = flow_table.show(ui, flows) {
            state.select_flow(db, new_id);
        }
    });

    if state.flow_id.is_none() {
        return;
    }

    ui.add_space(4.0);
    ui.label(RichText::new("Metrics").size(12.0).color(egui::Color32::DARK_GRAY));

    let available = state.available_series.clone();
    let selected_ids = state.selected_series_ids.clone();
    let colors: Vec<(i64, egui::Color32)> =
        state.series.iter().map(|s| (s.series_id, s.color)).collect();

    let metrics_height = (table_height * 0.5).max(80.0);
    egui::Frame::none().show(ui, |ui| {
        ui.set_max_height(metrics_height);
        if let Some(toggled_id) = series_table.show(ui, &available, &selected_ids, &colors) {
            state.toggle_series(db, toggled_id, settings);
        }
    });
}
