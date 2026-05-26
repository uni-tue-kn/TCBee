use egui::{RichText, ScrollArea};
use egui_plot::{Legend, Line, Plot, PlotBounds, PlotPoints};
use ts_storage::Flow;

use crate::{
    backend::db::DbBackend,
    data::{plot_state::PlotState, series_data::SeriesData},
    settings::AppSettings,
    ui::{
        flow_table::FlowTable,
        series_table::SeriesTable,
        tab_single_flow::{
            compact_axis_label, compact_coordinates_formatter, plot_height_with_footer,
            seconds_grid_spacer, seconds_since_formatter, split_plot_height_with_footer,
            to_plot_points,
        },
    },
};

type PlotDataBounds = ((f64, f64), (f64, f64));

pub struct TabMultiFlow {
    state_a: PlotState,
    state_b: PlotState,
    table_a: FlowTable,
    table_b: FlowTable,
    series_table_a: SeriesTable,
    series_table_b: SeriesTable,
    merged_view: bool,
    split_series_view: bool,
    drop_initial_points: bool,
    manual_x_min: f64,
    manual_x_max: f64,
    apply_manual_x: bool,
    needs_fit: bool,
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
            split_series_view: false,
            drop_initial_points: false,
            manual_x_min: 0.0,
            manual_x_max: 1.0,
            apply_manual_x: false,
            needs_fit: false,
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
        self.split_series_view = false;
        self.drop_initial_points = false;
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

        egui::SidePanel::left("multi_flow_sidebar")
            .resizable(true)
            .min_width(240.0)
            .max_width(500.0)
            .show_inside(ui, |ui| {
                let sidebar_height = ui.available_height();
                ScrollArea::vertical()
                    .id_salt("multi_flow_sidebar_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.show_sidebar(ui, db, settings, sidebar_height);
                    });
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            self.show_plot_area(ui, db, settings);
        });
    }

    fn show_sidebar(
        &mut self,
        ui: &mut egui::Ui,
        db: &DbBackend,
        settings: &AppSettings,
        sidebar_height: f32,
    ) {
        let flows = db.list_flows();
        let half_h = ((sidebar_height - 180.0) / 2.0).max(120.0);

        // ── Flow A ───────────────────────────────────────────────────────
        if flow_section(
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
        ) {
            self.needs_fit = true;
        }

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);

        // ── Flow B ───────────────────────────────────────────────────────
        if flow_section(
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
        ) {
            self.needs_fit = true;
        }

        ui.add_space(8.0);
        ui.separator();

        // ── View ─────────────────────────────────────────────────────────
        ui.label(RichText::new("View").strong().size(13.0));
        ui.add_space(2.0);
        if ui
            .checkbox(&mut self.merged_view, "Merge into one plot")
            .changed()
        {
            self.needs_fit = true;
        }
        if ui
            .checkbox(
                &mut self.split_series_view,
                "Split selected metrics into separate plots",
            )
            .changed()
        {
            self.needs_fit = true;
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let tooltip = "Values like CWND or SEQ can have large initial values. This removes them and fixes plots such as CWND.";
            if ui
                .checkbox(&mut self.drop_initial_points, "Drop first 5 points")
                .on_hover_text(tooltip)
                .changed()
            {
                self.needs_fit = true;
            }
            ui.add_sized(
                [18.0, 18.0],
                egui::Label::new(RichText::new("?").strong()).sense(egui::Sense::hover()),
            )
            .on_hover_text(tooltip);
        });

        ui.add_space(6.0);
        ui.label(RichText::new("X range").strong().size(12.0));
        egui::Grid::new("multi_x_range")
            .num_columns(2)
            .spacing([6.0, 4.0])
            .show(ui, |ui| {
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
                ui.label(
                    RichText::new("Select flows and metrics from the sidebar.")
                        .color(egui::Color32::GRAY),
                );
            });
            return;
        }

        let plot_width_px = ui.available_width().max(1.0);
        self.state_a
            .reload_if_sampling_changed(db, settings, plot_width_px);
        self.state_b
            .reload_if_sampling_changed(db, settings, plot_width_px);

        if self.split_series_view {
            self.show_series_split_plots(ui, db, settings);
        } else if self.merged_view {
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
        let fit = std::mem::take(&mut self.needs_fit);

        let display_a = series_display(&self.state_a.series, "A:", self.drop_initial_points);
        let display_b = series_display(&self.state_b.series, "B:", self.drop_initial_points);
        let x_origin = merged_x_origin(&self.state_a, &self.state_b);
        let ((fit_x_min, fit_x_max), (fit_y_min, fit_y_max)) =
            merged_display_bounds(&display_a, &display_b).unwrap_or((
                selected_x_bounds(&self.state_a, &self.state_b),
                merged_y_bounds(&self.state_a, &self.state_b),
            ));

        let mut reload_a = false;
        let mut reload_b = false;
        let mut new_x_min = self.state_a.x_min;
        let mut new_x_max = self.state_a.x_max;

        let plot_response = Plot::new("multi_merged")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .x_grid_spacer(seconds_grid_spacer(x_origin))
            .x_axis_formatter(seconds_since_formatter(x_origin))
            .y_axis_formatter(|mark, _| compact_axis_label(mark.value))
            .coordinates_formatter(
                egui_plot::Corner::LeftBottom,
                compact_coordinates_formatter(x_origin),
            )
            .legend(Legend::default())
            .height(plot_height_with_footer(ui.available_height()))
            .show(ui, |plot_ui| {
                if fit {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [fit_x_min, fit_y_min],
                        [fit_x_max, fit_y_max],
                    ));
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
                }

                for (pts, color, name) in &display_a {
                    plot_ui.line(
                        Line::new(PlotPoints::from(pts.clone()))
                            .color(*color)
                            .name(name),
                    );
                }
                for (pts, color, name) in &display_b {
                    plot_ui.line(
                        Line::new(PlotPoints::from(pts.clone()))
                            .color(*color)
                            .name(name),
                    );
                }
            });

        if plot_response.response.secondary_clicked() {
            self.needs_fit = true;
        }

        if reload_a {
            self.state_a.x_min = new_x_min;
            self.state_a.x_max = new_x_max;
            self.state_a
                .reload_visible_data(db, settings, Some(ui.available_width().max(1.0)));
        }
        if reload_b {
            self.state_b.x_min = new_x_min;
            self.state_b.x_max = new_x_max;
            self.state_b
                .reload_visible_data(db, settings, Some(ui.available_width().max(1.0)));
        }
    }

    fn show_split_plots(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let apply_x = self.apply_manual_x;
        let x_min = self.manual_x_min;
        let x_max = self.manual_x_max;
        self.apply_manual_x = false;
        let fit = std::mem::take(&mut self.needs_fit);

        let half_height = split_plot_height_with_footer(ui.available_height(), 2);
        let display_a = series_display(&self.state_a.series, "", self.drop_initial_points);
        let display_b = series_display(&self.state_b.series, "", self.drop_initial_points);
        let label_a = self.state_a.flow_label.clone();
        let label_b = self.state_b.flow_label.clone();
        let x_origin = merged_x_origin(&self.state_a, &self.state_b);
        let (fit_x_min, fit_x_max) = selected_x_bounds(&self.state_a, &self.state_b);
        let (_, (fit_y_a_min, fit_y_a_max)) =
            display_bounds(&display_a).unwrap_or(((fit_x_min, fit_x_max), self.state_a.y_bounds()));
        let (_, (fit_y_b_min, fit_y_b_max)) =
            display_bounds(&display_b).unwrap_or(((fit_x_min, fit_x_max), self.state_b.y_bounds()));

        let mut reload_a = false;
        let mut reload_b = false;
        let mut new_x_a = (self.state_a.x_min, self.state_a.x_max);
        let mut new_x_b = (self.state_b.x_min, self.state_b.x_max);

        ui.label(RichText::new(format!("Flow A: {}", label_a)).strong());
        let response_a = Plot::new("multi_split_a")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .link_axis("multi_x_axis", [true, false])
            .x_grid_spacer(seconds_grid_spacer(x_origin))
            .x_axis_formatter(seconds_since_formatter(x_origin))
            .y_axis_formatter(|mark, _| compact_axis_label(mark.value))
            .coordinates_formatter(
                egui_plot::Corner::LeftBottom,
                compact_coordinates_formatter(x_origin),
            )
            .legend(Legend::default())
            .height(half_height)
            .show(ui, |plot_ui| {
                if fit {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [fit_x_min, fit_y_a_min],
                        [fit_x_max, fit_y_a_max],
                    ));
                } else {
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
                }
                for (pts, color, name) in &display_a {
                    plot_ui.line(
                        Line::new(PlotPoints::from(pts.clone()))
                            .color(*color)
                            .name(name),
                    );
                }
            });

        ui.add_space(4.0);

        ui.label(RichText::new(format!("Flow B: {}", label_b)).strong());
        let response_b = Plot::new("multi_split_b")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .link_axis("multi_x_axis", [true, false])
            .x_grid_spacer(seconds_grid_spacer(x_origin))
            .x_axis_formatter(seconds_since_formatter(x_origin))
            .y_axis_formatter(|mark, _| compact_axis_label(mark.value))
            .coordinates_formatter(
                egui_plot::Corner::LeftBottom,
                compact_coordinates_formatter(x_origin),
            )
            .legend(Legend::default())
            .height(half_height)
            .show(ui, |plot_ui| {
                if fit {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [fit_x_min, fit_y_b_min],
                        [fit_x_max, fit_y_b_max],
                    ));
                } else {
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
                }
                for (pts, color, name) in &display_b {
                    plot_ui.line(
                        Line::new(PlotPoints::from(pts.clone()))
                            .color(*color)
                            .name(name),
                    );
                }
            });

        if response_a.response.secondary_clicked() || response_b.response.secondary_clicked() {
            self.needs_fit = true;
        }

        if reload_a {
            (self.state_a.x_min, self.state_a.x_max) = new_x_a;
            self.state_a
                .reload_visible_data(db, settings, Some(ui.available_width().max(1.0)));
        }
        if reload_b {
            (self.state_b.x_min, self.state_b.x_max) = new_x_b;
            self.state_b
                .reload_visible_data(db, settings, Some(ui.available_width().max(1.0)));
        }
    }

    fn show_series_split_plots(
        &mut self,
        ui: &mut egui::Ui,
        db: &DbBackend,
        settings: &AppSettings,
    ) {
        let apply_x = self.apply_manual_x;
        let x_min = self.manual_x_min;
        let x_max = self.manual_x_max;
        self.apply_manual_x = false;
        let fit = std::mem::take(&mut self.needs_fit);

        let display = split_series_display(
            &self.state_a.series,
            &self.state_b.series,
            self.drop_initial_points,
        );
        if display.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Select numeric metrics to display.").color(egui::Color32::GRAY),
                );
            });
            return;
        }

        let plot_height = split_plot_height_with_footer(ui.available_height(), display.len());
        let x_origin = merged_x_origin(&self.state_a, &self.state_b);
        let (fit_x_min, fit_x_max) = selected_x_bounds(&self.state_a, &self.state_b);

        let mut reload_a = false;
        let mut reload_b = false;
        let mut new_x_a = (self.state_a.x_min, self.state_a.x_max);
        let mut new_x_b = (self.state_b.x_min, self.state_b.x_max);
        let mut right_clicked = false;

        ScrollArea::vertical()
            .id_salt("multi_series_split_scroll")
            .show(ui, |ui| {
                for item in &display {
                    ui.label(RichText::new(&item.name).color(item.color).strong());

                    let plot_response = Plot::new(format!(
                        "multi_series_split_{}_{}",
                        item.flow_prefix, item.series_id
                    ))
                    .allow_boxed_zoom(true)
                    .allow_drag(true)
                    .allow_scroll(true)
                    .link_axis("multi_series_split_x_axis", [true, false])
                    .x_grid_spacer(seconds_grid_spacer(x_origin))
                    .x_axis_formatter(seconds_since_formatter(x_origin))
                    .y_axis_formatter(|mark, _| compact_axis_label(mark.value))
                    .coordinates_formatter(
                        egui_plot::Corner::LeftBottom,
                        compact_coordinates_formatter(x_origin),
                    )
                    .height(plot_height)
                    .show(ui, |plot_ui| {
                        if fit {
                            plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                                [fit_x_min, item.y_min],
                                [fit_x_max, item.y_max],
                            ));
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
                            if self.state_a.needs_reload(vx_min, vx_max) {
                                reload_a = true;
                                new_x_a = (vx_min, vx_max);
                            }
                            if self.state_b.needs_reload(vx_min, vx_max) {
                                reload_b = true;
                                new_x_b = (vx_min, vx_max);
                            }
                        }

                        plot_ui.line(
                            Line::new(PlotPoints::from(item.points.clone()))
                                .color(item.color)
                                .name(&item.name),
                        );
                    });

                    if plot_response.response.secondary_clicked() {
                        right_clicked = true;
                    }

                    ui.add_space(4.0);
                }
            });

        if right_clicked {
            self.needs_fit = true;
        }

        if reload_a {
            (self.state_a.x_min, self.state_a.x_max) = new_x_a;
            self.state_a
                .reload_visible_data(db, settings, Some(ui.available_width().max(1.0)));
        }
        if reload_b {
            (self.state_b.x_min, self.state_b.x_max) = new_x_b;
            self.state_b
                .reload_visible_data(db, settings, Some(ui.available_width().max(1.0)));
        }
    }
}

fn merged_x_origin(state_a: &PlotState, state_b: &PlotState) -> f64 {
    match (state_a.flow_id, state_b.flow_id) {
        (Some(_), Some(_)) => state_a.data_x_min.min(state_b.data_x_min),
        (Some(_), None) => state_a.data_x_min,
        (None, Some(_)) => state_b.data_x_min,
        (None, None) => 0.0,
    }
}

struct SplitSeriesDisplay {
    flow_prefix: &'static str,
    series_id: i64,
    points: Vec<[f64; 2]>,
    color: egui::Color32,
    name: String,
    y_min: f64,
    y_max: f64,
}

fn series_display(
    series: &[SeriesData],
    prefix: &str,
    drop_initial_points: bool,
) -> Vec<(Vec<[f64; 2]>, egui::Color32, String)> {
    series
        .iter()
        .filter(|s| !s.is_string_type())
        .map(|s| {
            let pts = to_plot_points(points_after_initial_drop(&s.points, drop_initial_points));
            let name = format!("{}{}", prefix, s.name);
            (pts, s.color, name)
        })
        .collect()
}

fn split_series_display(
    series_a: &[SeriesData],
    series_b: &[SeriesData],
    drop_initial_points: bool,
) -> Vec<SplitSeriesDisplay> {
    series_a
        .iter()
        .filter(|s| !s.is_string_type())
        .map(|s| split_series_item(s, "A", drop_initial_points))
        .chain(
            series_b
                .iter()
                .filter(|s| !s.is_string_type())
                .map(|s| split_series_item(s, "B", drop_initial_points)),
        )
        .collect()
}

fn split_series_item(
    series: &SeriesData,
    flow_prefix: &'static str,
    drop_initial_points: bool,
) -> SplitSeriesDisplay {
    let points = to_plot_points(points_after_initial_drop(
        &series.points,
        drop_initial_points,
    ));
    let (_, (y_min, y_max)) = points_bounds(&points).unwrap_or((
        (series.global_t_min, series.global_t_max),
        (series.global_y_min, series.global_y_max),
    ));

    SplitSeriesDisplay {
        flow_prefix,
        series_id: series.series_id,
        points,
        color: series.color,
        name: format!("{}:{}", flow_prefix, series.name),
        y_min,
        y_max,
    }
}

fn points_after_initial_drop(pts: &[(f64, f64)], drop_initial_points: bool) -> &[(f64, f64)] {
    if drop_initial_points {
        pts.get(5..).unwrap_or(&[])
    } else {
        pts
    }
}

fn merged_display_bounds(
    display_a: &[(Vec<[f64; 2]>, egui::Color32, String)],
    display_b: &[(Vec<[f64; 2]>, egui::Color32, String)],
) -> Option<PlotDataBounds> {
    merge_bounds(
        display_a
            .iter()
            .chain(display_b.iter())
            .filter_map(|(pts, _, _)| points_bounds(pts)),
    )
}

fn display_bounds(display: &[(Vec<[f64; 2]>, egui::Color32, String)]) -> Option<PlotDataBounds> {
    merge_bounds(display.iter().filter_map(|(pts, _, _)| points_bounds(pts)))
}

fn merge_bounds(bounds_iter: impl Iterator<Item = PlotDataBounds>) -> Option<PlotDataBounds> {
    bounds_iter.fold(
        None,
        |bounds, ((x_min, x_max), (y_min, y_max))| match bounds {
            None => Some(((x_min, x_max), (y_min, y_max))),
            Some(((cur_x_min, cur_x_max), (cur_y_min, cur_y_max))) => Some((
                (cur_x_min.min(x_min), cur_x_max.max(x_max)),
                (cur_y_min.min(y_min), cur_y_max.max(y_max)),
            )),
        },
    )
}

fn points_bounds(pts: &[[f64; 2]]) -> Option<PlotDataBounds> {
    pts.iter().fold(None, |bounds, [x, y]| match bounds {
        None => Some(((*x, *x), (*y, *y))),
        Some(((x_min, x_max), (y_min, y_max))) => Some((
            (x_min.min(*x), x_max.max(*x)),
            (y_min.min(*y), y_max.max(*y)),
        )),
    })
}

fn selected_x_bounds(state_a: &PlotState, state_b: &PlotState) -> (f64, f64) {
    match (state_a.flow_id, state_b.flow_id) {
        (Some(_), Some(_)) => (
            state_a.data_x_min.min(state_b.data_x_min),
            state_a.data_x_max.max(state_b.data_x_max),
        ),
        (Some(_), None) => (state_a.data_x_min, state_a.data_x_max),
        (None, Some(_)) => (state_b.data_x_min, state_b.data_x_max),
        (None, None) => (0.0, 1.0),
    }
}

fn merged_y_bounds(state_a: &PlotState, state_b: &PlotState) -> (f64, f64) {
    match (!state_a.series.is_empty(), !state_b.series.is_empty()) {
        (true, true) => {
            let (a_min, a_max) = state_a.y_bounds();
            let (b_min, b_max) = state_b.y_bounds();
            (a_min.min(b_min), a_max.max(b_max))
        }
        (true, false) => state_a.y_bounds(),
        (false, true) => state_b.y_bounds(),
        (false, false) => (0.0, 1.0),
    }
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
) -> bool {
    let mut changed = false;

    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 16.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 2.0, accent);
        ui.add_space(4.0);
        ui.label(RichText::new(title).strong().size(13.0).color(accent));
    });
    ui.add_space(2.0);

    if flows.is_empty() {
        ui.label(RichText::new("No flows found.").color(egui::Color32::GRAY));
        return false;
    }

    egui::Frame::none().show(ui, |ui| {
        ui.set_max_height(table_height * 0.45);
        if let Some(new_id) = flow_table.show(ui, flows) {
            state.select_flow(db, new_id);
            changed = true;
        }
    });

    if state.flow_id.is_none() {
        return changed;
    }

    ui.add_space(4.0);
    ui.label(
        RichText::new("Metrics")
            .size(12.0)
            .color(egui::Color32::DARK_GRAY),
    );

    let available = state.available_series.clone();
    let selected_ids = state.selected_series_ids.clone();
    let colors: Vec<(i64, egui::Color32)> = state
        .series
        .iter()
        .map(|s| (s.series_id, s.color))
        .collect();

    let metrics_height = (table_height * 0.5).max(80.0);
    egui::Frame::none().show(ui, |ui| {
        ui.set_max_height(metrics_height);
        if let Some(toggled_id) = series_table.show(ui, &available, &selected_ids, &colors) {
            state.toggle_series(db, toggled_id, settings);
            changed = true;
        }
    });

    changed
}
