use egui::{RichText, ScrollArea};
use egui_plot::{
    CoordinatesFormatter, Corner, GridInput, GridMark, Legend, Line, Plot, PlotBounds, PlotPoint,
    PlotPoints, Text, VLine,
};

use crate::{
    backend::db::DbBackend,
    data::{plot_state::PlotState, preprocessing::remove_leading_outliers},
    settings::AppSettings,
    ui::{flow_table::FlowTable, series_table::SeriesTable, theme},
};

const PLOT_AXIS_FOOTER: f32 = 36.0;
const OUTLIER_TOOLTIP: &str = "Automatically removes only leading points whose values are far outside the following steady-state data, so large initial CWND or ssthresh values do not distort auto-fit.";
type PlotDataBounds = ((f64, f64), (f64, f64));

pub struct TabSingleFlow {
    state: PlotState,
    flow_table: FlowTable,
    series_table: SeriesTable,
    manual_x_min: f64,
    manual_x_max: f64,
    apply_manual_x: bool,
    needs_fit: bool,
    remove_outliers: bool,
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
            remove_outliers: true,
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
        self.remove_outliers = true;
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
            .default_width(500.0)
            .frame(theme::sidebar_frame(settings.dark_mode))
            .show_inside(ui, |ui| {
                let sidebar_height = ui.available_height();
                ScrollArea::vertical()
                    .id_salt("single_flow_sidebar_scroll")
                    .auto_shrink([false, false])
                    .scroll_bar_visibility(
                        egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded,
                    )
                    .show(ui, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin::symmetric(16, 0))
                            .show(ui, |ui| {
                                ui.set_min_height(sidebar_height);
                                self.show_sidebar(ui, db, settings, sidebar_height);
                            });
                    });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::panel_bg(settings.dark_mode)))
            .show_inside(ui, |ui| {
                ui.add_space(4.0);
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
        // ── Flow table ──────────────────────────────────────────────────
        ui.add_space(4.0);
        section_heading(ui, "Flow Selection");

        let flows = db.list_flows();
        let flow_table_height = (sidebar_height * 0.45).max(120.0);
        if flows.is_empty() {
            ui.label(RichText::new("No flows found in database.").color(egui::Color32::GRAY));
        } else {
            // Reserve space for flow table — takes up top half of sidebar
            egui::Frame::NONE.show(ui, |ui| {
                ui.set_max_height(flow_table_height);
                if let Some(new_id) = self.flow_table.show(ui, db, &flows) {
                    self.state.select_flow(db, new_id);
                    self.manual_x_min = self.state.data_x_min;
                    self.manual_x_max = self.state.data_x_max;
                    self.needs_fit = true;
                }
            });
        }

        if self.state.flow_id.is_none() {
            ui.add_space(8.0);
            ui.label(
                RichText::new("← Select a flow above.")
                    .color(egui::Color32::GRAY)
                    .italics(),
            );
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
            let colors: Vec<(i64, egui::Color32)> = self
                .state
                .series
                .iter()
                .map(|s| (s.series_id, s.color))
                .collect();

            let metrics_height = (sidebar_height - flow_table_height - 180.0).max(100.0);
            egui::Frame::NONE.show(ui, |ui| {
                ui.set_max_height(metrics_height);
                if let Some(toggled_id) =
                    self.series_table
                        .show(ui, &available, &selected_ids, &colors)
                {
                    self.state.toggle_series(db, toggled_id, settings);
                    self.needs_fit = true;
                }
            });

            ui.add_space(6.0);
            ui.scope(|ui| {
                ui.style_mut().interaction.tooltip_delay = 0.0;
                ui.horizontal(|ui| {
                    let checkbox_response = ui
                        .checkbox(&mut self.remove_outliers, "Remove Outliers")
                        .on_hover_text(OUTLIER_TOOLTIP);
                    if checkbox_response.changed() {
                        self.needs_fit = true;
                    }
                    ui.add_sized(
                        [18.0, 18.0],
                        egui::Label::new(RichText::new("?").strong()).sense(egui::Sense::hover()),
                    )
                    .on_hover_text(OUTLIER_TOOLTIP);
                });
            });
        }

        ui.add_space(10.0);
        ui.separator();

        // ── View options ─────────────────────────────────────────────────
        section_heading(ui, "View");

        if ui
            .checkbox(&mut self.state.split_view, "Split into separate plots")
            .changed()
        {
            self.needs_fit = true;
        }

        ui.add_space(8.0);
        ui.label(RichText::new("X range").strong().size(12.0));

        egui::Grid::new("x_range_grid")
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
                    ui.label(
                        RichText::new("Select a flow from the sidebar.").color(egui::Color32::GRAY),
                    );
                } else {
                    ui.label(
                        RichText::new("Select metrics to display.").color(egui::Color32::GRAY),
                    );
                }
            });
            return;
        }

        let plot_width_px = ui.available_width().max(1.0);
        self.state
            .reload_if_sampling_changed(db, settings, plot_width_px);

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
            ScrollArea::vertical()
                .id_salt("string_series_scroll")
                .max_height(120.0)
                .show(ui, |ui| {
                    for (name, color, points) in &string_data {
                        ui.label(RichText::new(name).color(*color).strong());
                        for (t, val) in points {
                            ui.label(format!("  t={:.4}  {}", t, val));
                        }
                    }
                });
        }
    }

    fn show_combined_plot(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let apply_x = self.apply_manual_x;
        let x_min = self.manual_x_min;
        let x_max = self.manual_x_max;
        self.apply_manual_x = false;

        let fit = std::mem::take(&mut self.needs_fit);
        let remove_outliers = self.remove_outliers;

        let display: Vec<(Vec<[f64; 2]>, egui::Color32, String)> = self
            .state
            .series
            .iter()
            .filter(|s| !s.is_string_type() && !s.is_boolean_type())
            .map(|s| {
                let points = points_after_outlier_removal(&s.points, remove_outliers);
                (to_plot_points(points), s.color, s.name.clone())
            })
            .collect();
        let bool_markers: Vec<(String, egui::Color32, Vec<f64>)> = self
            .state
            .series
            .iter()
            .filter(|s| s.is_boolean_type())
            .map(|s| {
                let timestamps = s
                    .points
                    .iter()
                    .filter_map(|(t, value)| (*value >= 0.5).then_some(*t))
                    .collect();
                (s.name.clone(), s.color, timestamps)
            })
            .collect();
        let string_markers: Vec<(String, egui::Color32, Vec<(f64, String)>)> = self
            .state
            .series
            .iter()
            .filter(|s| s.is_string_type())
            .map(|s| (s.name.clone(), s.color, s.string_points.clone()))
            .collect();
        let ((fit_x_min, fit_x_max), (fit_y_min, fit_y_max)) = if remove_outliers {
            display_bounds(&display).unwrap_or((
                (self.state.data_x_min, self.state.data_x_max),
                self.state.y_bounds(),
            ))
        } else {
            (
                (self.state.data_x_min, self.state.data_x_max),
                self.state.y_bounds(),
            )
        };

        let plot = Plot::new("single_combined")
            .allow_boxed_zoom(true)
            .allow_drag(true)
            .allow_scroll(true)
            .x_grid_spacer(seconds_grid_spacer(self.state.data_x_min))
            .x_axis_formatter(seconds_since_formatter(self.state.data_x_min))
            .y_axis_formatter(time_or_compact_formatter(self.state.data_x_min))
            .coordinates_formatter(
                Corner::LeftBottom,
                time_or_compact_coordinates_formatter(self.state.data_x_min),
            )
            .legend(Legend::default())
            .height(plot_height_with_footer(ui.available_height()));

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
                    Line::new(PlotPoints::from(pts.clone()))
                        .color(*color)
                        .name(name),
                );
            }

            for (name, color, timestamps) in &bool_markers {
                for t in timestamps {
                    plot_ui.vline(VLine::new(*t).color(*color).name(name));
                }
            }

            let bounds = plot_ui.plot_bounds();
            let marker_y = (bounds.min()[1] + bounds.max()[1]) * 0.5;
            for (name, color, points) in &string_markers {
                for (t, label) in points {
                    plot_ui.vline(VLine::new(*t).color(*color).name(name));
                    plot_ui.text(
                        Text::new(PlotPoint::new(*t, marker_y), vertical_marker_label(label))
                            .anchor(egui::Align2::LEFT_CENTER)
                            .color(*color),
                    );
                }
            }
        });

        if plot_response.response.secondary_clicked() {
            self.reset_to_full_autofit(db, settings, ui.available_width().max(1.0));
        }

        if needs_reload {
            self.state.x_min = new_x_min;
            self.state.x_max = new_x_max;
            self.state
                .reload_visible_data(db, settings, Some(ui.available_width().max(1.0)));
        }
    }

    fn show_split_plots(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let apply_x = self.apply_manual_x;
        let x_min = self.manual_x_min;
        let x_max = self.manual_x_max;
        self.apply_manual_x = false;

        let fit = std::mem::take(&mut self.needs_fit);
        let remove_outliers = self.remove_outliers;

        let display: Vec<(i64, Vec<[f64; 2]>, egui::Color32, String, f64, f64)> = self
            .state
            .series
            .iter()
            .filter(|s| !s.is_string_type())
            .map(|s| {
                let points = points_after_outlier_removal(&s.points, remove_outliers);
                let pts = to_plot_points(points);
                let (y_min, y_max) = if remove_outliers {
                    points_bounds(&pts)
                        .map(|(_, y)| y)
                        .unwrap_or((s.global_y_min, s.global_y_max))
                } else {
                    (s.global_y_min, s.global_y_max)
                };
                (s.series_id, pts, s.color, s.name.clone(), y_min, y_max)
            })
            .collect();
        let (fit_x_min, fit_x_max) = if remove_outliers {
            merge_bounds(
                display
                    .iter()
                    .filter_map(|(_, pts, _, _, _, _)| points_bounds(pts)),
            )
            .map(|(x, _)| x)
            .unwrap_or((self.state.data_x_min, self.state.data_x_max))
        } else {
            (self.state.data_x_min, self.state.data_x_max)
        };

        let plot_height =
            split_plot_height_with_footer(ui.available_height(), display.len().max(1));

        let mut needs_reload = false;
        let mut new_x_min = self.state.x_min;
        let mut new_x_max = self.state.x_max;
        let mut right_clicked = false;

        ScrollArea::vertical()
            .id_salt("split_scroll")
            .show(ui, |ui| {
                for (sid, pts, color, name, y_min, y_max) in &display {
                    ui.label(RichText::new(name).color(*color).strong());

                    let plot = Plot::new(format!("split_{}", sid))
                        .allow_boxed_zoom(true)
                        .allow_drag(true)
                        .allow_scroll(true)
                        .link_axis("single_x_axis", [true, false])
                        .x_grid_spacer(seconds_grid_spacer(self.state.data_x_min))
                        .x_axis_formatter(seconds_since_formatter(self.state.data_x_min))
                        .y_axis_formatter(time_or_compact_formatter(self.state.data_x_min))
                        .coordinates_formatter(
                            Corner::LeftBottom,
                            time_or_compact_coordinates_formatter(self.state.data_x_min),
                        )
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
                            Line::new(PlotPoints::from(pts.clone()))
                                .color(*color)
                                .name(name),
                        );

                        // Show fit y bounds in the lower-right corner for debugging.
                        let vb = plot_ui.plot_bounds();
                        plot_ui.text(
                            Text::new(
                                PlotPoint::new(vb.max()[0], vb.min()[1]),
                                format!("Fit y: [{:.4}, {:.4}]", y_min, y_max),
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
            self.reset_to_full_autofit(db, settings, ui.available_width().max(1.0));
        }

        if needs_reload {
            self.state.x_min = new_x_min;
            self.state.x_max = new_x_max;
            self.state
                .reload_visible_data(db, settings, Some(ui.available_width().max(1.0)));
        }
    }

    fn reset_to_full_autofit(&mut self, db: &DbBackend, settings: &AppSettings, plot_width: f32) {
        self.state.x_min = self.state.data_x_min;
        self.state.x_max = self.state.data_x_max;
        self.manual_x_min = self.state.data_x_min;
        self.manual_x_max = self.state.data_x_max;
        self.apply_manual_x = false;
        self.needs_fit = true;
        self.state
            .reload_visible_data(db, settings, Some(plot_width));
    }
}

/// Convert (f64, f64) pairs to egui_plot's expected [f64; 2] arrays.
pub fn to_plot_points(pts: &[(f64, f64)]) -> Vec<[f64; 2]> {
    pts.iter().map(|&(x, y)| [x, y]).collect()
}

pub fn vertical_marker_label(label: &str) -> String {
    label
        .chars()
        .rev()
        .map(|ch| ch.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn points_after_outlier_removal(pts: &[(f64, f64)], remove_outliers: bool) -> &[(f64, f64)] {
    if remove_outliers {
        remove_leading_outliers(pts)
    } else {
        pts
    }
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

pub fn seconds_since_formatter(
    origin_ns: f64,
) -> impl Fn(GridMark, &std::ops::RangeInclusive<f64>) -> String {
    move |mark, _| format_seconds_since_step(mark.value, origin_ns, mark.step_size)
}

pub fn time_or_compact_formatter(
    origin_ns: f64,
) -> impl Fn(GridMark, &std::ops::RangeInclusive<f64>) -> String {
    move |mark, range| {
        if range_looks_like_ktime_ns(range, origin_ns) {
            format_seconds_since_step(mark.value, origin_ns, mark.step_size)
        } else {
            compact_axis_label(mark.value)
        }
    }
}

pub fn time_or_compact_coordinates_formatter(origin_ns: f64) -> CoordinatesFormatter<'static> {
    CoordinatesFormatter::new(move |point, bounds| {
        let y_range = bounds.min()[1]..=bounds.max()[1];
        let y = if range_looks_like_ktime_ns(&y_range, origin_ns) {
            format_seconds_since_step(point.y, origin_ns, y_step(bounds))
        } else {
            compact_axis_label(point.y)
        };
        format!(
            "x: {}\ny: {}",
            format_seconds_since_step(point.x, origin_ns, x_step(bounds)),
            y
        )
    })
}

pub fn compact_coordinates_formatter(origin_ns: f64) -> CoordinatesFormatter<'static> {
    CoordinatesFormatter::new(move |point, bounds| {
        format!(
            "x: {}\ny: {}",
            format_seconds_since_step(point.x, origin_ns, x_step(bounds)),
            compact_axis_label(point.y)
        )
    })
}

fn format_seconds_since_step(value_ns: f64, origin_ns: f64, step_ns: f64) -> String {
    let seconds = (value_ns - origin_ns) / 1_000_000_000.0;
    let step_seconds = (step_ns / 1_000_000_000.0).abs();
    let value = if seconds.abs() < 0.000_000_001 {
        0.0
    } else {
        seconds
    };

    if value.abs() >= 1_000_000.0 {
        format!("{}s", compact_axis_label(value))
    } else {
        format!("{}s", format_seconds_number(value, step_seconds))
    }
}

fn x_step(bounds: &PlotBounds) -> f64 {
    ((bounds.max()[0] - bounds.min()[0]).abs() / 6.0).max(1.0)
}

fn y_step(bounds: &PlotBounds) -> f64 {
    ((bounds.max()[1] - bounds.min()[1]).abs() / 6.0).max(1.0)
}

pub fn compact_axis_label(value: f64) -> String {
    let abs = value.abs();
    if abs >= 1_000_000_000_000.0 {
        format_scaled(value, 1_000_000_000_000.0, "T")
    } else if abs >= 1_000_000_000.0 {
        format_scaled(value, 1_000_000_000.0, "G")
    } else if abs >= 1_000_000.0 {
        format_scaled(value, 1_000_000.0, "M")
    } else if abs >= 1_000.0 {
        format_scaled(value, 1_000.0, "k")
    } else if value != 0.0 && abs < 0.001 {
        format_scaled(value, 0.000_001, "u")
    } else if value.fract().abs() < f64::EPSILON {
        format!("{value:.0}")
    } else {
        format!("{value:.3}")
    }
}

pub fn seconds_grid_spacer(origin_ns: f64) -> impl Fn(GridInput) -> Vec<GridMark> {
    move |input| {
        let (min_ns, max_ns) = if input.bounds.0 <= input.bounds.1 {
            input.bounds
        } else {
            (input.bounds.1, input.bounds.0)
        };
        let span_seconds = (max_ns - min_ns).abs() / 1_000_000_000.0;
        if span_seconds <= 0.0 || !span_seconds.is_finite() {
            return Vec::new();
        }

        let major_step_seconds = nice_seconds_step(span_seconds / 6.0);
        let major_step_ns = major_step_seconds * 1_000_000_000.0;

        let mut marks = Vec::new();
        push_second_marks(
            &mut marks,
            origin_ns,
            min_ns,
            max_ns,
            major_step_seconds,
            major_step_ns,
        );
        marks.sort_by(|a, b| {
            a.value
                .partial_cmp(&b.value)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        marks
    }
}

fn format_seconds_number(value: f64, step_seconds: f64) -> String {
    if step_seconds >= 1.0 {
        format!("{value:.0}")
    } else if step_seconds >= 0.1 {
        format!("{value:.1}")
    } else if step_seconds >= 0.01 {
        format!("{value:.2}")
    } else if step_seconds >= 0.001 {
        format!("{value:.3}")
    } else {
        format!("{value:.4}")
    }
}

fn format_scaled(value: f64, scale: f64, suffix: &str) -> String {
    let scaled = value / scale;
    if scaled.abs() >= 100.0 || scaled.fract().abs() < 0.005 {
        format!("{scaled:.0}{suffix}")
    } else if scaled.abs() >= 10.0 {
        format!("{scaled:.1}{suffix}")
    } else {
        format!("{scaled:.2}{suffix}")
    }
}

fn nice_seconds_step(base_step_seconds: f64) -> f64 {
    if base_step_seconds <= 0.0 || !base_step_seconds.is_finite() {
        return 1.0;
    }

    let magnitude = 10_f64.powi(base_step_seconds.log10().floor() as i32);
    for multiplier in [1.0, 2.0, 5.0, 10.0] {
        let step = multiplier * magnitude;
        if step >= base_step_seconds {
            return step;
        }
    }
    10.0 * magnitude
}

fn push_second_marks(
    marks: &mut Vec<GridMark>,
    origin_ns: f64,
    min_ns: f64,
    max_ns: f64,
    step_seconds: f64,
    step_ns: f64,
) {
    if step_seconds <= 0.0 || !step_seconds.is_finite() {
        return;
    }

    let first = ((min_ns - origin_ns) / step_ns).floor() as i64 - 1;
    let last = ((max_ns - origin_ns) / step_ns).ceil() as i64 + 1;
    for i in first..=last {
        marks.push(GridMark {
            value: origin_ns + i as f64 * step_ns,
            step_size: step_ns,
        });
    }
}

fn range_looks_like_ktime_ns(range: &std::ops::RangeInclusive<f64>, origin_ns: f64) -> bool {
    let start = *range.start();
    let end = *range.end();
    if !origin_ns.is_finite()
        || !start.is_finite()
        || !end.is_finite()
        || origin_ns.abs() < 1_000_000_000.0
    {
        return false;
    }

    let lo = start.min(end);
    let hi = start.max(end);
    let span = (hi - lo).abs();
    let midpoint = (lo + hi) * 0.5;
    (midpoint - origin_ns).abs() <= span.max(60_000_000_000.0) * 4.0
}

pub fn plot_height_with_footer(available_height: f32) -> f32 {
    (available_height - PLOT_AXIS_FOOTER).max(80.0)
}

pub fn split_plot_height_with_footer(available_height: f32, plot_count: usize) -> f32 {
    let count = plot_count.max(1) as f32;
    ((available_height - PLOT_AXIS_FOOTER) / count).max(80.0)
}

fn section_heading(ui: &mut egui::Ui, label: &str) {
    let dark_mode = ui.visuals().dark_mode;
    ui.label(
        RichText::new(label)
            .strong()
            .size(12.5)
            .color(theme::muted_text(dark_mode)),
    );
    ui.add_space(4.0);
}
