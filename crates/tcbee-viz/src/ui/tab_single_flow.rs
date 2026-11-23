use egui::{RichText, ScrollArea};
use egui_plot::{CoordinatesFormatter, GridInput, GridMark, PlotBounds, PlotPoint};

use crate::{
    backend::db::DbBackend,
    data::{
        plot_groups::{FlowSlot, PlotGroups, Preset, SeriesKey},
        plot_state::PlotState,
    },
    export,
    settings::AppSettings,
    ui::{
        flow_table::FlowTable,
        gap_marks,
        group_editor::{self, SidebarTab},
        grouped_plots,
        series_table::SeriesTable,
        sidebar::{self, apply_series_action, flow_picker, outliers_checkbox},
        theme,
        x_range::{self, XRangeEditor},
    },
};

const PLOT_AXIS_FOOTER: f32 = 36.0;
const SINGLE_PRESETS: &[Preset] = &[Preset::AllTogether, Preset::PerMetric];

pub struct TabSingleFlow {
    state: PlotState,
    flow_table: FlowTable,
    /// The flow table is shown again to pick another flow
    choosing_flow: bool,
    series_table: SeriesTable,
    manual_x_min: f64,
    manual_x_max: f64,
    apply_manual_x: bool,
    x_range: XRangeEditor,
    needs_fit: bool,
    remove_outliers: bool,
    show_gaps: bool,
    /// Which metrics share a plot
    groups: PlotGroups,
    sidebar_tab: SidebarTab,
    /// The visible part of the plot, for the figure export
    view: export::View,
    export_status: export::Status,
    /// The open export window
    preview: Option<export::Preview>,
    /// The data script shown for copying
    script: Option<String>,
}

impl Default for TabSingleFlow {
    fn default() -> Self {
        Self {
            state: PlotState::default(),
            flow_table: FlowTable::default(),
            choosing_flow: false,
            series_table: SeriesTable::default(),
            manual_x_min: 0.0,
            manual_x_max: 1.0,
            apply_manual_x: false,
            x_range: XRangeEditor::default(),
            needs_fit: false,
            remove_outliers: true,
            show_gaps: true,
            groups: PlotGroups::default(),
            sidebar_tab: SidebarTab::default(),
            view: export::View::default(),
            export_status: None,
            preview: None,
            script: None,
        }
    }
}

impl TabSingleFlow {
    pub fn reset(&mut self) {
        self.preview = None;
        self.script = None;
        self.state.reset();
        self.flow_table.reset();
        self.choosing_flow = false;
        self.series_table.reset();
        self.manual_x_min = 0.0;
        self.manual_x_max = 1.0;
        self.apply_manual_x = false;
        self.x_range.reset();
        self.needs_fit = false;
        self.remove_outliers = true;
        self.groups = PlotGroups::default();
        self.sidebar_tab = SidebarTab::default();
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
            .default_width(360.0)
            .frame(theme::sidebar_frame(settings.dark_mode))
            .show_inside(ui, |ui| {
                // The controls go first so the scroll area below gets the remaining height
                egui::TopBottomPanel::bottom("single_flow_controls")
                    .frame(theme::sidebar_controls_frame(settings.dark_mode))
                    .show_inside(ui, |ui| self.show_view_controls(ui, db, settings));
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
        group_editor::tab_strip(ui, &mut self.sidebar_tab);
        if self.sidebar_tab == SidebarTab::Groups {
            let selected = self.selected_colors();
            if group_editor::show(
                ui,
                "single_groups",
                &mut self.groups,
                &selected,
                SINGLE_PRESETS,
            ) {
                self.needs_fit = true;
            }
            return;
        }
        let sidebar_height = sidebar_height - ui.cursor().top() + ui.min_rect().top();

        let top = ui.cursor().top();

        // ── Flow table ──────────────────────────────────────────────────
        ui.add_space(4.0);
        section_heading(ui, "Flow");

        let flows = db.list_flows();
        if flows.is_empty() {
            ui.label(RichText::new("No flows found in database.").color(egui::Color32::GRAY));
        } else if let Some(new_id) = flow_picker(
            ui,
            db,
            flows,
            &mut self.flow_table,
            &self.state,
            &mut self.choosing_flow,
            (sidebar_height * 0.45).max(120.0),
            "flow_table",
        ) {
            self.state.select_flow(db, new_id);
            self.manual_x_min = self.state.data_x_min;
            self.manual_x_max = self.state.data_x_max;
            self.needs_fit = true;
        }

        if self.state.flow_id.is_none() {
            ui.add_space(8.0);
            ui.label(
                RichText::new("Select a flow above.")
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

            // The metrics table takes the rest of the sidebar
            let used = ui.cursor().top() - top;
            let metrics_height = (sidebar_height - used - sidebar::BOTTOM_GAP).max(160.0);
            egui::Frame::NONE.show(ui, |ui| {
                ui.set_max_height(metrics_height);
                if let Some(action) = self
                    .series_table
                    .show(ui, &available, &selected_ids, &colors)
                {
                    apply_series_action(&mut self.state, db, action, settings);
                    self.needs_fit = true;
                }
            });
        }
    }

    /// Reset zoom, the view toggles and the X range, always visible below the sidebar
    fn show_view_controls(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        ui.horizontal_wrapped(|ui| {
            if ui.button("Reset zoom").clicked() {
                self.manual_x_min = self.state.data_x_min;
                self.manual_x_max = self.state.data_x_max;
                self.apply_manual_x = true;
            }
            if outliers_checkbox(ui, &mut self.remove_outliers) {
                self.needs_fit = true;
            }
            gap_marks::controls(ui, &mut self.show_gaps, &self.state.series);
        });
        export::show_script(ui.ctx(), &mut self.script);
        if let Some(request) = export::controls(ui, &self.export_status) {
            self.export(request, db, settings);
        }
        if let Some(status) =
            export::show_preview(ui.ctx(), &mut self.preview, db, &[(&self.state, "")])
        {
            self.export_status = Some(status);
        }
        let bounds = self.state.flow_id.map(|_| x_range::Bounds {
            origin: self.state.data_x_min,
            data: (self.state.data_x_min, self.state.data_x_max),
            // The plot's bounds of the last frame
            visible: self.view.x.unwrap_or((self.state.x_min, self.state.x_max)),
        });
        if let Some((min, max)) = self.x_range.show(ui, "single_flow_x_range", bounds) {
            self.manual_x_min = min;
            self.manual_x_max = max;
            self.apply_manual_x = true;
        }
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

        if self.show_gaps {
            self.state.load_gaps(db);
        }

        let has_string = self.state.series.iter().any(|s| s.is_string_type());
        self.show_plots(ui, db, settings);

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

    fn show_plots(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        let flows = [grouped_plots::Flow {
            slot: FlowSlot::Single,
            state: &self.state,
            prefix: "",
        }];
        let selected = grouped_plots::selected_keys(&flows);
        self.groups.sync(&selected);
        let groups = self.groups.resolve(&selected);
        let plot_settings = grouped_plots::Settings {
            id: "single",
            x_origin: self.state.data_x_min,
            data_x: (self.state.data_x_min, self.state.data_x_max),
            fit: std::mem::take(&mut self.needs_fit),
            set_x: std::mem::take(&mut self.apply_manual_x)
                .then_some((self.manual_x_min, self.manual_x_max)),
            remove_outliers: self.remove_outliers,
            show_gaps: self.show_gaps,
        };
        let outcome = grouped_plots::show(ui, &groups, &flows, &plot_settings);

        let plot_width = ui.available_width().max(1.0);
        self.view = export::View {
            x: outcome.x(),
            // The figure keeps the y range of a single plot and fits its own otherwise
            y: match outcome.views.as_slice() {
                [(_, view)] => view.y,
                _ => None,
            },
            remove_outliers: self.remove_outliers,
        };
        if outcome.right_clicked {
            self.reset_to_full_autofit(db, settings, plot_width);
        }
        if let Some((x_min, x_max)) = outcome.reload[0] {
            self.state.x_min = x_min;
            self.state.x_max = x_max;
            self.state
                .reload_visible_data(db, settings, Some(plot_width));
        }
    }

    fn export(&mut self, request: export::Request, db: &DbBackend, settings: &AppSettings) {
        let style = &settings.plot_style;
        if style.show_gaps {
            self.state.load_gaps(db);
        }
        let metrics: Vec<&str> = self
            .state
            .series
            .iter()
            .filter_map(|s| s.info.as_ref().map(|i| i.name.as_str()))
            .collect();
        let file_stem = export::default_file_stem(self.state.flow_id, &metrics);
        match export::run(
            request,
            db,
            &[(&self.state, "")],
            self.state.data_x_min,
            export::View {
                remove_outliers: self.remove_outliers,
                ..self.view
            },
            style,
            &file_stem,
        ) {
            Some(export::Outcome::Saved(status)) => self.export_status = Some(status),
            Some(export::Outcome::Preview(preview)) => self.preview = Some(*preview),
            Some(export::Outcome::Script(text)) => self.script = Some(text),
            None => {}
        }
    }

    fn selected_colors(&self) -> Vec<(SeriesKey, egui::Color32)> {
        grouped_plots::selected_colors(&[grouped_plots::Flow {
            slot: FlowSlot::Single,
            state: &self.state,
            prefix: "",
        }])
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

/// Hover label of a plot: the item's name, the time in seconds since `origin_ns` and the
/// compact value
pub fn seconds_label_formatter(origin_ns: f64) -> impl Fn(&str, &PlotPoint) -> String {
    move |name, point| {
        let time = format!("{:.3} s", (point.x - origin_ns) / 1_000_000_000.0);
        let value = compact_axis_label(point.y);
        if name.is_empty() {
            format!("{time}\n{value}")
        } else {
            format!("{name}\n{time}\n{value}")
        }
    }
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

pub fn section_heading(ui: &mut egui::Ui, label: &str) {
    let dark_mode = ui.visuals().dark_mode;
    ui.label(
        RichText::new(label)
            .strong()
            .size(12.5)
            .color(theme::muted_text(dark_mode)),
    );
    ui.add_space(4.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hover_label_shows_seconds_since_origin() {
        let label = seconds_label_formatter(1_000_000_000_000.0);
        let point = PlotPoint::new(1_002_500_000_000.0, 41_565.5);
        assert_eq!(label("subflow 1", &point), "subflow 1\n2.500 s\n41.6k");
        assert_eq!(label("", &point), "2.500 s\n41.6k");
    }
}
