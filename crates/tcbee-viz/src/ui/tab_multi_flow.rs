use egui::{RichText, ScrollArea};
use ts_storage::Flow;

use crate::{
    backend::db::DbBackend,
    data::{
        plot_groups::{FlowSlot, PlotGroups, Preset, SeriesKey},
        plot_state::PlotState,
        preprocessing::generate_colors,
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

const MULTI_PRESETS: &[Preset] = &[
    Preset::AllTogether,
    Preset::PerFlow,
    Preset::PerMetric,
    Preset::PerSeries,
];

pub struct TabMultiFlow {
    state_a: PlotState,
    state_b: PlotState,
    table_a: FlowTable,
    table_b: FlowTable,
    /// The flow table of A or B is shown again to pick another flow
    choosing_flow_a: bool,
    choosing_flow_b: bool,
    series_table_a: SeriesTable,
    series_table_b: SeriesTable,
    /// Which metrics share a plot
    groups: PlotGroups,
    sidebar_tab: SidebarTab,
    remove_outliers: bool,
    show_gaps: bool,
    /// The visible part of the plots, for the figure export
    view: export::View,
    /// The drawn plots, for the figure export
    export_panels: Vec<export::ExportPanel>,
    export_status: export::Status,
    /// The open export window
    preview: Option<export::Preview>,
    /// The data script shown for copying
    script: Option<String>,
    manual_x_min: f64,
    manual_x_max: f64,
    apply_manual_x: bool,
    x_range: XRangeEditor,
    needs_fit: bool,
}

impl Default for TabMultiFlow {
    fn default() -> Self {
        Self {
            state_a: PlotState::default(),
            state_b: PlotState::default(),
            table_a: FlowTable::default(),
            table_b: FlowTable::default(),
            choosing_flow_a: false,
            choosing_flow_b: false,
            series_table_a: SeriesTable::default(),
            series_table_b: SeriesTable::default(),
            groups: PlotGroups::default(),
            sidebar_tab: SidebarTab::default(),
            remove_outliers: true,
            show_gaps: true,
            view: export::View::default(),
            export_panels: Vec::new(),
            export_status: None,
            preview: None,
            script: None,
            manual_x_min: 0.0,
            manual_x_max: 1.0,
            apply_manual_x: false,
            x_range: XRangeEditor::default(),
            needs_fit: false,
        }
    }
}

impl TabMultiFlow {
    pub fn reset(&mut self) {
        self.preview = None;
        self.script = None;
        self.state_a.reset();
        self.state_b.reset();
        self.table_a.reset();
        self.table_b.reset();
        self.choosing_flow_a = false;
        self.choosing_flow_b = false;
        self.series_table_a.reset();
        self.series_table_b.reset();
        self.groups = PlotGroups::default();
        self.sidebar_tab = SidebarTab::default();
        self.remove_outliers = true;
        self.show_gaps = true;
        self.manual_x_min = 0.0;
        self.manual_x_max = 1.0;
        self.apply_manual_x = false;
        self.x_range.reset();
        self.needs_fit = false;
    }

    pub fn show(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if !db.is_connected() {
            ui.centered_and_justified(|ui| {
                ui.label("No database loaded. Go to Home and select a database file.");
            });
            return;
        }

        apply_unified_multi_flow_colors(&mut self.state_a, &mut self.state_b);

        egui::SidePanel::left("multi_flow_sidebar")
            .resizable(true)
            .min_width(240.0)
            .max_width(500.0)
            .default_width(360.0)
            .frame(theme::sidebar_frame(settings.dark_mode))
            .show_inside(ui, |ui| {
                // The controls go first so the scroll area below gets the remaining height
                egui::TopBottomPanel::bottom("multi_flow_controls")
                    .frame(theme::sidebar_controls_frame(settings.dark_mode))
                    .show_inside(ui, |ui| self.show_view_controls(ui, db, settings));
                let sidebar_height = ui.available_height();
                ScrollArea::vertical()
                    .id_salt("multi_flow_sidebar_scroll")
                    .auto_shrink([false, false])
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
                apply_unified_multi_flow_colors(&mut self.state_a, &mut self.state_b);
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
                "multi_groups",
                &mut self.groups,
                &selected,
                MULTI_PRESETS,
            ) {
                self.needs_fit = true;
            }
            return;
        }
        let sidebar_height = sidebar_height - ui.cursor().top() + ui.min_rect().top();

        let flows = db.list_flows();
        // Each flow gets half of the sidebar, less the space between them
        let half_h = ((sidebar_height - 20.0) / 2.0).max(220.0);

        // ── Flow A ───────────────────────────────────────────────────────
        if flow_section(
            ui,
            "Flow A",
            egui::Color32::from_rgb(70, 130, 200),
            &mut self.table_a,
            &mut self.choosing_flow_a,
            &mut self.series_table_a,
            &mut self.state_a,
            flows,
            db,
            settings,
            half_h,
            "multi_flow_a_flows",
            "multi_flow_a_series",
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
            &mut self.choosing_flow_b,
            &mut self.series_table_b,
            &mut self.state_b,
            flows,
            db,
            settings,
            half_h,
            "multi_flow_b_flows",
            "multi_flow_b_series",
        ) {
            self.needs_fit = true;
        }
    }

    /// Reset zoom, the view toggles and the X range, always visible below the sidebar
    fn show_view_controls(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        ui.horizontal_wrapped(|ui| {
            if ui.button("Reset zoom").clicked() {
                let x_min = self.state_a.data_x_min.min(self.state_b.data_x_min);
                let x_max = self.state_a.data_x_max.max(self.state_b.data_x_max);
                self.manual_x_min = x_min;
                self.manual_x_max = x_max;
                self.apply_manual_x = true;
            }
            if outliers_checkbox(ui, &mut self.remove_outliers) {
                self.needs_fit = true;
            }
            gap_marks::controls(
                ui,
                &mut self.show_gaps,
                self.state_a.series.iter().chain(&self.state_b.series),
            );
        });
        export::show_script(ui.ctx(), &mut self.script);
        if let Some(request) = export::controls(ui, &self.export_status) {
            self.export(request, db, settings);
        }
        if let Some(status) = export::show_preview(
            ui.ctx(),
            &mut self.preview,
            db,
            (
                &[(&self.state_a, "A:"), (&self.state_b, "B:")],
                &self.export_panels,
            ),
        ) {
            self.export_status = Some(status);
        }
        if let Some((min, max)) = self.x_range.show(
            ui,
            "multi_flow_x_range",
            x_range_bounds(&self.state_a, &self.state_b, self.view.x),
        ) {
            self.manual_x_min = min;
            self.manual_x_max = max;
            self.apply_manual_x = true;
        }
    }

    fn export(&mut self, request: export::Request, db: &DbBackend, settings: &AppSettings) {
        let style = &settings.plot_style;
        if style.show_gaps {
            self.state_a.load_gaps(db);
            self.state_b.load_gaps(db);
        }
        let metrics: Vec<&str> = self
            .state_a
            .series
            .iter()
            .chain(&self.state_b.series)
            .filter_map(|s| s.info.as_ref().map(|i| i.name.as_str()))
            .collect();
        let file_stem = export::default_file_stem(None, &metrics);
        let view = export::View {
            y: self.view.y,
            remove_outliers: self.remove_outliers,
            ..self.view
        };
        match export::run(
            request,
            db,
            (
                &[(&self.state_a, "A:"), (&self.state_b, "B:")],
                &self.export_panels,
            ),
            merged_x_origin(&self.state_a, &self.state_b),
            view,
            style,
            &file_stem,
        ) {
            Some(export::Outcome::Saved(status)) => self.export_status = Some(status),
            Some(export::Outcome::Preview(preview)) => self.preview = Some(*preview),
            Some(export::Outcome::Script(text)) => self.script = Some(text),
            None => {}
        }
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

        if self.show_gaps {
            self.state_a.load_gaps(db);
            self.state_b.load_gaps(db);
        }

        let flows = [
            grouped_plots::Flow {
                slot: FlowSlot::A,
                state: &self.state_a,
                prefix: "A:",
            },
            grouped_plots::Flow {
                slot: FlowSlot::B,
                state: &self.state_b,
                prefix: "B:",
            },
        ];
        let selected = grouped_plots::selected_keys(&flows);
        self.groups.sync(&selected);
        let groups = self.groups.resolve(&selected);
        let plot_settings = grouped_plots::Settings {
            id: "multi",
            x_origin: merged_x_origin(&self.state_a, &self.state_b),
            data_x: selected_x_bounds(&self.state_a, &self.state_b),
            fit: std::mem::take(&mut self.needs_fit),
            set_x: std::mem::take(&mut self.apply_manual_x)
                .then_some((self.manual_x_min, self.manual_x_max)),
            remove_outliers: self.remove_outliers,
            show_gaps: self.show_gaps,
        };
        let outcome = grouped_plots::show(ui, &groups, &flows, &plot_settings);

        let plot_width = ui.available_width().max(1.0);
        self.export_panels = grouped_plots::export_panels(&groups, &flows, &outcome);
        self.view = export::View {
            x: outcome.x(),
            // Each panel has its own
            y: None,
            remove_outliers: self.remove_outliers,
        };
        if outcome.right_clicked {
            self.reset_to_full_autofit(db, settings, plot_width);
        }
        for (state, reload) in [&mut self.state_a, &mut self.state_b]
            .into_iter()
            .zip(outcome.reload)
        {
            if let Some((x_min, x_max)) = reload {
                state.x_min = x_min;
                state.x_max = x_max;
                state.reload_visible_data(db, settings, Some(plot_width));
            }
        }
    }

    fn selected_colors(&self) -> Vec<(SeriesKey, egui::Color32)> {
        grouped_plots::selected_colors(&[
            grouped_plots::Flow {
                slot: FlowSlot::A,
                state: &self.state_a,
                prefix: "A:",
            },
            grouped_plots::Flow {
                slot: FlowSlot::B,
                state: &self.state_b,
                prefix: "B:",
            },
        ])
    }

    fn reset_to_full_autofit(&mut self, db: &DbBackend, settings: &AppSettings, plot_width: f32) {
        let (x_min, x_max) = selected_x_bounds(&self.state_a, &self.state_b);
        self.manual_x_min = x_min;
        self.manual_x_max = x_max;
        self.apply_manual_x = false;
        self.needs_fit = true;

        if self.state_a.flow_id.is_some() {
            self.state_a.x_min = self.state_a.data_x_min;
            self.state_a.x_max = self.state_a.data_x_max;
            self.state_a
                .reload_visible_data(db, settings, Some(plot_width));
        }
        if self.state_b.flow_id.is_some() {
            self.state_b.x_min = self.state_b.data_x_min;
            self.state_b.x_max = self.state_b.data_x_max;
            self.state_b
                .reload_visible_data(db, settings, Some(plot_width));
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

fn apply_unified_multi_flow_colors(state_a: &mut PlotState, state_b: &mut PlotState) {
    let colors = generate_colors(state_a.series.len() + state_b.series.len());
    for (series, color) in state_a
        .series
        .iter_mut()
        .chain(state_b.series.iter_mut())
        .zip(colors)
    {
        series.color = color;
    }
}

/// The bounds of the X range editor over the selected flows, None without one. `plot_x` are
/// the plot's bounds of the last frame.
fn x_range_bounds(
    state_a: &PlotState,
    state_b: &PlotState,
    plot_x: Option<(f64, f64)>,
) -> Option<x_range::Bounds> {
    let selected: Vec<&PlotState> = [state_a, state_b]
        .into_iter()
        .filter(|s| s.flow_id.is_some())
        .collect();
    if selected.is_empty() {
        return None;
    }
    let visible_min = selected.iter().map(|s| s.x_min).fold(f64::MAX, f64::min);
    let visible_max = selected.iter().map(|s| s.x_max).fold(f64::MIN, f64::max);
    Some(x_range::Bounds {
        origin: merged_x_origin(state_a, state_b),
        data: selected_x_bounds(state_a, state_b),
        visible: plot_x.unwrap_or((visible_min, visible_max)),
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

#[allow(clippy::too_many_arguments)]
fn flow_section(
    ui: &mut egui::Ui,
    title: &str,
    accent: egui::Color32,
    flow_table: &mut FlowTable,
    choosing_flow: &mut bool,
    series_table: &mut SeriesTable,
    state: &mut PlotState,
    flows: &[Flow],
    db: &DbBackend,
    settings: &AppSettings,
    table_height: f32,
    flow_table_id: &'static str,
    series_table_id: &'static str,
) -> bool {
    let mut changed = false;
    let top = ui.cursor().top();

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

    if let Some(new_id) = flow_picker(
        ui,
        db,
        flows,
        flow_table,
        state,
        choosing_flow,
        (table_height * 0.62).max(160.0),
        flow_table_id,
    ) {
        state.select_flow(db, new_id);
        changed = true;
    }

    if state.flow_id.is_none() {
        return changed;
    }

    ui.add_space(4.0);
    ui.label(
        RichText::new("Metrics")
            .size(12.0)
            .strong()
            .color(theme::muted_text(ui.visuals().dark_mode)),
    );

    let available = state.available_series.clone();
    let selected_ids = state.selected_series_ids.clone();
    let colors: Vec<(i64, egui::Color32)> = state
        .series
        .iter()
        .map(|s| (s.series_id, s.color))
        .collect();

    // The metrics table takes the rest of the flow's half
    let used = ui.cursor().top() - top;
    let metrics_height = (table_height - used - sidebar::BOTTOM_GAP).max(160.0);
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_max_height(metrics_height);
        if let Some(action) =
            series_table.show_with_id_salt(ui, &available, &selected_ids, &colors, series_table_id)
        {
            apply_series_action(state, db, action, settings);
            changed = true;
        }
    });

    changed
}
