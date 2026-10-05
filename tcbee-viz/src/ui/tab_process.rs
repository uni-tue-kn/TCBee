use crate::ui::{
    flow_table::FlowTable,
    tab_single_flow::{to_plot_points, vertical_marker_label},
    theme,
};
use egui::RichText;
use egui_plot::{Legend, Line, Plot, PlotPoint, PlotPoints, Text, VLine};
use ts_storage::SeriesInfo;

use crate::{
    backend::{
        binding::{resolve_inputs, series_label},
        db::DbBackend,
        plugin::PluginKind,
    },
    data::{preprocessing::generate_colors, series_data::SeriesData},
    settings::AppSettings,
};

#[derive(Clone, Debug)]
struct InputBinding {
    required_name: String,
    selected_series_id: Option<i64>,
}

#[derive(Default)]
pub struct TabProcess {
    flow_table: FlowTable,
    /// Catalog rows of the selected flow, read once per selection and after a save.
    available: Vec<SeriesInfo>,
    available_flow: Option<i64>,
    selected_plugin: Option<PluginKind>,
    input_bindings: Vec<InputBinding>,
    /// Input series loaded from the database (raw_data populated).
    input_series: Vec<SeriesData>,
    /// Output series produced by the plugin.
    preview_series: Vec<SeriesData>,
    status: String,
    save_status: String,
    show_overwrite_confirm: bool,
    overwrite_conflicts: Vec<String>,
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
            .min_width(240.0)
            .max_width(500.0)
            .default_width(500.0)
            .frame(theme::sidebar_frame(_settings.dark_mode))
            .show_inside(ui, |ui| {
                let h = ui.available_height();
                egui::ScrollArea::vertical()
                    .id_salt("process_left_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin::symmetric(16, 0))
                            .show(ui, |ui| {
                                ui.set_min_height(h);
                                self.show_flow_panel(ui, db);
                            });
                    });
            });

        egui::SidePanel::right("process_right_panel")
            .resizable(true)
            .min_width(180.0)
            .max_width(300.0)
            .frame(theme::sidebar_frame(_settings.dark_mode))
            .show_inside(ui, |ui| {
                let h = ui.available_height();
                egui::ScrollArea::vertical()
                    .id_salt("process_right_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin::symmetric(16, 0))
                            .show(ui, |ui| {
                                ui.set_min_height(h);
                                self.show_plugin_panel(ui, db);
                            });
                    });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::panel_bg(_settings.dark_mode)))
            .show_inside(ui, |ui| {
                ui.add_space(4.0);
                self.show_preview_plot(ui);
            });

        self.show_overwrite_dialog(ui.ctx(), db);
    }

    fn show_flow_panel(&mut self, ui: &mut egui::Ui, db: &DbBackend) {
        ui.label(RichText::new("Flow").strong().size(13.0));
        ui.add_space(2.0);

        let flows = db.list_flows();
        if flows.is_empty() {
            ui.label(
                RichText::new("No flows found.").color(theme::muted_text(ui.visuals().dark_mode)),
            );
            return;
        }

        if self.flow_table.show(ui, db, flows).is_some() {
            self.input_bindings.clear();
            self.input_series.clear();
            self.preview_series.clear();
            self.status.clear();
            self.save_status.clear();
            self.show_overwrite_confirm = false;
            self.overwrite_conflicts.clear();
        }
    }

    /// Reads the series list again when the selected flow changed or after a save.
    fn sync_available(&mut self, db: &DbBackend) {
        let selected = self.flow_table.selected_id;
        if self.available_flow != selected {
            self.available = selected.map_or_else(Vec::new, |id| db.list_series_for_flow(id));
            self.available_flow = selected;
        }
    }

    /// The selected flow, if it exists.
    fn selected_flow(&self, db: &DbBackend) -> Result<i64, String> {
        match self.flow_table.selected_id {
            Some(id) if db.flow_exists(id) => Ok(id),
            Some(_) => Err("flow not found".to_string()),
            None => Err("no flow selected".to_string()),
        }
    }

    fn show_plugin_panel(&mut self, ui: &mut egui::Ui, db: &DbBackend) {
        self.sync_available(db);
        ui.heading("Plugin");
        ui.separator();

        for kind in PluginKind::ALL {
            let selected = self.selected_plugin == Some(*kind);
            if ui.selectable_label(selected, kind.label()).clicked() {
                self.selected_plugin = Some(*kind);
                self.input_bindings.clear();
                self.input_series.clear();
                self.preview_series.clear();
                self.status.clear();
                self.save_status.clear();
                self.show_overwrite_confirm = false;
                self.overwrite_conflicts.clear();
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
            let required = plugin.required_series();
            for name in &required {
                ui.label(format!("  • {}", name));
            }

            if let Some(flow_id) = self.flow_table.selected_id {
                Self::ensure_input_bindings(&mut self.input_bindings, &required, &self.available);

                ui.add_space(6.0);
                ui.label(RichText::new("Input mapping").strong());

                for binding in &mut self.input_bindings {
                    let selected_name = binding
                        .selected_series_id
                        .and_then(|id| self.available.iter().find(|s| s.id == id))
                        .map(series_label)
                        .unwrap_or_else(|| "Select series".to_string());

                    ui.horizontal(|ui| {
                        ui.label(&binding.required_name);
                        egui::ComboBox::from_id_salt(format!(
                            "process_input_{}_{}",
                            flow_id, binding.required_name
                        ))
                        .selected_text(selected_name)
                        .width(ui.available_width())
                        .show_ui(ui, |ui| {
                            for series in &self.available {
                                ui.selectable_value(
                                    &mut binding.selected_series_id,
                                    Some(series.id),
                                    series_label(series),
                                );
                            }
                        });
                    });
                }
            }
        }

        ui.add_space(12.0);
        ui.separator();

        let can_preview = self.flow_table.selected_id.is_some()
            && self.selected_plugin.is_some()
            && self
                .input_bindings
                .iter()
                .all(|binding| binding.selected_series_id.is_some());
        if ui
            .add_enabled(can_preview, egui::Button::new("Load & Preview"))
            .clicked()
        {
            self.run_preview(db);
        }

        if !self.status.is_empty() {
            ui.add_space(4.0);
            let color = if self.status.starts_with("Error") {
                theme::ERROR
            } else {
                theme::SUCCESS
            };
            ui.label(RichText::new(&self.status).color(color));
        }

        if !self.preview_series.is_empty() {
            ui.add_space(8.0);
            let can_save = self.flow_table.selected_id.is_some();
            if ui
                .add_enabled(can_save, egui::Button::new("Save to database"))
                .clicked()
            {
                self.save_results_or_confirm(db);
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
                    if s.is_boolean_type() || s.is_string_type() {
                        continue;
                    }
                    let pts = PlotPoints::from(to_plot_points(&s.points));
                    plot_ui.line(Line::new(pts).color(s.color).name(&s.name));
                }
                for s in &self.preview_series {
                    if s.is_boolean_type() || s.is_string_type() {
                        continue;
                    }
                    let pts = PlotPoints::from(to_plot_points(&s.points));
                    plot_ui.line(
                        Line::new(pts)
                            .color(s.color)
                            .name(format!("[new] {}", s.name))
                            .style(egui_plot::LineStyle::dashed_dense()),
                    );
                }

                for s in self.input_series.iter().chain(&self.preview_series) {
                    if !s.is_boolean_type() {
                        continue;
                    }
                    for (t, value) in &s.points {
                        if *value >= 0.5 {
                            plot_ui.vline(VLine::new(*t).color(s.color).name(&s.name));
                        }
                    }
                }

                let bounds = plot_ui.plot_bounds();
                let marker_y = (bounds.min()[1] + bounds.max()[1]) * 0.5;
                for s in self.input_series.iter().chain(&self.preview_series) {
                    if !s.is_string_type() {
                        continue;
                    }
                    for (t, label) in &s.string_points {
                        plot_ui.vline(VLine::new(*t).color(s.color).name(&s.name));
                        plot_ui.text(
                            Text::new(PlotPoint::new(*t, marker_y), vertical_marker_label(label))
                                .anchor(egui::Align2::LEFT_CENTER)
                                .color(s.color),
                        );
                    }
                }
            });
    }

    fn run_preview(&mut self, db: &DbBackend) {
        let Some(plugin_kind) = self.selected_plugin else {
            return;
        };
        if let Err(e) = self.selected_flow(db) {
            self.status = format!("Error: {e}");
            return;
        }
        self.sync_available(db);

        let plugin = plugin_kind.create();
        let required = plugin.required_series();
        Self::ensure_input_bindings(&mut self.input_bindings, &required, &self.available);

        let mut series_ids = Vec::with_capacity(self.input_bindings.len());
        for binding in &self.input_bindings {
            let Some(series_id) = binding.selected_series_id else {
                self.status = format!("Error: no series selected for {}", binding.required_name);
                return;
            };
            series_ids.push(series_id);
        }

        // A failed read stops here: the plugin never runs on missing data and nothing is saved.
        let colors = generate_colors(series_ids.len());
        self.input_series.clear();
        self.preview_series.clear();
        match db.load_inputs(&self.available, &series_ids, &colors) {
            Ok(inputs) => self.input_series = inputs,
            Err(e) => {
                self.status = format!("Error: {e}");
                return;
            }
        }

        match plugin.compute(&self.input_series) {
            Ok(results) => {
                self.preview_series = results;
                self.status = format!("OK — {} new series computed.", self.preview_series.len());
            }
            Err(e) => {
                self.status = format!("Error: {}", e);
            }
        }
    }

    /// Resolves the bindings when the plugin changed, and re-resolves selections that are not
    /// in the (new) flow's series list.
    fn ensure_input_bindings(
        bindings: &mut Vec<InputBinding>,
        required: &[String],
        available: &[SeriesInfo],
    ) {
        let rebuild = bindings.len() != required.len()
            || bindings
                .iter()
                .zip(required)
                .any(|(binding, name)| binding.required_name != *name);
        let stale: Vec<bool> = bindings
            .iter()
            .map(|b| {
                b.selected_series_id
                    .is_some_and(|id| available.iter().all(|s| s.id != id))
            })
            .collect();
        if !rebuild && !stale.contains(&true) {
            return;
        }

        let resolved = resolve_inputs(required, available);
        if rebuild {
            *bindings = required
                .iter()
                .zip(resolved)
                .map(|(name, id)| InputBinding {
                    required_name: name.clone(),
                    selected_series_id: id,
                })
                .collect();
        } else {
            for ((binding, id), stale) in bindings.iter_mut().zip(resolved).zip(stale) {
                if stale {
                    binding.selected_series_id = id;
                }
            }
        }
    }

    fn save_results_or_confirm(&mut self, db: &DbBackend) {
        let flow_id = match self.selected_flow(db) {
            Ok(id) => id,
            Err(e) => {
                self.save_status = format!("Error: {e}");
                return;
            }
        };

        let names = self
            .preview_series
            .iter()
            .map(|series| series.name.clone())
            .collect::<Vec<_>>();
        match db.existing_series_for_flow(flow_id, &names) {
            Ok(existing) if existing.is_empty() => self.save_results(db, false),
            Ok(existing) => {
                self.overwrite_conflicts = existing.into_iter().map(|series| series.name).collect();
                self.show_overwrite_confirm = true;
            }
            Err(e) => {
                self.save_status = format!("Error: {}", e);
            }
        }
    }

    fn save_results(&mut self, db: &DbBackend, overwrite: bool) {
        let flow_id = match self.selected_flow(db) {
            Ok(id) => id,
            Err(e) => {
                self.save_status = format!("Error: {e}");
                return;
            }
        };

        let mut saved = 0;
        let mut errors = Vec::new();
        for series in &self.preview_series {
            let result = if overwrite {
                db.replace_series_for_flow(flow_id, series)
            } else {
                db.create_series_for_flow(flow_id, series)
            };
            match result {
                Ok(()) => saved += 1,
                Err(e) => errors.push(e),
            }
        }

        // New or changed series: show them in the list and the flow's counts again.
        self.flow_table.clear_stats_cache();
        self.available_flow = None;
        self.save_status = if errors.is_empty() {
            format!("Saved {} series to database.", saved)
        } else {
            format!("Saved {}, errors: {}", saved, errors.join("; "))
        };
    }

    fn show_overwrite_dialog(&mut self, ctx: &egui::Context, db: &DbBackend) {
        if !self.show_overwrite_confirm {
            return;
        }

        egui::Window::new("Overwrite existing series?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label("The following derived series already exist:");
                ui.add_space(4.0);
                for name in &self.overwrite_conflicts {
                    ui.label(format!("  • {}", name));
                }
                ui.add_space(8.0);
                ui.label("Overwrite replaces the old derived series with the new plugin output.");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.show_overwrite_confirm = false;
                    }
                    if ui.button("Overwrite").clicked() {
                        self.show_overwrite_confirm = false;
                        self.save_results(db, true);
                    }
                });
            });
    }
}
