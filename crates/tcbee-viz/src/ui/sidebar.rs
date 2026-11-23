//! Widgets shared by the sidebars of the single and multi flow tabs.

use egui::{RichText, Ui};
use ts_storage::Flow;

use crate::{
    backend::db::DbBackend,
    data::{
        plot_groups::{PlotGroups, Preset, SeriesKey},
        plot_state::PlotState,
    },
    settings::AppSettings,
    ui::{flow_table::FlowTable, series_table::SeriesAction, table, theme},
};

/// Space between a table that fills the sidebar and the controls below it
pub const BOTTOM_GAP: f32 = 12.0;
const OUTLIER_TOOLTIP: &str = "Automatically removes only leading points whose values are far outside the following steady-state data, so large initial CWND or ssthresh values do not distort auto-fit.";

/// The selected flow of `state` as a card, and the flow table while no flow is selected or the
/// user is `choosing` another one, at most `table_height` high. Returns the id of a newly
/// picked flow; picking the selected flow again only hides the table.
#[allow(clippy::too_many_arguments)]
pub fn flow_picker(
    ui: &mut Ui,
    db: &DbBackend,
    flows: &[Flow],
    flow_table: &mut FlowTable,
    state: &PlotState,
    choosing: &mut bool,
    table_height: f32,
    id_salt: &'static str,
) -> Option<i64> {
    if let Some(flow_id) = state.flow_id {
        if selected_flow_card(ui, db, flow_id, &state.flow_label, *choosing) {
            *choosing = !*choosing;
        }
        ui.add_space(4.0);
    }
    if state.flow_id.is_some() && !*choosing {
        return None;
    }

    let mut picked = None;
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_max_height(table_height);
        if let Some(flow_id) = flow_table.show_with_id_salt(ui, db, flows, state.flow_id, id_salt) {
            *choosing = false;
            picked = (state.flow_id != Some(flow_id)).then_some(flow_id);
        }
    });
    picked
}

/// The selected flow as a card, `label` from `format_flow`, with the process below it if
/// known. The button reads "Change" while the table is hidden and "Done" while `choosing`.
/// Returns true when it was clicked.
fn selected_flow_card(
    ui: &mut Ui,
    db: &DbBackend,
    flow_id: i64,
    label: &str,
    choosing: bool,
) -> bool {
    let dark_mode = ui.visuals().dark_mode;
    // The label is empty if the flow is missing from the database
    let label = if label.is_empty() {
        format!("Flow {flow_id}")
    } else {
        label.to_string()
    };
    let mut clicked = false;
    let response = table::frame(dark_mode)
        .fill(theme::table_row_selected(dark_mode))
        .inner_margin(egui::Margin {
            left: 12,
            right: 8,
            top: 6,
            bottom: 6,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let text = if choosing { "Done" } else { "Change" };
                    clicked = ui.button(text).clicked();
                    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&label).strong().color(theme::text(dark_mode)),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&label);
                        let owner = db.owner_label(flow_id);
                        if !owner.is_empty() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(owner)
                                        .small()
                                        .color(theme::muted_text(dark_mode)),
                                )
                                .truncate(),
                            );
                        }
                    });
                });
            });
        })
        .response;
    // An accent stripe inside the border on the left sets the card apart from the table rows
    let inner = response.rect.shrink(1.0);
    let stripe = egui::Rect::from_min_size(inner.min, egui::vec2(4.0, inner.height()));
    ui.painter().rect_filled(
        stripe,
        egui::CornerRadius {
            nw: 6,
            sw: 6,
            ne: 0,
            se: 0,
        },
        theme::TOP_BAR_ACTIVE,
    );
    clicked
}

/// Change the selected metrics of `state` as the user asked in a `SeriesTable`
pub fn apply_series_action(
    state: &mut PlotState,
    db: &DbBackend,
    action: SeriesAction,
    settings: &AppSettings,
) {
    match action {
        SeriesAction::Toggle(id) => state.toggle_series(db, id, settings),
        SeriesAction::Select(ids) => state.select_series(db, &ids, settings),
        SeriesAction::Deselect(ids) => state.deselect_series(&ids),
    }
}

/// The "Remove outliers" checkbox, true when it changed
pub fn outliers_checkbox(ui: &mut Ui, remove_outliers: &mut bool) -> bool {
    ui.scope(|ui| {
        ui.style_mut().interaction.tooltip_delay = 0.0;
        ui.checkbox(remove_outliers, "Remove outliers")
            .on_hover_text(OUTLIER_TOOLTIP)
            .changed()
    })
    .inner
}

/// A drop-down of the `presets` that sets the plot groups, showing "Custom" once they were
/// edited. Returns true when a preset was picked.
pub fn layout_picker(
    ui: &mut Ui,
    id_salt: &str,
    groups: &mut PlotGroups,
    selected: &[SeriesKey],
    presets: &[Preset],
) -> bool {
    let mut picked = None;
    let current = groups.auto().map_or("Custom", preset_label);
    egui::ComboBox::from_id_salt(id_salt)
        .selected_text(current)
        .show_ui(ui, |ui| {
            for &preset in presets {
                if ui
                    .selectable_label(groups.auto() == Some(preset), preset_label(preset))
                    .clicked()
                {
                    picked = Some(preset);
                }
            }
        })
        .response
        .on_hover_text("Which metrics share a plot");
    if let Some(preset) = picked {
        groups.apply_preset(preset, selected);
    }
    picked.is_some()
}

pub fn preset_label(preset: Preset) -> &'static str {
    match preset {
        Preset::AllTogether => "All in one plot",
        Preset::PerMetric => "One plot per metric",
        Preset::PerFlow => "One plot per flow",
        Preset::PerSeries => "One plot per metric and flow",
    }
}
