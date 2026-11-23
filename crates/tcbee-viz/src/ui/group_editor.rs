//! The Groups tab of the flow tab sidebars: which selected metrics share a plot.

use egui::{Color32, RichText, Ui};

use crate::{
    data::plot_groups::{series_name, PlotGroup, PlotGroups, Preset, SeriesKey, UNGROUPED},
    ui::{sidebar::layout_picker, tab_single_flow::section_heading, theme},
};

/// The tabs of the flow tab sidebars.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SidebarTab {
    /// Flows and metrics to plot.
    #[default]
    Selection,
    /// Which metrics share a plot.
    Groups,
}

/// The tab strip at the top of a sidebar.
pub fn tab_strip(ui: &mut Ui, tab: &mut SidebarTab) {
    ui.horizontal(|ui| {
        ui.selectable_value(tab, SidebarTab::Selection, "Selection");
        ui.selectable_value(tab, SidebarTab::Groups, "Groups");
    });
    ui.separator();
}

/// The group editor. `selected` are the groupable selected series with their plot colours.
/// Returns true when the plots should fit their data again.
pub fn show(
    ui: &mut Ui,
    id_salt: &str,
    groups: &mut PlotGroups,
    selected: &[(SeriesKey, Color32)],
    presets: &[Preset],
) -> bool {
    let keys: Vec<SeriesKey> = selected.iter().map(|(k, _)| k.clone()).collect();
    let mut changed = false;

    section_heading(ui, "Layout");
    ui.horizontal(|ui| {
        changed |= layout_picker(ui, &format!("{id_salt}_layout"), groups, &keys, presets);
        if ui.button("New group").clicked() {
            groups.add_group();
            changed = true;
        }
    });
    ui.label(
        RichText::new("Each group is one plot. Metrics in no group share the Ungrouped plot.")
            .small()
            .color(theme::muted_text(ui.visuals().dark_mode)),
    );
    ui.add_space(8.0);

    if keys.is_empty() {
        ui.label(
            RichText::new("Select metrics in the Selection tab.")
                .color(Color32::GRAY)
                .italics(),
        );
    }

    let mut edits = Vec::new();
    for group in groups.groups() {
        group_card(ui, id_salt, group, selected, &mut edits);
        ui.add_space(6.0);
    }
    let ungrouped = groups.ungrouped(&keys);
    if !ungrouped.is_empty() {
        let card = PlotGroup {
            id: UNGROUPED,
            name: "Ungrouped".to_string(),
            members: ungrouped,
            hidden: false,
        };
        group_card(ui, id_salt, &card, selected, &mut edits);
    }

    changed |= !edits.is_empty();
    for edit in edits {
        edit.apply(groups);
    }
    changed
}

/// A change to the groups, applied after drawing them.
enum Edit {
    Rename(u64, String),
    SetHidden(u64, bool),
    Remove(u64),
    RemoveMember(SeriesKey, u64),
}

impl Edit {
    fn apply(self, groups: &mut PlotGroups) {
        match self {
            Edit::Rename(id, name) => groups.rename(id, name),
            Edit::SetHidden(id, hidden) => groups.set_hidden(id, hidden),
            Edit::Remove(id) => groups.remove_group(id),
            Edit::RemoveMember(key, from) => groups.remove_member(&key, from),
        }
    }
}

fn group_card(
    ui: &mut Ui,
    id_salt: &str,
    group: &PlotGroup,
    selected: &[(SeriesKey, Color32)],
    edits: &mut Vec<Edit>,
) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        card_header(ui, id_salt, group, edits);
        if group.members.is_empty() {
            ui.label(RichText::new("No metrics").color(Color32::GRAY).italics());
        }
        for key in &group.members {
            let color = selected.iter().find(|(k, _)| k == key).map(|(_, c)| *c);
            ui.horizontal(|ui| {
                member_chip(ui, key, color);
                if group.id != UNGROUPED
                    && ui
                        .small_button("✖")
                        .on_hover_text("Remove from this group")
                        .clicked()
                {
                    edits.push(Edit::RemoveMember(key.clone(), group.id));
                }
            });
        }
    });
}

fn card_header(ui: &mut Ui, id_salt: &str, group: &PlotGroup, edits: &mut Vec<Edit>) {
    ui.horizontal(|ui| {
        if group.id == UNGROUPED {
            ui.label(RichText::new(&group.name).strong());
            return;
        }
        let mut name = group.name.clone();
        let response = ui.add(
            egui::TextEdit::singleline(&mut name)
                .id_salt((id_salt, "group_name", group.id))
                .desired_width(ui.available_width() - 64.0),
        );
        if response.changed() {
            edits.push(Edit::Rename(group.id, name));
        }
        let (label, tip) = if group.hidden {
            ("Show", "Draw and export this group again")
        } else {
            ("Hide", "Neither draw nor export this group for now")
        };
        if ui.small_button(label).on_hover_text(tip).clicked() {
            edits.push(Edit::SetHidden(group.id, !group.hidden));
        }
        if ui
            .small_button("🗑")
            .on_hover_text("Delete the group; its metrics stay selected")
            .clicked()
        {
            edits.push(Edit::Remove(group.id));
        }
    });
}

/// A metric with its plot colour; dimmed while it is not selected.
fn member_chip(ui: &mut Ui, key: &SeriesKey, color: Option<Color32>) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    ui.painter()
        .circle_filled(rect.center(), 4.0, color.unwrap_or(Color32::GRAY));
    let text = RichText::new(series_name(key));
    if color.is_some() {
        ui.label(text);
    } else {
        ui.label(text.weak())
            .on_hover_text("Not selected: shown again once selected");
    }
}
