//! The View tab of the flow tab sidebars: which selected metrics share a plot.

use egui::{Color32, CursorIcon, DragAndDrop, RichText, Ui};

use crate::{
    data::{
        plot_groups::{series_name, PlotGroup, PlotGroups, Preset, SeriesKey, UNGROUPED},
        series_styles::{SeriesStyles, LINE_WIDTH_RANGE},
    },
    ui::{
        plot_frame::{heights_are_picked, reset_heights},
        sidebar::layout_picker,
        tab_single_flow::section_heading,
        theme,
    },
};

/// The tabs of the flow tab sidebars.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SidebarTab {
    /// Flows and metrics to plot.
    #[default]
    Selection,
    /// Which metrics share a plot.
    View,
}

/// The tab strip at the top of a sidebar.
pub fn tab_strip(ui: &mut Ui, tab: &mut SidebarTab) {
    ui.horizontal(|ui| {
        ui.selectable_value(tab, SidebarTab::Selection, "Selection");
        ui.selectable_value(tab, SidebarTab::View, "View");
    });
    ui.separator();
}

/// The group editor. `selected` are the groupable selected series with their plot colours,
/// `pick_colors` whether the user may change them. Returns true when the plots should fit
/// their data again.
#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut Ui,
    id_salt: &str,
    (groups, styles): (&mut PlotGroups, &mut SeriesStyles),
    show_grid: &mut bool,
    plot_stack: egui::Id,
    selected: &[(SeriesKey, Color32)],
    presets: &[Preset],
    pick_colors: bool,
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
        let resized = heights_are_picked(ui.ctx(), plot_stack);
        if ui
            .add_enabled(resized, egui::Button::new("Reset heights"))
            .on_hover_text("Let the plots fill the window again")
            .on_disabled_hover_text(
                "The plots fill the window; drag a plot's lower edge to resize it",
            )
            .clicked()
        {
            reset_heights(ui.ctx(), plot_stack);
        }
    });
    ui.checkbox(show_grid, "Grid lines");
    ui.label(
        RichText::new(
            "Each group is one plot; metrics in no group share the Ungrouped plot. Drag a \
             metric to move it, hold Ctrl (Cmd) while dropping to copy it.",
        )
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

    let copying = ui.input(|i| i.modifiers.command);
    if copying && DragAndDrop::has_payload_of_type::<DraggedMember>(ui.ctx()) {
        ui.ctx().set_cursor_icon(CursorIcon::Copy);
    }
    let targets: Vec<(u64, String)> = groups
        .groups()
        .iter()
        .map(|g| (g.id, g.name.clone()))
        .collect();
    let mut edits = Vec::new();
    for group in groups.groups() {
        group_card(
            ui,
            id_salt,
            group,
            selected,
            pick_colors,
            &targets,
            styles,
            copying,
            &mut edits,
        );
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
        group_card(
            ui,
            id_salt,
            &card,
            selected,
            pick_colors,
            &targets,
            styles,
            copying,
            &mut edits,
        );
    }

    // Only plots whose series changed need a new fit: renaming, hiding or recolouring
    // keeps the zoom
    changed |= edits.iter().any(Edit::changes_series);
    for edit in edits {
        edit.apply(groups, styles);
    }
    changed
}

/// A change to the groups, applied after drawing them: the cards borrow the groups.
enum Edit {
    Rename(u64, String),
    SetHidden(u64, bool),
    Remove(u64),
    RemoveMember(SeriesKey, u64),
    /// Key, from, to.
    MoveMember(SeriesKey, u64, u64),
    CopyMember(SeriesKey, u64),
    SetColor(SeriesKey, Color32),
    SetLineWidth(SeriesKey, f32),
}

/// What a dragged metric chip carries.
struct DraggedMember {
    key: SeriesKey,
    from: u64,
}

impl Edit {
    fn changes_series(&self) -> bool {
        matches!(
            self,
            Edit::Remove(_) | Edit::RemoveMember(..) | Edit::MoveMember(..) | Edit::CopyMember(..)
        )
    }

    fn apply(self, groups: &mut PlotGroups, styles: &mut SeriesStyles) {
        match self {
            Edit::Rename(id, name) => groups.rename(id, name),
            Edit::SetHidden(id, hidden) => groups.set_hidden(id, hidden),
            Edit::Remove(id) => groups.remove_group(id),
            Edit::RemoveMember(key, from) => groups.remove_member(&key, from),
            Edit::MoveMember(key, from, to) => groups.move_member(&key, from, to),
            Edit::CopyMember(key, to) => groups.copy_member(&key, to),
            Edit::SetColor(key, color) => styles.set_color(key, color),
            Edit::SetLineWidth(key, width) => styles.set_line_width(key, width),
        }
    }
}

/// A group's card, a drop target for metric chips. `targets` are all groups as (id, name),
/// `copying` whether a drop copies instead of moving.
#[allow(clippy::too_many_arguments)]
fn group_card(
    ui: &mut Ui,
    id_salt: &str,
    group: &PlotGroup,
    selected: &[(SeriesKey, Color32)],
    pick_colors: bool,
    targets: &[(u64, String)],
    styles: &SeriesStyles,
    copying: bool,
    edits: &mut Vec<Edit>,
) {
    let frame = egui::Frame::group(ui.style());
    let (_, dropped) = ui.dnd_drop_zone::<DraggedMember, _>(frame, |ui| {
        ui.set_width(ui.available_width());
        card_header(ui, id_salt, group, edits);
        if group.members.is_empty() {
            ui.label(
                RichText::new("Drop metrics here")
                    .color(Color32::GRAY)
                    .italics(),
            );
        }
        for key in &group.members {
            let color = selected.iter().find(|(k, _)| k == key).map(|(_, c)| *c);
            ui.horizontal(|ui| {
                let id = egui::Id::new((id_salt, "member", group.id, key));
                let payload = DraggedMember {
                    key: key.clone(),
                    from: group.id,
                };
                if let Some(color) = color.filter(|_| pick_colors) {
                    let mut picked = color;
                    if egui::color_picker::color_edit_button_srgba(
                        ui,
                        &mut picked,
                        egui::color_picker::Alpha::Opaque,
                    )
                    .on_hover_text("Colour of this metric in every plot")
                    .changed()
                    {
                        edits.push(Edit::SetColor(key.clone(), picked));
                    }
                }
                ui.dnd_drag_source(id, payload, |ui| member_chip(ui, key, color.is_some()))
                    .response
                    .on_hover_cursor(CursorIcon::Grab);
                member_menu(ui, key, group.id, targets, styles, edits);
            });
        }
    });
    if let Some(dropped) = dropped {
        let key = dropped.key.clone();
        let edit = if copying && group.id != UNGROUPED {
            Edit::CopyMember(key, group.id)
        } else {
            Edit::MoveMember(key, dropped.from, group.id)
        };
        edits.push(edit);
    }
}

/// Moving, copying and removing a metric without dragging.
fn member_menu(
    ui: &mut Ui,
    key: &SeriesKey,
    from: u64,
    targets: &[(u64, String)],
    styles: &SeriesStyles,
    edits: &mut Vec<Edit>,
) {
    ui.menu_button("☰", |ui| {
        let mut width = styles.line_width(key);
        if ui
            .add(
                egui::Slider::new(&mut width, LINE_WIDTH_RANGE)
                    .step_by(0.5)
                    .suffix(" px")
                    .text("Line width"),
            )
            .changed()
        {
            edits.push(Edit::SetLineWidth(key.clone(), width));
        }
        ui.separator();
        let others: Vec<&(u64, String)> = targets.iter().filter(|(id, _)| *id != from).collect();
        ui.add_enabled_ui(!others.is_empty() || from != UNGROUPED, |ui| {
            ui.menu_button("Move to", |ui| {
                for (id, name) in &others {
                    if ui.button(name).clicked() {
                        edits.push(Edit::MoveMember(key.clone(), from, *id));
                        ui.close_menu();
                    }
                }
                if from != UNGROUPED && ui.button("Ungrouped").clicked() {
                    edits.push(Edit::MoveMember(key.clone(), from, UNGROUPED));
                    ui.close_menu();
                }
            });
        });
        ui.add_enabled_ui(!others.is_empty(), |ui| {
            ui.menu_button("Copy to", |ui| {
                for (id, name) in &others {
                    if ui.button(name).clicked() {
                        edits.push(Edit::CopyMember(key.clone(), *id));
                        ui.close_menu();
                    }
                }
            });
        });
        if from != UNGROUPED && ui.button("Remove from group").clicked() {
            edits.push(Edit::RemoveMember(key.clone(), from));
            ui.close_menu();
        }
    });
}

fn card_header(ui: &mut Ui, id_salt: &str, group: &PlotGroup, edits: &mut Vec<Edit>) {
    ui.horizontal(|ui| {
        if group.id == UNGROUPED {
            ui.label(RichText::new(&group.name).strong());
            return;
        }
        // Buttons first from the right, so the name field takes only the width left over
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .small_button("🗑")
                .on_hover_text("Delete the group; its metrics stay selected")
                .clicked()
            {
                edits.push(Edit::Remove(group.id));
            }
            let (label, tip) = if group.hidden {
                ("Show", "Draw and export this group again")
            } else {
                ("Hide", "Neither draw nor export this group for now")
            };
            if ui.small_button(label).on_hover_text(tip).clicked() {
                edits.push(Edit::SetHidden(group.id, !group.hidden));
            }
            let mut name = group.name.clone();
            let response = ui.add(
                egui::TextEdit::singleline(&mut name)
                    .id_salt((id_salt, "group_name", group.id))
                    .desired_width(ui.available_width()),
            );
            if response.changed() {
                edits.push(Edit::Rename(group.id, name));
            }
        });
    });
}

/// A metric's name; dimmed while it is not selected.
fn member_chip(ui: &mut Ui, key: &SeriesKey, selected: bool) {
    let text = RichText::new(series_name(key));
    if selected {
        ui.label(text);
    } else {
        ui.label(text.weak())
            .on_hover_text("Not selected: shown again once selected");
    }
}
