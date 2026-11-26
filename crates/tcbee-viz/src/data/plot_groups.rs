//! Which selected series share a plot. Each group is drawn as one plot; a series may be in
//! several groups, and selected series in no group are drawn together in an implicit
//! "Ungrouped" plot. Groups live for the session only.

use ts_storage::{Dir, SeriesInfo};

use crate::data::series_data::SeriesData;

/// The flow a series belongs to: the only one of the single flow tab, or A/B of the multi
/// flow tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowSlot {
    Single,
    A,
    B,
}

/// A series by what it measures, not by its id, so groups carry over to another flow.
/// Names repeat across sources and directions (`snd_cwnd` of sock and of a derived plugin),
/// so the key holds all three.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SeriesKey {
    pub slot: FlowSlot,
    pub source: String,
    pub dir: Dir,
    pub name: String,
}

impl SeriesKey {
    pub fn from_info(slot: FlowSlot, info: &SeriesInfo) -> Self {
        Self {
            slot,
            source: info.source.clone(),
            dir: info.dir,
            name: info.name.clone(),
        }
    }

    /// The key of a loaded series; series without a catalog row are keyed by their name.
    pub fn of(slot: FlowSlot, sd: &SeriesData) -> Self {
        match &sd.info {
            Some(info) => Self::from_info(slot, info),
            None => Self {
                slot,
                source: String::new(),
                dir: Dir::None,
                name: sd.name.clone(),
            },
        }
    }
}

/// Plot id of the implicit group of selected series that are in no group.
pub const UNGROUPED: u64 = 0;

#[derive(Clone, Debug, PartialEq)]
pub struct PlotGroup {
    /// Stable across renames and deletes of other groups; plot ids are made from it, so a
    /// plot keeps its zoom while the groups change.
    pub id: u64,
    pub name: String,
    pub members: Vec<SeriesKey>,
    /// Hidden groups are neither drawn nor exported.
    pub hidden: bool,
}

/// Quick layouts that rebuild the groups from the current selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    /// One plot with everything.
    AllTogether,
    /// One plot per metric, with flow A and B of a metric together.
    PerMetric,
    /// One plot per flow (multi flow tab only).
    PerFlow,
    /// One plot per metric and flow.
    PerSeries,
}

/// A group as it is drawn: only the selected members, never hidden.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedGroup {
    pub id: u64,
    pub name: String,
    pub members: Vec<SeriesKey>,
}

#[derive(Clone, Debug)]
pub struct PlotGroups {
    groups: Vec<PlotGroup>,
    next_id: u64,
    /// While set, the groups follow this preset as the selection changes. Editing a group by
    /// hand ends it.
    auto: Option<Preset>,
}

impl Default for PlotGroups {
    fn default() -> Self {
        Self {
            groups: Vec::new(),
            next_id: UNGROUPED + 1,
            auto: Some(Preset::AllTogether),
        }
    }
}

impl PlotGroups {
    pub fn groups(&self) -> &[PlotGroup] {
        &self.groups
    }

    /// The preset the groups follow, `None` once edited by hand.
    pub fn auto(&self) -> Option<Preset> {
        self.auto
    }

    /// Follows the selection while a preset is active. Call once per frame before drawing.
    pub fn sync(&mut self, selected: &[SeriesKey]) {
        if let Some(preset) = self.auto {
            self.rebuild(preset, selected);
        }
    }

    /// Replaces the groups with `preset` applied to `selected` and keeps following it.
    pub fn apply_preset(&mut self, preset: Preset, selected: &[SeriesKey]) {
        self.auto = Some(preset);
        self.rebuild(preset, selected);
    }

    fn rebuild(&mut self, preset: Preset, selected: &[SeriesKey]) {
        let mut layout: Vec<(String, Vec<SeriesKey>)> = Vec::new();
        let mut push = |name: String, key: &SeriesKey| match layout.iter_mut().find(|g| g.0 == name)
        {
            Some(group) => group.1.push(key.clone()),
            None => layout.push((name, vec![key.clone()])),
        };
        for key in selected {
            match preset {
                Preset::AllTogether => push("All".to_string(), key),
                Preset::PerMetric => push(metric_name(key), key),
                Preset::PerFlow => push(flow_name(key.slot).to_string(), key),
                Preset::PerSeries => push(series_name(key), key),
            }
        }
        if layout.is_empty() && preset == Preset::AllTogether {
            layout.push(("All".to_string(), Vec::new()));
        }

        let old = std::mem::take(&mut self.groups);
        self.groups = layout
            .into_iter()
            .map(
                |(name, members)| match old.iter().find(|g| g.name == name) {
                    // Same name, same plot: keep its id (zoom) and visibility
                    Some(g) => PlotGroup {
                        id: g.id,
                        name,
                        members,
                        hidden: g.hidden,
                    },
                    None => {
                        let id = self.take_id();
                        PlotGroup {
                            id,
                            name,
                            members,
                            hidden: false,
                        }
                    }
                },
            )
            .collect();
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn group_mut(&mut self, id: u64) -> Option<&mut PlotGroup> {
        self.groups.iter_mut().find(|g| g.id == id)
    }

    /// Adds an empty group and returns its id.
    pub fn add_group(&mut self) -> u64 {
        self.auto = None;
        let id = self.take_id();
        let name = format!("Group {}", self.groups.len() + 1);
        self.groups.push(PlotGroup {
            id,
            name,
            members: Vec::new(),
            hidden: false,
        });
        id
    }

    /// Removes a group; its members that are in no other group move to Ungrouped.
    pub fn remove_group(&mut self, id: u64) {
        self.auto = None;
        self.groups.retain(|g| g.id != id);
    }

    pub fn rename(&mut self, id: u64, name: String) {
        self.auto = None;
        if let Some(g) = self.group_mut(id) {
            g.name = name;
        }
    }

    pub fn set_hidden(&mut self, id: u64, hidden: bool) {
        if let Some(g) = self.group_mut(id) {
            g.hidden = hidden;
        }
    }

    /// Adds `key` to group `to`; a key already in the group is left as it is.
    pub fn copy_member(&mut self, key: &SeriesKey, to: u64) {
        self.auto = None;
        if let Some(g) = self.group_mut(to) {
            if !g.members.contains(key) {
                g.members.push(key.clone());
            }
        }
    }

    /// Moves `key` from group `from` (or Ungrouped) to group `to` (or Ungrouped).
    pub fn move_member(&mut self, key: &SeriesKey, from: u64, to: u64) {
        if from == to {
            return;
        }
        self.copy_member(key, to);
        self.remove_member(key, from);
    }

    pub fn remove_member(&mut self, key: &SeriesKey, from: u64) {
        self.auto = None;
        if let Some(g) = self.group_mut(from) {
            g.members.retain(|k| k != key);
        }
    }

    /// The plots to draw for `selected`, in group order with Ungrouped last. Members that are
    /// not selected are left out but kept in the group, so selecting them again restores
    /// them. Empty groups are kept so that new groups show up as drop targets.
    pub fn resolve(&self, selected: &[SeriesKey]) -> Vec<ResolvedGroup> {
        let mut plots: Vec<ResolvedGroup> = self
            .groups
            .iter()
            .filter(|g| !g.hidden)
            .map(|g| ResolvedGroup {
                id: g.id,
                name: g.name.clone(),
                members: g
                    .members
                    .iter()
                    .filter(|k| selected.contains(k))
                    .cloned()
                    .collect(),
            })
            .collect();
        let ungrouped = self.ungrouped(selected);
        if !ungrouped.is_empty() {
            plots.push(ResolvedGroup {
                id: UNGROUPED,
                name: "Ungrouped".to_string(),
                members: ungrouped,
            });
        }
        plots
    }

    /// Selected series in no group, hidden or not.
    pub fn ungrouped(&self, selected: &[SeriesKey]) -> Vec<SeriesKey> {
        selected
            .iter()
            .filter(|k| !self.groups.iter().any(|g| g.members.contains(k)))
            .cloned()
            .collect()
    }
}

pub fn flow_name(slot: FlowSlot) -> &'static str {
    match slot {
        FlowSlot::Single => "Flow",
        FlowSlot::A => "Flow A",
        FlowSlot::B => "Flow B",
    }
}

/// `snd_cwnd · sock · send`, like the series lists.
pub fn metric_name(key: &SeriesKey) -> String {
    match (key.source.is_empty(), key.dir) {
        (true, _) => key.name.clone(),
        (false, Dir::None) => format!("{} · {}", key.name, key.source),
        (false, Dir::Send) => format!("{} · {} · send", key.name, key.source),
        (false, Dir::Recv) => format!("{} · {} · recv", key.name, key.source),
    }
}

/// The metric name, prefixed with the flow in the multi flow tab (`A: snd_cwnd · sock`).
pub fn series_name(key: &SeriesKey) -> String {
    match key.slot {
        FlowSlot::Single => metric_name(key),
        FlowSlot::A => format!("A: {}", metric_name(key)),
        FlowSlot::B => format!("B: {}", metric_name(key)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(slot: FlowSlot, source: &str, dir: Dir, name: &str) -> SeriesKey {
        SeriesKey {
            slot,
            source: source.to_string(),
            dir,
            name: name.to_string(),
        }
    }

    fn single(name: &str) -> SeriesKey {
        key(FlowSlot::Single, "sock", Dir::Send, name)
    }

    fn names(plots: &[ResolvedGroup]) -> Vec<(&str, Vec<&str>)> {
        plots
            .iter()
            .map(|p| {
                let members = p.members.iter().map(|k| k.name.as_str()).collect();
                (p.name.as_str(), members)
            })
            .collect()
    }

    #[test]
    fn all_together_follows_the_selection() {
        let mut groups = PlotGroups::default();
        let mut selected = vec![single("cwnd")];
        groups.sync(&selected);
        selected.push(single("ssthresh"));
        groups.sync(&selected);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("All", vec!["cwnd", "ssthresh"])]
        );
    }

    #[test]
    fn editing_ends_the_preset_and_new_series_are_ungrouped() {
        let mut groups = PlotGroups::default();
        let mut selected = vec![single("cwnd"), single("ssthresh"), single("retrans")];
        groups.sync(&selected);
        let all = groups.groups()[0].id;
        let own = groups.add_group();
        groups.move_member(&single("retrans"), all, own);
        assert_eq!(groups.auto(), None);
        selected.push(single("rtt"));
        groups.sync(&selected);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![
                ("All", vec!["cwnd", "ssthresh"]),
                ("Group 2", vec!["retrans"]),
                ("Ungrouped", vec!["rtt"]),
            ]
        );
    }

    #[test]
    fn copies_show_in_both_groups_once() {
        let mut groups = PlotGroups::default();
        let selected = vec![single("cwnd"), single("ssthresh")];
        groups.sync(&selected);
        let all = groups.groups()[0].id;
        let other = groups.add_group();
        groups.copy_member(&single("cwnd"), other);
        groups.copy_member(&single("cwnd"), other);
        groups.copy_member(&single("cwnd"), all);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("All", vec!["cwnd", "ssthresh"]), ("Group 2", vec!["cwnd"])]
        );
    }

    #[test]
    fn moving_to_the_same_group_keeps_it() {
        let mut groups = PlotGroups::default();
        let selected = vec![single("cwnd")];
        groups.sync(&selected);
        let all = groups.groups()[0].id;
        groups.move_member(&single("cwnd"), all, all);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("All", vec!["cwnd"])]
        );
    }

    #[test]
    fn deleted_and_moved_out_members_go_to_ungrouped() {
        let mut groups = PlotGroups::default();
        let selected = vec![single("cwnd"), single("ssthresh")];
        groups.sync(&selected);
        let all = groups.groups()[0].id;
        groups.move_member(&single("ssthresh"), all, UNGROUPED);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("All", vec!["cwnd"]), ("Ungrouped", vec!["ssthresh"])]
        );
        groups.remove_group(all);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("Ungrouped", vec!["cwnd", "ssthresh"])]
        );
    }

    #[test]
    fn deselected_members_come_back_when_selected_again() {
        let mut groups = PlotGroups::default();
        let selected = vec![single("cwnd"), single("ssthresh")];
        groups.sync(&selected);
        groups.add_group();
        assert_eq!(
            names(&groups.resolve(&selected[..1])),
            vec![("All", vec!["cwnd"]), ("Group 2", vec![])]
        );
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("All", vec!["cwnd", "ssthresh"]), ("Group 2", vec![])]
        );
    }

    #[test]
    fn hidden_groups_are_not_drawn_and_hold_their_members() {
        let mut groups = PlotGroups::default();
        let selected = vec![single("cwnd")];
        groups.sync(&selected);
        let all = groups.groups()[0].id;
        groups.set_hidden(all, true);
        assert!(groups.resolve(&selected).is_empty());
        groups.set_hidden(all, false);
        assert_eq!(groups.resolve(&selected).len(), 1);
    }

    #[test]
    fn same_name_from_other_source_or_dir_is_another_series() {
        let send = single("snd_cwnd");
        let derived = key(FlowSlot::Single, "derived", Dir::Send, "snd_cwnd");
        let recv = key(FlowSlot::Single, "sock", Dir::Recv, "snd_cwnd");
        let selected = vec![send.clone(), derived.clone(), recv.clone()];
        let mut groups = PlotGroups::default();
        groups.apply_preset(Preset::PerMetric, &selected);
        assert_eq!(groups.resolve(&selected).len(), 3);
        let first = groups.groups()[0].id;
        let other = groups.add_group();
        groups.move_member(&send, first, other);
        let plots = groups.resolve(&selected);
        assert_eq!(
            plots.iter().find(|p| p.id == other).unwrap().members,
            vec![send]
        );
    }

    #[test]
    fn multi_flow_presets() {
        let a = |n| key(FlowSlot::A, "sock", Dir::Send, n);
        let b = |n| key(FlowSlot::B, "sock", Dir::Send, n);
        let selected = vec![a("cwnd"), a("rtt"), b("cwnd")];
        let mut groups = PlotGroups::default();
        let layout = |groups: &mut PlotGroups, preset| {
            groups.apply_preset(preset, &selected);
            groups
                .resolve(&selected)
                .iter()
                .map(|p| (p.name.clone(), p.members.len()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            layout(&mut groups, Preset::AllTogether),
            vec![("All".into(), 3)]
        );
        assert_eq!(
            layout(&mut groups, Preset::PerMetric),
            vec![
                ("cwnd · sock · send".into(), 2),
                ("rtt · sock · send".into(), 1)
            ]
        );
        assert_eq!(
            layout(&mut groups, Preset::PerFlow),
            vec![("Flow A".into(), 2), ("Flow B".into(), 1)]
        );
        assert_eq!(
            layout(&mut groups, Preset::PerSeries),
            vec![
                ("A: cwnd · sock · send".into(), 1),
                ("A: rtt · sock · send".into(), 1),
                ("B: cwnd · sock · send".into(), 1),
            ]
        );
    }

    #[test]
    fn ids_stay_stable() {
        let selected = vec![single("cwnd"), single("ssthresh")];
        let mut groups = PlotGroups::default();
        groups.apply_preset(Preset::PerMetric, &selected);
        let ids: Vec<u64> = groups.groups().iter().map(|g| g.id).collect();
        groups.apply_preset(Preset::PerMetric, &selected[1..]);
        assert_eq!(groups.groups()[0].id, ids[1]);
        groups.remove_group(ids[1]);
        let new = groups.add_group();
        assert!(!ids.contains(&new) && new != UNGROUPED);
    }

    #[test]
    fn presets_keep_hidden_groups_hidden() {
        let selected = vec![single("cwnd"), single("rtt")];
        let mut groups = PlotGroups::default();
        groups.apply_preset(Preset::PerMetric, &selected);
        let rtt = groups.groups()[1].id;
        groups.set_hidden(rtt, true);
        groups.sync(&selected);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("cwnd · sock · send", vec!["cwnd"])]
        );
        groups.set_hidden(groups.groups()[0].id, true);
        assert!(groups.resolve(&selected).is_empty());
    }

    #[test]
    fn moving_to_and_from_ungrouped() {
        let selected = vec![single("cwnd"), single("rtt")];
        let mut groups = PlotGroups::default();
        let own = groups.add_group();
        groups.move_member(&single("rtt"), UNGROUPED, own);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("Group 1", vec!["rtt"]), ("Ungrouped", vec!["cwnd"])]
        );
        groups.move_member(&single("rtt"), own, UNGROUPED);
        assert_eq!(
            names(&groups.resolve(&selected)),
            vec![("Group 1", vec![]), ("Ungrouped", vec!["cwnd", "rtt"])]
        );
    }
}
