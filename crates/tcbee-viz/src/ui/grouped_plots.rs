//! The plots of the flow tabs: one plot per plot group, stacked, with a shared x axis.
//! The tabs keep the zoom state; this module draws and reports what changed.

use egui::{RichText, ScrollArea, Ui};
use egui_plot::{Corner, Legend, Line, Plot, PlotBounds, PlotPoints, VLine};

use crate::{
    data::{
        plot_groups::{FlowSlot, ResolvedGroup, SeriesKey},
        plot_state::PlotState,
        preprocessing::remove_leading_outliers,
        series_data::SeriesData,
    },
    export,
    ui::{
        event_labels, gap_marks,
        tab_single_flow::{
            plot_height_with_footer, seconds_grid_spacer, seconds_since_formatter,
            split_plot_height_with_footer, time_or_compact_coordinates_formatter,
            time_or_compact_formatter, to_plot_points,
        },
    },
};

/// Space around the data when fitting, as a fraction of its x and y span.
const PADDING_X: f64 = 0.02;
const PADDING_Y: f64 = 0.06;
/// Height of a group's name above its plot (px).
const HEADING_HEIGHT: f32 = 22.0;
/// Height of an empty group's drop strip (px).
const EMPTY_HEIGHT: f32 = 36.0;
/// Space below each plot (px).
const PLOT_GAP: f32 = 4.0;

type PlotDataBounds = ((f64, f64), (f64, f64));
/// The string events of a series with its legend name.
type NamedEvents<'a> = (String, egui::Color32, &'a [(f64, String)]);

/// A flow of the tab and the prefix of its series names in legends (`A:`).
pub struct Flow<'a> {
    pub slot: FlowSlot,
    pub state: &'a PlotState,
    pub prefix: &'static str,
}

impl Flow<'_> {
    /// The loaded series of `key`, if it belongs to this flow.
    fn series(&self, key: &SeriesKey) -> Option<&SeriesData> {
        if key.slot != self.slot {
            return None;
        }
        self.state
            .series
            .iter()
            .find(|s| SeriesKey::of(self.slot, s) == *key)
    }
}

/// The selected series of `flows` that can be grouped, with their plot colour: text series
/// are listed or marked separately and belong to no group.
pub fn selected_colors(flows: &[Flow]) -> Vec<(SeriesKey, egui::Color32)> {
    flows
        .iter()
        .flat_map(|f| {
            f.state
                .series
                .iter()
                .filter(|s| !s.is_string_type())
                .map(|s| (SeriesKey::of(f.slot, s), s.color))
        })
        .collect()
}

/// The keys of [`selected_colors`].
pub fn selected_keys(flows: &[Flow]) -> Vec<SeriesKey> {
    selected_colors(flows).into_iter().map(|(k, _)| k).collect()
}

pub struct Settings {
    /// Salt of the plot ids and the x axis link, unique per tab.
    pub id: &'static str,
    /// Time of the x axis's zero.
    pub x_origin: f64,
    /// X range to fit to when nothing narrower is known.
    pub data_x: (f64, f64),
    /// Fit both axes to the data this frame.
    pub fit: bool,
    /// Set this x range this frame.
    pub set_x: Option<(f64, f64)>,
    pub remove_outliers: bool,
    pub show_gaps: bool,
}

/// What the user did in the plots this frame.
#[derive(Default)]
pub struct Outcome {
    /// Per flow, in the order given: the visible x range when its data must be reloaded.
    pub reload: Vec<Option<(f64, f64)>>,
    pub right_clicked: bool,
    /// The visible part of each drawn group's plot, in group order.
    pub views: Vec<(u64, export::View)>,
}

impl Outcome {
    /// The x range shown, the same in every plot.
    pub fn x(&self) -> Option<(f64, f64)> {
        self.views.iter().find_map(|(_, v)| v.x)
    }
}

/// The drawn plots as export panels: each group's series by flow index and series id, and the
/// y range the plot shows. Hidden and empty groups are left out, as on screen.
pub fn export_panels(
    groups: &[ResolvedGroup],
    flows: &[Flow],
    outcome: &Outcome,
) -> Vec<export::ExportPanel> {
    outcome
        .views
        .iter()
        .filter_map(|(id, view)| {
            let group = groups.iter().find(|g| g.id == *id)?;
            let series = group
                .members
                .iter()
                .filter_map(|key| {
                    flows
                        .iter()
                        .enumerate()
                        .find_map(|(i, f)| f.series(key).map(|s| (i, s.series_id)))
                })
                .collect();
            Some(export::ExportPanel { series, y: view.y })
        })
        .collect()
}

/// A series as drawn in one plot.
struct Drawn<'a> {
    series: &'a SeriesData,
    name: String,
    points: Vec<[f64; 2]>,
}

/// Draws one plot per group of `groups` and the string events of `flows` in each.
pub fn show(ui: &mut Ui, groups: &[ResolvedGroup], flows: &[Flow], settings: &Settings) -> Outcome {
    let mut outcome = Outcome {
        reload: vec![None; flows.len()],
        ..Outcome::default()
    };
    let strings: Vec<NamedEvents> = flows
        .iter()
        .flat_map(|f| {
            f.state
                .series
                .iter()
                .filter(|s| s.is_string_type())
                .map(|s| {
                    let name = format!("{}{}", f.prefix, s.name);
                    (name, s.color, s.string_points.as_slice())
                })
        })
        .collect();
    let string_events: Vec<event_labels::Events> = strings
        .iter()
        .map(|(name, color, points)| (name.as_str(), *color, *points))
        .collect();

    // One group fills the area like a single plot; more groups share it and scroll when
    // they get too small
    let single = groups.len() == 1;
    let plot_count = groups.iter().filter(|g| !g.members.is_empty()).count();
    let plot_height = if single {
        plot_height_with_footer(ui.available_height())
    } else {
        let fixed = groups.len() as f32 * (HEADING_HEIGHT + PLOT_GAP)
            + (groups.len() - plot_count) as f32 * EMPTY_HEIGHT;
        split_plot_height_with_footer(ui.available_height() - fixed, plot_count)
    };

    // Linked plots must fit to the same x range, so it comes from all of them
    let drawn: Vec<Vec<Drawn>> = groups
        .iter()
        .map(|g| group_series(g, flows, settings.remove_outliers))
        .collect();
    let fit_x = shared_fit_x(drawn.iter().flatten(), settings);

    let mut draw_all = |ui: &mut Ui| {
        for (group, drawn) in groups.iter().zip(&drawn) {
            if !single {
                ui.label(RichText::new(&group.name).strong());
            }
            if group.members.is_empty() {
                empty_strip(ui);
            } else {
                let view = show_plot(
                    ui,
                    group.id,
                    drawn,
                    fit_x,
                    flows,
                    &string_events,
                    settings,
                    plot_height,
                    &mut outcome,
                );
                outcome.views.push((group.id, view));
            }
            ui.add_space(PLOT_GAP);
        }
    };
    if single {
        draw_all(ui);
    } else {
        ScrollArea::vertical()
            .id_salt(format!("{}_groups_scroll", settings.id))
            .show(ui, draw_all);
    }
    outcome
}

/// The plot area while every group is hidden.
pub fn all_hidden(ui: &mut Ui) {
    ui.centered_and_justified(|ui| {
        ui.label(
            RichText::new("All plot groups are hidden. Show one in the Groups tab.")
                .color(egui::Color32::GRAY),
        );
    });
}

fn empty_strip(ui: &mut Ui) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_size(egui::vec2(ui.available_width(), EMPTY_HEIGHT - 12.0));
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("Empty group: add metrics in the Groups tab").weak());
        });
    });
}

fn group_series<'a>(
    group: &ResolvedGroup,
    flows: &'a [Flow],
    remove_outliers: bool,
) -> Vec<Drawn<'a>> {
    group
        .members
        .iter()
        .filter_map(|key| {
            flows.iter().find_map(|f| {
                f.series(key).map(|s| Drawn {
                    series: s,
                    name: format!("{}{}", f.prefix, s.name),
                    points: to_plot_points(if remove_outliers && !s.step {
                        remove_leading_outliers(&s.points)
                    } else {
                        &s.points
                    }),
                })
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn show_plot(
    ui: &mut Ui,
    group_id: u64,
    drawn: &[Drawn],
    fit_x: (f64, f64),
    flows: &[Flow],
    string_events: &[event_labels::Events],
    settings: &Settings,
    height: f32,
    outcome: &mut Outcome,
) -> export::View {
    let lines: Vec<&Drawn> = drawn
        .iter()
        .filter(|d| !d.series.is_boolean_type())
        .collect();
    let fit_bounds = (fit_x, fit_y(&lines));
    let mut view = export::View::default();

    let response = Plot::new(format!("{}_group_{}", settings.id, group_id))
        .allow_boxed_zoom(true)
        .allow_drag(true)
        .allow_scroll(true)
        .link_axis(format!("{}_x_axis", settings.id), [true, false])
        .x_grid_spacer(seconds_grid_spacer(settings.x_origin))
        .x_axis_formatter(seconds_since_formatter(settings.x_origin))
        .y_axis_formatter(time_or_compact_formatter(settings.x_origin))
        .coordinates_formatter(
            Corner::LeftBottom,
            time_or_compact_coordinates_formatter(settings.x_origin),
        )
        .legend(Legend::default())
        .height(height)
        .show(ui, |plot_ui| {
            if settings.fit {
                let ((x_min, x_max), (y_min, y_max)) = fit_bounds;
                plot_ui.set_plot_bounds(PlotBounds::from_min_max([x_min, y_min], [x_max, y_max]));
                // No reload: selecting loaded the full range, and the new bounds only show
                // up in plot_bounds() next frame
            } else {
                if let Some((x_min, x_max)) = settings.set_x {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [x_min, f64::NEG_INFINITY],
                        [x_max, f64::INFINITY],
                    ));
                }
                let bounds = plot_ui.plot_bounds();
                let visible = (bounds.min()[0], bounds.max()[0]);
                for (flow, reload) in flows.iter().zip(outcome.reload.iter_mut()) {
                    if flow.state.needs_reload(visible.0, visible.1) {
                        *reload = Some(visible);
                    }
                }
            }

            let b = plot_ui.plot_bounds();
            view = export::View {
                x: Some((b.min()[0], b.max()[0])),
                y: Some((b.min()[1], b.max()[1])),
                remove_outliers: settings.remove_outliers,
            };

            if settings.show_gaps {
                for d in drawn {
                    gap_marks::draw_series(plot_ui, d.series);
                }
            }
            for d in &lines {
                plot_ui.line(
                    Line::new(PlotPoints::from(d.points.clone()))
                        .color(d.series.color)
                        .name(&d.name),
                );
            }
            for d in drawn.iter().filter(|d| d.series.is_boolean_type()) {
                for (t, value) in &d.series.points {
                    if *value >= 0.5 {
                        plot_ui.vline(VLine::new(*t).color(d.series.color).name(&d.name));
                    }
                }
            }
            event_labels::draw_lines(plot_ui, string_events);
        });
    event_labels::paint_labels(ui, &response.transform, string_events);
    if response.response.secondary_clicked() {
        outcome.right_clicked = true;
    }
    view
}

/// The x range to fit all plots to: that of their lines when leading outliers are removed,
/// else the data's, padded a little.
fn shared_fit_x<'a>(drawn: impl Iterator<Item = &'a Drawn<'a>>, settings: &Settings) -> (f64, f64) {
    let shown = settings
        .remove_outliers
        .then(|| {
            merge_bounds(
                drawn
                    .filter(|d| !d.series.is_boolean_type())
                    .filter_map(|d| points_bounds(&d.points)),
            )
        })
        .flatten();
    pad(shown.map_or(settings.data_x, |(x, _)| x), PADDING_X)
}

/// The y range to fit a plot to: that of its lines, or the catalog's value range when
/// nothing is loaded, padded a little.
fn fit_y(lines: &[&Drawn]) -> (f64, f64) {
    let shown = merge_bounds(lines.iter().filter_map(|d| points_bounds(&d.points)));
    let catalog = lines
        .iter()
        .map(|d| (d.series.global_y_min, d.series.global_y_max))
        .reduce(|(a_min, a_max), (b_min, b_max)| (a_min.min(b_min), a_max.max(b_max)))
        .unwrap_or((0.0, 1.0));
    pad(shown.map_or(catalog, |(_, y)| y), PADDING_Y)
}

fn merge_bounds(bounds: impl Iterator<Item = PlotDataBounds>) -> Option<PlotDataBounds> {
    bounds.reduce(|((ax0, ax1), (ay0, ay1)), ((bx0, bx1), (by0, by1))| {
        ((ax0.min(bx0), ax1.max(bx1)), (ay0.min(by0), ay1.max(by1)))
    })
}

fn points_bounds(pts: &[[f64; 2]]) -> Option<PlotDataBounds> {
    merge_bounds(pts.iter().map(|&[x, y]| ((x, x), (y, y))))
}

fn pad((min, max): (f64, f64), fraction: f64) -> (f64, f64) {
    if !min.is_finite() || !max.is_finite() {
        return (min, max);
    }
    let span = (max - min).abs();
    let pad = if span > 0.0 {
        span * fraction
    } else {
        fraction
    };
    (min - pad, max + pad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_merge_and_pad() {
        let pts = [[0.0, 5.0], [10.0, 1.0], [4.0, 9.0]];
        assert_eq!(points_bounds(&pts), Some(((0.0, 10.0), (1.0, 9.0))));
        assert_eq!(points_bounds(&[]), None);
        assert_eq!(pad((0.0, 10.0), 0.1), (-1.0, 11.0));
        assert_eq!(pad((3.0, 3.0), 0.5), (2.5, 3.5));
    }
}
