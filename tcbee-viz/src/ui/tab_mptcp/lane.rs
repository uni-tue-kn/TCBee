//! The event lane above the metric plots: a row for the connection and one per subflow, a
//! marker per group of close path manager events with a short label, a tooltip with the
//! group's events, and a legend. Also the event labels along the top of the first plot.

use std::sync::Arc;

use egui::{RichText, Vec2};
use egui_plot::{
    AxisHints, GridMark, MarkerShape, Plot, PlotBounds, PlotPoint, PlotPoints, PlotTransform,
    Points, Polygon,
};

use super::markers::{key_color, kind_color, paint_marker, SMALL_MARKER_RADIUS};
use super::model::{
    centered_x, event_type, event_type_name, group_at, group_events, lane_row_at, lane_row_name,
    lane_y, place_labels, row_name, EventGroup, EventKind,
};
use super::{TabMptcp, Y_AXIS_WIDTH};
use crate::{
    settings::AppSettings,
    ui::{
        tab_single_flow::{seconds_grid_spacer, section_heading},
        theme,
    },
};

/// Smallest height of a row of the event lane; it grows with the text size, so that the row
/// names fit (egui_plot leaves out axis labels that are closer than the text is high)
const MIN_ROW_PITCH: f32 = 26.0;
/// Rows the lane makes room for; more rows get narrower
const MAX_LANE_ROWS: usize = 8;
/// Opacity of a subflow's colour behind its row
const ROW_TINT: f32 = 0.12;
/// Events of a row closer than this on screen share one marker
const GROUP_PX: f64 = 10.0;
/// Space between a marker and its label, and between labels
const LABEL_GAP: f32 = 4.0;
const LABEL_SIZE: f32 = 11.0;
/// Radius of an event marker
const MARKER_RADIUS: f32 = 6.0;

/// What the event lane reports to the plots below it
#[derive(Default)]
pub(super) struct LaneResponse {
    /// Height it took, with its title and legend
    pub height: f32,
    /// Right-clicked to reset the view
    pub reset: bool,
    /// The time range it shows, which all plots share
    pub time_range: (f64, f64),
    /// Its groups of close events
    pub groups: Arc<[EventGroup]>,
    /// Time (ns) within which events group, a few pixels at the current zoom
    pub tol: f64,
}

impl TabMptcp {
    /// The path manager events above the metric plots: a row for the connection and one per
    /// subflow, a marker per group of close events, its events in a tooltip on hover.
    pub(super) fn show_event_lane(
        &mut self,
        ui: &mut egui::Ui,
        settings: &AppSettings,
        fit: bool,
        origin: f64,
    ) -> LaneResponse {
        let Some(connection) = &self.connection else {
            return LaneResponse::default();
        };
        let top = ui.cursor().top();
        let rows = self.subflows.len() + 1;
        let pitch = MIN_ROW_PITCH.max(ui.text_style_height(&egui::TextStyle::Body) + 6.0);
        // The rows, half a row of margin and the (empty) time axis
        let lane_height = (rows.min(MAX_LANE_ROWS) as f32 + 0.5) * pitch + 12.0;
        let dark_mode = settings.dark_mode;
        section_heading(ui, "Path manager events");
        // Groups use the scale of the last frame; the first frame groups nothing
        let tol = GROUP_PX * self.lane_ns_per_px;
        // An event picked in the list, shown once
        let focus = self.focus.take();
        let groups: Arc<[EventGroup]> = group_events(&self.events, tol).into();
        let response = Plot::new("mptcp_event_lane")
            // Only time moves; the rows stay in view
            .allow_drag([true, false])
            .allow_zoom([true, false])
            .allow_scroll([true, false])
            .allow_boxed_zoom(false)
            .allow_double_click_reset(false)
            .link_axis("mptcp_time", [true, false])
            .link_cursor("mptcp_time", [true, false])
            // Hover needs one of the two; the label shows the event, not the coordinates
            .show_x(true)
            .show_y(false)
            .x_grid_spacer(seconds_grid_spacer(origin))
            .x_axis_formatter(|_, _| String::new())
            .y_grid_spacer(move |_| {
                (0..rows)
                    .map(|i| GridMark {
                        value: i as f64,
                        step_size: 1.0,
                    })
                    .collect()
            })
            .custom_y_axes(vec![AxisHints::new_y()
                .formatter(move |mark, _| lane_row_name(mark.value, rows))
                .label_spacing(10.0..=12.0)
                // Same width as the metric plots, so the time axes line up
                .min_thickness(Y_AXIS_WIDTH)])
            // The tints mark the rows
            .show_grid([true, false])
            // The events under the pointer go into a tooltip below, which the lane does not
            // clip like its own hover text
            .label_formatter(move |_, point| format!("{:.3} s", (point.x - origin) / 1e9))
            .height(lane_height)
            .show(ui, |plot_ui| {
                let (start, end) = (connection.start_ts as f64, connection.end_ts as f64);
                let (y_min, y_max) = (-0.6, rows as f64 - 0.4);
                if fit {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max([start, y_min], [end, y_max]));
                }
                // An event picked in the list: the plots below follow through the linked axis
                if let Some(t) = focus {
                    let shown = plot_ui.plot_bounds();
                    let (x0, x1) = centered_x(shown.min()[0], shown.max()[0], t, start, end);
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max([x0, y_min], [x1, y_max]));
                }
                // Each subflow's row in its colour; they span the connection, which the fit
                // shows anyway
                for (index, sub) in self.subflows.iter().enumerate() {
                    let y = lane_y(index + 1, rows);
                    plot_ui.polygon(
                        Polygon::new(PlotPoints::from(vec![
                            [start, y - 0.5],
                            [end, y - 0.5],
                            [end, y + 0.5],
                            [start, y + 0.5],
                        ]))
                        .fill_color(sub.color.gamma_multiply(ROW_TINT))
                        .stroke(egui::Stroke::NONE)
                        .allow_hover(false),
                    );
                }
                if let Some(e) = self.selected_event.and_then(|i| self.events.get(i)) {
                    plot_ui.points(
                        Points::new(PlotPoints::from(vec![[e.t, lane_y(e.row, rows)]]))
                            .shape(MarkerShape::Circle)
                            .filled(false)
                            .radius(MARKER_RADIUS + 4.0)
                            .color(theme::text(dark_mode))
                            // Hovering shows the event under it
                            .allow_hover(false),
                    );
                }
                // One marker per group, of its most severe event
                for &(code, failed) in &self.event_keys {
                    let points: Vec<[f64; 2]> = groups
                        .iter()
                        .map(|g| &self.events[g.representative])
                        .filter(|e| e.code == code && e.failed == failed)
                        .map(|e| [e.t, lane_y(e.row, rows)])
                        .collect();
                    plot_ui.points(
                        Points::new(PlotPoints::from(points))
                            .shape(event_type(code).shape)
                            .color(key_color(code, failed, dark_mode))
                            .filled(true)
                            .radius(MARKER_RADIUS)
                            .name(event_type_name(code, failed)),
                    );
                }
            });
        let frame = *response.transform.frame();
        let bounds = response.transform.bounds();
        let ns_per_px = (bounds.max()[0] - bounds.min()[0]) / f64::from(frame.width().max(1.0));
        if (ns_per_px - self.lane_ns_per_px).abs() > 0.01 * ns_per_px {
            // Group again at the new scale without waiting for input
            ui.ctx().request_repaint();
        }
        self.lane_ns_per_px = ns_per_px;
        self.show_hovered_group(ui, &response, &groups, rows, tol, origin);
        self.paint_lane_labels(ui, &response.transform, &groups, rows, dark_mode);
        self.show_event_legend(ui, dark_mode);
        ui.add_space(4.0);
        LaneResponse {
            groups,
            tol,
            height: ui.cursor().top() - top,
            time_range: (bounds.min()[0], bounds.max()[0]),
            // Like on the metric plots
            reset: response.response.secondary_clicked() || response.response.double_clicked(),
        }
    }

    /// A tooltip with every event of the group under the pointer
    fn show_hovered_group(
        &self,
        ui: &egui::Ui,
        response: &egui_plot::PlotResponse<()>,
        groups: &[EventGroup],
        rows: usize,
        tol: f64,
        origin: f64,
    ) {
        let Some(pointer) = response.response.hover_pos() else {
            return;
        };
        let at = response.transform.value_from_position(pointer);
        let Some(g) =
            lane_row_at(at.y, rows).and_then(|row| group_at(groups, &self.events, row, at.x, tol))
        else {
            return;
        };
        egui::show_tooltip_at_pointer(
            ui.ctx(),
            ui.layer_id(),
            response.response.id.with("group"),
            |ui| {
                for &i in &groups[g].members {
                    let e = &self.events[i];
                    ui.label(format!("{:.3} s  {}", (e.t - origin) / 1e9, e.label));
                }
            },
        );
    }

    /// The short label right of each marker, where it neither overlaps the label before it
    /// nor covers the next marker. Data moves (reinjections) get none; there can be many.
    fn paint_lane_labels(
        &self,
        ui: &egui::Ui,
        transform: &PlotTransform,
        groups: &[EventGroup],
        rows: usize,
        dark_mode: bool,
    ) {
        let painter = ui.painter_at(*transform.frame());
        let color = theme::text(dark_mode);
        for row in 0..rows {
            // Groups of a row follow each other in time
            let markers: Vec<(&EventGroup, egui::Pos2)> = groups
                .iter()
                .filter(|g| g.row == row)
                .map(|g| {
                    let t = self.events[g.representative].t;
                    (
                        g,
                        transform.position_from_point(&PlotPoint::new(t, lane_y(row, rows))),
                    )
                })
                .collect();
            let labels = markers.iter().enumerate().filter_map(|(k, &(g, marker))| {
                if self.events[g.representative].kind() == EventKind::Data {
                    return None;
                }
                let galley = painter.layout_no_wrap(
                    g.label(&self.events),
                    egui::FontId::proportional(LABEL_SIZE),
                    color,
                );
                let next_marker = markers
                    .get(k + 1)
                    .map_or(f32::INFINITY, |(_, next)| next.x - MARKER_RADIUS);
                Some(PlacedLabel {
                    pos: egui::pos2(
                        marker.x + MARKER_RADIUS + LABEL_GAP,
                        marker.y - galley.size().y / 2.0,
                    ),
                    galley,
                    color,
                    limit: next_marker,
                })
            });
            paint_placed(&painter, labels.collect());
        }
    }

    /// Labels along the top of a metric plot for the lines of its events: the subflow's row
    /// and the short name, e.g. "#2 stale", where they do not overlap
    pub(super) fn paint_plot_labels(
        &self,
        ui: &egui::Ui,
        transform: &PlotTransform,
        groups: &[EventGroup],
        dark_mode: bool,
    ) {
        let frame = *transform.frame();
        let painter = ui.painter_at(frame);
        let labels = groups
            .iter()
            .map(|g| (g, &self.events[g.representative]))
            .filter(|(_, e)| self.marks_plots(e))
            .map(|(g, e)| {
                let text = match g.row {
                    0 => g.label(&self.events),
                    row => format!("{} {}", row_name(row), g.label(&self.events)),
                };
                let color = kind_color(e.kind(), dark_mode);
                PlacedLabel {
                    pos: egui::pos2(
                        transform.position_from_point_x(e.t) + LABEL_GAP,
                        frame.top() + 2.0,
                    ),
                    galley: painter.layout_no_wrap(
                        text,
                        egui::FontId::proportional(LABEL_SIZE),
                        color,
                    ),
                    color,
                    limit: f32::INFINITY,
                }
            })
            .collect();
        paint_placed(&painter, labels);
    }

    /// Marker and name of each event type of the connection
    fn show_event_legend(&self, ui: &mut egui::Ui, dark_mode: bool) {
        ui.horizontal_wrapped(|ui| {
            for &(code, failed) in &self.event_keys {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(14.0), egui::Sense::hover());
                paint_marker(
                    ui.painter(),
                    rect.center(),
                    event_type(code).shape,
                    key_color(code, failed, dark_mode),
                    SMALL_MARKER_RADIUS,
                );
                ui.label(
                    RichText::new(event_type_name(code, failed))
                        .size(11.5)
                        .color(theme::muted_text(dark_mode)),
                );
                ui.add_space(8.0);
            }
        });
    }
}

/// A label that is drawn only if there is room for it
struct PlacedLabel {
    pos: egui::Pos2,
    galley: Arc<egui::Galley>,
    color: egui::Color32,
    /// Its right end must stay left of this
    limit: f32,
}

/// Draws the labels that fit, from left to right
fn paint_placed(painter: &egui::Painter, mut labels: Vec<PlacedLabel>) {
    labels.sort_by(|a, b| a.pos.x.total_cmp(&b.pos.x));
    let spans: Vec<(f32, f32, f32)> = labels
        .iter()
        .map(|l| (l.pos.x, l.pos.x + l.galley.size().x, l.limit))
        .collect();
    for (label, shown) in labels.into_iter().zip(place_labels(&spans, LABEL_GAP)) {
        if shown {
            painter.galley(label.pos, label.galley, label.color);
        }
    }
}
