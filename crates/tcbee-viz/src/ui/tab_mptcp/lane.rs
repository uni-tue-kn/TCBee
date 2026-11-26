//! The event lane above the metric plots: a row for the connection and one per subflow, a
//! marker per group of close path manager events with a short label, a tooltip with the
//! group's events, and a legend. Also the event labels along the top of the first plot.

use std::sync::Arc;

use egui::{RichText, Vec2};
use egui_plot::{
    AxisHints, GridMark, LineStyle, MarkerShape, Plot, PlotBounds, PlotPoint, PlotPoints,
    PlotTransform, Points, Polygon,
};

use super::markers::{key_color, kind_color, paint_marker, SMALL_MARKER_RADIUS};
use super::model::{
    centered_x, event_type, event_type_name, group_at, group_events, lane_row_at, lane_row_name,
    lane_y, place_labels, row_name, EventGroup, LabelSpan,
};
use super::{
    TabMptcp, EVENT_LINE_STYLE, EVENT_LINE_WIDTH, PLOTS_ID, SELECTED_EVENT_STYLE,
    SELECTED_EVENT_WIDTH,
};
use crate::data::{
    segments::{HELD_ALPHA, POINT_RADIUS_PER_WIDTH},
    series_data::DEFAULT_LINE_WIDTH,
};
use crate::ui::plot_frame::{plot_title, TITLE_INSET, Y_AXIS_WIDTH};
use crate::{
    settings::AppSettings,
    ui::{
        grouped_plots,
        tab_single_flow::{seconds_grid_spacer, section_heading_text},
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
/// Relative change of the lane's time scale from which its events are grouped again
const REGROUP_SCALE_CHANGE: f64 = 0.01;
// Legend entries: the marker's box, the name's size and the space to the next entry
const LEGEND_SWATCH: f32 = 14.0;
const LEGEND_TEXT_SIZE: f32 = 11.5;
const LEGEND_ENTRY_GAP: f32 = 12.0;
/// Radius of an event marker
const MARKER_RADIUS: f32 = 6.0;

/// What the event lane reports to the plots below it
#[derive(Default)]
pub(super) struct LaneResponse {
    /// Right-clicked to reset the view
    pub reset: bool,
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
        let rows = self.subflows.len() + 1;
        let pitch = MIN_ROW_PITCH.max(ui.text_style_height(&egui::TextStyle::Body) + 6.0);
        // The rows, half a row of margin and the (empty) time axis
        let lane_height = (rows.min(MAX_LANE_ROWS) as f32 + 0.5) * pitch + 12.0;
        let dark_mode = settings.dark_mode;
        plot_title(ui, section_heading_text(ui, "Path manager events"));
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
            .link_axis(grouped_plots::x_axis_link(PLOTS_ID), [true, false])
            .link_cursor(grouped_plots::x_axis_link(PLOTS_ID), [true, false])
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
                    // The same time range as the plots fit to, which share the axis
                    let (x_min, x_max) = grouped_plots::fit_x((start, end));
                    plot_ui
                        .set_plot_bounds(PlotBounds::from_min_max([x_min, y_min], [x_max, y_max]));
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
        if (ns_per_px - self.lane_ns_per_px).abs() > REGROUP_SCALE_CHANGE * ns_per_px {
            // Group again at the new scale without waiting for input
            ui.ctx().request_repaint();
        }
        self.lane_ns_per_px = ns_per_px;
        self.show_hovered_group(ui, &response, &groups, rows, tol, origin);
        self.paint_lane_labels(ui, &response.transform, &groups, rows, dark_mode);
        self.show_event_legend(ui, dark_mode);
        show_line_legend(ui, dark_mode);
        ui.add_space(4.0);
        LaneResponse {
            groups,
            tol,
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
                if self.events[g.representative].moves_data() {
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
        ui.horizontal(|ui| {
            ui.add_space(TITLE_INSET);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = LEGEND_ENTRY_GAP;
                for &(code, failed) in &self.event_keys {
                    // One unit, so a line never breaks between marker and name
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        let (rect, _) = ui
                            .allocate_exact_size(Vec2::splat(LEGEND_SWATCH), egui::Sense::hover());
                        paint_marker(
                            ui.painter(),
                            rect.center(),
                            event_type(code).shape,
                            key_color(code, failed, dark_mode),
                            SMALL_MARKER_RADIUS,
                        );
                        ui.label(
                            RichText::new(event_type_name(code, failed))
                                .size(LEGEND_TEXT_SIZE)
                                .color(theme::muted_text(dark_mode)),
                        );
                    });
                }
            });
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
    let spans: Vec<LabelSpan> = labels
        .iter()
        .map(|l| LabelSpan {
            left: l.pos.x,
            right: l.pos.x + l.galley.size().x,
            limit: l.limit,
        })
        .collect();
    for (label, shown) in labels.into_iter().zip(place_labels(&spans, LABEL_GAP)) {
        if shown {
            painter.galley(label.pos, label.galley, label.color);
        }
    }
}

/// What a line in the metric plots looks like, for the legend below the events
#[derive(Clone, Copy, Debug, PartialEq)]
enum LineSample {
    /// A series between its records
    Records,
    /// A value held over a pause without records, see `segments`
    Held,
    /// A record with no neighbour close enough to join
    Lone,
    /// A path manager event
    Event,
    /// The event picked in the event list
    SelectedEvent,
}

const LINE_LEGEND: [(LineSample, &str); 5] = [
    (LineSample::Records, "records"),
    (LineSample::Held, "no records, last value held"),
    (LineSample::Lone, "single record"),
    (LineSample::Event, "path manager event"),
    (LineSample::SelectedEvent, "event picked in the list"),
];

/// Explains the lines and points of the metric plots, below the event legend
fn show_line_legend(ui: &mut egui::Ui, dark_mode: bool) {
    let color = theme::muted_text(dark_mode);
    ui.horizontal(|ui| {
        ui.add_space(TITLE_INSET);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = LEGEND_ENTRY_GAP;
            for (sample, name) in LINE_LEGEND {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    let size = Vec2::new(2.0 * LEGEND_SWATCH, LEGEND_SWATCH);
                    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
                    paint_line_sample(ui.painter(), rect, sample, color);
                    ui.label(RichText::new(name).size(LEGEND_TEXT_SIZE).color(color));
                });
            }
        });
    });
}

/// Paints `sample` into `rect` as the plots draw it: series lines across, event lines upright
fn paint_line_sample(
    painter: &egui::Painter,
    rect: egui::Rect,
    sample: LineSample,
    color: egui::Color32,
) {
    let across = [rect.left_center(), rect.right_center()];
    let upright = [rect.center_top(), rect.center_bottom()];
    let line = |style: LineStyle, width: f32, color: egui::Color32, path: [egui::Pos2; 2]| {
        let stroke = egui::Stroke::new(width, color);
        match style {
            LineStyle::Solid => vec![egui::Shape::line_segment(path, stroke)],
            LineStyle::Dashed { length } => {
                egui::Shape::dashed_line(&path, stroke, length, length / 2.0)
            }
            LineStyle::Dotted { spacing } => {
                egui::Shape::dotted_line(&path, color, spacing, width / 2.0)
            }
        }
    };
    let shapes = match sample {
        LineSample::Records => line(LineStyle::Solid, DEFAULT_LINE_WIDTH, color, across),
        LineSample::Held => line(
            LineStyle::dashed_dense(),
            DEFAULT_LINE_WIDTH,
            color.gamma_multiply(HELD_ALPHA),
            across,
        ),
        LineSample::Lone => vec![egui::Shape::circle_filled(
            rect.center(),
            DEFAULT_LINE_WIDTH * POINT_RADIUS_PER_WIDTH,
            color,
        )],
        LineSample::Event => line(EVENT_LINE_STYLE, EVENT_LINE_WIDTH, color, upright),
        LineSample::SelectedEvent => {
            line(SELECTED_EVENT_STYLE, SELECTED_EVENT_WIDTH, color, upright)
        }
    };
    painter.extend(shapes);
}
