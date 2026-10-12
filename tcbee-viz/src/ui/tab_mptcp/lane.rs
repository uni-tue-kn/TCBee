//! The event lane above the metric plots: a row for the connection and one per subflow, a
//! marker per path manager event, and its legend.

use std::sync::Arc;

use egui::{RichText, Vec2};
use egui_plot::{
    AxisHints, GridMark, MarkerShape, Plot, PlotBounds, PlotPoint, PlotPoints, PlotTransform,
    Points, Polygon,
};

use super::model::{
    centered_x, event_kind, event_type, event_type_name, group_at, group_events, lane_row_at,
    lane_row_name, lane_y, place_labels, EventGroup, EventKind,
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
    /// Its groups of close events, and the time within which events group
    pub groups: Arc<[EventGroup]>,
    pub tol: f64,
}

impl TabMptcp {
    /// The path manager events above the metric plots: a row for the connection and one per
    /// subflow, a marker per event, the full text on hover.
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
                let (t0, t1) = (connection.start_ts as f64, connection.end_ts as f64);
                for (index, sub) in self.subflows.iter().enumerate() {
                    let y = lane_y(index + 1, rows);
                    plot_ui.polygon(
                        Polygon::new(PlotPoints::from(vec![
                            [t0, y - 0.5],
                            [t1, y - 0.5],
                            [t1, y + 0.5],
                            [t0, y + 0.5],
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

    /// The short label right of each marker, where it does not overlap the one before it.
    /// Data moves (reinjections) get none; there can be many.
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
            let labelled: Vec<&EventGroup> = groups
                .iter()
                .filter(|g| g.row == row)
                .filter(|g| self.events[g.representative].kind() != EventKind::Data)
                .collect();
            let placed: Vec<(egui::Pos2, std::sync::Arc<egui::Galley>)> = labelled
                .iter()
                .map(|g| {
                    let e = &self.events[g.representative];
                    let marker =
                        transform.position_from_point(&PlotPoint::new(e.t, lane_y(row, rows)));
                    let galley = painter.layout_no_wrap(
                        g.label(&self.events),
                        egui::FontId::proportional(LABEL_SIZE),
                        color,
                    );
                    let left = marker.x + MARKER_RADIUS + LABEL_GAP;
                    (egui::pos2(left, marker.y - galley.size().y / 2.0), galley)
                })
                .collect();
            let spans: Vec<(f32, f32)> = placed
                .iter()
                .map(|(pos, galley)| (pos.x, pos.x + galley.size().x))
                .collect();
            for ((pos, galley), shown) in placed.into_iter().zip(place_labels(&spans, LABEL_GAP)) {
                if shown {
                    painter.galley(pos, galley, color);
                }
            }
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
        let mut labelled: Vec<(f32, std::sync::Arc<egui::Galley>, egui::Color32)> = groups
            .iter()
            .filter(|g| !self.is_hidden_row(g.row))
            .map(|g| (g, &self.events[g.representative]))
            .filter(|(_, e)| e.kind() != EventKind::Data)
            .map(|(g, e)| {
                let text = match g.row {
                    0 => g.label(&self.events),
                    row => format!("#{row} {}", g.label(&self.events)),
                };
                let x = transform.position_from_point_x(e.t);
                let color = kind_color(e.kind(), dark_mode);
                let galley =
                    painter.layout_no_wrap(text, egui::FontId::proportional(LABEL_SIZE), color);
                (x + LABEL_GAP, galley, color)
            })
            .collect();
        labelled.sort_by(|a, b| a.0.total_cmp(&b.0));
        let spans: Vec<(f32, f32)> = labelled
            .iter()
            .map(|(x, galley, _)| (*x, x + galley.size().x))
            .collect();
        for ((x, galley, color), shown) in labelled.into_iter().zip(place_labels(&spans, LABEL_GAP))
        {
            if shown {
                painter.galley(egui::pos2(x, frame.top() + 2.0), galley, color);
            }
        }
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
                    5.0,
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

/// Colour of the events of one type, failed or not
fn key_color(code: i64, failed: bool, dark_mode: bool) -> egui::Color32 {
    kind_color(event_kind(code, failed), dark_mode)
}

/// Colour of an event kind: green up, neutral end, red trouble, grey lifecycle, violet
/// information, orange data
pub(super) fn kind_color(kind: EventKind, dark_mode: bool) -> egui::Color32 {
    match kind {
        EventKind::Up => theme::SUCCESS,
        EventKind::End => theme::text(dark_mode),
        EventKind::Trouble => theme::ERROR,
        EventKind::Lifecycle => theme::muted_text(dark_mode),
        EventKind::Info => theme::info(dark_mode),
        EventKind::Data => theme::warning(dark_mode),
    }
}

/// Paints an egui_plot marker shape for the legend
pub(super) fn paint_marker(
    painter: &egui::Painter,
    c: egui::Pos2,
    shape: MarkerShape,
    color: egui::Color32,
    r: f32,
) {
    use egui::{pos2, Shape, Stroke};
    let stroke = Stroke::new(1.5, color);
    let triangle =
        |points: [egui::Pos2; 3]| Shape::convex_polygon(points.to_vec(), color, Stroke::NONE);
    let shape = match shape {
        MarkerShape::Circle => Shape::circle_filled(c, r, color),
        MarkerShape::Square => Shape::rect_filled(
            egui::Rect::from_center_size(c, Vec2::splat(2.0 * r)),
            0.0,
            color,
        ),
        MarkerShape::Diamond => Shape::convex_polygon(
            vec![
                pos2(c.x, c.y - r),
                pos2(c.x + r, c.y),
                pos2(c.x, c.y + r),
                pos2(c.x - r, c.y),
            ],
            color,
            Stroke::NONE,
        ),
        MarkerShape::Up => triangle([
            pos2(c.x, c.y - r),
            pos2(c.x + r, c.y + r),
            pos2(c.x - r, c.y + r),
        ]),
        MarkerShape::Down => triangle([
            pos2(c.x - r, c.y - r),
            pos2(c.x + r, c.y - r),
            pos2(c.x, c.y + r),
        ]),
        MarkerShape::Left => triangle([
            pos2(c.x - r, c.y),
            pos2(c.x + r, c.y - r),
            pos2(c.x + r, c.y + r),
        ]),
        MarkerShape::Right => triangle([
            pos2(c.x - r, c.y - r),
            pos2(c.x + r, c.y),
            pos2(c.x - r, c.y + r),
        ]),
        MarkerShape::Plus => Shape::Vec(vec![
            Shape::line_segment([pos2(c.x - r, c.y), pos2(c.x + r, c.y)], stroke),
            Shape::line_segment([pos2(c.x, c.y - r), pos2(c.x, c.y + r)], stroke),
        ]),
        MarkerShape::Cross => Shape::Vec(vec![
            Shape::line_segment([pos2(c.x - r, c.y - r), pos2(c.x + r, c.y + r)], stroke),
            Shape::line_segment([pos2(c.x - r, c.y + r), pos2(c.x + r, c.y - r)], stroke),
        ]),
        MarkerShape::Asterisk => Shape::Vec(vec![
            Shape::line_segment([pos2(c.x - r, c.y), pos2(c.x + r, c.y)], stroke),
            Shape::line_segment([pos2(c.x - r, c.y - r), pos2(c.x + r, c.y + r)], stroke),
            Shape::line_segment([pos2(c.x - r, c.y + r), pos2(c.x + r, c.y - r)], stroke),
        ]),
    };
    painter.add(shape);
}
