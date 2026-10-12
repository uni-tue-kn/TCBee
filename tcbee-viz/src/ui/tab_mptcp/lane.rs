//! The event lane above the metric plots: a row for the connection and one per subflow, a
//! marker per path manager event, and its legend.

use std::sync::Arc;

use egui::{RichText, Vec2};
use egui_plot::{AxisHints, GridMark, MarkerShape, Plot, PlotBounds, PlotPoints, Points, Polygon};

use super::model::{
    event_type, event_type_name, lane_row_name, lane_y, nearest_event, EventKind, PmEvent,
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
}

impl TabMptcp {
    /// The path manager events above the metric plots: a row for the connection and one per
    /// subflow, a marker per event, the full text on hover.
    pub(super) fn show_event_lane(
        &self,
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
        let events = Arc::clone(&self.events);
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
            .label_formatter(move |name, point| {
                let time = format!("{:.3} s", (point.x - origin) / 1e9);
                match nearest_event(&events, name, point.x, point.y, rows) {
                    Some(e) => format!("{}\n{:.3} s", e.label, (e.t - origin) / 1e9),
                    None => time,
                }
            })
            .height(lane_height)
            .show(ui, |plot_ui| {
                if fit {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max(
                        [connection.start_ts as f64, -0.6],
                        [connection.end_ts as f64, rows as f64 - 0.4],
                    ));
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
                for &(code, failed) in &self.event_keys {
                    let points: Vec<[f64; 2]> = self
                        .events
                        .iter()
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
        self.show_event_legend(ui, dark_mode);
        ui.add_space(4.0);
        let bounds = response.transform.bounds();
        LaneResponse {
            height: ui.cursor().top() - top,
            time_range: (bounds.min()[0], bounds.max()[0]),
            // Like on the metric plots
            reset: response.response.secondary_clicked() || response.response.double_clicked(),
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
    let probe = PmEvent {
        t: 0.0,
        code,
        row: 0,
        label: String::new(),
        backup: false,
        failed,
    };
    kind_color(probe.kind(), dark_mode)
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
fn paint_marker(
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
