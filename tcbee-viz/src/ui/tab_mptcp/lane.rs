//! The event lane above the metric plots: a row for the connection and one per subflow, a
//! marker per path manager event, and its legend.

use std::sync::Arc;

use egui::{RichText, Vec2};
use egui_plot::{GridMark, MarkerShape, Plot, PlotBounds, PlotPoints, Points};
use tcbee_common::records::{
    TCBEE_MPTCP_ANNOUNCED, TCBEE_MPTCP_CLOSED, TCBEE_MPTCP_CREATED, TCBEE_MPTCP_ESTABLISHED,
    TCBEE_MPTCP_FALLBACK, TCBEE_MPTCP_LISTENER_CLOSED, TCBEE_MPTCP_LISTENER_CREATED,
    TCBEE_MPTCP_MP_FAIL, TCBEE_MPTCP_MP_PRIO_SENT, TCBEE_MPTCP_PENDING_REQUEUED,
    TCBEE_MPTCP_REINJECTED, TCBEE_MPTCP_REMOVED, TCBEE_MPTCP_SUBFLOW_CONNECT,
    TCBEE_MPTCP_SUBFLOW_STALE, TCBEE_MPTCP_SUB_CLOSED, TCBEE_MPTCP_SUB_ESTABLISHED,
    TCBEE_MPTCP_SUB_PRIORITY, TCBEE_MPTCP_TOKEN_DESTROYED,
};

use super::model::{is_structural, lane_row_name, lane_y, nearest_event, pm_event_name};
use super::{TabMptcp, Y_AXIS_WIDTH};
use crate::{
    settings::AppSettings,
    ui::{
        tab_single_flow::{seconds_grid_spacer, section_heading},
        theme,
    },
};

/// Height of a row of the event lane
const LANE_ROW_HEIGHT: f32 = 18.0;
const MIN_LANE_HEIGHT: f32 = 60.0;

/// What the event lane reports to the plots below it
#[derive(Default)]
pub(super) struct LaneResponse {
    /// Height it took, with its title and legend
    pub height: f32,
    /// Right-clicked to reset the view
    pub reset: bool,
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
        let lane_height = ((rows + 1) as f32 * LANE_ROW_HEIGHT).max(MIN_LANE_HEIGHT);
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
            .y_axis_formatter(move |mark, _| lane_row_name(mark.value, rows))
            .y_axis_min_width(Y_AXIS_WIDTH)
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
                for &code in &self.event_codes {
                    let points: Vec<[f64; 2]> = self
                        .events
                        .iter()
                        .filter(|e| e.code == code)
                        .map(|e| [e.t, lane_y(e.row, rows)])
                        .collect();
                    plot_ui.points(
                        Points::new(PlotPoints::from(points))
                            .shape(event_shape(code))
                            .color(event_color(code, dark_mode))
                            .filled(true)
                            .radius(4.0)
                            .name(pm_event_name(code)),
                    );
                }
            });
        self.show_event_legend(ui, dark_mode);
        ui.add_space(4.0);
        LaneResponse {
            height: ui.cursor().top() - top,
            // Like on the metric plots
            reset: response.response.secondary_clicked() || response.response.double_clicked(),
        }
    }

    /// Marker and name of each event type of the connection
    fn show_event_legend(&self, ui: &mut egui::Ui, dark_mode: bool) {
        ui.horizontal_wrapped(|ui| {
            for &code in &self.event_codes {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), egui::Sense::hover());
                paint_marker(
                    ui.painter(),
                    rect.center(),
                    event_shape(code),
                    event_color(code, dark_mode),
                    4.0,
                );
                ui.label(
                    RichText::new(pm_event_name(code))
                        .size(11.5)
                        .color(theme::muted_text(dark_mode)),
                );
                ui.add_space(8.0);
            }
        });
    }
}

/// Marker of an event type. Types share a shape only between the connection row and the
/// subflow rows, where the row tells them apart.
fn event_shape(code: i64) -> MarkerShape {
    match u32::try_from(code).unwrap_or(0) {
        TCBEE_MPTCP_CREATED | TCBEE_MPTCP_REINJECTED => MarkerShape::Circle,
        TCBEE_MPTCP_ESTABLISHED | TCBEE_MPTCP_SUBFLOW_STALE => MarkerShape::Square,
        TCBEE_MPTCP_CLOSED | TCBEE_MPTCP_LISTENER_CLOSED => MarkerShape::Cross,
        TCBEE_MPTCP_ANNOUNCED | TCBEE_MPTCP_SUB_ESTABLISHED => MarkerShape::Up,
        TCBEE_MPTCP_REMOVED | TCBEE_MPTCP_SUB_CLOSED => MarkerShape::Down,
        TCBEE_MPTCP_TOKEN_DESTROYED | TCBEE_MPTCP_MP_PRIO_SENT => MarkerShape::Plus,
        TCBEE_MPTCP_FALLBACK | TCBEE_MPTCP_MP_FAIL => MarkerShape::Asterisk,
        TCBEE_MPTCP_LISTENER_CREATED | TCBEE_MPTCP_SUB_PRIORITY => MarkerShape::Diamond,
        TCBEE_MPTCP_SUBFLOW_CONNECT => MarkerShape::Right,
        TCBEE_MPTCP_PENDING_REQUEUED => MarkerShape::Left,
        _ => MarkerShape::Circle,
    }
}

/// Events in the text colour, data movements muted, so that subflow colours stay for the
/// subflows
fn event_color(code: i64, dark_mode: bool) -> egui::Color32 {
    if is_structural(code) {
        theme::text(dark_mode)
    } else {
        theme::muted_text(dark_mode)
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
