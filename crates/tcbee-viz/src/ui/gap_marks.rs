//! Shaded spans where hook_seq shows missing events (see `ts_storage::gaps`).

use egui::{Align2, Color32, Stroke};
use egui_plot::{PlotPoint, PlotPoints, PlotUi, Polygon, Text};
use ts_storage::{Gap, Gaps};

use crate::data::series_data::SeriesData;

/// Legend entry of the spans; all spans share it.
const LEGEND: &str = "missing events";

pub const TOOLTIP: &str = "Shades where events of a series are missing: its hook_seq numbers jump. Hover a span for the count. Series recorded without hook_seq and derived series have no gap information (n/a).";

/// A span to draw: `(start, end, missing events)`.
type Span = (f64, f64, i64);

/// The gaps that overlap `[x_min, x_max]`, merged when they are at most `px` apart, so a dense
/// loss region draws one span instead of thousands.
fn spans(gaps: &[Gap], x_min: f64, x_max: f64, px: f64) -> Vec<Span> {
    let mut visible: Vec<Span> = gaps
        .iter()
        .map(|g| (g.start_ns as f64, g.end_ns as f64, g.missing))
        .filter(|(start, end, _)| *end >= x_min && *start <= x_max)
        .collect();
    visible.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut out: Vec<Span> = Vec::new();
    for (start, end, missing) in visible {
        match out.last_mut() {
            Some(last) if start - last.1 <= px => {
                last.1 = last.1.max(end);
                last.2 += missing;
            }
            _ => out.push((start, end, missing)),
        }
    }
    out
}

/// Draws the gaps of a series as spans over the full plot height, at least one pixel wide,
/// and the missing count of the span under the pointer.
pub fn draw(plot_ui: &mut PlotUi, gaps: &[Gap], color: Color32) {
    let bounds = plot_ui.plot_bounds();
    let ([x_min, y_min], [x_max, y_max]) = (bounds.min(), bounds.max());
    let px = plot_ui.transform().dvalue_dpos()[0].abs();
    let pointer = plot_ui.pointer_coordinate();
    let fill = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 60);
    for (start, end, missing) in spans(gaps, x_min, x_max, px) {
        let pad = ((px - (end - start)) / 2.0).max(0.0);
        let (start, end) = (start - pad, end + pad);
        plot_ui.polygon(
            Polygon::new(PlotPoints::from(vec![
                [start, y_min],
                [end, y_min],
                [end, y_max],
                [start, y_max],
            ]))
            .fill_color(fill)
            .stroke(Stroke::NONE)
            .allow_hover(false)
            .name(LEGEND),
        );
        if let Some(p) = pointer.filter(|p| p.x >= start && p.x <= end) {
            plot_ui.text(
                Text::new(
                    PlotPoint::new(p.x, y_max),
                    format!("{missing} events missing"),
                )
                .anchor(Align2::CENTER_TOP)
                .color(color),
            );
        }
    }
}

/// Draws the known gaps of `series` in its colour.
pub fn draw_series(plot_ui: &mut PlotUi, series: &SeriesData) {
    if let Some(Gaps::Known(gaps)) = &series.gaps {
        draw(plot_ui, gaps, series.color);
    }
}

/// The names of the series whose gaps are unknown.
pub fn unavailable<'a>(series: impl IntoIterator<Item = &'a SeriesData>) -> Vec<&'a str> {
    series
        .into_iter()
        .filter(|s| matches!(s.gaps, Some(Gaps::Unavailable)))
        .map(|s| s.name.as_str())
        .collect()
}

/// The "Show gaps" checkbox and, when shown, the series without gap information.
pub fn controls<'a>(
    ui: &mut egui::Ui,
    show: &mut bool,
    series: impl IntoIterator<Item = &'a SeriesData>,
) {
    ui.checkbox(show, "Show gaps (hook_seq)")
        .on_hover_text(TOOLTIP);
    if *show {
        let names = unavailable(series);
        if !names.is_empty() {
            ui.label(egui::RichText::new(format!("Gaps n/a: {}", names.join(", "))).small())
                .on_hover_text(TOOLTIP);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gap(start_ns: i64, end_ns: i64, missing: i64) -> Gap {
        Gap {
            start_ns,
            end_ns,
            first_seq: 1,
            missing,
        }
    }

    #[test]
    fn spans_keep_visible_gaps_and_merge_close_ones() {
        let gaps = [
            gap(0, 5, 1),
            gap(20, 30, 2),
            gap(31, 40, 3),
            gap(100, 110, 4),
        ];
        assert_eq!(spans(&gaps, 10.0, 50.0, 2.0), vec![(20.0, 40.0, 5)]);
        assert_eq!(
            spans(&gaps, 0.0, 200.0, 0.5),
            vec![
                (0.0, 5.0, 1),
                (20.0, 30.0, 2),
                (31.0, 40.0, 3),
                (100.0, 110.0, 4)
            ]
        );
    }
}
