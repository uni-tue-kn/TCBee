//! String events in a plot: a vertical line per event with a horizontal label.
//! Labels that would overlap move into further rows below the plot's top edge.

use egui::{Align2, Color32, TextStyle};
use egui_plot::{PlotPoint, PlotUi, Text, VLine};

/// Space between two labels in the same row and between the line and its label (px).
const LABEL_GAP: f32 = 6.0;
/// Space between the plot's top edge and the first row (px).
const TOP_MARGIN: f32 = 4.0;

/// Draws the string events of each `(name, colour, events)` series.
pub fn draw<'a>(
    plot_ui: &mut PlotUi,
    series: impl IntoIterator<Item = (&'a str, Color32, &'a [(f64, String)])>,
) {
    let frame = *plot_ui.transform().frame();
    let font = plot_ui.ctx().style().text_styles[&TextStyle::Small].clone();

    // Lines for all events, labels only for the visible ones.
    let mut labels: Vec<(f64, f32, f32, &str, Color32)> = Vec::new();
    for (name, color, events) in series {
        for (t, label) in events {
            plot_ui.vline(VLine::new(*t).color(color).name(name));
            let x = plot_ui.screen_from_plot(PlotPoint::new(*t, 0.0)).x;
            if x < frame.left() || x > frame.right() {
                continue;
            }
            labels.push((*t, x, 0.0, label, color));
        }
    }
    if labels.is_empty() {
        return;
    }

    let line_height = plot_ui
        .ctx()
        .fonts(|fonts| fonts.row_height(&font))
        .max(1.0);
    for label in &mut labels {
        label.2 = plot_ui.ctx().fonts(|fonts| {
            fonts
                .layout_no_wrap(label.3.to_string(), font.clone(), Color32::WHITE)
                .size()
                .x
        });
    }
    labels.sort_by(|a, b| a.1.total_cmp(&b.1));

    let spans: Vec<(f32, f32)> = labels
        .iter()
        .map(|l| (l.1 + LABEL_GAP / 2.0, l.2))
        .collect();
    let rows = label_rows(&spans, LABEL_GAP);
    let row_count = (((frame.height() - TOP_MARGIN) / line_height).floor() as usize).max(1);

    for ((_, x, _, label, color), row) in labels.into_iter().zip(rows) {
        let y = frame.top() + TOP_MARGIN + (row % row_count) as f32 * line_height;
        let pos = plot_ui.plot_from_screen(egui::pos2(x + LABEL_GAP / 2.0, y));
        plot_ui.text(Text::new(pos, label).anchor(Align2::LEFT_TOP).color(color));
    }
}

/// The row of each `(start, width)` span, sorted by start, so that spans in one row are at
/// least `gap` apart. Each span takes the first row that is free at its start.
pub fn label_rows(spans: &[(f32, f32)], gap: f32) -> Vec<usize> {
    let mut row_ends: Vec<f32> = Vec::new();
    spans
        .iter()
        .map(|&(start, width)| {
            let row = row_ends
                .iter()
                .position(|&end| end + gap <= start)
                .unwrap_or(row_ends.len());
            if row == row_ends.len() {
                row_ends.push(start + width);
            } else {
                row_ends[row] = start + width;
            }
            row
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distant_labels_share_the_first_row() {
        assert_eq!(
            label_rows(&[(0.0, 10.0), (20.0, 10.0), (40.0, 10.0)], 5.0),
            [0, 0, 0]
        );
    }

    #[test]
    fn close_labels_move_down_and_reuse_freed_rows() {
        let spans = [(0.0, 50.0), (10.0, 50.0), (20.0, 5.0), (70.0, 10.0)];
        assert_eq!(label_rows(&spans, 5.0), [0, 1, 2, 0]);
    }
}
