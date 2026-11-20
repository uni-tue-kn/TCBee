//! String events in a plot: a vertical line per event with a horizontal label.
//! Labels that would overlap move into further rows below the plot's top edge.
//!
//! The lines are plot items ([`draw_lines`]). The labels are painted over the plot afterwards
//! ([`paint_labels`]): as plot items their positions would widen the auto-bounds every frame.

use egui::{Color32, TextStyle};
use egui_plot::{PlotTransform, PlotUi, VLine};

/// The string events of one series: name, colour, and `(time, label)` pairs.
pub type Events<'a> = (&'a str, Color32, &'a [(f64, String)]);

/// Space between two labels in the same row and between the line and its label (px).
const LABEL_GAP: f32 = 6.0;
/// Space between the plot's top edge and the first row (px).
const TOP_MARGIN: f32 = 4.0;

/// Draws a vertical line per string event; call inside the plot.
pub fn draw_lines(plot_ui: &mut PlotUi, series: &[Events]) {
    for &(name, color, events) in series {
        for (t, _) in events {
            plot_ui.vline(VLine::new(*t).color(color).name(name));
        }
    }
}

/// Paints the labels of the visible string events; call after the plot with its transform.
/// Labels that find no free row in the plot's height are left out.
pub fn paint_labels(ui: &egui::Ui, transform: &PlotTransform, series: &[Events]) {
    let frame = *transform.frame();
    let font = ui.style().text_styles[&TextStyle::Small].clone();
    let line_height = ui.fonts(|fonts| fonts.row_height(&font)).max(1.0);
    let row_count = ((frame.height() - TOP_MARGIN) / line_height)
        .floor()
        .max(0.0) as usize;

    let mut galleys = Vec::new();
    for &(_, color, events) in series {
        for (t, label) in events {
            let x = transform.position_from_point_x(*t);
            if x < frame.left() || x > frame.right() {
                continue;
            }
            let galley = ui.fonts(|fonts| fonts.layout_no_wrap(label.clone(), font.clone(), color));
            galleys.push((x + LABEL_GAP / 2.0, galley));
        }
    }
    galleys.sort_by(|a, b| a.0.total_cmp(&b.0));

    let spans: Vec<(f32, f32)> = galleys.iter().map(|(x, g)| (*x, g.size().x)).collect();
    let rows = label_rows(&spans, LABEL_GAP);
    let painter = ui.painter_at(frame);
    for ((x, galley), row) in galleys.into_iter().zip(rows) {
        if row < row_count {
            let y = frame.top() + TOP_MARGIN + row as f32 * line_height;
            painter.galley(egui::pos2(x, y), galley, Color32::PLACEHOLDER);
        }
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
