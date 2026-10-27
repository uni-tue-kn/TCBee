use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    symbols::Marker::Braille,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType},
    Frame,
};

use crate::viz::{
    format,
    history::{self, thin},
    model::ChartModel,
};

/// Title of a chart `width` cells wide: its zoom key, name and unit in bold, then the series
/// names in their colours. Names get shorter or go when they do not fit, the colour squares stay.
pub fn title(chart: &ChartModel, key: usize, width: u16) -> Line<'static> {
    let head = format!(" {key} {} ({}) ", chart.title, chart.unit);
    // The corners and a cell of border stay visible
    let room = (width as usize).saturating_sub(3);
    let legend = |chars: usize| -> Vec<String> {
        chart
            .series
            .iter()
            .map(|series| match chars {
                0 => "\u{25a0}".to_string(),
                _ => format!(
                    "\u{25a0} {}",
                    series.label.chars().take(chars).collect::<String>()
                ),
            })
            .collect()
    };
    let length = |names: &[String]| {
        head.chars().count() + names.iter().map(|n| n.chars().count() + 1).sum::<usize>()
    };
    let names = [usize::MAX, 4, 0]
        .into_iter()
        .map(legend)
        .find(|names| length(names) <= room)
        .unwrap_or_else(|| legend(0));
    let mut spans = vec![Span::styled(
        head,
        Style::default().add_modifier(Modifier::BOLD),
    )];
    for (series, name) in chart.series.iter().zip(names) {
        spans.push(Span::styled(
            format!("{name} "),
            Style::default().fg(series.color),
        ));
    }
    Line::from(spans)
}

/// The Braille line chart of a chart's histories in `span`, the legend is in the title and
/// `bottom` at the right of the bottom border
pub fn render(
    frame: &mut Frame,
    chart: &ChartModel,
    key: usize,
    span: history::Span,
    bottom: Option<Line<'static>>,
    area: Rect,
) {
    let end = chart.end();
    let (xmin, xmax) = match span {
        history::Span::Whole => (0.0, end.max(1.0)),
        history::Span::Last(window) => (end - window, end),
    };
    // Two points per Braille dot are enough, more only cost drawing time
    let data: Vec<_> = chart
        .series
        .iter()
        .map(|series| thin(series.points(span, end), 4 * area.width as usize))
        .collect();
    let ymax = data
        .iter()
        .flat_map(|points| points.iter().map(|(_, y)| *y))
        .fold(0.0, f64::max);
    let ymax = if ymax > 0.0 { ymax } else { 1.0 };
    let bold = Style::default().add_modifier(Modifier::BOLD);
    // A window counts back from now
    let x_labels = match span {
        history::Span::Whole => [xmin, (xmin + xmax) / 2.0, xmax].map(format::axis_time),
        history::Span::Last(window) => [
            format!("-{}", format::axis_time(window)),
            format!("-{}", format::axis_time(window / 2.0)),
            "now".to_string(),
        ],
    }
    .map(|label| Span::styled(label, bold))
    .to_vec();
    let y_labels = [0.0, ymax / 2.0, ymax]
        .into_iter()
        .map(|y| Span::styled(format::si(y), bold))
        .collect::<Vec<_>>();

    let datasets: Vec<Dataset> = chart
        .series
        .iter()
        .zip(&data)
        .map(|(series, points)| {
            Dataset::default()
                .marker(Braille)
                .style(Style::default().fg(series.color))
                .graph_type(GraphType::Line)
                .data(points)
        })
        .collect();

    let mut block = Block::default()
        .borders(Borders::ALL)
        .title(title(chart, key, area.width));
    if let Some(bottom) = bottom {
        block = block.title_bottom(bottom.right_aligned());
    }
    let widget = Chart::new(datasets)
        .block(block)
        .x_axis(Axis::default().bounds([xmin, xmax]).labels(x_labels))
        .y_axis(Axis::default().bounds([0.0, ymax]).labels(y_labels))
        .legend_position(None);
    frame.render_widget(widget, area);
}
