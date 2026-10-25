use ratatui::{
    style::{Modifier, Style},
    symbols::Marker::Braille,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType},
};

use crate::viz::{format, model::ChartModel};

/// Title of a chart: its zoom key, name and unit, then the series names in their colours
pub fn title(chart: &ChartModel, key: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(format!(
        "{key} {} ({}) ",
        chart.title, chart.unit
    ))];
    for series in &chart.series {
        spans.push(Span::styled(
            format!("\u{25a0} {} ", series.label),
            Style::default().fg(series.color),
        ));
    }
    Line::from(spans)
}

/// The Braille line chart of a chart's histories, the legend is in the title
pub fn chart(chart: &ChartModel, key: usize, window: Option<f64>) -> Chart<'_> {
    let end = chart.end();
    let xmin = window.map_or(0.0, |window| (end - window).max(0.0));
    let xmax = if end > xmin { end } else { xmin + 1.0 };
    let ymax = chart.max();
    let ymax = if ymax > 0.0 { ymax } else { 1.0 };
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let x_labels = [xmin, (xmin + xmax) / 2.0, xmax]
        .into_iter()
        .map(|x| Span::styled(format::axis_time(x), bold))
        .collect::<Vec<_>>();
    let y_labels = [0.0, ymax / 2.0, ymax]
        .into_iter()
        .map(|y| Span::styled(format::si(y), bold))
        .collect::<Vec<_>>();

    let datasets: Vec<Dataset> = chart
        .series
        .iter()
        .map(|series| {
            Dataset::default()
                .marker(Braille)
                .style(Style::default().fg(series.color))
                .graph_type(GraphType::Line)
                .data(series.history.points())
        })
        .collect();

    Chart::new(datasets)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title(chart, key)),
        )
        .x_axis(Axis::default().bounds([xmin, xmax]).labels(x_labels))
        .y_axis(Axis::default().bounds([0.0, ymax]).labels(y_labels))
        .legend_position(None)
}
