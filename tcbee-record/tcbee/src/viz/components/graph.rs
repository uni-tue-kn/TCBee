use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker::Braille;
use ratatui::text::Span;
use ratatui::widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, LegendPosition};

use crate::viz::{
    format,
    history::{History, HISTORY_POINTS},
};

pub struct Graph {
    data: Vec<History>,
    labels: Vec<String>,
    colors: Vec<Color>,
    observation_window: Option<f64>,
    name: String,
}

impl Graph {
    pub fn new(
        label_1: String,
        label_2: String,
        color_1: Color,
        color_2: Color,
        observation_window: Option<f64>,
        name: String,
    ) -> Graph {
        Graph {
            data: vec![
                History::new(HISTORY_POINTS, observation_window),
                History::new(HISTORY_POINTS, observation_window),
            ],
            labels: vec![label_1, label_2],
            colors: vec![color_1, color_2],
            observation_window,
            name,
        }
    }

    pub fn new_single(
        label: String,
        color: Color,
        observation_window: Option<f64>,
        name: String,
    ) -> Graph {
        Graph {
            data: vec![History::new(HISTORY_POINTS, observation_window)],
            labels: vec![label],
            colors: vec![color],
            observation_window,
            name,
        }
    }

    pub fn get_chart(&self, title: String, axis_color: Color, border_color: Color) -> Chart<'_> {
        let end = self
            .data
            .iter()
            .filter_map(History::end)
            .fold(0.0, f64::max);
        let xmin = self
            .observation_window
            .map_or(0.0, |window| (end - window).max(0.0));
        let xmax = if end > xmin { end } else { xmin + 1.0 };
        let ymax = self.data.iter().map(History::max).fold(0.0, f64::max);
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

        let datasets: Vec<Dataset> = self
            .data
            .iter()
            .zip(self.labels.iter())
            .zip(self.colors.iter())
            .map(|((data, label), color)| {
                Dataset::default()
                    .name(label.clone())
                    .marker(Braille)
                    .style(Style::default().fg(*color))
                    .graph_type(GraphType::Line)
                    .data(data.points())
            })
            .collect();

        Chart::new(datasets)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color))
                    .title(title),
            )
            .x_axis(
                Axis::default()
                    .style(Style::default().fg(axis_color))
                    .bounds([xmin, xmax])
                    .labels(x_labels),
            )
            .y_axis(
                Axis::default()
                    .style(Style::default().fg(axis_color))
                    .bounds([0.0, ymax])
                    .labels(y_labels),
            )
            .legend_position(Some(LegendPosition::TopLeft))
            .hidden_legend_constraints((Constraint::Min(0), Constraint::Min(0)))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn add_val(&mut self, idx: usize, val: (f64, f64)) {
        if let Some(data) = self.data.get_mut(idx) {
            data.push(val.0, val.1);
        }
    }
}
