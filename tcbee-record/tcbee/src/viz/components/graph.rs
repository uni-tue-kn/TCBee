use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker::Braille;
use ratatui::text::Span;
use ratatui::widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, LegendPosition};

use crate::viz::rate_watcher::RateWatcher;

pub struct Graph {
    data: Vec<Vec<(f64, f64)>>,
    labels: Vec<String>,
    colors: Vec<Color>,
    ymax: f64,
    xmax: f64,
    name: String,
}

impl Graph {
    pub fn new(
        label_1: String,
        label_2: String,
        color_1: Color,
        color_2: Color,
        name: String,
    ) -> Graph {
        Graph {
            data: vec![Vec::new(), Vec::new()],
            labels: vec![label_1, label_2],
            colors: vec![color_1, color_2],
            ymax: 0.0,
            xmax: 0.0,
            name,
        }
    }

    pub fn new_single(label: String, color: Color, name: String) -> Graph {
        Graph {
            data: vec![Vec::new()],
            labels: vec![label],
            colors: vec![color],
            ymax: 0.0,
            xmax: 0.0,
            name,
        }
    }

    pub fn get_chart(&self, y_suffix: &str) -> Chart {
        let x_labels = vec![
            Span::styled(
                format!("{}", 0),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:.2}s", self.xmax / 2.0),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:.2}s", self.xmax),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ];

        let y_labels = vec![
            Span::styled(
                format!("{}", 0),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "{}",
                    RateWatcher::<u32>::format_rate(self.ymax / 2.0, y_suffix)
                ),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{}", RateWatcher::<u32>::format_rate(self.ymax, y_suffix)),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ];

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
                    .data(data)
            })
            .collect();

        Chart::new(datasets)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(self.name.clone()),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(Color::White))
                .bounds([0.0, self.xmax])
                .labels(x_labels),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(Color::White))
                .bounds([0.0, self.ymax])
                .labels(y_labels),
        )
        .legend_position(Some(LegendPosition::TopLeft))
        .hidden_legend_constraints((Constraint::Min(0), Constraint::Min(0)))
    }

    pub fn add_val(&mut self, idx: usize, val: (f64, f64)) {
        if let Some(data) = self.data.get_mut(idx) {
            data.push(val);
            self.ymax = self.ymax.max(val.1);
            self.xmax = self.xmax.max(val.0);
        }
    }
}
