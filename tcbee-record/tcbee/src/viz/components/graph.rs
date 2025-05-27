use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker::Braille;
use ratatui::text::Span;
use ratatui::widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, LegendPosition};

use crate::viz::rate_watcher::RateWatcher;

pub struct Graph {
    ingress_vals: Vec<(f64, f64)>,
    egress_vals: Vec<(f64, f64)>,
    ymax: f64,
    xmax: f64,
    in_label: String,
    out_label: String,
    name: String,
    in_color: Color,
    out_color: Color,
}

impl Graph {
    pub fn new(
        in_label: String,
        out_label: String,
        in_color: Color,
        out_color: Color,
        name: String
    ) -> Graph {
        let ingress_vals: Vec<(f64, f64)> = Vec::new();
        let egress_vals: Vec<(f64, f64)> = Vec::new();

        Graph {
            ingress_vals,
            egress_vals,
            ymax: 0.0,
            xmax: 0.0,
            in_label,
            out_label,
            name,
            in_color,
            out_color,
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
                    format!("{:.2}s",self.xmax),
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
                    format!(
                        "{}",
                        RateWatcher::<u32>::format_rate(self.ymax, y_suffix)
                    ),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ];

        Chart::new(vec![
            Dataset::default()
                .name(self.in_label.clone())
                .marker(Braille)
                .style(Style::default().fg(self.in_color))
                .graph_type(GraphType::Line)
                .data(&self.ingress_vals),
            Dataset::default()
                .name(self.out_label.clone())
                .marker(Braille)
                .style(Style::default().fg(self.out_color))
                .graph_type(GraphType::Line)
                .data(&self.egress_vals),
        ])
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

    pub fn add_ingress(&mut self, val: (f64, f64)) {
        self.ingress_vals.push(val);

        // update ymax if needed
        self.ymax = self.ymax.max(val.1);

        // update xmax if needed
        self.xmax = self.xmax.max(val.0);
    }

    pub fn add_egress(&mut self, val: (f64, f64)) {
        self.egress_vals.push(val);

        // update ymax if needed
        self.ymax = self.ymax.max(val.1);
        self.xmax = self.xmax.max(val.0);
    }
}
