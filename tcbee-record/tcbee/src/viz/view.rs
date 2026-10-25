//! The terminal UI: renders a model into a frame and reacts to keys and the mouse

use ratatui::{
    crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind},
    layout::{Constraint, Direction, Layout, Margin, Position, Rect},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, TableState,
    },
    Frame,
};

use crate::{
    eBPF::ebpf_runner_config::GraphConfig,
    viz::{
        components::status::Status,
        flow_tracker::{flow_table, Flow},
        format,
        model::{
            Model, GRAPH_BBR, GRAPH_CALLS, GRAPH_CUBIC, GRAPH_EVENTS, GRAPH_PACKETS,
            GRAPH_TRACEPOINTS,
        },
    },
};

/// What the UI shows that does not change while recording
pub struct View {
    /// Tab titles and the graph each shows
    pub tabs: Vec<(&'static str, usize)>,
    pub observation_window: Option<f64>,
}

impl View {
    pub fn new(graphs: &GraphConfig, observation_window: Option<f64>) -> View {
        let tabs = [
            (graphs.events, "Events", GRAPH_EVENTS),
            (graphs.packets, "Packets", GRAPH_PACKETS),
            (graphs.kernel, "Kernel", GRAPH_CALLS),
            (graphs.cubic, "Cubic", GRAPH_CUBIC),
            (graphs.bbr, "BBR", GRAPH_BBR),
            (graphs.tracepoints, "Tracepoints", GRAPH_TRACEPOINTS),
        ]
        .into_iter()
        .filter(|(shown, _, _)| *shown)
        .map(|(_, title, graph)| (title, graph))
        .collect();
        View {
            tabs,
            observation_window,
        }
    }
}

/// What the user selected
#[derive(Default)]
pub struct UiState {
    pub tab: usize,
    /// First flow shown
    pub scroll: usize,
}

/// Where the last frame put the parts that take mouse clicks
#[derive(Default)]
pub struct Areas {
    pub tabs: Vec<Rect>,
}

impl UiState {
    /// Handles a key, returns whether to quit
    pub fn on_key(&mut self, code: KeyCode, view: &View, flows: usize) -> bool {
        let tabs = view.tabs.len();
        match code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            // Limit index to number of flows
            KeyCode::Down => self.scroll = (self.scroll + 1).min(flows),
            KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Right | KeyCode::Tab if tabs > 0 => self.tab = (self.tab + 1) % tabs,
            KeyCode::Left if tabs > 0 => self.tab = (self.tab + tabs - 1) % tabs,
            _ => {}
        }
        false
    }

    pub fn on_mouse(&mut self, mouse: MouseEvent, areas: &Areas, flows: usize) {
        match mouse.kind {
            MouseEventKind::ScrollDown => self.scroll = (self.scroll + 1).min(flows),
            MouseEventKind::ScrollUp => self.scroll = self.scroll.saturating_sub(1),
            MouseEventKind::Down(MouseButton::Left) => {
                let at = Position::new(mouse.column, mouse.row);
                if let Some(tab) = areas.tabs.iter().position(|area| area.contains(at)) {
                    self.tab = tab;
                }
            }
            _ => {}
        }
    }
}

pub fn render(
    frame: &mut Frame,
    model: &Model,
    view: &View,
    ui: &UiState,
    flows: &[Flow],
) -> Areas {
    frame.render_widget(Block::default().style(Style::default()), frame.area());

    // Main layout
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Min(8), Constraint::Max(3)])
        .split(frame.area());

    // Top layout
    let top_areas = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Percentage(20), Constraint::Percentage(80)])
        .split(areas[0]);

    // Top graph layout (Right side)
    let right_side = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(top_areas[1]);

    // Graph Area (Top of right side)
    let graph_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(right_side[0]);
    let tab_area = graph_layout[0];
    let chart_area = graph_layout[1];

    // Render Tabs
    let tab_constraints: Vec<Constraint> = (0..view.tabs.len())
        .map(|_| Constraint::Ratio(1, view.tabs.len() as u32))
        .collect();
    let tab_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(tab_constraints)
        .split(tab_area);
    for (i, (title, _)) in view.tabs.iter().enumerate() {
        let style = if i == ui.tab {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Reset)
        };
        frame.render_widget(
            Paragraph::new(*title)
                .block(Block::bordered().border_style(Style::default().fg(Color::Reset)))
                .style(style),
            tab_chunks[i],
        );
    }

    // Render Selected Graph
    let graph = view.tabs.get(ui.tab).map_or(GRAPH_EVENTS, |(_, id)| *id);
    let suffix = match graph {
        GRAPH_PACKETS => "pps",
        GRAPH_CALLS => "Calls/s",
        _ => "Events/s",
    };
    let chart = model.graphs[graph].get_chart(suffix, Color::Reset, Color::Reset);
    frame.render_widget(chart, chart_area);

    render_status(frame, model, top_areas[0]);
    render_flows(frame, ui, flows, right_side[1]);

    // Tooltips
    let window_label = view
        .observation_window
        .map(|window| format!(" | Window: {:.2}s", window))
        .unwrap_or_default();
    let keybindings = Paragraph::new(format!(
        "Close: q | Tabs: Tab | Scroll: \u{2191}\u{2193} | Legend: (K)ilo, (M)ega, (G)iga{}",
        window_label
    ))
    .style(Style::default().fg(Color::Reset));
    let keybindings_block = Block::bordered()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Reset))
        .title("Keybindings");
    frame.render_widget(keybindings.block(keybindings_block), areas[1]);

    Areas {
        tabs: tab_chunks.to_vec(),
    }
}

fn render_status(frame: &mut Frame, model: &Model, area: Rect) {
    let status = Status::new();
    let mut constraints = vec![Constraint::Max(3); status.num_blocks()];
    constraints.push(Constraint::Min(0));
    let sidebar = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let snap = &model.snapshot;
    let elapsed = model.elapsed;
    let time_string = format!("{}s {}ms", elapsed.as_secs(), elapsed.subsec_millis());
    let event_rate = format::rate(model.handled_rate() + model.dropped_rate(), " Events/s");
    let file_rate = format::rate(model.disk_rate(), "Byte/s");
    let blocks = status.get_blocks(
        time_string,
        format::sum(snap.handled(), ""),
        format::sum(snap.dropped(), ""),
        snap.dropped() > 0,
        event_rate,
        model.bytes_written,
        file_rate,
        Color::Reset,
    );
    for (i, block) in blocks.into_iter().enumerate() {
        frame.render_widget(block, sidebar[i]);
    }
}

fn render_flows(frame: &mut Frame, ui: &UiState, flows: &[Flow], area: Rect) {
    let table = flow_table(flows).block(
        Block::bordered()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Reset))
            .title(format!(
                "Tracking {} Flows. Scroll with arrows or mousewheel.",
                flows.len()
            )),
    );
    let mut table_state = TableState::new().with_offset(ui.scroll);
    frame.render_stateful_widget(table, area, &mut table_state);

    // Render scrollbar when more entries than height
    let inner = area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });
    if flows.len() > (inner.height - 1) as usize {
        let mut scrollbar_state = ScrollbarState::new(flows.len())
            .position(ui.scroll)
            .viewport_content_length(area.height as usize);
        scrollbar_state.next();
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);
        frame.render_stateful_widget(scrollbar, inner, &mut scrollbar_state);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use ratatui::{backend::TestBackend, Terminal};
    use tcbee_common::stats::{
        slot, RB_TCP4_EGRESS, RB_TCP4_INGRESS, STATS_LEN, STAT_DROPPED, STAT_HANDLED,
    };

    use super::*;
    use crate::stats::Snapshot;

    /// A snapshot with `values` in the given slots, zero elsewhere
    pub fn snapshot(values: &[(u32, u64)]) -> Snapshot {
        let mut all = vec![0; STATS_LEN as usize];
        for (slot, value) in values {
            all[*slot as usize] = *value;
        }
        Snapshot::from_values(all)
    }

    /// The screen as lines of text
    pub fn screen(
        width: u16,
        height: u16,
        model: &Model,
        view: &View,
        ui: &UiState,
        flows: &[Flow],
    ) -> (Vec<String>, Areas) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut areas = Areas::default();
        terminal
            .draw(|frame| areas = render(frame, model, view, ui, flows))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let lines = (0..height)
            .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect())
            .collect();
        (lines, areas)
    }

    /// Two ticks one second apart: 1000 records and 10 drops, 600 packets in, 400 out
    pub fn busy_model(driver_packets: bool, window: Option<f64>) -> Model {
        let mut model = Model::new(driver_packets, window);
        model.update(snapshot(&[]), 0, Duration::from_millis(500));
        model.record_history();
        let values = [
            (slot(RB_TCP4_INGRESS, STAT_HANDLED), 600),
            (slot(RB_TCP4_EGRESS, STAT_HANDLED), 390),
            (slot(RB_TCP4_EGRESS, STAT_DROPPED), 10),
        ];
        model.update(snapshot(&values), 2_000_000, Duration::from_millis(1500));
        model.record_history();
        model
    }

    fn all_graphs() -> GraphConfig {
        GraphConfig {
            events: true,
            packets: true,
            ..GraphConfig::default()
        }
    }

    fn contains(lines: &[String], text: &str) -> bool {
        lines.iter().any(|line| line.contains(text))
    }

    #[test]
    fn rates_follow_the_counters() {
        let model = busy_model(false, None);
        assert_eq!(model.handled_rate(), 990.0);
        assert_eq!(model.dropped_rate(), 10.0);
        assert_eq!(model.ingress_rate(), 600.0);
        assert_eq!(model.egress_rate(), 400.0);
        assert_eq!(model.disk_rate(), 2_000_000.0);
        // The driver rings saw nothing
        assert_eq!(busy_model(true, None).ingress_rate(), 0.0);
    }

    #[test]
    fn first_tick_has_no_rates() {
        let mut model = Model::new(false, None);
        model.update(
            snapshot(&[(slot(RB_TCP4_INGRESS, STAT_HANDLED), 5)]),
            10,
            Duration::from_secs(1),
        );
        assert_eq!(model.ingress_rate(), 0.0);
        assert_eq!(model.disk_rate(), 0.0);
    }

    #[test]
    fn screen_shows_status_tabs_and_flows() {
        let model = busy_model(false, None);
        let view = View::new(&all_graphs(), None);
        let flows = [Flow {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            sport: 5201,
            dport: 40000,
        }];
        let (lines, areas) = screen(160, 45, &model, &view, &UiState::default(), &flows);
        assert!(contains(&lines, "Time Elapsed"));
        assert!(contains(&lines, "1s 500ms"));
        assert!(contains(&lines, "Events Handled"));
        assert!(contains(&lines, "Events"));
        assert!(contains(&lines, "Packets"));
        assert!(contains(&lines, "Tracking 1 Flows"));
        assert!(contains(&lines, "10.0.0.2"));
        assert_eq!(areas.tabs.len(), 2);
    }

    #[test]
    fn keys_switch_tabs_and_quit() {
        let view = View::new(&all_graphs(), None);
        let mut ui = UiState::default();
        assert!(!ui.on_key(KeyCode::Tab, &view, 0));
        assert_eq!(ui.tab, 1);
        ui.on_key(KeyCode::Tab, &view, 0);
        assert_eq!(ui.tab, 0);
        ui.on_key(KeyCode::Left, &view, 0);
        assert_eq!(ui.tab, 1);
        assert!(ui.on_key(KeyCode::Char('q'), &view, 0));
    }
}
