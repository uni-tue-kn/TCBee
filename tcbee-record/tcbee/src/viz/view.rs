//! The terminal UI: renders a model into a frame and reacts to keys and the mouse

use ratatui::{
    crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind},
    layout::{Constraint, Direction, Layout, Margin, Position, Rect},
    style::{Color, Style},
    widgets::{
        Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, TableState,
        Wrap,
    },
    Frame,
};
use tcbee_common::stats::{RB_BBR, RB_CUBIC};

use crate::{
    eBPF::ebpf_runner_config::EbpfWatcherConfig,
    viz::{
        components::status::Status,
        flow_tracker::{flow_table, Flow},
        format,
        groups::{display_group, Group},
        model::{
            Model, GRAPH_BBR, GRAPH_CALLS, GRAPH_CUBIC, GRAPH_EVENTS, GRAPH_PACKETS,
            GRAPH_TRACEPOINTS,
        },
    },
};

/// Chart slots of the grid
pub const SLOTS: usize = 4;
/// Below this size the UI shows only a hint
pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 16;

/// What the UI shows that does not change while recording
pub struct View {
    /// The graph in each chart slot, at most `SLOTS`
    pub slots: Vec<usize>,
    pub context: EbpfWatcherConfig,
}

impl View {
    pub fn new(context: EbpfWatcherConfig) -> View {
        let rings = &context.active_rings;
        let group = |group: Group| rings.iter().any(|rb| display_group(*rb) == group);
        // In the order they get a slot
        let slots = [
            (true, GRAPH_EVENTS),
            (group(Group::Headers), GRAPH_PACKETS),
            (group(Group::Sock), GRAPH_CALLS),
            (rings.contains(&RB_CUBIC), GRAPH_CUBIC),
            (rings.contains(&RB_BBR), GRAPH_BBR),
            (group(Group::Tracepoints), GRAPH_TRACEPOINTS),
        ]
        .into_iter()
        .filter(|(shown, _)| *shown)
        .map(|(_, graph)| graph)
        .take(SLOTS)
        .collect();
        View { slots, context }
    }
}

/// What the user selected
#[derive(Default)]
pub struct UiState {
    /// The chart slot shown alone
    pub zoom: Option<usize>,
    /// First flow shown
    pub scroll: usize,
}

/// Where the last frame put the parts that take mouse clicks
#[derive(Default)]
pub struct Areas {
    /// Chart slots on screen and their areas
    pub slots: Vec<(usize, Rect)>,
}

impl UiState {
    /// Handles a key, returns whether to quit
    pub fn on_key(&mut self, code: KeyCode, view: &View, flows: usize) -> bool {
        match code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => self.zoom = None,
            KeyCode::Char(key @ '1'..='4') => {
                let slot = key as usize - '1' as usize;
                if slot < view.slots.len() {
                    self.zoom = Some(slot);
                }
            }
            // Limit index to number of flows
            KeyCode::Down => self.scroll = (self.scroll + 1).min(flows),
            KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
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
                // A click zooms a chart, a click on the zoomed chart returns to the grid
                if let Some((slot, _)) = areas.slots.iter().find(|(_, area)| area.contains(at)) {
                    self.zoom = match self.zoom {
                        Some(_) => None,
                        None => Some(*slot),
                    };
                }
            }
            _ => {}
        }
    }
}

/// Areas of `count` charts: one fills the area, two side by side, more in two rows
pub fn grid(area: Rect, count: usize) -> Vec<Rect> {
    let columns = |area: Rect, count: usize| {
        Layout::horizontal(vec![Constraint::Ratio(1, count as u32); count])
            .split(area)
            .to_vec()
    };
    match count {
        0 => Vec::new(),
        1 | 2 => columns(area, count),
        _ => {
            let [top, bottom] = Layout::vertical([Constraint::Ratio(1, 2); 2]).areas(area);
            let mut areas = columns(top, 2);
            areas.extend(columns(bottom, count - 2));
            areas
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
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let hint = format!(
            "Terminal too small, needs {MIN_WIDTH}x{MIN_HEIGHT}. Recording goes on, q quits."
        );
        frame.render_widget(Paragraph::new(hint).wrap(Wrap { trim: true }), area);
        return Areas::default();
    }

    let [main, footer] = Layout::vertical([Constraint::Min(8), Constraint::Max(3)]).areas(area);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(20), Constraint::Percentage(80)]).areas(main);

    // A zoomed chart takes the place of the flows as well
    let shown: Vec<usize> = match ui.zoom {
        Some(slot) => vec![slot],
        None => (0..view.slots.len()).collect(),
    };
    let chart_area = if ui.zoom.is_some() {
        right
    } else {
        let [charts, flow_area] = Layout::vertical([Constraint::Percentage(50); 2]).areas(right);
        render_flows(frame, ui, flows, flow_area);
        charts
    };
    let areas = grid(chart_area, shown.len());
    let slots: Vec<(usize, Rect)> = shown.into_iter().zip(areas).collect();
    for (slot, rect) in &slots {
        let graph = &model.graphs[view.slots[*slot]];
        let unit = match view.slots[*slot] {
            GRAPH_PACKETS => "pps",
            GRAPH_CALLS => "calls/s",
            _ => "events/s",
        };
        let title = format!("{} {} ({unit})", slot + 1, graph.name());
        frame.render_widget(graph.get_chart(title, Color::Reset, Color::Reset), *rect);
    }

    render_status(frame, model, view, left);

    let context = &view.context;
    let window_label = context
        .observation_window
        .map(|window| format!(" | Window: {}", format::axis_time(window)))
        .unwrap_or_default();
    let zoom_label = match ui.zoom {
        Some(_) => "Back: Esc",
        None => "Zoom: 1-4",
    };
    let keybindings = Paragraph::new(format!(
        "Quit: q | {zoom_label} | Scroll: \u{2191}\u{2193} | K, M, G: 10^3, 10^6, 10^9{window_label}"
    ))
    .style(Style::default().fg(Color::Reset));
    let keybindings_block = Block::bordered()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Reset))
        .title(format!(
            "Recording to {}{}, {} CPUs{}",
            context.dir,
            context
                .iface
                .as_ref()
                .map(|iface| format!(" at {iface}"))
                .unwrap_or_default(),
            context.cpus,
            if context.on_change { ", on change" } else { "" }
        ));
    frame.render_widget(keybindings.block(keybindings_block), footer);

    Areas { slots }
}

fn render_status(frame: &mut Frame, model: &Model, view: &View, area: Rect) {
    let status = Status::new();
    let mut constraints = vec![Constraint::Max(3); status.num_blocks()];
    constraints.push(Constraint::Min(0));
    let sidebar = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let snap = &model.snapshot;
    let elapsed = model.elapsed;
    let time_string = format::clock(elapsed);
    let event_rate = format::rate(model.handled_rate() + model.dropped_rate(), "events/s");
    let file_rate = format!("{}/s", format::bytes(model.disk_rate()));
    let blocks = status.get_blocks(
        time_string,
        format::si(snap.handled() as f64),
        format::si(snap.dropped() as f64),
        snap.dropped() > 0,
        event_rate,
        model.bytes_written,
        file_rate,
        Color::Reset,
    );
    let skipped_area = sidebar[blocks.len()];
    for (i, block) in blocks.into_iter().enumerate() {
        frame.render_widget(block, sidebar[i]);
    }
    if !view.context.skipped.is_empty() {
        let skipped = Paragraph::new(view.context.skipped.join("\n"))
            .wrap(Wrap { trim: true })
            .block(Block::default().title("Skipped"));
        frame.render_widget(skipped, skipped_area);
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
    // The header takes a line
    if flows.len() > inner.height.saturating_sub(1) as usize {
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
        slot, RB_COUNT, RB_TCP4_DRIVER_INGRESS, RB_TCP4_EGRESS, RB_TCP4_INGRESS, RB_TCP6_EGRESS,
        RB_TCP6_INGRESS, STATS_LEN, STAT_DROPPED, STAT_HANDLED,
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
    pub fn busy_model(rings: &[u32], window: Option<f64>) -> Model {
        let mut model = Model::new(rings, window);
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

    pub const TC_RINGS: [u32; 4] = [
        RB_TCP4_EGRESS,
        RB_TCP4_INGRESS,
        RB_TCP6_EGRESS,
        RB_TCP6_INGRESS,
    ];

    /// A run with the given rings
    pub fn context(rings: &[u32]) -> EbpfWatcherConfig {
        EbpfWatcherConfig {
            dir: "/data/run1".to_string(),
            iface: Some("eth0".to_string()),
            cpus: 8,
            active_rings: rings.to_vec(),
            skipped: vec!["BBR: tcp_bbr is not loaded".to_string()],
            on_change: false,
            observation_window: None,
        }
    }

    fn contains(lines: &[String], text: &str) -> bool {
        lines.iter().any(|line| line.contains(text))
    }

    #[test]
    fn rates_follow_the_counters() {
        let model = busy_model(&TC_RINGS, None);
        assert_eq!(model.handled_rate(), 990.0);
        assert_eq!(model.dropped_rate(), 10.0);
        assert_eq!(model.ingress_rate(), 600.0);
        assert_eq!(model.egress_rate(), 400.0);
        assert_eq!(model.disk_rate(), 2_000_000.0);
        // The driver rings saw nothing
        assert_eq!(
            busy_model(&[RB_TCP4_DRIVER_INGRESS], None).ingress_rate(),
            0.0
        );
    }

    #[test]
    fn first_tick_has_no_rates() {
        let mut model = Model::new(&TC_RINGS, None);
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
        let model = busy_model(&TC_RINGS, None);
        let view = View::new(context(&TC_RINGS));
        let flows = [Flow {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            sport: 5201,
            dport: 40000,
        }];
        let (lines, areas) = screen(160, 45, &model, &view, &UiState::default(), &flows);
        assert!(contains(&lines, "Time Elapsed"));
        assert!(contains(&lines, "00:00:01"));
        assert!(contains(&lines, "1.00K events/s"));
        assert!(contains(&lines, "2.00 MB/s"));
        assert!(contains(&lines, "Events Handled"));
        assert!(contains(&lines, "Events"));
        assert!(contains(&lines, "Tracking 1 Flows"));
        assert!(contains(&lines, "10.0.0.2"));
        assert!(contains(&lines, "Recording to /data/run1 at eth0, 8 CPUs"));
        assert!(contains(&lines, "tcp_bbr is not loaded"));
        assert_eq!(areas.slots.len(), 2);
        assert!(contains(&lines, "1 Events (events/s)"));
        assert!(contains(&lines, "2 Packet Rates (pps)"));
    }

    #[test]
    fn slots_follow_the_active_rings() {
        let all = View::new(context(&(0..RB_COUNT).collect::<Vec<_>>()));
        assert_eq!(
            all.slots,
            [GRAPH_EVENTS, GRAPH_PACKETS, GRAPH_CALLS, GRAPH_CUBIC]
        );
        assert_eq!(View::new(context(&[])).slots, [GRAPH_EVENTS]);
    }

    #[test]
    fn grid_fills_the_chart_area() {
        let area = Rect::new(0, 0, 100, 40);
        assert_eq!(grid(area, 1), [area]);
        assert_eq!(
            grid(area, 2),
            [Rect::new(0, 0, 50, 40), Rect::new(50, 0, 50, 40)]
        );
        assert_eq!(grid(area, 3)[2], Rect::new(0, 20, 100, 20));
        assert_eq!(grid(area, 4)[3], Rect::new(50, 20, 50, 20));
    }

    #[test]
    fn small_terminals_get_a_hint() {
        let model = busy_model(&TC_RINGS, None);
        let view = View::new(context(&TC_RINGS));
        // No panic on a tiny terminal
        screen(1, 1, &model, &view, &UiState::default(), &[]);
        for (width, height) in [(59, 45), (160, 15), (60, 16)] {
            let (lines, areas) = screen(width, height, &model, &view, &UiState::default(), &[]);
            let small = width < MIN_WIDTH || height < MIN_HEIGHT;
            assert_eq!(contains(&lines, "Terminal too small"), small);
            assert_eq!(areas.slots.is_empty(), small);
        }
    }

    #[test]
    fn zoom_shows_one_chart() {
        let model = busy_model(&TC_RINGS, None);
        let view = View::new(context(&TC_RINGS));
        let mut ui = UiState::default();
        ui.on_key(KeyCode::Char('2'), &view, 0);
        assert_eq!(ui.zoom, Some(1));
        let (lines, areas) = screen(160, 45, &model, &view, &ui, &[]);
        assert_eq!(areas.slots.len(), 1);
        assert_eq!(areas.slots[0].0, 1);
        assert!(!contains(&lines, "Tracking"));
        // No third slot to zoom, Esc returns, q quits
        ui.on_key(KeyCode::Char('3'), &view, 0);
        assert_eq!(ui.zoom, Some(1));
        assert!(!ui.on_key(KeyCode::Esc, &view, 0));
        assert_eq!(ui.zoom, None);
        assert!(ui.on_key(KeyCode::Char('q'), &view, 0));
    }

    #[test]
    fn clicks_zoom_the_chart_under_the_mouse() {
        let model = busy_model(&TC_RINGS, None);
        let view = View::new(context(&TC_RINGS));
        let mut ui = UiState::default();
        let (_, areas) = screen(160, 45, &model, &view, &ui, &[]);
        let (slot, area) = areas.slots[1];
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: area.x + 1,
            row: area.y + 1,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        };
        ui.on_mouse(click, &areas, 0);
        assert_eq!(ui.zoom, Some(slot));
        let (_, areas) = screen(160, 45, &model, &view, &ui, &[]);
        ui.on_mouse(click, &areas, 0);
        assert_eq!(ui.zoom, None);
    }
}
