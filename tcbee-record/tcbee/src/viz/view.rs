//! The terminal UI: renders a model into a frame and reacts to keys and the mouse

use ratatui::{
    crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind},
    layout::{Constraint, Layout, Margin, Position, Rect},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline,
        TableState, Wrap,
    },
    Frame,
};

use crate::{
    eBPF::ebpf_runner_config::EbpfWatcherConfig,
    viz::{
        components::{
            graph,
            status::{self, LEFT_WIDTH},
        },
        flow_tracker::{flow_table, Flow},
        format,
        model::Model,
    },
};

/// Below this size the UI shows only a hint
pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 16;

/// What the UI shows that does not change while recording
pub struct View {
    pub context: EbpfWatcherConfig,
}

impl View {
    pub fn new(context: EbpfWatcherConfig) -> View {
        View { context }
    }
}

/// What the user selected
#[derive(Default)]
pub struct UiState {
    /// The chart slot shown alone
    pub zoom: Option<usize>,
    /// First flow shown
    pub scroll: usize,
    /// The group table lists the rings of each group
    pub expanded: bool,
}

/// Where the last frame put the parts that take mouse clicks
#[derive(Default)]
pub struct Areas {
    /// Chart slots on screen and their areas
    pub slots: Vec<(usize, Rect)>,
}

impl UiState {
    /// Handles a key, returns whether to quit
    pub fn on_key(&mut self, code: KeyCode, charts: usize, flows: usize) -> bool {
        match code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => self.zoom = None,
            KeyCode::Char('e') => self.expanded = !self.expanded,
            KeyCode::Char(key @ '1'..='4') => {
                let slot = key as usize - '1' as usize;
                if slot < charts {
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

    let [main, footer] = Layout::vertical([Constraint::Min(8), Constraint::Length(1)]).areas(area);
    let [left, right] = Layout::horizontal([
        Constraint::Length(LEFT_WIDTH.min(area.width / 3)),
        Constraint::Min(0),
    ])
    .spacing(1)
    .areas(main);

    // A zoomed chart takes the place of the flows as well
    let shown: Vec<usize> = match ui.zoom {
        Some(slot) => vec![slot],
        None => (0..model.charts.len()).collect(),
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
    let window = view.context.observation_window;
    for (slot, rect) in &slots {
        let mut rect = *rect;
        // The events chart shows the dropped share below
        if *slot == 0 && rect.height >= 10 {
            let [above, drops] =
                Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(rect);
            render_drops(frame, model, drops);
            rect = above;
        }
        let chart = graph::chart(&model.charts[*slot], slot + 1, window);
        frame.render_widget(chart, rect);
    }

    status::render(frame, model, view, ui.expanded, left);

    let window = match view.context.observation_window {
        Some(window) => format!("last {}", format::axis_time(window)),
        None => "whole run".to_string(),
    };
    let zoom = match ui.zoom {
        Some(_) => "Esc back",
        None => "1-4 zoom",
    };
    let keys = format!(
        " q quit  {zoom}  e rings  \u{2191}\u{2193} scroll flows   charts: {window}, K M G = 10^3 10^6 10^9"
    );
    frame.render_widget(
        Paragraph::new(keys).style(Style::default().add_modifier(Modifier::DIM)),
        footer,
    );

    Areas { slots }
}

/// The dropped share of the events per tick as a red sparkline
fn render_drops(frame: &mut Frame, model: &Model, area: Rect) {
    let red = Style::default().fg(Color::Red);
    let label = format!(" drop {:.2}% ", model.drop_percent());
    let [label_area, spark_area] =
        Layout::horizontal([Constraint::Length(label.len() as u16), Constraint::Min(0)])
            .areas(area);
    frame.render_widget(Paragraph::new(label).style(red), label_area);
    let history = &model.drop_history;
    let shown = &history[history.len().saturating_sub(spark_area.width as usize)..];
    // A drop-free run stays a flat line instead of a full bar
    let max = shown.iter().copied().max().unwrap_or(0).max(1);
    frame.render_widget(
        Sparkline::default().data(shown).max(max).style(red),
        spark_area,
    );
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
        aggregated_slot, slot, suppressed_slot, RB_COUNT, RB_CUBIC, RB_SOCK_SEND,
        RB_TCP4_DRIVER_INGRESS, RB_TCP4_EGRESS, RB_TCP4_INGRESS, RB_TCP6_EGRESS, RB_TCP6_INGRESS,
        RB_TCP_EVENTS, STATS_LEN, STATS_STATE_ERR, STAT_DROPPED, STAT_HANDLED,
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
    fn screen_shows_context_health_charts_and_flows() {
        let model = busy_model(&TC_RINGS, None);
        let view = View::new(context(&TC_RINGS));
        let flows = [Flow {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            sport: 5201,
            dport: 40000,
        }];
        let (lines, areas) = screen(160, 45, &model, &view, &UiState::default(), &flows);
        assert!(contains(&lines, "TCBee 00:00:01"));
        assert!(contains(&lines, "/data/run1"));
        assert!(contains(&lines, "eth0  8 CPUs"));
        assert!(contains(&lines, "rec/s            990  total 990"));
        assert!(contains(&lines, "runs/s         1.00K"));
        assert!(contains(&lines, "drops/s           10  total 10"));
        assert!(contains(&lines, "drop %         1.00%  now 1.00%"));
        assert!(contains(&lines, "disk       2.00 MB/s  2.00 MB"));
        assert!(contains(&lines, "headers      1.00K    990     10 agg 0%"));
        assert!(contains(&lines, "- BBR: tcp_bbr is not loaded"));
        assert!(contains(&lines, " q quit  1-4 zoom  e rings"));
        assert!(contains(&lines, "Events"));
        assert!(contains(&lines, "Tracking 1 Flows"));
        assert!(contains(&lines, "10.0.0.2"));
        assert!(contains(&lines, "tcp_bbr is not loaded"));
        assert_eq!(areas.slots.len(), 2);
        assert!(contains(
            &lines,
            "1 Events (rec/s) \u{25a0} rec \u{25a0} drop"
        ));
        assert!(contains(&lines, "2 Headers (pps) \u{25a0} in \u{25a0} out"));
        assert!(contains(&lines, " drop 1.00% "));
    }

    #[test]
    fn charts_follow_the_active_rings() {
        let all = Model::new(&(0..RB_COUNT).collect::<Vec<_>>(), None);
        let titles: Vec<&str> = all.charts.iter().map(|chart| chart.title).collect();
        assert_eq!(
            titles,
            ["Events", "Headers", "Socket hooks", "CC internals"]
        );
        let labels: Vec<&str> = all.charts[1].series.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["in", "out", "drv in", "drv out"]);
        let tc = Model::new(&TC_RINGS, None);
        assert_eq!(tc.charts.len(), 2);
        assert_eq!(tc.charts[1].series.len(), 2);
        assert_eq!(Model::new(&[], None).charts.len(), 1);
    }

    #[test]
    fn group_charts_show_runs_per_series() {
        let model = busy_model(&TC_RINGS, None);
        let headers = &model.charts[1];
        let last = |s: usize| *headers.series[s].history.points().last().unwrap();
        assert_eq!(last(0), (1.5, 600.0));
        assert_eq!(last(1), (1.5, 400.0));
        assert_eq!(model.drop_history, [0, 100]);
        assert_eq!(model.drop_percent(), 1.0);
    }

    #[test]
    fn group_table_expands_into_rings() {
        let rings = [
            RB_TCP4_INGRESS,
            RB_TCP4_EGRESS,
            RB_SOCK_SEND,
            RB_CUBIC,
            RB_TCP_EVENTS,
        ];
        let mut model = Model::new(&rings, None);
        for (tick, count) in [(1, 0), (2, 100), (3, 300)] {
            let values = [
                (slot(RB_TCP4_INGRESS, STAT_HANDLED), count),
                (aggregated_slot(RB_TCP4_INGRESS), count / 2),
                (slot(RB_TCP_EVENTS, STAT_HANDLED), count),
                (STATS_STATE_ERR, 3),
            ];
            model.update(snapshot(&values), 0, Duration::from_secs(tick));
            model.record_history();
        }
        let view = View::new(context(&[]));
        let mut ui = UiState::default();
        let (lines, _) = screen(160, 45, &model, &view, &ui, &[]);
        assert!(contains(&lines, "headers        200    200      0 agg 50%"));
        // TCP events have no chart, so a sparkline
        assert!(contains(
            &lines,
            "tcp_ev         200    200      0 \u{2581}\u{2584}\u{2588}"
        ));
        assert!(contains(&lines, "! 3 state_err"));
        assert!(!contains(&lines, "tc v4 in"));
        ui.on_key(KeyCode::Char('e'), model.charts.len(), 0);
        let (lines, _) = screen(160, 45, &model, &view, &ui, &[]);
        assert!(contains(&lines, " tc v4 in      200    200      0 agg 50%"));
        assert!(contains(&lines, " tc v4 out       0      0      0 agg 0%"));
        assert!(contains(&lines, " tcp_events    200"));
    }

    #[test]
    fn on_change_shows_the_suppressed_share() {
        let mut model = Model::new(&[RB_SOCK_SEND], None);
        model.update(snapshot(&[]), 0, Duration::from_secs(1));
        let values = [
            (slot(RB_SOCK_SEND, STAT_HANDLED), 10),
            (suppressed_slot(RB_SOCK_SEND), 30),
        ];
        model.update(snapshot(&values), 0, Duration::from_secs(2));
        let mut context = context(&[]);
        context.on_change = true;
        let (lines, _) = screen(
            160,
            45,
            &model,
            &View::new(context),
            &UiState::default(),
            &[],
        );
        assert!(contains(
            &lines,
            "sock            40     10      0 supp 75%"
        ));
        assert!(contains(&lines, "on change"));
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
        ui.on_key(KeyCode::Char('2'), model.charts.len(), 0);
        assert_eq!(ui.zoom, Some(1));
        let (lines, areas) = screen(160, 45, &model, &view, &ui, &[]);
        assert_eq!(areas.slots.len(), 1);
        assert_eq!(areas.slots[0].0, 1);
        assert!(!contains(&lines, "Tracking"));
        // No third slot to zoom, Esc returns, q quits
        ui.on_key(KeyCode::Char('3'), model.charts.len(), 0);
        assert_eq!(ui.zoom, Some(1));
        assert!(!ui.on_key(KeyCode::Esc, model.charts.len(), 0));
        assert_eq!(ui.zoom, None);
        assert!(ui.on_key(KeyCode::Char('q'), model.charts.len(), 0));
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
