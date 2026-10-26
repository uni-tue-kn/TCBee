//! The terminal UI: renders a model into a frame and reacts to keys and the mouse

use ratatui::{
    crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind},
    layout::{Constraint, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline, TableState,
        Wrap,
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
        flow_tracker::{flow_table, Flows},
        history::{window_name, window_step, Span, WINDOWS},
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
pub struct UiState {
    /// The chart slot shown alone
    pub zoom: Option<usize>,
    /// The charts show the whole run, not the window
    pub whole: bool,
    /// Step of the window length in `WINDOWS`
    pub window: usize,
    /// The flow the table highlights
    pub selected: usize,
    /// First flow row shown
    pub offset: usize,
    /// The group table lists the rings of each group
    pub expanded: bool,
}

/// Where the last frame put the parts that take mouse clicks
#[derive(Default)]
pub struct Areas {
    /// Chart slots on screen and their areas
    pub slots: Vec<(usize, Rect)>,
    /// Charts that keys 1-4 can zoom
    pub charts: usize,
    /// The rows of the flow table below its header
    pub flow_rows: Rect,
}

/// Flow rows the mouse wheel scrolls
const WHEEL_ROWS: usize = 3;

/// The first of `rows` visible rows when `selected` of `len` rows must be visible: as close
/// to `offset` as possible, without empty rows after the last one
pub fn follow(offset: usize, selected: usize, rows: usize, len: usize) -> usize {
    let offset = offset
        .min(selected)
        .max((selected + 1).saturating_sub(rows.max(1)));
    offset.min(len.saturating_sub(rows))
}

impl Default for UiState {
    fn default() -> UiState {
        UiState::new(None)
    }
}

impl UiState {
    /// Charts of the whole run, or with `window` seconds of the window step at least as long
    pub fn new(window: Option<f64>) -> UiState {
        UiState {
            zoom: None,
            whole: window.is_none(),
            // One minute until chosen
            window: window_step(window.unwrap_or(60.0)),
            selected: 0,
            offset: 0,
            expanded: false,
        }
    }

    /// What the charts show
    pub fn span(&self) -> Span {
        match self.whole {
            true => Span::Whole,
            false => Span::Last(WINDOWS[self.window]),
        }
    }

    /// Handles a key, returns whether to quit
    pub fn on_key(&mut self, code: KeyCode, areas: &Areas, flows: usize) -> bool {
        let page = (areas.flow_rows.height as usize).max(1);
        let last = flows.saturating_sub(1);
        match code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => self.zoom = None,
            KeyCode::Char('e') => self.expanded = !self.expanded,
            KeyCode::Char('w') => self.whole = !self.whole,
            // Changing the length shows the window
            KeyCode::Char('+' | '=') => {
                self.window = (self.window + 1).min(WINDOWS.len() - 1);
                self.whole = false;
            }
            KeyCode::Char('-') => {
                self.window = self.window.saturating_sub(1);
                self.whole = false;
            }
            KeyCode::Char(key @ '1'..='4') => {
                let slot = key as usize - '1' as usize;
                if slot < areas.charts {
                    self.zoom = Some(slot);
                }
            }
            KeyCode::Down => self.selected = (self.selected + 1).min(last),
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::PageDown => self.selected = (self.selected + page).min(last),
            KeyCode::PageUp => self.selected = self.selected.saturating_sub(page),
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = last,
            _ => {}
        }
        self.offset = follow(self.offset, self.selected, page, flows);
        false
    }

    /// Scrolls the flow rows by `rows`, the selection stays on a visible row
    fn scroll(&mut self, rows: isize, areas: &Areas, flows: usize) {
        let page = (areas.flow_rows.height as usize).max(1);
        self.offset = self
            .offset
            .saturating_add_signed(rows)
            .min(flows.saturating_sub(page));
        self.selected = self
            .selected
            .clamp(self.offset, self.offset + page - 1)
            .min(flows.saturating_sub(1));
    }

    pub fn on_mouse(&mut self, mouse: MouseEvent, areas: &Areas, flows: usize) {
        match mouse.kind {
            MouseEventKind::ScrollDown => self.scroll(WHEEL_ROWS as isize, areas, flows),
            MouseEventKind::ScrollUp => self.scroll(-(WHEEL_ROWS as isize), areas, flows),
            MouseEventKind::Down(MouseButton::Left) => {
                let at = Position::new(mouse.column, mouse.row);
                if areas.flow_rows.contains(at) {
                    let row = self.offset + (mouse.row - areas.flow_rows.y) as usize;
                    if row < flows {
                        self.selected = row;
                    }
                }
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

pub fn render(frame: &mut Frame, model: &Model, view: &View, ui: &UiState, flows: &Flows) -> Areas {
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
    let mut flow_rows = Rect::default();
    let chart_area = if ui.zoom.is_some() {
        right
    } else {
        let [charts, flow_area] = Layout::vertical([Constraint::Percentage(50); 2]).areas(right);
        flow_rows = render_flows(frame, ui, flows, flow_area);
        charts
    };
    let areas = grid(chart_area, shown.len());
    let slots: Vec<(usize, Rect)> = shown.into_iter().zip(areas).collect();
    let span = ui.span();
    for (slot, rect) in &slots {
        let mut rect = *rect;
        // The events chart shows the dropped share below
        if *slot == 0 && rect.height >= 10 {
            let [above, drops] =
                Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(rect);
            render_drops(frame, model, drops);
            rect = above;
        }
        graph::render(frame, &model.charts[*slot], slot + 1, span, rect);
    }

    status::render(frame, model, view, ui.expanded, left);

    let span = match span {
        Span::Whole => "whole run".to_string(),
        Span::Last(window) => format!("window {}", window_name(window)),
    };
    let zoom = match ui.zoom {
        Some(_) => "Esc back",
        None => "1-4 zoom",
    };
    let keys = format!(
        " q quit  {zoom}  e rings  \u{2191}\u{2193} PgUp PgDn flows   charts: {span}  w whole/window  +/- length"
    );
    frame.render_widget(
        Paragraph::new(keys).style(Style::default().add_modifier(Modifier::DIM)),
        footer,
    );

    Areas {
        slots,
        charts: model.charts.len(),
        flow_rows,
    }
}

/// Dropped share of the events that fills the drop sparkline, in hundredths of a percent
const DROP_SCALE: u64 = 100;

/// The dropped share of the events per tick as a red sparkline from 0 to 1 %
fn render_drops(frame: &mut Frame, model: &Model, area: Rect) {
    let red = Style::default().fg(Color::Red);
    let label = format!(" drop {:.2}%  0-1%: ", model.drop_percent());
    let [label_area, spark_area] =
        Layout::horizontal([Constraint::Length(label.len() as u16), Constraint::Min(0)])
            .areas(area);
    frame.render_widget(Paragraph::new(label).style(red), label_area);
    let history = &model.drop_history;
    // A fixed scale, so the bars compare between ticks; more than 1 % fills a bar
    let shown: Vec<u64> = history[history.len().saturating_sub(spark_area.width as usize)..]
        .iter()
        .map(|value| (*value).min(DROP_SCALE))
        .collect();
    frame.render_widget(
        Sparkline::default().data(&shown).max(DROP_SCALE).style(red),
        spark_area,
    );
}

/// The flow table with the selected row highlighted, returns the area of its rows
fn render_flows(frame: &mut Frame, ui: &UiState, flows: &Flows, area: Rect) -> Rect {
    let len = flows.len();
    let mut title = match len {
        0 => "Flows: none yet".to_string(),
        _ => format!("Flows: {} of {len}", ui.selected.min(len - 1) + 1),
    };
    if flows.full {
        title.push_str(" (map full, newer flows not listed)");
    }
    let block = Block::bordered().title(title);
    let inner = block.inner(area);
    // Below the header
    let rows = Rect {
        y: inner.y + 1,
        height: inner.height.saturating_sub(1),
        ..inner
    };
    let selected = ui.selected.min(len.saturating_sub(1));
    let offset = follow(ui.offset, selected, rows.height as usize, len);
    let mut state = TableState::new()
        .with_offset(offset)
        .with_selected((len > 0).then_some(selected));
    frame.render_stateful_widget(
        flow_table(flows, inner.width).block(block),
        area,
        &mut state,
    );

    // On the right border, when not all rows fit
    if len > rows.height as usize {
        let mut scrollbar = ScrollbarState::new(len.saturating_sub(rows.height as usize))
            .position(offset)
            .viewport_content_length(rows.height as usize);
        frame.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            Rect {
                y: rows.y,
                height: rows.height,
                ..area
            },
            &mut scrollbar,
        );
    }
    rows
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
    use crate::{
        stats::Snapshot,
        viz::{
            flow_owners::{
                observer,
                tests::{ep, record},
                SharedOwners,
            },
            flow_tracker::tests::flow,
        },
    };

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
        flows: &Flows,
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
    pub fn busy_model(rings: &[u32]) -> Model {
        let mut model = Model::new(rings);
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
            owners: None,
        }
    }

    /// Areas with `count` charts
    fn charts(count: usize) -> Areas {
        Areas {
            charts: count,
            ..Areas::default()
        }
    }

    fn contains(lines: &[String], text: &str) -> bool {
        lines.iter().any(|line| line.contains(text))
    }

    #[test]
    fn rates_follow_the_counters() {
        let model = busy_model(&TC_RINGS);
        assert_eq!(model.handled_rate(), 990.0);
        assert_eq!(model.dropped_rate(), 10.0);
        assert_eq!(model.ingress_rate(), 600.0);
        assert_eq!(model.egress_rate(), 400.0);
        assert_eq!(model.disk_rate(), 2_000_000.0);
        // The driver rings saw nothing
        assert_eq!(busy_model(&[RB_TCP4_DRIVER_INGRESS]).ingress_rate(), 0.0);
    }

    #[test]
    fn first_tick_has_no_rates() {
        let mut model = Model::new(&TC_RINGS);
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
        let model = busy_model(&TC_RINGS);
        let view = View::new(context(&TC_RINGS));
        let mut flows = Flows::default();
        flows.add(flow(40000));
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
        assert!(contains(&lines, "Flows: 1 of 1"));
        assert!(contains(&lines, "Local"));
        assert!(contains(&lines, "Process"));
        assert!(contains(&lines, "10.0.0.2"));
        assert!(contains(&lines, "tcp_bbr is not loaded"));
        assert_eq!(areas.slots.len(), 2);
        assert!(contains(
            &lines,
            "1 Events (rec/s) \u{25a0} rec \u{25a0} drop"
        ));
        assert!(contains(&lines, "2 Headers (pps) \u{25a0} in \u{25a0} out"));
        assert!(contains(&lines, " drop 1.00%  0-1%: "));
    }

    #[test]
    fn charts_follow_the_active_rings() {
        let all = Model::new(&(0..RB_COUNT).collect::<Vec<_>>());
        let titles: Vec<&str> = all.charts.iter().map(|chart| chart.title).collect();
        assert_eq!(
            titles,
            ["Events", "Headers", "Socket hooks", "CC internals"]
        );
        let labels: Vec<&str> = all.charts[1].series.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["in", "out", "drv in", "drv out"]);
        let tc = Model::new(&TC_RINGS);
        assert_eq!(tc.charts.len(), 2);
        assert_eq!(tc.charts[1].series.len(), 2);
        assert_eq!(Model::new(&[]).charts.len(), 1);
    }

    #[test]
    fn group_charts_show_runs_per_series() {
        let model = busy_model(&TC_RINGS);
        let headers = &model.charts[1];
        let last = |s: usize| *headers.series[s].whole.points().last().unwrap();
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
        let mut model = Model::new(&rings);
        for (tick, count) in [(1, 0), (2, 100), (3, 300)] {
            let values = [
                (slot(RB_TCP4_INGRESS, STAT_HANDLED), count),
                (aggregated_slot(RB_TCP4_INGRESS).unwrap(), count / 2),
                (slot(RB_TCP_EVENTS, STAT_HANDLED), count),
                (STATS_STATE_ERR, 3),
            ];
            model.update(snapshot(&values), 0, Duration::from_secs(tick));
            model.record_history();
        }
        let view = View::new(context(&[]));
        let mut ui = UiState::default();
        let (lines, _) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert!(contains(&lines, "headers        200    200      0 agg 50%"));
        // TCP events have no chart, so a sparkline
        assert!(contains(
            &lines,
            "tcp_ev         200    200      0 \u{2581}\u{2584}\u{2588}"
        ));
        assert!(contains(&lines, "! 3 state_err"));
        assert!(!contains(&lines, "tc v4 in"));
        ui.on_key(KeyCode::Char('e'), &charts(model.charts.len()), 0);
        let (lines, _) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert!(contains(&lines, " tc v4 in      200    200      0 agg 50%"));
        assert!(contains(&lines, " tc v4 out       0      0      0 agg 0%"));
        assert!(contains(&lines, " tcp_events    200"));
    }

    #[test]
    fn on_change_shows_the_suppressed_share() {
        let mut model = Model::new(&[RB_SOCK_SEND]);
        model.update(snapshot(&[]), 0, Duration::from_secs(1));
        let values = [
            (slot(RB_SOCK_SEND, STAT_HANDLED), 10),
            (suppressed_slot(RB_SOCK_SEND).unwrap(), 30),
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
            &Flows::default(),
        );
        assert!(contains(
            &lines,
            "sock            40     10      0 supp 75%"
        ));
        assert!(contains(&lines, "on change"));
    }

    #[test]
    fn keys_switch_between_the_whole_run_and_a_window() {
        let mut ui = UiState::new(None);
        assert_eq!(ui.span(), Span::Whole);
        ui.on_key(KeyCode::Char('w'), &charts(1), 0);
        assert_eq!(ui.span(), Span::Last(60.0));
        ui.on_key(KeyCode::Char('+'), &charts(1), 0);
        ui.on_key(KeyCode::Char('='), &charts(1), 0);
        assert_eq!(ui.span(), Span::Last(300.0));
        for _ in 0..10 {
            ui.on_key(KeyCode::Char('+'), &charts(1), 0);
        }
        assert_eq!(ui.span(), Span::Last(1800.0));
        ui.on_key(KeyCode::Char('w'), &charts(1), 0);
        assert_eq!(ui.span(), Span::Whole);
        // - shows the window again, one step shorter
        ui.on_key(KeyCode::Char('-'), &charts(1), 0);
        assert_eq!(ui.span(), Span::Last(600.0));
        assert_eq!(UiState::new(Some(45.0)).span(), Span::Last(60.0));
    }

    #[test]
    fn window_shows_the_last_seconds_at_full_resolution() {
        let mut model = Model::new(&TC_RINGS);
        // 200 s at one tick per second, 600 packets per second, a spike at 100 s
        for t in 0..=200u64 {
            let count = 600 * t + if t >= 100 { 6000 } else { 0 };
            model.update(
                snapshot(&[(slot(RB_TCP4_INGRESS, STAT_HANDLED), count)]),
                0,
                Duration::from_secs(t),
            );
            model.record_history();
        }
        let view = View::new(context(&TC_RINGS));
        let mut ui = UiState::new(Some(60.0));
        let (lines, _) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert!(contains(&lines, "charts: window 1 min"));
        // The x axis counts back from now, the spike is outside
        assert!(contains(&lines, "-1:00"));
        assert!(contains(&lines, "now"));
        assert!(contains(&lines, "\u{2502}600 \u{2502}"));
        ui.on_key(KeyCode::Char('w'), &charts(4), 0);
        let (lines, _) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert!(contains(&lines, "charts: whole run"));
        assert!(contains(&lines, "3:20"));
        assert!(contains(&lines, "6.60K\u{2502}"));
        // Every point of the window, the spike in a longer one
        let headers = &model.charts[1].series[0];
        assert_eq!(headers.points(Span::Last(30.0), 200.0).len(), 31);
        let points = headers.points(Span::Last(120.0), 200.0);
        assert_eq!(points.iter().map(|(_, y)| *y).fold(0.0, f64::max), 6600.0);
    }

    #[test]
    fn drop_sparkline_has_a_fixed_scale() {
        let mut model = Model::new(&TC_RINGS);
        // 0.5 % of the events dropped, then 3 %
        for (t, dropped) in [(0, 0), (1, 5), (2, 35)] {
            let values = [
                (slot(RB_TCP4_INGRESS, STAT_HANDLED), 1000 * t - dropped),
                (slot(RB_TCP4_INGRESS, STAT_DROPPED), dropped),
            ];
            model.update(snapshot(&values), 0, Duration::from_secs(t));
            model.record_history();
        }
        assert_eq!(model.drop_history, [0, 50, 300]);
        let view = View::new(context(&TC_RINGS));
        let (lines, _) = screen(
            160,
            45,
            &model,
            &view,
            &UiState::default(),
            &Flows::default(),
        );
        // Half a bar, then a full one for more than 1 %
        assert!(contains(&lines, " drop 3.00%  0-1%:  \u{2584}\u{2588}"));
    }

    #[test]
    fn legends_fit_narrow_charts() {
        let model = Model::new(&(0..RB_COUNT).collect::<Vec<_>>());
        let view = View::new(context(&[]));
        for width in [160, 140, 125] {
            let (lines, areas) = screen(
                width,
                45,
                &model,
                &view,
                &UiState::default(),
                &Flows::default(),
            );
            let (_, sock) = areas.slots[2];
            let title: String = lines[sock.y as usize]
                .chars()
                .skip(sock.x as usize)
                .take(sock.width as usize)
                .collect();
            assert!(
                title.starts_with("\u{250c}3 Socket hooks (runs/s)"),
                "{title}"
            );
            // Every series keeps its colour square, the border shows after the legend
            assert_eq!(title.matches('\u{25a0}').count(), 4, "{title}");
            assert!(title.ends_with("\u{2500}\u{2510}"), "{title}");
        }
    }

    /// `count` flows with ports from 1
    fn many_flows(count: u16) -> Flows {
        let mut flows = Flows::default();
        for port in 1..=count {
            flows.add(flow(port));
        }
        flows
    }

    /// The ports of the flow rows on screen
    fn flow_rows(lines: &[String], areas: &Areas) -> Vec<u16> {
        let rows = areas.flow_rows;
        (rows.y..rows.y + rows.height)
            .filter_map(|y| {
                let row: String = lines[y as usize].chars().skip(rows.x as usize).collect();
                row.split_whitespace()
                    .nth(4)
                    .and_then(|port| port.parse().ok())
            })
            .collect()
    }

    #[test]
    fn keys_move_the_flow_selection_and_the_view_follows() {
        let model = busy_model(&TC_RINGS);
        let view = View::new(context(&TC_RINGS));
        let flows = many_flows(60);
        let mut ui = UiState::default();
        let (lines, areas) = screen(160, 45, &model, &view, &ui, &flows);
        let page = areas.flow_rows.height as usize;
        assert!(page > 5 && page < 60);
        let ports = flow_rows(&lines, &areas);
        assert_eq!(ports, (1..=page as u16).collect::<Vec<_>>());
        assert!(contains(&lines, "Flows: 1 of 60"));

        ui.on_key(KeyCode::Down, &areas, 60);
        ui.on_key(KeyCode::Down, &areas, 60);
        assert_eq!((ui.selected, ui.offset), (2, 0));
        ui.on_key(KeyCode::PageDown, &areas, 60);
        assert_eq!(ui.selected, 2 + page);
        // The selection is the last visible row
        assert_eq!(ui.offset, 3);
        let (lines, _) = screen(160, 45, &model, &view, &ui, &flows);
        assert!(contains(&lines, &format!("Flows: {} of 60", 3 + page)));
        ui.on_key(KeyCode::End, &areas, 60);
        assert_eq!((ui.selected, ui.offset), (59, 60 - page));
        // Down at the end stays there
        ui.on_key(KeyCode::Down, &areas, 60);
        assert_eq!((ui.selected, ui.offset), (59, 60 - page));
        let (lines, _) = screen(160, 45, &model, &view, &ui, &flows);
        let ports = flow_rows(&lines, &areas);
        assert_eq!(*ports.last().unwrap(), 60);
        ui.on_key(KeyCode::PageUp, &areas, 60);
        assert_eq!((ui.selected, ui.offset), (59 - page, 59 - page));
        ui.on_key(KeyCode::Home, &areas, 60);
        assert_eq!((ui.selected, ui.offset), (0, 0));
        ui.on_key(KeyCode::Up, &areas, 60);
        assert_eq!((ui.selected, ui.offset), (0, 0));
    }

    #[test]
    fn wheel_scrolls_rows_and_never_past_the_end() {
        let model = busy_model(&TC_RINGS);
        let view = View::new(context(&TC_RINGS));
        let flows = many_flows(30);
        let mut ui = UiState::default();
        let (_, areas) = screen(160, 45, &model, &view, &ui, &flows);
        let page = areas.flow_rows.height as usize;
        let wheel = |kind| MouseEvent {
            kind,
            column: areas.flow_rows.x + 2,
            row: areas.flow_rows.y,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        };
        ui.on_mouse(wheel(MouseEventKind::ScrollDown), &areas, 30);
        assert_eq!(ui.offset, 3);
        // The selection moves along to stay visible
        assert_eq!(ui.selected, 3);
        for _ in 0..20 {
            ui.on_mouse(wheel(MouseEventKind::ScrollDown), &areas, 30);
        }
        assert_eq!(ui.offset, 30 - page);
        let (lines, _) = screen(160, 45, &model, &view, &ui, &flows);
        let ports = flow_rows(&lines, &areas);
        assert_eq!(ports.len(), page);
        assert_eq!(*ports.last().unwrap(), 30);
        // A click selects the row under the mouse
        let mut click = wheel(MouseEventKind::Down(MouseButton::Left));
        click.row += 2;
        ui.on_mouse(click, &areas, 30);
        assert_eq!(ui.selected, 30 - page + 2);
        // Fewer flows than rows never scroll
        let mut ui = UiState::default();
        ui.on_mouse(wheel(MouseEventKind::ScrollDown), &areas, 3);
        ui.on_key(KeyCode::End, &areas, 3);
        assert_eq!((ui.selected, ui.offset), (2, 0));
    }

    #[test]
    fn new_flows_do_not_move_the_rows() {
        let model = busy_model(&TC_RINGS);
        let view = View::new(context(&TC_RINGS));
        let mut flows = many_flows(5);
        let mut ui = UiState::default();
        let (_, areas) = screen(160, 45, &model, &view, &ui, &flows);
        ui.on_key(KeyCode::Down, &areas, 5);
        let before = flow_rows(&screen(160, 45, &model, &view, &ui, &flows).0, &areas);
        // A flow seen again and new ones come in
        flows.add(flow(2));
        flows.add(flow(9));
        flows.add(flow(7));
        flows.full = true;
        let (lines, _) = screen(160, 45, &model, &view, &ui, &flows);
        let after = flow_rows(&lines, &areas);
        assert_eq!(after[..5], before[..]);
        assert_eq!(after[5..], [9, 7]);
        assert!(contains(
            &lines,
            "Flows: 2 of 7 (map full, newer flows not listed)"
        ));
        assert_eq!(follow(0, 0, 10, 0), 0);
    }

    #[test]
    fn flow_table_shows_the_local_side_and_the_process() {
        let model = busy_model(&TC_RINGS);
        let view = View::new(context(&TC_RINGS));
        let mut flows = Flows::default();
        flows.add(flow(40000));
        flows.add(flow(22));
        let owners = SharedOwners::default();
        let mut observe = observer(owners.clone());
        observe(&record(
            ep("10.0.0.2:40000"),
            ep("10.0.0.1:5201"),
            "iperf3",
            812,
            1,
        ));
        observe(&record(
            ep("10.0.0.1:5201"),
            ep("10.0.0.2:22"),
            "sshd",
            90,
            2,
        ));
        flows.find_owners(&owners.lock().unwrap());
        flows.add(flow(9));
        let (lines, areas) = screen(160, 45, &model, &view, &UiState::default(), &flows);
        let rows: Vec<String> = (0..3)
            .map(|i| {
                let row = &lines[(areas.flow_rows.y + i) as usize];
                let rows = areas.flow_rows;
                row.chars()
                    .skip(rows.x as usize)
                    .take(rows.width as usize)
                    .collect::<String>()
            })
            .map(|row| row.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        assert_eq!(rows[0], "10.0.0.2 40000 iperf3[812] 10.0.0.1 5201");
        assert_eq!(rows[1], "10.0.0.1 5201 svc sshd[90] 10.0.0.2 22");
        // Without an owner, the map's order and no process
        assert_eq!(rows[2], "10.0.0.1 5201 ? 10.0.0.2 9");
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
        let model = busy_model(&TC_RINGS);
        let view = View::new(context(&TC_RINGS));
        // No panic on a tiny terminal
        screen(1, 1, &model, &view, &UiState::default(), &Flows::default());
        for (width, height) in [(59, 45), (160, 15), (60, 16)] {
            let (lines, areas) = screen(
                width,
                height,
                &model,
                &view,
                &UiState::default(),
                &Flows::default(),
            );
            let small = width < MIN_WIDTH || height < MIN_HEIGHT;
            assert_eq!(contains(&lines, "Terminal too small"), small);
            assert_eq!(areas.slots.is_empty(), small);
        }
    }

    #[test]
    fn zoom_shows_one_chart() {
        let model = busy_model(&TC_RINGS);
        let view = View::new(context(&TC_RINGS));
        let mut ui = UiState::default();
        ui.on_key(KeyCode::Char('2'), &charts(model.charts.len()), 0);
        assert_eq!(ui.zoom, Some(1));
        let (lines, areas) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert_eq!(areas.slots.len(), 1);
        assert_eq!(areas.slots[0].0, 1);
        assert!(!contains(&lines, "Tracking"));
        // No third slot to zoom, Esc returns, q quits
        ui.on_key(KeyCode::Char('3'), &charts(model.charts.len()), 0);
        assert_eq!(ui.zoom, Some(1));
        assert!(!ui.on_key(KeyCode::Esc, &charts(model.charts.len()), 0));
        assert_eq!(ui.zoom, None);
        assert!(ui.on_key(KeyCode::Char('q'), &charts(model.charts.len()), 0));
    }

    #[test]
    fn clicks_zoom_the_chart_under_the_mouse() {
        let model = busy_model(&TC_RINGS);
        let view = View::new(context(&TC_RINGS));
        let mut ui = UiState::default();
        let (_, areas) = screen(160, 45, &model, &view, &ui, &Flows::default());
        let (slot, area) = areas.slots[1];
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: area.x + 1,
            row: area.y + 1,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        };
        ui.on_mouse(click, &areas, 0);
        assert_eq!(ui.zoom, Some(slot));
        let (_, areas) = screen(160, 45, &model, &view, &ui, &Flows::default());
        ui.on_mouse(click, &areas, 0);
        assert_eq!(ui.zoom, None);
    }
}
