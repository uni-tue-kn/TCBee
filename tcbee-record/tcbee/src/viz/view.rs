//! The terminal UI: renders a model into a frame and reacts to keys and the mouse

use std::time::Duration;

use ratatui::{
    crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind},
    layout::{Constraint, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{self, Line},
    widgets::{
        Block, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, TableState, Wrap,
    },
    Frame,
};

use crate::viz::{
    components::{graph, status},
    context::RunContext,
    flow_tracker::{flow_table, Flows},
    format,
    history::{window_name, window_step, window_steps, Span, WINDOWS},
    layout::{grid, Fit, MIN_HEIGHT, MIN_WIDTH},
    model::Model,
};

/// What the user selected
pub struct UiState {
    /// The chart slot shown alone
    pub zoom: Option<usize>,
    /// The charts show the whole run, not the window
    pub whole: bool,
    /// Step of the window length in `WINDOWS`
    pub window: usize,
    /// Window steps the full-resolution history covers at the update period
    pub steps: usize,
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
    /// The first flow row the frame showed
    pub flow_offset: usize,
}

/// Update period the UI state assumes unless told
pub const DEFAULT_TICK: Duration = Duration::from_millis(100);

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
        UiState::new(None, DEFAULT_TICK)
    }
}

impl UiState {
    /// Charts of the whole run, or with `window` seconds of the window step at least as long,
    /// updated every `tick`
    pub fn new(window: Option<f64>, tick: Duration) -> UiState {
        let steps = window_steps(tick);
        UiState {
            zoom: None,
            whole: window.is_none(),
            // One minute until chosen
            window: window_step(window.unwrap_or(60.0), steps),
            steps,
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
        self.sync(areas, flows);
        let page = (areas.flow_rows.height as usize).max(1);
        let last = flows.saturating_sub(1);
        match code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => self.zoom = None,
            KeyCode::Char('e') => self.expanded = !self.expanded,
            KeyCode::Char('w') => self.whole = !self.whole,
            // Changing the length shows the window
            KeyCode::Char('+' | '=') => {
                self.window = (self.window + 1).min(self.steps - 1);
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

    /// Starts from the rows the last frame showed, if it showed the flows: a resize or a zoom
    /// moved them
    fn sync(&mut self, areas: &Areas, flows: usize) {
        if areas.flow_rows.height > 0 {
            self.offset = areas.flow_offset;
        }
        self.selected = self.selected.min(flows.saturating_sub(1));
    }

    /// Scrolls the flow rows by `rows`, the selection stays on a visible row
    fn scroll(&mut self, rows: isize, areas: &Areas, flows: usize) {
        // Nothing to scroll while the table is hidden (a zoomed chart, a narrow terminal)
        if areas.flow_rows.height == 0 {
            return;
        }
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
        self.sync(areas, flows);
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

pub fn render(
    frame: &mut Frame,
    model: &Model,
    context: &RunContext,
    ui: &UiState,
    flows: &Flows,
) -> Areas {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let hint = format!(
            "Terminal too small, needs {MIN_WIDTH}x{MIN_HEIGHT}. Recording goes on, q quits."
        );
        frame.render_widget(Paragraph::new(hint).wrap(Wrap { trim: true }), area);
        return Areas::default();
    }

    let fit = Fit::of(area);
    let charts = model.charts.len().min(fit.charts());
    let [main, footer] = Layout::vertical([Constraint::Min(8), Constraint::Length(1)]).areas(area);
    let left_width = fit.left_width(area.width);
    let [left, right] = Layout::horizontal([Constraint::Length(left_width), Constraint::Min(0)])
        .spacing(1)
        .areas(main);

    // A zoomed chart takes the place of the flows as well
    let zoom = ui.zoom.filter(|slot| *slot < charts);
    let shown: Vec<usize> = match zoom {
        Some(slot) => vec![slot],
        None => (0..charts).collect(),
    };
    let (mut flow_rows, mut flow_offset) = (Rect::default(), 0);
    let chart_area = if zoom.is_some() {
        right
    } else if charts == 0 {
        if right.width > 0 {
            (flow_rows, flow_offset) = render_flows(frame, ui, flows, right);
        }
        Rect::default()
    } else {
        let [charts, flow_area] = Layout::vertical([Constraint::Percentage(50); 2]).areas(right);
        (flow_rows, flow_offset) = render_flows(frame, ui, flows, flow_area);
        charts
    };
    let areas = grid(chart_area, shown.len());
    let slots: Vec<(usize, Rect)> = shown.into_iter().zip(areas).collect();
    let span = ui.span();
    for (slot, rect) in &slots {
        // The events chart shows the dropped share in its bottom border
        let bottom = (*slot == 0).then(|| drop_line(model, rect.width));
        graph::render(frame, &model.charts[*slot], slot + 1, span, bottom, *rect);
    }

    status::render(frame, model, context, ui.expanded, fit, left);

    let span = match span {
        Span::Whole => "whole run".to_string(),
        // Faster updates make the full-resolution history cover less
        Span::Last(window) if ui.steps < WINDOWS.len() && ui.window == ui.steps - 1 => {
            format!(
                "window {} (longest at this update rate)",
                window_name(window)
            )
        }
        Span::Last(window) => format!("window {}", window_name(window)),
    };
    let mut keys = vec!["q quit".to_string()];
    match (zoom, charts) {
        (Some(_), _) => keys.push("Esc back".to_string()),
        (None, 0) => {}
        (None, 1) => keys.push("1 zoom".to_string()),
        (None, charts) => keys.push(format!("1-{charts} zoom")),
    }
    keys.push("e rings".to_string());
    keys.push("\u{2191}\u{2193} PgUp PgDn flows".to_string());
    if charts > 0 {
        keys.push(format!("charts: {span}"));
        keys.push("w whole/window".to_string());
        keys.push("+/- length".to_string());
    }
    // As many as fit
    let mut line = String::new();
    for key in keys {
        if line.chars().count() + key.chars().count() + 2 > footer.width as usize {
            break;
        }
        line.push_str("  ");
        line.push_str(&key);
    }
    let keys = line;
    frame.render_widget(
        Paragraph::new(keys).style(Style::default().add_modifier(Modifier::DIM)),
        footer,
    );

    Areas {
        slots,
        charts,
        flow_rows,
        flow_offset,
    }
}

/// Dropped share of the events that fills the drop sparkline, in hundredths of a percent
const DROP_SCALE: u64 = 100;

/// Cells a drop line leaves of the bottom border of a chart: the corners and some border
const DROP_LINE_MARGIN: usize = 6;

/// The dropped share of the events now and per tick as a red sparkline from 0 to 1 %, for the
/// bottom border of a chart `width` cells wide
fn drop_line(model: &Model, width: u16) -> Line<'static> {
    let label = format!(" drop {:.2}% ", model.tick.drop_percent());
    let scale = " 0\u{2013}1% ";
    let room = (width as usize).saturating_sub(DROP_LINE_MARGIN + label.len() + scale.len());
    let history: Vec<u64> = model.drop_history.iter().copied().collect();
    // A fixed scale, so the bars compare between ticks; more than 1 % fills a bar
    let spark = format::spark_fixed(&history, DROP_SCALE, room);
    let mut spans = vec![text::Span::raw(label)];
    if !spark.is_empty() {
        spans.push(text::Span::raw(spark));
        spans.push(text::Span::raw(scale));
    }
    Line::from(spans).style(Style::default().fg(Color::Red))
}

/// The flow table with the selected row highlighted, returns the area of its rows and the
/// first row shown
fn render_flows(frame: &mut Frame, ui: &UiState, flows: &Flows, area: Rect) -> (Rect, usize) {
    let len = flows.len();
    let mut title = match len {
        0 => "Flows: none yet".to_string(),
        _ => format!("Flows: {} of {len}", ui.selected.min(len - 1) + 1),
    };
    if flows.full {
        title.push_str(" (map full, newer flows not listed)");
    }
    let block = Block::bordered().title(status::bold_title(title));
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
    (rows, offset)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tcbee_common::stats::{
        aggregated_slot, slot, suppressed_slot, RB_COUNT, RB_CUBIC, RB_SOCK_SEND, RB_TCP4_EGRESS,
        RB_TCP4_INGRESS, RB_TCP_EVENTS, STATS_STATE_ERR, STAT_DROPPED, STAT_HANDLED,
    };

    use super::*;
    use crate::viz::{
        flow_owners::{observer, SharedOwners},
        test_support::{
            busy_model, contains, context, ep, flow, many_flows, record, row, screen, snapshot,
            TC_RINGS,
        },
    };

    /// Areas with `count` charts
    fn charts(count: usize) -> Areas {
        Areas {
            charts: count,
            ..Areas::default()
        }
    }

    #[test]
    fn screen_shows_context_health_charts_and_flows() {
        let model = busy_model(&TC_RINGS);
        let view = context(&TC_RINGS);
        let mut flows = Flows::default();
        flows.add(flow(40000));
        let (lines, areas) = screen(160, 45, &model, &view, &UiState::default(), &flows);
        assert!(contains(&lines, "TCBee  00:00:01"));
        assert!(contains(&lines, "/data/run1"));
        assert!(contains(&lines, "eth0 \u{b7} 8 CPUs"));
        // Every value of the health block below its column, now and since the start
        assert!(contains(&lines, "\u{250c} Health "));
        assert!(contains(&lines, " now \u{2500} total \u{2510}"));
        assert_eq!(row(&lines, "records/s"), ["records/s", "990", "990"]);
        assert_eq!(row(&lines, "drops/s"), ["drops/s", "10", "10"]);
        assert_eq!(row(&lines, "drop"), ["drop", "%", "1.00%", "1.00%"]);
        assert_eq!(row(&lines, "disk"), ["disk", "2.00", "MB/s", "2.00", "MB"]);
        // The cell after `text` on the line of `name`
        let end = |name: &str, text: &str| {
            let line = lines.iter().find(|line| line.contains(name)).unwrap();
            line[..line.find(text).unwrap()].chars().count() + text.chars().count()
        };
        assert_eq!(end("Health", "total"), end("records/s", "990 \u{2502}") - 2);
        assert_eq!(end("Health", "total"), end("disk", "MB \u{2502}") - 2);
        // The runs only differ from the records on change
        assert!(!contains(&lines, "\u{2502} runs/s"));
        // The groups with their records and drops, the headers with their aggregated share
        assert!(contains(&lines, "\u{250c} Probe groups "));
        assert!(contains(&lines, " rec/s  drops \u{2510}"));
        assert_eq!(row(&lines, "headers"), ["headers", "990", "10"]);
        assert!(contains(&lines, "\u{2502}   0% of pkts GSO/GRO "));
        assert!(contains(&lines, "e: show rings"));
        assert_eq!(
            row(&lines, "BBR:"),
            ["BBR:", "tcp_bbr", "is", "not", "loaded"]
        );
        assert!(contains(&lines, "  q quit  1-2 zoom  e rings"));
        assert!(contains(&lines, "Events"));
        assert!(contains(&lines, "Flows: 1 of 1"));
        assert!(contains(&lines, "Local/A"));
        assert!(contains(&lines, "Remote/B"));
        assert!(contains(&lines, "Process"));
        assert!(contains(&lines, "10.0.0.2"));
        assert!(contains(&lines, "tcp_bbr is not loaded"));
        assert_eq!(areas.slots.len(), 2);
        assert!(contains(
            &lines,
            "1 Events (rec/s) \u{25a0} rec \u{25a0} drop"
        ));
        assert!(contains(&lines, "2 Headers (pps) \u{25a0} in \u{25a0} out"));
        // The drop line sits in the bottom border of the events chart, so both charts of a row
        // are as high
        assert!(contains(
            &lines,
            " drop 1.00% \u{2581}\u{2588} 0\u{2013}1% \u{2518}"
        ));
        let (_, events) = areas.slots[0];
        let (_, headers) = areas.slots[1];
        assert_eq!(events.height, headers.height);
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
        let view = context(&[]);
        let mut ui = UiState::default();
        let (lines, _) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert_eq!(row(&lines, "headers"), ["headers", "200", "\u{b7}"]);
        assert!(contains(&lines, "50% of pkts GSO/GRO"));
        // Nothing is a dot, no sparklines next to the charts
        assert_eq!(row(&lines, "sock"), ["sock", "\u{b7}", "\u{b7}"]);
        assert_eq!(row(&lines, "tcp"), ["tcp", "events", "200", "\u{b7}"]);
        assert!(contains(&lines, "! 3 state errors"));
        assert!(!contains(&lines, "tc v4 in"));
        ui.on_key(KeyCode::Char('e'), &charts(model.charts.len()), 0);
        let (lines, _) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert_eq!(row(&lines, "tc"), ["tc", "v4", "in", "200", "\u{b7}"]);
        assert!(contains(&lines, "   tc v4 out "));
        assert_eq!(row(&lines, "tcp_events"), ["tcp_events", "200", "\u{b7}"]);
        assert!(contains(&lines, "e: hide rings"));
        // The share is the group's only
        assert_eq!(
            lines.iter().filter(|line| line.contains("GSO/GRO")).count(),
            1
        );
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
            &context,
            &UiState::default(),
            &Flows::default(),
        );
        assert_eq!(row(&lines, "sock"), ["sock", "10", "\u{b7}"]);
        assert!(contains(&lines, "\u{2502}   75% runs unchanged "));
        assert!(contains(&lines, "on change"));
        assert_eq!(row(&lines, "runs/s"), ["runs/s", "40", "40"]);
        assert_eq!(row(&lines, "records/s"), ["records/s", "10", "10"]);
    }

    #[test]
    fn keys_switch_between_the_whole_run_and_a_window() {
        let mut ui = UiState::new(None, DEFAULT_TICK);
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
        assert_eq!(
            UiState::new(Some(45.0), DEFAULT_TICK).span(),
            Span::Last(60.0)
        );
        // At 10 ms updates the window stops at 5 min and says so
        let mut fast = UiState::new(Some(3600.0), Duration::from_millis(10));
        assert_eq!(fast.span(), Span::Last(300.0));
        fast.on_key(KeyCode::Char('+'), &charts(1), 0);
        assert_eq!(fast.span(), Span::Last(300.0));
        let (lines, _) = screen(
            160,
            45,
            &busy_model(&TC_RINGS),
            &context(&TC_RINGS),
            &fast,
            &Flows::default(),
        );
        assert!(contains(
            &lines,
            "window 5 min (longest at this update rate)"
        ));
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
        let view = context(&TC_RINGS);
        let mut ui = UiState::new(Some(60.0), DEFAULT_TICK);
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
        let view = context(&TC_RINGS);
        let (lines, _) = screen(
            160,
            45,
            &model,
            &view,
            &UiState::default(),
            &Flows::default(),
        );
        // Half a bar, then a full one for more than 1 %
        assert!(contains(
            &lines,
            " drop 3.00% \u{2581}\u{2585}\u{2588} 0\u{2013}1% \u{2518}"
        ));
    }

    #[test]
    fn legends_fit_narrow_charts() {
        let model = Model::new(&(0..RB_COUNT).collect::<Vec<_>>());
        let view = context(&[]);
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
                title.starts_with("\u{250c} 3 Socket hooks (runs/s)"),
                "{title}"
            );
            // Every series keeps its colour square, the border shows after the legend
            assert_eq!(title.matches('\u{25a0}').count(), 4, "{title}");
            assert!(title.ends_with("\u{2500}\u{2510}"), "{title}");
        }
    }

    /// The ports of the flow rows on screen
    fn flow_rows(lines: &[String], areas: &Areas) -> Vec<u16> {
        let rows = areas.flow_rows;
        (rows.y..rows.y + rows.height)
            .filter_map(|y| {
                let row: String = lines[y as usize].chars().skip(rows.x as usize).collect();
                row.split_whitespace()
                    .nth(3)
                    .and_then(|port| port.parse().ok())
            })
            .collect()
    }

    /// Draws the screen and hands `key` over, as the TUI does
    fn press(ui: &mut UiState, key: KeyCode, model: &Model, context: &RunContext, flows: &Flows) {
        let (_, areas) = screen(160, 45, model, context, ui, flows);
        ui.on_key(key, &areas, flows.len());
    }

    /// Draws the screen and scrolls the flows by the wheel, as the TUI does
    fn wheel(ui: &mut UiState, kind: MouseEventKind, model: &Model, flows: &Flows) -> Areas {
        let context = context(&TC_RINGS);
        let (_, areas) = screen(160, 45, model, &context, ui, flows);
        let event = MouseEvent {
            kind,
            column: areas.flow_rows.x + 2,
            row: areas.flow_rows.y,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        };
        ui.on_mouse(event, &areas, flows.len());
        areas
    }

    #[test]
    fn keys_move_the_flow_selection_and_the_view_follows() {
        let model = busy_model(&TC_RINGS);
        let context = context(&TC_RINGS);
        let flows = many_flows(60);
        let mut ui = UiState::default();
        let (lines, areas) = screen(160, 45, &model, &context, &ui, &flows);
        let page = areas.flow_rows.height as usize;
        assert!(page > 5 && page < 60);
        let ports = flow_rows(&lines, &areas);
        assert_eq!(ports, (1..=page as u16).collect::<Vec<_>>());
        assert!(contains(&lines, "Flows: 1 of 60"));

        let mut press = |key| {
            press(&mut ui, key, &model, &context, &flows);
            (ui.selected, ui.offset)
        };
        press(KeyCode::Down);
        assert_eq!(press(KeyCode::Down), (2, 0));
        // The selection is the last visible row
        assert_eq!(press(KeyCode::PageDown), (2 + page, 3));
        assert_eq!(press(KeyCode::End), (59, 60 - page));
        // Down at the end stays there
        assert_eq!(press(KeyCode::Down), (59, 60 - page));
        assert_eq!(press(KeyCode::PageUp), (59 - page, 59 - page));
        assert_eq!(press(KeyCode::Home), (0, 0));
        assert_eq!(press(KeyCode::Up), (0, 0));
        ui.selected = 2 + page;
        let (lines, areas) = screen(160, 45, &model, &context, &ui, &flows);
        assert!(contains(&lines, &format!("Flows: {} of 60", 3 + page)));
        assert_eq!(*flow_rows(&lines, &areas).last().unwrap(), 3 + page as u16);
    }

    #[test]
    fn wheel_scrolls_rows_and_never_past_the_end() {
        let model = busy_model(&TC_RINGS);
        let context = context(&TC_RINGS);
        let flows = many_flows(30);
        let mut ui = UiState::default();
        let areas = wheel(&mut ui, MouseEventKind::ScrollDown, &model, &flows);
        let page = areas.flow_rows.height as usize;
        assert_eq!(ui.offset, 3);
        // The selection moves along to stay visible
        assert_eq!(ui.selected, 3);
        for _ in 0..20 {
            wheel(&mut ui, MouseEventKind::ScrollDown, &model, &flows);
        }
        assert_eq!(ui.offset, 30 - page);
        let (lines, areas) = screen(160, 45, &model, &context, &ui, &flows);
        let ports = flow_rows(&lines, &areas);
        assert_eq!(ports.len(), page);
        assert_eq!(*ports.last().unwrap(), 30);
        // A click selects the row under the mouse
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: areas.flow_rows.x + 2,
            row: areas.flow_rows.y + 2,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        };
        ui.on_mouse(click, &areas, 30);
        assert_eq!(ui.selected, 30 - page + 2);
        // Fewer flows than rows never scroll
        let few = many_flows(3);
        let mut ui = UiState::default();
        wheel(&mut ui, MouseEventKind::ScrollDown, &model, &few);
        press(&mut ui, KeyCode::End, &model, &context, &few);
        assert_eq!((ui.selected, ui.offset), (2, 0));
    }

    #[test]
    fn clicks_and_the_wheel_follow_the_rows_on_screen_after_a_resize() {
        let model = busy_model(&TC_RINGS);
        let context = context(&TC_RINGS);
        let flows = many_flows(60);
        let mut ui = UiState::default();
        let (_, areas) = screen(160, 45, &model, &context, &ui, &flows);
        ui.on_key(KeyCode::End, &areas, 60);
        // A smaller terminal shows fewer rows, the last ones
        let (lines, areas) = screen(160, 32, &model, &context, &ui, &flows);
        let shown = flow_rows(&lines, &areas);
        assert_eq!(*shown.last().unwrap(), 60);
        assert_eq!(areas.flow_offset, 60 - shown.len());
        let click = |row| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: areas.flow_rows.x + 2,
            row,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        };
        ui.on_mouse(click(areas.flow_rows.y), &areas, 60);
        assert_eq!(ui.selected + 1, shown[0] as usize);
        // The wheel scrolls from what is shown
        let mut wheel = click(areas.flow_rows.y);
        wheel.kind = MouseEventKind::ScrollUp;
        ui.on_mouse(wheel, &areas, 60);
        assert_eq!(ui.offset, areas.flow_offset - 3);
        // After a zoom the flows come back where they were
        ui.on_key(KeyCode::Char('1'), &areas, 60);
        let (_, zoomed) = screen(160, 32, &model, &context, &ui, &flows);
        ui.on_key(KeyCode::Esc, &zoomed, 60);
        let (lines, areas) = screen(160, 32, &model, &context, &ui, &flows);
        ui.on_mouse(click(areas.flow_rows.y), &areas, 60);
        assert_eq!(ui.selected + 1, flow_rows(&lines, &areas)[0] as usize);
    }

    #[test]
    fn new_flows_do_not_move_the_rows() {
        let model = busy_model(&TC_RINGS);
        let view = context(&TC_RINGS);
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
        let view = context(&TC_RINGS);
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
        flows.find_owners(&owners.live.lock().unwrap(), None);
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
        assert_eq!(rows[0], "10.0.0.2 40000 10.0.0.1 5201 iperf3[812]");
        assert_eq!(rows[1], "10.0.0.1 5201 svc 10.0.0.2 22 sshd[90]");
        // Without an owner, the map's order and no process
        assert_eq!(rows[2], "10.0.0.1 5201 10.0.0.2 9 ?");
        // The addresses sit together, the process comes last and gets the spare room
        let first = &lines[areas.flow_rows.y as usize];
        let row = first.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(row.contains("10.0.0.1 5201 iperf3[812]"), "{first}");
        assert!(first.contains("iperf3[812]          "), "{first}");
    }

    /// A busy run with every group, its flows and their owners
    fn every_group() -> (Model, RunContext, Flows) {
        let rings: Vec<u32> = (0..RB_COUNT).collect();
        let mut model = Model::new(&rings);
        for t in 0..20u64 {
            let values: Vec<(u32, u64)> = rings
                .iter()
                .map(|rb| (slot(*rb, STAT_HANDLED), t * t * 100 * (*rb as u64 + 1)))
                .collect();
            model.update(snapshot(&values), t * 1_000_000, Duration::from_secs(t));
            model.record_history();
        }
        let mut flows = Flows::default();
        for port in 1..=30 {
            flows.add(flow(port));
        }
        (model, context(&rings), flows)
    }

    #[test]
    fn compact_terminals_show_two_charts_and_a_narrow_column() {
        let (model, view, flows) = every_group();
        let mut ui = UiState::default();
        let (lines, areas) = screen(100, 30, &model, &view, &ui, &flows);
        assert_eq!(Fit::of(Rect::new(0, 0, 100, 30)), Fit::Compact);
        assert_eq!(areas.charts, 2);
        assert_eq!(areas.slots.len(), 2);
        assert!(contains(&lines, "1 Events"));
        assert!(contains(&lines, "2 Headers"));
        assert!(!contains(&lines, "3 Socket"));
        // The events legend still fits
        assert!(contains(
            &lines,
            "1 Events (rec/s) \u{25a0} rec \u{25a0} drop \u{2500}\u{2510}"
        ));
        // The same columns in a narrow column, no sparklines next to the charts
        assert!(contains(
            &lines,
            "\u{250c} Probe groups \u{2500}\u{2500} rec/s  drops \u{2510}"
        ));
        assert_eq!(row(&lines, "sock").len(), 3);
        assert_eq!(row(&lines, "owners").len(), 3);
        assert!(contains(&lines, "Flows: 1 of 30"));
        assert!(contains(&lines, "  q quit  1-2 zoom  e rings"));
        // Key 3 has no chart to zoom
        ui.on_key(KeyCode::Char('3'), &areas, 30);
        assert_eq!(ui.zoom, None);
        ui.on_key(KeyCode::Char('2'), &areas, 30);
        let (_, areas) = screen(100, 30, &model, &view, &ui, &flows);
        assert_eq!(areas.slots.len(), 1);
    }

    #[test]
    fn minimal_terminals_show_sparklines_instead_of_charts() {
        let (model, view, flows) = every_group();
        let (lines, areas) = screen(79, 23, &model, &view, &UiState::default(), &flows);
        assert!(areas.slots.is_empty());
        assert_eq!(areas.charts, 0);
        assert!(!contains(&lines, "1 Events"));
        // Every group gets a sparkline of the last 30 s
        assert!(contains(&lines, " rec/s  drops last 30 s \u{2510}"));
        assert!(row(&lines, "headers")[3].ends_with('\u{2588}'));
        assert!(row(&lines, "cc")[3].ends_with('\u{2588}'));
        assert!(contains(&lines, "GSO/GRO"));
        assert!(contains(&lines, "Flows: 1 of 30"));
        // A zoom from a larger terminal is not in the way
        let ui = UiState {
            zoom: Some(1),
            ..UiState::default()
        };
        let (lines, _) = screen(79, 23, &model, &view, &ui, &flows);
        assert!(contains(&lines, "Flows: 1 of 30"));
        // Too narrow for the flows next to the column
        let (lines, areas) = screen(60, 20, &model, &view, &UiState::default(), &flows);
        assert_eq!(areas.flow_rows, Rect::default());
        assert!(contains(&lines, "TCBee  00:00:19"));
    }

    #[test]
    fn small_terminals_get_a_hint() {
        let model = busy_model(&TC_RINGS);
        let view = context(&TC_RINGS);
        // No panic on a tiny terminal
        screen(1, 1, &model, &view, &UiState::default(), &Flows::default());
        for (width, height) in [(39, 45), (160, 11), (40, 12)] {
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
            // Too small for charts in any case
            assert!(areas.slots.is_empty());
        }
    }

    #[test]
    fn zoom_shows_one_chart() {
        let model = busy_model(&TC_RINGS);
        let view = context(&TC_RINGS);
        let mut ui = UiState::default();
        ui.on_key(KeyCode::Char('2'), &charts(model.charts.len()), 0);
        assert_eq!(ui.zoom, Some(1));
        let (lines, areas) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert_eq!(areas.slots.len(), 1);
        assert_eq!(areas.slots[0].0, 1);
        // The zoomed chart covers the flows
        assert!(!contains(&lines, "Flows:"));
        // No third slot to zoom, Esc returns, q quits
        ui.on_key(KeyCode::Char('3'), &charts(model.charts.len()), 0);
        assert_eq!(ui.zoom, Some(1));
        assert!(!ui.on_key(KeyCode::Esc, &charts(model.charts.len()), 0));
        assert_eq!(ui.zoom, None);
        assert!(ui.on_key(KeyCode::Char('q'), &charts(model.charts.len()), 0));
        // The zoomed events chart keeps the drop line in its border
        ui.on_key(KeyCode::Char('1'), &charts(model.charts.len()), 0);
        let (lines, _) = screen(160, 45, &model, &view, &ui, &Flows::default());
        assert!(contains(
            &lines,
            " drop 1.00% \u{2581}\u{2588} 0\u{2013}1% \u{2518}"
        ));
    }

    #[test]
    fn clicks_zoom_the_chart_under_the_mouse() {
        let model = busy_model(&TC_RINGS);
        let view = context(&TC_RINGS);
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
