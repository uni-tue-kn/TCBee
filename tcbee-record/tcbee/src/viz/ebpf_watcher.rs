use std::{
    io::{self, Write},
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::anyhow;

use crate::{
    eBPF::ebpf_runner_config::EbpfWatcherConfig,
    stats::{Snapshot, Stats},
    viz::{flow_tracker::FlowTracker, rate_watcher::RateWatcher},
};

use aya::{maps::PerCpuHashMap, Ebpf};
use log::error;
use ratatui::{
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, KeyCode},
        execute,
    },
    layout::{Constraint, Direction, Layout, Margin, Position, Rect},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, TableState,
    },
    DefaultTerminal,
};
use tcbee_common::stats::{
    slot, RB_BAD_CSUM, RB_BBR, RB_COUNT, RB_CUBIC, RB_CWND_RECV, RB_CWND_SEND,
    RB_RETRANSMIT_SYNACK, RB_SOCK_RECV, RB_SOCK_SEND, RB_TCP4_EGRESS, RB_TCP4_INGRESS,
    RB_TCP6_EGRESS, RB_TCP6_INGRESS, RB_TCP_PROBE, SLOT_TCP_BYTES_RECEIVED, SLOT_TCP_BYTES_SENT,
    STAT_ATTEMPTED, STAT_DROPPED, STAT_HANDLED,
};
use tokio_util::sync::CancellationToken;

use super::{
    components::{graph::Graph, status::Status},
    file_tracker::FileTracker,
};

pub struct EBPFWatcher {
    stats: Arc<Stats>,
    snapshot: Snapshot,
    events_drops: RateWatcher,
    events_handled: RateWatcher,
    ingress_counter: RateWatcher,
    egress_counter: RateWatcher,
    tcp_sock_send: RateWatcher,
    tcp_sock_recv: RateWatcher,
    tcp_bytes_recv: RateWatcher,
    tcp_bytes_sent: RateWatcher,
    cubic_events: RateWatcher,
    bbr_events: RateWatcher,
    tracepoint_events: RateWatcher,
    flow_tracker: FlowTracker,
    update_period: u128,
    token: CancellationToken,
    terminal: Option<DefaultTerminal>,
    config: EbpfWatcherConfig,
}

//TODO: Monitor packet rate vs TCP packet rate?
impl EBPFWatcher {
    pub fn new(
        ebpf: &mut Ebpf,
        stats: Arc<Stats>,
        update_period: u128,
        token: CancellationToken,
        config: EbpfWatcherConfig,
        do_tui: bool,
    ) -> anyhow::Result<EBPFWatcher> {
        let all = |stat: u32| (0..RB_COUNT).map(|rb| slot(rb, stat)).collect::<Vec<u32>>();
        let attempts = |rbs: &[u32]| {
            rbs.iter()
                .map(|rb| slot(*rb, STAT_ATTEMPTED))
                .collect::<Vec<u32>>()
        };

        let events_drops = RateWatcher::new(all(STAT_DROPPED), "Events/s");
        let events_handled = RateWatcher::new(all(STAT_HANDLED), "Events/s");
        let ingress_counter =
            RateWatcher::new(attempts(&[RB_TCP4_INGRESS, RB_TCP6_INGRESS]), "pps");
        let egress_counter = RateWatcher::new(attempts(&[RB_TCP4_EGRESS, RB_TCP6_EGRESS]), "pps");
        let tcp_sock_send = RateWatcher::new(attempts(&[RB_SOCK_SEND, RB_CWND_SEND]), "Calls/s");
        let tcp_sock_recv = RateWatcher::new(attempts(&[RB_SOCK_RECV, RB_CWND_RECV]), "Calls/s");
        let tcp_bytes_recv = RateWatcher::new(vec![SLOT_TCP_BYTES_RECEIVED], "Bytes/s");
        let tcp_bytes_sent = RateWatcher::new(vec![SLOT_TCP_BYTES_SENT], "Bytes/s");
        let cubic_events = RateWatcher::new(attempts(&[RB_CUBIC]), "Calls/s");
        let bbr_events = RateWatcher::new(attempts(&[RB_BBR]), "Calls/s");
        let tracepoint_events = RateWatcher::new(
            attempts(&[RB_TCP_PROBE, RB_RETRANSMIT_SYNACK, RB_BAD_CSUM]),
            "Calls/s",
        );

        let flow_tracker = FlowTracker::new(PerCpuHashMap::try_from(
            ebpf.take_map("FLOWS")
                .ok_or_else(|| anyhow!("Could not find FLOWS map!"))?,
        )?);

        let terminal: Option<DefaultTerminal> = match do_tui {
            true => {
                let term = ratatui::init();
                execute!(io::stdout(), EnableMouseCapture)?;
                Some(term)
            }
            false => None,
        };

        Ok(EBPFWatcher {
            stats,
            snapshot: Snapshot::default(),
            events_drops,
            events_handled,
            ingress_counter,
            egress_counter,
            tcp_sock_send,
            tcp_sock_recv,
            tcp_bytes_sent,
            tcp_bytes_recv,
            cubic_events,
            bbr_events,
            tracepoint_events,
            flow_tracker,
            update_period,
            token,
            terminal,
            config,
        })
    }

    fn update_snapshot(&mut self) {
        match self.stats.snapshot() {
            Ok(snapshot) => self.snapshot = snapshot,
            Err(err) => error!("Failed to read event counters: {}", err),
        }
    }

    pub fn run(&mut self) {
        if self.terminal.is_some() {
            self.run_tui();
        } else {
            self.run_no_tui();
        }
    }

    fn run_no_tui(&mut self) {
        // To calculate rate over multiple iterations
        let application_start = Instant::now();
        let mut last_loop: Duration = Duration::default();

        while !self.token.is_cancelled() {
            let start_elapsed = application_start.elapsed();
            let loop_elapsed = start_elapsed - last_loop;
            self.update_snapshot();
            let snap = &self.snapshot;

            // Get current counter values
            let dropped = self.events_drops.get_rate_string(snap, loop_elapsed);
            let handled = self.events_handled.get_rate_string(snap, loop_elapsed);
            let ingress = self.ingress_counter.get_rate_string(snap, loop_elapsed);
            let egress = self.egress_counter.get_rate_string(snap, loop_elapsed);

            // Time elapsed display string
            let time_string = format!(
                "{}s {}ms",
                start_elapsed.as_secs(),
                start_elapsed.subsec_millis()
            );

            let to_display = format!(
                // \r returns cursor to beginning of line, effectively overwriting the last line
                "\r| {} time elapsed | {} handled | {} dropped | {} events/s | {} drops/s | {} ingress packets/s | {} egress packets/s | ",
                time_string, snap.handled(), snap.dropped(), handled, dropped, ingress, egress
            );

            print!("{to_display}");

            let _ = io::stdout().flush();

            last_loop = application_start.elapsed();
            // Sleep until next calc
            sleep(Duration::from_millis(500))
        }
    }

    // TODO: move elements to separate files!
    fn run_tui(&mut self) {
        let mut last_size: u64 = 0;

        // Track time for averages
        let application_start = Instant::now();
        let mut last_loop: Duration = Duration::default();

        // Graph definitions
        let mut graph_titles = Vec::new();
        let mut graph_ids = Vec::new();

        if self.config.graphs.events {
            graph_titles.push("Events");
            graph_ids.push(0);
        }
        if self.config.graphs.packets {
            graph_titles.push("Packets");
            graph_ids.push(1);
        }
        if self.config.graphs.kernel {
            graph_titles.push("Kernel");
            graph_ids.push(2);
        }
        if self.config.graphs.cubic {
            graph_titles.push("Cubic");
            graph_ids.push(3);
        }
        if self.config.graphs.bbr {
            graph_titles.push("BBR");
            graph_ids.push(4);
        }
        if self.config.graphs.tracepoints {
            graph_titles.push("Tracepoints");
            graph_ids.push(5);
        }

        let mut graph_events = Graph::new(
            "Handled".to_string(),
            "Dropped".to_string(),
            Color::Green,
            Color::Red,
            self.config.observation_window,
            "Events".to_string(),
        );
        let mut graph_packets = Graph::new(
            "Ingress".to_string(),
            "Egress".to_string(),
            Color::Green,
            Color::Cyan,
            self.config.observation_window,
            "Packet Rates".to_string(),
        );
        let mut graph_calls = Graph::new(
            "tcp_recvmsg".to_string(),
            "tcp_sendmsg".to_string(),
            Color::Red,
            Color::Blue,
            self.config.observation_window,
            "Function Calls".to_string(),
        );
        let mut graph_cubic = Graph::new_single(
            "Cubic".to_string(),
            Color::Yellow,
            self.config.observation_window,
            "Cubic Events".to_string(),
        );
        let mut graph_bbr = Graph::new_single(
            "BBR".to_string(),
            Color::Magenta,
            self.config.observation_window,
            "BBR Events".to_string(),
        );
        let mut graph_tracepoints = Graph::new_single(
            "Tracepoints".to_string(),
            Color::Reset,
            self.config.observation_window,
            "Tracepoint Events".to_string(),
        );

        let status = Status::new();

        let mut scrollbar_state = ScrollbarState::new(0);
        let mut scroll_index: usize = 0;
        let mut num_flows: usize;

        let file_tracker = FileTracker::new(&self.config.dir);

        #[derive(Clone, Copy)]
        enum ViewLayout {
            PacketsOnly,
            CallsOnly,
            SplitHorizontal,
            SplitVertical,
            BBROnly,
            CubicOnly,
        }

        let mut views = Vec::new();
        if self.config.packets {
            views.push(("Packets", ViewLayout::PacketsOnly));
        }
        if self.config.calls {
            views.push(("Calls", ViewLayout::CallsOnly));
        }
        if self.config.packets && self.config.calls {
            views.push(("Split H", ViewLayout::SplitHorizontal));
            views.push(("Split V", ViewLayout::SplitVertical));
        }
        if self.config.algorithms {
            views.push(("BBR", ViewLayout::BBROnly));
            views.push(("Cubic", ViewLayout::CubicOnly));
        }
        if views.is_empty() {
            views.push(("None", ViewLayout::PacketsOnly));
        }
        let mut selected_tab = 0;

        while !self.token.is_cancelled() {
            let start_elapsed = application_start.elapsed();
            let loop_elapsed = start_elapsed - last_loop;

            self.update_snapshot();
            let snap = &self.snapshot;

            // Update tracker of alll flows internal list and then print it
            self.flow_tracker.read_flows();
            // Update size of scrollbar
            scrollbar_state = self.flow_tracker.update_scrollbar_state(scrollbar_state);
            scrollbar_state = scrollbar_state.position(scroll_index);
            scrollbar_state.next();
            num_flows = self.flow_tracker.num_flows;

            let flows = self.flow_tracker.get_flows().block(
                Block::bordered()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Reset))
                    .title(format!(
                        "Tracking {} Flows. Scroll with arrows or mousewheel.",
                        num_flows
                    )),
            );
            let mut flows_state = TableState::new().with_offset(scroll_index);

            // Track file size and rate
            let files_size = file_tracker.get_file_size();
            let file_rate = RateWatcher::format_rate(
                files_size.saturating_sub(last_size) as f64 * (1.0 / loop_elapsed.as_secs_f64()),
                "Byte/s",
            );

            // Track changes in rates
            let time_sec = start_elapsed.as_secs_f64();

            let handled_rate = self.events_handled.get_rate(snap, loop_elapsed);
            let dropped_rate = self.events_drops.get_rate(snap, loop_elapsed);
            graph_events.add_val(0, (time_sec, handled_rate));
            graph_events.add_val(1, (time_sec, dropped_rate));

            graph_packets.add_val(
                0,
                (time_sec, self.ingress_counter.get_rate(snap, loop_elapsed)),
            );
            graph_packets.add_val(
                1,
                (time_sec, self.egress_counter.get_rate(snap, loop_elapsed)),
            );

            graph_calls.add_val(
                0,
                (time_sec, self.tcp_sock_recv.get_rate(snap, loop_elapsed)),
            );
            graph_calls.add_val(
                1,
                (time_sec, self.tcp_sock_send.get_rate(snap, loop_elapsed)),
            );
            graph_cubic.add_val(
                0,
                (time_sec, self.cubic_events.get_rate(snap, loop_elapsed)),
            );
            graph_bbr.add_val(0, (time_sec, self.bbr_events.get_rate(snap, loop_elapsed)));
            graph_tracepoints.add_val(
                0,
                (
                    time_sec,
                    self.tracepoint_events.get_rate(snap, loop_elapsed),
                ),
            );

            // Time elapsed
            let time_string = format!(
                "{}s {}ms",
                start_elapsed.as_secs(),
                start_elapsed.subsec_millis()
            );

            let event_rate = RateWatcher::format_rate(handled_rate + dropped_rate, " Events/s");

            // Tooltips
            let window_label = self
                .config
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

            // Render function
            // TODO: move to own function
            let _ = self.terminal.as_mut().unwrap().draw(|frame| {
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

                // Top Sidebar layout
                let mut constraints = vec![Constraint::Max(3); status.num_blocks()];
                constraints.push(Constraint::Min(0));

                // Top graph layout (Right side)
                let right_side = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(top_areas[1]);

                // Graph Area (Top of right side)
                let graph_area_full = right_side[0];
                let graph_layout = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(3), Constraint::Min(0)])
                    .split(graph_area_full);

                let tab_area = graph_layout[0];
                let chart_area = graph_layout[1];

                // Render Tabs
                let tab_constraints: Vec<Constraint> = (0..graph_titles.len())
                    .map(|_| Constraint::Ratio(1, graph_titles.len() as u32))
                    .collect();

                let tab_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints(tab_constraints)
                    .split(tab_area);

                for (i, title) in graph_titles.iter().enumerate() {
                    let style = if i == selected_tab {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Reset)
                    };
                    frame.render_widget(
                        Paragraph::new(*title)
                            .block(
                                Block::bordered().border_style(Style::default().fg(Color::Reset)),
                            )
                            .style(style),
                        tab_chunks[i],
                    );
                }

                // Render Selected Graph
                let chart_id = if !graph_ids.is_empty() {
                    graph_ids[selected_tab]
                } else {
                    0
                };
                let chart = match chart_id {
                    0 => graph_events.get_chart("Events/s", Color::Reset, Color::Reset),
                    1 => graph_packets.get_chart("pps", Color::Reset, Color::Reset),
                    2 => graph_calls.get_chart("Calls/s", Color::Reset, Color::Reset),
                    3 => graph_cubic.get_chart("Events/s", Color::Reset, Color::Reset),
                    4 => graph_bbr.get_chart("Events/s", Color::Reset, Color::Reset),
                    5 => graph_tracepoints.get_chart("Events/s", Color::Reset, Color::Reset),
                    _ => graph_events.get_chart("Events/s", Color::Reset, Color::Reset),
                };
                frame.render_widget(chart, chart_area);

                let sidebar = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints(constraints)
                    .split(top_areas[0]);

                // Render each status bar block

                for (i, block) in status
                    .get_blocks(
                        time_string,
                        self.events_handled.get_counter_sum_string(snap),
                        self.events_drops.get_counter_sum_string(snap),
                        snap.dropped() > 0,
                        event_rate,
                        files_size,
                        file_rate,
                        self.tcp_bytes_recv.get_counter_sum_string(snap),
                        self.tcp_bytes_sent.get_counter_sum_string(snap),
                        Color::Reset,
                    )
                    .into_iter()
                    .enumerate()
                {
                    frame.render_widget(block, sidebar[i]);
                }

                // Scrollbar
                let scrollbar = Scrollbar::default()
                    .orientation(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None);

                scrollbar_state =
                    scrollbar_state.viewport_content_length(right_side[1].height as usize);

                // Render flows in bottom right
                frame.render_stateful_widget(flows, right_side[1], &mut flows_state);

                // Render scrollbar when more entries than height
                if num_flows
                    > (right_side[1]
                        .inner(Margin {
                            vertical: 1,
                            horizontal: 1,
                        })
                        .height
                        - 1) as usize
                {
                    frame.render_stateful_widget(
                        scrollbar,
                        right_side[1].inner(Margin {
                            vertical: 1,
                            horizontal: 1,
                        }),
                        &mut scrollbar_state,
                    );
                }

                frame.render_widget(keybindings.block(keybindings_block), areas[1]);
            });

            // Store time after calculation for rate calculation
            last_loop = application_start.elapsed();
            last_size = files_size;

            // Main visualization and processing part is done now!
            // Wait for key event for 0.5s and check key presses inbetween runs
            let start = Instant::now();
            // Loop until 500ms elapsed
            while start.elapsed().as_millis() < self.update_period {
                // Poll for eavent ready
                // Timout after 10ms
                // On Error continue to next loop iteration
                let Ok(ready) = event::poll(Duration::from_millis(10)) else {
                    continue;
                };

                if ready {
                    match event::read() {
                        Ok(event::Event::Key(key)) => {
                            if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                                self.token.cancel();
                            }

                            if key.code == KeyCode::Down {
                                // Limit index to number of flows
                                scroll_index = (scroll_index + 1).min(self.flow_tracker.num_flows);
                            }

                            if key.code == KeyCode::Up {
                                // Limit index to be 0 at min
                                // Cant be with .min() due to overflow at 0 - 1
                                scroll_index = scroll_index.saturating_sub(1);
                            }

                            // Graph navigation
                            if key.code == KeyCode::Right || key.code == KeyCode::Tab {
                                if !graph_titles.is_empty() {
                                    selected_tab = (selected_tab + 1) % graph_titles.len();
                                }
                            }
                            if key.code == KeyCode::Left {
                                if graph_titles.is_empty() {
                                    // Do nothing
                                } else if selected_tab > 0 {
                                    selected_tab -= 1;
                                } else {
                                    selected_tab = graph_titles.len() - 1;
                                }
                            }
                        }
                        Ok(event::Event::Mouse(mouse)) => {
                            match mouse.kind {
                                event::MouseEventKind::ScrollDown => {
                                    scroll_index =
                                        (scroll_index + 1).min(self.flow_tracker.num_flows);
                                }
                                event::MouseEventKind::ScrollUp => {
                                    scroll_index = scroll_index.saturating_sub(1);
                                }
                                event::MouseEventKind::Down(event::MouseButton::Left) => {
                                    // Check if click is in tab area
                                    if let Ok(size) = self.terminal.as_ref().unwrap().size() {
                                        let rect = Rect::new(0, 0, size.width, size.height);
                                        // Replicate layout logic to find tab area
                                        let areas = Layout::default()
                                            .direction(Direction::Vertical)
                                            .constraints(vec![
                                                Constraint::Min(8),
                                                Constraint::Max(3),
                                            ])
                                            .split(rect);
                                        let top_areas = Layout::default()
                                            .direction(Direction::Horizontal)
                                            .constraints(vec![
                                                Constraint::Percentage(20),
                                                Constraint::Percentage(80),
                                            ])
                                            .split(areas[0]);
                                        let right_side = Layout::default()
                                            .direction(Direction::Vertical)
                                            .constraints(vec![
                                                Constraint::Percentage(50),
                                                Constraint::Percentage(50),
                                            ])
                                            .split(top_areas[1]);
                                        let graph_layout = Layout::default()
                                            .direction(Direction::Vertical)
                                            .constraints([
                                                Constraint::Length(3),
                                                Constraint::Min(0),
                                            ])
                                            .split(right_side[0]);
                                        let tab_area = graph_layout[0];

                                        if !tab_area
                                            .contains(Position::new(mouse.column, mouse.row))
                                        {
                                            continue;
                                        }

                                        let tab_constraints: Vec<Constraint> = (0..graph_titles
                                            .len())
                                            .map(|_| {
                                                Constraint::Ratio(1, graph_titles.len() as u32)
                                            })
                                            .collect();

                                        let tab_chunks = Layout::default()
                                            .direction(Direction::Horizontal)
                                            .constraints(tab_constraints)
                                            .split(tab_area);
                                        for (i, chunk) in tab_chunks.iter().enumerate() {
                                            if chunk
                                                .contains(Position::new(mouse.column, mouse.row))
                                            {
                                                selected_tab = i;
                                                break;
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Restore terminal view
        let _ = execute!(io::stdout(), DisableMouseCapture);
        ratatui::restore();
    }
}
