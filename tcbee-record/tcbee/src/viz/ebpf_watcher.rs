use std::{
    fs::File,
    io::{self, BufWriter, Write},
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use serde::Serialize;

use crate::{
    eBPF::{ebpf_runner::prepend_string, ebpf_runner_config::EbpfWatcherConfig},
    viz::{flow_tracker::FlowTracker, rate_watcher::RateWatcher},
};

use aya::{
    maps::{PerCpuArray, PerCpuHashMap},
    Ebpf,
};
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
use tokio_util::sync::CancellationToken;

use super::{
    components::{graph::Graph, status::Status},
    file_tracker::FileTracker,
};

pub struct EBPFWatcher {
    events_drops: RateWatcher<u32>,
    events_handled: RateWatcher<u32>,
    ingress_counter: RateWatcher<u32>,
    egress_counter: RateWatcher<u32>,
    tcp_sock_send: RateWatcher<u32>,
    tcp_sock_recv: RateWatcher<u32>,
    tcp_bytes_recv: RateWatcher<u32>,
    tcp_bytes_sent: RateWatcher<u32>,
    cubic_events: RateWatcher<u32>,
    bbr_events: RateWatcher<u32>,
    tracepoint_events: RateWatcher<u32>,
    flow_tracker: FlowTracker,
    update_period: u128,
    token: CancellationToken,
    terminal: Option<DefaultTerminal>,
    config: EbpfWatcherConfig,
}

#[derive(Serialize)]
pub struct Metrics {
    handled: u32,
    dropped: u32,
    ingress: u32,
    egress: u32,
    ingress_calls: u32,
    egress_calls: u32,
    tcp_bytes_sent: u32,
    tcp_bytes_received: u32,
}
//TODO: Monitor packet rate vs TCP packet rate?
impl EBPFWatcher {
    pub fn new(
        ebpf: &mut Ebpf,
        update_period: u128,
        token: CancellationToken,
        config: EbpfWatcherConfig,
        do_tui: bool,
    ) -> anyhow::Result<EBPFWatcher> {
        // Track rate of passed maps
        // TODO: This really should be moved to some sort of loop and dict approach
        let events_drops = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("EVENTS_DROPPED")
                    .ok_or_else(|| anyhow!("Could not find EVENTS_DROPPED map!"))?,
            )?,
            "Events/s".to_string(),
            0,
            "Event Drops".to_string(),
        );
        let events_handled = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("EVENTS_HANDLED")
                    .ok_or_else(|| anyhow!("Could not find EVENTS_HANDLED map!"))?,
            )?,
            "Events/s".to_string(),
            0,
            "Event Handled".to_string(),
        );
        let ingress_counter = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("INGRESS_EVENTS")
                    .ok_or_else(|| anyhow!("Could not find INGRESS_EVENTS map!"))?,
            )?,
            "pps".to_string(),
            0,
            "Ingress Packets".to_string(),
        );
        let egress_counter = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("EGRESS_EVENTS")
                    .ok_or_else(|| anyhow!("Could not find EGRESS_EVENTS map!"))?,
            )?,
            "pps".to_string(),
            0,
            "Egress Packets".to_string(),
        );
        let tcp_sock_send = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("SEND_TCP_SOCK")
                    .ok_or_else(|| anyhow!("Could not find SEND_TCP_SOCK map!"))?,
            )?,
            "Calls/s".to_string(),
            0,
            "TCP Sendmsg".to_string(),
        );
        let tcp_sock_recv = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("RECV_TCP_SOCK")
                    .ok_or_else(|| anyhow!("Could not find RECV_TCP_SOCK map!"))?,
            )?,
            "Bytes/s".to_string(),
            0,
            "TCP Recvmsg".to_string(),
        );
        let tcp_bytes_recv = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("RECEIVED_TCP_BYTES")
                    .ok_or_else(|| anyhow!("Could not find RECEIVED_TCP_BYTES map!"))?,
            )?,
            "Calls/s".to_string(),
            0,
            "TCP Bytes Received".to_string(),
        );
        let tcp_bytes_sent = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("SENT_TCP_BYTES")
                    .ok_or_else(|| anyhow!("Could not find SENT_TCP_BYTES map!"))?,
            )?,
            "Calls/s".to_string(),
            0,
            "TCP Bytes Sent".to_string(),
        );

        let cubic_events = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("CUBIC_EVENTS_COUNTER")
                    .ok_or_else(|| anyhow!("Could not find CUBIC_EVENTS_COUNTER map!"))?,
            )?,
            "Calls/s".to_string(),
            0,
            "Cubic Events".to_string(),
        );

        let bbr_events = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("BBR_EVENTS_COUNTER")
                    .ok_or_else(|| anyhow!("Could not find BBR_EVENTS_COUNTER map!"))?,
            )?,
            "Calls/s".to_string(),
            0,
            "BBR Events".to_string(),
        );

        let tracepoint_events = RateWatcher::<u32>::new(
            PerCpuArray::try_from(
                ebpf.take_map("TRACEPOINT_EVENTS")
                    .ok_or_else(|| anyhow!("Could not find TRACEPOINT_EVENTS map!"))?,
            )?,
            "Calls/s".to_string(),
            0,
            "Tracepoint Events".to_string(),
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

            // Get current counter values
            let dropped = self.events_drops.get_rate_string(loop_elapsed);
            let handled = self.events_handled.get_rate_string(loop_elapsed);
            let ingress = self.ingress_counter.get_rate_string(loop_elapsed);
            let egress = self.egress_counter.get_rate_string(loop_elapsed);

            // Time elapsed display string
            let time_string = format!(
                "{}s {}ms",
                start_elapsed.as_secs(),
                start_elapsed.subsec_millis()
            );

            let to_display = format!(
                // \r returns cursor to beginning of line, effectively overwriting the last line
                "\r| {} time elapsed | {} handled | {} dropped | {} events/s | {} drops/s | {} ingress packets/s | {} egress packets/s | ",
                time_string,self.events_handled.get_counter_sum(), self.events_drops.get_counter_sum(), handled, dropped,ingress,egress
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
            let file_rate = RateWatcher::<u64>::format_rate(
                (files_size - last_size) as f64 * (1.0 / loop_elapsed.as_secs_f64()),
                "Byte/s",
            );

            // Track changes in rates
            let time_sec = start_elapsed.as_secs_f64();

            let handled_rate = self.events_handled.get_rate(loop_elapsed);
            let dropped_rate = self.events_drops.get_rate(loop_elapsed);
            graph_events.add_val(0, (time_sec, handled_rate));
            graph_events.add_val(1, (time_sec, dropped_rate));

            graph_packets.add_val(0, (time_sec, self.ingress_counter.get_rate(loop_elapsed)));
            graph_packets.add_val(1, (time_sec, self.egress_counter.get_rate(loop_elapsed)));

            graph_calls.add_val(0, (time_sec, self.tcp_sock_recv.get_rate(loop_elapsed)));
            graph_calls.add_val(1, (time_sec, self.tcp_sock_send.get_rate(loop_elapsed)));
            graph_cubic.add_val(0, (time_sec, self.cubic_events.get_rate(loop_elapsed)));
            graph_bbr.add_val(0, (time_sec, self.bbr_events.get_rate(loop_elapsed)));
            graph_tracepoints.add_val(0, (time_sec, self.tracepoint_events.get_rate(loop_elapsed)));

            // Time elapsed
            let time_string = format!(
                "{}s {}ms",
                start_elapsed.as_secs(),
                start_elapsed.subsec_millis()
            );

            let event_rate =
                RateWatcher::<u32>::format_rate(handled_rate + dropped_rate, " Events/s");

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
                        self.events_handled.get_counter_sum_string(),
                        self.events_drops.get_counter_sum_string(),
                        self.events_drops.get_counter_sum() > 0,
                        event_rate,
                        files_size,
                        file_rate,
                        self.tcp_bytes_recv.get_counter_sum_string(),
                        self.tcp_bytes_sent.get_counter_sum_string(),
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

        // Store metrics if needed
        if self.config.metrics {
            let metrics = Metrics {
                handled: self.events_handled.get_counter_sum(),
                dropped: self.events_drops.get_counter_sum(),
                ingress: self.ingress_counter.get_counter_sum(),
                egress: self.egress_counter.get_counter_sum(),
                ingress_calls: self.tcp_sock_recv.get_counter_sum(),
                egress_calls: self.tcp_sock_send.get_counter_sum(),
                tcp_bytes_sent: self.tcp_bytes_sent.get_counter_sum(),
                tcp_bytes_received: self.tcp_bytes_recv.get_counter_sum(),
            };

            let Ok(outfile) =
                File::create(prepend_string("metrics.json".to_string(), &self.config.dir))
            else {
                error!("Could not open outfile: {}/metrics.json", self.config.dir);
                return;
            };

            let mut writer = BufWriter::new(outfile);

            let _ = serde_json::to_writer(&mut writer, &metrics);
            let _ = writer.flush();
        }

        // Restore terminal view
        let _ = execute!(io::stdout(), DisableMouseCapture);
        ratatui::restore();
    }
}
