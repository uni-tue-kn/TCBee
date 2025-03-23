use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num,
    ops::{AddAssign, Sub},
    os::linux::fs::MetadataExt,
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use glob;

use crate::{
    config::UI_UPDATE_MS_INTERVAL,
    viz::{flow_tracker::FlowTracker, rate_watcher::RateWatcher},
};

use aya::{
    maps::{PerCpuArray, PerCpuHashMap},
    util::nr_cpus,
    Pod,
};
use log::{error, info, warn};
use ratatui::{
    buffer::Buffer,
    crossterm::event::{self, KeyCode, KeyEventKind},
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols,
    text::Span,
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, GraphType, LegendPosition, List, Paragraph,
        Row, ScrollDirection, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState,
        Widget,
    },
    DefaultTerminal,
};
use tcbee_common::bindings::flow::IpTuple;
use tokio_util::sync::CancellationToken;

use super::file_tracker::{self, FileTracker};

pub struct EBPFWatcher {
    events_drops: RateWatcher<u32>,
    events_handled: RateWatcher<u32>,
    ingress_counter: RateWatcher<u32>,
    egress_counter: RateWatcher<u32>,
    tcp_sock_send: RateWatcher<u32>,
    tcp_sock_recv: RateWatcher<u32>,
    flow_tracker: FlowTracker,
    token: CancellationToken,
    terminal: Option<DefaultTerminal>,
}

//TODO: Monitor packet rate vs TCP packet rate?
impl EBPFWatcher {
    pub fn new(
        events_drops: PerCpuArray<aya::maps::MapData, u32>,
        events_handled: PerCpuArray<aya::maps::MapData, u32>,
        ingress_counter: PerCpuArray<aya::maps::MapData, u32>,
        egress_counter: PerCpuArray<aya::maps::MapData, u32>,
        tcp_sock_send: PerCpuArray<aya::maps::MapData, u32>,
        tcp_sock_recv: PerCpuArray<aya::maps::MapData, u32>,
        flow_tracker: PerCpuHashMap<aya::maps::MapData, IpTuple, IpTuple>,
        token: CancellationToken,
        do_tui: bool,
    ) -> Result<EBPFWatcher, Box<dyn Error>> {
        // Track rate of passed maps
        let events_drops = RateWatcher::<u32>::new(
            events_drops,
            "Events/s".to_string(),
            0,
            "Event Drops".to_string(),
        );
        let events_handled = RateWatcher::<u32>::new(
            events_handled,
            "Events/s".to_string(),
            0,
            "Event Handled".to_string(),
        );
        let ingress_counter = RateWatcher::<u32>::new(
            ingress_counter,
            "pps".to_string(),
            0,
            "Ingress Packets".to_string(),
        );
        let egress_counter = RateWatcher::<u32>::new(
            egress_counter,
            "pps".to_string(),
            0,
            "Egress Packets".to_string(),
        );
        let tcp_sock_send = RateWatcher::<u32>::new(
            tcp_sock_send,
            "Calls/s".to_string(),
            0,
            "TCP Sendmsg".to_string(),
        );
        let tcp_sock_recv = RateWatcher::<u32>::new(
            tcp_sock_recv,
            "Calls/s".to_string(),
            0,
            "TCP Recvmsg".to_string(),
        );

        let flow_tracker = FlowTracker::new(flow_tracker);

        if do_tui {
            color_eyre::install()?;
            let terminal: DefaultTerminal = ratatui::init();

            Ok(EBPFWatcher {
                events_drops,
                events_handled,
                ingress_counter,
                egress_counter,
                tcp_sock_send,
                tcp_sock_recv,
                flow_tracker,
                token,
                terminal: Some(terminal),
            })
        } else {
            Ok(EBPFWatcher {
                events_drops,
                events_handled,
                ingress_counter,
                egress_counter,
                tcp_sock_send,
                tcp_sock_recv,
                flow_tracker,
                token,
                terminal: None,
            })
        }
    }

    pub fn run_no_tui(&mut self) {
        // To calculate rate over multiple iterations
        let application_start = Instant::now();

        while !self.token.is_cancelled() {
            let elapsed = application_start.elapsed();

            // Get current counter values
            let dropped = self.events_drops.get_rate_string(elapsed);
            let handled = self.events_handled.get_rate_string(elapsed);
            let ingress = self.ingress_counter.get_rate_string(elapsed);
            let egress = self.egress_counter.get_rate_string(elapsed);

            // Time elapsed display string
            let time_string = format!("{}s {}ms", elapsed.as_secs(), elapsed.subsec_millis());

            let to_display = format!(
                // \r returns cursor to beginning of line, effectively overwriting the last line
                "\r| {} time elapsed | {} handled | {} dropped | {} events/s | {} drops/s | {} ingress packets/s | {} egress packets/s | ",
                time_string,self.events_handled.get_counter_sum(), self.events_drops.get_counter_sum(), handled, dropped,ingress,egress
            );

            print!("{to_display}");

            let _ = io::stdout().flush();

            // Sleep until next calc
            sleep(Duration::from_millis(500))
        }
    }

    // TODO: move elements to separate files!
    pub fn run(&mut self) -> () {
        // Rate tracking for graph bounds
        let mut max_rate: f64 = 0.0;
        let mut tcp_sock_max_rate: f64 = 0.0;

        let mut last_size: u64 = 0;

        let application_start = Instant::now();
        let mut last_loop: Duration = Duration::default();

        // For plotting
        // TODO: Add max number of entries handling!
        let mut ingress_rates: Vec<(f64, f64)> = vec![(0.0, 0.0)];
        let mut egress_rates: Vec<(f64, f64)> = vec![(0.0, 0.0)];
        let mut tcp_send_rates: Vec<(f64, f64)> = vec![(0.0, 0.0)];
        let mut tcp_recv_rates: Vec<(f64, f64)> = vec![(0.0, 0.0)];

        let mut scrollbar_state = ScrollbarState::new(0);
        let mut scroll_index: usize = 0;
        let mut num_flows: usize = 0;

        let file_tracker = FileTracker::new();

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

            let flows =
                self.flow_tracker
                    .get_flows()
                    .block(Block::bordered().borders(Borders::ALL).title(format!(
                        "Tracking {} Flows. Scroll with arrows or mousewheel.",
                        num_flows
                    )));
            let mut flows_state = TableState::new().with_offset(scroll_index);

            // Track file size and rate
            let files_size = file_tracker.get_file_size();
            let file_rate = RateWatcher::<u64>::format_rate(
                (files_size - last_size) as f64 * (1.0 / loop_elapsed.as_secs_f64()),
                "Byte/s",
            );

            // Get ingress and egress packets per second
            let ingress_rate = self.ingress_counter.get_rate(loop_elapsed);
            let egress_rate = self.egress_counter.get_rate(loop_elapsed);
            // Add rates fto graph lines
            ingress_rates.push((start_elapsed.as_secs_f64(), ingress_rate as f64));
            egress_rates.push((start_elapsed.as_secs_f64(), egress_rate as f64));
            // Get maximum packet rate to set y-limit of graph
            max_rate = max_rate.max(ingress_rate);
            max_rate = max_rate.max(egress_rate);

            // Get ingress and egress tcp segments per second
            let tcp_send_rate = self.tcp_sock_send.get_rate(loop_elapsed);
            let tcp_recv_rate = self.tcp_sock_recv.get_rate(loop_elapsed);
            // Add rates fto graph lines
            tcp_send_rates.push((start_elapsed.as_secs_f64(), tcp_send_rate as f64));
            tcp_recv_rates.push((start_elapsed.as_secs_f64(), tcp_recv_rate as f64));
            // Get maximum packet rate to set y-limit of graph
            tcp_sock_max_rate = tcp_sock_max_rate.max(tcp_send_rate);
            tcp_sock_max_rate = tcp_sock_max_rate.max(tcp_recv_rate);

            // Time elapsed
            let time_string = format!(
                "{}s {}ms",
                start_elapsed.as_secs(),
                start_elapsed.subsec_millis()
            );

            // Track rate of all events as sum of dropped and handled
            let event_rate = RateWatcher::<u32>::format_rate(
                self.events_handled.get_rate(loop_elapsed)
                    + self.events_drops.get_rate(loop_elapsed),
                " Events/s",
            );

            // Check if packets were lost
            let mut dropped_style: Style = Style::default();
            if self.events_drops.get_counter_sum() > 0 {
                dropped_style = dropped_style.bg(Color::LightRed);
            }

            // Blocks for UI
            let status_blocks = vec![
                Paragraph::new(time_string).block(
                    Block::bordered()
                        .borders(Borders::BOTTOM)
                        .title("Time Elapsed"),
                ),
                Paragraph::new(self.events_handled.get_counter_sum_string()).block(
                    Block::bordered()
                        .borders(Borders::BOTTOM)
                        .title("Events Handled"),
                ),
                Paragraph::new(self.events_drops.get_counter_sum_string())
                    .block(
                        Block::bordered()
                            .borders(Borders::BOTTOM)
                            .title("Events Dropped"),
                    )
                    .style(dropped_style),
                Paragraph::new(event_rate).block(
                    Block::bordered()
                        .borders(Borders::BOTTOM)
                        .title("Event Rate"),
                ),
                Paragraph::new(RateWatcher::<u64>::format_sum(files_size, "Byte")).block(
                    Block::bordered()
                        .borders(Borders::BOTTOM)
                        .title("Disk File Size"),
                ),
                Paragraph::new(file_rate).block(
                    Block::bordered()
                        .borders(Borders::BOTTOM)
                        .title("Write Speed"),
                ),
            ];

            // Tooltips
            let keybindings =
                Paragraph::new("Close application: q | Esc  - Legend: (K)ilo, (M)ega, (G)iga");
            let keybindings_block = Block::bordered().borders(Borders::ALL).title("Keybindings");

            // Rate chart labels
            let y_labels = vec![
                Span::styled(
                    format!("{}", 0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", RateWatcher::<u32>::format_rate(max_rate / 2.0, "pps")),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", RateWatcher::<u32>::format_rate(max_rate, "pps")),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ];

            let x_labels = vec![
                Span::styled(
                    format!("{}", 0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}s", start_elapsed.as_secs() as f64 / 2.0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}s", start_elapsed.as_secs()),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ];

            // Rate chart
            let chart = Chart::new(vec![
                Dataset::default()
                    .name("Ingress")
                    .marker(symbols::Marker::Braille)
                    .style(Style::default().fg(Color::Cyan))
                    .graph_type(GraphType::Line)
                    .data(&ingress_rates),
                Dataset::default()
                    .name("Egress")
                    .marker(symbols::Marker::Braille)
                    .style(Style::default().fg(Color::LightGreen))
                    .graph_type(GraphType::Line)
                    .data(&egress_rates),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Packet Rate Graph"),
            )
            .x_axis(
                Axis::default()
                    .style(Style::default().fg(Color::White))
                    .bounds([0.0, start_elapsed.as_secs_f64()])
                    .labels(x_labels),
            )
            .y_axis(
                Axis::default()
                    .style(Style::default().fg(Color::White))
                    .bounds([0.0, max_rate])
                    .labels(y_labels),
            )
            .legend_position(Some(LegendPosition::TopLeft))
            .hidden_legend_constraints((Constraint::Min(0), Constraint::Min(0)));

            // Rate chart labels
            let y_labels = vec![
                Span::styled(
                    format!("{}", 0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", RateWatcher::<u32>::format_rate(tcp_sock_max_rate / 2.0, "Calls/s")),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", RateWatcher::<u32>::format_rate(tcp_sock_max_rate, "Calls/s")),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ];

            let x_labels = vec![
                Span::styled(
                    format!("{}", 0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}s", start_elapsed.as_secs() as f64 / 2.0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}s", start_elapsed.as_secs()),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ];

            // TCP sock chart
            let tcp_sock_chart = Chart::new(vec![
                Dataset::default()
                    .name("tcp_sendmsg")
                    .marker(symbols::Marker::Braille)
                    .style(Style::default().fg(Color::Red))
                    .graph_type(GraphType::Line)
                    .data(&tcp_send_rates),
                Dataset::default()
                    .name("tcp_recvmsg")
                    .marker(symbols::Marker::Braille)
                    .style(Style::default().fg(Color::LightBlue))
                    .graph_type(GraphType::Line)
                    .data(&tcp_recv_rates),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("TCP Kernel Function Calls"),
            )
            .x_axis(
                Axis::default()
                    .style(Style::default().fg(Color::White))
                    .bounds([0.0, start_elapsed.as_secs_f64()])
                    .labels(x_labels),
            )
            .y_axis(
                Axis::default()
                    .style(Style::default().fg(Color::White))
                    .bounds([0.0, tcp_sock_max_rate])
                    .labels(y_labels),
            )
            .legend_position(Some(LegendPosition::TopLeft))
            .hidden_legend_constraints((Constraint::Min(0), Constraint::Min(0)));

            // Render function
            // TODO: move to own function
            let _ = self.terminal.as_mut().unwrap().draw(|frame| {
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
                let mut constraints = vec![Constraint::Max(3); status_blocks.len()];
                constraints.push(Constraint::Min(0));

                // Top graph layout
                let mut graphs = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(top_areas[1]);

                // Split into two graphs
                let mut sub_graphs = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(graphs[0]);

                let sidebar = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints(constraints)
                    .split(top_areas[0]);

                // Render each status bar block
                let mut i = 0;
                for block in status_blocks {
                    frame.render_widget(block, sidebar[i]);
                    i = i + 1;
                }

                // Scrollbar
                let scrollbar = Scrollbar::default()
                    .orientation(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None);

                scrollbar_state =
                    scrollbar_state.viewport_content_length(graphs[1].height as usize);

                frame.render_widget(chart, sub_graphs[0]);
                frame.render_widget(tcp_sock_chart, sub_graphs[1]);
                frame.render_stateful_widget(flows, graphs[1], &mut flows_state);

                // Render scrollbar when more entries than height
                if num_flows
                    > (graphs[1]
                        .inner(Margin {
                            vertical: 1,
                            horizontal: 1,
                        })
                        .height
                        - 1) as usize
                {
                    frame.render_stateful_widget(
                        scrollbar,
                        graphs[1].inner(Margin {
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
            while start.elapsed().as_millis() < UI_UPDATE_MS_INTERVAL {
                // Poll for eavent ready
                // Timout after 10ms
                // On Error continue to next loop iteration
                let Ok(ready) = event::poll(Duration::from_millis(10)) else {
                    continue;
                };

                if ready {
                    // Get key event
                    // If not a key event or error returned, continue
                    let Ok(event::Event::Key(key)) = event::read() else {
                        continue;
                    };

                    // Check for esc or q to cancel
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
                        if scroll_index > 0 {
                            scroll_index = scroll_index - 1;
                        }
                    }
                }
            }
        }

        // Restore terminal view
        ratatui::restore();
    }
}
