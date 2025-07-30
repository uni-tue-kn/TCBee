use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::{self, BufWriter, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num,
    ops::{AddAssign, Sub},
    os::linux::fs::MetadataExt,
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use glob;
use serde::Serialize;

use crate::{
    config::UI_UPDATE_MS_INTERVAL,
    eBPF::{ebpf_runner::prepend_string, ebpf_runner_config::EbpfWatcherConfig},
    viz::{flow_tracker::FlowTracker, rate_watcher::RateWatcher},
};

use aya::{
    maps::{PerCpuArray, PerCpuHashMap},
    util::nr_cpus,
    Ebpf, Pod,
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
    DefaultTerminal, Terminal,
};
use tcbee_common::bindings::flow::IpTuple;
use tokio_util::sync::CancellationToken;

use super::{
    components::{graph::Graph, status::Status},
    file_tracker::{self, FileTracker},
};

pub struct EBPFWatcher {
    events_drops: RateWatcher<u32>,
    events_handled: RateWatcher<u32>,
    ingress_counter: RateWatcher<u32>,
    egress_counter: RateWatcher<u32>,
    tcp_sock_send: RateWatcher<u32>,
    tcp_sock_recv: RateWatcher<u32>,
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
    egress_calls: u32 
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
        // TODO: can this be cleaned up?
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
            "Calls/s".to_string(),
            0,
            "TCP Recvmsg".to_string(),
        );

        let flow_tracker = FlowTracker::new(PerCpuHashMap::try_from(
            ebpf.take_map("FLOWS")
                .ok_or_else(|| anyhow!("Could not find FLOWS map!"))?,
        )?);

        let terminal: Option<DefaultTerminal> = match do_tui {
            true => Some(ratatui::init()),
            false => None,
        };

        Ok(EBPFWatcher {
            events_drops,
            events_handled,
            ingress_counter,
            egress_counter,
            tcp_sock_send,
            tcp_sock_recv,
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
    fn run_tui(&mut self) {
        // Rate tracking for graph bounds
        let mut max_rate: f64 = 0.0;
        let mut tcp_sock_max_rate: f64 = 0.0;

        let mut last_size: u64 = 0;

        // Track time for averages
        let application_start = Instant::now();
        let mut last_loop: Duration = Duration::default();

        // For plotting
        // TODO: Add max number of entries handling!
        let mut packet_rates = Graph::new(
            "Ingress".to_string(),
            "Egress".to_string(),
            Color::Green,
            Color::Cyan,
            "Packet Rates".to_string(),
        );
        let mut function_calls = Graph::new(
            "tcp_recvmsg".to_string(),
            "tcp_sendmsg".to_string(),
            Color::Red,
            Color::Blue,
            "Function Calls".to_string(),
        );

        let mut status = Status::new();

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

            // Track changes in rates
            packet_rates.add_ingress((
                start_elapsed.as_secs_f64(),
                self.ingress_counter.get_rate(loop_elapsed),
            ));
            packet_rates.add_egress((
                start_elapsed.as_secs_f64(),
                self.egress_counter.get_rate(loop_elapsed),
            ));
            function_calls.add_ingress((
                start_elapsed.as_secs_f64(),
                self.tcp_sock_recv.get_rate(loop_elapsed),
            ));
            function_calls.add_egress((
                start_elapsed.as_secs_f64(),
                self.tcp_sock_send.get_rate(loop_elapsed),
            ));

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

            // Tooltips
            let keybindings =
                Paragraph::new("Close application: q | Esc  - Legend: (K)ilo, (M)ega, (G)iga");
            let keybindings_block = Block::bordered().borders(Borders::ALL).title("Keybindings");

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
                let mut constraints = vec![Constraint::Max(3); status.num_blocks()];
                constraints.push(Constraint::Min(0));

                // Top graph layout
                let graphs = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(top_areas[1]);

                // Split into two graphs, only if two graphs are needed
                if self.config.calls && self.config.packets {
                    let sub_graphs = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
                        .split(graphs[0]);

                    frame.render_widget(packet_rates.get_chart("pps"), sub_graphs[0]);
                    frame.render_widget(function_calls.get_chart("Calls/s"), sub_graphs[1]);
                } else if self.config.packets {
                    frame.render_widget(packet_rates.get_chart("pps"), graphs[0]);
                } else {
                    frame.render_widget(function_calls.get_chart("Calls/s"), graphs[0]);
                }

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
                    scrollbar_state.viewport_content_length(graphs[1].height as usize);

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
            while start.elapsed().as_millis() < self.update_period {
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
                        scroll_index = scroll_index.saturating_sub(1);
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
            };
            


            let Ok(outfile) = File::create(prepend_string("metrics.json".to_string(), &self.config.dir)) else {
                error!("Could not open outfile: {}/metrics.json",self.config.dir);
                return;
            };

            let mut writer = BufWriter::new(outfile);

            let _ = serde_json::to_writer(&mut writer, &metrics);
            let _ = writer.flush();
        }

        // Restore terminal view
        ratatui::restore();
    }
}
