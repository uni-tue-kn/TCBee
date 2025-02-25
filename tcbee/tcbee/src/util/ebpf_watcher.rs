use std::{
    collections::HashMap, error::Error, fs::File, io::{self, Read, Write}, net::{IpAddr, Ipv4Addr, Ipv6Addr}, ops::{AddAssign, Sub}, os::linux::fs::MetadataExt, path::Path, thread::sleep, time::{Duration, Instant}
};

use glob;

use crate::viz::{flow_tracker::FlowTracker, rate_watcher::RateWatcher};

use aya::{
    maps::{PerCpuArray, PerCpuHashMap},
    util::nr_cpus,
    Pod,
};
use log::{error, info, warn};
use ratatui::{
    buffer::Buffer,
    crossterm::event::{self, KeyCode, KeyEventKind},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols,
    text::Span,
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, List, Paragraph, Row, Table, Widget},
    DefaultTerminal,
};
use tcbee_common::bindings::flow::IpTuple;
use tokio_util::sync::CancellationToken;

enum Counter {
    Dropped,
    Handled,
    Ingress,
    Egress,
}


pub struct EBPFWatcher {
    events_drops: RateWatcher<u32>,
    events_handled: RateWatcher<u32>,
    ingress_counter: RateWatcher<u32>,
    egress_counter: RateWatcher<u32>,
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

        let flow_tracker = FlowTracker::new(flow_tracker);

        if do_tui {
            color_eyre::install()?;
            let terminal: DefaultTerminal = ratatui::init();

            Ok(EBPFWatcher {
                events_drops,
                events_handled,
                ingress_counter,
                egress_counter,
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

        // Open all .tcp files to watch file size!
        let mut files: Vec<File> = Vec::new();
        if let Ok(paths) = glob::glob("/tmp/*.tcp") {
            for p in paths {
                if let Ok(path) = p {
                    let open = File::open(path);
                    if open.is_ok() {
                        files.push(open.unwrap());
                    }
                }
            }
        } else {
            error!("Cannot read files at /tmp for size watcher!")
        }
        let mut last_size: u64 = 0;

        let application_start = Instant::now();
        let mut last_loop: Duration = Duration::default();

        // For plotting
        // TODO: Add max number of entries handling!
        let mut ingress_rates: Vec<(f64, f64)> = vec![(0.0, 0.0)];
        let mut egress_rates: Vec<(f64, f64)> = vec![(0.0, 0.0)];

        while !self.token.is_cancelled() {
            let start_elapsed = application_start.elapsed();
            let loop_elapsed = start_elapsed - last_loop;

            // Update tracker of alll flows internal list and then print it
            self.flow_tracker.read_flows();
            let flows = self.flow_tracker.get_flows();

            // Get sum of file sizes
            let mut files_size: u64 = 0;
            for f in files.iter() {
                if let Ok(meta) = f.metadata() {
                    files_size = files_size + meta.st_size();
                } else {
                    println!("ERR");
                }
            }
            let file_rate = RateWatcher::<u64>::format_rate(
                (files_size - last_size) as f64 * (1.0 / loop_elapsed.as_secs_f64()),
                "Byte/s",
            );

            // For graph plotting
            let ingress_rate = self.ingress_counter.get_rate(loop_elapsed);
            let egress_rate = self.egress_counter.get_rate(loop_elapsed);

            if ingress_rate > max_rate {
                max_rate = ingress_rate;
            }

            if egress_rate > max_rate {
                max_rate = egress_rate;
            }

            // Add rates for graph
            ingress_rates.push((start_elapsed.as_secs_f64(), ingress_rate as f64));
            egress_rates.push((start_elapsed.as_secs_f64(), egress_rate as f64));

            // Time elapsed
            let time_string = format!(
                "{}s {}ms",
                start_elapsed.as_secs(),
                start_elapsed.subsec_millis()
            );

            // Sum of handled and dropped
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
                Paragraph::new("Close application: q | Esc  - Legend: (K)ilo, (M)ega, (Giga)");
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
                    .marker(symbols::Marker::Dot)
                    .style(Style::default().fg(Color::Cyan))
                    .graph_type(GraphType::Line)
                    .data(&ingress_rates),
                Dataset::default()
                    .name("Egress")
                    .marker(symbols::Marker::Dot)
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
            );

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

                frame.render_widget(chart, graphs[0]);
                frame.render_widget(flows, graphs[1]);
                frame.render_widget(keybindings.block(keybindings_block), areas[1]);
            });

            // Store time after calculation for rate calculation
            last_loop = application_start.elapsed();
            last_size = files_size;

            // Wait for key event for 0.5s and check key presses inbetween runs
            let start = Instant::now();

            // Loop until 500ms elapsed
            while start.elapsed().as_millis() < 500 {
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
                }
            }
        }

        // Restore terminal view
        ratatui::restore();
    }
}
