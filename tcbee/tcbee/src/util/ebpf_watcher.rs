use std::{error::Error, io::{self, Write}, thread::sleep, time::{Duration, Instant}};

use aya::{maps::PerCpuArray, util::nr_cpus};
use log::{error, info};
use ratatui::{
    buffer::Buffer, crossterm::event::{self, KeyCode, KeyEventKind}, layout::{Constraint, Direction, Layout, Rect}, style::{Color, Modifier, Style}, symbols, text::Span, widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph, Widget}, DefaultTerminal
};
use tokio_util::sync::CancellationToken;

enum Counter {
    Dropped,
    Handled,
    Ingress,
    Egress
}

pub struct EBPFWatcher {
    events_drops: PerCpuArray<aya::maps::MapData, u32>,
    events_handled: PerCpuArray<aya::maps::MapData, u32>,
    ingress_counter: PerCpuArray<aya::maps::MapData, u32>,
    egress_counter: PerCpuArray<aya::maps::MapData, u32>,
    token: CancellationToken,
    terminal: Option<DefaultTerminal>
}

//TODO: Monitor packet rate vs TCP packet rate?
impl EBPFWatcher {
    pub fn new(
        events_drops: PerCpuArray<aya::maps::MapData, u32>,
        events_handled: PerCpuArray<aya::maps::MapData, u32>,
        ingress_counter: PerCpuArray<aya::maps::MapData, u32>,
        egress_counter: PerCpuArray<aya::maps::MapData, u32>,
        token: CancellationToken,
        do_tui: bool
    ) -> Result<EBPFWatcher, Box<dyn Error>> {
        if do_tui {
            color_eyre::install()?;
            let terminal: DefaultTerminal = ratatui::init();

            Ok(EBPFWatcher {
                events_drops,
                events_handled,
                ingress_counter,
                egress_counter,
                token,
                terminal: Some(terminal),
            })
        } else {
            Ok(EBPFWatcher {
                events_drops,
                events_handled,
                ingress_counter,
                egress_counter,
                token,
                terminal: None,
            })
        }        
    }

    pub fn run_no_tui(&mut self) {
        // To calculate rate over multiple iterations
        let mut last_dropped: u32 = 0;
        let mut last_handled: u32 = 0;
        let mut last_ingress: u32 = 0;
        let mut last_egress: u32 = 0;
        let mut max_rate: f64 = 0.0;

        let application_start = Instant::now();

        let mut ingress_rates: Vec<(f64, f64)> = vec![(0.0,0.0)];

        while !self.token.is_cancelled() {
            // Get current counter values
            let dropped = self.get_counter_sum(Counter::Dropped);
            let handled = self.get_counter_sum(Counter::Handled);
            let ingress = self.get_counter_sum(Counter::Ingress);
            let egress = self.get_counter_sum(Counter::Egress);

            // Calculate current rate in 1/s
            // TODO: change to be based on loop sleep duration
            let drate = (dropped - last_dropped) * 2;
            let hrate = (handled - last_handled) * 2;
            let irate = ((ingress - last_ingress) * 2) as f64;
            let erate = ((egress - last_egress) * 2) as f64;

            // Time elapsed
            let elapsed = application_start.elapsed();
            let time_string = format!("{}s {}ms",elapsed.as_secs(),elapsed.subsec_millis());

            let to_display = format!(
                // \r returns cursor to beginning of line, effectively overwriting the last line
                "\r| {} time elapsed | {} handled | {} dropped | {} events/s | {} drops/s | {} ingress packets/s | {} egress packets/s | ",
                time_string,handled, dropped, hrate, drate,irate,erate
            );

            print!("{to_display}");
            let _ = io::stdout().flush();

            // Store values for next loop iteration
            last_dropped = dropped;
            last_handled = handled;
            last_ingress = ingress;
            last_egress = egress;

            // Sleep until next calc
            sleep(Duration::from_millis(500))
        }

    }

    pub fn run(&mut self) -> () {

        // Start tokio task that listens to keyboard press

        // To calculate rate over multiple iterations
        let mut last_dropped: u32 = 0;
        let mut last_handled: u32 = 0;
        let mut last_ingress: u32 = 0;
        let mut last_egress: u32 = 0;
        let mut max_rate: f64 = 0.0;

        let application_start = Instant::now();

        let mut ingress_rates: Vec<(f64, f64)> = vec![(0.0,0.0)];
        let mut egress_rates: Vec<(f64, f64)> = vec![(0.0,0.0)];
        

        while !self.token.is_cancelled() {
            // Get current counter values
            let dropped = self.get_counter_sum(Counter::Dropped);
            let handled = self.get_counter_sum(Counter::Handled);
            let ingress = self.get_counter_sum(Counter::Ingress);
            let egress = self.get_counter_sum(Counter::Egress);

            // Calculate current rate in 1/s
            // TODO: change to be based on loop sleep duration
            let drate = (dropped - last_dropped) * 2;
            let hrate = (handled - last_handled) * 2;
            let irate = ((ingress - last_ingress) * 2) as f64;
            let erate = ((egress - last_egress) * 2) as f64;

            if irate > max_rate {
                max_rate = irate as f64;
            }

            if erate > max_rate {
                max_rate = erate as f64;
            }

            // Add rates for graph 
            ingress_rates.push(
                (application_start.elapsed().as_secs_f64(),irate as f64)
            );
            egress_rates.push(
                (application_start.elapsed().as_secs_f64(),erate as f64)
            );

            // Time elapsed
            let elapsed = application_start.elapsed();
            let time_string = format!("{}s {}ms",elapsed.as_secs(),elapsed.subsec_millis());

            // Generate Paragraph text
            let to_draw = Paragraph::new(format!(
                "{} handled\n{} dropped\n{} events/s\n{} drops/s\n{} ingress packets/s\n{} egress packets/s\n{} time elapsed",
                handled, dropped, hrate, drate,irate,erate, time_string
            ));
            // Block that contains paragraph
            let events_block = Block::bordered().borders(Borders::ALL).title("Event stats");

            // Tooltips
            let keybindings = Paragraph::new("Close application: q | Esc");
            let keybindings_block = Block::bordered().borders(Borders::ALL).title("Keybindings");

            // Rate chart labels
            let y_labels = vec![
                
                
                Span::styled(
                    format!("{}",0), 
                    Style::default().add_modifier(Modifier::BOLD)
                ),
                Span::styled(
                    format!("{}",max_rate/2.0), 
                    Style::default().add_modifier(Modifier::BOLD)
                ),
                Span::styled(
                    format!("{}",max_rate), 
                    Style::default().add_modifier(Modifier::BOLD)
                ),

            ];

            let x_labels = vec![
                Span::styled(
                    format!("{}",0), 
                    Style::default().add_modifier(Modifier::BOLD)
                ),
                Span::styled(
                    format!("{}",elapsed.as_secs() as f64 /2.0), 
                    Style::default().add_modifier(Modifier::BOLD)
                ),
                Span::styled(
                    format!("{}",elapsed.as_secs()), 
                    Style::default().add_modifier(Modifier::BOLD)
                ),
            ];


            // Rate chart
            let chart = Chart::new(
                vec![
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
                ]
            )
            .block(Block::default().borders(Borders::ALL).title("Packet Rate Graph"))
            .x_axis(Axis::default()
                .title("Time (s)")
                .style(Style::default().fg(Color::White))
                .bounds([0.0,elapsed.as_secs_f64()])
                .labels(x_labels)
            )
            .y_axis(Axis::default()
                .title("Packets/s")
                .style(Style::default().fg(Color::White))
                .bounds([0.0,max_rate])
                .labels(y_labels)
            );

            // Render function
            // TODO: move to own function
            let _ = self.terminal.as_mut().unwrap().draw(|frame| {

                // Main layout
                let areas= Layout::default()
                    .direction(Direction::Vertical)
                    .constraints(vec![
                        Constraint::Min(8),
                        Constraint::Max(3)
                    ])
                    .split(frame.area());

                // Top layout
                let top_areas = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints(vec![
                        Constraint::Percentage(20),
                        Constraint::Percentage(80)
                    ])
                    .split(areas[0]);

                frame.render_widget(to_draw.block(events_block), top_areas[0]);
                frame.render_widget(chart, top_areas[1]);

                frame.render_widget(keybindings.block(keybindings_block), areas[1]);

            });

            // Store values for next loop iteration
            last_dropped = dropped;
            last_handled = handled;
            last_ingress = ingress;
            last_egress = egress;

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

    fn get_counter_sum(&self, counter: Counter) -> u32 {
        // Get counter based on passed enum
        let counter_instance = match counter {
            Counter::Dropped => &self.events_drops,
            Counter::Egress => &self.egress_counter,
            Counter::Handled => &self.events_handled,
            Counter::Ingress => &self.ingress_counter
        };

        // Counter is per CPU, sum will hold sum across CPUs
        let mut sum: u32 = 0;

        // Get counter array
        let values = counter_instance.get(&0, 0);

        // Check if error erturned
        match values {
            Err(err) => {
                error!("Failed to read event drop counters: {}!", err);
            }
            Ok(counters) => {
                // Iterate and sum over array
                for i in 1..nr_cpus().expect("failed to get number of cpus") {
                    sum += counters[i];
                }
            }
        }
        sum
    }

    
}
