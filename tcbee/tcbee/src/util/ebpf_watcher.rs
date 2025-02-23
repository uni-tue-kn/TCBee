use std::{
    error::Error,
    io::{self, Write},
    ops::{AddAssign, Sub},
    thread::sleep,
    time::{Duration, Instant},
};

use aya::{maps::PerCpuArray, util::nr_cpus, Pod};
use log::{error, info};
use ratatui::{
    buffer::Buffer,
    crossterm::event::{self, KeyCode, KeyEventKind},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph, Widget},
    DefaultTerminal,
};
use tokio_util::sync::CancellationToken;

enum Counter {
    Dropped,
    Handled,
    Ingress,
    Egress,
}

// TODO: make more generic to handle float maps as well?
pub struct RateWatcher<T: Pod + AddAssign + Sub> {
    map: PerCpuArray<aya::maps::MapData, T>,
    suffix: String,
    last_val: T,
    name: String,
}

impl<T: Pod + AddAssign + Default + Sub> RateWatcher<T> {
    pub fn new(
        map: PerCpuArray<aya::maps::MapData, T>,
        suffix: String,
        init_val: T,
        name: String,
    ) -> RateWatcher<T> {
        RateWatcher {
            map: map,
            suffix: suffix,
            last_val: init_val,
            name: name,
        }
    }
    pub fn get_rate_string(&mut self, elapsed: Duration) -> String
    where
        f64: From<<T as Sub>::Output>,
    {
        let rate = self.get_rate(elapsed);
        RateWatcher::<T>::format_rate(rate, &self.suffix)
    }

    pub fn get_rate(&mut self, elapsed: Duration) -> f64
    where
        f64: From<<T as Sub>::Output>,
    {
        let sum = self.get_counter_sum();

        // TODO: better handling?
        let rate = f64::try_from(sum - self.last_val).unwrap_or_else(|_| -1.0)
            * (1.0 / elapsed.as_secs_f64());

        self.last_val = sum;

        rate
    }

    pub fn get_counter_sum(&self) -> T {
        // Counter is per CPU, sum will hold sum across CPUs
        let mut sum: T = T::default();

        // Get counter array
        let values = self.map.get(&0, 0);

        // Check if error erturned
        match values {
            Err(err) => {
                error!("Failed to read event counter {}: {}!", self.name, err);
            }
            Ok(counters) => {
                // Iterate and sum over array
                if let Ok(num_cpus) = nr_cpus() {
                    for i in 0..=num_cpus {
                        sum += counters[i];
                    }
                } else {
                    error!("Failed to get number of CPUs for {}", self.name);
                }
            }
        }
        sum
    }

    // TODO: prettier?
    fn format_rate(val: f64, suffix: &str) -> String {
        if val > 1_000_000_000.0 {
            return format!("{} G{}", val, suffix);
        } else if val > 1_000_000.0 {
            return format!("{} M{}", val, suffix);
        } else if val > 1_0000.0 {
            return format!("{} K{}", val, suffix);
        } else {
            return format!("{} {}", val, suffix);
        }
    }
}

pub struct EBPFWatcher {
    events_drops: RateWatcher<u32>,
    events_handled: RateWatcher<u32>,
    ingress_counter: RateWatcher<u32>,
    egress_counter: RateWatcher<u32>,
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

    pub fn run(&mut self) -> () {
        // Rate trcking for
        let mut last_dropped: u32 = 0;
        let mut last_handled: u32 = 0;
        let mut last_ingress: u32 = 0;
        let mut last_egress: u32 = 0;
        let mut max_rate: f64 = 0.0;

        let application_start = Instant::now();

        // For plotting
        // TODO: Add max number of entries handling!
        let mut ingress_rates: Vec<(f64, f64)> = vec![(0.0, 0.0)];
        let mut egress_rates: Vec<(f64, f64)> = vec![(0.0, 0.0)];

        while !self.token.is_cancelled() {
            let elapsed = application_start.elapsed();

            // Get current counter values
            let dropped = self.events_drops.get_rate_string(elapsed);
            let handled = self.events_handled.get_rate_string(elapsed);
            let ingress = self.ingress_counter.get_rate_string(elapsed);
            let egress = self.egress_counter.get_rate_string(elapsed);

            // For graph plotting
            let ingress_rate = self.ingress_counter.get_rate(elapsed);
            let egress_rate = self.egress_counter.get_rate(elapsed);

            if ingress_rate > max_rate {
                max_rate = ingress_rate;
            }

            if egress_rate > max_rate {
                max_rate =egress_rate;
            }

            // Add rates for graph
            ingress_rates.push((application_start.elapsed().as_secs_f64(), ingress_rate as f64));
            egress_rates.push((application_start.elapsed().as_secs_f64(), egress_rate as f64));

            // Time elapsed
            let elapsed = application_start.elapsed();
            let time_string = format!("{}s {}ms", elapsed.as_secs(), elapsed.subsec_millis());


            // Blocks for UI



            // Generate Paragraph text
            let to_draw = Paragraph::new(format!(
                "{} handled\n{} dropped\n{} events/s\n{} drops/s\n{} ingress packets/s\n{} egress packets/s\n{} time elapsed",
                self.events_handled.get_counter_sum(), self.events_drops.get_counter_sum(), handled, dropped,ingress_rate,egress_rate, time_string
            ));
            // Block that contains paragraph
            let events_block = Block::bordered().borders(Borders::ALL).title("Event stats");

            // Tooltips
            let keybindings = Paragraph::new("Close application: q | Esc");
            let keybindings_block = Block::bordered().borders(Borders::ALL).title("Keybindings");

            // Rate chart labels
            let y_labels = vec![
                Span::styled(
                    format!("{}", 0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", max_rate / 2.0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", max_rate),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ];

            let x_labels = vec![
                Span::styled(
                    format!("{}", 0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", elapsed.as_secs() as f64 / 2.0),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", elapsed.as_secs()),
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
                    .title("Time (s)")
                    .style(Style::default().fg(Color::White))
                    .bounds([0.0, elapsed.as_secs_f64()])
                    .labels(x_labels),
            )
            .y_axis(
                Axis::default()
                    .title("Packets/s")
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

                frame.render_widget(to_draw.block(events_block), top_areas[0]);
                frame.render_widget(chart, top_areas[1]);

                frame.render_widget(keybindings.block(keybindings_block), areas[1]);
            });

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
