use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::sleep,
    time::{Duration, Instant},
};

use libbpf_rs::MapHandle;
use log::error;
use ratatui::{
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, MouseEventKind},
        execute,
    },
    DefaultTerminal,
};
use tokio_util::sync::CancellationToken;

use crate::{
    stats::Stats,
    viz::{
        context::RunContext,
        flow_owners::SharedOwners,
        flow_tracker::FlowTracker,
        model::Model,
        view::{render, Areas, UiState},
    },
};

pub struct EBPFWatcher {
    stats: Arc<Stats>,
    bytes_written: Arc<AtomicU64>,
    flow_tracker: FlowTracker,
    /// The owners of the flows, with the owner programs
    owners: Option<SharedOwners>,
    update_period: u128,
    token: CancellationToken,
    terminal: Option<DefaultTerminal>,
    model: Model,
    context: RunContext,
}

//TODO: Monitor packet rate vs TCP packet rate?
impl EBPFWatcher {
    pub fn new(
        flows: MapHandle,
        stats: Arc<Stats>,
        bytes_written: Arc<AtomicU64>,
        update_period: u128,
        token: CancellationToken,
        context: RunContext,
        do_tui: bool,
    ) -> anyhow::Result<EBPFWatcher> {
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
            bytes_written,
            flow_tracker: FlowTracker::new(flows),
            owners: context.owners.clone(),
            update_period,
            token,
            terminal,
            model: Model::new(&context.active_rings),
            context,
        })
    }

    /// Reads the counters into the model, returns whether they could be read
    fn update_model(&mut self, elapsed: Duration) -> bool {
        match self.stats.snapshot() {
            Ok(snapshot) => {
                let bytes_written = self.bytes_written.load(Ordering::Relaxed);
                self.model.update(snapshot, bytes_written, elapsed);
                true
            }
            Err(err) => {
                error!("Failed to read event counters: {}", err);
                false
            }
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
        let application_start = Instant::now();

        while !self.token.is_cancelled() {
            self.update_model(application_start.elapsed());
            print!("{}", self.model.quiet_line());
            let _ = io::stdout().flush();

            // Sleep until next calc
            sleep(Duration::from_millis(500))
        }
    }

    /// Draws the current model, returns where the frame put the clickable parts
    fn draw(&mut self, ui: &UiState) -> Areas {
        let mut areas = Areas::default();
        let flows = &self.flow_tracker.flows;
        let _ = self.terminal.as_mut().unwrap().draw(|frame| {
            areas = render(frame, &self.model, &self.context, ui, flows);
        });
        areas
    }

    fn run_tui(&mut self) {
        let application_start = Instant::now();
        let mut ui = UiState::new(
            self.context.observation_window,
            Duration::from_millis(self.update_period as u64),
        );

        while !self.token.is_cancelled() {
            // A failed read leaves the rates of the tick before, which are no new point
            if self.update_model(application_start.elapsed()) {
                self.model.record_history();
            }

            // Update tracker of all flows internal list and then show it
            self.flow_tracker.read_flows();
            if let Some(owners) = &self.owners {
                if let Ok(live) = owners.live.lock() {
                    self.flow_tracker
                        .flows
                        .find_owners(&live, owners.snapshot.get());
                }
            }
            let mut areas = self.draw(&ui);

            // Wait for key events until the next update
            let start = Instant::now();
            while start.elapsed().as_millis() < self.update_period {
                // Poll for event ready
                // Timout after 10ms
                // On Error continue to next loop iteration
                let Ok(ready) = event::poll(Duration::from_millis(10)) else {
                    continue;
                };
                if !ready {
                    continue;
                }
                let flows = self.flow_tracker.flows.len();
                match event::read() {
                    Ok(event::Event::Key(key)) => {
                        if ui.on_key(key.code, &areas, flows) {
                            self.token.cancel();
                        }
                    }
                    // The terminal reports every move of the pointer, which changes nothing
                    Ok(event::Event::Mouse(mouse))
                        if matches!(
                            mouse.kind,
                            MouseEventKind::Moved | MouseEventKind::Drag(_)
                        ) =>
                    {
                        continue
                    }
                    Ok(event::Event::Mouse(mouse)) => ui.on_mouse(mouse, &areas, flows),
                    // A resize draws below
                    Ok(event::Event::Resize(..)) => {}
                    _ => continue,
                }
                // Shows the input right away, from the counters of the last update
                areas = self.draw(&ui);
            }
        }

        // Restore terminal view
        let _ = execute!(io::stdout(), DisableMouseCapture);
        ratatui::restore();
    }
}
