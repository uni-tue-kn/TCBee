use ratatui::{
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

use crate::viz::rate_watcher::RateWatcher;

#[derive(Default)]
pub struct Status {}

impl Status {
    pub fn new() -> Status {
        Status::default()
    }

    // TODO: makes this cleaner with builder pattern?
    pub fn get_blocks(
        &self,
        time: String,
        events_handled: String,
        events_dropped: String,
        dropped: bool,
        event_rate: String,
        files_size: u64,
        file_rate: String,
    ) -> Vec<Paragraph<'_>> {
        let drop_style = match dropped {
            true => Style::default().bg(Color::LightRed),
            false => Style::default(),
        };

        vec![
            Paragraph::new(time).block(
                Block::bordered()
                    .borders(Borders::BOTTOM)
                    .title("Time Elapsed"),
            ),
            Paragraph::new(events_handled).block(
                Block::bordered()
                    .borders(Borders::BOTTOM)
                    .title("Events Handled"),
            ),
            Paragraph::new(events_dropped)
                .block(
                    Block::bordered()
                        .borders(Borders::BOTTOM)
                        .title("Events Dropped"),
                )
                .style(drop_style),
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
        ]
    }

    pub fn num_blocks(&self) -> usize {
        6
    }
}
