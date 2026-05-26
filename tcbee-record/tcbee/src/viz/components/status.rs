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
        bytes_received: String,
        bytes_sent: String,
        border: Color,
    ) -> Vec<Paragraph<'_>> {
        let drop_style = match dropped {
            true => Style::default().fg(Color::Black).bg(Color::LightRed),
            false => Style::default(),
        };
        let block_style = Style::default().fg(border);
        let value_style = Style::default();

        vec![
            Paragraph::new(time).style(value_style).block(
                Block::bordered()
                    .borders(Borders::BOTTOM)
                    .border_style(block_style)
                    .title("Time Elapsed"),
            ),
            Paragraph::new(events_handled).style(value_style).block(
                Block::bordered()
                    .borders(Borders::BOTTOM)
                    .border_style(block_style)
                    .title("Events Handled"),
            ),
            Paragraph::new(events_dropped)
                .block(
                    Block::bordered()
                        .borders(Borders::BOTTOM)
                        .border_style(block_style)
                        .title("Events Dropped"),
                )
                .style(drop_style),
            Paragraph::new(event_rate).style(value_style).block(
                Block::bordered()
                    .borders(Borders::BOTTOM)
                    .border_style(block_style)
                    .title("Event Rate"),
            ),
            Paragraph::new(RateWatcher::<u64>::format_sum(files_size, "Byte"))
                .style(value_style)
                .block(
                    Block::bordered()
                        .borders(Borders::BOTTOM)
                        .border_style(block_style)
                        .title("Disk File Size"),
                ),
            Paragraph::new(file_rate).style(value_style).block(
                Block::bordered()
                    .borders(Borders::BOTTOM)
                    .border_style(block_style)
                    .title("Write Speed"),
            ),
            Paragraph::new(bytes_sent).style(value_style).block(
                Block::bordered()
                    .borders(Borders::BOTTOM)
                    .border_style(block_style)
                    .title("TCP Bytes Sent"),
            ),
            Paragraph::new(bytes_received).style(value_style).block(
                Block::bordered()
                    .borders(Borders::BOTTOM)
                    .border_style(block_style)
                    .title("TCP Bytes Received"),
            ),
        ]
    }

    pub fn num_blocks(&self) -> usize {
        8
    }
}
