use std::{
    collections::HashMap,
    error::Error,
    time::{Duration, Instant},
};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use log::error;
use tokio::sync::mpsc::Receiver;
use ts_storage::{database_factory, DBBackend, DataPoint, IpTuple, TSDBInterface};

use crate::{bindings::event_indexer::EventIndexer, flow_tracker::FlowTracker};

const PROGRESS_LABEL_WIDTH: usize = 24;

#[derive(Debug)]
pub struct DBOperation {
    pub tuple: IpTuple,
    pub time_series: String,
    pub data_point: DataPoint,
}

pub fn as_db_operation<T: EventIndexer>(event: T) -> Vec<DBOperation> {
    let mut vec: Vec<DBOperation> = Vec::with_capacity(event.get_max_index());

    for i in 0..=event.get_max_index() {
        vec.push(DBOperation {
            tuple: event.get_ip_tuple(),
            time_series: event.get_field_name(i).to_string(),
            data_point: DataPoint {
                timestamp: event.get_timestamp(),
                value: event.get_field(i),
            },
        });
    }
    vec
}

pub struct DBWriter {
    db: Box<dyn TSDBInterface + Send>,
    streams: HashMap<IpTuple, FlowTracker>,
    rx: Receiver<Vec<DBOperation>>,
    status: ProgressBar,
    flush_bar: ProgressBar,
    num_flows: i32,
    last_status_update: Instant,
}

impl DBWriter {
    pub fn new(
        backend: DBBackend,
        rx: Receiver<Vec<DBOperation>>,
        status: ProgressBar,
    ) -> Result<DBWriter, Box<dyn Error>> {
        let db: Box<dyn TSDBInterface + Send> = database_factory(backend)?;

        let streams: HashMap<IpTuple, FlowTracker> = HashMap::new();

        status.set_message("Processed 0 operations across 0 flows");

        Ok(DBWriter {
            db,
            streams,
            rx,
            status,
            flush_bar: ProgressBar::hidden(),
            num_flows: 0,
            last_status_update: Instant::now(),
        })
    }

    fn update_status(&self) {
        self.status.set_message(format!(
            "Processed {} operations across {} flows",
            self.status.position(),
            self.num_flows
        ));
    }

    pub fn setup_new_stream(&mut self, tuple: &IpTuple) -> Result<(), Box<dyn Error>> {
        // Insert stream if not known
        if !self.streams.contains_key(tuple) {
            let new_tracker = FlowTracker::new(&self.db, tuple);

            // TODO: remove unwrap, error handling!
            self.streams.insert(tuple.clone(), new_tracker);

            // Update progress message!
            self.num_flows += 1;
            self.update_status();
        }

        Ok(())
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        while let Some(batch) = self.rx.blocking_recv() {
            self.status.inc(batch.len() as u64);
            if self.last_status_update.elapsed() >= Duration::from_millis(250) {
                self.update_status();
                self.last_status_update = Instant::now();
            }

            for event in batch {
                if let Some(tracker) = self.streams.get_mut(&event.tuple) {
                    let res = tracker.add_event(&self.db, event);

                    if res.is_err() {
                        error!("Failed to handle event. Error: {}", res.err().unwrap());
                    }
                } else {
                    self.setup_new_stream(&event.tuple)?;
                    let tracker = self.streams.get_mut(&event.tuple).unwrap();
                    let res = tracker.add_event(&self.db, event);

                    if res.is_err() {
                        error!("Failed to handle event. Error: {}", res.err().unwrap());
                    }
                }
            }
        }
        // This is reached when all tx channels are dropped, flush files!
        self.update_status();
        self.status.finish_and_clear();

        self.flush_bar.set_draw_target(ProgressDrawTarget::stderr());
        self.flush_bar.set_length(self.streams.len() as u64);
        self.flush_bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {prefix:.bold.dim} [{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {percent:>3}% {wide_msg}",
            )
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );
        self.flush_bar
            .set_prefix(format!("{:<width$}", "flush", width = PROGRESS_LABEL_WIDTH));
        self.flush_bar.set_message("Writing buffered points");
        self.flush_bar
            .enable_steady_tick(Duration::from_millis(100));

        for (_tuple, tracker) in self.streams.iter_mut() {
            tracker.flush(&self.db);
            self.flush_bar.inc(1);
        }
        self.flush_bar.finish_and_clear();
        self.flush_bar.reset();

        self.flush_bar.set_style(
            ProgressStyle::with_template("{spinner:.green} {wide_msg}")
                .unwrap()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );
        self.flush_bar
            .enable_steady_tick(std::time::Duration::from_millis(100));
        self.flush_bar.set_message("Finalizing database");

        Ok(())
    }
}
